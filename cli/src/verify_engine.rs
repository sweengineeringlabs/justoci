//! Verify pillar walker.
//!
//! Inverse of `build` + `attest`: reads an OCI image dir, walks the
//! referrer manifests, classifies each by `artifactType`, validates
//! structural integrity (SLSA statement shape, SBOM media type,
//! signature blob shape), optionally invokes `cosign verify-blob` to
//! confirm the signature, and applies a `--policy` gate if supplied.
//!
//! ## v0 contract (per the task spec)
//!
//! - `<ref>` is a path to a local OCI image-layout directory.
//!   Registry-pull is v0.2.
//! - We delegate the OCI-layout validation to `oci_publish::ImageDir`
//!   so verify and publish agree on what "valid" means.
//! - Cosign signature verification goes through the
//!   [`CosignVerifyInvoker`] trait so tests can script outcomes
//!   deterministically without a real cosign install (mirrors the
//!   approach attest uses for its sign step).
//!
//! ## What `verify` does NOT do (v0)
//!
//! - It does NOT re-canonicalise the spec. The post-publish image
//!   dir doesn't carry the source TOML; the spec hash is read from
//!   the SLSA statement's `externalParameters.spec_hash` and
//!   structurally validated.
//! - It does NOT prove the signature was issued by a trusted
//!   identity unless `--policy` declares the rule. The default
//!   posture is "structural integrity + presence"; policy turns
//!   the dial up.
//!
//! ## Pillar-by-pillar behaviour
//!
//! Each referrer is classified by `artifactType`:
//!
//! - `application/vnd.in-toto+json` → SLSA statement
//! - `application/vnd.cyclonedx+json` or `application/spdx+json` → SBOM
//! - `application/vnd.dev.cosign.simplesigning.v1+json` → signature
//!
//! The walker emits a `VerifyReport` summarising what was found and
//! what (if anything) failed. Policy violations short-circuit with
//! a typed `VerifyError::PolicyViolation`.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

use oci_publish::ImageDir;

use crate::policy::Policy;

/// One artifact-type discriminator we know how to classify.
const MEDIA_TYPE_IN_TOTO: &str = "application/vnd.in-toto+json";
const MEDIA_TYPE_CYCLONEDX: &str = "application/vnd.cyclonedx+json";
const MEDIA_TYPE_SPDX: &str = "application/spdx+json";
const MEDIA_TYPE_COSIGN_SIG: &str = "application/vnd.dev.cosign.simplesigning.v1+json";
const SLSA_PROVENANCE_V1: &str = "https://slsa.dev/provenance/v1";

/// Errors raised by the verify walker.
///
/// Each variant carries enough context for an operator to act.
/// `PolicyViolation` names the rule and the observed value so the
/// operator can fix the policy or the artifact without re-reading
/// the source.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// The image dir itself was malformed (delegates to the publish
    /// crate's validation). Surfaces here because verify takes the
    /// same `ImageDir::open` contract publish does.
    #[error("image dir malformed: {0}")]
    ImageDir(#[from] oci_publish::ImageDirError),

    /// A signature referrer was present but the bundle bytes failed
    /// signature verification (cosign returned non-zero, or the
    /// bundle is structurally invalid). The artifact is unsigned.
    #[error("signature invalid: {detail}")]
    SignatureInvalid { detail: String },

    /// The signature is structurally present and cosign returned
    /// success, but Rekor coupling could not be confirmed (no
    /// `logIndex` in the bundle, or the operator opted into
    /// `--no-rekor` and the policy rejects it).
    #[error("signature not recorded in Rekor: {detail}")]
    RekorNotRecorded { detail: String },

    /// The SLSA statement is present but its shape doesn't match
    /// what `attest` would emit (wrong predicateType, missing
    /// subject digest, missing externalParameters.spec_hash).
    #[error("SLSA statement malformed: {detail}")]
    SlsaMalformed { detail: String },

    /// A pillar that policy required was missing entirely.
    #[error("SLSA statement missing — required by policy")]
    SlsaMissing,

    /// SBOM is missing — required by policy.
    #[error("SBOM missing — required by policy")]
    SbomMissing,

    /// Signature is missing — required by policy.
    #[error("signature missing — required by policy")]
    SignatureMissing,

    /// Policy gate violation. `rule` names the policy field that
    /// failed; `detail` describes the observed value.
    #[error("policy violation [{rule}]: {detail}")]
    PolicyViolation { rule: String, detail: String },

    /// Cosign was required by policy or by signature presence but
    /// is not installed / not invokable on this host. The signature
    /// blob is left un-verified; verify cannot say signed-or-not.
    #[error("cosign verify failed (cosign not invokable): {stderr}")]
    Cosign { stderr: String },

    /// IO failure reading a referrer blob.
    #[error("verify io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Generic bytes-level parse failure for a referrer blob (e.g.
    /// the in-toto Statement is not parseable JSON).
    #[error("malformed referrer blob {digest}: {detail}")]
    MalformedBlob { digest: String, detail: String },
}

/// Per-pillar verdict for one image dir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PillarVerdict {
    /// Pillar referrer is missing entirely.
    Missing,
    /// Pillar present and structurally valid. `detail` is a human-
    /// readable summary (digest, log index, etc.) that the CLI
    /// surfaces in the verdict table.
    Found { detail: String },
    /// Pillar present but cosign couldn't verify it / Rekor coupling
    /// missing. The verifier logs this and returns the matching
    /// `VerifyError` variant only when policy demands the failure
    /// be hard.
    Failed { detail: String },
}

impl PillarVerdict {
    pub fn label(&self) -> &'static str {
        match self {
            PillarVerdict::Missing => "missing",
            PillarVerdict::Found { .. } => "ok",
            PillarVerdict::Failed { .. } => "failed",
        }
    }
}

/// Aggregate report from a successful verify run (no policy violation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    pub manifest_digest: String,
    pub slsa: PillarVerdict,
    pub sbom: PillarVerdict,
    pub signature: PillarVerdict,
}

impl VerifyReport {
    /// `true` if any pillar reported `Failed`. Useful for callers
    /// that want a softer "informational" exit.
    pub fn any_failed(&self) -> bool {
        matches!(self.slsa, PillarVerdict::Failed { .. })
            || matches!(self.sbom, PillarVerdict::Failed { .. })
            || matches!(self.signature, PillarVerdict::Failed { .. })
    }
}

// ── Cosign verify invoker abstraction ─────────────────────────────

/// Outcome of asking cosign to verify a signature blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CosignVerifyOutcome {
    /// cosign verify-blob succeeded AND the bundle has a Rekor
    /// log index.
    VerifiedAndRecorded { log_index: u64 },
    /// cosign succeeded structurally but no Rekor entry could be
    /// confirmed (operator opted into `--no-rekor` or Rekor was
    /// down at sign-time).
    VerifiedNotRecorded { reason: String },
    /// cosign returned non-zero — the signature does not verify
    /// against the manifest digest.
    InvalidSignature { stderr: String },
    /// cosign is not on PATH on this host. The verifier reports
    /// this as a soft failure; policy decides whether to escalate.
    CosignNotInstalled,
}

/// Indirection over the `cosign verify-blob` subprocess. Production
/// uses `RealCosignVerifyInvoker`; tests inject `StubCosignVerifyInvoker`.
///
/// The trait isolates the subprocess boundary so the verify pillar
/// walker is fully testable without cosign installed.
pub trait CosignVerifyInvoker: Send + Sync {
    /// Verify `bundle_bytes` cover `manifest_digest`. The caller has
    /// already located both — the trait is purely about cosign side
    /// effects.
    fn verify(
        &self,
        manifest_digest: &str,
        bundle_bytes: &[u8],
    ) -> CosignVerifyOutcome;
}

/// Real cosign verifier — spawns `cosign verify-blob`.
///
/// Operator note: v0's verify path is "best effort" — cosign needs a
/// public key or a Fulcio identity to fully verify. In its absence
/// we still parse the bundle for `rekorBundle.Payload.logIndex` and
/// surface that information; full identity verification is the
/// operator's job via a `--policy` rule (`sign.identity matches ...`).
///
/// If cosign is missing we return `CosignNotInstalled` rather than
/// panicking — the verify pillar walker downgrades the signature
/// pillar to `Missing` / `Failed` based on policy.
pub struct RealCosignVerifyInvoker {
    /// Override the `cosign` binary path via env. Useful in CI where
    /// the path-probe lookup is unreliable.
    bin: PathBuf,
}

impl RealCosignVerifyInvoker {
    pub fn new() -> Self {
        let bin = std::env::var_os("OCIMAGE_COSIGN_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("cosign"));
        RealCosignVerifyInvoker { bin }
    }
}

impl Default for RealCosignVerifyInvoker {
    fn default() -> Self {
        Self::new()
    }
}

impl CosignVerifyInvoker for RealCosignVerifyInvoker {
    fn verify(
        &self,
        manifest_digest: &str,
        bundle_bytes: &[u8],
    ) -> CosignVerifyOutcome {
        // First: do the structural Rekor-bundle probe locally. If
        // cosign isn't present we still surface what the bundle
        // tells us, as a softer signal.
        let log_index = extract_rekor_log_index(bundle_bytes);

        // Stage the bundle to a temp file (cosign verify-blob reads
        // both the payload and the bundle from disk).
        let payload_path = match write_payload_tempfile(manifest_digest) {
            Ok(p) => p,
            Err(e) => {
                return CosignVerifyOutcome::InvalidSignature {
                    stderr: format!("could not stage cosign payload: {e}"),
                };
            }
        };
        let bundle_path = payload_path.with_extension("bundle.json");
        if let Err(e) = std::fs::write(&bundle_path, bundle_bytes) {
            let _ = std::fs::remove_file(&payload_path);
            return CosignVerifyOutcome::InvalidSignature {
                stderr: format!("could not stage cosign bundle: {e}"),
            };
        }

        let mut cmd = Command::new(&self.bin);
        cmd.arg("verify-blob")
            .arg("--bundle")
            .arg(&bundle_path)
            .arg(&payload_path);

        let output = match cmd.output() {
            Ok(o) => o,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let _ = std::fs::remove_file(&payload_path);
                let _ = std::fs::remove_file(&bundle_path);
                return CosignVerifyOutcome::CosignNotInstalled;
            }
            Err(e) => {
                let _ = std::fs::remove_file(&payload_path);
                let _ = std::fs::remove_file(&bundle_path);
                return CosignVerifyOutcome::InvalidSignature {
                    stderr: format!("failed to spawn cosign verify-blob: {e}"),
                };
            }
        };

        let _ = std::fs::remove_file(&payload_path);
        let _ = std::fs::remove_file(&bundle_path);

        if !output.status.success() {
            return CosignVerifyOutcome::InvalidSignature {
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            };
        }

        match log_index {
            Some(idx) => CosignVerifyOutcome::VerifiedAndRecorded { log_index: idx },
            None => CosignVerifyOutcome::VerifiedNotRecorded {
                reason: "cosign verify succeeded but bundle has no rekorBundle.Payload.logIndex"
                    .into(),
            },
        }
    }
}

/// Test verifier — returns scripted outcomes.
pub struct StubCosignVerifyInvoker {
    outcome: std::sync::Mutex<CosignVerifyOutcome>,
}

impl StubCosignVerifyInvoker {
    pub fn new(outcome: CosignVerifyOutcome) -> Self {
        StubCosignVerifyInvoker {
            outcome: std::sync::Mutex::new(outcome),
        }
    }
}

impl CosignVerifyInvoker for StubCosignVerifyInvoker {
    fn verify(
        &self,
        _manifest_digest: &str,
        _bundle_bytes: &[u8],
    ) -> CosignVerifyOutcome {
        self.outcome.lock().expect("stub mutex").clone()
    }
}

// ── Walker ────────────────────────────────────────────────────────

/// Walk `image_dir` and produce a [`VerifyReport`].
///
/// `policy` is optional. When `None`, missing pillars and
/// failed-but-not-policy-required pillars are reported as
/// `PillarVerdict` non-`Found` states without short-circuiting —
/// the caller (CLI) can choose to print a verdict table and exit 0
/// (informational) or escalate.
///
/// When `Some`, every pillar the policy mandates must be Found AND
/// every gate (slsa.level, sign.identity regex, builder_id, sbom
/// format) must pass. The first failure short-circuits with the
/// matching `VerifyError`.
pub fn verify(
    image_dir: &Path,
    policy: Option<&Policy>,
    cosign: &dyn CosignVerifyInvoker,
) -> Result<VerifyReport, VerifyError> {
    let image = ImageDir::open(image_dir)?;
    let primary_digest = image.descriptor().primary_manifest_digest.clone();

    // Pre-classify referrers.
    let mut slsa_blob: Option<(String, Vec<u8>)> = None;
    let mut sbom_blob: Option<(String, String, Vec<u8>)> = None; // (artifactType, digest, bytes)
    let mut sig_blob: Option<(String, Vec<u8>)> = None;

    for ref_desc in &image.descriptor().referrer_manifests {
        let ref_manifest_path = image.blob_path(&ref_desc.digest)?;
        let ref_bytes = std::fs::read(&ref_manifest_path).map_err(|source| VerifyError::Io {
            path: ref_manifest_path,
            source,
        })?;
        let ref_manifest: ReferrerManifest = serde_json::from_slice(&ref_bytes)
            .map_err(|e| VerifyError::MalformedBlob {
                digest: ref_desc.digest.clone(),
                detail: format!("referrer manifest JSON: {e}"),
            })?;
        // The artifact bytes live in the first layer of the referrer
        // manifest (OCI 1.1 referrer convention used by attest).
        let layer = match ref_manifest.layers.first() {
            Some(l) => l,
            None => {
                // No payload layer — skip this referrer; it doesn't
                // describe anything we can verify.
                continue;
            }
        };
        let artifact_type = ref_manifest
            .artifact_type
            .clone()
            .or_else(|| ref_desc.artifact_type.clone())
            .unwrap_or_else(|| layer.media_type.clone());

        let layer_path = image.blob_path(&layer.digest)?;
        let layer_bytes = std::fs::read(&layer_path).map_err(|source| VerifyError::Io {
            path: layer_path,
            source,
        })?;

        match classify_artifact_type(&artifact_type) {
            ArtifactClass::Slsa => slsa_blob = Some((layer.digest.clone(), layer_bytes)),
            ArtifactClass::Sbom => {
                sbom_blob = Some((artifact_type.clone(), layer.digest.clone(), layer_bytes))
            }
            ArtifactClass::Signature => sig_blob = Some((layer.digest.clone(), layer_bytes)),
            ArtifactClass::Unknown => { /* tolerate — future expansion */ }
        }
    }

    // ── SLSA pillar ────────────────────────────────────────
    let slsa_verdict = match &slsa_blob {
        Some((digest, bytes)) => match validate_slsa_statement(bytes, &primary_digest) {
            Ok(slsa_info) => PillarVerdict::Found {
                detail: format!(
                    "SLSA in-toto v1, builder={}, spec_hash={}, blob={}",
                    slsa_info.builder_id, slsa_info.spec_hash, digest
                ),
            },
            Err(e) => return Err(e),
        },
        None => PillarVerdict::Missing,
    };

    // ── SBOM pillar ────────────────────────────────────────
    let sbom_verdict = match &sbom_blob {
        Some((media_type, digest, bytes)) => match validate_sbom(bytes, media_type) {
            Ok(()) => PillarVerdict::Found {
                detail: format!("{media_type}, blob={digest}"),
            },
            Err(e) => return Err(e),
        },
        None => PillarVerdict::Missing,
    };

    // ── Signature pillar ───────────────────────────────────
    let sig_verdict = match &sig_blob {
        Some((digest, bytes)) => {
            match cosign.verify(&primary_digest, bytes) {
                CosignVerifyOutcome::VerifiedAndRecorded { log_index } => PillarVerdict::Found {
                    detail: format!("cosign verified, rekor logIndex={log_index}, blob={digest}"),
                },
                CosignVerifyOutcome::VerifiedNotRecorded { reason } => PillarVerdict::Failed {
                    detail: format!("cosign verified but Rekor not recorded: {reason}"),
                },
                CosignVerifyOutcome::InvalidSignature { stderr } => PillarVerdict::Failed {
                    detail: format!("cosign rejected signature: {stderr}"),
                },
                CosignVerifyOutcome::CosignNotInstalled => PillarVerdict::Failed {
                    detail: "cosign not installed; signature blob present but unverified".into(),
                },
            }
        }
        None => PillarVerdict::Missing,
    };

    let report = VerifyReport {
        manifest_digest: primary_digest,
        slsa: slsa_verdict,
        sbom: sbom_verdict,
        signature: sig_verdict,
    };

    if let Some(p) = policy {
        apply_policy(&report, p, &slsa_blob)?;
    }

    Ok(report)
}

#[derive(Debug)]
enum ArtifactClass {
    Slsa,
    Sbom,
    Signature,
    Unknown,
}

fn classify_artifact_type(t: &str) -> ArtifactClass {
    if t == MEDIA_TYPE_IN_TOTO {
        ArtifactClass::Slsa
    } else if t == MEDIA_TYPE_CYCLONEDX || t == MEDIA_TYPE_SPDX {
        ArtifactClass::Sbom
    } else if t == MEDIA_TYPE_COSIGN_SIG {
        ArtifactClass::Signature
    } else if t.contains("cyclonedx") || t.contains("spdx") {
        // Tolerate vendor-suffix variants ("…+cyclonedx", "…+spdx").
        ArtifactClass::Sbom
    } else if t.contains("cosign") {
        ArtifactClass::Signature
    } else {
        ArtifactClass::Unknown
    }
}

#[derive(Debug)]
struct SlsaInfo {
    spec_hash: String,
    builder_id: String,
    claimed_level: i64,
}

/// Validate the SLSA in-toto Statement's structural integrity.
///
/// Checks (per the task spec):
///
/// 1. predicateType == `https://slsa.dev/provenance/v1`
/// 2. subject contains the artifact's manifest digest
/// 3. externalParameters.spec_hash exists
fn validate_slsa_statement(
    bytes: &[u8],
    expected_manifest_digest: &str,
) -> Result<SlsaInfo, VerifyError> {
    let stmt: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| VerifyError::SlsaMalformed {
            detail: format!("statement is not JSON: {e}"),
        })?;

    let predicate_type = stmt
        .get("predicateType")
        .and_then(|v| v.as_str())
        .ok_or_else(|| VerifyError::SlsaMalformed {
            detail: "missing predicateType".into(),
        })?;
    if predicate_type != SLSA_PROVENANCE_V1 {
        return Err(VerifyError::SlsaMalformed {
            detail: format!(
                "predicateType {predicate_type:?} != {SLSA_PROVENANCE_V1:?}"
            ),
        });
    }

    // Subject: an array of {name, digest:{sha256:<hex>}}. Check the
    // expected manifest digest's hex appears in any subject.
    let expected_hex = expected_manifest_digest
        .split_once(':')
        .map(|(_, h)| h)
        .unwrap_or(expected_manifest_digest);

    let subjects = stmt.get("subject").and_then(|v| v.as_array()).ok_or_else(|| {
        VerifyError::SlsaMalformed {
            detail: "missing or non-array subject".into(),
        }
    })?;
    let mut found_subject = false;
    for s in subjects {
        if let Some(d) = s.get("digest").and_then(|v| v.as_object()) {
            for (_algo, val) in d {
                if val.as_str() == Some(expected_hex) {
                    found_subject = true;
                }
            }
        }
    }
    if !found_subject {
        return Err(VerifyError::SlsaMalformed {
            detail: format!(
                "no subject digest matches expected manifest digest {expected_manifest_digest}"
            ),
        });
    }

    let predicate = stmt.get("predicate").ok_or_else(|| VerifyError::SlsaMalformed {
        detail: "missing predicate".into(),
    })?;
    let bd = predicate
        .get("buildDefinition")
        .ok_or_else(|| VerifyError::SlsaMalformed {
            detail: "missing predicate.buildDefinition".into(),
        })?;
    let ep = bd
        .get("externalParameters")
        .ok_or_else(|| VerifyError::SlsaMalformed {
            detail: "missing buildDefinition.externalParameters".into(),
        })?;
    let spec_hash = ep
        .get("spec_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| VerifyError::SlsaMalformed {
            detail: "missing externalParameters.spec_hash".into(),
        })?
        .to_string();

    let claimed_level = ep
        .get("claimed_slsa_level")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);

    let builder_id = predicate
        .get("runDetails")
        .and_then(|v| v.get("builder"))
        .and_then(|v| v.get("id"))
        .and_then(|v| v.as_str())
        .unwrap_or("<unknown>")
        .to_string();

    Ok(SlsaInfo {
        spec_hash,
        builder_id,
        claimed_level,
    })
}

/// Validate the SBOM's structural integrity. We do not parse the
/// full SBOM schema — we check it is JSON and matches the
/// declared media type's expected `bomFormat` / `spdxVersion`.
fn validate_sbom(bytes: &[u8], media_type: &str) -> Result<(), VerifyError> {
    let v: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| {
        VerifyError::MalformedBlob {
            digest: "<sbom>".into(),
            detail: format!("SBOM is not JSON: {e}"),
        }
    })?;
    if media_type.contains("cyclonedx") {
        let format = v.get("bomFormat").and_then(|x| x.as_str()).unwrap_or("");
        if format != "CycloneDX" {
            return Err(VerifyError::MalformedBlob {
                digest: "<sbom>".into(),
                detail: format!("CycloneDX SBOM has bomFormat {format:?}, expected \"CycloneDX\""),
            });
        }
    } else if media_type.contains("spdx") {
        let v_ver = v.get("spdxVersion").and_then(|x| x.as_str()).unwrap_or("");
        if !v_ver.starts_with("SPDX-") {
            return Err(VerifyError::MalformedBlob {
                digest: "<sbom>".into(),
                detail: format!("SPDX SBOM has spdxVersion {v_ver:?}, expected SPDX-x.y"),
            });
        }
    }
    Ok(())
}

fn apply_policy(
    report: &VerifyReport,
    policy: &Policy,
    slsa_blob: &Option<(String, Vec<u8>)>,
) -> Result<(), VerifyError> {
    // SLSA presence + level.
    if let Some(min_level) = policy.slsa_min_level {
        match (&report.slsa, slsa_blob) {
            (PillarVerdict::Missing, _) => return Err(VerifyError::SlsaMissing),
            (_, Some((_, bytes))) => {
                let info = validate_slsa_statement(bytes, &report.manifest_digest)?;
                if info.claimed_level < min_level {
                    return Err(VerifyError::PolicyViolation {
                        rule: "slsa.level".into(),
                        detail: format!(
                            "claimed_slsa_level {} < required {}",
                            info.claimed_level, min_level
                        ),
                    });
                }
            }
            _ => {
                return Err(VerifyError::PolicyViolation {
                    rule: "slsa.level".into(),
                    detail: "SLSA pillar required but unreadable".into(),
                });
            }
        }
    }

    // Builder id exact match.
    if let Some(expected_builder) = &policy.builder_id {
        match slsa_blob {
            Some((_, bytes)) => {
                let info = validate_slsa_statement(bytes, &report.manifest_digest)?;
                if &info.builder_id != expected_builder {
                    return Err(VerifyError::PolicyViolation {
                        rule: "sign.builder_id".into(),
                        detail: format!(
                            "builder_id {:?} != expected {:?}",
                            info.builder_id, expected_builder
                        ),
                    });
                }
            }
            None => {
                return Err(VerifyError::PolicyViolation {
                    rule: "sign.builder_id".into(),
                    detail: "no SLSA statement to read builder_id from".into(),
                });
            }
        }
    }

    // Signature presence.
    if policy.require_signature {
        match &report.signature {
            PillarVerdict::Found { .. } => {}
            PillarVerdict::Missing => return Err(VerifyError::SignatureMissing),
            PillarVerdict::Failed { detail } => {
                return Err(VerifyError::SignatureInvalid {
                    detail: detail.clone(),
                });
            }
        }
    }

    // SBOM format gate.
    if let Some(expected_formats) = &policy.sbom_formats {
        match &report.sbom {
            PillarVerdict::Missing => return Err(VerifyError::SbomMissing),
            PillarVerdict::Found { detail } => {
                let matches = expected_formats.iter().any(|f| detail.contains(f));
                if !matches {
                    return Err(VerifyError::PolicyViolation {
                        rule: "sbom.format".into(),
                        detail: format!(
                            "SBOM media type does not match any of {expected_formats:?} (got: {detail})"
                        ),
                    });
                }
            }
            PillarVerdict::Failed { detail } => {
                return Err(VerifyError::PolicyViolation {
                    rule: "sbom.format".into(),
                    detail: detail.clone(),
                });
            }
        }
    }

    Ok(())
}

// ── helpers ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct ReferrerManifest {
    #[serde(default, rename = "artifactType")]
    artifact_type: Option<String>,
    #[serde(default)]
    layers: Vec<ReferrerLayer>,
}

#[derive(Debug, Deserialize)]
struct ReferrerLayer {
    #[serde(rename = "mediaType")]
    media_type: String,
    digest: String,
    #[allow(dead_code)]
    size: u64,
}

fn extract_rekor_log_index(bundle_bytes: &[u8]) -> Option<u64> {
    let v: serde_json::Value = serde_json::from_slice(bundle_bytes).ok()?;
    let payload = v.get("rekorBundle")?.get("Payload")?;
    payload.get("logIndex").and_then(|x| x.as_u64())
}

fn write_payload_tempfile(content: &str) -> std::io::Result<PathBuf> {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "ocimage-verify-payload-{}-{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::write(&path, content)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Catches: a refactor that loosens classify_artifact_type to map
    // SLSA-flavoured strings to SBOM, or vice versa, would silently
    // mis-tag every referrer and verify would always report
    // "missing" / "wrong pillar found".
    #[test]
    fn test_classify_artifact_type_in_toto_is_slsa() {
        assert!(matches!(
            classify_artifact_type(MEDIA_TYPE_IN_TOTO),
            ArtifactClass::Slsa
        ));
    }

    #[test]
    fn test_classify_artifact_type_cyclonedx_is_sbom() {
        assert!(matches!(
            classify_artifact_type(MEDIA_TYPE_CYCLONEDX),
            ArtifactClass::Sbom
        ));
    }

    #[test]
    fn test_classify_artifact_type_spdx_is_sbom() {
        assert!(matches!(
            classify_artifact_type(MEDIA_TYPE_SPDX),
            ArtifactClass::Sbom
        ));
    }

    #[test]
    fn test_classify_artifact_type_cosign_is_signature() {
        assert!(matches!(
            classify_artifact_type(MEDIA_TYPE_COSIGN_SIG),
            ArtifactClass::Signature
        ));
    }

    #[test]
    fn test_classify_artifact_type_unknown_is_unknown() {
        assert!(matches!(
            classify_artifact_type("application/octet-stream"),
            ArtifactClass::Unknown
        ));
    }

    // Catches: a SLSA validator that drops the predicateType check
    // would let a bogus statement (wrong predicate URI but right
    // shape) pass verification — silently lying about provenance.
    #[test]
    fn test_validate_slsa_statement_rejects_wrong_predicate_type() {
        let stmt = serde_json::json!({
            "predicateType": "https://example.com/wrong/predicate",
            "subject": [{ "name": "x", "digest": { "sha256": "abc" } }],
            "predicate": {
                "buildDefinition": {
                    "externalParameters": { "spec_hash": "sha256:zzz" }
                },
                "runDetails": {}
            }
        });
        let bytes = serde_json::to_vec(&stmt).unwrap();
        let err = validate_slsa_statement(&bytes, "sha256:abc").unwrap_err();
        match err {
            VerifyError::SlsaMalformed { detail } => {
                assert!(detail.contains("predicateType"));
            }
            other => panic!("expected SlsaMalformed, got {other:?}"),
        }
    }

    // Catches: a SLSA validator that doesn't check the subject
    // digest against the manifest would let a SLSA statement
    // attesting to a DIFFERENT artifact pass verification — i.e.
    // accepting cross-artifact provenance fraud.
    #[test]
    fn test_validate_slsa_statement_rejects_wrong_subject_digest() {
        let stmt = serde_json::json!({
            "predicateType": SLSA_PROVENANCE_V1,
            "subject": [{ "name": "x", "digest": { "sha256": "wrong-hex" } }],
            "predicate": {
                "buildDefinition": {
                    "externalParameters": { "spec_hash": "sha256:zzz" }
                },
                "runDetails": {}
            }
        });
        let bytes = serde_json::to_vec(&stmt).unwrap();
        let err = validate_slsa_statement(&bytes, "sha256:abc").unwrap_err();
        match err {
            VerifyError::SlsaMalformed { detail } => {
                assert!(detail.contains("subject digest"));
            }
            other => panic!("expected SlsaMalformed, got {other:?}"),
        }
    }

    // Catches: a SLSA validator that ignores externalParameters.spec_hash
    // would silently accept a statement that doesn't pin the build to
    // a spec — provenance becomes worthless.
    #[test]
    fn test_validate_slsa_statement_rejects_missing_spec_hash() {
        let stmt = serde_json::json!({
            "predicateType": SLSA_PROVENANCE_V1,
            "subject": [{ "name": "x", "digest": { "sha256": "abc" } }],
            "predicate": {
                "buildDefinition": { "externalParameters": {} },
                "runDetails": {}
            }
        });
        let bytes = serde_json::to_vec(&stmt).unwrap();
        let err = validate_slsa_statement(&bytes, "sha256:abc").unwrap_err();
        match err {
            VerifyError::SlsaMalformed { detail } => {
                assert!(detail.contains("spec_hash"));
            }
            other => panic!("expected SlsaMalformed, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_slsa_statement_extracts_builder_and_level() {
        // Catches: a future field-rename that drops the builder_id /
        // claimed_slsa_level extraction would break every policy
        // gate that compares to either field.
        let stmt = serde_json::json!({
            "predicateType": SLSA_PROVENANCE_V1,
            "subject": [{ "name": "x", "digest": { "sha256": "abc" } }],
            "predicate": {
                "buildDefinition": {
                    "externalParameters": {
                        "spec_hash": "sha256:zzz",
                        "claimed_slsa_level": 3
                    }
                },
                "runDetails": { "builder": { "id": "ci.example.com/runner" } }
            }
        });
        let bytes = serde_json::to_vec(&stmt).unwrap();
        let info = validate_slsa_statement(&bytes, "sha256:abc").unwrap();
        assert_eq!(info.spec_hash, "sha256:zzz");
        assert_eq!(info.builder_id, "ci.example.com/runner");
        assert_eq!(info.claimed_level, 3);
    }

    // Catches: SBOM validator that doesn't sanity-check `bomFormat`
    // would let a corrupt CycloneDX SBOM through — we'd report
    // "ok" while shipping unsafe data.
    #[test]
    fn test_validate_sbom_cyclonedx_rejects_wrong_bom_format() {
        let bytes = serde_json::to_vec(&serde_json::json!({ "bomFormat": "Other" })).unwrap();
        let err = validate_sbom(&bytes, MEDIA_TYPE_CYCLONEDX).unwrap_err();
        match err {
            VerifyError::MalformedBlob { detail, .. } => {
                assert!(detail.contains("CycloneDX"));
            }
            other => panic!("expected MalformedBlob, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_sbom_spdx_rejects_wrong_spdx_version() {
        // Catches: an SPDX validator that doesn't enforce the
        // version prefix would accept arbitrary JSON as an SPDX
        // SBOM — tools downstream then misinterpret it.
        let bytes = serde_json::to_vec(&serde_json::json!({ "spdxVersion": "1.0" })).unwrap();
        let err = validate_sbom(&bytes, MEDIA_TYPE_SPDX).unwrap_err();
        match err {
            VerifyError::MalformedBlob { detail, .. } => {
                assert!(detail.contains("SPDX"));
            }
            other => panic!("expected MalformedBlob, got {other:?}"),
        }
    }

    // Catches: extract_rekor_log_index regression that returns None
    // for a valid bundle with logIndex — verify would mis-classify
    // every signed artifact as VerifiedNotRecorded.
    #[test]
    fn test_extract_rekor_log_index_present_returns_value() {
        let bundle = serde_json::to_vec(&serde_json::json!({
            "rekorBundle": { "Payload": { "logIndex": 7777 } }
        }))
        .unwrap();
        assert_eq!(extract_rekor_log_index(&bundle), Some(7777));
    }

    #[test]
    fn test_extract_rekor_log_index_missing_returns_none() {
        let bundle = b"{}";
        assert_eq!(extract_rekor_log_index(bundle), None);
    }

    // Catches: a stub invoker that doesn't actually return the
    // configured outcome — every test that depends on scripted
    // outcomes would silently no-op.
    #[test]
    fn test_stub_invoker_returns_configured_outcome() {
        let stub = StubCosignVerifyInvoker::new(CosignVerifyOutcome::VerifiedAndRecorded {
            log_index: 42,
        });
        let out = stub.verify("sha256:x", b"{}");
        assert_eq!(out, CosignVerifyOutcome::VerifiedAndRecorded { log_index: 42 });
    }
}
