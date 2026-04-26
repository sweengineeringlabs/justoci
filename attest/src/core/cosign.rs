//! Cosign-based signing with mandatory Rekor coupling.
//!
//! ## Coupling guarantee
//!
//! Per spec doc Production Guarantee §6: a `Signature` value is only
//! produced when **both**
//!
//! 1. cosign successfully signed the manifest digest, and
//! 2. the resulting signature was confirmed in Rekor.
//!
//! If step 1 fails → `AttestError::SignFailed { stderr }`.
//! If step 1 succeeds but step 2 fails → `AttestError::SignNotRecorded
//! { rekor_error }`. The artifact is unsigned in that state — there
//! is no half-state where we record the signature blob without a
//! Rekor receipt.
//!
//! ## Subprocess vs SDK
//!
//! v0 invokes the `cosign` binary as a subprocess. Pulling
//! `sigstore-rs` would add a non-trivial dep tree (rustls, oauth2,
//! etc.). The trade-off is documented: operators must have `cosign`
//! installed (>=2.0) to sign with justoci. If it's missing we
//! return `AttestError::CosignNotInstalled` — distinct from
//! `SignFailed`, because there's nothing to retry; the host tooling
//! is missing.
//!
//! ## Testability
//!
//! The `CosignInvoker` trait isolates the subprocess boundary. Tests
//! supply a `StubCosignInvoker` that returns scripted outcomes
//! without touching PATH. Production calls pass `RealCosignInvoker`,
//! which spawns the actual `cosign sign-blob --bundle ...`
//! subprocess. The bundle JSON cosign emits already contains the
//! Rekor inclusion proof + log index, so "Rekor confirmed" reduces
//! to "the bundle has a populated `rekorBundle.Payload.logIndex`"
//! at parse time. Cosign bundles without a Rekor entry indicate
//! `--no-tlog-upload` was set, and we treat that as "not recorded".

use std::path::PathBuf;
use std::process::{Command, Stdio};

use cas::{Cas, Digest};
use serde_json::Value;
use spec::{SignConfig, SignKind};

use crate::api::attestation::Signature;
use crate::api::error::AttestError;

/// Cosign signature media type for OCI 1.1 referrers. Cosign's
/// "simple signing" format wraps the DSSE envelope in a
/// content-addressable JSON document.
const COSIGN_MEDIA_TYPE: &str = "application/vnd.dev.cosign.simplesigning.v1+json";

/// Outcome of a single cosign invocation, normalised so the calling
/// code (which is responsible for the coupling check) can branch on
/// it without parsing stderr.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CosignOutcome {
    /// cosign succeeded AND the bundle contains a Rekor inclusion
    /// proof. `bundle_bytes` is the cosign bundle JSON; `log_index`
    /// is the parsed Rekor log index.
    SignedAndRecorded {
        bundle_bytes: Vec<u8>,
        log_index: u64,
    },
    /// cosign succeeded but the bundle has no Rekor entry (typical
    /// of `--no-tlog-upload` or a Rekor outage). Per spec §6 this
    /// surfaces as `SignNotRecorded`. `reason` describes why the
    /// Rekor entry was absent — for operators reading the error.
    SignedNotRecorded { reason: String },
    /// cosign itself returned a non-zero exit code.
    SignFailed { stderr: String },
    /// `cosign` is not on PATH. Distinct from a spawn IO error
    /// because the actionable response is "install cosign".
    CosignNotInstalled,
}

/// Description of a cosign invocation — what we're signing with what
/// configuration. Used by `StubCosignInvoker` to assert the right
/// arguments were passed without spawning a process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CosignInvocation {
    pub manifest_digest: Digest,
    pub kind: SignKind,
    pub identity: Option<String>,
}

/// Indirection over `cosign` invocation. Production uses
/// `RealCosignInvoker`; tests use `StubCosignInvoker` to inject
/// outcomes (sign+rekor success, sign-success-rekor-fail,
/// sign-fail, cosign-missing).
pub trait CosignInvoker: Send + Sync {
    fn invoke(&self, invocation: &CosignInvocation) -> CosignOutcome;
}

/// Production `CosignInvoker` — spawns `cosign sign-blob ...`.
pub struct RealCosignInvoker;

impl RealCosignInvoker {
    pub fn new() -> Self {
        RealCosignInvoker
    }
}

impl Default for RealCosignInvoker {
    fn default() -> Self {
        Self::new()
    }
}

impl CosignInvoker for RealCosignInvoker {
    fn invoke(&self, invocation: &CosignInvocation) -> CosignOutcome {
        if !cosign_on_path() {
            return CosignOutcome::CosignNotInstalled;
        }

        // Materialise the manifest-digest string as a payload file
        // — cosign sign-blob signs the bytes of a file, and we want
        // to sign the digest string itself (the OCI digest is a
        // stable identifier for the artifact). A future iteration
        // signing the manifest *bytes* would fetch them from CAS;
        // we keep v0 simple by signing the digest string.
        let payload_path = match write_payload_tempfile(invocation.manifest_digest.to_string()) {
            Ok(p) => p,
            Err(e) => {
                return CosignOutcome::SignFailed {
                    stderr: format!("could not write cosign payload temp file: {e}"),
                };
            }
        };
        let bundle_path = payload_path.with_extension("bundle.json");

        let mut cmd = Command::new("cosign");
        cmd.arg("sign-blob")
            .arg("--yes")
            .arg("--bundle")
            .arg(&bundle_path);

        match invocation.kind {
            SignKind::CosignKey => {
                let key_path = match invocation.identity.as_ref() {
                    Some(p) => p,
                    None => {
                        let _ = std::fs::remove_file(&payload_path);
                        return CosignOutcome::SignFailed {
                            stderr: "cosign-key mode requires sign.identity to point at a keyfile"
                                .to_string(),
                        };
                    }
                };
                cmd.arg("--key").arg(key_path);
            }
            SignKind::CosignKeyless => {
                if let Some(identity) = invocation.identity.as_ref() {
                    cmd.arg("--identity-token").arg(identity);
                }
            }
            SignKind::Off => {
                let _ = std::fs::remove_file(&payload_path);
                // The caller (`sign_with`) short-circuits Off before
                // ever invoking the trait; reaching here is a bug.
                return CosignOutcome::SignFailed {
                    stderr: "cosign invoker called with SignKind::Off (programmer error)"
                        .to_string(),
                };
            }
        }

        cmd.arg(&payload_path);
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        let output = match cmd.output() {
            Ok(o) => o,
            Err(e) => {
                let _ = std::fs::remove_file(&payload_path);
                return CosignOutcome::SignFailed {
                    stderr: format!("failed to run cosign sign-blob: {e}"),
                };
            }
        };

        if !output.status.success() {
            let _ = std::fs::remove_file(&payload_path);
            let _ = std::fs::remove_file(&bundle_path);
            return CosignOutcome::SignFailed {
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            };
        }

        // Read the bundle file cosign wrote. Parse it for the Rekor
        // log index — its presence is our coupling check.
        let bundle_bytes = match std::fs::read(&bundle_path) {
            Ok(b) => b,
            Err(e) => {
                let _ = std::fs::remove_file(&payload_path);
                return CosignOutcome::SignedNotRecorded {
                    reason: format!("cosign succeeded but bundle file unreadable: {e}"),
                };
            }
        };

        let _ = std::fs::remove_file(&payload_path);
        let _ = std::fs::remove_file(&bundle_path);

        match extract_rekor_log_index(&bundle_bytes) {
            Some(log_index) => CosignOutcome::SignedAndRecorded {
                bundle_bytes,
                log_index,
            },
            None => CosignOutcome::SignedNotRecorded {
                reason: "cosign bundle has no rekorBundle.Payload.logIndex (Rekor entry not recorded — likely --no-tlog-upload or Rekor outage)".to_string(),
            },
        }
    }
}

/// Test `CosignInvoker` — returns a scripted outcome.
///
/// `expected_invocation` (when set) is used by tests to assert the
/// right arguments reached the invoker. `outcome` is what the stub
/// returns. Stored under a `Mutex` so the trait can stay
/// `Send + Sync` while tests still observe state.
pub struct StubCosignInvoker {
    outcome: std::sync::Mutex<CosignOutcome>,
    last_invocation: std::sync::Mutex<Option<CosignInvocation>>,
}

impl StubCosignInvoker {
    pub fn new(outcome: CosignOutcome) -> Self {
        StubCosignInvoker {
            outcome: std::sync::Mutex::new(outcome),
            last_invocation: std::sync::Mutex::new(None),
        }
    }

    /// Returns the most recent invocation passed to `invoke`, or
    /// `None` if `invoke` was never called.
    pub fn last_invocation(&self) -> Option<CosignInvocation> {
        self.last_invocation.lock().expect("stub mutex").clone()
    }
}

impl CosignInvoker for StubCosignInvoker {
    fn invoke(&self, invocation: &CosignInvocation) -> CosignOutcome {
        *self.last_invocation.lock().expect("stub mutex") = Some(invocation.clone());
        self.outcome.lock().expect("stub mutex").clone()
    }
}

/// Sign `manifest_digest` per `sign_cfg` using `invoker`, store the
/// resulting bundle in `cas`, and return a `Signature`.
///
/// Returns `Ok(None)` if signing is opted out (`SignKind::Off`).
/// All other variants are typed errors per `AttestError`.
pub fn sign_with(
    manifest_digest: &Digest,
    sign_cfg: &SignConfig,
    cas: &dyn Cas,
    invoker: &dyn CosignInvoker,
) -> Result<Option<Signature>, AttestError> {
    if sign_cfg.kind == SignKind::Off {
        return Ok(None);
    }

    let invocation = CosignInvocation {
        manifest_digest: manifest_digest.clone(),
        kind: sign_cfg.kind,
        identity: sign_cfg.identity.clone(),
    };

    match invoker.invoke(&invocation) {
        CosignOutcome::SignedAndRecorded {
            bundle_bytes,
            log_index,
        } => {
            let size = bundle_bytes.len() as u64;
            let bundle_digest = cas.put(&bundle_bytes)?;
            Ok(Some(Signature {
                bundle_digest,
                size,
                media_type: COSIGN_MEDIA_TYPE,
                rekor_log_index: log_index,
                identity: sign_cfg
                    .identity
                    .clone()
                    .unwrap_or_else(|| "<unspecified>".to_string()),
            }))
        }
        CosignOutcome::SignedNotRecorded { reason } => Err(AttestError::SignNotRecorded {
            rekor_error: reason,
        }),
        CosignOutcome::SignFailed { stderr } => Err(AttestError::SignFailed { stderr }),
        CosignOutcome::CosignNotInstalled => Err(AttestError::CosignNotInstalled),
    }
}

/// Walk `PATH` looking for an executable named `cosign` (or
/// `cosign.exe` on Windows). Returns `false` if the env var is
/// unset, the directories don't exist, or no executable matches.
fn cosign_on_path() -> bool {
    let exe_names: &[&str] = if cfg!(windows) {
        &["cosign.exe", "cosign"]
    } else {
        &["cosign"]
    };

    let path_var = match std::env::var_os("PATH") {
        Some(p) => p,
        None => return false,
    };

    for dir in std::env::split_paths(&path_var) {
        for name in exe_names {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return true;
            }
        }
    }
    false
}

fn write_payload_tempfile(content: String) -> std::io::Result<PathBuf> {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "justoci-cosign-payload-{}-{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::write(&path, content)?;
    Ok(path)
}

fn extract_rekor_log_index(bundle_bytes: &[u8]) -> Option<u64> {
    // Cosign bundle shape (v0.x):
    //   { "base64Signature": "...",
    //     "cert": "...",
    //     "rekorBundle": {
    //       "SignedEntryTimestamp": "...",
    //       "Payload": {
    //         "body": "...",
    //         "integratedTime": <int>,
    //         "logIndex": <int>,
    //         "logID": "..."
    //       }
    //     }
    //   }
    let v: Value = serde_json::from_slice(bundle_bytes).ok()?;
    let payload = v.get("rekorBundle")?.get("Payload")?;
    payload.get("logIndex").and_then(Value::as_u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cas::{Algorithm, Digest as CasDigest};

    fn fake_digest() -> CasDigest {
        CasDigest::from_bytes(Algorithm::Sha256, b"manifest-bytes")
    }

    #[test]
    fn test_extract_rekor_log_index_returns_value_when_present() {
        // Catches: a parser change that drops `logIndex` from the
        // bundle would cause every "signed" artifact to surface as
        // SignNotRecorded — silently failing the coupling check.
        let bundle = r#"{
            "base64Signature": "AAA",
            "rekorBundle": {
                "Payload": {
                    "logIndex": 12345,
                    "integratedTime": 1700000000
                }
            }
        }"#;
        assert_eq!(extract_rekor_log_index(bundle.as_bytes()), Some(12345));
    }

    #[test]
    fn test_extract_rekor_log_index_returns_none_when_rekor_block_missing() {
        // Catches: a bundle that signed without --tlog-upload would
        // have no rekorBundle. We must surface this as None so
        // sign_with returns SignNotRecorded, not a half-signed state.
        let bundle = r#"{ "base64Signature": "AAA", "cert": "..." }"#;
        assert_eq!(extract_rekor_log_index(bundle.as_bytes()), None);
    }

    #[test]
    fn test_extract_rekor_log_index_returns_none_for_malformed_json() {
        // Catches: a corrupt cosign bundle must not panic the
        // attestation pipeline — it must surface as None and bubble
        // up to SignNotRecorded with a clear reason.
        let bundle = b"not json at all";
        assert_eq!(extract_rekor_log_index(bundle), None);
    }

    #[test]
    fn test_stub_invoker_records_invocation() {
        // Catches: a regression where StubCosignInvoker drops the
        // invocation arguments would invalidate every test that
        // asserts the right SignKind / identity reached the invoker.
        let stub = StubCosignInvoker::new(CosignOutcome::CosignNotInstalled);
        assert_eq!(stub.last_invocation(), None);
        let inv = CosignInvocation {
            manifest_digest: fake_digest(),
            kind: SignKind::CosignKeyless,
            identity: Some("alice@example.com".into()),
        };
        let _ = stub.invoke(&inv);
        assert_eq!(stub.last_invocation(), Some(inv));
    }
}
