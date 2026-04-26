//! Attestation helper — reads a build's `build-manifest.json` and
//! produces an `Attestation` via the `attest` crate.
//!
//! This is the thin glue between:
//!   * `oci-build`'s on-disk artefact + `BuildManifest` format
//!   * `attest`'s `BuildContext` + `attest_build` pipeline
//!
//! The publish-side facades (`publish_http`, `push_oci`) call into
//! this module when `--attest` is passed. A rendered Statement JSON
//! is written alongside the publish output as an unsigned or
//! cosign-signed sidecar per ADR-016 pillars B + C.

use std::path::Path;
use std::sync::Arc;

use attest::api::attestation::{Attestation, Subject};
use attest::core::slsa_builder::{ArtifactDigest, BuildContext, PackageRecord};
use attest::saf::config::AttestConfig;
use attest::saf::facade::attest_build;
use attest::spi::{Attester, CosignAttester, NoopAttester};

use oci_build::api::error::Error as BuildError;
use oci_build::api::manifest::{BuildManifest, INSTALLER_FAMILY_ALPINE_APK};

/// How to sign the attestation.
///
/// Parallels the attester modes exposed by the `attest` crate but
/// flattened to a CLI-friendly enum. `Unsigned` is the dev default
/// (no cosign required); the cosign variants require the `cosign`
/// binary on PATH.
#[derive(Debug, Clone)]
pub enum AttestMode {
    /// No real signing. Produces an Attestation with
    /// `Signature::unsigned()` — never valid for production
    /// verifiers. Useful for dev loops and CI without cosign.
    Unsigned,
    /// Keyless OIDC flow via cosign. `identity` is the expected
    /// OIDC subject (GitHub workflow URI in CI). Cosign must be on
    /// PATH and OIDC must be reachable.
    CosignKeyless { identity: String },
    /// Keyed mode via cosign. Supply a cosign keyfile path.
    CosignKeyed {
        key_path: std::path::PathBuf,
        identity: String,
    },
}

impl AttestMode {
    /// Build the matching `Attester` trait object.
    fn attester(&self) -> Arc<dyn Attester> {
        match self {
            AttestMode::Unsigned => Arc::new(NoopAttester::new()),
            AttestMode::CosignKeyless { identity } => {
                Arc::new(CosignAttester::keyless(identity.clone()))
            }
            AttestMode::CosignKeyed { key_path, identity } => Arc::new(
                CosignAttester::with_key(key_path.clone(), identity.clone()),
            ),
        }
    }
}

/// Produce an `Attestation` for the artefacts under `build_dir`.
///
/// Reads `build-manifest.json` from the build output, translates
/// each field into the `attest::core::BuildContext` shape, then
/// drives the `attest` crate's one-call pipeline.
///
/// `subject_name` is what ends up in the Statement's `subject.name`
/// field. For `publish-http` it's the image id; for `push` it's the
/// full OCI reference.
///
/// `builder_id` is the identity to embed in the SLSA predicate.
/// In CI: the GitHub workflow run URL. In local builds: an
/// operator-chosen identifier. Defaults apply if empty.
pub fn attest_build_dir(
    build_dir: &Path,
    subject_name: &str,
    builder_id: &str,
    mode: AttestMode,
) -> Result<Attestation, AttestationError> {
    let manifest_path = build_dir.join("build-manifest.json");
    let manifest_bytes = std::fs::read(&manifest_path).map_err(|e| AttestationError::Io {
        path: manifest_path.clone(),
        source: e,
    })?;
    let manifest: BuildManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| AttestationError::ManifestParse { detail: format!("{e}") })?;

    let spec_sha256 = manifest
        .spec_sha256
        .clone()
        .unwrap_or_else(|| "0".repeat(64));

    let artifacts = vec![
        ArtifactDigest {
            name: "kernel".into(),
            sha256: manifest.artifacts.kernel_sha256.clone(),
        },
        ArtifactDigest {
            name: "initrd.cpio".into(),
            sha256: manifest.artifacts.initrd_cpio_sha256.clone(),
        },
        ArtifactDigest {
            name: "rootfs.ext4".into(),
            sha256: manifest.artifacts.rootfs_ext4_sha256.clone(),
        },
        ArtifactDigest {
            name: "config.json".into(),
            sha256: manifest.artifacts.config_json_sha256.clone(),
        },
    ];

    let packages = manifest
        .packages
        .requested
        .iter()
        .map(|name| PackageRecord {
            name: name.clone(),
            version: String::new(),
            family: manifest
                .packages
                .installer_family
                .clone()
                .unwrap_or_else(|| "unknown".into()),
        })
        .collect();

    let ctx = BuildContext {
        spec_sha256,
        builder_id: if builder_id.is_empty() {
            "local-operator".into()
        } else {
            builder_id.to_string()
        },
        artifacts,
        packages,
        started_at_unix: manifest.build_time_unix,
        finished_at_unix: manifest.build_time_unix,
    };

    // The subject's digest_sha256 is the content-identifier for the
    // artefact as a whole. In a single-artifact world we typically
    // use the rootfs.ext4 digest since that's the biggest payload;
    // verifiers can cross-check any of the four via the predicate's
    // byproducts.
    let subject = Subject {
        name: subject_name.to_string(),
        digest_sha256: manifest.artifacts.rootfs_ext4_sha256.clone(),
    };

    let config = AttestConfig {
        subject,
        attester: mode.attester(),
    };

    attest_build(&ctx, &config).map_err(|e| AttestationError::AttestFailed {
        detail: format!("{e}"),
    })
}

/// Produce a CycloneDX v1.5 SBOM from a build's `build-manifest.json`.
///
/// Pillar C of ADR-016. The returned JSON bytes are a valid
/// CycloneDX v1.5 document — Grype / Trivy / dependency-track
/// consume them without surface-scanning the rootfs filesystem.
///
/// Components produced:
///   * one `type: "file"` entry per `manifest.files[]` — carries the
///     host-side SHA256 as a CycloneDX hash plus `oci:path` +
///     `oci:mode` properties so verifiers can map the component
///     back to the guest filesystem entry.
///   * one `type: "library"` entry per `manifest.packages.requested[]`
///     — carries a `pkg:` purl when `installer_family` is known
///     (currently only `alpine_apk`).
///
/// A `metadata.component` of type `operating-system` is always
/// emitted, identifying the image as a whole (id, parsed version,
/// description). When both files and packages are empty the
/// `components` array is empty — that is a valid CycloneDX
/// document and intentionally is NOT backfilled with placeholders.
///
/// Hand-rolled with `serde_json::json!` for the same reason the
/// attestation emitter avoids a cyclonedx-specific crate: the shape
/// is small, stable, and tested here.
pub fn sbom_from_build_dir(build_dir: &Path) -> Result<Vec<u8>, AttestationError> {
    let manifest_path = build_dir.join("build-manifest.json");
    let manifest_bytes = std::fs::read(&manifest_path).map_err(|e| AttestationError::Io {
        path: manifest_path.clone(),
        source: e,
    })?;
    let manifest: BuildManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| AttestationError::ManifestParse { detail: format!("{e}") })?;

    let sbom = build_cyclonedx_document(&manifest);
    serde_json::to_vec_pretty(&sbom).map_err(|e| AttestationError::AttestFailed {
        detail: format!("SBOM serialisation failed: {e}"),
    })
}

/// Split an image id like `"llmboot:0.1.14"` into (name, version).
/// When no `:` is present, version is `"unknown"` per the run-book's
/// DoD — we never silently drop the version field.
fn parse_image_id_version(id: &str) -> (&str, &str) {
    match id.split_once(':') {
        Some((name, version)) if !version.is_empty() => (name, version),
        _ => (id, "unknown"),
    }
}

/// Return the final path segment of a `/`-or-`\`-separated path.
/// Used for CycloneDX `component.name` on file components. Falls
/// back to the whole string if no separator is present (defensive
/// — `BuildManifest.files[].dest` is always an absolute guest path
/// in practice).
fn basename_of(path: &str) -> &str {
    // Split on both separators so Windows-shaped dest strings
    // (unlikely for a Linux guest path but cheap to cover) behave.
    path.rsplit(|c| c == '/' || c == '\\').next().unwrap_or(path)
}

/// Construct the CycloneDX document for a given manifest.
/// Separated from `sbom_from_build_dir` so unit tests can drive it
/// synchronously without a temp-dir round-trip.
fn build_cyclonedx_document(manifest: &BuildManifest) -> serde_json::Value {
    use serde_json::json;

    let (image_name, image_version) = parse_image_id_version(&manifest.id);

    let mut components: Vec<serde_json::Value> = Vec::new();

    // Files → `type: "file"` components. Each carries the host-side
    // SHA256 both as a short `version` prefix (CycloneDX consumers
    // surface this in UIs) and as a full `hashes[]` entry (the
    // authoritative field for verifiers).
    for f in &manifest.files {
        let short = f.sha256.get(..12).unwrap_or(f.sha256.as_str()).to_string();
        let mode_octal = f
            .mode
            .map(|m| format!("{m:o}"))
            .unwrap_or_else(String::new);

        let mut props = vec![json!({
            "name": "oci:path",
            "value": f.dest,
        })];
        if !mode_octal.is_empty() {
            props.push(json!({
                "name": "oci:mode",
                "value": mode_octal,
            }));
        }

        components.push(json!({
            "type": "file",
            "name": basename_of(&f.dest),
            "version": short,
            "hashes": [
                {
                    "alg": "SHA-256",
                    "content": f.sha256,
                }
            ],
            "properties": props,
        }));
    }

    // Packages → `type: "library"` components. We only know how to
    // mint a purl for installer families we've explicitly mapped;
    // for everything else we omit `purl` rather than fabricate one
    // (a wrong purl is worse than no purl because CVE scanners
    // key off it).
    let family = manifest.packages.installer_family.as_deref();
    for pkg_name in &manifest.packages.requested {
        let mut component = json!({
            "type": "library",
            "name": pkg_name,
        });

        if let Some(purl) = purl_for(family, pkg_name) {
            component["purl"] = json!(purl);
        }

        if let Some(fam) = family {
            component["properties"] = json!([
                {
                    "name": "oci:installer_family",
                    "value": fam,
                }
            ]);
        }

        components.push(component);
    }

    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "operating-system",
                "name": image_name,
                "version": image_version,
                "description": manifest.description,
            }
        },
        "components": components,
    })
}

/// Minted-purl table. Kept deliberately small: only families where
/// we can produce a purl that CVE scanners will actually match
/// against upstream feeds. Extend as we add installer families.
fn purl_for(family: Option<&str>, name: &str) -> Option<String> {
    match family? {
        INSTALLER_FAMILY_ALPINE_APK => Some(format!("pkg:apk/alpine/{name}?arch=x86_64")),
        _ => None,
    }
}

/// Write an attestation's Statement JSON to disk alongside the
/// publish output. The file is named `attestation.json` by default;
/// verifiers can pair it with the artifacts by checking the
/// `subject.digest_sha256` field against the published artifact's
/// digest.
pub fn write_attestation_statement(
    attestation: &Attestation,
    output_path: &Path,
) -> Result<(), AttestationError> {
    let statement_bytes = attest::core::emit::emit_statement(attestation.statement())
        .map_err(|e| AttestationError::AttestFailed {
            detail: format!("{e}"),
        })?;
    std::fs::write(output_path, &statement_bytes).map_err(|e| AttestationError::Io {
        path: output_path.to_path_buf(),
        source: e,
    })?;
    Ok(())
}

/// Errors that can fire from the attestation-helper path.
///
/// Kept separate from `BuildError` because the attest-side failures
/// (manifest-not-found, JSON parse, cosign unavailable) have
/// different recoveries than build errors.
#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    #[error("i/o: {path:?}: {source}")]
    Io {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("build-manifest.json parse failed: {detail}")]
    ManifestParse { detail: String },
    #[error("attestation failed: {detail}")]
    AttestFailed { detail: String },
}

// Convenience conversion so publish facades can surface a single
// Error type to the CLI.
impl From<AttestationError> for BuildError {
    fn from(e: AttestationError) -> Self {
        BuildError::Config {
            message: format!("{e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oci_build::api::manifest::{
        ArtifactDigests, BuildManifest, FileManifestEntry, PackageManifest,
    };
    use std::fs;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "attest-helper-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample_manifest() -> BuildManifest {
        BuildManifest {
            schema_version: 1,
            id: "example:1.0".into(),
            description: "test".into(),
            build_time_unix: 1_700_000_000,
            spec_sha256: Some("a".repeat(64)),
            artifacts: ArtifactDigests {
                kernel_sha256: "b".repeat(64),
                initrd_cpio_sha256: "c".repeat(64),
                rootfs_ext4_sha256: "d".repeat(64),
                config_json_sha256: "e".repeat(64),
            },
            packages: PackageManifest {
                installer_family: Some("apk".into()),
                requested: vec!["ca-certificates".into(), "openssl".into()],
            },
            files: vec![FileManifestEntry {
                source: "downloads/llmd".into(),
                dest: "/usr/bin/llmd".into(),
                sha256: "f".repeat(64),
                mode: Some(0o755),
            }],
        }
    }

    #[test]
    fn test_attest_build_dir_reads_manifest_and_produces_slsa() {
        let dir = temp_dir("reads-manifest");
        fs::write(
            dir.join("build-manifest.json"),
            serde_json::to_vec_pretty(&sample_manifest()).unwrap(),
        )
        .unwrap();

        let att = attest_build_dir(&dir, "example:1.0", "https://ci.example.com/run/1", AttestMode::Unsigned).unwrap();

        // Subject — name round-trips, digest is rootfs.ext4.
        assert_eq!(att.statement().subject.name, "example:1.0");
        assert_eq!(att.statement().subject.digest_sha256, "d".repeat(64));

        // Predicate type is SLSA provenance.
        assert_eq!(
            att.statement().predicate_type,
            "https://slsa.dev/provenance/v1"
        );

        // Unsigned sentinel because mode = Unsigned.
        assert!(att.signature().is_unsigned());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_attest_reports_packages_in_resolved_dependencies() {
        let dir = temp_dir("packages");
        fs::write(
            dir.join("build-manifest.json"),
            serde_json::to_vec_pretty(&sample_manifest()).unwrap(),
        )
        .unwrap();

        let att = attest_build_dir(&dir, "example:1.0", "test", AttestMode::Unsigned).unwrap();

        // Serialize the predicate and grep for package names.
        let json = serde_json::to_string(&att.statement().predicate).unwrap();
        assert!(json.contains("ca-certificates"));
        assert!(json.contains("openssl"));
        // purl format: pkg:apk/<name>
        assert!(json.contains("pkg:apk/"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_missing_manifest_returns_io_error() {
        let dir = temp_dir("missing");
        // Note: no build-manifest.json written.
        let err = attest_build_dir(&dir, "example:1.0", "test", AttestMode::Unsigned)
            .unwrap_err();
        assert!(matches!(err, AttestationError::Io { .. }));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_malformed_manifest_returns_parse_error() {
        let dir = temp_dir("malformed");
        fs::write(dir.join("build-manifest.json"), b"not json at all").unwrap();
        let err = attest_build_dir(&dir, "example:1.0", "test", AttestMode::Unsigned)
            .unwrap_err();
        assert!(matches!(err, AttestationError::ManifestParse { .. }));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_write_statement_to_disk() {
        let dir = temp_dir("write-sidecar");
        fs::write(
            dir.join("build-manifest.json"),
            serde_json::to_vec_pretty(&sample_manifest()).unwrap(),
        )
        .unwrap();

        let att = attest_build_dir(&dir, "example:1.0", "test", AttestMode::Unsigned).unwrap();
        let sidecar = dir.join("attestation.json");
        write_attestation_statement(&att, &sidecar).unwrap();

        // Statement parse-round-trip.
        let bytes = fs::read(&sidecar).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            parsed["_type"].as_str().unwrap(),
            "https://in-toto.io/Statement/v1"
        );
        assert_eq!(
            parsed["predicateType"].as_str().unwrap(),
            "https://slsa.dev/provenance/v1"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_sbom_from_build_dir_emits_cyclonedx_with_files_and_packages() {
        let dir = temp_dir("sbom");
        fs::write(
            dir.join("build-manifest.json"),
            serde_json::to_vec_pretty(&sample_manifest()).unwrap(),
        )
        .unwrap();

        let sbom_bytes = sbom_from_build_dir(&dir).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&sbom_bytes).unwrap();
        assert_eq!(parsed["bomFormat"], "CycloneDX");
        assert_eq!(parsed["specVersion"], "1.5");

        // Top-level metadata.component always populated.
        let mc = &parsed["metadata"]["component"];
        assert_eq!(mc["type"], "operating-system");
        assert_eq!(mc["name"], "example");
        assert_eq!(mc["version"], "1.0");
        assert_eq!(mc["description"], "test");

        // 1 file + 2 packages = 3 components.
        let components = parsed["components"].as_array().unwrap();
        assert_eq!(components.len(), 3);

        let names: Vec<&str> = components
            .iter()
            .map(|c| c["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"ca-certificates"));
        assert!(names.contains(&"openssl"));
        assert!(names.contains(&"llmd"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_sbom_files_only_emits_file_components_with_sha256() {
        let dir = temp_dir("sbom-files-only");
        let mut m = sample_manifest();
        m.packages = PackageManifest {
            installer_family: None,
            requested: vec![],
        };
        fs::write(
            dir.join("build-manifest.json"),
            serde_json::to_vec_pretty(&m).unwrap(),
        )
        .unwrap();

        let sbom_bytes = sbom_from_build_dir(&dir).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&sbom_bytes).unwrap();

        let components = parsed["components"].as_array().unwrap();
        assert_eq!(components.len(), 1);
        let c = &components[0];
        assert_eq!(c["type"], "file");
        assert_eq!(c["name"], "llmd");
        // Full SHA256 under hashes[0].content — the authoritative field.
        assert_eq!(c["hashes"][0]["alg"], "SHA-256");
        assert_eq!(c["hashes"][0]["content"], "f".repeat(64));
        // Properties carry the guest path + octal mode.
        let props = c["properties"].as_array().unwrap();
        let path_prop = props.iter().find(|p| p["name"] == "oci:path").unwrap();
        assert_eq!(path_prop["value"], "/usr/bin/llmd");
        let mode_prop = props.iter().find(|p| p["name"] == "oci:mode").unwrap();
        assert_eq!(mode_prop["value"], "755");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_sbom_packages_only_emits_alpine_apk_purls() {
        let dir = temp_dir("sbom-pkgs-only");
        let mut m = sample_manifest();
        m.files = vec![];
        m.packages = PackageManifest {
            installer_family: Some(INSTALLER_FAMILY_ALPINE_APK.into()),
            requested: vec!["nginx".into(), "openssl".into()],
        };
        fs::write(
            dir.join("build-manifest.json"),
            serde_json::to_vec_pretty(&m).unwrap(),
        )
        .unwrap();

        let sbom_bytes = sbom_from_build_dir(&dir).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&sbom_bytes).unwrap();

        let components = parsed["components"].as_array().unwrap();
        assert_eq!(components.len(), 2);
        for c in components {
            assert_eq!(c["type"], "library");
            let name = c["name"].as_str().unwrap();
            assert_eq!(
                c["purl"].as_str().unwrap(),
                format!("pkg:apk/alpine/{name}?arch=x86_64")
            );
            // installer_family surfaced as a property.
            let props = c["properties"].as_array().unwrap();
            let fam = props
                .iter()
                .find(|p| p["name"] == "oci:installer_family")
                .unwrap();
            assert_eq!(fam["value"], INSTALLER_FAMILY_ALPINE_APK);
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_sbom_unknown_installer_family_omits_purl() {
        let dir = temp_dir("sbom-unknown-fam");
        let mut m = sample_manifest();
        m.files = vec![];
        m.packages = PackageManifest {
            installer_family: Some("gentoo_portage".into()), // not in our table
            requested: vec!["gcc".into()],
        };
        fs::write(
            dir.join("build-manifest.json"),
            serde_json::to_vec_pretty(&m).unwrap(),
        )
        .unwrap();

        let sbom_bytes = sbom_from_build_dir(&dir).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&sbom_bytes).unwrap();
        let c = &parsed["components"][0];
        assert_eq!(c["type"], "library");
        assert_eq!(c["name"], "gcc");
        // A wrong purl is worse than no purl (CVE scanners key off it),
        // so we MUST omit it rather than fabricate.
        assert!(c.get("purl").is_none(), "unknown family must NOT emit purl");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_sbom_empty_spec_emits_empty_components_but_keeps_metadata() {
        let dir = temp_dir("sbom-empty");
        let mut m = sample_manifest();
        m.files = vec![];
        m.packages = PackageManifest {
            installer_family: None,
            requested: vec![],
        };
        fs::write(
            dir.join("build-manifest.json"),
            serde_json::to_vec_pretty(&m).unwrap(),
        )
        .unwrap();

        let sbom_bytes = sbom_from_build_dir(&dir).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&sbom_bytes).unwrap();

        // Empty components is a VALID CycloneDX doc — don't fabricate.
        assert_eq!(parsed["components"].as_array().unwrap().len(), 0);
        // But metadata.component is still populated.
        assert_eq!(parsed["metadata"]["component"]["name"], "example");
        assert_eq!(parsed["metadata"]["component"]["version"], "1.0");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_sbom_image_id_without_colon_defaults_version_to_unknown() {
        let dir = temp_dir("sbom-no-version");
        let mut m = sample_manifest();
        m.id = "bareimage".into();
        fs::write(
            dir.join("build-manifest.json"),
            serde_json::to_vec_pretty(&m).unwrap(),
        )
        .unwrap();

        let sbom_bytes = sbom_from_build_dir(&dir).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&sbom_bytes).unwrap();
        assert_eq!(parsed["metadata"]["component"]["name"], "bareimage");
        assert_eq!(parsed["metadata"]["component"]["version"], "unknown");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_empty_builder_id_defaults_to_local_operator() {
        let dir = temp_dir("empty-builder");
        fs::write(
            dir.join("build-manifest.json"),
            serde_json::to_vec_pretty(&sample_manifest()).unwrap(),
        )
        .unwrap();

        let att = attest_build_dir(&dir, "example:1.0", "", AttestMode::Unsigned).unwrap();
        let json = serde_json::to_string(&att.statement().predicate).unwrap();
        assert!(
            json.contains("local-operator"),
            "empty builder_id should fall back to 'local-operator', got: {json}"
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
