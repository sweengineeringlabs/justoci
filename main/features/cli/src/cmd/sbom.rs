//! `ocimage sbom <spec-or-ref> [-o <file>] [--format <cyclonedx|spdx>]`.
//!
//! Two modes, auto-detected from the input path:
//!
//! - **spec mode**: `<spec-or-ref>` is a `*.toml` file → parse +
//!   validate, run the SBOM emitter directly via
//!   `attest::core::sbom_cyclonedx` / `attest::core::sbom_spdx`,
//!   write the JSON to stdout (or `-o <file>`).
//! - **image mode**: `<spec-or-ref>` is a directory containing
//!   `oci-layout` → walk the referrer manifests, find the SBOM
//!   referrer, extract its blob bytes, write to stdout.
//!
//! Auto-detection is by `is_dir()` + `<dir>/oci-layout` presence.
//! A file that's not a TOML, or a dir that's not an OCI layout,
//! surfaces as `CliError::Cli` (exit 64).

use std::path::Path;

use cas::{Algorithm, Cas, Digest, MemCas};
use spec::{parse_and_validate, spec_hash};

use attest::core::sbom_cyclonedx::emit_cyclonedx;
use attest::core::sbom_spdx::emit_spdx;
use attest::BuiltArtifact;

use oci_publish::ImageDir;

use crate::error::CliError;

/// SBOM output format, chosen by `--format` (default cyclonedx).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbomFormat {
    CycloneDx,
    Spdx,
}

impl SbomFormat {
    pub fn parse(s: &str) -> Result<Self, CliError> {
        match s {
            "cyclonedx" => Ok(SbomFormat::CycloneDx),
            "spdx" => Ok(SbomFormat::Spdx),
            other => Err(CliError::Cli {
                detail: format!(
                    "--format: unknown SBOM format {other:?} (expected cyclonedx or spdx)"
                ),
            }),
        }
    }
}

/// Run the sbom subcommand. Returns the SBOM bytes the caller is
/// expected to write to stdout / -o file.
pub fn run(input: &Path, format: SbomFormat) -> Result<Vec<u8>, CliError> {
    if is_image_dir(input) {
        run_image_mode(input)
    } else if input.is_file() {
        run_spec_mode(input, format)
    } else {
        Err(CliError::Cli {
            detail: format!(
                "sbom <spec-or-ref>: {} is neither a TOML file nor an OCI image-layout dir",
                input.display()
            ),
        })
    }
}

fn is_image_dir(path: &Path) -> bool {
    path.is_dir() && path.join("oci-layout").is_file()
}

/// Emit a fresh SBOM from a spec (preview before build). We don't
/// have manifest/layer digests yet, so we synthesise digests from
/// the spec's *resolved layer source bytes* — a deterministic
/// stand-in that lets the SBOM enumerate components without
/// requiring a full build.
fn run_spec_mode(spec_path: &Path, format: SbomFormat) -> Result<Vec<u8>, CliError> {
    let loaded = parse_and_validate(spec_path)?;
    let canonical_hash = spec_hash(&loaded.spec)?;

    // Synthesise a BuiltArtifact. Digests for layers come from
    // hashing the resolved source files (or, for [[layers.files]],
    // a placeholder digest computed over the layer's TOML
    // representation). This is a *preview* — the real build
    // pipeline is the source of truth for final digests.
    let mut layer_digests: Vec<(usize, Digest)> = Vec::with_capacity(loaded.spec.layers.len());
    for (i, layer) in loaded.spec.layers.iter().enumerate() {
        let bytes_for_digest: Vec<u8> = match &layer.source {
            spec::LayerSource::Blob { path } => {
                let resolved = loaded.resolve(path);
                std::fs::read(&resolved).map_err(|source| CliError::CliIo {
                    path: resolved.display().to_string(),
                    source,
                })?
            }
            spec::LayerSource::Files { entries } => {
                // Stable preview hash — derived from the entry list
                // alone. The real build digests will differ; this
                // is an acceptable preview because the SBOM's
                // primary purpose at preview time is enumerating
                // components, not giving the final digest table.
                let preview = entries
                    .iter()
                    .map(|e| format!("{}|{}|{:o}", e.source.display(), e.dest, e.mode))
                    .collect::<Vec<_>>()
                    .join("\n");
                preview.into_bytes()
            }
        };
        layer_digests.push((i, Digest::from_bytes(Algorithm::Sha256, &bytes_for_digest)));
    }

    // Manifest/config digests aren't yet known — use the spec hash
    // as a stable proxy so the SBOM document has a well-formed
    // identity. This is a *preview*; the real digests appear in
    // the post-build SBOM at `ocimage sbom <built-dir>`.
    let manifest_proxy = canonical_hash.clone();
    let config_proxy = canonical_hash.clone();

    let built = BuiltArtifact::new(
        manifest_proxy,
        config_proxy,
        layer_digests,
        loaded.spec.clone(),
        canonical_hash,
    )
    .map_err(|e| CliError::Cli {
        detail: format!("internal: BuiltArtifact construction rejected spec preview: {e}"),
    })?;

    // Emit into a MemCas — we want the bytes back, not a stored blob.
    let mem = MemCas::new();
    let scope = loaded.spec.attestation.sbom.scope;
    let sbom = match format {
        SbomFormat::CycloneDx => emit_cyclonedx(&built, scope, &mem)?,
        SbomFormat::Spdx => emit_spdx(&built, scope, &mem)?,
    };
    let bytes = mem.get(&sbom.blob_digest).map_err(|e| CliError::Cli {
        detail: format!("internal: SBOM bytes not retrievable from MemCas: {e}"),
    })?;
    Ok(bytes)
}

/// Walk `image_dir`'s referrer manifests, find the SBOM referrer,
/// and return its layer-blob bytes.
fn run_image_mode(image_dir: &Path) -> Result<Vec<u8>, CliError> {
    let image = ImageDir::open(image_dir).map_err(oci_publish::PublishError::from)?;

    // Walk referrer descriptors. For each, read its manifest and
    // check artifactType.
    for ref_desc in &image.descriptor().referrer_manifests {
        let manifest_path = image
            .blob_path(&ref_desc.digest)
            .map_err(oci_publish::PublishError::from)?;
        let bytes = std::fs::read(&manifest_path).map_err(|source| CliError::CliIo {
            path: manifest_path.display().to_string(),
            source,
        })?;
        let v: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| CliError::Cli {
            detail: format!("malformed referrer manifest {}: {e}", ref_desc.digest),
        })?;
        let artifact_type = v
            .get("artifactType")
            .and_then(|x| x.as_str())
            .or(ref_desc.artifact_type.as_deref())
            .unwrap_or("");
        let is_sbom = artifact_type.contains("cyclonedx") || artifact_type.contains("spdx");
        if !is_sbom {
            continue;
        }
        // Extract the layer[0] blob digest — that's the SBOM bytes.
        let layer = v
            .get("layers")
            .and_then(|x| x.as_array())
            .and_then(|a| a.first())
            .ok_or_else(|| CliError::Cli {
                detail: format!("referrer manifest {} has no layers[]", ref_desc.digest),
            })?;
        let layer_digest = layer
            .get("digest")
            .and_then(|x| x.as_str())
            .ok_or_else(|| CliError::Cli {
                detail: format!(
                    "referrer manifest {} layer[0] missing digest",
                    ref_desc.digest
                ),
            })?;
        let layer_path = image
            .blob_path(layer_digest)
            .map_err(oci_publish::PublishError::from)?;
        let layer_bytes = std::fs::read(&layer_path).map_err(|source| CliError::CliIo {
            path: layer_path.display().to_string(),
            source,
        })?;
        return Ok(layer_bytes);
    }
    Err(CliError::Cli {
        detail: format!(
            "no SBOM referrer found in image dir {} (was the build attested?)",
            image_dir.display()
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Catches: parse() silently defaulting to CycloneDx for unknown
    // strings would mean `--format spxd` (typo) emits a CycloneDX
    // SBOM with no warning, and the operator ships the wrong format.
    #[test]
    fn test_parse_format_rejects_unknown() {
        let err = SbomFormat::parse("xml").unwrap_err();
        match err {
            CliError::Cli { detail } => assert!(detail.contains("unknown SBOM format")),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn test_parse_format_accepts_cyclonedx() {
        assert_eq!(
            SbomFormat::parse("cyclonedx").unwrap(),
            SbomFormat::CycloneDx
        );
    }

    #[test]
    fn test_parse_format_accepts_spdx() {
        assert_eq!(SbomFormat::parse("spdx").unwrap(), SbomFormat::Spdx);
    }
}
