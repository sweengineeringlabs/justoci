//! `ocimage inspect <spec-or-ref>`.
//!
//! Two modes (auto-detected, same rule as `sbom`):
//!
//! - **spec mode**: print the canonical (JCS) bytes + the spec hash.
//!   Useful for debugging "why does my hash differ between hosts?"
//!   — eyeball the canonical form for whitespace / ordering drift.
//! - **image mode**: print the manifest digest, config digest, each
//!   layer's media type + digest, and each referrer descriptor's
//!   artifactType + digest.

use std::path::Path;

use serde_json::Value;
use spec::{canonical_bytes, parse_and_validate, spec_hash};

use oci_publish::ImageDir;

use crate::error::CliError;

/// Output of an `inspect` invocation. The CLI writes the rendered
/// text to stdout; carrying the structured form here lets tests
/// assert specific fields without parsing the rendered text.
#[derive(Debug)]
pub enum InspectOutput {
    Spec {
        canonical_json: Vec<u8>,
        spec_hash: String,
    },
    Image {
        manifest_digest: String,
        config_digest: String,
        config_media_type: String,
        layers: Vec<LayerInfo>,
        referrers: Vec<ReferrerInfo>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerInfo {
    pub media_type: String,
    pub digest: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferrerInfo {
    pub artifact_type: String,
    pub digest: String,
    pub size: u64,
}

/// Run inspect. Auto-detects mode by `<input>/oci-layout` presence.
pub fn run(input: &Path) -> Result<InspectOutput, CliError> {
    if input.is_dir() && input.join("oci-layout").is_file() {
        return run_image_mode(input);
    }
    if input.is_file() {
        return run_spec_mode(input);
    }
    Err(CliError::Cli {
        detail: format!(
            "inspect <spec-or-ref>: {} is neither a TOML file nor an OCI image-layout dir",
            input.display()
        ),
    })
}

fn run_spec_mode(spec_path: &Path) -> Result<InspectOutput, CliError> {
    let loaded = parse_and_validate(spec_path)?;
    let canonical = canonical_bytes(&loaded.spec)?;
    let h = spec_hash(&loaded.spec)?;
    Ok(InspectOutput::Spec {
        canonical_json: canonical,
        spec_hash: h.to_string(),
    })
}

fn run_image_mode(image_dir: &Path) -> Result<InspectOutput, CliError> {
    let image = ImageDir::open(image_dir).map_err(oci_publish::PublishError::from)?;
    let desc = image.descriptor();
    let manifest_digest = desc.primary_manifest_digest.clone();
    let config_descriptor = desc.config.clone();
    let layers = desc
        .layers
        .iter()
        .map(|d| LayerInfo {
            media_type: d.media_type.clone(),
            digest: d.digest.clone(),
            size: d.size,
        })
        .collect();
    let mut referrers = Vec::with_capacity(desc.referrer_manifests.len());
    for r in &desc.referrer_manifests {
        let manifest_path = image
            .blob_path(&r.digest)
            .map_err(oci_publish::PublishError::from)?;
        let bytes = std::fs::read(&manifest_path).map_err(|source| CliError::CliIo {
            path: manifest_path.display().to_string(),
            source,
        })?;
        let v: Value = serde_json::from_slice(&bytes).map_err(|e| CliError::Cli {
            detail: format!("malformed referrer manifest {}: {e}", r.digest),
        })?;
        let artifact_type = v
            .get("artifactType")
            .and_then(|x| x.as_str())
            .or_else(|| r.artifact_type.as_deref())
            .unwrap_or("<unknown>")
            .to_string();
        referrers.push(ReferrerInfo {
            artifact_type,
            digest: r.digest.clone(),
            size: r.size,
        });
    }
    Ok(InspectOutput::Image {
        manifest_digest,
        config_digest: config_descriptor.digest,
        config_media_type: config_descriptor.media_type,
        layers,
        referrers,
    })
}
