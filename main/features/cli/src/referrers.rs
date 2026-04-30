//! Wire `attest::AttestationOutputs` into the OCI image dir as
//! OCI 1.1 referrer manifests + index.json updates.
//!
//! ## Why this lives in the CLI, not in `attest`
//!
//! `attest` produces blob-level outputs (SLSA / SBOM / signature
//! bytes addressed in a `Cas`). It deliberately does NOT mutate
//! `index.json` because the attest crate doesn't know what kind
//! of registry layout it's writing into — its `Cas` could be
//! the same on-disk dir as build's, or a separate CAS spool that
//! a later step copies into a registry. Wiring referrer manifests
//! into `index.json` is a layout-level concern that belongs at
//! whatever orchestrator is composing build + attest. For justoci
//! that orchestrator is the CLI; for vmisolate's pipeline it would
//! be a higher layer.
//!
//! ## What we write
//!
//! Per OCI 1.1 referrer convention:
//!
//! ```json
//! // index.json after this runs has the primary descriptor PLUS
//! // one descriptor per attestation output:
//! {
//!   "manifests": [
//!     { primary, no subject },
//!     { slsa-referrer-manifest, artifactType: "application/vnd.in-toto+json" },
//!     { sbom-referrer-manifest, artifactType: "application/vnd.cyclonedx+json" },
//!     { sig-referrer-manifest,  artifactType: "application/vnd.dev.cosign.simplesigning.v1+json" },
//!   ]
//! }
//! ```
//!
//! Each referrer manifest blob has the canonical OCI 1.1 shape:
//!
//! ```json
//! {
//!   "schemaVersion": 2,
//!   "mediaType": "application/vnd.oci.image.manifest.v1+json",
//!   "artifactType": "<the in-toto / cyclonedx / cosign type>",
//!   "config": {  empty config blob — sha256 of "{}", size 2 },
//!   "layers": [{ payload bytes — addressed by the digest attest
//!                already wrote into the CAS }],
//!   "subject": { primary manifest descriptor }
//! }
//! ```
//!
//! The "empty config" pattern is what oras + cosign use today and
//! what the `oci_publish::ImageDir` validator already accepts.

use std::path::Path;

use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

use attest::AttestationOutputs;

use crate::error::CliError;

const MEDIA_TYPE_OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const MEDIA_TYPE_OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
/// Canonical empty-config pattern. Bytes literally `{}` (2 bytes),
/// sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a.
const EMPTY_CONFIG_BYTES: &[u8] = b"{}";
const EMPTY_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.empty.v1+json";

/// Write referrer manifests for `outputs` into `image_dir` and
/// rewrite `index.json` to reference them. The primary manifest's
/// digest + size are required so each referrer's `subject` field
/// points at it.
///
/// Idempotent within a single build: re-running this on the same
/// `outputs` against the same `image_dir` re-writes the same
/// referrer manifest blobs (their digests are content-addressed,
/// so re-writing produces the same bytes at the same path) and
/// re-emits the same `index.json` JSON.
pub fn write_referrers_into_image_dir(
    image_dir: &Path,
    outputs: &AttestationOutputs,
    primary_manifest_digest: &str,
    primary_manifest_size: u64,
) -> Result<(), CliError> {
    // Read existing index.json so we can preserve the primary
    // descriptor and any existing referrer descriptors (e.g. from
    // a re-run that already wrote some).
    let index_path = image_dir.join("index.json");
    let index_bytes = std::fs::read(&index_path).map_err(|source| CliError::CliIo {
        path: index_path.display().to_string(),
        source,
    })?;
    let mut index: Value = serde_json::from_slice(&index_bytes).map_err(|e| CliError::Cli {
        detail: format!("malformed index.json at {}: {e}", index_path.display()),
    })?;

    // Ensure empty-config blob exists. Same content always, so
    // re-running is a no-op.
    write_blob_if_absent(image_dir, EMPTY_CONFIG_BYTES)?;
    let empty_cfg_digest = format!("sha256:{}", hex_sha256(EMPTY_CONFIG_BYTES));
    let empty_cfg_size = EMPTY_CONFIG_BYTES.len() as u64;

    let primary_subject = json!({
        "mediaType": MEDIA_TYPE_OCI_MANIFEST,
        "digest": primary_manifest_digest,
        "size": primary_manifest_size,
    });

    // For each attestation output, build a referrer manifest, write
    // it as a blob, add it to the index.
    let manifests = index
        .get_mut("manifests")
        .and_then(|v| v.as_array_mut())
        .ok_or_else(|| CliError::Cli {
            detail: "index.json has no manifests[] array".into(),
        })?;

    if let Some(slsa) = &outputs.slsa {
        let layer_descriptor = json!({
            "mediaType": slsa.media_type,
            "digest": slsa.blob_digest.to_string(),
            "size": slsa.size,
        });
        let referrer_desc = build_and_write_referrer_manifest(
            image_dir,
            slsa.media_type,
            layer_descriptor,
            empty_cfg_digest.clone(),
            empty_cfg_size,
            EMPTY_CONFIG_MEDIA_TYPE,
            primary_subject.clone(),
        )?;
        manifests.push(referrer_desc);
    }

    if let Some(sbom) = &outputs.sbom {
        let layer_descriptor = json!({
            "mediaType": sbom.media_type.as_str(),
            "digest": sbom.blob_digest.to_string(),
            "size": sbom.size,
        });
        let referrer_desc = build_and_write_referrer_manifest(
            image_dir,
            sbom.media_type.as_str(),
            layer_descriptor,
            empty_cfg_digest.clone(),
            empty_cfg_size,
            EMPTY_CONFIG_MEDIA_TYPE,
            primary_subject.clone(),
        )?;
        manifests.push(referrer_desc);
    }

    if let Some(sig) = &outputs.signature {
        let layer_descriptor = json!({
            "mediaType": sig.media_type,
            "digest": sig.bundle_digest.to_string(),
            "size": sig.size,
        });
        let referrer_desc = build_and_write_referrer_manifest(
            image_dir,
            sig.media_type,
            layer_descriptor,
            empty_cfg_digest.clone(),
            empty_cfg_size,
            EMPTY_CONFIG_MEDIA_TYPE,
            primary_subject.clone(),
        )?;
        manifests.push(referrer_desc);
    }

    // Ensure the index has its mediaType pinned (build emits this,
    // but we re-set defensively in case a future build crate change
    // omits it).
    if index.get("mediaType").is_none() {
        index["mediaType"] = json!(MEDIA_TYPE_OCI_INDEX);
    }

    // Atomic-rewrite index.json: write to .tmp, then rename.
    let tmp_path = index_path.with_extension("json.tmp");
    let serialised = serde_json::to_vec(&index).map_err(|e| CliError::Cli {
        detail: format!("failed to serialise index.json: {e}"),
    })?;
    std::fs::write(&tmp_path, &serialised).map_err(|source| CliError::CliIo {
        path: tmp_path.display().to_string(),
        source,
    })?;
    std::fs::rename(&tmp_path, &index_path).map_err(|source| CliError::CliIo {
        path: index_path.display().to_string(),
        source,
    })?;

    Ok(())
}

/// Build a referrer manifest, write it as a blob under `<image_dir>/blobs/sha256/<hex>`,
/// and return its descriptor (mediaType + digest + size + artifactType).
fn build_and_write_referrer_manifest(
    image_dir: &Path,
    artifact_type: &str,
    layer_descriptor: Value,
    config_digest: String,
    config_size: u64,
    config_media_type: &str,
    subject: Value,
) -> Result<Value, CliError> {
    // Build the manifest object. Field order matches OCI 1.1
    // canonical examples; serde_json::to_vec preserves declaration
    // order for json! macros.
    let manifest_value = json!({
        "schemaVersion": 2,
        "mediaType": MEDIA_TYPE_OCI_MANIFEST,
        "artifactType": artifact_type,
        "config": {
            "mediaType": config_media_type,
            "digest": config_digest,
            "size": config_size,
        },
        "layers": [layer_descriptor],
        "subject": subject,
    });
    let manifest_bytes = serde_json::to_vec(&manifest_value).map_err(|e| CliError::Cli {
        detail: format!("failed to serialise referrer manifest: {e}"),
    })?;
    let digest = format!("sha256:{}", hex_sha256(&manifest_bytes));
    let size = manifest_bytes.len() as u64;
    write_blob_if_absent(image_dir, &manifest_bytes)?;

    Ok(json!({
        "mediaType": MEDIA_TYPE_OCI_MANIFEST,
        "digest": digest,
        "size": size,
        "artifactType": artifact_type,
    }))
}

/// Write `bytes` under `<image_dir>/blobs/sha256/<hex>` if not
/// already present. Idempotent — re-writing the same bytes to the
/// same digest is a no-op.
fn write_blob_if_absent(image_dir: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let hex = hex_sha256(bytes);
    let blob_dir = image_dir.join("blobs").join("sha256");
    std::fs::create_dir_all(&blob_dir).map_err(|source| CliError::CliIo {
        path: blob_dir.display().to_string(),
        source,
    })?;
    let blob_path = blob_dir.join(&hex);
    if blob_path.is_file() {
        return Ok(());
    }
    // Atomic: write to a tmp sibling then rename.
    let tmp_path = blob_dir.join(format!(".{hex}.tmp-{}", std::process::id()));
    std::fs::write(&tmp_path, bytes).map_err(|source| CliError::CliIo {
        path: tmp_path.display().to_string(),
        source,
    })?;
    std::fs::rename(&tmp_path, &blob_path).map_err(|source| CliError::CliIo {
        path: blob_path.display().to_string(),
        source,
    })?;
    Ok(())
}

fn hex_sha256(bytes: &[u8]) -> String {
    let d = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in d {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Catches: a refactor that uses a different sha256 binding
    // (e.g. uppercase hex, different padding) — would silently
    // break agreement with the on-disk paths the cas crate
    // produces, leading to "blob missing" failures at publish-time.
    #[test]
    fn test_hex_sha256_lowercase_64_chars() {
        let h = hex_sha256(b"hello");
        assert_eq!(h.len(), 64);
        assert!(h
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
        // Anchor to the known sha256 of "hello" so this can't
        // silently regress.
        assert_eq!(
            h,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    // Catches: the empty-config sentinel drifting from the
    // canonical bytes — `oras` and `cosign` look for exactly
    // sha256:44136fa3... at size=2; if we emit different bytes
    // those tools fail to recognise our referrer artifacts.
    #[test]
    fn test_empty_config_bytes_are_canonical_two_bytes() {
        assert_eq!(EMPTY_CONFIG_BYTES, b"{}");
        assert_eq!(EMPTY_CONFIG_BYTES.len(), 2);
        assert_eq!(
            hex_sha256(EMPTY_CONFIG_BYTES),
            "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        );
    }
}
