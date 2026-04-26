//! End-to-end build of a vm_image spec into an OCI Image Layout v1.1.
//!
//! Bug this test catches: any regression in the wire shape of the
//! output directory — missing `oci-layout`, missing `index.json`,
//! wrong number of blobs, layer media types not preserved, or
//! manifest `schemaVersion` drifted from `2`. A passing test means
//! a downstream `oras pull` would still consume the artifact.

mod common;

use std::fs;

use oci_build::{build, MEDIA_TYPE_OCI_MANIFEST};

#[test]
fn test_vm_image_full_build_produces_complete_oci_layout() {
    let work = tempfile::TempDir::new().expect("tempdir");
    let fx = common::stage_vm_image_fixture(work.path());
    let toml_text = common::vm_image_toml(&fx);
    let spec = common::parse_spec(&toml_text, work.path());

    let output = work.path().join("out");
    let result = build(&spec, &output).expect("build must succeed");

    // ── Output directory shape ───────────────────────────────
    assert!(output.exists(), "output dir must exist");
    assert!(output.is_dir());

    let layout_path = output.join("oci-layout");
    assert!(
        layout_path.is_file(),
        "OCI Image Layout requires an `oci-layout` marker file"
    );
    let layout_bytes = fs::read(&layout_path).unwrap();
    let layout_value: serde_json::Value = serde_json::from_slice(&layout_bytes).unwrap();
    assert_eq!(layout_value["imageLayoutVersion"], "1.0.0");

    let index_path = output.join("index.json");
    assert!(index_path.is_file(), "OCI requires `index.json` at root");

    let blob_dir = output.join("blobs").join("sha256");
    assert!(blob_dir.is_dir(), "OCI mandates blobs/sha256/ directory");

    // 3 layer blobs + 1 config blob + 1 manifest blob = 5 entries.
    let blob_count = fs::read_dir(&blob_dir)
        .unwrap()
        .filter_map(Result::ok)
        .count();
    assert_eq!(
        blob_count, 5,
        "expected 3 layer blobs + 1 config + 1 manifest = 5; got {blob_count}"
    );

    // ── Manifest digest in index points at a real blob ──────
    let index_bytes = fs::read(&index_path).unwrap();
    let index_value: serde_json::Value = serde_json::from_slice(&index_bytes).unwrap();
    let manifest_descriptor = &index_value["manifests"][0];
    let manifest_digest_str = manifest_descriptor["digest"].as_str().unwrap();
    assert_eq!(manifest_digest_str, &result.manifest_digest.to_string());
    let manifest_blob_path = blob_dir.join(result.manifest_digest.hex());
    assert!(
        manifest_blob_path.is_file(),
        "manifest blob must exist at the digest the index points to"
    );

    // ── Manifest content invariants ─────────────────────────
    let manifest_bytes = fs::read(&manifest_blob_path).unwrap();
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes).unwrap();
    assert_eq!(
        manifest["schemaVersion"], 2,
        "OCI 1.1 mandates integer schemaVersion=2"
    );
    assert_eq!(
        manifest["mediaType"], MEDIA_TYPE_OCI_MANIFEST,
        "manifest mediaType must be the OCI manifest type"
    );

    // Layer media types must survive the pipeline verbatim.
    let layers = manifest["layers"].as_array().unwrap();
    assert_eq!(layers.len(), 3);
    assert_eq!(
        layers[0]["mediaType"],
        "application/vnd.vmisolate.kernel+binary"
    );
    assert_eq!(
        layers[1]["mediaType"],
        "application/vnd.vmisolate.initrd.cpio+gzip"
    );
    assert_eq!(
        layers[2]["mediaType"],
        "application/vnd.vmisolate.rootfs.ext4+gzip"
    );

    // Each layer descriptor's digest must point at an existing blob.
    for layer in layers {
        let digest = layer["digest"].as_str().unwrap();
        let hex = digest.strip_prefix("sha256:").unwrap();
        let blob = blob_dir.join(hex);
        assert!(
            blob.is_file(),
            "layer digest {digest} has no corresponding blob"
        );
    }

    // ── Annotations from the spec must be on the manifest ──
    assert_eq!(
        manifest["annotations"]["org.opencontainers.image.title"], "llmboot",
        "spec annotations must land on the OCI manifest unchanged"
    );

    // ── Config blob exists and matches descriptor digest ───
    let config_descriptor = &manifest["config"];
    let config_digest_str = config_descriptor["digest"].as_str().unwrap();
    assert_eq!(config_digest_str, &result.config_digest.to_string());
    assert_eq!(
        config_descriptor["mediaType"],
        "application/vnd.oci.image.config.v1+json"
    );
    assert!(blob_dir.join(result.config_digest.hex()).is_file());

    // ── No partial dir lingers after success ────────────────
    let partial = work.path().join("out.partial");
    assert!(
        !partial.exists(),
        "successful build must rename .partial to final, leaving no .partial"
    );
}
