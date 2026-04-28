//! Single-layer `oci_artifact` spec — the simplest happy path.
//!
//! Bug this catches: a regression that hardcodes the 3-layer
//! vm_image shape, breaking the generic oras-style use case the
//! spec doc commits to.

mod common;

use std::fs;

use oci_build::build;

#[test]
fn test_oci_artifact_single_layer_no_compression_builds() {
    let work = tempfile::TempDir::new().unwrap();
    let blob = work.path().join("weights.gguf");
    // 4 KiB of pseudo-weights — enough for the test to be more than
    // a smoke check but not so large that it slows the suite.
    let mut payload = Vec::with_capacity(4096);
    for i in 0..4096u32 {
        payload.push((i as u8).wrapping_mul(7));
    }
    fs::write(&blob, &payload).unwrap();

    let toml_text = common::oci_artifact_toml(&blob);
    let spec = common::parse_spec(&toml_text, work.path());

    let output = work.path().join("out");
    let result = build(&spec, &output).expect("oci_artifact must build");

    // The single layer's digest must match SHA256(payload) exactly,
    // since `compression = none` (default for non-`+gzip`/`+zstd`
    // media types) means the source bytes ARE the layer bytes.
    assert_eq!(result.layer_digests.len(), 1);
    let expected = cas::Digest::from_bytes(cas::Algorithm::Sha256, &payload);
    assert_eq!(
        result.layer_digests[0], expected,
        "no-compression layer's digest must equal SHA256 of source bytes"
    );

    // Layer media type lands verbatim.
    let manifest_blob = output
        .join("blobs")
        .join("sha256")
        .join(result.manifest_digest.hex());
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_blob).unwrap()).unwrap();
    assert_eq!(
        manifest["layers"][0]["mediaType"],
        "application/vnd.ggml.weights.gguf"
    );
    assert_eq!(manifest["layers"].as_array().unwrap().len(), 1);
}

#[test]
fn test_raw_image_single_layer_builds_with_unknown_platform_handling() {
    // Bug this catches: the OCI image config field defaults
    // (`architecture`, `os`) blowing up for `os = "none"` (bare-
    // metal firmware). The spec validator allows it; the build
    // must too.
    let work = tempfile::TempDir::new().unwrap();
    let blob = work.path().join("firmware.bin");
    fs::write(&blob, b"FIRMWARE-PAYLOAD-BYTES").unwrap();

    let toml_text = common::raw_image_toml(&blob);
    let spec = common::parse_spec(&toml_text, work.path());

    let output = work.path().join("fw-out");
    let result = build(&spec, &output).expect("raw_image must build");
    assert_eq!(result.layer_digests.len(), 1);

    // Verify the config blob carries the spec's `os = "none"` and
    // `arch = "armv7"` verbatim.
    let config_blob = output
        .join("blobs")
        .join("sha256")
        .join(result.config_digest.hex());
    let config: serde_json::Value =
        serde_json::from_slice(&fs::read(&config_blob).unwrap()).unwrap();
    assert_eq!(config["os"], "none");
    assert_eq!(config["architecture"], "armv7");
}
