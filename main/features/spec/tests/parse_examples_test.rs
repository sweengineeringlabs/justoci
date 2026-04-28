//! Validate that the three reference example specs in `examples/`
//! parse cleanly. These specs are the user-facing demonstrations of
//! v0 — if they don't parse, the documentation is broken.
//!
//! Each example is built without on-disk source files, so this
//! test deliberately bypasses the file-existence check by writing
//! placeholder source files into a tempdir alongside a copy of the
//! spec.

use std::fs;
use std::path::Path;

use spec::{parse_and_validate, Kind};
use tempfile::TempDir;

/// Stage `<spec>` plus zero-byte stand-ins for every layer's
/// `source = "..."` so the file-existence check passes.
fn stage_spec(name: &str, spec_text: &str, source_files: &[&str]) -> TempDir {
    let dir = TempDir::new().unwrap();
    let spec_path = dir.path().join(name);
    fs::write(&spec_path, spec_text).unwrap();

    for path in source_files {
        let target = dir.path().join(path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&target, b"").unwrap();
    }
    dir
}

#[test]
fn test_vm_image_example_parses() {
    let toml = include_str!("../../examples/vm-image.toml");
    let dir = stage_spec(
        "vm-image.toml",
        toml,
        &[
            "downloads/bzImage",
            "downloads/initrd.cpio",
            "downloads/rootfs-alpine.ext4",
        ],
    );
    let spec = parse_and_validate(dir.path().join("vm-image.toml"))
        .expect("parses")
        .spec;

    assert_eq!(spec.kind, Kind::VmImage);
    assert_eq!(spec.id.name, "llmboot");
    assert_eq!(spec.id.tag, "0.1.14");
    assert_eq!(spec.layers.len(), 3);
    // vm_image layer ordering — kernel, initrd, rootfs.
    assert!(spec.layers[0].media_type.as_str().contains("kernel"));
    assert!(spec.layers[1].media_type.as_str().contains("initrd"));
    assert!(spec.layers[2].media_type.as_str().contains("rootfs"));
    // Default attestation applies (no [attestation] block in this spec).
    assert!(matches!(spec.attestation.slsa.level, spec::SlsaLevel::L2));
    assert!(matches!(
        spec.attestation.sbom.format,
        spec::SbomFormat::CycloneDx
    ));
    assert!(matches!(
        spec.attestation.sign.kind,
        spec::SignKind::CosignKeyless
    ));
}

#[test]
fn test_oci_artifact_example_parses() {
    let toml = include_str!("../../examples/oci-artifact.toml");
    let dir = stage_spec("oci-artifact.toml", toml, &["weights/llama-7b.q4_0.gguf"]);
    let spec = parse_and_validate(dir.path().join("oci-artifact.toml"))
        .expect("parses")
        .spec;

    assert_eq!(spec.kind, Kind::OciArtifact);
    assert_eq!(spec.id.name, "ggml-llama-7b");
    assert_eq!(spec.layers.len(), 1);
    // SBOM explicitly off in this spec.
    assert!(matches!(
        spec.attestation.sbom.format,
        spec::SbomFormat::Off
    ));
}

#[test]
fn test_firmware_example_parses() {
    let toml = include_str!("../../examples/firmware.toml");
    let dir = stage_spec("firmware.toml", toml, &["build/firmware.bin"]);
    let spec = parse_and_validate(dir.path().join("firmware.toml"))
        .expect("parses")
        .spec;

    assert_eq!(spec.kind, Kind::RawImage);
    assert_eq!(spec.id.name, "device-firmware");
    assert_eq!(spec.layers.len(), 1);
    // Defaults applied (no [attestation] block).
    assert!(matches!(spec.attestation.slsa.level, spec::SlsaLevel::L2));
}

#[test]
fn test_unknown_field_is_rejected_by_serde() {
    // Production guarantee: `deny_unknown_fields` on every raw type.
    // A typo in a field name surfaces at parse time, not as silent
    // "I ignored your value".
    let toml = r#"
spec_version = "0"
id           = "x:1"
kind         = "raw_image"
typoed_field = "should be rejected"

[[layers]]
source     = "blob.bin"
media_type = "application/octet-stream"
"#;
    let dir = TempDir::new().unwrap();
    let spec_path = dir.path().join("typo.toml");
    fs::write(&spec_path, toml).unwrap();
    fs::write(dir.path().join("blob.bin"), b"").unwrap();

    let err = parse_and_validate(&spec_path).expect_err("must reject typoed_field");
    let msg = err.to_string();
    assert!(
        msg.contains("typoed_field") || msg.contains("unknown field"),
        "expected unknown-field message, got: {msg}"
    );
    let _ = Path::new(&spec_path);
}
