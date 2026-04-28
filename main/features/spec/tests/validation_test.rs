//! One test per validation rule. Each test names the bug it would
//! catch — no tautological assertions.

use std::fs;
use std::path::PathBuf;

use spec::{parse_and_validate_str, SpecError};
use tempfile::TempDir;

/// Stage a tempdir with the given spec text + a list of zero-byte
/// stand-in files. Returns (spec_text, spec_dir) for
/// `parse_and_validate_str`.
fn staged(spec_text: &str, files: &[&str]) -> (String, PathBuf) {
    let dir = TempDir::new().unwrap();
    for f in files {
        let target = dir.path().join(f);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&target, b"").unwrap();
    }
    let path = dir.path().to_path_buf();
    // We leak the TempDir on purpose — keeping it alive until the
    // test ends. The simpler approach (return TempDir) hits the
    // ergonomic cliff of needing `&` everywhere. For test code the
    // leak is fine: each test stages once and returns shortly.
    std::mem::forget(dir);
    (spec_text.to_string(), path)
}

const VALID_SPEC: &str = r#"
spec_version = "0"
id           = "valid:1.0.0"
kind         = "raw_image"

[[layers]]
source     = "blob.bin"
media_type = "application/vnd.firmware.raw+binary"
"#;

#[test]
fn test_valid_spec_round_trips() {
    // Anchor: confirms the test setup itself isn't broken before
    // any individual rule test fires.
    let (text, dir) = staged(VALID_SPEC, &["blob.bin"]);
    parse_and_validate_str(&text, dir).expect("baseline must parse");
}

#[test]
fn test_unsupported_spec_version_rejected() {
    // Bug it catches: a parser that accepted `spec_version = "1"`
    // by treating unknown versions as "future, probably fine" would
    // misinterpret v1+ specs as v0.
    let bad = VALID_SPEC.replace(r#"spec_version = "0""#, r#"spec_version = "99""#);
    let (text, dir) = staged(&bad, &["blob.bin"]);
    let err = parse_and_validate_str(&text, dir).expect_err("must reject");
    assert!(matches!(err, SpecError::UnsupportedSpecVersion { .. }));
}

#[test]
fn test_malformed_id_rejected() {
    // Bug it catches: an id parser that accepted "no colon" as a
    // valid id would break OCI registry pushes downstream where
    // name+tag are required.
    let bad = VALID_SPEC.replace(
        r#"id           = "valid:1.0.0""#,
        r#"id           = "no-colon-here""#,
    );
    let (text, dir) = staged(&bad, &["blob.bin"]);
    let err = parse_and_validate_str(&text, dir).expect_err("must reject");
    assert!(matches!(err, SpecError::MalformedId { .. }));
}

#[test]
fn test_uppercase_name_in_id_rejected() {
    // OCI registry refs forbid uppercase in the name component.
    // Bug it catches: a regex that accepted [a-zA-Z] for the name
    // body would push artifacts that some registries reject at
    // upload time.
    let bad = VALID_SPEC.replace(
        r#"id           = "valid:1.0.0""#,
        r#"id           = "VALID:1.0.0""#,
    );
    let (text, dir) = staged(&bad, &["blob.bin"]);
    let err = parse_and_validate_str(&text, dir).expect_err("must reject");
    assert!(matches!(err, SpecError::MalformedId { .. }));
}

#[test]
fn test_unknown_kind_rejected() {
    let bad = VALID_SPEC.replace(
        r#"kind         = "raw_image""#,
        r#"kind         = "container_image""#,
    );
    let (text, dir) = staged(&bad, &["blob.bin"]);
    let err = parse_and_validate_str(&text, dir).expect_err("must reject");
    assert!(matches!(err, SpecError::UnknownKind { .. }));
}

#[test]
fn test_raw_image_with_two_layers_rejected() {
    // raw_image must be exactly 1 layer.
    let bad = r#"
spec_version = "0"
id           = "valid:1.0.0"
kind         = "raw_image"

[[layers]]
source     = "blob.bin"
media_type = "application/vnd.firmware.raw+binary"

[[layers]]
source     = "blob2.bin"
media_type = "application/vnd.firmware.raw+binary"
"#
    .to_string();
    let (text, dir) = staged(&bad, &["blob.bin", "blob2.bin"]);
    let err = parse_and_validate_str(&text, dir).expect_err("must reject");
    assert!(matches!(
        err,
        SpecError::WrongLayerCount {
            kind: "raw_image",
            actual: 2,
            ..
        }
    ));
}

#[test]
fn test_vm_image_wrong_layer_order_rejected() {
    // vm_image MUST be kernel, initrd, rootfs in that order.
    // Bug it catches: an operator who reordered layers would ship
    // an image that boots the wrong blob first — broken at runtime.
    let bad = r#"
spec_version = "0"
id           = "vm:1"
kind         = "vm_image"

[[layers]]
source     = "rootfs"
media_type = "application/vnd.vmisolate.rootfs.ext4+gzip"

[[layers]]
source     = "initrd"
media_type = "application/vnd.vmisolate.initrd.cpio+gzip"

[[layers]]
source     = "kernel"
media_type = "application/vnd.vmisolate.kernel+binary"
"#;
    let (text, dir) = staged(bad, &["rootfs", "initrd", "kernel"]);
    let err = parse_and_validate_str(&text, dir).expect_err("must reject");
    assert!(matches!(
        err,
        SpecError::WrongLayerOrder {
            position: 0,
            expected_marker: "kernel",
            ..
        }
    ));
}

#[test]
fn test_layer_with_both_source_modes_rejected() {
    // Layer can declare `source = "..."` OR `[[layers.files]]`,
    // not both.
    let bad = r#"
spec_version = "0"
id           = "x:1"
kind         = "raw_image"

[[layers]]
source     = "blob.bin"
media_type = "application/octet-stream"

[[layers.files]]
source = "extra"
dest   = "/extra"
mode   = 0o644
"#;
    let (text, dir) = staged(bad, &["blob.bin", "extra"]);
    let err = parse_and_validate_str(&text, dir).expect_err("must reject");
    assert!(matches!(err, SpecError::LayerSourceConflict { .. }));
}

#[test]
fn test_layer_with_no_source_mode_rejected() {
    // Bug it catches: a parser that allowed neither would silently
    // produce empty layers later in the build pipeline.
    let bad = r#"
spec_version = "0"
id           = "x:1"
kind         = "raw_image"

[[layers]]
media_type = "application/octet-stream"
"#;
    let (text, dir) = staged(bad, &[]);
    let err = parse_and_validate_str(&text, dir).expect_err("must reject");
    assert!(matches!(err, SpecError::LayerSourceConflict { .. }));
}

#[test]
fn test_missing_source_file_rejected() {
    // Surfaces missing files at spec-load time, not halfway through
    // a build. Bug it catches: a build that started, compressed
    // some layers, then failed when trying to read a missing one
    // would leave behind partial output.
    let bad = r#"
spec_version = "0"
id           = "x:1"
kind         = "raw_image"

[[layers]]
source     = "does-not-exist.bin"
media_type = "application/octet-stream"
"#;
    let (text, dir) = staged(bad, &[]); // no source files staged
    let err = parse_and_validate_str(&text, dir).expect_err("must reject");
    assert!(matches!(err, SpecError::UnreadableSource { .. }));
}

#[test]
fn test_empty_files_block_rejected() {
    // An empty [[layers.files]] block is always a copy-paste error.
    let bad = r#"
spec_version = "0"
id           = "x:1"
kind         = "raw_image"

[[layers]]
media_type = "application/x-tar+gzip"
files      = []
"#;
    let (text, dir) = staged(bad, &[]);
    let err = parse_and_validate_str(&text, dir).expect_err("must reject");
    assert!(matches!(err, SpecError::EmptyFilesBlock { .. }));
}

#[test]
fn test_malformed_media_type_rejected() {
    // No slash separator.
    let bad = VALID_SPEC.replace(
        r#"media_type = "application/vnd.firmware.raw+binary""#,
        r#"media_type = "no-slash-here""#,
    );
    let (text, dir) = staged(&bad, &["blob.bin"]);
    let err = parse_and_validate_str(&text, dir).expect_err("must reject");
    assert!(matches!(err, SpecError::MalformedMediaType { .. }));
}

#[test]
fn test_unknown_compression_rejected() {
    let bad = VALID_SPEC.replace(
        r#"media_type = "application/vnd.firmware.raw+binary""#,
        r#"media_type = "application/vnd.firmware.raw+binary"
compression = "lz4""#,
    );
    let (text, dir) = staged(&bad, &["blob.bin"]);
    let err = parse_and_validate_str(&text, dir).expect_err("must reject");
    assert!(matches!(err, SpecError::UnknownCompression { .. }));
}

#[test]
fn test_default_compression_inferred_from_media_type_suffix() {
    // +gzip suffix → Gzip. +zstd → Zstd. Anything else → None.
    // Bug it catches: a "default to gzip always" change would
    // silently double-compress already-compressed blobs.
    use spec::Compression;
    let s = r#"
spec_version = "0"
id           = "x:1"
kind         = "oci_artifact"

[[layers]]
source     = "a.bin"
media_type = "application/x-tar+gzip"

[[layers]]
source     = "b.bin"
media_type = "application/x-tar+zstd"

[[layers]]
source     = "c.bin"
media_type = "application/octet-stream"
"#;
    let (text, dir) = staged(s, &["a.bin", "b.bin", "c.bin"]);
    let spec = parse_and_validate_str(&text, dir).expect("parses").spec;
    assert!(matches!(spec.layers[0].compression, Compression::Gzip));
    assert!(matches!(spec.layers[1].compression, Compression::Zstd));
    assert!(matches!(spec.layers[2].compression, Compression::None));
}

#[test]
fn test_slsa_level_out_of_range_rejected() {
    let bad = r#"
spec_version = "0"
id           = "x:1"
kind         = "raw_image"

[[layers]]
source     = "blob.bin"
media_type = "application/octet-stream"

[attestation.slsa]
level = 7
"#
    .to_string();
    let (text, dir) = staged(&bad, &["blob.bin"]);
    let err = parse_and_validate_str(&text, dir).expect_err("must reject");
    assert!(matches!(err, SpecError::SlsaLevelOutOfRange { got: 7 }));
}

#[test]
fn test_unknown_sbom_format_rejected() {
    let bad = r#"
spec_version = "0"
id           = "x:1"
kind         = "raw_image"

[[layers]]
source     = "blob.bin"
media_type = "application/octet-stream"

[attestation.sbom]
format = "swid"
"#
    .to_string();
    let (text, dir) = staged(&bad, &["blob.bin"]);
    let err = parse_and_validate_str(&text, dir).expect_err("must reject");
    assert!(matches!(err, SpecError::UnknownSbomFormat { .. }));
}

#[test]
fn test_cosign_key_without_identity_rejected() {
    // cosign-key without a key path is unusable — surface it now,
    // not at sign time.
    let bad = r#"
spec_version = "0"
id           = "x:1"
kind         = "raw_image"

[[layers]]
source     = "blob.bin"
media_type = "application/octet-stream"

[attestation.sign]
kind = "cosign-key"
"#
    .to_string();
    let (text, dir) = staged(&bad, &["blob.bin"]);
    let err = parse_and_validate_str(&text, dir).expect_err("must reject");
    assert!(matches!(err, SpecError::MissingSigningKeyPath));
}

#[test]
fn test_invalid_created_annotation_rejected() {
    // Reserved OCI annotation must be RFC3339.
    let bad = r#"
spec_version = "0"
id           = "x:1"
kind         = "raw_image"

[[layers]]
source     = "blob.bin"
media_type = "application/octet-stream"

[annotations]
"org.opencontainers.image.created" = "yesterday"
"#
    .to_string();
    let (text, dir) = staged(&bad, &["blob.bin"]);
    let err = parse_and_validate_str(&text, dir).expect_err("must reject");
    assert!(matches!(err, SpecError::InvalidReservedAnnotation { .. }));
}

#[test]
fn test_default_attestation_when_block_omitted() {
    // The product opinion: omit [attestation] entirely, get the
    // on-by-default posture (SLSA L2 + CycloneDX + cosign-keyless).
    let (text, dir) = staged(VALID_SPEC, &["blob.bin"]);
    let spec = parse_and_validate_str(&text, dir).expect("parses").spec;
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
