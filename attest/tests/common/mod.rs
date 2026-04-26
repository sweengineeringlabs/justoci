//! Shared fixtures for the attest crate's integration tests.
//!
//! `make_built_artifact()` produces a fully-validated `BuiltArtifact`
//! against a tempdir-backed spec. Each layer is a real (zero-byte)
//! file because spec validation existence-tests layer sources.

use std::fs;
use std::path::PathBuf;

use cas::{Algorithm, Digest};
use spec::{parse_and_validate_str, spec_hash, Spec};
use tempfile::TempDir;

use attest::BuiltArtifact;

/// Return a built-artifact + the tempdir holding it. Callers must
/// keep the TempDir alive for the duration of the test, otherwise
/// the layer source paths get garbage-collected.
pub fn make_built_artifact() -> (BuiltArtifact, TempDir) {
    let tmp = TempDir::new().expect("tempdir");
    let spec_dir = tmp.path().to_path_buf();
    write_layer_files(&spec_dir);
    let spec = parse_and_validate_str(sample_spec_toml(), spec_dir).expect("spec parses");
    let built = built_from(&spec);
    (built, tmp)
}

fn write_layer_files(dir: &PathBuf) {
    fs::write(dir.join("kernel.bin"), b"fake-kernel").expect("write kernel");
    fs::write(dir.join("initrd.img"), b"fake-initrd").expect("write initrd");
    fs::write(dir.join("rootfs.ext4"), b"fake-rootfs").expect("write rootfs");
}

fn sample_spec_toml() -> &'static str {
    // vm_image kind requires exactly 3 layers in kernel/initrd/rootfs
    // order. We use blob sources because that's what the most
    // commonly-tested case is; tests that need `[[layers.files]]`
    // build their own spec.
    r#"
spec_version = "0"
id           = "demo:1.0"
kind         = "vm_image"

[[layers]]
source     = "kernel.bin"
media_type = "application/vnd.justoci.kernel+binary"

[[layers]]
source     = "initrd.img"
media_type = "application/vnd.justoci.initrd+binary"

[[layers]]
source     = "rootfs.ext4"
media_type = "application/vnd.justoci.rootfs.ext4+binary"
"#
}

fn built_from(spec: &Spec) -> BuiltArtifact {
    let manifest = Digest::from_bytes(Algorithm::Sha256, b"manifest-blob");
    let config = Digest::from_bytes(Algorithm::Sha256, b"config-blob");
    let layer_digests = spec
        .layers
        .iter()
        .enumerate()
        .map(|(i, _)| {
            let bytes = format!("layer-{i}-content").into_bytes();
            (i, Digest::from_bytes(Algorithm::Sha256, &bytes))
        })
        .collect::<Vec<_>>();
    let hash = spec_hash(spec).expect("spec hash");
    BuiltArtifact::new(manifest, config, layer_digests, spec.clone(), hash)
        .expect("BuiltArtifact::new")
}
