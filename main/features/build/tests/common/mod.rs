//! Shared test fixtures.
//!
//! Specs in tests use absolute layer source paths so the build
//! pipeline doesn't depend on the test process's cwd (which
//! `cargo test` parallelism makes unsafe to mutate).
//!
//! ## Why `#![allow(dead_code)]` here
//!
//! Each integration test compiles this file as part of its own test
//! binary. A helper used by some test binaries (e.g.
//! `oci_artifact_toml` is only used by `oci_artifact_build_test`)
//! but not all of them produces `dead_code` warnings in every other
//! binary. The standard cargo-test idiom is a single module-level
//! allow on `tests/common/mod.rs`; the alternative — fragmenting the
//! helpers across test-specific common files — duplicates code for
//! no production-code clarity gain. This is NOT a "hide unconsumed
//! code between milestones" allow (which the user's metaprompt
//! correctly rejects); it's an artefact of cargo's per-test-binary
//! compilation model.

#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};

/// Stage three small fixture files (`bzImage`, `initrd.cpio`,
/// `rootfs.ext4`) under `dir` and return their absolute paths.
pub struct VmImageFixture {
    pub kernel: PathBuf,
    pub initrd: PathBuf,
    pub rootfs: PathBuf,
}

pub fn stage_vm_image_fixture(dir: &Path) -> VmImageFixture {
    let kernel = dir.join("bzImage");
    let initrd = dir.join("initrd.cpio");
    let rootfs = dir.join("rootfs.ext4");
    fs::write(&kernel, b"FAKE-KERNEL-BYTES").unwrap();
    // Make the initrd big enough to be worth compressing — gzip of
    // 17 bytes can be larger than the input, which makes some
    // assertions confusing. 4 KiB of pseudo-payload is adequate.
    let mut initrd_bytes = Vec::with_capacity(4096);
    for i in 0..4096u32 {
        initrd_bytes.push((i as u8).wrapping_mul(17));
    }
    fs::write(&initrd, &initrd_bytes).unwrap();
    let mut rootfs_bytes = Vec::with_capacity(8192);
    for i in 0..8192u32 {
        rootfs_bytes.push((i as u8).wrapping_add(31));
    }
    fs::write(&rootfs, &rootfs_bytes).unwrap();
    VmImageFixture {
        kernel,
        initrd,
        rootfs,
    }
}

/// Build a vm_image-shaped TOML spec with absolute layer paths and
/// return it (caller passes the result to `parse_and_validate_str`).
pub fn vm_image_toml(fx: &VmImageFixture) -> String {
    format!(
        r#"
spec_version = "0"
id = "llmboot:0.1.14"
kind = "vm_image"
description = "test vm_image"

[platform]
os = "linux"
arch = "x86_64"

[[layers]]
source = "{kernel}"
media_type = "application/vnd.vmisolate.kernel+binary"

[[layers]]
source = "{initrd}"
media_type = "application/vnd.vmisolate.initrd.cpio+gzip"
compression = "gzip"

[[layers]]
source = "{rootfs}"
media_type = "application/vnd.vmisolate.rootfs.ext4+gzip"
compression = "gzip"

[config]
init_mode = "xkinit"
entrypoint = ["/usr/bin/llmd", "serve"]
kernel_cmdline = "console=ttyS0 quiet"

[config.env]
RUST_LOG = "info"
HOME = "/root"

[annotations]
"org.opencontainers.image.title" = "llmboot"
"org.opencontainers.image.version" = "0.1.14"
"#,
        kernel = posix(&fx.kernel),
        initrd = posix(&fx.initrd),
        rootfs = posix(&fx.rootfs),
    )
}

pub fn oci_artifact_toml(blob_path: &Path) -> String {
    format!(
        r#"
spec_version = "0"
id = "ggml-llama-7b:q4_0"
kind = "oci_artifact"
description = "test artifact"

[[layers]]
source = "{blob}"
media_type = "application/vnd.ggml.weights.gguf"

[config]
quantization = "q4_0"
parameters = 7000000000

[annotations]
"org.opencontainers.image.title" = "llama-7b-q4_0"
"#,
        blob = posix(blob_path),
    )
}

pub fn raw_image_toml(blob_path: &Path) -> String {
    format!(
        r#"
spec_version = "0"
id = "device-firmware:1.4.2"
kind = "raw_image"
description = "test firmware"

[platform]
arch = "armv7"
os = "none"

[[layers]]
source = "{blob}"
media_type = "application/vnd.devboard-x7.firmware+binary"

[config]
flash_offset_bytes = 0
size_bytes = 4194304
"#,
        blob = posix(blob_path),
    )
}

/// Render a path with forward slashes for embedding in TOML on
/// Windows. TOML strings escape `\` so a Windows absolute path of
/// `C:\Users\…` would need doubling; emitting `C:/Users/…` sidesteps
/// the issue and Rust's `Path` handles `/` on Windows just fine.
pub fn posix(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

/// `cargo test` runs each test binary under its own cwd; the spec
/// crate uses the spec_dir argument only for relative-path resolution
/// at validation time. Tests pass an arbitrary spec_dir (the temp
/// dir) since all our staged TOMLs use absolute layer paths.
pub fn parse_spec(toml_text: &str, spec_dir: &Path) -> spec::LoadedSpec {
    spec::parse_and_validate_str(toml_text, spec_dir.to_path_buf())
        .expect("test spec must parse + validate")
}
