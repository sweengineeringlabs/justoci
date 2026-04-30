//! Shared test helpers for the CLI integration test binaries.
//!
//! `cargo test` compiles each `tests/*.rs` as its own binary; helpers
//! shared between them go here. The standard cargo idiom of a single
//! `#![allow(dead_code)]` at the top is the only place we use it —
//! per-test-binary unused code is a cargo artefact, not a hidden
//! dead-code problem (per CLAUDE.md memory note `feedback_no_blanket_allow`).

#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// Stage a minimal `raw_image` firmware spec + its source file
/// under `dir` and return the spec path.
///
/// Why firmware: it's the simplest spec kind (one layer, no
/// platform-shape requirements), so the CLI tests can drive build →
/// publish → verify without dragging vm_image's three-layer ordering
/// invariants into the test surface.
pub fn stage_firmware_fixture(dir: &Path) -> PathBuf {
    let firmware_path = dir.join("firmware.bin");
    // 4 KiB pseudo-payload — large enough that gzip-vs-no-gzip
    // wouldn't collapse to a tautology, but small enough not to
    // slow `cargo test` materially.
    let mut bytes = Vec::with_capacity(4096);
    for i in 0..4096u32 {
        bytes.push((i as u8).wrapping_mul(31));
    }
    std::fs::write(&firmware_path, &bytes).unwrap();

    let spec_path = dir.join("firmware.toml");
    let toml = format!(
        r#"
spec_version = "0"
id           = "device-firmware:1.4.2"
kind         = "raw_image"
description  = "Test firmware fixture"

[platform]
arch = "armv7"
os   = "none"

[[layers]]
source     = "{src}"
media_type = "application/vnd.devboard-x7.firmware+binary"

[config]
flash_offset_bytes = 0
size_bytes         = 4096
hardware_revision  = "rev3"

[annotations]
"org.opencontainers.image.title"   = "devboard-x7-firmware"
"org.opencontainers.image.version" = "1.4.2"

[attestation]
slsa.level  = 0
sbom.format = "off"
sign.kind   = "off"
"#,
        src = posix(&firmware_path),
    );
    std::fs::write(&spec_path, toml).unwrap();
    spec_path
}

/// Stage a firmware spec with attestation defaults left ON, except
/// signing — defaults are L2 + cyclonedx + cosign-keyless, but we
/// can't test cosign in CI without it installed. We override
/// sign.kind = "off" so SLSA + SBOM still emit.
pub fn stage_firmware_fixture_attested_no_sign(dir: &Path) -> PathBuf {
    let firmware_path = dir.join("firmware.bin");
    let mut bytes = Vec::with_capacity(4096);
    for i in 0..4096u32 {
        bytes.push((i as u8).wrapping_mul(31));
    }
    std::fs::write(&firmware_path, &bytes).unwrap();

    let spec_path = dir.join("firmware.toml");
    let toml = format!(
        r#"
spec_version = "0"
id           = "device-firmware:1.4.2"
kind         = "raw_image"
description  = "Test firmware fixture (attested, no sign)"

[[layers]]
source     = "{src}"
media_type = "application/vnd.devboard-x7.firmware+binary"

[config]
flash_offset_bytes = 0
size_bytes         = 4096

[attestation]
slsa.level  = 2
sbom.format = "cyclonedx"
sign.kind   = "off"
"#,
        src = posix(&firmware_path),
    );
    std::fs::write(&spec_path, toml).unwrap();
    spec_path
}

/// Render a path with forward slashes for embedding in TOML on
/// Windows. Same approach as the build crate's tests/common.
pub fn posix(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

/// Locate the compiled `oci` binary using `assert_cmd`'s
/// CARGO_BIN_EXE machinery. Lives here to keep the lookup uniform
/// across test files.
pub fn oci_bin() -> assert_cmd::Command {
    assert_cmd::Command::cargo_bin("oci").expect("oci binary built")
}
