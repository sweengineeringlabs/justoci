//! Asserts each spec-doc §7 exit code is reachable end-to-end.
//!
//! Each test names the bug a missed mapping would cause: CI
//! pipelines route on the exit code; routing on stderr text would
//! be brittle, so the exit-code assertions are the contract.

mod common;

use std::path::PathBuf;

use predicates::prelude::*;
use tempfile::TempDir;

#[test]
fn test_bad_spec_returns_exit_1_spec_error() {
    // Bug this catches: a spec validation error mapped to anything
    // other than 1. CI pipelines branch "exit 1 → fix the spec";
    // a wrong code routes the operator to fix the inputs (exit 2)
    // or the publish backend (exit 4) — both wrong.
    let tmp = TempDir::new().expect("tempdir");
    let bad_spec = tmp.path().join("bad.toml");
    std::fs::write(
        &bad_spec,
        // Valid TOML, invalid spec: unknown kind.
        r#"
spec_version = "0"
id           = "x:1"
kind         = "totally_made_up"

[[layers]]
source = "/nonexistent"
media_type = "application/vnd.x+binary"
"#,
    )
    .unwrap();

    common::ocimage_bin()
        .arg("build")
        .arg(&bad_spec)
        .arg("-o")
        .arg(tmp.path().join("out"))
        .arg("--no-attest")
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("unknown kind"));
}

#[test]
fn test_existing_output_dir_returns_exit_2_build_error() {
    // Bug this catches: the build crate's atomicity contract refuses
    // pre-existing output_dir; if the CLI silently swallowed that
    // and returned 0 / 64, the build pipeline's "I won't overwrite
    // your dir" promise becomes a lie.
    let tmp = TempDir::new().expect("tempdir");
    let spec = common::stage_firmware_fixture(tmp.path());
    let output_dir = tmp.path().join("oci-out");
    std::fs::create_dir_all(&output_dir).unwrap();

    common::ocimage_bin()
        .arg("build")
        .arg(&spec)
        .arg("-o")
        .arg(&output_dir)
        .arg("--no-attest")
        .assert()
        .failure()
        .code(2);
}

#[test]
fn test_attestation_with_cosign_required_returns_exit_3_attest_error() {
    // Bug this catches: when cosign is not installed (the standard
    // CI default), a spec that requires signing must surface as
    // exit 3 — the spec doc explicitly recommends "re-run with
    // --no-attest if signing infra is unavailable" on a 3. Exit 0
    // would silently ship an unsigned artifact in production.
    //
    // We force the cosign-not-installed path by clearing PATH for
    // the spawned subprocess (assert_cmd::Command supports env
    // mutation per-invocation).
    let tmp = TempDir::new().expect("tempdir");
    let firmware = tmp.path().join("firmware.bin");
    let mut bytes = Vec::with_capacity(4096);
    for i in 0..4096u32 {
        bytes.push((i as u8).wrapping_mul(31));
    }
    std::fs::write(&firmware, &bytes).unwrap();
    let spec_path = tmp.path().join("firmware.toml");
    std::fs::write(
        &spec_path,
        format!(
            r#"
spec_version = "0"
id           = "device-firmware:1.4.2"
kind         = "raw_image"

[[layers]]
source     = "{src}"
media_type = "application/vnd.devboard-x7.firmware+binary"

[config]
size_bytes = 4096

[attestation]
slsa.level  = 2
sbom.format = "cyclonedx"
sign.kind   = "cosign-keyless"
"#,
            src = common::posix(&firmware)
        ),
    )
    .unwrap();

    let output_dir = tmp.path().join("out");
    common::ocimage_bin()
        .env_clear()
        .env("PATH", "")
        .arg("build")
        .arg(&spec_path)
        .arg("-o")
        .arg(&output_dir)
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains("cosign"));
}

#[test]
fn test_publish_to_malformed_uri_returns_exit_64_cli_error() {
    // Bug this catches: a typo in `--to` mis-routed as exit 4
    // (publish backend error). The operator's reaction to 4 is
    // "retry, it's transient"; a typo isn't transient. Routing
    // local invocation errors through 64 keeps the recovery
    // path correct.
    let tmp = TempDir::new().expect("tempdir");
    let spec = common::stage_firmware_fixture(tmp.path());
    let image_dir = tmp.path().join("oci-out");
    common::ocimage_bin()
        .arg("build")
        .arg(&spec)
        .arg("-o")
        .arg(&image_dir)
        .arg("--no-attest")
        .assert()
        .success();

    common::ocimage_bin()
        .arg("publish")
        .arg(&image_dir)
        .arg("--to")
        .arg("s3://bogus") // Unknown scheme.
        .assert()
        .failure()
        .code(64);
}

#[test]
fn test_publish_to_nonexistent_image_dir_returns_exit_4_publish_error() {
    // Bug this catches: a malformed image dir surfacing as exit 64
    // (CLI-local) when in fact it's a publish-backend validation
    // failure — the publish crate owns ImageDir validation, and
    // its errors are operator-actionable as "fix the producer."
    // The spec-doc §7 mapping puts that at exit 4.
    let tmp = TempDir::new().expect("tempdir");
    let nonexistent: PathBuf = tmp.path().join("not-built-yet");

    common::ocimage_bin()
        .arg("publish")
        .arg(&nonexistent)
        .arg("--to")
        .arg(format!("http:{}", common::posix(&tmp.path().join("dest"))))
        .assert()
        .failure()
        .code(4);
}

#[test]
fn test_verify_policy_violation_returns_exit_5() {
    // Bug this catches: a verify policy violation mis-routed to
    // anything but 5. The 5 is the signal "your artifact does not
    // satisfy the declared policy"; anything else mis-leads the
    // operator's reaction (retry / re-build / re-sign).
    let tmp = TempDir::new().expect("tempdir");
    let spec = common::stage_firmware_fixture_attested_no_sign(tmp.path());
    let image_dir = tmp.path().join("oci-out");
    common::ocimage_bin()
        .arg("build")
        .arg(&spec)
        .arg("-o")
        .arg(&image_dir)
        .assert()
        .success();

    let policy_path = tmp.path().join("policy.toml");
    std::fs::write(
        &policy_path,
        r#"
[slsa]
level = 4

[sign]
required = false
"#,
    )
    .unwrap();

    common::ocimage_bin()
        .arg("verify")
        .arg(&image_dir)
        .arg("--policy")
        .arg(&policy_path)
        .assert()
        .failure()
        .code(5)
        .stderr(predicate::str::contains("policy violation"));
}
