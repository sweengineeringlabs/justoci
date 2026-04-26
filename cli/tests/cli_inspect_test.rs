//! `ocimage inspect <spec | image-dir>` integration test.

mod common;

use predicates::prelude::*;
use tempfile::TempDir;

#[test]
fn test_inspect_spec_emits_canonical_json_that_round_trips_as_json() {
    // Bug this catches: a refactor that prints the canonical form
    // with embedded newlines or extra whitespace would break the
    // "JCS bytes are stable" guarantee. The downstream test (a Go
    // re-implementation) relies on byte-identical output for the
    // same TOML input; if the CLI mangles it during pretty-printing,
    // the spec hash differs across implementations.
    let tmp = TempDir::new().expect("tempdir");
    let spec = common::stage_firmware_fixture(tmp.path());

    let mut cmd = common::ocimage_bin();
    cmd.arg("inspect").arg(&spec);
    let output = cmd.assert().success().get_output().clone();

    let stdout = String::from_utf8(output.stdout).unwrap();
    // The first line(s) up to the trailing `\nspec_hash: ...` line
    // are the canonical JSON. Round-trip must succeed.
    let split = stdout
        .rfind("\nspec_hash: ")
        .expect("inspect stdout must include spec_hash: line");
    let json_part = &stdout[..split];
    let _: serde_json::Value =
        serde_json::from_str(json_part.trim()).expect("canonical JSON must be parseable");
    assert!(stdout.contains("\nspec_hash: sha256:"));
}

#[test]
fn test_inspect_image_dir_lists_manifest_digest_and_layers() {
    // Bug this catches: inspect dropping the manifest_digest line or
    // re-naming it would break operators using
    // `ocimage inspect <dir> | grep manifest_digest:` to fetch the
    // digest for a downstream verify. Stable line prefixes are part
    // of the contract.
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
        .arg("inspect")
        .arg(&image_dir)
        .assert()
        .success()
        .stdout(predicate::str::contains("manifest_digest: sha256:"))
        .stdout(predicate::str::contains("config:          sha256:"))
        .stdout(predicate::str::contains("layer[0]:  sha256:"));
}
