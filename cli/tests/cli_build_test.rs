//! `ocimage build <fixture> -o <out>` integration test.
//!
//! Runs the actual CLI binary via `assert_cmd` and asserts:
//!
//! - exit 0
//! - the output dir is populated with an OCI Image Layout
//!   (`oci-layout`, `index.json`, `blobs/sha256/...`).
//! - stdout includes the manifest digest the operator can pipe
//!   into a downstream tool (e.g. `xargs cosign sign`).

mod common;

use std::path::PathBuf;

use predicates::prelude::*;
use tempfile::TempDir;

#[test]
fn test_build_no_attest_emits_oci_layout_with_manifest_digest_on_stdout() {
    // Bug this catches: a refactor that drops the `manifest_digest:`
    // stdout line, or routes it to stderr, would silently break every
    // CI script that pipes `ocimage build … | grep manifest_digest`
    // into a downstream sign / publish step. Stdout is the data
    // channel; stderr is for diagnostics.
    let tmp = TempDir::new().expect("tempdir");
    let spec = common::stage_firmware_fixture(tmp.path());
    let output_dir: PathBuf = tmp.path().join("oci-out");

    let mut cmd = common::ocimage_bin();
    cmd.arg("build")
        .arg(&spec)
        .arg("-o")
        .arg(&output_dir)
        .arg("--no-attest");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("manifest_digest: sha256:"))
        .stdout(predicate::str::contains("spec_hash:       sha256:"))
        .stdout(predicate::str::contains(
            "attestation:     skipped: --no-attest",
        ));

    // OCI Image Layout invariants. If any of these is missing, the
    // build either failed silently or wrote a malformed layout —
    // both are bugs the build crate's atomicity contract is supposed
    // to prevent, so a CLI regression that fails to call build()
    // correctly would surface here.
    assert!(
        output_dir.join("oci-layout").is_file(),
        "missing oci-layout marker"
    );
    assert!(
        output_dir.join("index.json").is_file(),
        "missing index.json"
    );
    assert!(
        output_dir.join("blobs").join("sha256").is_dir(),
        "missing blobs/sha256/"
    );
}

#[test]
fn test_build_into_existing_output_dir_fails_with_build_error() {
    // Bug this catches: a CLI regression that silently overwrites an
    // existing output dir would let a stale build leak into a fresh
    // attempt — operators expecting "rebuild from scratch" would get
    // a half-rebuilt mix. The build crate's atomicity contract refuses
    // pre-existing output_dir; the CLI must surface that as exit 2,
    // not exit 64 / paper over with a "remove-then-build" hack.
    let tmp = TempDir::new().expect("tempdir");
    let spec = common::stage_firmware_fixture(tmp.path());
    let output_dir = tmp.path().join("oci-out");
    std::fs::create_dir_all(&output_dir).unwrap();

    let mut cmd = common::ocimage_bin();
    cmd.arg("build")
        .arg(&spec)
        .arg("-o")
        .arg(&output_dir)
        .arg("--no-attest");

    cmd.assert().failure().code(2);
}

#[test]
fn test_build_with_attestation_emits_referrer_descriptors_in_index() {
    // Bug this catches: a CLI that runs attest() but doesn't wire the
    // outputs into index.json as referrers — operators downstream
    // (`ocimage verify`, `oras discover`, `crane manifest`) would not
    // see the SLSA / SBOM blobs even though they exist in the CAS.
    // The presence of two extra `manifests` entries (one SLSA + one
    // SBOM, sign opted out) confirms the wiring.
    let tmp = TempDir::new().expect("tempdir");
    let spec = common::stage_firmware_fixture_attested_no_sign(tmp.path());
    let output_dir = tmp.path().join("oci-out");

    let mut cmd = common::ocimage_bin();
    cmd.arg("build").arg(&spec).arg("-o").arg(&output_dir);
    cmd.assert().success();

    let index_bytes = std::fs::read(output_dir.join("index.json")).unwrap();
    let index: serde_json::Value = serde_json::from_slice(&index_bytes).unwrap();
    let manifests = index
        .get("manifests")
        .and_then(|v| v.as_array())
        .expect("index.json has manifests[]");

    // 1 primary + 2 referrers (SLSA + SBOM; signing opted out).
    assert_eq!(
        manifests.len(),
        3,
        "expected 1 primary + 2 referrer manifests, got {} entries: {index_bytes:?}",
        manifests.len()
    );

    let mut found_slsa = false;
    let mut found_sbom = false;
    for m in manifests {
        let at = m.get("artifactType").and_then(|x| x.as_str()).unwrap_or("");
        if at == "application/vnd.in-toto+json" {
            found_slsa = true;
        }
        if at == "application/vnd.cyclonedx+json" {
            found_sbom = true;
        }
    }
    assert!(found_slsa, "no in-toto referrer found in index.json");
    assert!(found_sbom, "no cyclonedx referrer found in index.json");
}
