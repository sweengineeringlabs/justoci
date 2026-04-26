//! `ocimage sbom` integration test — both modes (from spec, from
//! built image dir).

mod common;

use predicates::prelude::*;
use tempfile::TempDir;

#[test]
fn test_sbom_from_spec_cyclonedx_emits_valid_cyclonedx_json() {
    // Bug this catches: a refactor that swapped the cyclonedx /
    // spdx emitters would silently emit SPDX bytes when the
    // operator asked for cyclonedx — downstream Grype / Trivy
    // would then fail with a confusing "wrong format" instead of
    // the operator's actual question being answered.
    let tmp = TempDir::new().expect("tempdir");
    let spec = common::stage_firmware_fixture_attested_no_sign(tmp.path());
    let out = tmp.path().join("preview.cdx.json");

    common::ocimage_bin()
        .arg("sbom")
        .arg(&spec)
        .arg("--format")
        .arg("cyclonedx")
        .arg("-o")
        .arg(&out)
        .assert()
        .success();

    let bytes = std::fs::read(&out).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        v.get("bomFormat").and_then(|x| x.as_str()),
        Some("CycloneDX"),
        "spec-mode SBOM must declare bomFormat=CycloneDX"
    );
}

#[test]
fn test_sbom_from_spec_spdx_emits_valid_spdx_json() {
    // Bug this catches: --format spdx silently delegating to the
    // cyclonedx emitter would break --format honoring on the spec
    // path.
    let tmp = TempDir::new().expect("tempdir");
    let spec = common::stage_firmware_fixture_attested_no_sign(tmp.path());
    let out = tmp.path().join("preview.spdx.json");

    common::ocimage_bin()
        .arg("sbom")
        .arg(&spec)
        .arg("--format")
        .arg("spdx")
        .arg("-o")
        .arg(&out)
        .assert()
        .success();

    let bytes = std::fs::read(&out).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let v_ver = v.get("spdxVersion").and_then(|x| x.as_str()).unwrap_or("");
    assert!(
        v_ver.starts_with("SPDX-"),
        "spec-mode SBOM (spdx) must carry spdxVersion=SPDX-…, got {v_ver:?}"
    );
}

#[test]
fn test_sbom_from_image_dir_extracts_emitted_sbom_bytes() {
    // Bug this catches: image-mode walking the wrong referrer (e.g.
    // returning the SLSA blob bytes instead of the SBOM) — operators
    // would feed an in-toto Statement to a CycloneDX consumer.
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

    let extracted = tmp.path().join("extracted.cdx.json");
    common::ocimage_bin()
        .arg("sbom")
        .arg(&image_dir)
        .arg("-o")
        .arg(&extracted)
        .assert()
        .success();

    let bytes = std::fs::read(&extracted).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        v.get("bomFormat").and_then(|x| x.as_str()),
        Some("CycloneDX"),
        "image-mode SBOM must be the cyclonedx blob the build emitted"
    );
}

#[test]
fn test_sbom_unknown_format_rejected() {
    // Bug this catches: the format flag silently defaulting on
    // unknown input would let typos through (`spxd` → cyclonedx
    // silently). The operator must see a clean rejection.
    let tmp = TempDir::new().expect("tempdir");
    let spec = common::stage_firmware_fixture(tmp.path());

    common::ocimage_bin()
        .arg("sbom")
        .arg(&spec)
        .arg("--format")
        .arg("xml")
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown SBOM format"));
}
