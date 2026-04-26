//! End-to-end pipeline test: build → publish → verify, all via
//! spawned `ocimage` subprocesses.
//!
//! ## Trade-off documented
//!
//! `cosign` is NOT required to run this test. The build is invoked
//! with `--no-attest` (when sign.kind defaults to cosign-keyless and
//! cosign isn't installed, the build would otherwise exit 3, which
//! is not what we're proving here). The task spec explicitly
//! authorises this trade: "use --no-attest in build for the e2e if
//! cosign isn't available."
//!
//! What this test still proves end-to-end:
//!
//! - the CLI `build` subcommand consumes the spec and writes a
//!   complete OCI Image Layout
//! - the CLI `publish` subcommand HTTP-copies that layout to a
//!   destination directory verbatim
//! - the CLI `verify` subcommand opens the published copy and
//!   reports pillar verdicts (Missing for SLSA / SBOM / signature
//!   because the build was --no-attest)
//! - all three exit 0 in sequence
//!
//! What this test does NOT prove (out of scope for v0 e2e):
//!
//! - cosign signature verification end-to-end (requires a real
//!   cosign install + a Sigstore Fulcio + Rekor reachable; out of
//!   scope per the task spec)
//! - registry-mode publish (requires a registry container or
//!   service; the http: sink exercises the same `ImageDir` →
//!   `PublishOutcome` path).
//!
//! When cosign integration ships in v0.2, this file gets a
//! companion `e2e_signed_test.rs` that drives the full chain
//! including signature verification.

mod common;

use predicates::prelude::*;
use tempfile::TempDir;

#[test]
fn test_e2e_build_then_publish_then_verify_succeeds() {
    let tmp = TempDir::new().expect("tempdir");
    let spec = common::stage_firmware_fixture(tmp.path());
    let build_dir = tmp.path().join("oci-build-out");
    let publish_dest = tmp.path().join("static-served");

    // ── 1. build ──────────────────────────────────────────────
    // Bug this assertion catches: a build subcommand that returns
    // 0 without actually emitting blobs (e.g. spec parse succeeds
    // but layer assembly silently no-ops). The OCI Image Layout
    // file invariants below confirm real bytes hit disk.
    common::ocimage_bin()
        .arg("build")
        .arg(&spec)
        .arg("-o")
        .arg(&build_dir)
        .arg("--no-attest")
        .assert()
        .success()
        .stdout(predicate::str::contains("manifest_digest: sha256:"));

    assert!(
        build_dir.join("oci-layout").is_file(),
        "build did not emit oci-layout marker"
    );
    assert!(
        build_dir.join("index.json").is_file(),
        "build did not emit index.json"
    );

    // Capture the manifest digest from build's index.json so we
    // can assert publish + verify see the SAME digest. If any of
    // the three stages re-computes / mangles the digest, this
    // line catches the regression.
    let pre_publish_index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(build_dir.join("index.json")).unwrap()).unwrap();
    let original_manifest_digest = pre_publish_index
        .get("manifests")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|m| m.get("digest"))
        .and_then(|d| d.as_str())
        .expect("build's index.json must have a primary manifest descriptor")
        .to_string();
    assert!(original_manifest_digest.starts_with("sha256:"));

    // ── 2. publish (http:<dest>) ──────────────────────────────
    // Bug this catches: a publish HTTP sink that doesn't actually
    // copy the layout (e.g. only writes `index.json` but skips
    // `blobs/`) — verify in step 3 would then fail with "missing
    // blob" instead of validating the round-trip.
    common::ocimage_bin()
        .arg("publish")
        .arg(&build_dir)
        .arg("--to")
        .arg(format!("http:{}", common::posix(&publish_dest)))
        .assert()
        .success()
        .stdout(predicate::str::contains("pushed:").or(predicate::str::contains("skipped:")));

    assert!(
        publish_dest.join("oci-layout").is_file(),
        "publish did not write oci-layout to dest"
    );
    assert!(
        publish_dest.join("blobs").join("sha256").is_dir(),
        "publish did not write blobs/sha256/ to dest"
    );

    let post_publish_index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(publish_dest.join("index.json")).unwrap()).unwrap();
    let dest_manifest_digest = post_publish_index
        .get("manifests")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|m| m.get("digest"))
        .and_then(|d| d.as_str())
        .unwrap()
        .to_string();
    assert_eq!(
        original_manifest_digest, dest_manifest_digest,
        "publish must propagate manifest digest unchanged"
    );

    // ── 3. verify ─────────────────────────────────────────────
    // The fixture was built with --no-attest, so all three pillars
    // are Missing. With no policy supplied, verify exits 0 and
    // reports the three pillar states informationally — that's the
    // contract documented in spec-doc §7 and the task spec's verify
    // section ("Pure 'not found' + no policy → exit 0
    // (informational)").
    common::ocimage_bin()
        .arg("verify")
        .arg(&publish_dest)
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "manifest: {}",
            original_manifest_digest
        )))
        .stdout(predicate::str::contains("slsa:      missing"))
        .stdout(predicate::str::contains("sbom:      missing"))
        .stdout(predicate::str::contains("signature: missing"));
}

#[test]
fn test_e2e_build_attested_then_publish_then_verify_finds_pillars() {
    // Bug this catches: a regression where the SLSA + SBOM
    // referrers emitted by build don't survive the publish HTTP
    // sink (e.g. the publish path drops referrer manifest blobs
    // that aren't reachable from the primary). After publish,
    // verify must still find both pillars in the destination dir.
    let tmp = TempDir::new().expect("tempdir");
    let spec = common::stage_firmware_fixture_attested_no_sign(tmp.path());
    let build_dir = tmp.path().join("oci-build-out");
    let publish_dest = tmp.path().join("static-served");

    common::ocimage_bin()
        .arg("build")
        .arg(&spec)
        .arg("-o")
        .arg(&build_dir)
        .assert()
        .success();

    common::ocimage_bin()
        .arg("publish")
        .arg(&build_dir)
        .arg("--to")
        .arg(format!("http:{}", common::posix(&publish_dest)))
        .assert()
        .success();

    common::ocimage_bin()
        .arg("verify")
        .arg(&publish_dest)
        .assert()
        .success()
        .stdout(predicate::str::contains("slsa:      ok"))
        .stdout(predicate::str::contains("sbom:      ok"))
        .stdout(predicate::str::contains("signature: missing"));
}
