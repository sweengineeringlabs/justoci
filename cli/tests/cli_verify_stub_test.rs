//! `verify_engine::verify` integration test with a stub cosign invoker.
//!
//! These tests drive the verify pillar walker directly via the
//! library API (not the spawned CLI binary) so we can inject scripted
//! cosign outcomes — proving the walker correctly classifies each
//! invocation outcome and applies policy gates without needing
//! cosign installed.

mod common;

use std::path::Path;

use tempfile::TempDir;

use swe_justoci_oci_cli::policy::Policy;
use swe_justoci_oci_cli::verify_engine::{
    verify, CosignVerifyOutcome, PillarVerdict, StubCosignVerifyInvoker, VerifyError,
};

/// Build a fixture image dir with SLSA + SBOM (no signing).
/// We can't easily fabricate a cosign signature blob, so signature-
/// pillar tests below override the stub outcome; SLSA + SBOM are
/// the real bytes the build/attest pipeline emitted.
fn build_attested_image_dir(tmp: &TempDir) -> std::path::PathBuf {
    let spec = common::stage_firmware_fixture_attested_no_sign(tmp.path());
    let image_dir = tmp.path().join("oci-out");
    let assert = common::ocimage_bin()
        .arg("build")
        .arg(&spec)
        .arg("-o")
        .arg(&image_dir)
        .assert();
    assert.success();
    image_dir
}

#[test]
fn test_verify_walker_finds_slsa_and_sbom_pillars_when_present() {
    // Bug this catches: a refactor that drops the slsa or sbom
    // referrer from the index walk — verify would report Missing
    // for a pillar that was actually emitted, mis-reporting the
    // image's true posture.
    let tmp = TempDir::new().expect("tempdir");
    let image_dir = build_attested_image_dir(&tmp);

    let stub = StubCosignVerifyInvoker::new(CosignVerifyOutcome::CosignNotInstalled);
    let report = verify(&image_dir, None, &stub).expect("verify must succeed without policy");

    assert!(
        matches!(report.slsa, PillarVerdict::Found { .. }),
        "SLSA pillar must be Found, got {:?}",
        report.slsa
    );
    assert!(
        matches!(report.sbom, PillarVerdict::Found { .. }),
        "SBOM pillar must be Found, got {:?}",
        report.sbom
    );
    assert!(
        matches!(report.signature, PillarVerdict::Missing),
        "signature pillar must be Missing (no signing in fixture), got {:?}",
        report.signature
    );
}

#[test]
fn test_verify_walker_signature_invalid_outcome_is_failed_verdict() {
    // Bug this catches: a stub invoker outcome `InvalidSignature`
    // mapped to `PillarVerdict::Missing` (or Found) would silently
    // accept a tampered artifact. Failed verdict is the contract.
    let tmp = TempDir::new().expect("tempdir");
    let image_dir = build_attested_image_dir(&tmp);

    // Inject a fake signature referrer so the walker has something
    // to invoke the stub on.
    inject_fake_cosign_referrer(&image_dir);

    let stub = StubCosignVerifyInvoker::new(CosignVerifyOutcome::InvalidSignature {
        stderr: "cosign rejected: bad signature".into(),
    });

    let report = verify(&image_dir, None, &stub).expect("verify (no policy) returns Ok");
    match &report.signature {
        PillarVerdict::Failed { detail } => {
            assert!(
                detail.contains("cosign rejected"),
                "Failed verdict must carry cosign stderr; got {detail:?}"
            );
        }
        other => panic!("expected Failed signature verdict, got {other:?}"),
    }
}

#[test]
fn test_verify_walker_policy_gate_slsa_level_violation_short_circuits() {
    // Bug this catches: a verifier that ignores `[slsa] level = N`
    // and reports success for an L1 attestation against an L3
    // policy — the operator's "require L3" promise becomes a
    // silent no-op.
    let tmp = TempDir::new().expect("tempdir");
    let image_dir = build_attested_image_dir(&tmp);

    let policy = Policy {
        slsa_min_level: Some(4),
        require_signature: false,
        builder_id: None,
        sbom_formats: None,
    };

    let stub = StubCosignVerifyInvoker::new(CosignVerifyOutcome::CosignNotInstalled);
    let err = verify(&image_dir, Some(&policy), &stub)
        .expect_err("policy slsa.level=4 against L2 attestation must violate");
    match err {
        VerifyError::PolicyViolation { rule, detail } => {
            assert_eq!(rule, "slsa.level");
            assert!(detail.contains("claimed_slsa_level"));
        }
        other => panic!("expected PolicyViolation, got {other:?}"),
    }
}

#[test]
fn test_verify_walker_policy_require_signature_missing_fails() {
    // Bug this catches: `require_signature = true` silently passing
    // when the artifact has no signature pillar — the strongest
    // promise verify offers (no policy violations) becomes
    // tautological, accepting unsigned artifacts.
    let tmp = TempDir::new().expect("tempdir");
    let image_dir = build_attested_image_dir(&tmp);

    let policy = Policy {
        slsa_min_level: None,
        require_signature: true,
        builder_id: None,
        sbom_formats: None,
    };

    let stub = StubCosignVerifyInvoker::new(CosignVerifyOutcome::CosignNotInstalled);
    let err = verify(&image_dir, Some(&policy), &stub)
        .expect_err("policy require_signature=true must violate when sig is missing");
    match err {
        VerifyError::SignatureMissing => {}
        other => panic!("expected SignatureMissing, got {other:?}"),
    }
}

#[test]
fn test_verify_walker_policy_sbom_format_match_passes() {
    // Bug this catches: an SBOM-format gate that always fails (or
    // always passes) regardless of the actual SBOM media type —
    // the gate becomes worthless either way. This test pins the
    // happy path: cyclonedx artifact + cyclonedx policy → pass.
    let tmp = TempDir::new().expect("tempdir");
    let image_dir = build_attested_image_dir(&tmp);

    let policy = Policy {
        slsa_min_level: None,
        require_signature: false,
        builder_id: None,
        sbom_formats: Some(vec!["cyclonedx".into()]),
    };

    let stub = StubCosignVerifyInvoker::new(CosignVerifyOutcome::CosignNotInstalled);
    let report = verify(&image_dir, Some(&policy), &stub)
        .expect("cyclonedx policy must accept cyclonedx SBOM");
    assert!(matches!(report.sbom, PillarVerdict::Found { .. }));
}

#[test]
fn test_verify_walker_policy_sbom_format_mismatch_violates() {
    // Bug this catches: a policy expecting `spdx` accepting a
    // `cyclonedx` SBOM because the substring check was wrong way
    // around — the operator's "we ship spdx only" mandate is silently
    // violated.
    let tmp = TempDir::new().expect("tempdir");
    let image_dir = build_attested_image_dir(&tmp);

    let policy = Policy {
        slsa_min_level: None,
        require_signature: false,
        builder_id: None,
        sbom_formats: Some(vec!["spdx".into()]),
    };

    let stub = StubCosignVerifyInvoker::new(CosignVerifyOutcome::CosignNotInstalled);
    let err = verify(&image_dir, Some(&policy), &stub)
        .expect_err("spdx policy must reject cyclonedx SBOM");
    match err {
        VerifyError::PolicyViolation { rule, .. } => {
            assert_eq!(rule, "sbom.format");
        }
        other => panic!("expected PolicyViolation[sbom.format], got {other:?}"),
    }
}

// ── helpers ────────────────────────────────────────────────────────

/// Stage a fake cosign referrer manifest into `image_dir` so the
/// walker has a signature pillar to feed the stub invoker.
///
/// We DON'T put valid bytes — the stub returns a scripted outcome
/// regardless of bytes, so we only need the bytes to be *present*
/// at the digest the manifest claims.
fn inject_fake_cosign_referrer(image_dir: &Path) {
    use sha2::{Digest as _, Sha256};

    let blobs = image_dir.join("blobs").join("sha256");
    let bundle_bytes = br#"{"base64Signature":"AAAA"}"#;
    let bundle_digest = format!("sha256:{}", hex(&Sha256::digest(bundle_bytes)));
    std::fs::write(
        blobs.join(bundle_digest.split_once(':').unwrap().1),
        bundle_bytes,
    )
    .unwrap();

    // We also need an empty config blob, which the build path may
    // already have written. Either way, putting `{}` is idempotent.
    let cfg_bytes: &[u8] = b"{}";
    let cfg_digest = format!("sha256:{}", hex(&Sha256::digest(cfg_bytes)));
    std::fs::write(blobs.join(cfg_digest.split_once(':').unwrap().1), cfg_bytes).unwrap();

    // Read the existing index.json to find the primary manifest
    // descriptor (so our fake referrer can subject-link to it).
    let index_path = image_dir.join("index.json");
    let mut index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&index_path).unwrap()).unwrap();

    let primary_desc = {
        let manifests = index
            .get("manifests")
            .and_then(|v| v.as_array())
            .expect("index has manifests[]");
        manifests
            .iter()
            .find(|m| {
                m.get("artifactType").is_none()
                    || m.get("artifactType").and_then(|x| x.as_str()) == Some("")
            })
            .cloned()
            .or_else(|| manifests.first().cloned())
            .unwrap()
    };

    let manifest_value = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "artifactType": "application/vnd.dev.cosign.simplesigning.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.empty.v1+json",
            "digest": cfg_digest,
            "size": cfg_bytes.len(),
        },
        "layers": [{
            "mediaType": "application/vnd.dev.cosign.simplesigning.v1+json",
            "digest": bundle_digest,
            "size": bundle_bytes.len(),
        }],
        "subject": {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": primary_desc.get("digest").and_then(|x| x.as_str()).unwrap().to_string(),
            "size": primary_desc.get("size").and_then(|x| x.as_u64()).unwrap(),
        },
    });
    let manifest_bytes = serde_json::to_vec(&manifest_value).unwrap();
    let manifest_digest = format!("sha256:{}", hex(&Sha256::digest(&manifest_bytes)));
    std::fs::write(
        blobs.join(manifest_digest.split_once(':').unwrap().1),
        &manifest_bytes,
    )
    .unwrap();

    let manifests = index.get_mut("manifests").unwrap().as_array_mut().unwrap();
    manifests.push(serde_json::json!({
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "digest": manifest_digest,
        "size": manifest_bytes.len(),
        "artifactType": "application/vnd.dev.cosign.simplesigning.v1+json",
    }));
    std::fs::write(&index_path, serde_json::to_vec(&index).unwrap()).unwrap();
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
