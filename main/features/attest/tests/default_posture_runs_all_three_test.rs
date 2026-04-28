//! Asserts that the default `AttestationConfig` (no `[attestation]`
//! block in the spec) runs all three pillars.
//!
//! Bug this catches: a partial wiring where, say, the SLSA pillar
//! ran by default but the SBOM pillar required an explicit
//! `format = "cyclonedx"` would silently produce un-SBOM'd
//! artifacts in production. The product opinion is "all three on
//! by default"; this test makes that opinion testable.
//!
//! We use a `StubCosignInvoker` returning a successful outcome so
//! the test runs without cosign installed but still asserts that
//! the cosign code path was reached.

mod common;

use cas::FsCas;
use spec::{AttestationConfig, SignKind};
use tempfile::TempDir;

use attest::core::cosign::{CosignOutcome, StubCosignInvoker};
use attest::saf::attest::attest_with_invoker;
use attest::SbomMediaType;

const FAKE_BUNDLE: &str = r#"{
  "base64Signature": "AAA",
  "rekorBundle": {
    "Payload": {
      "logIndex": 9999,
      "integratedTime": 1700000000
    }
  }
}"#;

#[test]
fn test_default_attestation_config_emits_slsa_sbom_and_signature() {
    let (built, _spec_tmp) = common::make_built_artifact();
    let cas_root = TempDir::new().expect("tempdir");
    let cas = FsCas::new(cas_root.path()).expect("FsCas");

    let cfg = AttestationConfig::default();
    // Sanity-check the default posture matches the spec doc.
    assert_eq!(cfg.slsa.level, spec::SlsaLevel::L2);
    assert_eq!(cfg.sbom.format, spec::SbomFormat::CycloneDx);
    assert_eq!(cfg.sign.kind, SignKind::CosignKeyless);

    let stub = StubCosignInvoker::new(CosignOutcome::SignedAndRecorded {
        bundle_bytes: FAKE_BUNDLE.as_bytes().to_vec(),
        log_index: 9999,
    });
    let outputs = attest_with_invoker(&built, &cfg, &cas, &stub).expect("attest");

    assert!(
        outputs.slsa.is_some(),
        "default posture must produce a SLSA statement"
    );
    let sbom = outputs
        .sbom
        .as_ref()
        .expect("default posture must produce a CycloneDX SBOM");
    assert_eq!(sbom.media_type, SbomMediaType::CycloneDxJson);
    let sig = outputs
        .signature
        .as_ref()
        .expect("default posture must produce a signature");
    assert_eq!(sig.rekor_log_index, 9999);

    // Cosign was actually invoked — the stub recorded the call.
    let invocation = stub
        .last_invocation()
        .expect("cosign code path must have been reached");
    assert_eq!(invocation.kind, SignKind::CosignKeyless);
    assert_eq!(
        invocation.manifest_digest, built.manifest_digest,
        "cosign must be invoked against the manifest digest"
    );
}
