//! Asserts the three pillars are independent: opting out of one
//! does not opt out the others.
//!
//! Bug this catches: a shared "skip if any pillar opted out" guard
//! (the kind of "let's centralise the early-return" refactor that
//! looks tidy in PR review) would silently disable two pillars
//! when the operator only meant to disable one.

mod common;

use cas::FsCas;
use spec::{
    AttestationConfig, SbomConfig, SbomFormat, SbomScope, SignConfig, SignKind, SlsaConfig,
    SlsaLevel,
};
use tempfile::TempDir;

use attest::core::cosign::{CosignOutcome, StubCosignInvoker};
use attest::saf::attest::attest_with_invoker;

const FAKE_BUNDLE: &str = r#"{
  "rekorBundle": { "Payload": { "logIndex": 1, "integratedTime": 1 } }
}"#;

fn ok_stub() -> StubCosignInvoker {
    StubCosignInvoker::new(CosignOutcome::SignedAndRecorded {
        bundle_bytes: FAKE_BUNDLE.as_bytes().to_vec(),
        log_index: 1,
    })
}

#[test]
fn test_opt_out_slsa_keeps_sbom_and_signature() {
    let (built, _spec_tmp) = common::make_built_artifact();
    let cas_root = TempDir::new().expect("tempdir");
    let cas = FsCas::new(cas_root.path()).expect("FsCas");
    let cfg = AttestationConfig {
        slsa: SlsaConfig {
            level: SlsaLevel::Off,
            builder_id: None,
        },
        ..AttestationConfig::default()
    };
    let stub = ok_stub();
    let outputs = attest_with_invoker(&built, &cfg, &cas, &stub).expect("attest");

    assert!(outputs.slsa.is_none(), "SLSA opted out");
    assert!(outputs.sbom.is_some(), "SBOM still runs");
    assert!(outputs.signature.is_some(), "signature still runs");
}

#[test]
fn test_opt_out_sbom_keeps_slsa_and_signature() {
    let (built, _spec_tmp) = common::make_built_artifact();
    let cas_root = TempDir::new().expect("tempdir");
    let cas = FsCas::new(cas_root.path()).expect("FsCas");
    let cfg = AttestationConfig {
        sbom: SbomConfig {
            format: SbomFormat::Off,
            scope: SbomScope::Layers,
        },
        ..AttestationConfig::default()
    };
    let stub = ok_stub();
    let outputs = attest_with_invoker(&built, &cfg, &cas, &stub).expect("attest");

    assert!(outputs.slsa.is_some(), "SLSA still runs");
    assert!(outputs.sbom.is_none(), "SBOM opted out");
    assert!(outputs.signature.is_some(), "signature still runs");
}

#[test]
fn test_opt_out_sign_keeps_slsa_and_sbom() {
    let (built, _spec_tmp) = common::make_built_artifact();
    let cas_root = TempDir::new().expect("tempdir");
    let cas = FsCas::new(cas_root.path()).expect("FsCas");
    let cfg = AttestationConfig {
        sign: SignConfig {
            kind: SignKind::Off,
            identity: None,
        },
        ..AttestationConfig::default()
    };
    // Sign opted out, so even an "unhappy" invoker won't matter —
    // it must NOT be called.
    let stub = StubCosignInvoker::new(CosignOutcome::SignFailed {
        stderr: "should never be reached".into(),
    });
    let outputs = attest_with_invoker(&built, &cfg, &cas, &stub).expect("attest");

    assert!(outputs.slsa.is_some(), "SLSA still runs");
    assert!(outputs.sbom.is_some(), "SBOM still runs");
    assert!(outputs.signature.is_none(), "sign opted out");
    assert!(
        stub.last_invocation().is_none(),
        "cosign invoker must NOT be called when sign.kind = Off"
    );
}

#[test]
fn test_all_three_off_returns_three_nones() {
    // Bug this catches: the "all three off" cross-product (a state
    // operators reach by setting `--no-attest` flags) silently
    // emitting one of the pillars due to a missing branch.
    let (built, _spec_tmp) = common::make_built_artifact();
    let cas_root = TempDir::new().expect("tempdir");
    let cas = FsCas::new(cas_root.path()).expect("FsCas");
    let cfg = AttestationConfig {
        slsa: SlsaConfig {
            level: SlsaLevel::Off,
            builder_id: None,
        },
        sbom: SbomConfig {
            format: SbomFormat::Off,
            scope: SbomScope::Layers,
        },
        sign: SignConfig {
            kind: SignKind::Off,
            identity: None,
        },
    };
    let stub = StubCosignInvoker::new(CosignOutcome::SignFailed {
        stderr: "unreachable".into(),
    });
    let outputs = attest_with_invoker(&built, &cfg, &cas, &stub).expect("attest");
    assert!(outputs.slsa.is_none());
    assert!(outputs.sbom.is_none());
    assert!(outputs.signature.is_none());
}
