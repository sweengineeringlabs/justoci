//! Asserts SBOM emission is skipped when the format is `Off`.
//!
//! Bug this catches: a wired-through `Off` branch that still emits
//! a SBOM blob would (a) waste CAS space, (b) defeat the spec's
//! opt-out semantics, and (c) confuse downstream publish into
//! registering a bogus referrer.

mod common;

use cas::FsCas;
use spec::{AttestationConfig, SbomConfig, SbomFormat, SbomScope, SignConfig, SignKind};
use tempfile::TempDir;

use attest::core::cosign::{CosignOutcome, StubCosignInvoker};
use attest::saf::attest::attest_with_invoker;

#[test]
fn test_attest_with_sbom_off_returns_none() {
    let (built, _spec_tmp) = common::make_built_artifact();
    let cas_root = TempDir::new().expect("tempdir");
    let cas = FsCas::new(cas_root.path()).expect("FsCas");

    // We disable signing in this test (Off) so the test doesn't
    // depend on cosign being present — the focus is the SBOM=Off
    // branch.
    let cfg = AttestationConfig {
        sbom: SbomConfig {
            format: SbomFormat::Off,
            scope: SbomScope::Layers,
        },
        sign: SignConfig {
            kind: SignKind::Off,
            ..SignConfig::default()
        },
        ..AttestationConfig::default()
    };

    // No-op invoker — won't be called because sign.kind = Off.
    let invoker = StubCosignInvoker::new(CosignOutcome::CosignNotInstalled);
    let outputs = attest_with_invoker(&built, &cfg, &cas, &invoker).expect("attest");

    assert!(
        outputs.sbom.is_none(),
        "SBOM=Off must produce no SBOM output"
    );
    assert!(
        outputs.slsa.is_some(),
        "SBOM=Off must NOT affect SLSA pillar"
    );
}
