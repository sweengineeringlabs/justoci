//! Asserts the CosignNotInstalled error path.
//!
//! Bug this catches: mapping a missing-cosign condition to a generic
//! `SignFailed` would mislead operators into believing they had a
//! cosign config bug, when the real fix is "install cosign". The
//! distinct variant is the actionable signal.
//!
//! Two layers are tested:
//!
//! 1. The `attest_with_invoker` mapping: when the invoker returns
//!    `CosignOutcome::CosignNotInstalled`, the call returns
//!    `AttestError::CosignNotInstalled`.
//! 2. The `RealCosignInvoker` PATH probe: with PATH cleared, it
//!    returns `CosignNotInstalled` even when run directly. Gated
//!    behind a serial `#[ignore = "mutates process env"]` because
//!    `std::env::set_var` is process-global.

mod common;

use cas::FsCas;
use spec::{AttestationConfig, SignConfig, SignKind};
use tempfile::TempDir;

use attest::core::cosign::{CosignOutcome, StubCosignInvoker};
use attest::saf::attest::attest_with_invoker;
use attest::AttestError;

// `RealCosignInvoker` only exists under the `cosign-subprocess`
// Cargo feature; the PATH-probe test below is gated on that feature
// because it has no meaning on the sigstore-rs path (no PATH lookup
// happens). The `attest_with_invoker` mapping test above stays
// unconditional — it depends only on the trait and stub.
#[cfg(feature = "cosign-subprocess")]
use attest::core::cosign::{CosignInvocation, CosignInvoker, RealCosignInvoker};

#[test]
fn test_attest_maps_cosign_not_installed_outcome_to_typed_error() {
    let (built, _spec_tmp) = common::make_built_artifact();
    let cas_root = TempDir::new().expect("tempdir");
    let cas = FsCas::new(cas_root.path()).expect("FsCas");

    let cfg = AttestationConfig {
        sign: SignConfig {
            kind: SignKind::CosignKeyless,
            identity: None,
        },
        ..AttestationConfig::default()
    };
    let invoker = StubCosignInvoker::new(CosignOutcome::CosignNotInstalled);

    let err = attest_with_invoker(&built, &cfg, &cas, &invoker)
        .expect_err("CosignNotInstalled outcome must surface as error");
    match err {
        AttestError::CosignNotInstalled => { /* correct */ }
        other => panic!("expected CosignNotInstalled, got {other:?}"),
    }
}

#[cfg(feature = "cosign-subprocess")]
#[test]
#[ignore = "mutates process-global PATH; run with --ignored after isolated tests pass"]
fn test_real_invoker_returns_cosign_not_installed_when_path_has_no_cosign() {
    // Bug this catches: the path-probe accidentally treating an
    // empty PATH (or a PATH without cosign) as a successful probe
    // would route a missing-cosign condition into a SignFailed
    // (subprocess spawn error) instead of the dedicated variant.
    //
    // We mutate the process-global PATH to a single empty directory
    // so cosign_on_path() returns false. The test is `#[ignore]`d
    // because mutating the process env races with parallel tests
    // that also read PATH; run it explicitly with `cargo test --
    // --ignored`.
    let tmp = TempDir::new().expect("tempdir");
    let original_path = std::env::var_os("PATH");
    // This test is `#[ignore]`d so the harness will not run it
    // concurrently with other tests by default. Operators running
    // `--ignored` are expected to use `--test-threads=1`.
    std::env::set_var("PATH", tmp.path());

    let invoker = RealCosignInvoker::new();
    let outcome = invoker.invoke(&CosignInvocation {
        manifest_digest: cas::Digest::from_bytes(cas::Algorithm::Sha256, b"x"),
        kind: SignKind::CosignKeyless,
        identity: None,
    });

    // Restore PATH before any assertion to avoid leaking the empty
    // PATH into a panic-unwinding teardown.
    match original_path {
        Some(p) => std::env::set_var("PATH", p),
        None => std::env::remove_var("PATH"),
    }

    assert_eq!(outcome, CosignOutcome::CosignNotInstalled);
}
