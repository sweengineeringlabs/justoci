//! Asserts the Production Guarantees §6 contract: a successful
//! cosign sign that did NOT make it into Rekor surfaces as
//! `AttestError::SignNotRecorded` — distinct from `SignFailed`.
//!
//! Bug this catches: a refactor that collapsed both failure modes
//! into a single `SignFailed` variant would mask the
//! "artifact-is-unsigned-but-cosign-thinks-it-signed" half-state.
//! The product position is "no half-states"; this test enforces it.
//!
//! And the inverse: a `SignFailed` (cosign exit non-zero, before
//! the Rekor step) must NOT surface as `SignNotRecorded`. The two
//! variants point at different operator actions:
//!   - SignFailed → fix cosign config / credentials, retry.
//!   - SignNotRecorded → check Rekor reachability; the artifact
//!     itself isn't signed, do not publish.

mod common;

use cas::{Cas, FsCas};
use spec::{AttestationConfig, SignConfig, SignKind};
use tempfile::TempDir;

use attest::core::cosign::{CosignOutcome, StubCosignInvoker};
use attest::saf::attest::attest_with_invoker;
use attest::AttestError;

#[test]
fn test_sign_succeeded_but_rekor_failed_returns_sign_not_recorded() {
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
    let stub = StubCosignInvoker::new(CosignOutcome::SignedNotRecorded {
        reason: "rekor.sigstore.dev returned 503".into(),
    });

    let err = attest_with_invoker(&built, &cfg, &cas, &stub)
        .expect_err("Rekor failure must surface as error, not Ok");
    match err {
        AttestError::SignNotRecorded { rekor_error } => {
            assert!(
                rekor_error.contains("rekor"),
                "rekor_error must carry the diagnostic; got: {rekor_error}"
            );
        }
        other => panic!(
            "expected SignNotRecorded (artifact is unsigned), got {other:?} \
             — collapsing this to a generic SignFailed misleads operators"
        ),
    }
}

#[test]
fn test_sign_step_failed_returns_sign_failed_not_sign_not_recorded() {
    // The mirror image: cosign exit non-zero must NOT be reported
    // as a Rekor problem. Operators reading SignNotRecorded would
    // chase a transparency-log issue when the real fix is in
    // cosign config.
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
    let stub = StubCosignInvoker::new(CosignOutcome::SignFailed {
        stderr: "OIDC token expired".into(),
    });

    let err = attest_with_invoker(&built, &cfg, &cas, &stub)
        .expect_err("cosign failure must surface as error");
    match err {
        AttestError::SignFailed { stderr } => {
            assert!(stderr.contains("OIDC"));
        }
        AttestError::SignNotRecorded { .. } => {
            panic!("cosign-exit-nonzero must NOT collapse into SignNotRecorded");
        }
        other => panic!("expected SignFailed, got {other:?}"),
    }
}

#[test]
fn test_signed_and_recorded_outcome_produces_signature_with_log_index() {
    // Bug this catches: a happy-path regression where the log_index
    // gets lost in transit (e.g. a refactor stops parsing it from
    // the bundle) — verifiers later would have no Rekor entry to
    // look up.
    let bundle = br#"{ "rekorBundle": { "Payload": { "logIndex": 42, "integratedTime": 1 } } }"#;
    let (built, _spec_tmp) = common::make_built_artifact();
    let cas_root = TempDir::new().expect("tempdir");
    let cas = FsCas::new(cas_root.path()).expect("FsCas");
    let cfg = AttestationConfig {
        sign: SignConfig {
            kind: SignKind::CosignKeyless,
            identity: Some("alice@example.com".into()),
        },
        ..AttestationConfig::default()
    };
    let stub = StubCosignInvoker::new(CosignOutcome::SignedAndRecorded {
        bundle_bytes: bundle.to_vec(),
        log_index: 42,
    });
    let outputs = attest_with_invoker(&built, &cfg, &cas, &stub).expect("attest");
    let sig = outputs
        .signature
        .expect("signed-and-recorded must produce signature");
    assert_eq!(sig.rekor_log_index, 42);
    assert_eq!(sig.identity, "alice@example.com");
    // The bundle bytes must round-trip through the CAS.
    let stored = cas.get(&sig.bundle_digest).expect("CAS get");
    assert_eq!(stored, bundle);
}
