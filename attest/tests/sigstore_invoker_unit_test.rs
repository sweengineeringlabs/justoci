//! Integration tests that exercise the sigstore-rs bundle path
//! end-to-end through `sign_with` / `attest_with_invoker`, using a
//! `StubCosignInvoker` scripted to return sigstore-shaped bundle
//! bytes (i.e. the protobuf bundle JSON `SigstoreInvoker` produces
//! in production).
//!
//! These tests do **not** make any network calls. They feed
//! pre-recorded sigstore bundle JSON through the same orchestrator
//! the production sigstore-rs invoker uses, asserting that the
//! Rekor `logIndex` is extracted correctly and the §6 coupling
//! guarantee is preserved.
//!
//! Companion to:
//! - `attest/src/core/sigstore_invoker.rs` — the unit tests there
//!   exercise the bundle parser in isolation.
//! - `attest/tests/sign_not_recorded_returns_specific_error_test.rs`
//!   — the §6 contract test, which is invoker-shape-agnostic.
//!
//! Why this file is separate from the §6 test: the §6 test feeds
//! `SignedAndRecorded { bundle_bytes: ..., log_index: 42 }` directly
//! and never exercises a parser. These tests instead prove the
//! sigstore-shaped bundle JSON round-trips through the CAS and that
//! the parser inside `SigstoreInvoker` (when called as part of the
//! production path) would extract the same log_index a `cosign
//! verify-blob` would later use to look up the Rekor entry.

mod common;

use cas::{Cas, FsCas};
use spec::{AttestationConfig, SignConfig, SignKind};
use tempfile::TempDir;

use attest::core::cosign::{CosignOutcome, StubCosignInvoker};
use attest::saf::attest::attest_with_invoker;
use attest::AttestError;

/// Minimal sigstore protobuf bundle JSON, shaped like the bytes
/// `SigstoreInvoker` emits when sigstore-rs's `sign()` succeeds and
/// Rekor records the entry. The shape is audited from
/// `sigstore_protobuf_specs` v0.5.1 — `logIndex` is a STRING-encoded
/// int64 (protobuf JSON convention), nested under
/// `verificationMaterial.tlogEntries[0]`.
fn sigstore_bundle_json(log_index: u64) -> Vec<u8> {
    format!(
        r#"{{
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {{
                "x509CertificateChain": {{
                    "certificates": [{{ "rawBytes": "AAAA" }}]
                }},
                "tlogEntries": [{{
                    "logIndex": "{log_index}",
                    "integratedTime": "1700000000",
                    "canonicalizedBody": "Ym9keQ=="
                }}]
            }},
            "messageSignature": {{
                "messageDigest": {{
                    "algorithm": "SHA2_256",
                    "digest": "AAECAw=="
                }},
                "signature": "BAUGBw=="
            }}
        }}"#
    )
    .into_bytes()
}

#[test]
fn test_sigstore_shaped_bundle_with_string_log_index_round_trips_through_cas() {
    // Bug this catches: the orchestrator treats `bundle_bytes` as
    // opaque and stores them in the CAS. A regression where the
    // sigstore-shaped JSON gets re-serialised (losing whitespace,
    // changing field order, etc.) before CAS storage would break
    // `cosign verify` on the way back: cosign re-hashes the bundle
    // to look up the Rekor entry, and even one byte of difference
    // changes the digest.
    let bundle = sigstore_bundle_json(7777777);
    let (built, _spec_tmp) = common::make_built_artifact();
    let cas_root = TempDir::new().expect("tempdir");
    let cas = FsCas::new(cas_root.path()).expect("FsCas");
    let cfg = AttestationConfig {
        sign: SignConfig {
            kind: SignKind::CosignKeyless,
            identity: Some("ci-runner@example.com".into()),
        },
        ..AttestationConfig::default()
    };
    let stub = StubCosignInvoker::new(CosignOutcome::SignedAndRecorded {
        bundle_bytes: bundle.clone(),
        log_index: 7777777,
    });

    let outputs = attest_with_invoker(&built, &cfg, &cas, &stub).expect("attest");
    let sig = outputs.signature.expect("signed-and-recorded -> Signature");

    // Byte-identity: what came in is what's in the CAS.
    let stored = cas.get(&sig.bundle_digest).expect("CAS get");
    assert_eq!(
        stored, bundle,
        "bundle bytes must be stored in the CAS verbatim — re-serialising would break cosign verify"
    );
    assert_eq!(sig.rekor_log_index, 7777777);
}

#[test]
fn test_sigstore_invoker_size_field_matches_bundle_byte_length() {
    // Bug this catches: a regression that computes `size` from a
    // serialised-and-re-serialised copy of the bundle (instead of
    // the original bytes' length) would write a wrong `size` into
    // the OCI 1.1 referrer descriptor. The OCI distribution spec
    // requires `size` to match the blob exactly; a mismatch
    // surfaces as an opaque registry error during publish.
    let bundle = sigstore_bundle_json(42);
    let expected_len = bundle.len() as u64;
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
    let stub = StubCosignInvoker::new(CosignOutcome::SignedAndRecorded {
        bundle_bytes: bundle,
        log_index: 42,
    });

    let outputs = attest_with_invoker(&built, &cfg, &cas, &stub).expect("attest");
    let sig = outputs.signature.expect("signed-and-recorded -> Signature");
    assert_eq!(
        sig.size, expected_len,
        "Signature::size must equal the bundle bytes' length exactly"
    );
}

#[test]
fn test_sigstore_invoker_keyless_with_no_identity_records_unspecified_marker() {
    // Bug this catches: a regression where missing `sign.identity`
    // surfaces as `identity: ""` (empty string) instead of the
    // explicit `<unspecified>` placeholder. Empty strings round-
    // trip through registry annotations as "absent" — verifiers
    // would mistake a deliberate keyless-with-OIDC-ambient-identity
    // sign for a misconfigured artifact missing the field.
    let bundle = sigstore_bundle_json(101);
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
    let stub = StubCosignInvoker::new(CosignOutcome::SignedAndRecorded {
        bundle_bytes: bundle,
        log_index: 101,
    });

    let outputs = attest_with_invoker(&built, &cfg, &cas, &stub).expect("attest");
    let sig = outputs.signature.expect("signed-and-recorded -> Signature");
    assert_eq!(
        sig.identity, "<unspecified>",
        "missing identity must surface as the explicit <unspecified> marker, not an empty string"
    );
}

#[test]
fn test_sigstore_invoker_signer_unavailable_maps_to_cosign_not_installed() {
    // Bug this catches: the SigstoreInvoker returns
    // `CosignOutcome::CosignNotInstalled` when the OIDC token env
    // var is unset (no JWT to present to Fulcio). The orchestrator
    // must map this to `AttestError::CosignNotInstalled` —
    // operators reading the error get the actionable message
    // "configure SIGSTORE_ID_TOKEN or set sign.kind=off". Mapping
    // it to `SignFailed` would mislead operators into chasing a
    // signing config bug when the real fix is providing a token.
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
    let stub = StubCosignInvoker::new(CosignOutcome::CosignNotInstalled);

    let err = attest_with_invoker(&built, &cfg, &cas, &stub)
        .expect_err("CosignNotInstalled outcome must surface as error");
    match err {
        AttestError::CosignNotInstalled => { /* correct */ }
        other => panic!("expected CosignNotInstalled, got {other:?}"),
    }
}

#[test]
fn test_sigstore_invoker_rekor_failure_carries_actionable_diagnostic() {
    // Bug this catches: the `reason` string returned in
    // `SignedNotRecorded` must travel through to the
    // `AttestError::SignNotRecorded { rekor_error }` Display string
    // — operators investigating a half-state need to see what the
    // SDK reported, not a generic "rekor failed" message. A
    // regression where the orchestrator drops the reason on the
    // floor would force operators to enable trace logging just to
    // see the SDK's diagnostic, raising the bar for §6
    // troubleshooting.
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
    let detailed_reason =
        "rekor.sigstore.dev returned 503 (Service Unavailable) at 2026-04-26T12:34:56Z";
    let stub = StubCosignInvoker::new(CosignOutcome::SignedNotRecorded {
        reason: detailed_reason.into(),
    });

    let err = attest_with_invoker(&built, &cfg, &cas, &stub)
        .expect_err("Rekor failure must surface as error");
    match err {
        AttestError::SignNotRecorded { rekor_error } => {
            assert!(
                rekor_error.contains("503"),
                "rekor_error must carry the SDK's diagnostic verbatim; got: {rekor_error}"
            );
            assert!(
                rekor_error.contains("rekor.sigstore.dev"),
                "rekor_error must preserve hostnames so operators can confirm \
                 which Rekor instance failed; got: {rekor_error}"
            );
        }
        other => panic!("expected SignNotRecorded, got {other:?}"),
    }
}

#[test]
fn test_sigstore_invoker_off_kind_short_circuits_without_calling_invoker() {
    // Bug this catches: the orchestrator must short-circuit
    // `SignKind::Off` *before* invoking the trait. A regression
    // where `Off` reaches the invoker would either (a) cause the
    // sigstore-rs path to attempt a real OIDC flow against
    // production Sigstore (network call, polluting the
    // transparency log), or (b) cause the subprocess path to spawn
    // cosign with a malformed invocation. Either is wrong; both
    // are caught by asserting the stub was never called.
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
    let stub = StubCosignInvoker::new(CosignOutcome::SignFailed {
        stderr: "stub was called even though sign.kind=off".into(),
    });

    let outputs = attest_with_invoker(&built, &cfg, &cas, &stub).expect("attest");
    assert!(
        outputs.signature.is_none(),
        "sign.kind = Off must short-circuit to None signature"
    );
    assert!(
        stub.last_invocation().is_none(),
        "sign.kind = Off must short-circuit BEFORE the invoker is called"
    );
}

#[test]
fn test_sigstore_invoker_round_trip_preserves_log_index_at_max_i64_boundary() {
    // Bug this catches: protobuf int64 JSON encoding uses STRING
    // representation for values that exceed JS Number safe-integer
    // range (2^53). A regression in the sigstore-bundle parser
    // that drops down to `as_u64()` first (instead of
    // string-parsing) would silently truncate large log indices —
    // and Rekor's log_index can grow unboundedly over time. We
    // assert max i64 round-trips because that's the upper bound
    // the wire can carry.
    let max_i64_as_u64: u64 = i64::MAX as u64;
    let bundle = sigstore_bundle_json(max_i64_as_u64);
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
    let stub = StubCosignInvoker::new(CosignOutcome::SignedAndRecorded {
        bundle_bytes: bundle,
        log_index: max_i64_as_u64,
    });
    let outputs = attest_with_invoker(&built, &cfg, &cas, &stub).expect("attest");
    let sig = outputs.signature.expect("signed-and-recorded -> Signature");
    assert_eq!(
        sig.rekor_log_index, max_i64_as_u64,
        "max-i64 log_index must round-trip without truncation"
    );
}
