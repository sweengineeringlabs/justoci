//! Real Fulcio + Rekor end-to-end round-trip against Sigstore
//! staging via the [`attest::core::justsign_invoker::JustsignInvoker`]
//! (`fulcio.sigstage.dev` / `rekor.sigstage.dev`).
//!
//! Skip-pass pattern: the test ALWAYS compiles + links + runs; it
//! returns early with a `SKIP[justsign-e2e]: ...` marker (mirrored
//! from the justsign repo's own staging tests) when the
//! environment to drive a live call isn't present. That keeps the
//! default `cargo test --workspace` green on machines without
//! network access or a staging-trusted OIDC issuer, while still
//! lighting up in CI when the dedicated staging job sets the
//! gating env vars.
//!
//! Two gates:
//!
//! * `JUSTSIGN_E2E_STAGING` — must be exactly `"1"`. Opt-in flag
//!   so the test never silently bills staging quota on a default
//!   `cargo test`. Mirrors `JUSTSIGN_FULCIO_STAGING` from the
//!   sibling justsign crate.
//! * One of `JUSTSIGN_OIDC_TOKEN` or `SIGSTORE_ID_TOKEN` —
//!   non-empty. We can't mint an OIDC token without a human (or a
//!   CI-side identity-token exchange that's out of scope here);
//!   unset = SKIP.
//!
//! ## Why staging, never production
//!
//! Production Sigstore's Rekor is the canonical, immutable, public
//! transparency log. Anything written to it is permanent and
//! cannot be deleted. CI test runs writing to production Rekor
//! would pollute that log forever. The hard rule:
//!
//!   > Use staging, never production. Any path that defaults to
//!   > production from a test is a bug.
//!
//! This test verifies that contract end-to-end: it calls
//! [`JustsignInvoker::staging`] (never `::new()`) and asserts the
//! constructed invoker's `target()` is `Staging` BEFORE any I/O
//! happens, so a regression that flips the constructor's target
//! is caught before a real Rekor write.
//!
//! ## Bug class caught
//!
//! Wire-format drift between justsign's bundle shape and what the
//! staging Rekor + Fulcio actually accept end-to-end. The unit
//! suite (`tests/justsign_invoker_unit_test.rs` + the inline
//! tests in `core::justsign_invoker`) verifies isolated piece
//! behaviour — env-var precedence, target routing, kind
//! rejection — but cannot surface protocol-level integration
//! bugs because none of those tests speak to a live server. This
//! e2e test is the only place a renamed Fulcio JSON field, a
//! header that became required, or a Rekor body shape Rekor
//! decided to reject can be caught before downstream consumers
//! hit the same wall.
//!
//! ## CI invocation (recommended)
//!
//! See the parallel pattern in `attest/tests/sigstore_e2e_test.rs`
//! (the sigstore-rs counterpart). Suggested job shape:
//!
//! ```bash
//! JUSTSIGN_E2E_STAGING=1 \
//! SIGSTORE_ID_TOKEN="$(curl_oidc_token aud=sigstore)" \
//! cargo test -p swe_justoci_attest \
//!   --no-default-features --features justsign \
//!   --test justsign_e2e_test -- --test-threads=1
//! ```
//!
//! `--test-threads=1` serialises OIDC token use because Sigstore
//! rate-limits per-identity.
//!
//! ## Feature gating
//!
//! Whole file gated behind `feature = "justsign"`. Under the
//! default `sigstore-rs` feature the `JustsignInvoker` type
//! doesn't exist (the module is `#[cfg(feature = "justsign")]`)
//! so the file compiles down to an empty crate-root and the
//! test count is 0 — same shape as
//! `tests/sigstore_e2e_test.rs` under `--features cosign-subprocess`.

#![cfg(feature = "justsign")]

use cas::{Algorithm, Digest};
use spec::SignKind;

use attest::core::cosign::{CosignInvocation, CosignInvoker, CosignOutcome};
use attest::core::justsign_invoker::{JustsignInvoker, JustsignTarget};

/// Marker the test prints to stderr when it skips. Greppable from
/// CI logs to confirm the SKIP is intentional, not a silent pass —
/// mirrors the `SKIP[sigstore-e2e]` marker in the sibling test.
const SKIP_MARKER: &str = "SKIP[justsign-e2e]";

/// Resolve an OIDC token from the environment, returning `None`
/// if neither `JUSTSIGN_OIDC_TOKEN` nor `SIGSTORE_ID_TOKEN` is
/// set non-empty. Both are accepted because the justsign sibling
/// repo's staging tests use `JUSTSIGN_OIDC_TOKEN` while justoci's
/// sigstore-rs e2e test uses `SIGSTORE_ID_TOKEN` — accepting both
/// here means a CI job with either var set will exercise the wire
/// without re-templating between repos.
fn oidc_token_from_env() -> Option<String> {
    for key in ["JUSTSIGN_OIDC_TOKEN", "SIGSTORE_ID_TOKEN"] {
        if let Ok(v) = std::env::var(key) {
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

#[test]
fn test_real_justsign_staging_signs_and_records_in_rekor() {
    // Bug class caught (when the test runs):
    //
    // (a) Wire-format drift: justsign's `HttpFulcioClient` body
    //     shape, `HttpRekorClient` body shape, or
    //     `Bundle::encode_json()` output drifting away from what
    //     the staging Sigstore deployment accepts. The unit suite
    //     can't surface this; only a live round-trip can.
    //
    // (b) Production hygiene: a regression that ships
    //     `JustsignInvoker::staging()` returning a Production-
    //     targeted invoker would write CI test runs to the public
    //     production Rekor log forever. The staging pin is
    //     load-bearing — this test asserts the constructor returns
    //     a Staging-targeted invoker BEFORE any I/O fires, so a
    //     mistargeting is caught client-side.

    // ── Skip-pass gate 1: opt-in flag ───────────────────────────────
    // Default cargo test runs MUST NOT bill staging quota or
    // contact the network. The flag is the explicit handshake from
    // the CI job that DOES want this test to run.
    match std::env::var("JUSTSIGN_E2E_STAGING").as_deref() {
        Ok("1") => {}
        _ => {
            eprintln!(
                "{SKIP_MARKER}: JUSTSIGN_E2E_STAGING != 1 — staging Fulcio + Rekor \
                 e2e round-trip skipped. Set JUSTSIGN_E2E_STAGING=1 plus \
                 SIGSTORE_ID_TOKEN (or JUSTSIGN_OIDC_TOKEN) to a JWT with \
                 aud=sigstore to exercise the live wire."
            );
            return;
        }
    }

    // ── Skip-pass gate 2: caller-supplied OIDC token ────────────────
    // Without a token Fulcio rejects the CSR exchange with HTTP
    // 401. Surfacing that as a test failure would be misleading
    // (it's a missing-prereq, not a code bug), so unset = SKIP.
    let token = match oidc_token_from_env() {
        Some(t) => t,
        None => {
            eprintln!(
                "{SKIP_MARKER}: SIGSTORE_ID_TOKEN / JUSTSIGN_OIDC_TOKEN unset or empty — \
                 cannot mint a staging Fulcio cert without an OIDC token."
            );
            return;
        }
    };

    // The invoker reads `SIGSTORE_ID_TOKEN` from the environment
    // (or `OIDC_TOKEN` as fallback). If the CI job set
    // `JUSTSIGN_OIDC_TOKEN` only — to match the sibling justsign
    // staging test's contract — we forward it into
    // `SIGSTORE_ID_TOKEN` for the duration of this test. The
    // mutation is process-global; the test runs single-threaded
    // (CI is expected to pass `--test-threads=1`), so no race.
    // We restore the prior value at the end.
    let prev_sigstore_id = std::env::var("SIGSTORE_ID_TOKEN").ok();
    std::env::set_var("SIGSTORE_ID_TOKEN", &token);

    // Construction-time invariant: BEFORE any network call, the
    // staging constructor MUST produce a Staging-targeted
    // invoker. If this assertion ever fails we want the test to
    // explode here, not after a write to a real Rekor instance —
    // catching the bug client-side is the cheap path.
    let invoker = JustsignInvoker::staging();
    assert_eq!(
        invoker.target(),
        JustsignTarget::Staging,
        "JustsignInvoker::staging() MUST return a Staging-targeted invoker; \
         a Production target here would mean every staging-e2e CI run writes \
         to the immutable public production Rekor log"
    );

    let invocation = CosignInvocation {
        manifest_digest: Digest::from_bytes(Algorithm::Sha256, b"justsign-e2e-staging"),
        kind: SignKind::CosignKeyless,
        identity: Some("ci-justsign-staging-e2e".to_string()),
    };

    let outcome = invoker.invoke(&invocation);

    // Restore SIGSTORE_ID_TOKEN BEFORE asserting so a panic
    // here doesn't leak our injected token into sibling tests.
    match prev_sigstore_id {
        Some(v) => std::env::set_var("SIGSTORE_ID_TOKEN", v),
        None => std::env::remove_var("SIGSTORE_ID_TOKEN"),
    }

    // Branch on the outcome. The honest results are:
    //
    //   1. SignedAndRecorded { bundle_bytes, log_index } — the
    //      live round-trip succeeded. Assert the bundle parses,
    //      the log_index is plausibly valid, and the bundle's
    //      Rekor + cert-chain shape is what a downstream verifier
    //      would expect.
    //
    //   2. SignedNotRecorded — Rekor accepted the request shape
    //      but rejected the body, OR justsign's `sign_blob_keyless`
    //      returned an Ok bundle with empty tlog_entries (the §6
    //      defensive guard). This is a real bug class for the
    //      justsign producer side — print the reason, then fail
    //      with diagnostics so an on-call can see what staging
    //      reported.
    //
    //   3. SignFailed — Fulcio rejected the cert exchange, or any
    //      step before Rekor failed. Almost always a config /
    //      reachability issue (proxy, DNS, expired token); we
    //      print the stderr verbatim so an on-call can route on
    //      it. Treated as a failed test because the gates above
    //      already filtered the "no token / no flag" cases.
    //
    //   4. CosignNotInstalled — unreachable here because we
    //      verified the OIDC token is set above and forwarded it
    //      into `SIGSTORE_ID_TOKEN`. Reaching this would mean the
    //      env-resolution logic regressed.
    match outcome {
        CosignOutcome::SignedAndRecorded {
            bundle_bytes,
            log_index,
        } => {
            assert!(
                log_index > 0,
                "staging Rekor log_index must be > 0 (Rekor log indices are \
                 monotonically increasing positive integers); got: {log_index}"
            );
            assert!(
                !bundle_bytes.is_empty(),
                "SignedAndRecorded bundle_bytes must be non-empty"
            );
            // The bundle MUST parse as JSON — a non-JSON bundle
            // would round-trip to a registry referrer that no
            // verifier could read.
            let bundle: serde_json::Value = serde_json::from_slice(&bundle_bytes)
                .expect("staging bundle must be valid JSON (sigstore protobuf v0.3)");
            // §6 belt-and-braces: tlogEntries MUST contain exactly
            // one entry — matching the single Rekor write
            // `sign_blob_keyless` performed.
            let tlog_count = bundle
                .get("verificationMaterial")
                .and_then(|v| v.get("tlogEntries"))
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .expect("staging bundle must carry verificationMaterial.tlogEntries");
            assert_eq!(
                tlog_count, 1,
                "staging bundle must contain exactly one Rekor entry; got {tlog_count} \
                 (a count of 0 means the §6 Rekor-coupling guarantee was bypassed; \
                 a count of >1 is unexpected for a single sign call)"
            );
            // Cert chain MUST be attached — keyless verification
            // requires the leaf's SubjectPublicKeyInfo to validate
            // the DSSE signature.
            let cert_count = bundle
                .get("verificationMaterial")
                .and_then(|v| v.get("x509CertificateChain"))
                .and_then(|v| v.get("certificates"))
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .or_else(|| {
                    // Spec crate may emit `certificate.certificates`
                    // (singular wrapping object) — accept either
                    // shape since spec drift between versions of
                    // the bundle wire format is exactly the kind
                    // of surface we want this test to surface.
                    bundle
                        .get("verificationMaterial")
                        .and_then(|v| v.get("certificate"))
                        .and_then(|v| v.get("certificates"))
                        .and_then(|v| v.as_array())
                        .map(|a| a.len())
                });
            match cert_count {
                Some(n) if n >= 1 => { /* leaf present */ }
                Some(0) => panic!(
                    "staging bundle has empty cert chain — keyless verification \
                     requires the leaf cert. Wire-shape regression suspected."
                ),
                None => panic!(
                    "staging bundle missing verificationMaterial cert chain — \
                     bundle JSON shape: {bundle:#?}"
                ),
                _ => unreachable!(),
            }
            eprintln!(
                "{SKIP_MARKER}-OK: staging round-trip succeeded; Rekor log_index = \
                 {log_index}, bundle bytes = {} bytes",
                bundle_bytes.len()
            );
        }
        CosignOutcome::SignedNotRecorded { reason } => panic!(
            "staging Rekor write reported as not-recorded; this would mean \
             Sigstore staging is degraded OR our justsign code path returned a \
             half-state that the §6 coupling rule forbids. Investigate: {reason}"
        ),
        CosignOutcome::SignFailed { stderr } => panic!(
            "staging round-trip failed with SignFailed: {stderr}\n\
             (the env gates above already filtered the 'no token' case, so \
             this is either a real wire-format / reachability bug, or a \
             Fulcio-side outage — check `curl https://fulcio.sigstage.dev/` \
             and the OIDC token's aud claim)"
        ),
        CosignOutcome::CosignNotInstalled => panic!(
            "OIDC token was set above (we verified above) — reaching \
             CosignNotInstalled means the env-resolution logic regressed \
             (or the test's env forwarding from JUSTSIGN_OIDC_TOKEN to \
             SIGSTORE_ID_TOKEN got dropped)"
        ),
    }
}
