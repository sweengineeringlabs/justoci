//! Real Fulcio + Rekor end-to-end against Sigstore staging
//! (`fulcio.sigstage.dev` / `rekor.sigstage.dev`).
//!
//! Every test in this file is `#[ignore]`-gated. They are NOT part of
//! the default `cargo test` run; CI invokes them explicitly with
//! `cargo test ... -- --ignored --test-threads=1` from a job that
//! grants OIDC `id-token: write` permission.
//!
//! ## Why staging, never production
//!
//! Production Sigstore's Rekor is the canonical, immutable, public
//! transparency log. Anything written to it is permanent and cannot
//! be deleted. CI test runs writing to production Rekor would
//! pollute that log forever. The hard rule:
//!
//!   > Use staging, never production. Any path that defaults to
//!   > production from a test is a bug.
//!
//! This test verifies that contract end-to-end: it calls
//! `SigstoreInvoker::staging()` (never `::new()`), and asserts the
//! resulting outcome did not touch production trust roots.
//!
//! ## Why these tests are also a stub today
//!
//! `sigstore = "0.13"` (the version we link against) does **not**
//! expose a public way to construct a `SigningContext` for staging:
//! `SigningContext::production()` exists; `SigningContext::staging()`
//! does not. The lower-level `SigningContext::new(fulcio, rekor,
//! ctfe_keyring)` is publicly callable, but the `Keyring` argument
//! type is `pub(crate)`, so it cannot be constructed from outside
//! the sigstore crate.
//!
//! The `SigstoreInvoker::staging()` constructor we ship today
//! returns an invoker that surfaces this upstream gap as a typed
//! `CosignOutcome::SignFailed` with an actionable diagnostic — see
//! `attest::core::sigstore_invoker::STAGING_UNAVAILABLE_MSG`.
//!
//! These tests therefore serve two purposes:
//!
//! 1. **Today (sigstore-rs 0.13):** assert that the staging
//!    constructor is wired up and that invoking it does NOT silently
//!    fall back to production Sigstore (which would pollute the
//!    immutable production Rekor log on every CI run). The test runs
//!    on every CI invocation with `--ignored` and SKIPs cleanly with
//!    a documented reason if `OIDC_TOKEN` is absent (local dev).
//! 2. **Tomorrow (sigstore-rs adds staging):** the same test will
//!    light up — invoking the staging invoker will hit
//!    `fulcio.sigstage.dev` for a real cert, sign a fixture digest,
//!    write to `rekor.sigstage.dev`, and read back the Rekor entry.
//!    Lifting the gate is one PR against `sigstore_invoker.rs`; this
//!    test file does not need to change.
//!
//! ## CI invocation
//!
//! See `.github/workflows/ci.yml` job `sigstore-e2e`. That job
//! requests an OIDC token via `actions/github-script` with audience
//! `sigstore` (Fulcio staging requires `aud="sigstore"`), exports it
//! as `OIDC_TOKEN`, and runs:
//!
//! ```bash
//! cargo test -p swe_justoci_attest \
//!   --test sigstore_e2e_test -- --ignored --test-threads=1
//! ```
//!
//! `--test-threads=1` serialises OIDC token use because Sigstore
//! rate-limits per-identity.
//!
//! ## Feature gating
//!
//! The whole file is gated behind `feature = "sigstore-rs"`. Under
//! `--no-default-features --features cosign-subprocess` the
//! `SigstoreInvoker` type doesn't exist (the module is
//! `#[cfg(feature = "sigstore-rs")]`), so the file compiles down to
//! an empty crate-root and the test count is 0 — same effect as
//! a missing test, no behavioural surprise.

#![cfg(feature = "sigstore-rs")]

mod common;

use attest::core::cosign::{CosignInvocation, CosignInvoker, CosignOutcome};
use attest::core::sigstore_invoker::{SigstoreInvoker, SigstoreTarget};
use spec::SignKind;

/// Marker the test prints to stderr when it skips. Greppable from CI
/// logs to confirm the SKIP is intentional, not a silent pass.
const SKIP_MARKER: &str = "SKIP[sigstore-e2e]";

/// Resolve an OIDC token from the environment, returning `None` if
/// neither `OIDC_TOKEN` nor `SIGSTORE_ID_TOKEN` is set. Mirrors the
/// invoker's own resolution order — the test fakes the same env
/// surface the production code reads.
fn oidc_token_from_env() -> Option<String> {
    for key in ["OIDC_TOKEN", "SIGSTORE_ID_TOKEN"] {
        if let Ok(v) = std::env::var(key) {
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

#[test]
#[ignore = "requires OIDC token + network reachability to fulcio.sigstage.dev"]
fn test_real_sigstore_staging_signs_and_records_in_rekor() {
    // Bug this catches:
    //
    // (a) Production hygiene: a regression that ships
    //     `SigstoreInvoker` defaulting to `Production` for every
    //     constructor would write CI test runs to the public
    //     production Rekor log forever. The staging pin is
    //     load-bearing — this test asserts the constructor returns
    //     a Staging-targeted invoker and that invoking it does NOT
    //     produce a successfully-signed-and-recorded outcome
    //     (which would imply a Rekor write happened — to which
    //     instance?).
    //
    // (b) Wiring regression: a future PR that lifts staging support
    //     in sigstore-rs and rewires `SigstoreInvoker::staging` must
    //     keep `target() == Staging`. If a maintainer accidentally
    //     plumbs `SigningContext::production()` into the staging
    //     constructor (because production is the path of least
    //     resistance), this test catches it before the test ever
    //     reaches Rekor.

    if oidc_token_from_env().is_none() {
        eprintln!(
            "{SKIP_MARKER}: OIDC_TOKEN/SIGSTORE_ID_TOKEN not set; staging e2e \
             requires a CI OIDC bootstrap (aud=\"sigstore\"). Local laptops \
             without GitHub Actions id-token: write should skip this test."
        );
        return;
    }

    // Construction-time invariant: the staging constructor MUST
    // produce a Staging-targeted invoker. A regression here would
    // be the most expensive-to-detect bug class — silent production
    // Rekor writes — so we assert it before any I/O happens.
    let invoker = SigstoreInvoker::staging();
    assert_eq!(
        invoker.target(),
        SigstoreTarget::Staging,
        "SigstoreInvoker::staging() MUST return a Staging-targeted invoker; \
         a Production target here would mean every staging-e2e CI run writes \
         to the immutable public production Rekor log"
    );

    let (built, _spec_tmp) = common::make_built_artifact();
    let invocation = CosignInvocation {
        manifest_digest: built.manifest_digest.clone(),
        kind: SignKind::CosignKeyless,
        identity: Some("ci-sigstore-staging-e2e".to_string()),
    };

    let outcome = invoker.invoke(&invocation);

    // Branch on the outcome. There are exactly three honest results:
    //
    //   1. SignFailed { stderr } where stderr names the upstream-gap
    //      diagnostic — this is the current (sigstore-rs 0.13)
    //      reality. We assert the diagnostic does NOT name production
    //      semantics (no fall-through to prod Rekor) and SKIP-pass
    //      the test with a clear marker for CI grep.
    //
    //   2. SignedAndRecorded { bundle_bytes, log_index } — sigstore-rs
    //      grew staging support since this test was written. We
    //      assert the bundle parses, the log_index is non-zero, and
    //      that the bundle's identity claim is plausibly the OIDC
    //      subject we presented. (We don't query rekor.sigstage.dev
    //      to confirm the entry — that would add a network
    //      dependency unrelated to the §6 contract being tested
    //      here. A future test can do the round-trip lookup.)
    //
    //   3. Anything else (SignedNotRecorded, CosignNotInstalled,
    //      SignFailed with a different message) is a bug — fail
    //      loudly.
    match outcome {
        CosignOutcome::SignFailed { stderr } => {
            // Path 1. Verify it's the upstream-gap diagnostic, not
            // a Rekor outage (which would be a different SignFailed).
            assert!(
                stderr.contains("sigstore-rs 0.13 does not expose a public staging"),
                "staging invoker on sigstore-rs 0.13 must surface the upstream-gap \
                 diagnostic verbatim; got: {stderr}"
            );
            // Critical: the diagnostic must NOT mention production —
            // a fall-through to prod would say "production trust root".
            assert!(
                !stderr.contains("production trust root"),
                "staging invoker MUST NOT fall back to production trust roots \
                 (immutable Rekor pollution risk); got: {stderr}"
            );
            eprintln!(
                "{SKIP_MARKER}: sigstore-rs 0.13 does not expose staging; staging \
                 invoker correctly surfaced the upstream-gap diagnostic without \
                 falling back to production. When sigstore-rs ships a public \
                 `staging()` API, this branch will become unreachable and the \
                 SignedAndRecorded branch will exercise the live wire."
            );
        }
        CosignOutcome::SignedAndRecorded {
            bundle_bytes,
            log_index,
        } => {
            // Path 2. Live staging path is now wired. Validate.
            assert!(
                log_index > 0,
                "staging Rekor log_index must be > 0 (Rekor log indices are \
                 monotonically increasing positive integers); got: {log_index}"
            );
            assert!(
                !bundle_bytes.is_empty(),
                "SignedAndRecorded bundle bytes must be non-empty"
            );
            // Verify the bundle is valid JSON and contains the expected
            // shape. A bundle that doesn't parse here would round-trip
            // to a registry referrer that no verifier could read.
            let bundle: serde_json::Value = serde_json::from_slice(&bundle_bytes)
                .expect("staging bundle must be valid JSON (sigstore protobuf v0.3)");
            let media_type = bundle
                .get("mediaType")
                .and_then(|v| v.as_str())
                .expect("staging bundle must carry a mediaType field");
            assert!(
                media_type.starts_with("application/vnd.dev.sigstore.bundle"),
                "staging bundle mediaType must be a sigstore bundle media type; \
                 got: {media_type}"
            );
            // The tlogEntries list must contain exactly one entry —
            // matching the single Rekor write the SDK performed.
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
        }
        CosignOutcome::SignedNotRecorded { reason } => panic!(
            "staging Rekor write reported as not-recorded; this would mean Sigstore \
             staging is in a degraded state, OR our SDK code path returned a half-state \
             that the §6 coupling rule forbids. Investigate: {reason}"
        ),
        CosignOutcome::CosignNotInstalled => panic!(
            "OIDC_TOKEN was set above (we checked) — reaching CosignNotInstalled \
             means the env-resolution logic regressed (or the test got the env \
             precedence wrong)"
        ),
    }
}

#[test]
#[ignore = "interop test deferred to v0.2 — see test body for rationale"]
fn test_real_sigstore_staging_signature_verifies_via_cosign_verify_blob() {
    // Bug this *would* catch: sigstore-rs produces a bundle that
    // `cosign verify-blob` cannot parse (interop regression). If our
    // SigstoreInvoker output doesn't round-trip through the canonical
    // cosign CLI verifier, downstream consumers using cosign for
    // verification will silently fail to verify our signatures.
    //
    // ## Status: harness-deferred to v0.2
    //
    // Three reasons this test ships ignored-without-skip-message
    // today:
    //
    // 1. **Upstream sigstore-rs 0.13 doesn't expose staging**, so
    //    we can't get a real bundle to feed to cosign. The
    //    SignFailed-with-staging-gap path that test #1 exercises
    //    can't produce a bundle to verify against.
    //
    // 2. **cosign CLI's staging trust root must match.** Cosign 2.x
    //    accepts `--trust-root staging` but has its own version of
    //    the staging TUF metadata. Verifying a bundle signed against
    //    one staging TUF snapshot with a cosign that has another
    //    staging TUF snapshot can fail for non-bug reasons. Pinning
    //    cosign + sigstore-rs versions so the trust roots agree is
    //    a v0.2 task.
    //
    // 3. **The `--certificate-identity` claim format depends on the
    //    OIDC issuer.** GitHub Actions with `aud=sigstore` issues a
    //    JWT whose subject is `repo:owner/repo:ref:refs/heads/main`
    //    or similar; cosign's expected `--certificate-identity` value
    //    must be templated from the runtime environment. Wiring that
    //    template into a portable test (vs hardcoding our repo path)
    //    is fiddly and the failure mode is "wrong identity rejected"
    //    which is a cosign-side problem, not a sigstore-rs interop
    //    bug.
    //
    // We ship the test placeholder to track the work and to make
    // it discoverable to the next maintainer. Lifting it is:
    // (a) wait for sigstore-rs staging support (which unblocks test
    // #1 too), then (b) install cosign in the CI job, (c) save the
    // staging bundle from test #1 to a tempfile, (d) spawn cosign
    // verify-blob with the staging trust root and the templated
    // identity. The shape is sketched below for the implementer.
    //
    // ```ignore
    // if oidc_token_from_env().is_none() { return; }
    // if which::which("cosign").is_err() { return; }
    // // ... obtain bundle from invoker.invoke(...) ...
    // // tempfile::NamedTempFile::new()? -> write bundle ->
    // // std::process::Command::new("cosign")
    // //     .arg("verify-blob")
    // //     .arg("--trust-root").arg("sigstage")           // pin
    // //     .arg("--certificate-identity").arg(expected)   // templated
    // //     .arg("--certificate-oidc-issuer").arg("https://token.actions.githubusercontent.com")
    // //     .arg("--bundle").arg(bundle_path)
    // //     .arg(payload_file)
    // //     .status()?
    // // assert exit 0
    // ```

    eprintln!(
        "{SKIP_MARKER}: cosign-verify-blob interop deferred to v0.2 (blocked on \
         sigstore-rs staging support; see test body)."
    );
}
