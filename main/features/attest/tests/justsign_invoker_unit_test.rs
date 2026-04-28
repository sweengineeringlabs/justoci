//! Integration-test surface for [`attest::core::justsign_invoker::JustsignInvoker`].
//!
//! Lives in `tests/` (not inline `#[cfg(test)]`) so it builds the
//! crate the way a downstream consumer would — exercises the public
//! re-exports in `attest::core` as well as the trait surface in
//! `attest::core::cosign`. Mirrors `tests/sigstore_invoker_unit_test.rs`
//! in shape, scope, and skip behaviour.
//!
//! Three classes of test live here:
//!
//! 1. **Construction-time invariants** — assert that the
//!    `new()` / `default()` / `staging()` constructors target the
//!    correct Sigstore-compatible deployment. Production hygiene:
//!    a regression here would cause CI test runs to write to the
//!    immutable production Rekor.
//! 2. **`SignKind` rejection** — assert that `CosignKey` and `Off`
//!    short-circuit with actionable typed errors before any I/O
//!    happens. The orchestrator already filters `Off`; reaching the
//!    invoker with `Off` is a programmer error and the message says
//!    so.
//! 3. **OIDC-missing path** — assert that `invoke()` returns
//!    `CosignNotInstalled` (the "signer unavailable" variant) when
//!    no OIDC token env var is set. The orchestrator maps this to
//!    `AttestError::CosignNotInstalled` so operators get the
//!    actionable "configure SIGSTORE_ID_TOKEN" message — NOT a
//!    generic Fulcio HTTP 401 from a downstream layer.
//!
//! ## Feature gating
//!
//! Whole file gated behind `feature = "justsign"`. Under
//! `--no-default-features --features sigstore-rs` (the default) the
//! `JustsignInvoker` type doesn't exist, so the file compiles down
//! to an empty crate-root and the test count is 0 — same shape as
//! `sigstore_invoker_unit_test.rs` under `--features cosign-subprocess`.
//!
//! ## What this file does NOT test
//!
//! * Live Fulcio / Rekor I/O — covered by the skip-pass e2e test in
//!   `tests/justsign_e2e_test.rs`.
//! * Bundle-bytes round-trip through the orchestrator — covered
//!   indirectly by the §6 contract test in
//!   `tests/sign_not_recorded_returns_specific_error_test.rs` which
//!   uses the `StubCosignInvoker` and is invoker-shape-agnostic.

#![cfg(feature = "justsign")]

use std::sync::Mutex;

use cas::{Algorithm, Digest};
use spec::SignKind;

use attest::core::cosign::{CosignInvocation, CosignInvoker, CosignOutcome};
use attest::core::justsign_invoker::{JustsignInvoker, JustsignTarget};

/// Serialises tests that mutate process-global env vars
/// (`SIGSTORE_ID_TOKEN`, `OIDC_TOKEN`) — the same pattern the
/// inline tests in `core::justsign_invoker::tests` use, applied at
/// the integration-test scope so the OIDC-missing test can stash +
/// restore env vars without racing parallel sibling tests in this
/// same binary. Cargo runs `tests/*.rs` files as separate binaries
/// but tests *within* one file share a process, so the mutex is
/// scoped to this file.
static ENV_MUTEX: Mutex<()> = Mutex::new(());

fn fake_invocation(kind: SignKind) -> CosignInvocation {
    CosignInvocation {
        manifest_digest: Digest::from_bytes(Algorithm::Sha256, b"justsign-unit-test"),
        kind,
        identity: None,
    }
}

#[test]
fn test_default_invoker_targets_production() {
    // Bug it catches: a regression that flips the default target
    // to Staging would cause every `JustsignInvoker::default()`
    // caller (including the production attest path when an
    // operator builds with `--features justsign`) to write
    // CI/test runs to the staging Rekor — quietly breaking every
    // operator who relies on production Rekor for verification.
    // Mirror of the corresponding sigstore_invoker test.
    assert_eq!(
        JustsignInvoker::default().target(),
        JustsignTarget::Production
    );
}

#[test]
fn test_staging_invoker_targets_staging() {
    // Bug it catches: a regression that makes
    // `JustsignInvoker::staging` accidentally return a production-
    // targeted invoker would invert the e2e test —
    // `JUSTSIGN_E2E_STAGING=1` runs would write production Rekor
    // entries instead of staging ones, polluting the immutable
    // public production log.
    assert_eq!(JustsignInvoker::staging().target(), JustsignTarget::Staging);
}

#[test]
fn test_invoke_with_cosign_key_kind_returns_actionable_sign_failed() {
    // Bug it catches: a regression where `SignKind::CosignKey`
    // (BYO local keyfile mode) silently falls through to the
    // keyless flow and tries to mint a Fulcio cert. That would
    // surface as a confusing Fulcio HTTP 4xx far down the stack;
    // operators would chase a Fulcio config bug when the real fix
    // is "rebuild with --features cosign-subprocess for keyfile
    // signing or set sign.kind = cosign-keyless".
    //
    // The actionable error message MUST name `cosign-subprocess`
    // and `cosign-keyless` so operators see the two routes
    // forward without reading source code.
    let invoker = JustsignInvoker::new();
    let outcome = invoker.invoke(&fake_invocation(SignKind::CosignKey));
    match outcome {
        CosignOutcome::SignFailed { stderr } => {
            assert!(
                stderr.contains("cosign-key"),
                "error must name the rejected sign kind; got: {stderr}"
            );
            assert!(
                stderr.contains("cosign-subprocess"),
                "error must point at the alternate feature flag; got: {stderr}"
            );
            assert!(
                stderr.contains("cosign-keyless"),
                "error must point at the alternate sign kind; got: {stderr}"
            );
        }
        other => panic!(
            "CosignKey kind must surface as SignFailed with actionable message, got: {other:?}"
        ),
    }
}

#[test]
fn test_invoke_with_off_kind_returns_programmer_error_message() {
    // Bug it catches: the orchestrator (`sign_with`) is
    // responsible for short-circuiting `SignKind::Off` BEFORE
    // invoking the trait. A regression where Off reaches the
    // invoker would either cause the keyless flow to attempt a
    // real OIDC + Fulcio + Rekor round-trip (network calls,
    // potentially polluting the transparency log) or a confusing
    // crash. The invoker surfaces this distinctly as a
    // "programmer error" so the bug surfaces in tests rather
    // than in production.
    let invoker = JustsignInvoker::new();
    let outcome = invoker.invoke(&fake_invocation(SignKind::Off));
    match outcome {
        CosignOutcome::SignFailed { stderr } => {
            assert!(
                stderr.contains("programmer error"),
                "Off-at-invoker must surface as programmer error; got: {stderr}"
            );
            assert!(
                stderr.contains("Off"),
                "error must name the offending kind; got: {stderr}"
            );
        }
        other => panic!(
            "Off kind reaching the invoker must surface as SignFailed with programmer-error \
             message, got: {other:?}"
        ),
    }
}

#[test]
fn test_invoke_with_no_oidc_token_returns_cosign_not_installed() {
    // Bug it catches: a regression where missing OIDC token env
    // vars (`SIGSTORE_ID_TOKEN` / `OIDC_TOKEN`) surface as a
    // generic `SignFailed { stderr: "Fulcio HTTP 4xx" }` from
    // downstream — operators reading the error would chase a
    // Fulcio outage when the real fix is "set SIGSTORE_ID_TOKEN".
    // The `CosignNotInstalled` variant is the actionable signal
    // the orchestrator maps to `AttestError::CosignNotInstalled`,
    // whose Display string says "configure SIGSTORE_ID_TOKEN or
    // set sign.kind=off".
    //
    // Mutates process-global env vars. Holds `ENV_MUTEX` for the
    // whole body so a sibling test in this same binary that
    // sets either var doesn't race the unset/check sequence
    // here. Stashes + restores prior values so the test is
    // hermetic regardless of what the host environment had set.
    let _g = ENV_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
    let prev_sig = std::env::var("SIGSTORE_ID_TOKEN").ok();
    let prev_oidc = std::env::var("OIDC_TOKEN").ok();
    std::env::remove_var("SIGSTORE_ID_TOKEN");
    std::env::remove_var("OIDC_TOKEN");

    let invoker = JustsignInvoker::new();
    let outcome = invoker.invoke(&fake_invocation(SignKind::CosignKeyless));

    // Restore env BEFORE asserting so a panic doesn't leak the
    // unset state into a sibling test.
    if let Some(v) = prev_sig {
        std::env::set_var("SIGSTORE_ID_TOKEN", v);
    }
    if let Some(v) = prev_oidc {
        std::env::set_var("OIDC_TOKEN", v);
    }

    match outcome {
        CosignOutcome::CosignNotInstalled => { /* correct */ }
        other => panic!(
            "missing OIDC token must surface as CosignNotInstalled (signer unavailable), \
             not as SignFailed with a downstream HTTP error or a SignedAndRecorded write \
             to a real Rekor; got: {other:?}"
        ),
    }
}
