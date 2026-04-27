//! `SigstoreInvoker` — the production `CosignInvoker` backed by the
//! [`sigstore`](https://crates.io/crates/sigstore) crate.
//!
//! This module is gated behind the `sigstore-rs` feature (default
//! on). It replaces the legacy `cosign` subprocess invocation with a
//! linked-in SDK call, keeping the `CosignInvoker` trait surface
//! unchanged so the rest of `attest` and every existing test
//! continue to work without modification.
//!
//! ## How the §6 coupling rule is preserved
//!
//! Spec doc Production Guarantee §6: "Sign + Rekor are coupled.
//! `cosign sign` succeeds → Rekor log entry confirmed → only then
//! is the artifact 'signed'. If Rekor fails, return
//! `AttestError::SignNotRecorded`."
//!
//! Sigstore-rs's `SigningSession::sign` is structured so the §6
//! rule is enforced **inside the SDK**:
//!
//! 1. The SDK requests a signing certificate from Fulcio.
//! 2. The SDK signs the artifact bytes with the ephemeral key.
//! 3. The SDK calls `create_log_entry` against Rekor with the
//!    signature bundle.
//! 4. **If the Rekor call returns an error, the entire `sign()` call
//!    returns `Err(SigstoreError::RekorClientError(...))`** — there
//!    is no path where `sign()` returns `Ok(SigningArtifact)` with
//!    a missing or absent log entry.
//! 5. The returned `SigningArtifact` carries a
//!    `TransparencyLogEntry` (i.e. the Rekor receipt) by
//!    construction; converting it to a `Bundle` includes the entry
//!    in the `tlog_entries` field unconditionally.
//!
//! Concretely: the §6 Rekor-coupling check moves from "parse the
//! bundle for `logIndex`" (the subprocess path) to "trust that
//! `sign()` returning `Ok` means Rekor recorded it". We **still**
//! parse the bundle for `logIndex` to populate
//! `Signature::rekor_log_index`, and we still surface a
//! `SignedNotRecorded` outcome if for any reason the SDK returned
//! an `Ok` bundle whose `tlog_entries` is empty (defensive — should
//! be unreachable per the SDK source we audited at v0.13.0, but a
//! future SDK version could regress and we'd rather catch it as a
//! `SignNotRecorded` than silently emit a Rekor-less Signature).
//!
//! See `docs/3-design/cosign_rekor.md` for the operator-facing
//! description of this flow.
//!
//! ## OIDC token sourcing
//!
//! Sigstore keyless signing requires an OIDC identity token whose
//! `aud` claim is `"sigstore"`. We do **not** run the interactive
//! browser-based OIDC flow (`oauth::openidflow`) — justoci is
//! invoked from CI and from operator scripts; popping a browser is
//! the wrong UX. Instead, the token is read from environment
//! variables, in priority order:
//!
//! 1. `SIGSTORE_ID_TOKEN` — sigstore convention.
//! 2. `OIDC_TOKEN` — generic fallback used by some CI templates.
//!
//! If neither is set, the invoker returns
//! `CosignOutcome::CosignNotInstalled` (the variant is reused as
//! "signer unavailable"; see the `CosignOutcome` docstring for the
//! rationale on keeping the variant name). Operators get a clear
//! actionable error: provide an OIDC token, or set
//! `attestation.sign.kind = "off"`.

use std::io::Cursor;

use sigstore::bundle::sign::SigningContext;
use sigstore::oauth::IdentityToken;

use super::cosign::{CosignInvocation, CosignInvoker, CosignOutcome};
use spec::SignKind;

/// Stable error string surfaced when an invoker constructed via
/// [`SigstoreInvoker::staging`] is invoked on sigstore-rs 0.13
/// (which doesn't expose a public staging path). Lifted to a
/// `pub(crate)` constant so the e2e test can substring-match
/// against it without coupling to the exact wording — see
/// `attest/tests/sigstore_e2e_test.rs`.
pub(crate) const STAGING_UNAVAILABLE_MSG: &str =
    "sigstore-rs 0.13 does not expose a public staging SigningContext (the \
     `Keyring` argument to `SigningContext::new` is `pub(crate)`); cannot \
     reach fulcio.sigstage.dev / rekor.sigstage.dev through the SDK from \
     external code. Tracking upstream sigstore-rs for a public `staging()` \
     constructor; until then this invoker is a harness-only stub. \
     Production code must use `SigstoreInvoker::new()` (production target).";

/// Which Sigstore instance the invoker targets.
///
/// Public-good Sigstore runs two parallel deployments:
///
/// - **Production** (`fulcio.sigstore.dev` / `rekor.sigstore.dev`)
///   — the canonical, immutable, public-facing transparency log.
///   Anything written here is permanent. This is the only target
///   for real artifacts.
/// - **Staging** (`fulcio.sigstage.dev` / `rekor.sigstage.dev`) —
///   a parallel deployment used by the Sigstore project for
///   integration testing. Writes are accepted but the staging
///   trust roots are NOT honoured by production cosign verifiers,
///   so signatures produced against staging cannot be verified
///   against production. Test-only target.
///
/// **The variant is load-bearing for production hygiene.** A
/// regression that defaults staging callers to production would
/// pollute the public log with CI test entries that are immutable
/// and cannot be deleted. The `staging()` constructor exists
/// solely to support `attest/tests/sigstore_e2e_test.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigstoreTarget {
    /// Public-good production. Default for real signing.
    Production,
    /// Staging deployment. Tests only.
    Staging,
}

/// Production `CosignInvoker` backed by the linked-in `sigstore`
/// SDK. Constructed with [`SigstoreInvoker::new`] (production) or
/// [`SigstoreInvoker::staging`] (test-only). The struct is
/// stateless — every `invoke` call constructs a fresh
/// `SigningContext` and `SigningSession`. That's the same shape
/// the SDK examples use (see `examples/bundle/main.rs` upstream)
/// and keeps the invoker `Send + Sync` without locks.
pub struct SigstoreInvoker {
    target: SigstoreTarget,
}

impl SigstoreInvoker {
    /// Construct an invoker against the public-good **production**
    /// Sigstore instance. This is the only constructor production
    /// code paths should call.
    pub fn new() -> Self {
        SigstoreInvoker {
            target: SigstoreTarget::Production,
        }
    }

    /// Construct an invoker against the public-good **staging**
    /// Sigstore instance (`fulcio.sigstage.dev` /
    /// `rekor.sigstage.dev`).
    ///
    /// **Test-only.** Staging trust roots are not honoured by
    /// production cosign verifiers; bundles produced here cannot be
    /// round-tripped through `cosign verify-blob` against the
    /// production trust root. Production code must NEVER call this.
    ///
    /// ## Upstream limitation (sigstore-rs 0.13)
    ///
    /// As of `sigstore = "0.13"`, the SDK does **not** expose a
    /// public `SigningContext::staging()` constructor. The
    /// equivalent type, `SigningContext::new(...)`, requires a
    /// `Keyring` argument whose type is `pub(crate)` — not
    /// constructible from outside the crate. The only publicly
    /// reachable trust root is hard-coded production via
    /// `SigningContext::production()`.
    ///
    /// Consequently, an invoker constructed via `staging()`
    /// currently surfaces a typed `SignFailed` outcome when invoked,
    /// with an actionable error message pointing at the upstream
    /// gap. The harness here (constructor + `target` field +
    /// `attest/tests/sigstore_e2e_test.rs`) is in place so that
    /// when sigstore-rs ships a public staging path, we lift the
    /// gate by routing through the new API — no changes to test
    /// code or CI plumbing required.
    ///
    /// Tracking: <https://github.com/sigstore/sigstore-rs/issues>
    /// (no `staging()` API in 0.13.0 / `main` as of audit).
    pub fn staging() -> Self {
        SigstoreInvoker {
            target: SigstoreTarget::Staging,
        }
    }

    /// Which target this invoker is configured against. Exposed for
    /// the e2e test to assert it didn't accidentally get a
    /// production-default invoker.
    pub fn target(&self) -> SigstoreTarget {
        self.target
    }
}

impl Default for SigstoreInvoker {
    fn default() -> Self {
        Self::new()
    }
}

impl CosignInvoker for SigstoreInvoker {
    fn invoke(&self, invocation: &CosignInvocation) -> CosignOutcome {
        // Cosign-key (BYO local key file) is not supported on the
        // sigstore-rs path: the SDK is built around the keyless
        // (Fulcio + Rekor + transparency log) flow. Operators
        // who need cosign-key must build with
        // `--no-default-features --features cosign-subprocess` and
        // have the cosign binary on PATH. Surface this as
        // SignFailed with an actionable message rather than
        // pretending we can do it and crashing later.
        if matches!(invocation.kind, SignKind::CosignKey) {
            return CosignOutcome::SignFailed {
                stderr: "sign.kind = \"cosign-key\" is not supported on the sigstore-rs path; \
                    rebuild with --features cosign-subprocess (and `cosign` on PATH) or use \
                    sign.kind = \"cosign-keyless\""
                    .to_string(),
            };
        }
        if matches!(invocation.kind, SignKind::Off) {
            // The orchestrator (`sign_with`) short-circuits Off
            // before ever invoking the trait; reaching here is a
            // bug in the caller, not a runtime failure mode.
            return CosignOutcome::SignFailed {
                stderr: "sigstore invoker called with SignKind::Off (programmer error)".to_string(),
            };
        }

        // ── 1. If staging was selected, fail fast with the upstream-gap ─
        //    diagnostic before doing any OIDC work. Staging
        //    unavailability is a build-time SDK limitation, not a
        //    runtime config issue; reporting it before token
        //    resolution gives operators the most actionable error.
        //    Equally important for §6 hygiene: a regression here
        //    must NOT silently fall through to production.
        if matches!(self.target, SigstoreTarget::Staging) {
            return CosignOutcome::SignFailed {
                stderr: STAGING_UNAVAILABLE_MSG.to_string(),
            };
        }

        // ── 2. Resolve OIDC identity token ──────────────────────────────
        let raw_token = match resolve_oidc_token() {
            Some(t) => t,
            None => return CosignOutcome::CosignNotInstalled,
        };
        let identity_token = match IdentityToken::try_from(raw_token.as_str()) {
            Ok(t) => t,
            Err(e) => {
                return CosignOutcome::SignFailed {
                    stderr: format!(
                        "OIDC token rejected by sigstore: {e}. \
                         Token must be a JWT with aud=\"sigstore\". \
                         Configure SIGSTORE_ID_TOKEN to a valid token."
                    ),
                };
            }
        };

        // ── 3. Build a SigningContext against the production Sigstore ───
        //    Staging was already short-circuited above, so we know
        //    `target == Production` here. `production()` blocks on a
        //    current-thread tokio runtime internally; the SDK creates
        //    one for the duration of the call. This is fine for our
        //    sync API: we don't need to thread a runtime through
        //    `attest`.
        let ctx = match SigningContext::production() {
            Ok(c) => c,
            Err(e) => {
                return CosignOutcome::SignFailed {
                    stderr: format!("could not initialise Sigstore production trust root: {e}"),
                };
            }
        };

        // ── 4. Open a blocking signing session ──────────────────────────
        // `blocking_signer` does the Fulcio CSR exchange to obtain a
        // short-lived signing certificate bound to the OIDC subject.
        let session = match ctx.blocking_signer(identity_token) {
            Ok(s) => s,
            Err(e) => {
                return CosignOutcome::SignFailed {
                    stderr: format!("Fulcio certificate exchange failed: {e}"),
                };
            }
        };

        // ── 5. Sign the manifest digest bytes ───────────────────────────
        // Symmetric with the subprocess path: we sign the digest
        // *string* (e.g. "sha256:abc..."), not the manifest bytes.
        // That keeps the signed payload small and stable, and
        // matches what cosign-verify-blob expects on the verify
        // side. A future iteration could sign the manifest bytes.
        let payload = invocation.manifest_digest.to_string();
        let signing_artifact = match session.sign(Cursor::new(payload.into_bytes())) {
            Ok(a) => a,
            Err(e) => {
                // sigstore-rs's `sign` returns Err when *anything*
                // in the chain fails — including the Rekor write.
                // We can't reliably distinguish "Fulcio failed" from
                // "Rekor failed" from the public error type alone
                // (both are `SigstoreError` variants stringified
                // through Display). For §6 correctness this is
                // fine: the orchestrator only needs to know "sign
                // didn't complete with a Rekor receipt" — that
                // surfaces as SignFailed, which the CLI maps to
                // exit 3 (AttestError class). The error message
                // carries the SDK's Display so operators can
                // diagnose Rekor outages vs Fulcio outages from
                // the text. We err toward `SignFailed` rather than
                // `SignNotRecorded` because we don't have a
                // typed-error guarantee that `Ok` was returned
                // from Fulcio before Rekor was attempted.
                return CosignOutcome::SignFailed {
                    stderr: format!("sigstore sign failed: {e}"),
                };
            }
        };

        // ── 6. Convert the artifact to a Bundle, serialise to JSON ──────
        let bundle = signing_artifact.to_bundle();
        let bundle_bytes = match serde_json::to_vec(&bundle) {
            Ok(b) => b,
            Err(e) => {
                return CosignOutcome::SignFailed {
                    stderr: format!("could not serialise sigstore Bundle to JSON: {e}"),
                };
            }
        };

        // ── 7. Extract the Rekor log_index from the bundle ──────────────
        // The §6 belt-and-braces check: even though the SDK's
        // `sign()` only returns `Ok` when Rekor recorded the entry
        // (per audit of sigstore-rs v0.13.0 source), we still
        // verify the bundle's `tlog_entries` is non-empty and
        // pull out the `logIndex` for `Signature::rekor_log_index`.
        // If the bundle is somehow Rekor-less, surface as
        // `SignedNotRecorded` — that's the §6 unsigned-state
        // signal, never a "signature without receipt" half-state.
        match extract_sigstore_bundle_log_index(&bundle_bytes) {
            Some(log_index) => CosignOutcome::SignedAndRecorded {
                bundle_bytes,
                log_index,
            },
            None => CosignOutcome::SignedNotRecorded {
                reason: "sigstore Bundle returned by sign() has no \
                         verificationMaterial.tlogEntries[0].logIndex \
                         (Rekor entry missing — defensive guard, \
                         this should be unreachable per sigstore-rs v0.13)"
                    .to_string(),
            },
        }
    }
}

/// Resolve the OIDC identity-token JWT from the environment.
/// Returns `Some(token)` if `SIGSTORE_ID_TOKEN` or `OIDC_TOKEN` is
/// set to a non-empty value, `None` otherwise.
///
/// We deliberately do **not** trigger the interactive browser
/// OIDC flow that the upstream `examples/bundle/main.rs` uses —
/// justoci is non-interactive (CI, scripted operator runs).
fn resolve_oidc_token() -> Option<String> {
    for key in ["SIGSTORE_ID_TOKEN", "OIDC_TOKEN"] {
        match std::env::var(key) {
            Ok(v) if !v.is_empty() => return Some(v),
            _ => continue,
        }
    }
    None
}

/// Extract the Rekor `logIndex` from a serialised sigstore protobuf
/// bundle (media type
/// `application/vnd.dev.sigstore.bundle.v0.3+json`).
///
/// The sigstore protobuf bundle JSON (audited from
/// `sigstore_protobuf_specs` v0.5.1) shape:
///
/// ```text
/// { "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
///   "verificationMaterial": {
///     "x509CertificateChain": { ... },
///     "tlogEntries": [
///       { "logIndex": "12345",        // STRING — protobuf int64
///         "integratedTime": "1700000000",
///         "canonicalizedBody": "..." } ] },
///   "messageSignature": { ... } }
/// ```
///
/// Notes for the maintainer:
/// - `logIndex` is a **string** in the JSON encoding (protobuf
///   int64 JSON convention), not a number. We parse it as such.
/// - The shape differs from the legacy cosign bundle parsed in
///   `core::cosign::extract_cosign_legacy_log_index`: that one
///   nests the field at `rekorBundle.Payload.logIndex` and uses
///   numeric encoding. The two parsers are deliberately separate
///   so the cosign-subprocess fallback continues to work
///   bit-for-bit identically.
pub(crate) fn extract_sigstore_bundle_log_index(bundle_bytes: &[u8]) -> Option<u64> {
    let v: serde_json::Value = serde_json::from_slice(bundle_bytes).ok()?;
    let entries = v
        .get("verificationMaterial")?
        .get("tlogEntries")?
        .as_array()?;
    let first = entries.first()?;
    let log_index = first.get("logIndex")?;
    // Per protobuf int64 JSON encoding the field is a STRING.
    // Belt-and-braces: also accept a JSON number, in case a
    // future sigstore-rs encoder switches representations.
    if let Some(s) = log_index.as_str() {
        s.parse::<u64>().ok()
    } else {
        log_index.as_u64()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serialises tests that mutate process-global env vars
    /// (`SIGSTORE_ID_TOKEN`, `OIDC_TOKEN`). Cargo runs tests within
    /// a module in parallel by default, so two env-var tests racing
    /// each other intermittently corrupts each other's setup —
    /// observed pre-fix as `oidc-token-loses` -> None when the
    /// sibling test `remove_var`'d between this test's set and read.
    /// Hold the mutex for the entire duration of any test that
    /// touches these env vars.
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn test_extract_sigstore_log_index_parses_string_encoded_int64() {
        // Catches: a parser that expects a JSON number (the cosign
        // legacy shape) would fail to extract logIndex from a
        // sigstore bundle, surfacing every signed artifact as
        // SignNotRecorded — silently breaking §6 by routing real
        // signatures into the unsigned-state error path.
        let bundle = br#"{
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {
                "tlogEntries": [
                    { "logIndex": "1234567",
                      "integratedTime": "1700000000",
                      "canonicalizedBody": "AAAA" }
                ]
            }
        }"#;
        assert_eq!(extract_sigstore_bundle_log_index(bundle), Some(1234567));
    }

    #[test]
    fn test_extract_sigstore_log_index_accepts_numeric_encoding() {
        // Forward-compat: a future sigstore-rs encoder that emits
        // logIndex as a JSON number must still parse cleanly. Catches
        // a regression where we hardcode `as_str()` and lose
        // compatibility silently.
        let bundle = br#"{
            "verificationMaterial": {
                "tlogEntries": [ { "logIndex": 9999 } ]
            }
        }"#;
        assert_eq!(extract_sigstore_bundle_log_index(bundle), Some(9999));
    }

    #[test]
    fn test_extract_sigstore_log_index_returns_none_when_tlog_entries_empty() {
        // The §6 belt-and-braces guard: a bundle with an empty
        // tlogEntries array means Rekor did not record. We must
        // surface this as None so sign_with returns SignNotRecorded,
        // not pretend a signature exists with a phantom log_index.
        let bundle = br#"{
            "verificationMaterial": { "tlogEntries": [] }
        }"#;
        assert_eq!(extract_sigstore_bundle_log_index(bundle), None);
    }

    #[test]
    fn test_extract_sigstore_log_index_returns_none_when_verification_material_missing() {
        // A malformed bundle missing verificationMaterial entirely
        // (e.g. an SDK regression that drops the Rekor receipt
        // unconditionally) must NOT panic — must surface as None
        // and bubble up to SignNotRecorded.
        let bundle = br#"{ "mediaType": "x", "messageSignature": {} }"#;
        assert_eq!(extract_sigstore_bundle_log_index(bundle), None);
    }

    #[test]
    fn test_extract_sigstore_log_index_returns_none_for_malformed_json() {
        // A corrupt bundle (truncated download, encoding bug) must
        // not panic the attestation pipeline; it must surface as
        // None and bubble up to SignNotRecorded with a clear reason.
        let bundle = b"not json at all";
        assert_eq!(extract_sigstore_bundle_log_index(bundle), None);
    }

    #[test]
    fn test_extract_sigstore_log_index_returns_none_for_unparseable_string() {
        // Catches: a bundle with a logIndex string that isn't a
        // valid integer (e.g. "12.5", "1e9", "abc") must not panic
        // and must surface as None — defending against a future
        // sigstore-rs encoding bug or an attacker-crafted bundle.
        let bundle = br#"{
            "verificationMaterial": {
                "tlogEntries": [ { "logIndex": "not-a-number" } ]
            }
        }"#;
        assert_eq!(extract_sigstore_bundle_log_index(bundle), None);
    }

    #[test]
    fn test_resolve_oidc_token_prefers_sigstore_id_token_over_oidc_token() {
        // Catches: a regression where the env var precedence
        // inverts (or one of the two is dropped) would silently
        // grab the wrong token in CI environments where both are
        // set (e.g. GitHub Actions setting OIDC_TOKEN for ambient
        // identity, plus a build script setting SIGSTORE_ID_TOKEN
        // for an explicit Sigstore audience).
        //
        // The test mutates process-global env vars; ENV_MUTEX
        // serialises with the sibling env-touching test so we don't
        // observe each other's transient state under cargo's
        // default parallel test execution.
        let _g = ENV_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let prev_sig = std::env::var("SIGSTORE_ID_TOKEN").ok();
        let prev_oidc = std::env::var("OIDC_TOKEN").ok();

        std::env::set_var("SIGSTORE_ID_TOKEN", "sigstore-token-wins");
        std::env::set_var("OIDC_TOKEN", "oidc-token-loses");
        assert_eq!(resolve_oidc_token().as_deref(), Some("sigstore-token-wins"));

        std::env::remove_var("SIGSTORE_ID_TOKEN");
        assert_eq!(resolve_oidc_token().as_deref(), Some("oidc-token-loses"));

        std::env::remove_var("OIDC_TOKEN");
        assert_eq!(resolve_oidc_token(), None);

        // Restore for any later test in the same process.
        if let Some(v) = prev_sig {
            std::env::set_var("SIGSTORE_ID_TOKEN", v);
        }
        if let Some(v) = prev_oidc {
            std::env::set_var("OIDC_TOKEN", v);
        }
    }

    #[test]
    fn test_new_constructor_targets_production() {
        // Bug this catches: a regression that flips the default
        // target to Staging would cause every `SigstoreInvoker::new`
        // caller (including the production attest path in
        // `saf::attest::attest`) to write CI/test runs to the
        // staging Rekor instead of production — quietly breaking
        // every operator who relies on production Rekor for
        // verification. Production hygiene rule.
        let inv = SigstoreInvoker::new();
        assert_eq!(inv.target(), SigstoreTarget::Production);
    }

    #[test]
    fn test_default_constructor_targets_production() {
        // Bug this catches: a regression where `Default::default()`
        // diverges from `new()` (e.g. someone "helpfully" makes
        // Default point at a stub for tests) would silently change
        // production behaviour. The two must remain identical.
        assert_eq!(
            SigstoreInvoker::default().target(),
            SigstoreInvoker::new().target()
        );
    }

    #[test]
    fn test_staging_constructor_targets_staging() {
        // Bug this catches: a regression that makes
        // `SigstoreInvoker::staging` accidentally return a
        // production-targeted invoker would invert the e2e test —
        // `cargo test sigstore_e2e -- --ignored` would write
        // production Rekor entries instead of skipping cleanly,
        // polluting the immutable production log. The hard rule
        // "Use staging, never production" depends on this assertion.
        let inv = SigstoreInvoker::staging();
        assert_eq!(inv.target(), SigstoreTarget::Staging);
    }

    #[test]
    fn test_staging_invoker_short_circuits_before_oidc_resolution() {
        // Bug this catches: a regression that silently falls back
        // to production when staging can't be constructed (e.g.
        // future code added `or SigningContext::production()`)
        // would write CI test runs to the production transparency
        // log forever. We assert that staging produces a typed
        // `SignFailed` whose message names the upstream sigstore-rs
        // limitation — never a Production Rekor write, never a
        // confusing OIDC-config error.
        //
        // We deliberately do NOT mutate process-global env vars here:
        //
        // - The staging-target check is *the first thing* `invoke`
        //   does (after the kind-not-supported guard). It must
        //   short-circuit regardless of whether `OIDC_TOKEN` /
        //   `SIGSTORE_ID_TOKEN` is set, unset, valid, or malformed.
        //   Reading any of those branches as a test outcome would
        //   indicate a real regression.
        // - Mutating env vars here races with `test_resolve_oidc_*`
        //   tests in the same module under parallel test execution.
        //   The point of *this* test is to prove the staging branch
        //   is env-independent; the env-precedence tests cover the
        //   env path separately.
        let inv = SigstoreInvoker::staging();
        let invocation = CosignInvocation {
            manifest_digest: cas::Digest::from_bytes(cas::Algorithm::Sha256, b"test"),
            kind: SignKind::CosignKeyless,
            identity: None,
        };
        let outcome = inv.invoke(&invocation);
        match outcome {
            CosignOutcome::SignFailed { stderr } => {
                assert!(
                    stderr.contains("sigstore-rs 0.13 does not expose a public staging"),
                    "staging invoker must surface the upstream limitation verbatim, \
                     not a production trust-root error or OIDC-config error; got: {stderr}"
                );
                assert!(
                    !stderr.contains("production trust root"),
                    "staging invoker MUST NOT fall back to production semantics \
                     (Rekor pollution risk); got: {stderr}"
                );
            }
            CosignOutcome::CosignNotInstalled => {
                panic!(
                    "staging invoker must short-circuit BEFORE OIDC token resolution; \
                     reaching CosignNotInstalled means a regression added an OIDC \
                     check ahead of the staging-target check"
                );
            }
            CosignOutcome::SignedAndRecorded { .. } => {
                panic!(
                    "staging invoker must NEVER return SignedAndRecorded — that \
                     means we wrote to a Rekor instance, polluting either \
                     production or staging from a unit test"
                );
            }
            other => panic!(
                "staging invoker must surface SignFailed with the upstream-gap \
                 message, got: {other:?}"
            ),
        }
    }

    #[test]
    fn test_resolve_oidc_token_treats_empty_string_as_unset() {
        // Catches: a regression where `Ok("")` is treated as a
        // valid token. CI env vars often expand to empty strings
        // when no value is provided (e.g.
        // `SIGSTORE_ID_TOKEN=${ID_TOKEN_VAR:-}` with `ID_TOKEN_VAR`
        // unset). An empty string would then be passed to
        // `IdentityToken::try_from(&str)`, which would fail with
        // "Malformed JWT" — a confusing error compared to the
        // actionable "OIDC token not configured" we want.
        let _g = ENV_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
        let prev = std::env::var("SIGSTORE_ID_TOKEN").ok();
        let prev_oidc = std::env::var("OIDC_TOKEN").ok();
        std::env::remove_var("OIDC_TOKEN");
        std::env::set_var("SIGSTORE_ID_TOKEN", "");
        assert_eq!(resolve_oidc_token(), None);

        std::env::remove_var("SIGSTORE_ID_TOKEN");
        if let Some(v) = prev {
            std::env::set_var("SIGSTORE_ID_TOKEN", v);
        }
        if let Some(v) = prev_oidc {
            std::env::set_var("OIDC_TOKEN", v);
        }
    }
}
