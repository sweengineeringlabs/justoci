//! `JustsignInvoker` — the third production `CosignInvoker` impl,
//! backed by the in-house [`swe_justsign_*`](https://github.com/sweengineeringlabs/justsign)
//! stack instead of the sigstore-rs SDK.
//!
//! Gated behind the `justsign` Cargo feature (default off). The
//! v0.2 attest crate ships three interchangeable invokers:
//!
//! | Feature              | Type                    | Transport                                              |
//! |----------------------|-------------------------|--------------------------------------------------------|
//! | `sigstore-rs` (def.) | [`super::SigstoreInvoker`]   | linked-in [`sigstore`](https://crates.io/crates/sigstore) SDK |
//! | `cosign-subprocess`  | `super::RealCosignInvoker` | spawns the `cosign` CLI                                |
//! | `justsign`           | [`JustsignInvoker`]     | [`swe_justsign_sign::sign_blob_keyless`]               |
//!
//! All three implement the same [`CosignInvoker`] trait, so swapping
//! between them is a Cargo-feature flip. Tests in `attest/tests/`
//! drive the trait via [`super::StubCosignInvoker`] and never touch a
//! concrete invoker.
//!
//! ## Why this third invoker exists
//!
//! `sigstore-rs` is a 100+ crate dep tree and a moving target —
//! `SigningContext::staging()` is `pub(crate)`, the bundle wire
//! format has shifted twice in 0.13.x, and the SDK's `tokio` runtime
//! sits awkwardly under `attest`'s sync API. justsign is the in-
//! house alternative: a small set of crates we own, with a
//! deterministic blocking API and a wire-format spec we control. The
//! `JustsignInvoker` lets justoci drop the sigstore-rs dep tree
//! entirely once justsign reaches parity for the keyless flow we
//! care about. Tracked in justsign issue #16; this invoker is the
//! producer side.
//!
//! ## Wire-shape compatibility
//!
//! The bundle this invoker emits is a [`swe_justsign_spec::Bundle`]
//! serialised through [`swe_justsign_spec::Bundle::encode_json`].
//! That is wire-compatible with the Sigstore protobuf bundle v0.3
//! shape every cosign verifier reads:
//!
//! * `verificationMaterial.certificate.certificates` carries the
//!   leaf-first DER chain Fulcio returned (because
//!   [`swe_justsign_sign::sign_blob_keyless`] populates the
//!   `Certificate` field unconditionally).
//! * `verificationMaterial.tlogEntries[0].logIndex` carries the
//!   Rekor entry index — populated only when [`HttpRekorClient`]
//!   accepted the submission (the §6 sign+rekor coupling guarantee
//!   is enforced inside `sign_blob_keyless`, not here).
//! * The DSSE envelope payload is the manifest digest string,
//!   identical to what [`super::SigstoreInvoker`] produces — so
//!   downstream consumers see the same bytes regardless of which
//!   invoker was active at sign time.
//!
//! ## §6 sign+rekor coupling enforcement
//!
//! Per the [`super::cosign`] module-level docstring, the §6
//! Production Guarantee is: **a `Signature` is emitted only when
//! sign succeeded AND Rekor recorded the entry.** The justsign
//! invoker enforces this through three composing checks:
//!
//! 1. [`swe_justsign_sign::sign_blob_keyless`] is called with
//!    `rekor: Some(&HttpRekorClient)`. If the Rekor `submit()` call
//!    returns an error, `sign_blob_keyless` short-circuits and
//!    returns `Err(SignError::RekorSubmit(_))` — there is no path
//!    where it returns `Ok(Bundle)` with an empty `tlog_entries`
//!    list when a Rekor client was supplied.
//! 2. We re-check the returned bundle's
//!    `verification_material.tlog_entries` is non-empty before
//!    returning [`CosignOutcome::SignedAndRecorded`] — defensive
//!    against a future justsign regression that drops the entry on
//!    `Ok`. Mirrors the parallel guard in
//!    [`super::sigstore_invoker::extract_sigstore_bundle_log_index`].
//! 3. `SignError::RekorSubmit(_)` is mapped to
//!    [`CosignOutcome::SignedNotRecorded`] (the §6 unsigned-state
//!    signal), distinct from `SignFailed` for non-Rekor failures.
//!    This lets operators reading the typed error tell "Rekor
//!    outage" apart from "Fulcio outage" without parsing strings.
//!
//! ## Targeting: production vs staging
//!
//! Public-good Sigstore runs two parallel deployments. The
//! justsign invoker uses the same [`JustsignTarget`] enum +
//! [`JustsignInvoker::new`] / [`JustsignInvoker::staging`]
//! constructors as [`super::SigstoreInvoker`]:
//!
//! * **Production** — `https://fulcio.sigstore.dev` /
//!   `https://rekor.sigstore.dev`. The canonical, immutable, public-
//!   facing transparency log. **Production hygiene: writes are
//!   permanent. Tests must NEVER target this.**
//! * **Staging** — `https://fulcio.sigstage.dev` /
//!   `https://rekor.sigstage.dev`. Parallel deployment for
//!   integration testing; staging trust roots are not honoured by
//!   production verifiers, so signatures cannot round-trip.
//!
//! Unlike the sigstore-rs invoker, justsign's
//! [`HttpFulcioClient::new`] / [`HttpRekorClient::new`] constructors
//! take a base URL string directly, so wiring staging is a one-line
//! flip — no `pub(crate)` `Keyring` plumbing to work around.
//!
//! ## OIDC token sourcing
//!
//! Same env-var precedence as [`super::sigstore_invoker`]:
//!
//! 1. `SIGSTORE_ID_TOKEN` — sigstore convention.
//! 2. `OIDC_TOKEN` — generic CI fallback.
//!
//! No interactive browser flow — justoci is non-interactive (CI,
//! scripted operator runs). If neither var is set the invoker
//! returns [`CosignOutcome::CosignNotInstalled`] (the variant is
//! reused as "signer unavailable" — see [`CosignOutcome`] for the
//! rationale).
//!
//! TODO(refactor): the `resolve_oidc_token` helper is duplicated
//! verbatim in [`super::sigstore_invoker`]. The two MUST agree on
//! precedence (an inversion would silently grab the wrong token in
//! CI); merging them into a shared `crate::core::oidc` module is a
//! follow-up. Keeping the duplication for v0 trades a couple of
//! lines of dup against shrinking the patch the reviewer has to
//! audit. See justoci PR feature/justsign-invoker.

use super::cosign::{CosignInvocation, CosignInvoker, CosignOutcome};
use spec::SignKind;

use swe_justsign_fulcio::{build_csr, FulcioClient, HttpFulcioClient};
use swe_justsign_rekor::HttpRekorClient;
use swe_justsign_sign::{sign_blob_keyless, EcdsaP256Signer, SignError};

/// Which Sigstore-compatible deployment the justsign invoker
/// targets — selects the Fulcio + Rekor base URLs the
/// [`HttpFulcioClient`] and [`HttpRekorClient`] are constructed
/// against.
///
/// Mirrors [`super::sigstore_invoker::SigstoreTarget`] field-for-
/// field so an operator switching invokers via Cargo features sees
/// the same `{Production, Staging}` surface on both sides.
///
/// **Production hygiene rule:** the variant is load-bearing.
/// Defaulting a staging caller to production would pollute the
/// public-good Rekor with CI test entries that are immutable and
/// cannot be deleted. The [`JustsignInvoker::staging`] constructor
/// exists solely to support `attest/tests/justsign_e2e_test.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JustsignTarget {
    /// Public-good production. Default for real signing.
    /// Resolves to `fulcio.sigstore.dev` / `rekor.sigstore.dev`.
    Production,
    /// Staging deployment. Tests only.
    /// Resolves to `fulcio.sigstage.dev` / `rekor.sigstage.dev`.
    Staging,
}

/// Production `CosignInvoker` backed by the [`swe_justsign_*`]
/// stack. Constructed with [`JustsignInvoker::new`] (production)
/// or [`JustsignInvoker::staging`] (test-only). Stateless — every
/// `invoke` call constructs a fresh ephemeral keypair, CSR, Fulcio
/// client, and Rekor client. Same shape [`super::SigstoreInvoker`]
/// uses for the same reason: keeping the invoker `Send + Sync`
/// without locks, and confining all the secret material (the
/// ECDSA private key) to a single call frame so it is dropped
/// immediately after the bundle is built.
pub struct JustsignInvoker {
    target: JustsignTarget,
}

impl JustsignInvoker {
    /// Construct an invoker against the public-good **production**
    /// Sigstore-compatible deployment. The only constructor
    /// production code paths should call.
    pub fn new() -> Self {
        JustsignInvoker {
            target: JustsignTarget::Production,
        }
    }

    /// Construct an invoker against the public-good **staging**
    /// deployment (`fulcio.sigstage.dev` / `rekor.sigstage.dev`).
    ///
    /// **Test-only.** Staging trust roots are not honoured by
    /// production cosign verifiers; bundles produced here cannot
    /// round-trip through `cosign verify-blob` against the
    /// production trust root. Production code must NEVER call this
    /// — a fall-through to staging would still produce a bundle but
    /// downstream verifiers would silently reject it.
    pub fn staging() -> Self {
        JustsignInvoker {
            target: JustsignTarget::Staging,
        }
    }

    /// Which target this invoker is configured against. Exposed for
    /// the e2e test to assert it didn't accidentally get a
    /// production-default invoker — same load-bearing accessor
    /// [`super::SigstoreInvoker::target`] exposes for the same
    /// reason.
    pub fn target(&self) -> JustsignTarget {
        self.target
    }

    /// Resolve the (Fulcio base URL, Rekor base URL) pair for this
    /// invoker's target. Held as a method so the production /
    /// staging URL strings live in one place — a typo here would
    /// route signatures to the wrong instance, so we pin them here
    /// and assert against them in the unit tests.
    fn endpoints(&self) -> (&'static str, &'static str) {
        match self.target {
            JustsignTarget::Production => {
                ("https://fulcio.sigstore.dev", "https://rekor.sigstore.dev")
            }
            JustsignTarget::Staging => {
                ("https://fulcio.sigstage.dev", "https://rekor.sigstage.dev")
            }
        }
    }
}

impl Default for JustsignInvoker {
    fn default() -> Self {
        Self::new()
    }
}

impl CosignInvoker for JustsignInvoker {
    fn invoke(&self, invocation: &CosignInvocation) -> CosignOutcome {
        // ── 1. Reject unsupported `SignKind` arms up front ──────────────
        // `cosign-key` (BYO local keyfile) is not part of the keyless
        // surface justsign exposes. Operators who need keyfile signing
        // must build with `--features cosign-subprocess` (the cosign
        // CLI subprocess path is the only invoker that supports it).
        // We surface this as a typed `SignFailed` with an actionable
        // message, identical to the corresponding branch in
        // [`super::sigstore_invoker::SigstoreInvoker::invoke`], so an
        // operator switching invokers sees the same diagnostic.
        if matches!(invocation.kind, SignKind::CosignKey) {
            return CosignOutcome::SignFailed {
                stderr: "sign.kind = \"cosign-key\" is not supported on the justsign path; \
                    rebuild with --features cosign-subprocess (and `cosign` on PATH) or use \
                    sign.kind = \"cosign-keyless\""
                    .to_string(),
            };
        }
        if matches!(invocation.kind, SignKind::Off) {
            // The orchestrator (`super::cosign::sign_with`) short-
            // circuits Off before ever invoking the trait; reaching
            // here is a programmer error, not a runtime failure mode.
            return CosignOutcome::SignFailed {
                stderr: "justsign invoker called with SignKind::Off (programmer error)".to_string(),
            };
        }

        // ── 2. Resolve OIDC identity token ──────────────────────────────
        // Same env-var precedence the sigstore-rs invoker reads
        // (SIGSTORE_ID_TOKEN > OIDC_TOKEN). A missing token is
        // surfaced as `CosignNotInstalled` (= "signer unavailable"
        // — see the variant docstring), which the orchestrator maps
        // to `AttestError::CosignNotInstalled` so operators get the
        // actionable "configure SIGSTORE_ID_TOKEN" message.
        let token = match resolve_oidc_token() {
            Some(t) => t,
            None => return CosignOutcome::CosignNotInstalled,
        };

        // ── 3. Pick endpoints by target ─────────────────────────────────
        // Mismatching the URLs would be a §6 hygiene bug (writing
        // staging entries to a production-targeted invoker, or vice
        // versa). The lookup is a single `match` so the failure mode
        // is "wrong endpoint pair" — caught by the unit tests against
        // `endpoints()` directly.
        let (fulcio_url, rekor_url) = self.endpoints();

        // ── 4. Build the Fulcio client ──────────────────────────────────
        // `HttpFulcioClient::new` is fallible (it constructs a
        // blocking reqwest client; on platforms where the TLS
        // initialiser fails this surfaces here). Map any error to
        // `SignFailed` with the underlying diagnostic preserved
        // verbatim — operators reading the message can route on
        // hostname / TLS / DNS as needed.
        let fulcio_client = match HttpFulcioClient::new(fulcio_url) {
            Ok(c) => c,
            Err(e) => {
                return CosignOutcome::SignFailed {
                    stderr: format!(
                        "could not initialise justsign HttpFulcioClient against {fulcio_url}: {e}"
                    ),
                };
            }
        };

        // ── 5. Mint an ephemeral ECDSA P-256 keypair ────────────────────
        // Fresh per-invoke: the private key is dropped at the end of
        // this call (no shared state on the invoker — see the type
        // docstring), so a Fulcio cert leaks at most the duration of
        // one sign call. Same shape `swe_justsign_cli::cmd_generate_key_pair`
        // uses: `SigningKey::random(&mut OsRng)`, OS CSPRNG-seeded.
        let signing_key = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);

        // ── 6. Build a CSR for Fulcio ───────────────────────────────────
        // Fulcio binds identity off the SAN, not the Subject. The
        // `subject_email` we pass is a placeholder — Fulcio derives
        // the *real* identity from the OIDC token's claims server-
        // side and overwrites the leaf SAN with whatever it found
        // there. Sigstore-rs's `SigningContext::blocking_signer`
        // does the same thing internally; we can't extract the
        // email from the OIDC token at this layer without pulling
        // a JWT parser into the build.
        //
        // The placeholder MUST be ASCII-only (rfc822Name SAN is
        // IA5String — `build_csr` rejects non-ASCII) and non-empty
        // (Fulcio rejects an empty CN). `justoci@local` satisfies
        // both and is unambiguously a local placeholder, not a
        // claim about the operator's identity.
        let csr_subject_placeholder = "justoci@local";
        let csr = match build_csr(&signing_key, csr_subject_placeholder) {
            Ok(c) => c,
            Err(e) => {
                return CosignOutcome::SignFailed {
                    stderr: format!("justsign CSR construction failed: {e}"),
                };
            }
        };

        // ── 7. Exchange CSR + OIDC token for a Fulcio cert chain ────────
        let cert_chain = match fulcio_client.sign_csr(&csr, &token) {
            Ok(chain) => chain,
            Err(e) => {
                return CosignOutcome::SignFailed {
                    stderr: format!(
                        "justsign Fulcio CSR exchange against {fulcio_url} failed: {e}"
                    ),
                };
            }
        };

        // ── 8. Extract DER bytes for the bundle's cert chain ────────────
        // [`swe_justsign_sign::sign_blob_keyless`] expects
        // `&[Vec<u8>]` of DER-encoded certs, leaf-first.
        // [`swe_justsign_fulcio::CertChain::certs`] already preserves
        // that order, so we walk the certs and clone the verbatim
        // DER bytes (NOT a re-encode — the `X509Cert::der` field is
        // documented as "DER bytes exactly as they came off the
        // wire"; round-tripping through a re-encoder would risk
        // changing SET ordering on uncareful encoders).
        let cert_chain_der: Vec<Vec<u8>> = cert_chain.certs.iter().map(|c| c.der.clone()).collect();

        // ── 9. Build the Rekor client ───────────────────────────────────
        let rekor_client = match HttpRekorClient::new(rekor_url) {
            Ok(c) => c,
            Err(e) => {
                return CosignOutcome::SignFailed {
                    stderr: format!(
                        "could not initialise justsign HttpRekorClient against {rekor_url}: {e}"
                    ),
                };
            }
        };

        // ── 10. Build the EcdsaP256Signer ───────────────────────────────
        // `key_id = None` because the verifier obtains the public
        // key out-of-band from the Fulcio leaf's SubjectPublicKeyInfo
        // — populating a DSSE keyid here would be a "keyid hint"
        // the verifier is required to ignore anyway, per the DSSE
        // spec. Same shape `swe_justsign_sign::sign_blob_keyless`
        // expects.
        let signer = EcdsaP256Signer::new(signing_key, None);

        // ── 11. Sign the manifest digest ────────────────────────────────
        // Symmetric with [`super::sigstore_invoker::SigstoreInvoker::invoke`]:
        // sign the digest *string* (e.g. "sha256:abc..."), NOT the
        // manifest bytes. That keeps the signed payload small,
        // stable, and reproducible — and matches what cosign-
        // verify-blob expects on the verify side. A future iteration
        // could sign the manifest bytes; today we keep parity with
        // the sigstore-rs invoker so the two are byte-for-byte
        // interchangeable from the verifier's perspective.
        let payload = invocation.manifest_digest.to_string();
        let bundle = match sign_blob_keyless(
            payload.as_bytes(),
            // `text/plain` matches the digest-string payload type;
            // sigstore_invoker.rs lets the SDK pick the payload type
            // and the SDK's default is also `text/plain` for raw
            // bytes (audited from sigstore-rs v0.13 SigningSession::sign).
            // Pinning it here removes one layer of "what does the
            // SDK think today" from the wire-format surface.
            "text/plain",
            &signer,
            &cert_chain_der,
            // §6 sign+rekor coupling: ALWAYS pass `Some(&rekor)`.
            // Passing `None` would short-circuit the Rekor write and
            // return a Rekor-less bundle — exactly the half-state
            // the §6 contract forbids.
            Some(&rekor_client),
        ) {
            Ok(b) => b,
            Err(SignError::RekorSubmit(rekor_err)) => {
                // §6 Rekor-coupling failure: sign succeeded (we got
                // far enough to attempt the submission) but the
                // Rekor server rejected it. Surface as
                // `SignedNotRecorded` (the §6 unsigned-state signal)
                // rather than `SignFailed` so the orchestrator maps
                // it to `AttestError::SignNotRecorded` and operators
                // can route on the typed error.
                //
                // NB: `SignError::RekorSubmit` only fires AFTER the
                // signature has been computed and the Rekor request
                // was issued — `swe_justsign_sign::sign_blob_keyless`
                // calls `signer.sign(pae)` BEFORE `rekor.submit(...)`
                // (audited from justsign sign/src/lib.rs as of the
                // commit that landed `sign_blob_keyless`), so the
                // distinction "Rekor failed" vs "anything else"
                // is preserved on the typed error boundary.
                return CosignOutcome::SignedNotRecorded {
                    reason: format!(
                        "justsign Rekor submission against {rekor_url} failed: {rekor_err}"
                    ),
                };
            }
            Err(e) => {
                return CosignOutcome::SignFailed {
                    stderr: format!("justsign sign_blob_keyless failed: {e}"),
                };
            }
        };

        // ── 12. §6 belt-and-braces guard ────────────────────────────────
        // `sign_blob_keyless` only returns `Ok(Bundle)` with a
        // non-empty `tlog_entries` when a Rekor client was supplied
        // AND the submit returned `Ok` (audited from justsign
        // sign/src/lib.rs at the commit that landed the function).
        // We re-check defensively: a future justsign regression
        // that drops the entry on `Ok` would otherwise silently
        // emit a Rekor-less Signature, breaking §6 in a way no
        // test outside this guard would catch. Mirrors the parallel
        // check in
        // [`super::sigstore_invoker::extract_sigstore_bundle_log_index`].
        let log_index = match bundle.verification_material.tlog_entries.first() {
            Some(entry) => entry.log_index,
            None => {
                return CosignOutcome::SignedNotRecorded {
                    reason: "justsign Bundle returned by sign_blob_keyless has empty \
                             verification_material.tlog_entries (Rekor entry missing — \
                             defensive guard, this should be unreachable per justsign \
                             sign_blob_keyless contract)"
                        .to_string(),
                };
            }
        };

        // The bundle's `log_index` is `i64` (matching the protobuf
        // wire shape); `CosignOutcome::SignedAndRecorded` carries
        // `u64` (Rekor indices are monotonically increasing
        // non-negative). A negative bundle log_index means upstream
        // emitted a malformed bundle — surface as a defensive
        // `SignedNotRecorded` rather than truncating with `as u64`.
        let log_index_u64: u64 = match u64::try_from(log_index) {
            Ok(v) => v,
            Err(_) => {
                return CosignOutcome::SignedNotRecorded {
                    reason: format!(
                        "justsign Bundle's tlog_entries[0].log_index is negative ({log_index}); \
                         Rekor indices must be non-negative — bundle is malformed"
                    ),
                };
            }
        };

        // ── 13. Encode the bundle to canonical JSON ─────────────────────
        // [`swe_justsign_spec::Bundle::encode_json`] is the canonical
        // encoder; using it (rather than `serde_json::to_vec`) means
        // the bytes the CAS stores match what
        // `swe_justsign_spec::Bundle::decode_json` will accept on
        // the way back. A re-encode through `serde_json::to_vec`
        // would skip any base64 / canonicalisation the spec encoder
        // enforces, which would break round-trip verification.
        let bundle_bytes = match bundle.encode_json() {
            Ok(b) => b,
            Err(e) => {
                return CosignOutcome::SignFailed {
                    stderr: format!("could not serialise justsign Bundle to JSON: {e}"),
                };
            }
        };

        CosignOutcome::SignedAndRecorded {
            bundle_bytes,
            log_index: log_index_u64,
        }
    }
}

/// Resolve the OIDC identity-token JWT from the environment.
/// Returns `Some(token)` if `SIGSTORE_ID_TOKEN` or `OIDC_TOKEN` is
/// set to a non-empty value, `None` otherwise.
///
/// Same precedence as
/// [`super::sigstore_invoker::resolve_oidc_token`]: `SIGSTORE_ID_TOKEN`
/// wins over `OIDC_TOKEN` because the former is the sigstore-
/// specific convention (set with `aud="sigstore"`) and the latter
/// is a generic CI fallback that may carry a different `aud`. The
/// two MUST agree on precedence — a future merge into a shared
/// `crate::core::oidc` helper is tracked in the module-level
/// docstring TODO.
///
/// We deliberately do **not** trigger an interactive browser OIDC
/// flow — justoci is non-interactive (CI, scripted operator runs).
fn resolve_oidc_token() -> Option<String> {
    for key in ["SIGSTORE_ID_TOKEN", "OIDC_TOKEN"] {
        match std::env::var(key) {
            Ok(v) if !v.is_empty() => return Some(v),
            _ => continue,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serialises tests that mutate process-global env vars
    /// (`SIGSTORE_ID_TOKEN`, `OIDC_TOKEN`). Same pattern
    /// `super::sigstore_invoker`'s test module uses; see that
    /// module's docstring for the rationale (cargo runs tests in
    /// parallel by default, racing env-var sets corrupt each
    /// other's setup).
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn test_new_constructor_targets_production() {
        // Bug this catches: a regression that flips the default
        // target to Staging would cause every `JustsignInvoker::new`
        // caller (including the production attest path when an
        // operator builds with `--features justsign`) to write
        // CI/test runs to the staging Rekor — quietly breaking
        // every operator who relies on production Rekor for
        // verification. Production hygiene rule.
        let inv = JustsignInvoker::new();
        assert_eq!(inv.target(), JustsignTarget::Production);
    }

    #[test]
    fn test_default_constructor_targets_production() {
        // Bug this catches: a regression where `Default::default()`
        // diverges from `new()` (e.g. someone "helpfully" makes
        // Default point at staging for tests) would silently
        // change production behaviour. The two must remain
        // identical.
        assert_eq!(
            JustsignInvoker::default().target(),
            JustsignInvoker::new().target()
        );
    }

    #[test]
    fn test_staging_constructor_targets_staging() {
        // Bug this catches: a regression that makes
        // `JustsignInvoker::staging` accidentally return a
        // production-targeted invoker would invert the e2e test —
        // staging-targeted CI runs would write production Rekor
        // entries instead of staging ones, polluting the immutable
        // production log. The hard rule "Use staging, never
        // production" depends on this assertion.
        let inv = JustsignInvoker::staging();
        assert_eq!(inv.target(), JustsignTarget::Staging);
    }

    #[test]
    fn test_endpoints_for_production_target_resolve_to_sigstore_dev() {
        // Bug this catches: a typo'd URL constant (e.g.
        // `fulcio.sigstoredev` missing the dot) would silently
        // route production sign calls to a non-resolving host
        // and surface as a confusing TLS / DNS error far down
        // the call stack. Pinning the strings here so the
        // reviewer can eyeball them, and asserting the exact
        // value, catches a mistyped letter immediately.
        let inv = JustsignInvoker::new();
        let (fulcio, rekor) = inv.endpoints();
        assert_eq!(fulcio, "https://fulcio.sigstore.dev");
        assert_eq!(rekor, "https://rekor.sigstore.dev");
    }

    #[test]
    fn test_endpoints_for_staging_target_resolve_to_sigstage_dev() {
        // Bug this catches: a swap between the production and
        // staging URL pairs would have the staging invoker write
        // to production Rekor (or vice versa). Asserting the exact
        // hostnames here pins the routing — a refactor that
        // accidentally inverts the match arms gets caught.
        let inv = JustsignInvoker::staging();
        let (fulcio, rekor) = inv.endpoints();
        assert_eq!(fulcio, "https://fulcio.sigstage.dev");
        assert_eq!(rekor, "https://rekor.sigstage.dev");
    }

    #[test]
    fn test_resolve_oidc_token_prefers_sigstore_id_token_over_oidc_token() {
        // Bug this catches: a regression where the env var
        // precedence inverts (or one of the two is dropped) would
        // silently grab the wrong token in CI environments where
        // both are set (e.g. GitHub Actions setting `OIDC_TOKEN`
        // for ambient identity, plus a build script setting
        // `SIGSTORE_ID_TOKEN` for an explicit Sigstore audience).
        //
        // Mirrors the corresponding test in
        // `super::sigstore_invoker::tests` — the two helpers MUST
        // agree on precedence so a future merge into a shared
        // helper doesn't silently invert one of them.
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
    fn test_resolve_oidc_token_treats_empty_string_as_unset() {
        // Bug this catches: a regression where `Ok("")` is treated
        // as a valid token. CI env vars often expand to empty
        // strings when no value is provided
        // (e.g. `SIGSTORE_ID_TOKEN=${ID_TOKEN_VAR:-}` with
        // `ID_TOKEN_VAR` unset). Passing an empty string to
        // Fulcio would trip the MockFulcioClient's 401 branch
        // (real Fulcio also rejects 401 on empty token) — but
        // surfacing as `CosignNotInstalled` (the actionable
        // "configure SIGSTORE_ID_TOKEN" message) is better operator
        // UX than a Fulcio HTTP 401.
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
