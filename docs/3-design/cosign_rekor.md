# Cosign + Rekor coupled signing

**Audience**: Contributors, architects

> **TLDR**: Signing is coupled to Rekor log confirmation — `cosign sign` success plus Rekor entry confirmed is the only "signed" state; Rekor failure returns `AttestError::SignNotRecorded` with no half-states.

## Production Guarantee §6, restated

> **Sign + Rekor are coupled.** `cosign sign` succeeds → Rekor log
> entry confirmed → only then is the artifact "signed". If Rekor
> fails, return `AttestError::SignNotRecorded`; the artifact is
> unsigned (no half-states).

The single most important rule of justoci's signing pipeline.

## Why coupled

A signature without a transparency log entry is a signature you
have to *trust the signer* to produce. With Rekor's transparency
log, the signature is bound to a tamper-evident, append-only
public log — anyone can verify the signature was made when it
claims to have been made, by the identity it claims to have been
made by.

If sign succeeds but Rekor write fails, the artifact has a
signature but no corresponding log entry. Two possible
interpretations:

1. "We signed it; the Rekor write was a transient failure; the
   artifact is signed." Trusting interpretation.
2. "Without a Rekor entry, we can't prove anything about *when*
   or *by whom*. The artifact is unsigned." Skeptical
   interpretation.

The product opinion is **interpretation 2**. Half-signed states
are how supply-chain compromises hide. We refuse the gradient.

## v0.2 — sigstore-rs is the production path

As of issue #13, the production signer is the linked-in
[`sigstore`](https://crates.io/crates/sigstore) Rust SDK
(`SigstoreInvoker` in `attest/src/core/sigstore_invoker.rs`),
gated behind the `sigstore-rs` Cargo feature (default-on).

The cosign subprocess is kept as an opt-in fallback behind the
`cosign-subprocess` feature (`RealCosignInvoker` in
`attest/src/core/cosign.rs`). Operators who need it
(e.g. air-gapped builds with a managed cosign install, BYO-key
mode) build with:

```bash
cargo build --no-default-features --features cosign-subprocess
```

Both implementations satisfy the same `CosignInvoker` trait, so
every test in `attest/tests/` runs against both — the §6 contract
is exercised on both code paths.

## The flow (sigstore-rs path — default)

```
                ┌──────────────────────────────┐
                │  justoci build               │
                └──────────────┬───────────────┘
                               │
                               ▼
                ┌──────────────────────────────┐
                │  attest::saf::attest         │
                │   sign.kind != Off?          │
                └──────────────┬───────────────┘
                               │ yes
                               ▼
                ┌──────────────────────────────┐
                │  SigstoreInvoker::invoke     │
                │   resolve OIDC token from    │
                │   SIGSTORE_ID_TOKEN /        │
                │   OIDC_TOKEN env             │
                └──────────────┬───────────────┘
                               │
              ┌────────────────┼────────────────┐
              │ token absent   │ token present  │
              ▼                ▼
       CosignNotInstalled  SigningContext::production()
       (signer-unavailable)     │
                                ▼
                ┌──────────────────────────────┐
                │  ctx.blocking_signer(token)  │
                │   Fulcio CSR exchange        │
                └──────────────┬───────────────┘
                               │
              ┌────────────────┼────────────────┐
              │ Fulcio fails   │ session opens
              ▼                ▼
         SignFailed        session.sign(payload)
                                │   ↓ inside the SDK:
                                │   1. sign payload
                                │   2. POST to Rekor
                                │   3. if Rekor fails, ENTIRE
                                │      sign() returns Err
                                │
              ┌─────────────────┼────────────────┐
              │ SDK Err         │ SDK Ok(SigningArtifact)
              ▼                 ▼
         SignFailed        artifact.to_bundle() →
        (covers both:        serde_json::to_vec(&bundle)
         Fulcio failure        │
         AND Rekor failure)    ▼
                          extract logIndex from
                          verificationMaterial.tlogEntries[0]
                                │
              ┌─────────────────┼─────────────────┐
              │ logIndex        │ logIndex        │
              │ present         │ absent (defensive)
              ▼                 ▼
       Signature           SignNotRecorded
       (recorded)          (SDK regression guard)
```

Key observation: **the §6 Rekor-coupling check moves from "parse
the bundle" (subprocess path) to "trust the SDK return value"
(sigstore-rs path)**. The SDK's `SigningSession::sign` is
structured so it only returns `Ok(SigningArtifact)` when Rekor
recorded the entry — a Rekor failure surfaces as
`SigstoreError::RekorClientError`, which we map to
`CosignOutcome::SignFailed`. The audit reference is
[`sigstore-rs/src/bundle/sign.rs`](https://github.com/sigstore/sigstore-rs/blob/main/src/bundle/sign.rs)
at v0.13.0.

We **still** parse the returned bundle's `logIndex` for
`Signature::rekor_log_index` (operators rely on it for post-hoc
Rekor lookup), and we **still** treat an empty
`tlogEntries` array as `SignedNotRecorded` — defensive guard
against a future SDK regression that could ship a Rekor-less
bundle.

## The flow (cosign-subprocess path — fallback)

The legacy v0 flow. Documented for operators who need it.

```
                ┌──────────────────────────────┐
                │  RealCosignInvoker::invoke   │
                │   spawn `cosign sign-blob`   │
                └──────────────┬───────────────┘
                               │
              ┌────────────────┼────────────────┐
              │ exec fails     │ exit non-zero  │ exit 0
              ▼                ▼                ▼
       SignFailed         SignFailed        parse cosign bundle
                                                │
                              ┌─────────────────┼─────────────────┐
                              │ rekorBundle.    │ rekorBundle.    │ rekorBundle
                              │ Payload.        │ Payload.        │ block missing
                              │ logIndex        │ logIndex        │ entirely
                              │ present         │ absent          │
                              ▼                 ▼                 ▼
                       Signature           SignNotRecorded   SignNotRecorded
                       (recorded)          (--no-tlog-       (Rekor outage,
                                            upload mode)      malformed bundle,
                                                              etc.)
```

Same end-state: `Signature` only emerges when Rekor recorded.
The bundle parser lives in
`attest/src/core/cosign.rs::extract_cosign_legacy_log_index`
(only compiled under `cosign-subprocess`).

## Bundle shape — sigstore-rs vs subprocess

The two paths emit **different** bundle JSON. Verifiers should
treat both as opaque blobs (look up by digest in the OCI
referrer index, hand to cosign-verify-blob), but operators
debugging the wire format should know:

| Path | Media type | logIndex location | logIndex JSON type |
|------|------------|-------------------|--------------------|
| sigstore-rs (default) | `application/vnd.dev.sigstore.bundle.v0.3+json` | `verificationMaterial.tlogEntries[0].logIndex` | string (protobuf int64 JSON) |
| cosign-subprocess (fallback) | legacy cosign bundle | `rekorBundle.Payload.logIndex` | number |

Both are stored under the same OCI referrer media type
(`application/vnd.dev.cosign.simplesigning.v1+json`) for
ecosystem compatibility — the wider cosign tooling keys off it.
A future change may split this; for now, keying both bundle
formats off the same media type means a verifier needs to
content-sniff the JSON to decide which parser to use. That's
acceptable v0.2 trade-off; documented here for the verify-side
implementer.

## OIDC identity token sourcing (sigstore-rs path)

Sigstore keyless signing requires a JWT whose `aud` claim is
`"sigstore"`. `SigstoreInvoker` does **not** run the interactive
browser-based OIDC flow — justoci is invoked from CI and operator
scripts; popping a browser is the wrong UX. The token is read
from environment variables, in priority order:

1. `SIGSTORE_ID_TOKEN` — sigstore convention.
2. `OIDC_TOKEN` — generic fallback.

If neither is set, the invoker returns
`AttestError::CosignNotInstalled` (the variant name is
historical; under sigstore-rs it means "signer unavailable —
provide an OIDC token"). The error message covers both
production paths so operators get an actionable hint regardless
of the active feature.

GitHub Actions workflows requesting an ambient OIDC identity
expose `ACTIONS_ID_TOKEN_REQUEST_TOKEN`; the workflow must
exchange that for a sigstore-aud token (e.g. via
`actions/oidc-token`) and export it as `SIGSTORE_ID_TOKEN`.

## The `CosignInvoker` trait

```rust
pub trait CosignInvoker: Send + Sync {
    fn invoke(&self, invocation: &CosignInvocation) -> CosignOutcome;
}

pub enum CosignOutcome {
    /// Signed AND Rekor confirmed.
    SignedAndRecorded { bundle_bytes: Vec<u8>, log_index: u64 },
    /// Signed but Rekor entry missing or unparseable.
    /// Caller maps to AttestError::SignNotRecorded.
    SignedNotRecorded { reason: String },
    /// Sign step itself failed.
    SignFailed { stderr: String },
    /// Signer unavailable (cosign not on PATH on the subprocess
    /// path; OIDC token unset on the sigstore-rs path).
    CosignNotInstalled,
}
```

The trait predates the sigstore-rs migration; we kept the name
to avoid churn across every test. The trait is still the
migration seam — a hypothetical v0.3 invoker (e.g. against a
private Sigstore instance, or a custom KMS) implements the same
trait and slots into `attest_with_invoker` without changing any
caller.

## Verify-side

`cli/src/verify_engine.rs` uses the same `CosignVerifyInvoker`
pattern. `RealCosignVerifyInvoker` invokes `cosign verify-blob`;
`StubCosignVerifyInvoker` returns scripted outcomes for tests.

The same coupling rule applies on verify: a cosign signature
without a confirmed Rekor entry is a `VerifiedNotRecorded`
outcome, and `justoci verify` reports it as not-fully-attested
(or with `--policy [sign].required = true`, fails the verify with
exit 5).

A future iteration will migrate the verify path to sigstore-rs
too (issue #13's sibling). v0.2 keeps verify on the subprocess
path because the verify wire is much smaller (no OIDC, no
Fulcio) and the audit cost-benefit was wrong for v0.2.

## What this means in practice

If you're an operator running `justoci build` and Rekor is down:

```bash
$ justoci build spec.toml -o dist/
Error: AttestError::SignNotRecorded
  signature was not recorded in Rekor (artifact is unsigned):
  rekor.sigstore.dev returned 503 (Service Unavailable)
  Re-run when Rekor is reachable, or build with --no-attest if
  signing must be deferred.
```

Exit code 3 (AttestError class). The build artifact is preserved
(build atomicity §6) — you can re-run attest without re-running
the build, or fall back to `--no-attest` and ship without a
signature.

If you're verifying:

```bash
$ justoci verify ghcr.io/acme/firmware:1.4.2
[OK] SLSA statement found and well-formed (level 2)
[OK] CycloneDX SBOM found (8 components)
[FAIL] Cosign signature found but no Rekor log entry — artifact is
       unsigned per the cosign+Rekor coupled rule
Exit 5: VerifyError::PolicyViolation { rule: "sign.required" }
```

(With default policy. Override with `[sign].required = false` if
you accept VerifiedNotRecorded as a soft warning.)

## Testing against staging

Real Fulcio + Rekor wire-level coverage lives behind an
`#[ignore]` gate in
`attest/tests/sigstore_e2e_test.rs`. The CI job
`sigstore-e2e` (in `.github/workflows/ci.yml`) drives it.

### Staging vs production trust roots

Public-good Sigstore runs two parallel deployments:

| Deployment | Fulcio | Rekor | Trust root | Purpose |
|------------|--------|-------|------------|---------|
| Production | `fulcio.sigstore.dev` | `rekor.sigstore.dev` | shipped with cosign + sigstore-rs | Real artifacts. Immutable, public. |
| Staging | `fulcio.sigstage.dev` | `rekor.sigstage.dev` | distinct staging trust root | Test traffic. Not honoured by production verifiers. |

**The test runs against staging, never production.** Production's
Rekor is the canonical immutable public log; CI test entries
written there would persist forever. Issue #14's hard rule:

> Use staging, never production. Any path that defaults to
> production from a test is a bug.

The hygiene assertion is encoded in the test itself: it constructs
a `SigstoreInvoker::staging()` and asserts
`invoker.target() == SigstoreTarget::Staging` before any I/O
happens. A regression that wires `staging()` to `Production` is
caught at test construction time, not after a Rekor pollution.

### OIDC `aud` claim requirement

Fulcio (staging and production both) requires the OIDC JWT's
`aud` claim to be `"sigstore"`. Confirmed against
`https://fulcio.sigstage.dev/api/v2/configuration` which lists
`"audience": "sigstore"` for the
`token.actions.githubusercontent.com` issuer.

The CI job mints the token with that audience explicitly via
`actions/github-script`:

```yaml
- name: Get OIDC token from GitHub Actions
  uses: actions/github-script@v7
  with:
    script: |
      const token = await core.getIDToken('sigstore');
      core.setSecret(token);
      core.setOutput('token', token);
```

Any other audience is rejected by Fulcio at certificate-exchange
time — so getting this wrong fails fast with an actionable error,
not silently.

### CI job permissions

The `sigstore-e2e` job declares:

```yaml
permissions:
  contents: read
  id-token: write
```

`id-token: write` is what unlocks `core.getIDToken()` — the
default `GITHUB_TOKEN` cannot mint OIDC identity tokens.
`contents: read` is restated explicitly because once any
`permissions:` key is set, all unset keys default to `none`,
which would block `actions/checkout`.

### Local skip behaviour

When `OIDC_TOKEN` is not set (a developer laptop without a
GitHub Actions OIDC bootstrap), the test prints
`SKIP[sigstore-e2e]: ...` to stderr and returns Ok. The SKIP
marker is greppable from CI logs to confirm the SKIP is
intentional, not a silent pass.

### Upstream sigstore-rs limitation (0.13 era)

`sigstore = "0.13"` does NOT expose a public way to construct a
`SigningContext` against staging:

- `SigningContext::production()` exists.
- `SigningContext::staging()` does NOT exist (audited against
  v0.13.0 and `main` at the time of the issue #14 commit).
- `SigningContext::new(fulcio, rekor, ctfe_keyring)` is `pub`,
  but the `Keyring` parameter type is `pub(crate)` — not
  constructible from outside the sigstore crate.

Until upstream lands a `staging()` constructor (or marks
`Keyring` `pub`), the `SigstoreInvoker::staging()` constructor
in `attest/src/core/sigstore_invoker.rs` returns an invoker that
surfaces the gap as a typed `CosignOutcome::SignFailed` with a
diagnostic message. The e2e test recognises this state and
SKIP-passes after asserting the staging target was preserved
and no production fall-through occurred.

When upstream fixes the gap, the e2e test's `SignedAndRecorded`
branch becomes the live wire — no test-side or CI-side YAML
changes needed.

### `cosign verify-blob` interop test

A second `#[ignore]`-gated test
(`test_real_sigstore_staging_signature_verifies_via_cosign_verify_blob`)
sketches a cosign-CLI interop check: feed the staging bundle to
`cosign verify-blob --trust-root sigstage` and assert exit 0.
Deferred to v0.2 because it's blocked on the same upstream gap
(no staging bundle to feed cosign), and because pinning
sigstore-rs's staging TUF snapshot to cosign's staging TUF
snapshot adds a coupling cost not justified at v0.2.
