# Cosign + Rekor coupled signing

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

## The flow

```
                ┌──────────────────────────────┐
                │  ocimage build               │
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
                │  CosignInvoker::sign         │
                │   spawn `cosign sign-blob`   │
                └──────────────┬───────────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
            error            stdout         exit code
                                │
                                ▼
                ┌──────────────────────────────┐
                │  parse cosign bundle         │
                │  extract rekorBundle.        │
                │   Payload.logIndex           │
                └──────────────┬───────────────┘
                               │
              ┌────────────────┼────────────────┐
              │ logIndex       │ logIndex       │ logIndex
              │ present        │ absent         │ unparseable
              ▼                ▼                ▼
       Signature         SignNotRecorded   SignNotRecorded
       (recorded)        (Rekor failed     (cosign output
                          OR --no-rekor    malformed —
                          mode used)       defensive default)
```

## Why subprocess (for v0)

`attest/src/core/cosign.rs` invokes the `cosign` binary as a
subprocess. Reasons:

1. **No Rust SDK link debt.** `sigstore-rs` exists but adds a
   significant transitive dependency footprint. v0 ships
   subprocess; v0.2 swaps the implementation behind the
   `CosignInvoker` trait.
2. **Cosign is the de facto reference.** Every test expectation
   matches what `cosign verify-blob` would produce in the wild.
3. **Easy to stub for tests.** `StubCosignInvoker` returns
   scripted outcomes; production tests never hit the network.

The cost: cosign must be on PATH at production runtime. CI
installs it via `sigstore/cosign-installer@v3`; operators
running `ocimage build --attest` in production do the same.

## The `CosignInvoker` trait

```rust
pub trait CosignInvoker: Send + Sync {
    fn sign(&self, manifest_digest: &Digest, sign_cfg: &SignConfig)
        -> Result<CosignOutcome, AttestError>;
}

pub enum CosignOutcome {
    /// Signed AND Rekor confirmed.
    VerifiedAndRecorded { bundle: SignatureBundle, log_index: u64 },
    /// Signed but Rekor entry missing or unparseable.
    /// Caller maps to AttestError::SignNotRecorded.
    VerifiedNotRecorded { bundle: SignatureBundle },
    /// cosign exited non-zero / signature validation failed.
    InvalidSignature { stderr: String },
    /// cosign not on PATH.
    CosignNotInstalled,
}
```

The trait is the migration seam. v0.2 swaps `RealCosignInvoker`
(subprocess) for a `SigstoreInvoker` (linked-in `sigstore-rs`)
without touching the rest of `attest` or `cli`.

## Verify-side

`cli/src/verify_engine.rs` uses the same `CosignVerifyInvoker`
pattern. `RealCosignVerifyInvoker` invokes `cosign verify-blob`;
`StubCosignVerifyInvoker` returns scripted outcomes for tests.

The same coupling rule applies on verify: a cosign signature
without a confirmed Rekor entry is a `VerifiedNotRecorded`
outcome, and `ocimage verify` reports it as not-fully-attested
(or with `--policy [sign].required = true`, fails the verify with
exit 5).

## What this means in practice

If you're an operator running `ocimage build` and Rekor is down:

```bash
$ ocimage build spec.toml -o dist/
Error: AttestError::SignNotRecorded
  cosign signed manifest digest sha256:abc... but no Rekor log
  index was returned. Inspect cosign output:
    <stderr lines>
  Re-run when Rekor is reachable, or build with --no-attest if
  signing must be deferred.
```

Exit code 3 (AttestError class). The build artifact is preserved
(build atomicity §6) — you can re-run attest without re-running
the build, or fall back to `--no-attest` and ship without a
signature.

If you're verifying:

```bash
$ ocimage verify ghcr.io/acme/firmware:1.4.2
[✓] SLSA statement found and well-formed (level 2)
[✓] CycloneDX SBOM found (8 components)
[✗] Cosign signature found but no Rekor log entry — artifact is
    unsigned per the cosign+Rekor coupled rule
Exit 5: VerifyError::PolicyViolation { rule: "sign.required" }
```

(With default policy. Override with `[sign].required = false` if
you accept VerifiedNotRecorded as a soft warning.)
