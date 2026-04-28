//! Public attestation entry point.
//!
//! `attest()` runs each of the three pillars (SLSA, SBOM, signing)
//! independently against the provided `BuiltArtifact` and `Cas`. The
//! pillars are independent — opting out of one does not affect the
//! others. The function returns once all enabled pillars succeed; if
//! any pillar fails, it short-circuits with a typed `AttestError`
//! and the partially-written CAS blobs of the prior pillars are NOT
//! removed (that's `gc`'s job, not attest's).
//!
//! Two flavours:
//!
//! - `attest()` — production entry. The concrete `CosignInvoker`
//!   it constructs depends on which Cargo feature is active:
//!   - `sigstore-rs` (default): `SigstoreInvoker` (linked-in SDK).
//!   - `cosign-subprocess`: `RealCosignInvoker` (spawns the
//!     `cosign` binary).
//!   - `justsign`: `JustsignInvoker` (in-house `swe_justsign_*`
//!     stack — see `crate::core::justsign_invoker`).
//! - `attest_with_invoker()` — test entry. Lets callers supply a
//!   `StubCosignInvoker` to script signing outcomes deterministically.
//!   Tests use this to exercise the Rekor-coupling failure mode
//!   (`SignNotRecorded`) without needing a real Sigstore identity.

use cas::Cas;
use spec::{AttestationConfig, SbomFormat, SignKind};

use crate::api::attestation::AttestationOutputs;
use crate::api::built_artifact::BuiltArtifact;
use crate::api::error::AttestError;
use crate::core::cosign::{sign_with, CosignInvoker};
use crate::core::sbom_cyclonedx::emit_cyclonedx;
use crate::core::sbom_spdx::emit_spdx;
use crate::core::slsa::emit_slsa;

/// Run the full attestation pipeline using the production signer.
///
/// Which signer that is depends on the `[features]` selection at
/// build time. See module docs for semantics.
pub fn attest(
    built: &BuiltArtifact,
    attestation: &AttestationConfig,
    cas: &dyn Cas,
) -> Result<AttestationOutputs, AttestError> {
    // Compile-time pick of the production invoker. Precedence
    // when multiple features are active (e.g. `cargo test
    // --all-features` in dev) is: sigstore-rs > cosign-subprocess
    // > justsign. sigstore-rs is the documented default;
    // cosign-subprocess is the legacy escape hatch; justsign is
    // the v0 opt-in alternative. The `core::mod` `compile_error!`
    // ensures at least one feature is on; we don't repeat that
    // guard here.
    #[cfg(feature = "sigstore-rs")]
    let invoker: Box<dyn CosignInvoker> =
        Box::new(crate::core::sigstore_invoker::SigstoreInvoker::new());
    #[cfg(all(not(feature = "sigstore-rs"), feature = "cosign-subprocess"))]
    let invoker: Box<dyn CosignInvoker> = Box::new(crate::core::cosign::RealCosignInvoker::new());
    #[cfg(all(
        not(feature = "sigstore-rs"),
        not(feature = "cosign-subprocess"),
        feature = "justsign"
    ))]
    let invoker: Box<dyn CosignInvoker> =
        Box::new(crate::core::justsign_invoker::JustsignInvoker::new());

    attest_with_invoker(built, attestation, cas, invoker.as_ref())
}

/// Same as `attest`, but the cosign invoker is injected. Used by
/// integration tests to script signing outcomes; can also be used
/// in production to swap a custom invoker (e.g. a future BYO-key
/// signer) without changing the public API.
pub fn attest_with_invoker(
    built: &BuiltArtifact,
    attestation: &AttestationConfig,
    cas: &dyn Cas,
    invoker: &dyn CosignInvoker,
) -> Result<AttestationOutputs, AttestError> {
    tracing::debug!(
        target: "attest",
        manifest = %built.manifest_digest,
        slsa_level = attestation.slsa.level.as_int(),
        sbom_format = attestation.sbom.format.as_str(),
        sign_kind = attestation.sign.kind.as_str(),
        "running attestation pipeline",
    );

    let slsa = emit_slsa(built, &attestation.slsa, cas)?;

    let sbom = match attestation.sbom.format {
        SbomFormat::CycloneDx => Some(emit_cyclonedx(built, attestation.sbom.scope, cas)?),
        SbomFormat::Spdx => Some(emit_spdx(built, attestation.sbom.scope, cas)?),
        SbomFormat::Off => None,
    };

    let signature = match attestation.sign.kind {
        SignKind::Off => None,
        SignKind::CosignKeyless | SignKind::CosignKey => {
            sign_with(&built.manifest_digest, &attestation.sign, cas, invoker)?
        }
    };

    Ok(AttestationOutputs {
        slsa,
        sbom,
        signature,
    })
}
