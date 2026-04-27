pub mod cosign;
pub mod sbom_cyclonedx;
pub mod sbom_spdx;
pub mod slsa;

#[cfg(feature = "sigstore-rs")]
pub mod sigstore_invoker;

#[cfg(feature = "justsign")]
pub mod justsign_invoker;

// Re-exported so integration tests in `tests/` (which build the
// crate normally, not under #[cfg(test)]) can construct the stub
// invoker and inject scripted outcomes. The trait surface is
// independent of which production invoker is wired up by Cargo
// features.
pub use cosign::{sign_with, CosignInvocation, CosignInvoker, CosignOutcome, StubCosignInvoker};

#[cfg(feature = "cosign-subprocess")]
pub use cosign::RealCosignInvoker;

#[cfg(feature = "sigstore-rs")]
pub use sigstore_invoker::SigstoreInvoker;

#[cfg(feature = "justsign")]
pub use justsign_invoker::{JustsignInvoker, JustsignTarget};

// Compile-time guard: the lib must be built with at least one
// signer feature on. Default is `sigstore-rs`. Operators who pass
// `--no-default-features` without re-enabling a signer get a
// clear compiler error rather than a binary that panics at the
// first sign call. Mirrors the [features] block in Cargo.toml.
#[cfg(not(any(
    feature = "sigstore-rs",
    feature = "cosign-subprocess",
    feature = "justsign"
)))]
compile_error!(
    "swe_justoci_attest requires at least one signer feature: \
     `sigstore-rs` (default), `cosign-subprocess`, or `justsign`. \
     Re-build with --features sigstore-rs, --features cosign-subprocess, \
     or --features justsign."
);
