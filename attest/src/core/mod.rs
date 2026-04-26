pub mod cosign;
pub mod sbom_cyclonedx;
pub mod sbom_spdx;
pub mod slsa;

// Re-exported so integration tests in `tests/` (which build the
// crate normally, not under #[cfg(test)]) can construct the stub
// cosign invoker and inject scripted outcomes.
pub use cosign::{
    sign_with, CosignInvocation, CosignInvoker, CosignOutcome, RealCosignInvoker, StubCosignInvoker,
};
