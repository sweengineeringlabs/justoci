#[cfg(feature = "oras")]
pub mod oras;
#[cfg(feature = "cosign")]
pub mod cosign;
#[cfg(all(feature = "oras", feature = "cosign"))]
pub mod oras_cosign;
