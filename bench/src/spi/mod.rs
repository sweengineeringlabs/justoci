#[cfg(feature = "oras")]
pub mod oras;
#[cfg(all(feature = "oras", feature = "cosign"))]
pub mod oras_cosign;
