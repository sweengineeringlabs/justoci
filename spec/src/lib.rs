//! justoci spec — parser + validator + canonicaliser for v0 specs.
//!
//! Single source of truth for what a justoci v0 TOML spec means.
//! Build / attest / publish all consume `Spec` values produced here.
//!
//! ```ignore
//! use spec::{parse_and_validate, spec_hash};
//!
//! let spec = parse_and_validate("examples/vm-image.toml")?;
//! let hash = spec_hash(&spec)?;
//! println!("spec_hash = {hash}");
//! ```
//!
//! Once a `Spec` exists, every Production-Guarantees-§4 rule has been
//! checked: id format, kind-correct layer count, vm_image layer
//! ordering, source path existence, media type grammar, reserved
//! annotation values, SLSA range, sign mode requirements. There is
//! no path that produces a `Spec` and later raises a validation
//! error during build.

pub mod api;
pub mod core;
pub mod saf;

pub use api::{
    ArtifactId, AttestationConfig, Compression, ConfigBlob, Kind, Layer, LayerFile, LayerSource,
    MediaType, Platform, SbomConfig, SbomFormat, SbomScope, SignConfig, SignKind, SlsaConfig,
    SlsaLevel, Spec, SpecError, SpecVersion,
};
pub use saf::{
    canonical_bytes, parse_and_validate, parse_and_validate_str, spec_hash, CanonicalizationError,
};
