pub mod attestation;
pub mod error;
pub mod spec;

pub use attestation::{
    AttestationConfig, SbomConfig, SbomFormat, SbomScope, SignConfig, SignKind, SlsaConfig,
    SlsaLevel,
};
pub use error::SpecError;
pub use spec::{
    ArtifactId, Compression, ConfigBlob, Kind, Layer, LayerFile, LayerSource, MediaType, Platform,
    Spec, SpecVersion,
};
