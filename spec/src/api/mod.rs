pub mod attestation;
pub mod error;
pub mod loaded;
pub mod spec;

pub use attestation::{
    AttestationConfig, SbomConfig, SbomFormat, SbomScope, SignConfig, SignKind, SlsaConfig,
    SlsaLevel,
};
pub use error::SpecError;
pub use loaded::LoadedSpec;
pub use spec::{
    ArtifactId, Compression, ConfigBlob, Kind, Layer, LayerFile, LayerSource, MediaType, Platform,
    Spec, SpecVersion,
};
