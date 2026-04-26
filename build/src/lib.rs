//! `oci-build` — assemble an OCI Image Spec v1.1 layout from a
//! validated [`spec::Spec`].
//!
//! Phase-1 surface: the spec-driven [`build`] entry point produces a
//! complete `OCI Image Layout v1.1` directory containing layer blobs
//! (compressed per the spec's `Compression`), an OCI image config
//! blob, an OCI manifest, and the `oci-layout` + `index.json`
//! markers — directly consumable by `oras pull`, `crane pull`, or any
//! distribution-spec registry.
//!
//! See [`saf::build::build`] for the public entry point and
//! [`api::build_error::BuildError`] for the error model.
//!
//! ## Legacy surface
//!
//! [`api::error::Error`], [`api::spec`] (`ImageSpec`, `BaseRef`,
//! `BuildArtifacts`, `FileEntry`, `InitMode`), and [`api::manifest`]
//! (`BuildManifest`, etc.) are kept as plain serde data types so
//! sibling crates (`oci-publish`, the `cli`) continue to compile
//! while their refactors land. The legacy `build_image` orchestrator
//! and the `RootfsBuilder` / `PackageInstaller` / `FileOverlay`
//! traits moved out — they belong in the vmisolate workspace
//! (per ADR P2).

pub mod api;
pub mod core;
pub mod saf;

// Spec-driven public surface — the new primary API.
pub use api::build_error::BuildError;
pub use api::build_output::BuildOutput;
pub use api::oci_manifest::{
    OciDescriptor, OciImageConfig, OciIndex, OciLayout, OciManifest, OciRuntimeConfig,
    MEDIA_TYPE_OCI_CONFIG, MEDIA_TYPE_OCI_INDEX, MEDIA_TYPE_OCI_MANIFEST,
    OCI_LAYOUT_VERSION,
};
pub use saf::build::build;

// Legacy types kept for sibling-crate compilation. The new pipeline
// does not consume any of these.
pub use api::error::Error;
pub use api::manifest::{
    source_date_epoch, ArtifactDigests, BuildManifest, FileManifestEntry, PackageManifest,
    INSTALLER_FAMILY_ALPINE_APK,
};
pub use api::spec::{BaseRef, BuildArtifacts, FileEntry, ImageSpec, InitMode};
