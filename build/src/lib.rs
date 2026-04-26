//! `oci-build` — assemble an OCI Image Spec v1.1 layout from a
//! validated [`spec::Spec`].
//!
//! The spec-driven [`build`] entry point produces a complete
//! `OCI Image Layout v1.1` directory containing layer blobs
//! (compressed per the spec's `Compression`), an OCI image config
//! blob, an OCI manifest, and the `oci-layout` + `index.json`
//! markers — directly consumable by `oras pull`, `crane pull`, or any
//! distribution-spec registry.
//!
//! See [`saf::build::build`] for the public entry point and
//! [`api::build_error::BuildError`] for the error model.

pub mod api;
pub mod core;
pub mod saf;

pub use api::build_error::BuildError;
pub use api::build_output::BuildOutput;
pub use api::oci_manifest::{
    OciDescriptor, OciImageConfig, OciIndex, OciLayout, OciManifest, OciRuntimeConfig,
    MEDIA_TYPE_OCI_CONFIG, MEDIA_TYPE_OCI_INDEX, MEDIA_TYPE_OCI_MANIFEST,
    OCI_LAYOUT_VERSION,
};
pub use saf::build::build;
