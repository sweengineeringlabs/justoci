//! `swe_justoci_oci_publish` — push a built OCI image directory to a sink.
//!
//! Two sinks ship in v0:
//!
//!   * [`PublishSink::Http`]     — copy the image into a static-served
//!     directory (ADR-015 Level 2). Per-blob skip-if-exists makes
//!     re-publishes idempotent; the `index.json` is written LAST under
//!     a temp file + atomic rename so consumers never see a half-state.
//!   * [`PublishSink::Registry`] — push to an OCI Distribution v2
//!     registry (ADR-015 Level 4). Per-blob HEAD-then-PUT skips blobs
//!     the registry already has; manifest PUT is the commit point and
//!     fires after every other blob is confirmed-present.
//!
//! Both sinks consume an [`ImageDir`] — an opaque newtype around a
//! validated OCI image directory. `ImageDir::open` is the input
//! contract: it parses `oci-layout` + `index.json`, walks the manifest
//! and any referrer artifacts (SLSA / SBOM / signatures), and returns
//! a typed view a publish sink can copy without re-parsing JSON.
//!
//! The single public entry point is [`publish`] in [`saf::publish`];
//! it dispatches on the sink variant and never bypasses the
//! [`api::error::PublishError`] surface.

pub mod api;
pub mod core;
pub mod saf;

pub use api::error::PublishError;
pub use api::image_dir::{ImageDescriptor, ImageDir, ImageDirError};
pub use api::sink::{PublishOutcome, PublishSink, RegistryAuth};
pub use saf::publish::publish;
pub use core::streaming_sink::push_artifact_streaming;
