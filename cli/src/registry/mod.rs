//! Registry-pull machinery for `ocimage verify <registry-ref>`.
//!
//! Module map:
//!
//! - [`error`] — [`error::RegistryPullError`], the typed failure
//!   surface (folds into [`crate::error::CliError::RegistryPull`]).
//! - [`ref_parser`] — strict parser for `host[:port]/repo:tag`
//!   and `@sha256:<hex>` reference forms.
//! - [`auth`] — auth header resolution + 401-then-bearer token
//!   dance per OCI Distribution §3.4.
//! - [`pull`] — the pull pipeline: manifest, blobs, referrers,
//!   layout assembly, atomic `index.json`-last commit.
//!
//! Public entry points:
//!
//! - [`pull::pull_into_image_dir`] — auth-resolved pull.
//! - [`pull::pull_anonymous_into_image_dir`] — explicit anon.
//!
//! Both write a complete OCI Image Layout into the destination
//! directory; on success, the caller's [`oci_publish::ImageDir::open`]
//! validates and the existing local-verify path runs unchanged.

pub mod auth;
pub mod error;
pub mod pull;
pub mod ref_parser;

pub use error::RegistryPullError;
pub use pull::{pull_anonymous_into_image_dir, pull_into_image_dir};
pub use ref_parser::{parse_registry_ref, RefTarget, RegistryRef};
