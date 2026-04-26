//! Registry-pull machinery for `ocimage verify <registry-ref>`.
//!
//! Module map:
//!
//! - [`error`] — [`error::RegistryPullError`], the typed failure
//!   surface (folds into [`crate::error::CliError::RegistryPull`]).
//! - [`ref_parser`] — strict parser for `host[:port]/repo:tag`
//!   and `@sha256:<hex>` reference forms.
//! - [`credential_provider`] — [`credential_provider::CredentialProvider`]
//!   trait + built-in `Anonymous`/`Basic`/`Bearer`/`Env` impls. The
//!   plug-point that lets new credential sources (Vault, Docker-config)
//!   slot in without growing the wire layer.
//! - [`auth`] — [`auth::AuthManager`] (provider chain + bearer
//!   cache) and the OCI 401-then-realm dance helpers.
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
pub mod credential_provider;
pub mod error;
pub mod pull;
pub mod ref_parser;

pub use auth::AuthManager;
pub use credential_provider::{
    AnonymousProvider, BasicProvider, BearerProvider, CredError, CredentialProvider, Credentials,
    EnvProvider,
};
pub use error::RegistryPullError;
pub use pull::{
    pull_anonymous_into_image_dir, pull_anonymous_into_image_dir_with_options, pull_into_image_dir,
    pull_into_image_dir_with_options, PullOptions,
};
pub use ref_parser::{parse_registry_ref, RefTarget, RegistryRef};
