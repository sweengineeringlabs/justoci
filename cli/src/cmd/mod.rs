//! One module per `ocimage` subcommand.
//!
//! Each module exposes a single typed-Result entry point that
//! `main` dispatches into. Subcommand internals never use
//! `anyhow::Result` — only typed errors that fold into
//! [`crate::error::CliError`].

pub mod build;
pub mod inspect;
pub mod publish;
pub mod sbom;
pub mod verify;
