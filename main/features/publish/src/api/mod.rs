//! API layer — public types, errors, and the input/output contract
//! for `publish`.
//!
//! Module map:
//!   * [`error`]     — [`PublishError`], the typed failure surface.
//!   * [`sink`]      — [`PublishSink`], [`PublishOutcome`], [`RegistryAuth`].
//!   * [`image_dir`] — [`ImageDir`], the validated input contract.

pub mod error;
pub mod image_dir;
pub mod sink;
