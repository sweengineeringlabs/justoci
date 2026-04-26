//! `ocimage` — the operator-facing CLI for justoci.
//!
//! This crate is dual-target:
//!
//! - **`bin/ocimage`** is the binary operators run. It's a thin
//!   clap-driven dispatcher: parse args → call into one of the
//!   `cmd::*` entry points → translate the typed `CliError` into
//!   the spec-doc §7 exit code. The binary owns no business logic.
//!
//! - **`lib`** exposes the typed subcommand entry points, the
//!   `CliError` enum, the verify pillar walker, the policy parser,
//!   and the referrer-writing helper. Integration tests under
//!   `tests/` import this lib so they can drive subcommand logic
//!   with stub invokers (e.g. `StubCosignVerifyInvoker`) without
//!   needing cosign installed.
//!
//! The CLI never imports `anyhow::Result` for subcommand internals —
//! every per-subcommand entry point returns `Result<T, CliError>`,
//! and `CliError` carries the upstream typed errors verbatim. This
//! is the contract that makes spec-doc §7 (typed exit codes per
//! error class) implementable.

pub mod cmd;
pub mod error;
pub mod policy;
pub mod referrers;
pub mod verify_engine;

pub use error::CliError;
