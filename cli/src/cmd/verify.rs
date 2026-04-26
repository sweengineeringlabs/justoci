//! `ocimage verify <ref> [--policy <policy.toml>] [--auth ...]`.
//!
//! ## Reference detection
//!
//! `<ref>` is detected as one of two shapes:
//!
//! - **Local OCI Image Layout dir.** If the ref names an existing
//!   path on disk, treat as the local-verify path the v0 CLI
//!   already shipped — `ImageDir::open(path)` then walk pillars.
//! - **Registry reference.** If the ref does NOT exist on disk,
//!   parse as `host[:port]/repo:tag` (or `@sha256:<hex>`).
//!   Pull the artifact + its referrers into a fresh tempdir, then
//!   dispatch into the same local-verify path.
//!
//! The path-first detection rule means a typo'd local path
//! (`./by-image-dr` instead of `./my-image-dir`) doesn't silently
//! attempt a registry call; the parser surfaces "MalformedRef"
//! immediately and the operator fixes the path.
//!
//! ## Auth (registry-ref branch only)
//!
//! Re-uses [`oci_publish::RegistryAuth`] so an operator who
//! configured `ocimage publish` doesn't have to learn a second
//! model. The CLI surface is identical to publish's:
//!
//! - `--auth env` (default) — `REGISTRY_TOKEN`, then
//!   `REGISTRY_USERNAME` + `REGISTRY_PASSWORD`.
//! - `--auth basic` — requires `--registry-username` +
//!   `--registry-password`.
//! - `--auth bearer` — requires `--registry-token`.
//! - `--no-auth` — explicit anonymous (skips env lookup; the
//!   shorthand for "I know this registry is public").
//!
//! ## v0.2 contract
//!
//! Returns a [`VerifyReport`] on success. The CLI layer prints
//! the pillar verdicts (table) and exits 0 when no policy was
//! supplied and no pillar was Found-but-Failed; otherwise the
//! typed [`CliError::Verify`] / [`CliError::RegistryPull`]
//! propagate to exit 5.

use std::path::Path;

use crate::cmd::publish::AuthMode;
use crate::error::CliError;
use crate::policy::Policy;
use crate::registry::{pull_anonymous_into_image_dir, pull_into_image_dir};
use crate::verify_engine::{verify, RealCosignVerifyInvoker, VerifyReport};

/// Auth selector for `ocimage verify <registry-ref>`. Mirrors
/// publish's [`AuthMode`] plus an explicit anonymous variant; we
/// don't reuse publish's enum directly because verify supports
/// `--no-auth` (skip env entirely) which publish doesn't expose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyAuthMode {
    /// Explicit anonymous — skip credential resolution entirely.
    /// For public registries; equivalent to `--no-auth`.
    Anonymous,
    /// Pre-resolved auth identical to the publish surface.
    Authenticated(AuthMode),
}

/// Run the verify subcommand.
///
/// `<reference>` is treated as a local path FIRST: if the path
/// exists, the existing local-verify flow runs. If not, the ref
/// is parsed as a registry reference and a pull-into-tempdir
/// happens before dispatching into the same local-verify code
/// path.
///
/// `auth` is consulted only on the registry-ref branch. Local
/// paths ignore it (auth has no meaning for a layout already on
/// disk).
pub fn run(
    reference: &str,
    policy_path: Option<&Path>,
    auth: VerifyAuthMode,
) -> Result<VerifyReport, CliError> {
    let policy: Option<Policy> = match policy_path {
        Some(p) => Some(Policy::load(p)?),
        None => None,
    };

    // Path-first detection. `Path::exists` returns true for both
    // files and dirs; the local-verify path inside `verify_engine`
    // requires a dir — `ImageDir::open` errors with a precise
    // message if the path is a file rather than a layout dir,
    // which is the right diagnostic for the operator.
    let candidate = Path::new(reference);
    if candidate.exists() {
        return run_local(candidate, policy.as_ref());
    }

    // Not a local path → treat as a registry reference. Build a
    // fresh tempdir, pull into it, then run the same local-verify.
    let tempdir = tempfile::TempDir::new().map_err(|source| CliError::CliIo {
        path: "<tempdir for registry pull>".into(),
        source,
    })?;
    pull_for_verify(reference, &auth, tempdir.path())?;
    run_local(tempdir.path(), policy.as_ref())
}

/// Path-only convenience for callers that pre-resolved a path to
/// disk. Defaults to anonymous auth (irrelevant — auth is only
/// consulted on the registry-ref branch). Kept so existing
/// integration tests under `tests/` that drive the library
/// directly don't have to import the full auth surface.
pub fn run_path(image_dir: &Path, policy_path: Option<&Path>) -> Result<VerifyReport, CliError> {
    let s = image_dir
        .to_str()
        .ok_or_else(|| CliError::Cli {
            detail: format!("verify: path is not valid UTF-8: {}", image_dir.display()),
        })?
        .to_string();
    run(&s, policy_path, VerifyAuthMode::Anonymous)
}

fn run_local(image_dir: &Path, policy: Option<&Policy>) -> Result<VerifyReport, CliError> {
    let invoker = RealCosignVerifyInvoker::new();
    let report = verify(image_dir, policy, &invoker)?;
    Ok(report)
}

fn pull_for_verify(reference: &str, auth: &VerifyAuthMode, dest: &Path) -> Result<(), CliError> {
    match auth {
        VerifyAuthMode::Anonymous => {
            pull_anonymous_into_image_dir(reference, dest)?;
        }
        VerifyAuthMode::Authenticated(mode) => {
            let registry_auth = mode.clone().into_registry_auth();
            pull_into_image_dir(reference, &registry_auth, dest)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Catches: a path-first detection regression that tries to
    // hit the network on every invocation, including ones whose
    // ref is a clearly-local path. The contract is "if it's a
    // path on disk, it's local"; without this test, a refactor
    // that flips the order would make every local verify timeout
    // against a non-existent host.
    #[test]
    fn test_run_path_existing_path_does_not_attempt_network() {
        // Tempdir is the deterministic choice for an existing-but-
        // empty path. The tempdir contents won't pass layout
        // validation, so an error IS expected — but the error
        // MUST be from the local layout validator (folded through
        // `CliError::Verify`), NOT a `CliError::RegistryPull`.
        // Asserting the variant proves we routed through the
        // local branch.
        let tmp = tempfile::TempDir::new().unwrap();
        let err = run_path(tmp.path(), None).unwrap_err();
        match err {
            CliError::Verify(_) => { /* expected: layout-side error */ }
            CliError::RegistryPull(_) => {
                panic!(
                    "verify with an existing path must NOT route through the registry-pull branch"
                )
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    // Catches: a missing path silently treated as a malformed
    // registry ref, then surfaced as a confusing parser error.
    // The right behaviour: try to parse as a registry ref ONCE;
    // a parser failure surfaces as `RegistryPull(MalformedRef)`
    // — which still maps to exit 5 — so the CLI can clearly say
    // "this is not a path AND not a registry ref."
    #[test]
    fn test_run_nonexistent_path_routes_to_registry_pull_branch() {
        // Use a string that has no `/` — guaranteed to fail the
        // ref parser, proving the routing happened.
        let err = run(
            "definitely-not-a-real-ref-or-path",
            None,
            VerifyAuthMode::Anonymous,
        )
        .unwrap_err();
        match err {
            CliError::RegistryPull(_) => { /* expected: ref parser rejected */ }
            other => panic!("expected CliError::RegistryPull, got {other:?}"),
        }
    }
}
