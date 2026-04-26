//! Typed CLI error model.
//!
//! `CliError` is the single failure surface every subcommand bubbles
//! up to `main`. It wraps the upstream typed errors verbatim
//! (no string-formatting them at the boundary, so the chained
//! `Display` walks render the original spec/build/attest/publish
//! diagnostic exactly as those crates produced it) and adds two
//! CLI-only variants — `Verify` and `Cli` — for the new verify
//! pillar walker and for argument-parsing-shaped local failures
//! (e.g. malformed `--to` URI).
//!
//! ## Exit-code mapping
//!
//! Per spec doc §7 (`docs/spec-v0.md`):
//!
//! | Exit | Variant                  | Meaning                                  |
//! |------|--------------------------|------------------------------------------|
//! | `0`  | (success — no `Err`)     | OK                                       |
//! | `1`  | `Spec(SpecError)`        | Spec didn't parse / validate             |
//! | `2`  | `Build(BuildError)`      | Build failed (compression, hashing, etc.)|
//! | `3`  | `Attest(AttestError)`    | Attestation failed (cosign, Rekor, IO)   |
//! | `4`  | `Publish(PublishError)`  | Publish failed (HTTP / registry / auth)  |
//! | `5`  | `Verify(VerifyError)`    | Verify pillar failed or policy violation |
//! | `64` | `Cli { .. }`             | Catastrophic / unexpected                |
//!
//! CI pipelines route on `exit_code()`. Strings are for humans;
//! never grep stderr to decide what to do.

use thiserror::Error;

use crate::registry::RegistryPullError;
use crate::verify_engine::VerifyError;

/// Top-level CLI error. Implements the spec-doc §7 exit-code table
/// via [`Self::exit_code`].
#[derive(Debug, Error)]
pub enum CliError {
    /// Spec load / validate failure. Maps to exit 1.
    #[error("spec error: {0}")]
    Spec(#[from] spec::SpecError),

    /// Spec canonicalisation failure (rare — failed JCS or hash
    /// step). Maps to exit 1: it's still a spec-side problem the
    /// operator must fix at the spec layer.
    #[error("spec canonicalisation failure: {0}")]
    SpecCanonicalize(#[from] spec::CanonicalizationError),

    /// Build pipeline failure. Maps to exit 2.
    #[error("build error: {0}")]
    Build(#[from] oci_build::BuildError),

    /// Attestation pipeline failure. Maps to exit 3.
    #[error("attest error: {0}")]
    Attest(#[from] attest::AttestError),

    /// Publish pipeline failure. Maps to exit 4.
    #[error("publish error: {0}")]
    Publish(#[from] oci_publish::PublishError),

    /// Verify pipeline failure. Maps to exit 5. The verify pillar
    /// walker is CLI-local, so its error type lives in
    /// [`crate::verify_engine`].
    #[error("verify error: {0}")]
    Verify(#[from] VerifyError),

    /// Registry-pull failure on `ocimage verify <registry-ref>`.
    /// Maps to exit 5 — same class as a verify failure, since the
    /// pull is the prelude to verify. Distinct variant so a CLI
    /// log scraper can route on "the artifact wasn't even
    /// pullable" vs "pulled, structurally invalid".
    #[error("registry pull error: {0}")]
    RegistryPull(#[from] RegistryPullError),

    /// CLI-local failure that doesn't fit a pipeline class.
    /// Examples: malformed `--to` URI, image dir / spec path
    /// arguments that aren't actual files, IO writing the
    /// SBOM `--output` file.
    ///
    /// The mapping is deliberate: an operator typo in a CLI flag
    /// is a different fix from a build / publish backend error.
    /// This maps to exit 64 (catastrophic) per spec §7 — the
    /// operator must read the message and fix invocation.
    #[error("cli error: {detail}")]
    Cli { detail: String },

    /// IO failure inside the CLI itself (e.g. writing stdout to a
    /// `-o <file>`, reading a `--policy` TOML). Maps to 64.
    #[error("cli io error at {path}: {source}")]
    CliIo {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

impl CliError {
    /// Map to the spec doc §7 exit code.
    pub fn exit_code(&self) -> u8 {
        match self {
            CliError::Spec(_) | CliError::SpecCanonicalize(_) => 1,
            CliError::Build(_) => 2,
            CliError::Attest(_) => 3,
            CliError::Publish(_) => 4,
            CliError::Verify(_) | CliError::RegistryPull(_) => 5,
            CliError::Cli { .. } | CliError::CliIo { .. } => 64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // Catches: a refactor that re-orders the match arms in
    // exit_code() and silently re-classifies a SpecError as exit 2.
    // CI pipelines that branch on the exit code would route a spec
    // typo into the build-failure handler. The mapping is the
    // contract; pin it.
    #[test]
    fn test_exit_code_spec_returns_1() {
        let e = CliError::Spec(spec::SpecError::UnknownKind {
            got: "bogus".into(),
        });
        assert_eq!(e.exit_code(), 1);
    }

    // Catches: re-classifying BuildError to a non-2 exit. The
    // spec doc §7 table is the operator-facing contract — drift
    // breaks every CI script.
    #[test]
    fn test_exit_code_build_returns_2() {
        let e = CliError::Build(oci_build::BuildError::Io {
            path: PathBuf::from("/x"),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "missing"),
        });
        assert_eq!(e.exit_code(), 2);
    }

    // Catches: AttestError mapped to anything but 3. The spec
    // doc explicitly recommends "re-run with --no-attest" on a 3,
    // so a wrong code mis-leads the operator's recovery path.
    #[test]
    fn test_exit_code_attest_returns_3() {
        let e = CliError::Attest(attest::AttestError::CosignNotInstalled);
        assert_eq!(e.exit_code(), 3);
    }

    // Catches: PublishError → wrong exit. Publish failures are
    // safe-to-retry per spec §6 ("transient or auth"); the 4 is
    // the signal that retrying is the right reaction.
    #[test]
    fn test_exit_code_publish_returns_4() {
        let e = CliError::Publish(oci_publish::PublishError::RegistryRefused {
            status: 503,
            body: "unavailable".into(),
        });
        assert_eq!(e.exit_code(), 4);
    }

    // Catches: VerifyError absorbed into a non-5 exit. Verify is
    // the only subcommand whose failure must NOT crash a deploy
    // (operators choose what to do with a policy violation).
    // Routing it through 5 keeps that decision deterministic.
    #[test]
    fn test_exit_code_verify_returns_5() {
        let e = CliError::Verify(VerifyError::SbomMissing);
        assert_eq!(e.exit_code(), 5);
    }

    // Catches: RegistryPullError mapped to anything but 5. The
    // pull is the prelude to verify; a registry-side failure that
    // exits 4 would mis-route a CI script to the publish-class
    // recovery path (where 4 means "transient, retry"). Pull
    // failures are NOT generally retryable — a malformed ref,
    // 404 manifest, or tampered blob is a real verify-side
    // problem.
    #[test]
    fn test_exit_code_registry_pull_returns_5() {
        let e = CliError::RegistryPull(RegistryPullError::MalformedRef {
            got: "bad".into(),
            reason: "test".into(),
        });
        assert_eq!(e.exit_code(), 5);
    }

    // Catches: CLI-local errors silently mapped to 1/2/3/4 and
    // mis-attributed to a backend failure. A typo in `--to` is
    // not a publish-backend error.
    #[test]
    fn test_exit_code_cli_local_returns_64() {
        let e = CliError::Cli {
            detail: "bad --to URI".into(),
        };
        assert_eq!(e.exit_code(), 64);
    }
}
