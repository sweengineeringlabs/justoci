//! Cosign-backed attester — shells out to the `cosign` CLI.
//!
//! Initial impl: invokes `cosign attest-blob --predicate <payload>
//! --type slsaprovenance <subject-digest>` on the statement bytes,
//! captures the output, returns a Signature. Does NOT handle OCI
//! registry attachment yet — that lands when this crate is wired
//! into `ocimage publish`.
//!
//! Keyless vs keyed is chosen by config: `CosignAttester::keyless()`
//! uses OIDC (GITHUB_* env vars in CI, browser flow locally);
//! `CosignAttester::with_key(path)` uses a cosign keyfile.
//!
//! # Requirements
//!
//! - `cosign` binary on PATH (tested with v2.4+)
//! - For keyless: OIDC issuer reachable (public sigstore by default)
//! - For keyed: private key file accessible to the process
//!
//! # Smoke testing
//!
//! Cosign integration tests gate on `ATTEST_SMOKE=1` — CI without
//! cosign installed skips them rather than failing. Set the env
//! var and ensure cosign is on PATH before running
//! `cargo test -p swe_vmisolate_attest`.
//!
//! # Future migration (tracked: ADR-016 "Implementation note")
//!
//! Same story as the Fleet-side verifier
//! (`swe_vmisolate_fleet::spi::image_verifier::cosign_image_verifier`):
//! we shell out rather than linking sigstore-rs because the dep-graph
//! tax is worse than asking operators to install one binary.
//!
//! Revisit when sigstore-rs stabilises a lean signing API, or when we
//! decide to drop Fulcio/Rekor for keyed ed25519 (Scope 1). The
//! `Attester` trait already isolates the swap — drop in a
//! `SigstoreRsAttester` or `Ed25519Attester` behind the same
//! interface. Do NOT migrate pre-emptively.

use std::path::PathBuf;
use std::process::Command;

use super::Attester;
use crate::api::attestation::Statement;
use crate::api::error::AttestError;
use crate::api::signature::{Signature, SignatureFormat};
use crate::core::emit::emit_statement;

/// Cosign attester modes.
#[derive(Debug, Clone)]
enum Mode {
    /// Keyless OIDC flow. Identity comes from the OIDC issuer
    /// (Fulcio); cosign handles the browser or CI-token handshake.
    Keyless,
    /// Keyed mode — the operator supplies a cosign keyfile path.
    Keyed { key_path: PathBuf },
}

/// Cosign-backed attester.
pub struct CosignAttester {
    mode: Mode,
    /// Identity string as reported to the Signature — for keyless
    /// this is the builder URI (GitHub workflow in CI); for keyed
    /// this is a user-chosen identifier (typically the key fingerprint).
    identity: String,
}

impl CosignAttester {
    /// Keyless mode. `identity` names the expected OIDC subject
    /// for later verification (e.g. the GitHub workflow URI). Not
    /// enforced by the CLI at signing time — Rekor records whatever
    /// the OIDC issuer returns.
    pub fn keyless(identity: impl Into<String>) -> Self {
        Self {
            mode: Mode::Keyless,
            identity: identity.into(),
        }
    }

    /// Keyed mode — supply a cosign private key file path.
    /// `identity` is a caller-chosen label (e.g. the key
    /// fingerprint) that's embedded in the resulting Signature.
    pub fn with_key(key_path: impl Into<PathBuf>, identity: impl Into<String>) -> Self {
        Self {
            mode: Mode::Keyed {
                key_path: key_path.into(),
            },
            identity: identity.into(),
        }
    }

    /// Build the argv for `cosign attest-blob`. Split out so tests
    /// can assert the command shape without spawning a process.
    fn build_argv(&self, payload_path: &std::path::Path) -> Vec<String> {
        let mut argv: Vec<String> = vec![
            "attest-blob".into(),
            "--predicate".into(),
            payload_path.display().to_string(),
            "--type".into(),
            "slsaprovenance".into(),
        ];
        match &self.mode {
            Mode::Keyless => {
                // Cosign's default is keyless when no --key is passed.
                // Explicitly pass --yes to skip the interactive
                // confirmation in non-tty contexts.
                argv.push("--yes".into());
            }
            Mode::Keyed { key_path } => {
                argv.push("--key".into());
                argv.push(key_path.display().to_string());
                argv.push("--yes".into());
            }
        }
        argv
    }

    /// Check if `cosign` is on PATH. Used by the smoke test gate to
    /// skip rather than fail when the dev env doesn't have cosign.
    pub fn cosign_available() -> bool {
        Command::new("cosign")
            .arg("version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

impl Attester for CosignAttester {
    fn sign(&self, statement: &Statement) -> Result<Signature, AttestError> {
        // Write the statement bytes to a temp file so cosign can
        // read them via --predicate. Cosign supports stdin for
        // some subcommands but attest-blob needs a file path.
        let bytes = emit_statement(statement)?;

        let tmp_dir = std::env::temp_dir();
        let tmp_path = tmp_dir.join(format!("attest-{}.json", std::process::id()));
        std::fs::write(&tmp_path, &bytes)
            .map_err(|e| AttestError::io(e, format!("writing payload to {}", tmp_path.display())))?;

        let argv = self.build_argv(&tmp_path);

        let output = Command::new("cosign")
            .args(&argv)
            .output()
            .map_err(|e| AttestError::AttesterFailed {
                detail: format!(
                    "failed to spawn cosign (is it on PATH?): {e}"
                ),
            })?;

        // Best-effort cleanup; keep-going on failure — the tmp will
        // get cleared by the OS eventually.
        let _ = std::fs::remove_file(&tmp_path);

        if !output.status.success() {
            return Err(AttestError::AttesterFailed {
                detail: format!(
                    "cosign exit {}: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            });
        }

        // Cosign attest-blob emits the DSSE envelope on stdout.
        // We store it verbatim as the Signature bytes; verifiers
        // parse it back via cosign verify-blob-attestation.
        Ok(Signature {
            format: SignatureFormat::CosignDsse,
            identity: self.identity.clone(),
            bytes: output.stdout,
        })
    }

    fn name(&self) -> &'static str {
        match self.mode {
            Mode::Keyless => "cosign-keyless",
            Mode::Keyed { .. } => "cosign-keyed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keyless_argv_includes_yes_flag() {
        let a = CosignAttester::keyless("https://example.com/ci");
        let argv = a.build_argv(std::path::Path::new("/tmp/p.json"));
        assert!(argv.contains(&"--yes".to_string()));
        assert!(!argv.iter().any(|s| s == "--key"));
        assert!(argv.contains(&"--predicate".to_string()));
        assert!(argv.contains(&"slsaprovenance".to_string()));
    }

    #[test]
    fn test_keyed_argv_passes_key_path() {
        let a = CosignAttester::with_key("/secrets/cosign.key", "fingerprint:abc");
        let argv = a.build_argv(std::path::Path::new("/tmp/p.json"));
        let key_idx = argv.iter().position(|s| s == "--key").unwrap();
        assert_eq!(argv[key_idx + 1], "/secrets/cosign.key");
        assert!(argv.contains(&"--yes".to_string()));
    }

    #[test]
    fn test_name_reflects_mode() {
        assert_eq!(CosignAttester::keyless("x").name(), "cosign-keyless");
        assert_eq!(
            CosignAttester::with_key("/k", "f").name(),
            "cosign-keyed"
        );
    }

    #[test]
    fn test_cosign_available_probes_path_without_side_effect() {
        // Just exercise the function — can return true or false
        // depending on the host. Either outcome is fine for this
        // regression test.
        let _ = CosignAttester::cosign_available();
    }

    /// Smoke test — actually runs cosign. Gated behind
    /// `ATTEST_SMOKE=1` so CI without cosign still passes.
    #[test]
    fn test_cosign_smoke_if_available() {
        if std::env::var("ATTEST_SMOKE").as_deref() != Ok("1") {
            return;
        }
        if !CosignAttester::cosign_available() {
            eprintln!("ATTEST_SMOKE=1 set but cosign not on PATH — skipping");
            return;
        }

        use crate::api::attestation::{Statement, Subject};
        use crate::api::predicate_type::Predicate;
        use crate::core::slsa_builder::{BuildContext, SlsaBuilder};

        let ctx = BuildContext {
            spec_sha256: "abcd".repeat(16),
            builder_id: "https://example.com/ci/run/1".into(),
            artifacts: vec![],
            packages: vec![],
            started_at_unix: 1_700_000_000,
            finished_at_unix: 1_700_000_010,
        };
        let slsa = SlsaBuilder::new().build(&ctx).unwrap();
        let statement = Statement::new(
            Subject {
                name: "smoke:test".into(),
                digest_sha256: "f".repeat(64),
            },
            Predicate::SlsaProvenance(slsa),
        )
        .unwrap();

        // Use a keyed attester with a dev keypair for reproducibility.
        // This test assumes the env has cosign + a keyfile at
        // ATTEST_SMOKE_KEY. If not, skip.
        let key = match std::env::var("ATTEST_SMOKE_KEY") {
            Ok(k) => k,
            Err(_) => {
                eprintln!("ATTEST_SMOKE=1 but ATTEST_SMOKE_KEY unset — skipping");
                return;
            }
        };
        let attester = CosignAttester::with_key(key, "smoke:identity");
        let sig = attester.sign(&statement).expect("sign");
        assert_eq!(sig.format, SignatureFormat::CosignDsse);
        assert!(!sig.bytes.is_empty(), "cosign should emit a DSSE envelope");
    }
}
