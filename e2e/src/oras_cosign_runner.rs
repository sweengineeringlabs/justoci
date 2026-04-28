use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use tempfile::TempDir;

use crate::{CaseConfig, PipelineRunner};

pub struct OrasCosignRunner {
    label: String,
    payload_bytes: u64,
    registry: String,
    repo: String,
    key_path: std::path::PathBuf,
    bundle_path: std::path::PathBuf,
    counter: AtomicU64,
    _tmp: TempDir,
}

impl OrasCosignRunner {
    pub fn new(case: CaseConfig) -> Self {
        which_tool("oras");
        which_tool("cosign");

        let payload_bytes = case
            .params
            .get("payload_bytes")
            .and_then(|v| v.as_integer())
            .unwrap_or_else(|| panic!("oras-cosign case '{}': missing param 'payload_bytes'", case.label))
            as u64;

        let registry = case
            .params
            .get("registry")
            .and_then(|v| v.as_str())
            .unwrap_or("localhost:5000")
            .to_owned();

        let tmp = TempDir::new().expect("oras-cosign bench: failed to create work dir");

        // Write payload — oras reads it by bare filename via current_dir.
        let payload: Vec<u8> = (0..payload_bytes as usize).map(|i| i as u8).collect();
        fs::write(tmp.path().join("payload.bin"), &payload)
            .expect("oras-cosign bench: failed to write payload");

        // Generate cosign key pair with empty password.
        let key_prefix = tmp.path().join("key");
        let key_prefix_str = key_prefix.to_str().expect("key prefix is valid utf-8");
        let status = Command::new("cosign")
            .args(["generate-key-pair", "--output-key-prefix", key_prefix_str])
            .env("COSIGN_PASSWORD", "")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("oras-cosign bench: failed to spawn cosign generate-key-pair");
        assert!(status.success(), "cosign generate-key-pair exited with {status}");

        let key_path = tmp.path().join("key.key");
        let bundle_path = tmp.path().join("bundle.json");
        let repo = case.label.replace('/', "-");

        Self {
            label: case.label,
            payload_bytes,
            registry,
            repo,
            key_path,
            bundle_path,
            counter: AtomicU64::new(0),
            _tmp: tmp,
        }
    }
}

impl PipelineRunner for OrasCosignRunner {
    fn label(&self) -> &str {
        &self.label
    }

    fn payload_bytes(&self) -> u64 {
        self.payload_bytes
    }

    // `output_path` is unused — oras pushes to the registry, not local disk.
    fn run(&self, _output_path: &Path) {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let registry_ref = format!("{}/{}:bench-{n}", self.registry, self.repo);

        // Step 1: push via oras.
        let status = Command::new("oras")
            .current_dir(self._tmp.path())
            .args([
                "push",
                "--plain-http",
                &registry_ref,
                "payload.bin:application/octet-stream",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("oras-cosign bench: failed to spawn oras push");
        assert!(status.success(), "oras push exited with {status}");

        // Step 2: sign the payload blob via cosign.
        let status = Command::new("cosign")
            .current_dir(self._tmp.path())
            .args([
                "sign-blob",
                "--key",
                self.key_path.to_str().expect("key path is valid utf-8"),
                "--bundle",
                self.bundle_path.to_str().expect("bundle path is valid utf-8"),
                "--yes",
                "payload.bin",
            ])
            .env("COSIGN_PASSWORD", "")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("oras-cosign bench: failed to spawn cosign sign-blob");
        assert!(status.success(), "cosign sign-blob exited with {status}");
    }
}

fn which_tool(name: &str) {
    Command::new(name)
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap_or_else(|_| panic!(
            "e2e bench: '{name}' not found on PATH\n\
             oras:   winget install ORASProject.ORAS  (or Linux package)\n\
             cosign: https://github.com/sigstore/cosign/releases  (Linux / WSL2)"
        ));
}
