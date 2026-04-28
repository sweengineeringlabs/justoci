use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

use tempfile::TempDir;

use crate::{BuildRunner, CaseConfig};

pub struct OrasRunner {
    label: String,
    payload_bytes: u64,
    /// Pre-built `path:media-type` argument for `oras push`.
    file_arg: String,
    registry_ref: String,
    _tmp: TempDir,
}

impl OrasRunner {
    pub fn new(case: CaseConfig) -> Self {
        which_oras();

        let payload_bytes = case
            .params
            .get("payload_bytes")
            .and_then(|v| v.as_integer())
            .unwrap_or_else(|| panic!("oras case '{}': missing param 'payload_bytes'", case.label))
            as u64;

        let registry = case
            .params
            .get("registry")
            .and_then(|v| v.as_str())
            .unwrap_or("localhost:5000")
            .to_owned();

        let tmp = TempDir::new().expect("oras bench: failed to create work dir");

        let payload: Vec<u8> = (0..payload_bytes as usize).map(|i| i as u8).collect();
        let payload_path = tmp.path().join("payload.bin");
        fs::write(&payload_path, &payload).expect("oras bench: failed to write payload");

        // OCI tags must not contain '/'; derive a stable tag from the label.
        let tag = case.label.replace('/', "-");
        let registry_ref = format!("{registry}/bench-artifact:{tag}");

        // oras 1.x file:type syntax: `<path>:<media-type>`.
        let file_arg = format!(
            "{}:application/octet-stream",
            payload_path.to_str().expect("payload path is valid utf-8"),
        );

        Self { label: case.label, payload_bytes, file_arg, registry_ref, _tmp: tmp }
    }
}

impl BuildRunner for OrasRunner {
    fn label(&self) -> &str {
        &self.label
    }

    fn bytes_written(&self) -> u64 {
        self.payload_bytes
    }

    // `output_path` is unused — oras pushes to the registry, not to local disk.
    fn run(&self, _output_path: &Path) {
        let status = Command::new("oras")
            .args([
                "push",
                "--plain-http",
                &self.registry_ref,
                &self.file_arg,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("oras bench: failed to spawn oras push");
        assert!(status.success(), "oras push exited with {status}");
    }
}

fn which_oras() {
    Command::new("oras")
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap_or_else(|_| panic!(
            "oras not found on PATH — the oras bench requires Linux or WSL2 with oras 1.x \
             installed and a local registry running (e.g. docker run -d -p 5000:5000 registry:2)"
        ));
}
