use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use tempfile::TempDir;

use crate::{BuildRunner, CaseConfig};

pub struct OrasRunner {
    label: String,
    payload_bytes: u64,
    registry_ref: String,
    /// Working directory passed to oras so we can use a bare filename instead
    /// of an absolute path. oras 1.x on Windows rejects absolute paths in the
    /// `file:media-type` argument; using a relative name avoids the issue.
    work_dir: PathBuf,
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
        fs::write(tmp.path().join("payload.bin"), &payload)
            .expect("oras bench: failed to write payload");

        // OCI tags must not contain '/'; derive a stable tag from the label.
        let tag = case.label.replace('/', "-");
        let registry_ref = format!("{registry}/bench-artifact:{tag}");
        let work_dir = tmp.path().to_path_buf();

        Self { label: case.label, payload_bytes, registry_ref, work_dir, _tmp: tmp }
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
            .current_dir(&self.work_dir)
            .args([
                "push",
                "--plain-http",
                &self.registry_ref,
                "payload.bin:application/octet-stream",
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
            "oras not found on PATH — the oras bench requires oras 1.x \
             and a local registry running (e.g. docker run -d -p 5000:5000 registry:2)"
        ));
}
