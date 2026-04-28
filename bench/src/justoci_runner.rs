use std::fs;
use std::path::Path;

use spec::{LoadedSpec, parse_and_validate_str};
use tempfile::TempDir;

use crate::{BuildRunner, CaseConfig};

pub struct JustociRunner {
    label: String,
    payload_bytes: u64,
    spec: LoadedSpec,
    // Keep the temp dir alive so the source blob path in the spec stays valid.
    _work: TempDir,
}

impl JustociRunner {
    pub fn new(case: CaseConfig) -> Self {
        let payload_bytes = case
            .params
            .get("payload_bytes")
            .and_then(|v| v.as_integer())
            .unwrap_or_else(|| panic!("justoci case '{}': missing param 'payload_bytes'", case.label))
            as u64;

        // Write source blob once; re-used across all iterations.
        let work = TempDir::new().expect("justoci bench: failed to create work dir");
        let blob_path = work.path().join("payload.bin");
        let payload: Vec<u8> = (0..payload_bytes as usize).map(|i| i as u8).collect();
        fs::write(&blob_path, &payload)
            .expect("justoci bench: failed to write payload blob");

        // Forward slashes so the TOML path string works on Windows.
        let blob_str = blob_path.to_string_lossy().replace('\\', "/");

        // Spec id tag must match [a-zA-Z0-9._-]; replace '/' in label.
        let id_tag = case.label.replace('/', "-");
        let toml = format!(
            r#"
spec_version = "0"
id           = "bench-artifact:{id_tag}"
kind         = "oci_artifact"
description  = "bench"

[[layers]]
source     = "{blob_str}"
media_type = "application/octet-stream"
"#,
        );

        let spec = parse_and_validate_str(&toml, work.path().to_path_buf())
            .expect("justoci bench: spec must parse");

        Self { label: case.label, payload_bytes, spec, _work: work }
    }
}

impl BuildRunner for JustociRunner {
    fn label(&self) -> &str {
        &self.label
    }

    fn bytes_written(&self) -> u64 {
        self.payload_bytes
    }

    fn run(&self, output_path: &Path) {
        oci_build::build(&self.spec, output_path)
            .expect("justoci bench: build must succeed");
    }
}
