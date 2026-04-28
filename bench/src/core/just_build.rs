use std::fs;
use std::path::Path;

use spec::{LoadedSpec, parse_and_validate_str};
use tempfile::TempDir;

use crate::api::{CaseConfig, Runner};

pub struct JustBuild {
    label: String,
    payload_bytes: u64,
    spec: LoadedSpec,
    _work: TempDir,
}

impl JustBuild {
    pub fn new(case: CaseConfig) -> Self {
        let payload_bytes = case
            .params
            .get("payload_bytes")
            .and_then(|v| v.as_integer())
            .unwrap_or_else(|| panic!("just-build case '{}': missing param 'payload_bytes'", case.label))
            as u64;

        let work = TempDir::new().expect("just-build bench: failed to create work dir");
        let blob_path = work.path().join("payload.bin");
        let payload: Vec<u8> = (0..payload_bytes as usize).map(|i| i as u8).collect();
        fs::write(&blob_path, &payload).expect("just-build bench: failed to write payload blob");

        let blob_str = blob_path.to_string_lossy().replace('\\', "/");
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
            .expect("just-build bench: spec must parse");

        Self { label: case.label, payload_bytes, spec, _work: work }
    }
}

impl Runner for JustBuild {
    fn label(&self) -> &str {
        &self.label
    }

    fn bytes(&self) -> u64 {
        self.payload_bytes
    }

    fn run(&self, output_path: &Path) {
        oci_build::build(&self.spec, output_path)
            .expect("just-build bench: build must succeed");
    }
}
