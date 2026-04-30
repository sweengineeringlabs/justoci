use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use oci_build::build;
use oci_publish::{ImageDir, PublishSink, publish};
use spec::parse_and_validate_str;
use tempfile::TempDir;

use crate::api::{CaseConfig, Runner};

pub struct JustPush {
    label: String,
    payload_bytes: u64,
    image_dir: ImageDir,
    registry: String,
    counter: AtomicU64,
    _tmp: TempDir,
}

impl JustPush {
    pub fn new(case: CaseConfig) -> Self {
        let payload_bytes = case
            .params
            .get("payload_bytes")
            .and_then(|v| v.as_integer())
            .unwrap_or_else(|| panic!("just-push case '{}': missing param 'payload_bytes'", case.label))
            as u64;

        let registry = crate::api::resolve_registry(&case);

        if std::env::var("JUSTOCI_ALLOW_INSECURE").as_deref() != Ok("1") {
            panic!(
                "just-push bench: JUSTOCI_ALLOW_INSECURE=1 is not set.\n\
                 Run: JUSTOCI_ALLOW_INSECURE=1 cargo bench -p swe_justoci_bench --bench push --features just-push"
            );
        }

        let tmp = TempDir::new().expect("just-push bench: failed to create work dir");
        let blob_path = tmp.path().join("payload.bin");
        let payload: Vec<u8> = (0..payload_bytes as usize).map(|i| i as u8).collect();
        fs::write(&blob_path, &payload).expect("just-push bench: failed to write payload blob");

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

        let spec = parse_and_validate_str(&toml, tmp.path().to_path_buf())
            .expect("just-push bench: spec must parse");

        let layout_path = tmp.path().join("layout");
        build(&spec, &layout_path).expect("just-push bench: build must succeed");

        let image_dir = ImageDir::open(&layout_path)
            .expect("just-push bench: ImageDir::open must succeed");

        Self { label: case.label, payload_bytes, image_dir, registry, counter: AtomicU64::new(0), _tmp: tmp }
    }
}

impl Runner for JustPush {
    fn label(&self) -> &str {
        &self.label
    }

    fn bytes(&self) -> u64 {
        self.payload_bytes
    }

    fn run(&self, _output_path: &Path) {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let sink = PublishSink::Registry {
            registry: self.registry.clone(),
            repository: "bench-artifact".to_owned(),
            tag: format!("bench-{n}"),
            auth: None,
        };
        publish(&self.image_dir, &sink).expect("just-push bench: publish must succeed");
    }
}
