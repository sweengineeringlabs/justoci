use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use oci_build::build;
use oci_publish::{ImageDir, PublishSink, publish};
use spec::parse_and_validate_str;
use tempfile::TempDir;

use crate::{BuildRunner, CaseConfig};

pub struct PublishRunner {
    label: String,
    payload_bytes: u64,
    image_dir: ImageDir,
    registry: String,
    /// Each iteration pushes to a unique tag so the manifest PUT always fires.
    /// Blobs are content-addressed and deduplicated by the registry after the
    /// first warmup iteration — the measured steady state is HEAD×N + PUT
    /// manifest (re-push of the same content).
    counter: AtomicU64,
    _tmp: TempDir,
}

impl PublishRunner {
    pub fn new(case: CaseConfig) -> Self {
        let payload_bytes = case
            .params
            .get("payload_bytes")
            .and_then(|v| v.as_integer())
            .unwrap_or_else(|| panic!("publish case '{}': missing param 'payload_bytes'", case.label))
            as u64;

        let registry = case
            .params
            .get("registry")
            .and_then(|v| v.as_str())
            .unwrap_or("localhost:5000")
            .to_owned();

        // Plain-HTTP opt-in required for local registry:2.  The publish crate
        // reads OCIMAGE_ALLOW_INSECURE at call time, so it must be set before
        // this process starts — we cannot set it here (set_var is unsafe in
        // Rust 1.81+ and unsafe_code = "forbid" applies to this crate).
        if std::env::var("OCIMAGE_ALLOW_INSECURE").as_deref() != Ok("1") {
            panic!(
                "publish bench: OCIMAGE_ALLOW_INSECURE=1 is not set.\n\
                 Run: OCIMAGE_ALLOW_INSECURE=1 cargo bench -p swe_justoci_bench \
                 --bench build --features publish"
            );
        }

        let tmp = TempDir::new().expect("publish bench: failed to create work dir");

        // Write source blob.
        let blob_path = tmp.path().join("payload.bin");
        let payload: Vec<u8> = (0..payload_bytes as usize).map(|i| i as u8).collect();
        fs::write(&blob_path, &payload).expect("publish bench: failed to write payload blob");

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
            .expect("publish bench: spec must parse");

        // Build the OCI layout once; re-used across all iterations.
        let layout_path = tmp.path().join("layout");
        build(&spec, &layout_path).expect("publish bench: build must succeed");

        let image_dir = ImageDir::open(&layout_path)
            .expect("publish bench: ImageDir::open must succeed");

        Self {
            label: case.label,
            payload_bytes,
            image_dir,
            registry,
            counter: AtomicU64::new(0),
            _tmp: tmp,
        }
    }
}

impl BuildRunner for PublishRunner {
    fn label(&self) -> &str {
        &self.label
    }

    fn bytes_written(&self) -> u64 {
        self.payload_bytes
    }

    // `output_path` is unused — publish pushes to the registry, not local disk.
    fn run(&self, _output_path: &Path) {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let tag = format!("bench-{n}");
        let sink = PublishSink::Registry {
            registry: self.registry.clone(),
            repository: "bench-artifact".to_owned(),
            tag,
            auth: None,
        };
        publish(&self.image_dir, &sink)
            .expect("publish bench: publish must succeed");
    }
}
