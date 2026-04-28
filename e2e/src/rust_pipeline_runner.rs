use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use oci_build::build;
use oci_publish::{ImageDir, PublishSink, publish};
use p256::ecdsa::SigningKey;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use spec::parse_and_validate_str;
use swe_justsign_sign::{EcdsaP256Signer, sign_blob};
use tempfile::TempDir;

use crate::{CaseConfig, PipelineRunner};

pub struct RustPipelineRunner {
    label: String,
    payload_bytes: u64,
    payload: Vec<u8>,
    spec: spec::LoadedSpec,
    signer: EcdsaP256Signer,
    registry: String,
    counter: AtomicU64,
    _tmp: TempDir,
}

impl RustPipelineRunner {
    pub fn new(case: CaseConfig) -> Self {
        if std::env::var("OCIMAGE_ALLOW_INSECURE").as_deref() != Ok("1") {
            panic!(
                "e2e bench: OCIMAGE_ALLOW_INSECURE=1 is not set.\n\
                 Run: OCIMAGE_ALLOW_INSECURE=1 cargo bench -p swe_justoci_e2e_bench \
                 --bench pipeline"
            );
        }

        let payload_bytes = case
            .params
            .get("payload_bytes")
            .and_then(|v| v.as_integer())
            .unwrap_or_else(|| panic!("rust-pipeline case '{}': missing param 'payload_bytes'", case.label))
            as u64;

        let registry = case
            .params
            .get("registry")
            .and_then(|v| v.as_str())
            .unwrap_or("localhost:5000")
            .to_owned();

        let tmp = TempDir::new().expect("e2e bench: failed to create work dir");

        let payload: Vec<u8> = (0..payload_bytes as usize).map(|i| i as u8).collect();
        let blob_path = tmp.path().join("payload.bin");
        fs::write(&blob_path, &payload).expect("e2e bench: failed to write payload");

        let blob_str = blob_path.to_string_lossy().replace('\\', "/");
        let id_tag = case.label.replace('/', "-");
        let toml = format!(
            r#"
spec_version = "0"
id           = "e2e-artifact:{id_tag}"
kind         = "oci_artifact"
description  = "e2e bench"

[[layers]]
source     = "{blob_str}"
media_type = "application/octet-stream"
"#,
        );

        let spec = parse_and_validate_str(&toml, tmp.path().to_path_buf())
            .expect("e2e bench: spec must parse");

        // Deterministic P-256 keypair — reproducible across runs.
        let sk = SigningKey::random(&mut ChaCha20Rng::from_seed([0x45u8; 32]));
        let signer = EcdsaP256Signer::new(sk, None);

        Self {
            label: case.label,
            payload_bytes,
            payload,
            spec,
            signer,
            registry,
            counter: AtomicU64::new(0),
            _tmp: tmp,
        }
    }
}

impl PipelineRunner for RustPipelineRunner {
    fn label(&self) -> &str {
        &self.label
    }

    fn payload_bytes(&self) -> u64 {
        self.payload_bytes
    }

    fn run(&self, output_path: &Path) {
        // Step 1: build OCI layout to disk.
        build(&self.spec, output_path).expect("e2e bench: build must succeed");

        // Step 2: sign the payload blob (offline, no Rekor).
        sign_blob(&self.payload, "application/octet-stream", &self.signer, None)
            .expect("e2e bench: sign_blob must succeed");

        // Step 3: push OCI layout to registry.
        let image_dir = ImageDir::open(output_path)
            .expect("e2e bench: ImageDir::open must succeed");
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let sink = PublishSink::Registry {
            registry: self.registry.clone(),
            repository: "e2e-bench".to_owned(),
            tag: format!("bench-{n}"),
            auth: None,
        };
        publish(&image_dir, &sink).expect("e2e bench: publish must succeed");
    }
}
