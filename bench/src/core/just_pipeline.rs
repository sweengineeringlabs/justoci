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

use crate::api::{CaseConfig, Runner};

pub struct JustPipeline {
    label: String,
    payload_bytes: u64,
    payload: Vec<u8>,
    spec: spec::LoadedSpec,
    signer: EcdsaP256Signer,
    registry: String,
    counter: AtomicU64,
    _tmp: TempDir,
}

impl JustPipeline {
    pub fn new(case: CaseConfig) -> Self {
        let payload_bytes = case
            .params
            .get("payload_bytes")
            .and_then(|v| v.as_integer())
            .unwrap_or_else(|| panic!("just-pipeline case '{}': missing param 'payload_bytes'", case.label))
            as u64;

        let registry = case
            .params
            .get("registry")
            .and_then(|v| v.as_str())
            .unwrap_or("localhost:5000")
            .to_owned();

        if std::env::var("OCIMAGE_ALLOW_INSECURE").as_deref() != Ok("1") {
            panic!(
                "just-pipeline bench: OCIMAGE_ALLOW_INSECURE=1 is not set.\n\
                 Run: OCIMAGE_ALLOW_INSECURE=1 cargo bench -p swe_justoci_bench --bench pipeline --features just-pipeline"
            );
        }

        let tmp = TempDir::new().expect("just-pipeline bench: failed to create work dir");
        let blob_path = tmp.path().join("payload.bin");
        let payload: Vec<u8> = (0..payload_bytes as usize).map(|i| i as u8).collect();
        fs::write(&blob_path, &payload).expect("just-pipeline bench: failed to write payload");

        let blob_str = blob_path.to_string_lossy().replace('\\', "/");
        let id_tag = case.label.replace('/', "-");
        let toml = format!(
            r#"
spec_version = "0"
id           = "e2e-artifact:{id_tag}"
kind         = "oci_artifact"
description  = "pipeline bench"

[[layers]]
source     = "{blob_str}"
media_type = "application/octet-stream"
"#,
        );

        let spec = parse_and_validate_str(&toml, tmp.path().to_path_buf())
            .expect("just-pipeline bench: spec must parse");

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

impl Runner for JustPipeline {
    fn label(&self) -> &str {
        &self.label
    }

    fn bytes(&self) -> u64 {
        self.payload_bytes
    }

    fn run(&self, output_path: &Path) {
        build(&self.spec, output_path).expect("just-pipeline bench: build must succeed");

        sign_blob(&self.payload, "application/octet-stream", &self.signer, None)
            .expect("just-pipeline bench: sign_blob must succeed");

        let image_dir = ImageDir::open(output_path).expect("just-pipeline bench: ImageDir::open must succeed");
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let sink = PublishSink::Registry {
            registry: self.registry.clone(),
            repository: "pipeline-bench".to_owned(),
            tag: format!("bench-{n}"),
            auth: None,
        };
        publish(&image_dir, &sink).expect("just-pipeline bench: publish must succeed");
    }
}
