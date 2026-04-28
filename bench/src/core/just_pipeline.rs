use std::fmt::Write as _;
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use oci_publish::push_artifact_streaming;
use p256::ecdsa::SigningKey;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha2::{Digest as _, Sha256};
use swe_justsign_sign::{EcdsaP256Signer, sign_blob_message_prehashed};
use tempfile::TempDir;

use crate::api::{CaseConfig, Runner};

pub struct JustPipeline {
    label: String,
    payload_bytes: u64,
    blob_path: PathBuf,
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
            .unwrap_or_else(|| {
                panic!("just-pipeline case '{}': missing param 'payload_bytes'", case.label)
            }) as u64;

        let registry = crate::api::resolve_registry(&case);

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
        drop(payload);

        let sk = SigningKey::random(&mut ChaCha20Rng::from_seed([0x45u8; 32]));
        let signer = EcdsaP256Signer::new(sk, None);

        Self {
            label: case.label,
            payload_bytes,
            blob_path,
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

    fn run(&self, _output_path: &Path) {
        // Single hash pass — the same digest drives both the signer and the
        // registry PUT URL, avoiding the double-SHA-256 from the old
        // build() + publish() path.
        let digest_bytes = hash_file(&self.blob_path);

        sign_blob_message_prehashed(digest_bytes, &self.signer, None)
            .expect("just-pipeline bench: sign must succeed");

        let layer_hex = bytes_to_hex(&digest_bytes);
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        push_artifact_streaming(
            &self.blob_path,
            &layer_hex,
            self.payload_bytes,
            "application/octet-stream",
            &self.registry,
            "pipeline-bench",
            &format!("bench-{n}"),
            None,
        )
        .expect("just-pipeline bench: push must succeed");
    }
}

fn hash_file(path: &Path) -> [u8; 32] {
    let mut f = fs::File::open(path).expect("just-pipeline: source file must be readable");
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf).expect("just-pipeline: source file read error");
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    hasher.finalize().into()
}

fn bytes_to_hex(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        write!(s, "{b:02x}").unwrap();
    }
    s
}
