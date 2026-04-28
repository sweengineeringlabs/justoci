use std::path::Path;

use p256::ecdsa::SigningKey;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use swe_justsign_sign::{EcdsaP256Signer, sign_blob};

use crate::api::{CaseConfig, Runner};

pub struct JustSign {
    label: String,
    payload: Vec<u8>,
    signer: EcdsaP256Signer,
}

impl JustSign {
    pub fn new(case: CaseConfig) -> Self {
        let payload_bytes = case
            .params
            .get("payload_bytes")
            .and_then(|v| v.as_integer())
            .unwrap_or_else(|| panic!("just-sign case '{}': missing param 'payload_bytes'", case.label))
            as usize;

        let payload: Vec<u8> = (0..payload_bytes).map(|i| i as u8).collect();
        let sk = SigningKey::random(&mut ChaCha20Rng::from_seed([0x45u8; 32]));
        let signer = EcdsaP256Signer::new(sk, None);

        Self { label: case.label, payload, signer }
    }
}

impl Runner for JustSign {
    fn label(&self) -> &str {
        &self.label
    }

    fn bytes(&self) -> u64 {
        self.payload.len() as u64
    }

    fn run(&self, _output_path: &Path) {
        sign_blob(&self.payload, "application/octet-stream", &self.signer, None)
            .expect("just-sign bench: sign_blob must succeed");
    }
}
