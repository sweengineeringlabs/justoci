//! Signature type — opaque to this crate, verified by consumers.
//!
//! Signatures are whatever the SPI backend produces. Cosign emits
//! DSSE (Dead Simple Signing Envelope) blobs; offline signing
//! produces raw ed25519 / ecdsa bytes. We keep the wire format
//! opaque and store the identity metadata the verifier needs.

use serde::{Deserialize, Serialize};

/// How a signature was produced — the verifier uses this to pick
/// a verification strategy.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SignatureFormat {
    /// DSSE envelope produced by cosign (keyless or keyed).
    /// The blob is opaque to us; cosign verifies it.
    CosignDsse,

    /// A raw signature from a known keypair. Verifier matches
    /// against a trust anchor configured out-of-band.
    RawEd25519,

    /// Placeholder — no real signing happened. Only the
    /// `NoopAttester` produces this, and consumers must reject
    /// unless an explicit dev mode is set.
    Unsigned,
}

/// One signature over a Statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    /// Wire format. Guides the verifier's parse strategy.
    pub format: SignatureFormat,

    /// The signing identity as the backend reported it:
    /// - cosign keyless: the OIDC subject (e.g. a GitHub workflow URI)
    /// - cosign keyed: the public-key fingerprint
    /// - raw: the public-key fingerprint
    /// - unsigned: "noop"
    pub identity: String,

    /// Opaque signature bytes. Base64 for DSSE envelopes, raw bytes
    /// for ed25519, empty for unsigned. Verifier is responsible for
    /// parsing based on `format`.
    pub bytes: Vec<u8>,
}

impl Signature {
    /// Construct the sentinel unsigned signature. Produced by
    /// `NoopAttester` for tests; never valid for real consumers.
    pub fn unsigned() -> Self {
        Self {
            format: SignatureFormat::Unsigned,
            identity: "noop".into(),
            bytes: Vec::new(),
        }
    }

    /// `true` if the signature is the unsigned sentinel. Consumers
    /// that reject unsigned attestations check this.
    pub fn is_unsigned(&self) -> bool {
        self.format == SignatureFormat::Unsigned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unsigned_sentinel_is_detectable() {
        let s = Signature::unsigned();
        assert!(s.is_unsigned());
        assert!(s.bytes.is_empty());
        assert_eq!(s.identity, "noop");
    }

    #[test]
    fn test_real_signature_is_not_unsigned() {
        let s = Signature {
            format: SignatureFormat::CosignDsse,
            identity: "https://github.com/org/repo/.github/workflows/ci.yml".into(),
            bytes: vec![1, 2, 3, 4],
        };
        assert!(!s.is_unsigned());
    }
}
