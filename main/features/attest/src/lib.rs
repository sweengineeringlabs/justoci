//! justoci attestation pipeline.
//!
//! Three independent emitters consume a `BuiltArtifact` (the output
//! of the build crate) and produce three referrer artifacts that
//! sit alongside the main artifact in the OCI registry:
//!
//! 1. **SLSA statement** — in-toto `Statement` with predicateType
//!    `https://slsa.dev/provenance/v1`.
//! 2. **SBOM** — CycloneDX 1.5 or SPDX 2.3 listing the artifact's
//!    components.
//! 3. **Signature** — Sigstore (cosign-compatible) signature over
//!    the manifest digest with Rekor coupling (no half-states:
//!    sign-success without a Rekor record is reported as
//!    `SignNotRecorded`, not as success). The production path
//!    links the [`sigstore`](https://crates.io/crates/sigstore) SDK
//!    directly (feature `sigstore-rs`, default-on); a legacy cosign
//!    subprocess invoker is available behind feature
//!    `cosign-subprocess` for environments where the SDK dep tree
//!    is unwelcome. See `docs/3-design/cosign_rekor.md`.
//!
//! Defaults (no `[attestation]` block in the spec) → SLSA L2 +
//! CycloneDX layers + cosign-keyless. Each pillar is independently
//! opt-out via the spec's `level=0` / `format="off"` / `kind="off"`.
//!
//! Each pillar's output blob is written to a `Cas`; downstream
//! (publish) reads them out by digest and registers them as OCI 1.1
//! referrers of the manifest.
//!
//! ```ignore
//! use attest::{attest, BuiltArtifact};
//! use cas::FsCas;
//!
//! let cas = FsCas::new("./out")?;
//! let outputs = attest(&built, &spec.attestation, &cas)?;
//! // outputs.slsa, outputs.sbom, outputs.signature each carry the
//! // CAS digest of the referrer blob (or `None` if opted out).
//! ```

pub mod api;
pub mod core;
pub mod saf;

pub use api::attestation::{AttestationOutputs, Sbom, SbomMediaType, Signature, SlsaStatement};
pub use api::built_artifact::BuiltArtifact;
pub use api::error::AttestError;
pub use saf::attest::attest;
