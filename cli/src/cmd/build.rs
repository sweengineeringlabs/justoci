//! `ocimage build <spec.toml> [-o <dir>] [--no-attest]`.
//!
//! Pipeline:
//!
//! 1. `spec::parse_and_validate(spec)` → `LoadedSpec`.
//! 2. `spec::spec_hash(&spec)` → canonical hash for SLSA pinning.
//! 3. `oci_build::build(&loaded, &output_dir)` → `BuildOutput`.
//! 4. Unless `--no-attest`: open an `FsCas` rooted at `output_dir`,
//!    construct a `BuiltArtifact`, run `attest::attest()`, then wire
//!    the resulting `AttestationOutputs` into `index.json` as OCI 1.1
//!    referrer manifests.
//!
//! ## Atomicity
//!
//! `oci_build::build` emits to `<output_dir>.partial` and renames on
//! success, so `<output_dir>` only appears when the build itself
//! succeeded. If attest then fails, `<output_dir>` survives (build
//! was successful — its atomicity contract is preserved) but
//! `index.json` may have been partially updated; we use a temp-file
//! + rename for the index update so the index is either
//! pre-attestation or fully-post-attestation, never half-written.
//!
//! ## Error-class mapping
//!
//! - `SpecError`     → `CliError::Spec`     → exit 1
//! - `BuildError`    → `CliError::Build`    → exit 2
//! - `AttestError`   → `CliError::Attest`   → exit 3
//! - referrer/index io → `CliError::CliIo`  → exit 64

use std::path::{Path, PathBuf};

use cas::FsCas;
use spec::{parse_and_validate, spec_hash};

use crate::error::CliError;
use crate::referrers::write_referrers_into_image_dir;

/// Result of a successful build, surfaced for the CLI to print.
pub struct BuildSummary {
    pub manifest_digest: String,
    pub spec_hash: String,
    pub output_dir: PathBuf,
    pub attestation_summary: Option<AttestationSummary>,
}

/// What attestation produced, if it ran.
pub struct AttestationSummary {
    pub slsa_digest: Option<String>,
    pub sbom_digest: Option<String>,
    pub signature_digest: Option<String>,
}

/// Run the build subcommand. `quiet` is propagated for callers that
/// want to suppress secondary stdout — but stdout itself stays
/// machine-parseable; the quiet flag only governs human-eyes
/// preamble lines.
pub fn run(
    spec_path: &Path,
    output_dir: &Path,
    no_attest: bool,
) -> Result<BuildSummary, CliError> {
    tracing::debug!(
        spec = %spec_path.display(),
        output = %output_dir.display(),
        no_attest,
        "ocimage build start"
    );

    let loaded = parse_and_validate(spec_path)?;
    let canonical_hash = spec_hash(&loaded.spec)?;

    let build_output = oci_build::build(&loaded, output_dir)?;

    let attestation_summary = if no_attest {
        None
    } else {
        // Open an FsCas rooted at the *final* image dir (same place
        // the build crate's CAS pointed at). The build crate's CAS
        // is dropped at this point — but FsCas is purely path-based,
        // we just open a fresh handle.
        let cas = FsCas::new(output_dir).map_err(|e| CliError::Cli {
            detail: format!("could not open FsCas at {}: {e}", output_dir.display()),
        })?;

        // Build the BuiltArtifact contract attest expects.
        // layer_digests was returned in spec-order by the build crate;
        // we attach the spec-position to each.
        let positioned: Vec<(usize, cas::Digest)> = build_output
            .layer_digests
            .iter()
            .enumerate()
            .map(|(i, d)| (i, d.clone()))
            .collect();

        let built = attest::BuiltArtifact::new(
            build_output.manifest_digest.clone(),
            build_output.config_digest.clone(),
            positioned,
            loaded.spec.clone(),
            canonical_hash.clone(),
        )
        .map_err(|e| CliError::Cli {
            detail: format!("internal: BuiltArtifact construction rejected build output: {e}"),
        })?;

        let outputs = attest::attest(&built, &loaded.spec.attestation, &cas)?;

        // Wire the attestation outputs into the OCI image dir's
        // index.json as OCI 1.1 referrer manifests. The blobs
        // themselves are already in CAS thanks to attest; this
        // step just adds the referrer manifest blobs and updates
        // the index. We need the primary manifest's *size*; the
        // primary manifest blob lives at <image_dir>/blobs/sha256/<hex>.
        let primary_size = read_blob_size(output_dir, &build_output.manifest_digest.to_string())?;
        write_referrers_into_image_dir(
            output_dir,
            &outputs,
            &build_output.manifest_digest.to_string(),
            primary_size,
        )?;

        Some(AttestationSummary {
            slsa_digest: outputs.slsa.as_ref().map(|s| s.blob_digest.to_string()),
            sbom_digest: outputs.sbom.as_ref().map(|s| s.blob_digest.to_string()),
            signature_digest: outputs.signature.as_ref().map(|s| s.bundle_digest.to_string()),
        })
    };

    Ok(BuildSummary {
        manifest_digest: build_output.manifest_digest.to_string(),
        spec_hash: canonical_hash.to_string(),
        output_dir: build_output.output_dir,
        attestation_summary,
    })
}

fn read_blob_size(image_dir: &Path, digest: &str) -> Result<u64, CliError> {
    let (algo, hex) = digest.split_once(':').ok_or_else(|| CliError::Cli {
        detail: format!("malformed digest {digest}: missing ':' separator"),
    })?;
    let path = image_dir.join("blobs").join(algo).join(hex);
    let meta = std::fs::metadata(&path).map_err(|source| CliError::CliIo {
        path: path.display().to_string(),
        source,
    })?;
    Ok(meta.len())
}
