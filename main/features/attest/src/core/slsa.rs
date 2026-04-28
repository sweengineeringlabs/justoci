//! SLSA Provenance v1 statement emitter.
//!
//! Produces an in-toto Statement (`https://in-toto.io/Statement/v1`)
//! with `predicateType = "https://slsa.dev/provenance/v1"` and a
//! Provenance v1 predicate. The statement's `subject` is the OCI
//! manifest digest (under `spec.id` as the name); the predicate's
//! `buildDefinition.externalParameters` records the spec hash;
//! `resolvedDependencies` lists every layer.
//!
//! ## Reproducibility
//!
//! The serialised JSON is **byte-identical** for byte-identical
//! input. This is enforced by:
//!
//! - Using `serde_json::Map` (lex-sorted keys without
//!   `preserve_order`) for every object. Same input → same key
//!   order → same bytes.
//! - Embedding **no** timestamps. The spec-doc Reproducibility §2
//!   says: "the spec hash that pins the build is computed *before*
//!   timestamps are introduced — the spec hash is reproducible
//!   across re-runs." We honour that here by leaving timestamp
//!   fields out entirely. Build-environment time, if it ever needs
//!   to be recorded, can ride on the Rekor log entry (which is by
//!   design non-reproducible — it's a transparency-log timestamp).
//! - Using `serde_json::to_vec` (compact, no trailing whitespace)
//!   so platform-specific newline handling can't sneak in.
//!
//! The `slsa_reproducibility_test` integration test asserts
//! byte-identical output for the same input.

use cas::Cas;
use serde_json::{Map, Value};
use spec::{Layer, LayerSource, SlsaConfig, SlsaLevel};

use crate::api::attestation::SlsaStatement;
use crate::api::built_artifact::BuiltArtifact;
use crate::api::error::AttestError;

/// in-toto Statement type URI (v1).
const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";

/// SLSA Provenance v1 predicate type URI.
pub(crate) const SLSA_PROVENANCE_V1: &str = "https://slsa.dev/provenance/v1";

/// in-toto attestation media type.
pub(crate) const IN_TOTO_MEDIA_TYPE: &str = "application/vnd.in-toto+json";

/// Default builder URI when the spec did not pin one. We do NOT
/// auto-derive `<git remote>@<rev>` here — that involves shelling out
/// to git and is a build-time concern, not an attest-time concern.
/// The build crate is expected to set `slsa.builder_id` on the spec
/// before calling attest if it wants the auto-derived value. If
/// neither was set, we emit this sentinel — it's a deliberate
/// placeholder, not a silent default that pretends to be valid.
const UNKNOWN_BUILDER: &str = "urn:justoci:builder:unknown";

/// Emit a SLSA Provenance v1 statement for `built` and store it in
/// `cas`. Returns the descriptor for downstream publish.
///
/// Returns `Ok(None)` if the SLSA pillar is opted out
/// (`level = SlsaLevel::Off`).
pub fn emit_slsa(
    built: &BuiltArtifact,
    slsa_cfg: &SlsaConfig,
    cas: &dyn Cas,
) -> Result<Option<SlsaStatement>, AttestError> {
    if slsa_cfg.level == SlsaLevel::Off {
        return Ok(None);
    }

    let bytes = build_statement_bytes(built, slsa_cfg)?;
    let size = bytes.len() as u64;
    let blob_digest = cas.put(&bytes)?;

    Ok(Some(SlsaStatement {
        blob_digest,
        size,
        media_type: IN_TOTO_MEDIA_TYPE,
        predicate_type: SLSA_PROVENANCE_V1,
    }))
}

/// Build the canonical JSON bytes for the in-toto Statement. Public
/// to the crate so the reproducibility test can exercise this layer
/// without the CAS dependency.
pub(crate) fn build_statement_bytes(
    built: &BuiltArtifact,
    slsa_cfg: &SlsaConfig,
) -> Result<Vec<u8>, AttestError> {
    let statement = build_statement_value(built, slsa_cfg);
    serde_json::to_vec(&statement).map_err(|e| AttestError::SlsaEmit {
        source: Box::new(e),
    })
}

fn build_statement_value(built: &BuiltArtifact, slsa_cfg: &SlsaConfig) -> Value {
    let mut statement = Map::new();
    statement.insert(
        "_type".to_string(),
        Value::String(STATEMENT_TYPE.to_string()),
    );
    statement.insert(
        "predicateType".to_string(),
        Value::String(SLSA_PROVENANCE_V1.to_string()),
    );
    statement.insert("subject".to_string(), build_subject(built));
    statement.insert("predicate".to_string(), build_predicate(built, slsa_cfg));
    Value::Object(statement)
}

fn build_subject(built: &BuiltArtifact) -> Value {
    // in-toto subject: `[{ name, digest: { sha256: <hex> } }]`. The
    // digest map is keyed by algorithm string; the value is the raw
    // hex (no `sha256:` prefix), which is the in-toto convention.
    let mut digest_map = Map::new();
    digest_map.insert(
        built.manifest_digest.algorithm().as_str().to_string(),
        Value::String(built.manifest_digest.hex().to_string()),
    );

    let mut subject_entry = Map::new();
    subject_entry.insert(
        "name".to_string(),
        Value::String(built.spec.id.to_string_form()),
    );
    subject_entry.insert("digest".to_string(), Value::Object(digest_map));

    Value::Array(vec![Value::Object(subject_entry)])
}

fn build_predicate(built: &BuiltArtifact, slsa_cfg: &SlsaConfig) -> Value {
    let mut predicate = Map::new();
    predicate.insert(
        "buildDefinition".to_string(),
        build_build_definition(built, slsa_cfg),
    );
    predicate.insert("runDetails".to_string(), build_run_details(slsa_cfg));
    Value::Object(predicate)
}

fn build_build_definition(built: &BuiltArtifact, slsa_cfg: &SlsaConfig) -> Value {
    // SLSA Provenance v1: buildDefinition contains buildType,
    // externalParameters, internalParameters (optional), and
    // resolvedDependencies. We pin `buildType` to a justoci-namespaced
    // URI so verifiers can opt-in to justoci-specific semantics.
    let mut bd = Map::new();
    bd.insert(
        "buildType".to_string(),
        Value::String("https://justoci.dev/buildtype/spec/v1".to_string()),
    );
    bd.insert(
        "externalParameters".to_string(),
        build_external_parameters(built, slsa_cfg),
    );
    bd.insert(
        "resolvedDependencies".to_string(),
        build_resolved_dependencies(built),
    );
    Value::Object(bd)
}

fn build_external_parameters(built: &BuiltArtifact, slsa_cfg: &SlsaConfig) -> Value {
    // The spec hash pins the build. The intended SLSA level is
    // emitted as a *claim*; the spec doc says verify (not attest)
    // is responsible for validating L3+ claims against the build
    // environment. We emit it as-is here.
    let mut ep = Map::new();
    ep.insert(
        "spec_id".to_string(),
        Value::String(built.spec.id.to_string_form()),
    );
    ep.insert(
        "spec_hash".to_string(),
        Value::String(built.spec_hash.to_string()),
    );
    ep.insert(
        "spec_kind".to_string(),
        Value::String(built.spec.kind.as_str().to_string()),
    );
    ep.insert(
        "claimed_slsa_level".to_string(),
        Value::Number(slsa_cfg.level.as_int().into()),
    );
    Value::Object(ep)
}

fn build_resolved_dependencies(built: &BuiltArtifact) -> Value {
    // One ResourceDescriptor per layer: name describes the source
    // (file path or "files:N" for tar-from-files layers), digest
    // anchors it to the layer blob, mediaType records the OCI media
    // type so a verifier can sanity-check the layer kind.
    let mut deps = Vec::with_capacity(built.layer_digests.len());
    for ((idx, digest), layer) in built.layer_digests.iter().zip(built.spec.layers.iter()) {
        let mut entry = Map::new();
        entry.insert("name".to_string(), Value::String(layer_name(*idx, layer)));
        let mut digest_map = Map::new();
        digest_map.insert(
            digest.algorithm().as_str().to_string(),
            Value::String(digest.hex().to_string()),
        );
        entry.insert("digest".to_string(), Value::Object(digest_map));
        entry.insert(
            "mediaType".to_string(),
            Value::String(layer.media_type.as_str().to_string()),
        );
        deps.push(Value::Object(entry));
    }
    Value::Array(deps)
}

fn layer_name(idx: usize, layer: &Layer) -> String {
    match &layer.source {
        LayerSource::Blob { path } => format!("layer[{idx}]:{}", path.display()),
        LayerSource::Files { entries } => {
            format!("layer[{idx}]:files({})", entries.len())
        }
    }
}

fn build_run_details(slsa_cfg: &SlsaConfig) -> Value {
    let builder_id = slsa_cfg
        .builder_id
        .clone()
        .unwrap_or_else(|| UNKNOWN_BUILDER.to_string());

    // SLSA v1 `runDetails.builder` requires `id`; `version` and
    // `builderDependencies` are optional. We omit `metadata.startedOn`
    // / `finishedOn` because they're timestamps and would break
    // reproducibility (Reproducibility §2 in the spec doc). Cosign
    // signing rides on Rekor's transparency-log timestamp, which is
    // explicitly non-reproducible by design.
    let mut builder = Map::new();
    builder.insert("id".to_string(), Value::String(builder_id));

    let mut run_details = Map::new();
    run_details.insert("builder".to_string(), Value::Object(builder));
    Value::Object(run_details)
}
