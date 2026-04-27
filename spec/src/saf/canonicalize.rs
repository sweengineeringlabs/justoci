//! Spec canonicalisation — compute the bit-stable spec hash that
//! pins the build for SLSA provenance.
//!
//! Pipeline (per spec_v0.md Production Guarantees §3):
//!
//!   sha256(jcs(spec_as_json(spec)))
//!
//! 1. Project the typed `Spec` to a `serde_json::Value` with stable
//!    field naming and key ordering.
//! 2. Apply RFC 8785 JSON Canonicalization Scheme via `serde_jcs`.
//! 3. Hash the canonical bytes via `cas::Digest`.
//!
//! Because step 1 is deterministic (BTreeMap-backed objects, sorted
//! keys, fixed enum stringification) and steps 2-3 are spec-defined,
//! re-implementations of justoci in Go/Python compute the same hash
//! for the same input.

use std::collections::BTreeMap;

use cas::{Algorithm, CasError, Digest};
use serde_json::{json, Map, Value};

use crate::api::{
    AttestationConfig, ConfigBlob, Layer, LayerSource, Platform, SbomConfig, SignConfig,
    SlsaConfig, Spec,
};

/// Compute the spec hash of `spec`. The result is a `cas::Digest`
/// suitable for direct embedding in SLSA statements, manifest
/// referrers, and any downstream consumer that already speaks the
/// OCI digest format.
pub fn spec_hash(spec: &Spec) -> Result<Digest, CanonicalizationError> {
    let canonical = canonical_bytes(spec)?;
    Ok(Digest::from_bytes(Algorithm::Sha256, &canonical))
}

/// Return the canonical (JCS) byte sequence for `spec`, without
/// hashing. Useful for tests and for callers that want to embed
/// the canonical form (e.g. as the SLSA statement's `subject.uri`).
pub fn canonical_bytes(spec: &Spec) -> Result<Vec<u8>, CanonicalizationError> {
    let json = spec_to_json(spec);
    serde_jcs::to_vec(&json).map_err(CanonicalizationError::Jcs)
}

/// Errors raised during canonicalisation.
#[derive(Debug, thiserror::Error)]
pub enum CanonicalizationError {
    #[error("JCS serialisation failed: {0}")]
    Jcs(#[source] serde_json::Error),

    #[error("cas error during hash construction: {0}")]
    Cas(#[from] CasError),
}

// ── projection: Spec -> serde_json::Value ─────────────────────────
//
// Rules:
// - Field names match the TOML wire shape (e.g. `spec_version`, not
//   `specVersion`). This means a future Go re-implementation can
//   round-trip via the same TOML file without translation tables.
// - Optional fields are *omitted* when None, not serialised as
//   `null`. The JCS hash differs between "key absent" and "key:
//   null", so this is a substantive choice — we follow OCI's
//   convention of omitting absent fields.
// - Enums project to their canonical string form (the value users
//   write in TOML).
// - `BTreeMap` traversal already orders keys lexicographically; JCS
//   re-sorts them at the byte level, but using an ordered map at
//   the source means the JSON tree we hand to JCS is already
//   stable, and tests can predict the JSON output without invoking
//   JCS.

fn spec_to_json(spec: &Spec) -> Value {
    let mut obj = Map::new();
    obj.insert(
        "spec_version".into(),
        Value::String(spec.spec_version.as_str().into()),
    );
    obj.insert("id".into(), Value::String(spec.id.to_string_form()));
    obj.insert("kind".into(), Value::String(spec.kind.as_str().into()));

    if let Some(d) = &spec.description {
        obj.insert("description".into(), Value::String(d.clone()));
    }

    if let Some(p) = platform_to_json(&spec.platform) {
        obj.insert("platform".into(), p);
    }

    obj.insert(
        "layers".into(),
        Value::Array(spec.layers.iter().map(layer_to_json).collect()),
    );

    if let Some(c) = config_to_json(&spec.config) {
        obj.insert("config".into(), c);
    }

    if !spec.annotations.is_empty() {
        obj.insert("annotations".into(), annotations_to_json(&spec.annotations));
    }

    obj.insert("attestation".into(), attestation_to_json(&spec.attestation));

    Value::Object(obj)
}

fn platform_to_json(p: &Platform) -> Option<Value> {
    if p.os.is_none() && p.arch.is_none() {
        return None;
    }
    let mut o = Map::new();
    if let Some(os) = &p.os {
        o.insert("os".into(), Value::String(os.clone()));
    }
    if let Some(arch) = &p.arch {
        o.insert("arch".into(), Value::String(arch.clone()));
    }
    Some(Value::Object(o))
}

fn layer_to_json(l: &Layer) -> Value {
    let mut o = Map::new();
    o.insert(
        "media_type".into(),
        Value::String(l.media_type.as_str().into()),
    );
    o.insert(
        "compression".into(),
        Value::String(l.compression.as_str().into()),
    );
    match &l.source {
        LayerSource::Blob { path } => {
            // Use forward slashes regardless of host OS so the same
            // spec file produces the same hash on Windows and Linux.
            o.insert("source".into(), Value::String(normalise_path(path)));
        }
        LayerSource::Files { entries } => {
            let arr: Vec<Value> = entries
                .iter()
                .map(|f| {
                    let mut fo = Map::new();
                    fo.insert("source".into(), Value::String(normalise_path(&f.source)));
                    fo.insert("dest".into(), Value::String(f.dest.clone()));
                    fo.insert(
                        "mode".into(),
                        Value::Number(serde_json::Number::from(f.mode)),
                    );
                    Value::Object(fo)
                })
                .collect();
            o.insert("files".into(), Value::Array(arr));
        }
    }
    Value::Object(o)
}

fn config_to_json(c: &ConfigBlob) -> Option<Value> {
    // Empty object is treated as "no config block in the source TOML"
    // for canonicalisation purposes — this matches the rule that
    // optional fields are omitted, not null-serialised.
    match &c.0 {
        Value::Object(m) if m.is_empty() => None,
        v => Some(v.clone()),
    }
}

fn annotations_to_json(map: &BTreeMap<String, String>) -> Value {
    let mut o = Map::new();
    for (k, v) in map {
        o.insert(k.clone(), Value::String(v.clone()));
    }
    Value::Object(o)
}

fn attestation_to_json(a: &AttestationConfig) -> Value {
    json!({
        "slsa": slsa_to_json(&a.slsa),
        "sbom": sbom_to_json(&a.sbom),
        "sign": sign_to_json(&a.sign),
    })
}

fn slsa_to_json(s: &SlsaConfig) -> Value {
    let mut o = Map::new();
    o.insert(
        "level".into(),
        Value::Number(serde_json::Number::from(s.level.as_int())),
    );
    if let Some(b) = &s.builder_id {
        o.insert("builder_id".into(), Value::String(b.clone()));
    }
    Value::Object(o)
}

fn sbom_to_json(s: &SbomConfig) -> Value {
    json!({
        "format": s.format.as_str(),
        "scope": s.scope.as_str(),
    })
}

fn sign_to_json(s: &SignConfig) -> Value {
    let mut o = Map::new();
    o.insert("kind".into(), Value::String(s.kind.as_str().into()));
    if let Some(id) = &s.identity {
        o.insert("identity".into(), Value::String(id.clone()));
    }
    Value::Object(o)
}

fn normalise_path(p: &std::path::Path) -> String {
    // Replace OS-native separators with `/` so the spec hash is
    // platform-independent.
    p.to_string_lossy().replace('\\', "/")
}
