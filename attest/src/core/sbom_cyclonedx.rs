//! CycloneDX 1.5 SBOM emitter (hand-rolled JSON).
//!
//! The CycloneDX 1.5 schema is a public JSON specification; we
//! produce a minimal but spec-compliant document containing one
//! `component` per layer (for `Layers` scope), or one component per
//! source file (for `Sources` scope), or both (for `Both`).
//!
//! ## Why hand-rolled
//!
//! Pulling `cyclonedx-bom` would add ~200 transitive deps for what is
//! ~30 lines of JSON construction. We control the byte layout, which
//! matters for reproducibility — same input → same bytes.
//!
//! ## Reproducibility
//!
//! - No timestamps. CycloneDX 1.5 allows `metadata.timestamp` to be
//!   omitted. We omit it. (Same reasoning as SLSA — Production
//!   Guarantee §2.)
//! - No randomness. We use a stable `serialNumber` derived from the
//!   manifest digest (`urn:uuid:` form requires a UUID; we use
//!   `urn:justoci:sbom:<sha256-hex>` instead, which is a valid
//!   `urn:` URI and equally identifies the SBOM uniquely while
//!   staying reproducible).
//! - Components are emitted in layer-declaration order;
//!   `serde_json::Map` sorts object keys.

use cas::{Cas, Digest};
use serde_json::{Map, Value};
use spec::{Layer, LayerSource, SbomScope};

use crate::api::attestation::{Sbom, SbomMediaType};
use crate::api::built_artifact::BuiltArtifact;
use crate::api::error::AttestError;

const CYCLONEDX_VERSION: &str = "1.5";
const BOM_FORMAT: &str = "CycloneDX";

/// Emit a CycloneDX 1.5 SBOM for `built` and store the JSON in `cas`.
pub fn emit_cyclonedx(
    built: &BuiltArtifact,
    scope: SbomScope,
    cas: &dyn Cas,
) -> Result<Sbom, AttestError> {
    let bytes = build_bom_bytes(built, scope)?;
    let size = bytes.len() as u64;
    let blob_digest = cas.put(&bytes)?;

    Ok(Sbom {
        blob_digest,
        size,
        media_type: SbomMediaType::CycloneDxJson,
    })
}

pub(crate) fn build_bom_bytes(
    built: &BuiltArtifact,
    scope: SbomScope,
) -> Result<Vec<u8>, AttestError> {
    let bom = build_bom_value(built, scope);
    serde_json::to_vec(&bom).map_err(|e| AttestError::SbomEmit {
        format: "cyclonedx",
        source: Box::new(e),
    })
}

fn build_bom_value(built: &BuiltArtifact, scope: SbomScope) -> Value {
    let mut bom = Map::new();
    bom.insert(
        "bomFormat".to_string(),
        Value::String(BOM_FORMAT.to_string()),
    );
    bom.insert(
        "specVersion".to_string(),
        Value::String(CYCLONEDX_VERSION.to_string()),
    );
    bom.insert("version".to_string(), Value::Number(1.into()));
    bom.insert(
        "serialNumber".to_string(),
        Value::String(stable_serial_number(&built.manifest_digest)),
    );
    bom.insert("metadata".to_string(), build_metadata(built));
    bom.insert("components".to_string(), build_components(built, scope));
    Value::Object(bom)
}

fn stable_serial_number(manifest: &Digest) -> String {
    // Non-UUID URN form chosen deliberately for reproducibility.
    // CycloneDX schema validates `serialNumber` as a URN; both
    // `urn:uuid:` and other `urn:<nid>:` namespaces are conformant.
    format!("urn:justoci:sbom:{}", manifest.hex())
}

fn build_metadata(built: &BuiltArtifact) -> Value {
    // `metadata.component` is the artifact this SBOM describes.
    let mut component = Map::new();
    component.insert(
        "type".to_string(),
        Value::String("container".to_string()),
    );
    component.insert(
        "bom-ref".to_string(),
        Value::String(built.manifest_digest.to_string()),
    );
    component.insert(
        "name".to_string(),
        Value::String(built.spec.id.name.clone()),
    );
    component.insert(
        "version".to_string(),
        Value::String(built.spec.id.tag.clone()),
    );
    component.insert("hashes".to_string(), build_hashes(&built.manifest_digest));

    let mut metadata = Map::new();
    metadata.insert("component".to_string(), Value::Object(component));
    Value::Object(metadata)
}

fn build_components(built: &BuiltArtifact, scope: SbomScope) -> Value {
    let mut components: Vec<Value> = Vec::new();
    let want_layers = matches!(scope, SbomScope::Layers | SbomScope::Both);
    let want_sources = matches!(scope, SbomScope::Sources | SbomScope::Both);

    if want_layers {
        for ((idx, digest), layer) in built.layer_digests.iter().zip(built.spec.layers.iter()) {
            components.push(build_layer_component(*idx, digest, layer));
        }
    }

    if want_sources {
        for (idx, layer) in built.spec.layers.iter().enumerate() {
            if let LayerSource::Files { entries } = &layer.source {
                for (file_idx, entry) in entries.iter().enumerate() {
                    components.push(build_source_component(idx, file_idx, entry));
                }
            }
        }
    }

    Value::Array(components)
}

fn build_layer_component(idx: usize, digest: &Digest, layer: &Layer) -> Value {
    let mut comp = Map::new();
    comp.insert(
        "type".to_string(),
        Value::String("file".to_string()),
    );
    comp.insert(
        "bom-ref".to_string(),
        Value::String(format!("layer-{idx}-{}", digest.hex())),
    );
    comp.insert(
        "name".to_string(),
        Value::String(layer_display_name(idx, layer)),
    );
    comp.insert(
        "mime-type".to_string(),
        Value::String(layer.media_type.as_str().to_string()),
    );
    comp.insert("hashes".to_string(), build_hashes(digest));
    Value::Object(comp)
}

fn build_source_component(layer_idx: usize, file_idx: usize, entry: &spec::LayerFile) -> Value {
    let mut comp = Map::new();
    comp.insert(
        "type".to_string(),
        Value::String("file".to_string()),
    );
    comp.insert(
        "bom-ref".to_string(),
        Value::String(format!(
            "source-l{layer_idx}-f{file_idx}-{}",
            entry.dest
        )),
    );
    comp.insert(
        "name".to_string(),
        Value::String(entry.dest.clone()),
    );
    let mut props = Vec::new();
    let mut src_prop = Map::new();
    src_prop.insert(
        "name".to_string(),
        Value::String("justoci:source-path".to_string()),
    );
    src_prop.insert(
        "value".to_string(),
        Value::String(entry.source.display().to_string()),
    );
    props.push(Value::Object(src_prop));
    let mut mode_prop = Map::new();
    mode_prop.insert(
        "name".to_string(),
        Value::String("justoci:mode-octal".to_string()),
    );
    mode_prop.insert(
        "value".to_string(),
        Value::String(format!("{:o}", entry.mode)),
    );
    props.push(Value::Object(mode_prop));
    comp.insert("properties".to_string(), Value::Array(props));
    Value::Object(comp)
}

fn layer_display_name(idx: usize, layer: &Layer) -> String {
    match &layer.source {
        LayerSource::Blob { path } => format!("layer-{idx}:{}", path.display()),
        LayerSource::Files { entries } => {
            format!("layer-{idx}:files({})", entries.len())
        }
    }
}

fn build_hashes(digest: &Digest) -> Value {
    // CycloneDX's hash schema: `[{ alg: "SHA-256", content: "<hex>" }]`.
    // The `alg` enum is uppercase + dash-separated.
    let mut entry = Map::new();
    entry.insert("alg".to_string(), Value::String("SHA-256".to_string()));
    entry.insert(
        "content".to_string(),
        Value::String(digest.hex().to_string()),
    );
    Value::Array(vec![Value::Object(entry)])
}
