//! SPDX 2.3 SBOM emitter (hand-rolled JSON).
//!
//! Same calculus as `sbom_cyclonedx`: hand-rolled JSON keeps the
//! dep-graph small and gives us byte-level control of reproducibility.
//!
//! ## Reproducibility
//!
//! - SPDX 2.3 requires `creationInfo.created` (RFC3339 timestamp)
//!   and a non-empty `creators` list. To stay reproducible we use
//!   a fixed sentinel timestamp `1970-01-01T00:00:00Z` (Unix epoch
//!   = 0). The Production Guarantees §2 contract says "no
//!   timestamps embedded in the JSON output unless they came from
//!   the spec" — we emit a fixed, spec-independent constant, which
//!   satisfies the reproducibility guarantee. Operators who need
//!   the *real* build time read it from the Rekor log entry (which
//!   carries a transparency-log timestamp by design).
//! - `documentNamespace` is derived from the manifest digest
//!   (deterministic), not from a fresh UUID.

use cas::{Cas, Digest};
use serde_json::{Map, Value};
use spec::{LayerSource, SbomScope};

use crate::api::attestation::{Sbom, SbomMediaType};
use crate::api::built_artifact::BuiltArtifact;
use crate::api::error::AttestError;

const SPDX_VERSION: &str = "SPDX-2.3";
const DATA_LICENSE: &str = "CC0-1.0";
const REPRODUCIBLE_TIMESTAMP: &str = "1970-01-01T00:00:00Z";

/// Emit an SPDX 2.3 SBOM for `built`.
pub fn emit_spdx(
    built: &BuiltArtifact,
    scope: SbomScope,
    cas: &dyn Cas,
) -> Result<Sbom, AttestError> {
    let bytes = build_doc_bytes(built, scope)?;
    let size = bytes.len() as u64;
    let blob_digest = cas.put(&bytes)?;

    Ok(Sbom {
        blob_digest,
        size,
        media_type: SbomMediaType::SpdxJson,
    })
}

pub(crate) fn build_doc_bytes(
    built: &BuiltArtifact,
    scope: SbomScope,
) -> Result<Vec<u8>, AttestError> {
    let doc = build_doc_value(built, scope);
    serde_json::to_vec(&doc).map_err(|e| AttestError::SbomEmit {
        format: "spdx",
        source: Box::new(e),
    })
}

fn build_doc_value(built: &BuiltArtifact, scope: SbomScope) -> Value {
    let mut doc = Map::new();
    doc.insert(
        "spdxVersion".to_string(),
        Value::String(SPDX_VERSION.to_string()),
    );
    doc.insert(
        "dataLicense".to_string(),
        Value::String(DATA_LICENSE.to_string()),
    );
    doc.insert(
        "SPDXID".to_string(),
        Value::String("SPDXRef-DOCUMENT".to_string()),
    );
    doc.insert(
        "name".to_string(),
        Value::String(built.spec.id.to_string_form()),
    );
    doc.insert(
        "documentNamespace".to_string(),
        Value::String(format!(
            "https://justoci.dev/spdx/{}",
            built.manifest_digest.hex()
        )),
    );
    doc.insert("creationInfo".to_string(), build_creation_info());
    doc.insert("packages".to_string(), build_packages(built));
    doc.insert("files".to_string(), build_files(built, scope));
    doc.insert(
        "relationships".to_string(),
        build_relationships(built, scope),
    );
    Value::Object(doc)
}

fn build_creation_info() -> Value {
    let mut ci = Map::new();
    ci.insert(
        "created".to_string(),
        Value::String(REPRODUCIBLE_TIMESTAMP.to_string()),
    );
    ci.insert(
        "creators".to_string(),
        Value::Array(vec![Value::String("Tool: justoci".to_string())]),
    );
    Value::Object(ci)
}

fn build_packages(built: &BuiltArtifact) -> Value {
    // SPDX requires at least one package describing the artifact
    // itself — the "root" package. Layers are emitted as files
    // (with package-level files relationships).
    let mut pkg = Map::new();
    pkg.insert(
        "SPDXID".to_string(),
        Value::String("SPDXRef-Package-Artifact".to_string()),
    );
    pkg.insert(
        "name".to_string(),
        Value::String(built.spec.id.name.clone()),
    );
    pkg.insert(
        "versionInfo".to_string(),
        Value::String(built.spec.id.tag.clone()),
    );
    pkg.insert(
        "downloadLocation".to_string(),
        Value::String("NOASSERTION".to_string()),
    );
    pkg.insert("filesAnalyzed".to_string(), Value::Bool(false));
    pkg.insert(
        "checksums".to_string(),
        build_spdx_checksums(&built.manifest_digest),
    );
    Value::Array(vec![Value::Object(pkg)])
}

fn build_files(built: &BuiltArtifact, scope: SbomScope) -> Value {
    let mut files: Vec<Value> = Vec::new();
    let want_layers = matches!(scope, SbomScope::Layers | SbomScope::Both);
    let want_sources = matches!(scope, SbomScope::Sources | SbomScope::Both);

    if want_layers {
        for ((idx, digest), layer) in built.layer_digests.iter().zip(built.spec.layers.iter()) {
            let mut f = Map::new();
            f.insert("SPDXID".to_string(), Value::String(layer_spdx_id(*idx)));
            f.insert(
                "fileName".to_string(),
                Value::String(layer_file_name(*idx, layer)),
            );
            f.insert("checksums".to_string(), build_spdx_checksums(digest));
            f.insert(
                "comment".to_string(),
                Value::String(format!(
                    "OCI layer media type: {}",
                    layer.media_type.as_str()
                )),
            );
            files.push(Value::Object(f));
        }
    }

    if want_sources {
        for (idx, layer) in built.spec.layers.iter().enumerate() {
            if let LayerSource::Files { entries } = &layer.source {
                for (file_idx, entry) in entries.iter().enumerate() {
                    let mut f = Map::new();
                    f.insert(
                        "SPDXID".to_string(),
                        Value::String(format!("SPDXRef-Source-L{idx}-F{file_idx}")),
                    );
                    f.insert("fileName".to_string(), Value::String(entry.dest.clone()));
                    f.insert(
                        "comment".to_string(),
                        Value::String(format!(
                            "source: {} mode: {:o}",
                            entry.source.display(),
                            entry.mode
                        )),
                    );
                    files.push(Value::Object(f));
                }
            }
        }
    }

    Value::Array(files)
}

fn build_relationships(built: &BuiltArtifact, scope: SbomScope) -> Value {
    let mut rels: Vec<Value> = Vec::new();

    // Document → root package.
    let mut describes = Map::new();
    describes.insert(
        "spdxElementId".to_string(),
        Value::String("SPDXRef-DOCUMENT".to_string()),
    );
    describes.insert(
        "relationshipType".to_string(),
        Value::String("DESCRIBES".to_string()),
    );
    describes.insert(
        "relatedSpdxElement".to_string(),
        Value::String("SPDXRef-Package-Artifact".to_string()),
    );
    rels.push(Value::Object(describes));

    if matches!(scope, SbomScope::Layers | SbomScope::Both) {
        for (idx, _digest) in built.layer_digests.iter() {
            let mut rel = Map::new();
            rel.insert(
                "spdxElementId".to_string(),
                Value::String("SPDXRef-Package-Artifact".to_string()),
            );
            rel.insert(
                "relationshipType".to_string(),
                Value::String("CONTAINS".to_string()),
            );
            rel.insert(
                "relatedSpdxElement".to_string(),
                Value::String(layer_spdx_id(*idx)),
            );
            rels.push(Value::Object(rel));
        }
    }

    Value::Array(rels)
}

fn build_spdx_checksums(digest: &Digest) -> Value {
    // SPDX `Checksum.algorithm` enum: `SHA256` (no dash, uppercase).
    let mut entry = Map::new();
    entry.insert("algorithm".to_string(), Value::String("SHA256".to_string()));
    entry.insert(
        "checksumValue".to_string(),
        Value::String(digest.hex().to_string()),
    );
    Value::Array(vec![Value::Object(entry)])
}

fn layer_spdx_id(idx: usize) -> String {
    format!("SPDXRef-Layer-{idx}")
}

fn layer_file_name(idx: usize, layer: &spec::Layer) -> String {
    match &layer.source {
        LayerSource::Blob { path } => format!("layer-{idx}:{}", path.display()),
        LayerSource::Files { entries } => {
            format!("layer-{idx}:files({})", entries.len())
        }
    }
}
