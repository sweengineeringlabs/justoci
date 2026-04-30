//! Validation rules — convert a `RawSpec` (deserialised TOML) into
//! a typed `Spec`, raising `SpecError` for every guarantee in the
//! spec doc's "Validation at spec load" section.
//!
//! Validation is *eager* and *complete*: by the time this returns
//! `Ok(Spec)`, every rule has been checked, every source file
//! existence-tested, every media type parsed. There is no path that
//! produces a `Spec` and later raises a validation error during
//! build.

use std::collections::BTreeMap;
use std::path::Path;

use crate::api::{
    ArtifactId, AttestationConfig, Compression, ConfigBlob, Kind, Layer, LayerFile, LayerSource,
    MediaType, Platform, SbomConfig, SbomFormat, SbomScope, SignConfig, SignKind, SlsaConfig,
    SlsaLevel, Spec, SpecError, SpecVersion,
};

use super::raw::{RawAttestation, RawLayer, RawLayerFile, RawSbom, RawSign, RawSlsa, RawSpec};

const SUPPORTED_VERSIONS: &[&str] = &["0"];

/// Validate a `RawSpec` against an absolute `spec_dir` (the directory
/// containing the spec file, used to resolve layer source paths).
///
/// `spec_dir` is required because `[[layers]] source = "..."` paths
/// are spec-relative — the caller (saf::parse) passes the spec file's
/// parent directory, not the process cwd, so the same spec file
/// validates the same way regardless of where `justoci` is invoked.
pub(crate) fn validate(raw: RawSpec, spec_dir: &Path) -> Result<Spec, SpecError> {
    // ── spec_version ──────────────────────────────────────────────
    let spec_version = match raw.spec_version.as_str() {
        "0" => SpecVersion::V0,
        _ => {
            return Err(SpecError::UnsupportedSpecVersion {
                got: raw.spec_version,
                supported: SUPPORTED_VERSIONS,
            })
        }
    };

    // ── id ────────────────────────────────────────────────────────
    let id = parse_id(&raw.id)?;

    // ── kind ──────────────────────────────────────────────────────
    let kind = Kind::parse(&raw.kind).ok_or(SpecError::UnknownKind { got: raw.kind })?;

    // ── platform ──────────────────────────────────────────────────
    let platform = match raw.platform {
        Some(p) => Platform {
            os: p.os,
            arch: p.arch,
        },
        None => Platform::default(),
    };

    // ── layers — count + per-layer rules + ordering ──────────────
    check_layer_count(kind, raw.layers.len())?;
    let layers = raw
        .layers
        .into_iter()
        .enumerate()
        .map(|(pos, l)| validate_layer(pos, l, spec_dir))
        .collect::<Result<Vec<_>, _>>()?;
    check_layer_order(kind, &layers)?;

    // ── config ────────────────────────────────────────────────────
    let config = match raw.config {
        Some(value) => ConfigBlob(toml_to_json(value)),
        None => ConfigBlob::default(),
    };

    // ── annotations ───────────────────────────────────────────────
    let annotations = raw.annotations.unwrap_or_default();
    validate_reserved_annotations(&annotations)?;

    // ── attestation ───────────────────────────────────────────────
    let attestation = match raw.attestation {
        Some(a) => validate_attestation(a)?,
        None => AttestationConfig::default(),
    };

    Ok(Spec {
        spec_version,
        id,
        kind,
        description: raw.description,
        platform,
        layers,
        config,
        annotations,
        attestation,
    })
}

// ── id parsing ────────────────────────────────────────────────────

fn parse_id(s: &str) -> Result<ArtifactId, SpecError> {
    let (name, tag) = s.split_once(':').ok_or(SpecError::MalformedId {
        got: s.to_string(),
        reason: "missing ':' between name and tag",
    })?;

    if name.is_empty() {
        return Err(SpecError::MalformedId {
            got: s.to_string(),
            reason: "name cannot be empty",
        });
    }
    if tag.is_empty() {
        return Err(SpecError::MalformedId {
            got: s.to_string(),
            reason: "tag cannot be empty",
        });
    }

    // name: lowercase only, must start with [a-z0-9].
    let mut name_chars = name.chars();
    let first = name_chars.next().expect("non-empty checked above");
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return Err(SpecError::MalformedId {
            got: s.to_string(),
            reason: "name must start with [a-z0-9]",
        });
    }
    for c in name_chars {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-')) {
            return Err(SpecError::MalformedId {
                got: s.to_string(),
                reason: "name body must match [a-z0-9._-]",
            });
        }
    }

    // tag: case-insensitive [a-zA-Z0-9._-].
    for c in tag.chars() {
        if !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')) {
            return Err(SpecError::MalformedId {
                got: s.to_string(),
                reason: "tag must match [a-zA-Z0-9._-]",
            });
        }
    }

    Ok(ArtifactId {
        name: name.to_string(),
        tag: tag.to_string(),
    })
}

// ── layer rules ───────────────────────────────────────────────────

fn check_layer_count(kind: Kind, actual: usize) -> Result<(), SpecError> {
    let (allowed, expected_str): (bool, &'static str) = match kind {
        Kind::OciArtifact => (actual >= 1, "≥1"),
        Kind::VmImage => (actual == 3, "exactly 3"),
        Kind::RawImage => (actual == 1, "exactly 1"),
    };
    if !allowed {
        return Err(SpecError::WrongLayerCount {
            kind: kind.as_str(),
            expected: expected_str,
            actual,
        });
    }
    Ok(())
}

fn validate_layer(position: usize, raw: RawLayer, spec_dir: &Path) -> Result<Layer, SpecError> {
    // Source mode: exactly one of `source` or `files`.
    let source = match (raw.source, raw.files) {
        (Some(_), Some(_)) => {
            return Err(SpecError::LayerSourceConflict {
                position,
                detail: "both `source = \"...\"` and `[[layers.files]]` set",
            })
        }
        (None, None) => {
            return Err(SpecError::LayerSourceConflict {
                position,
                detail: "neither `source = \"...\"` nor `[[layers.files]]` set",
            })
        }
        (Some(path), None) => {
            // Resolve relative to spec_dir, then check readability.
            let resolved = if path.is_absolute() {
                path.clone()
            } else {
                spec_dir.join(&path)
            };
            match std::fs::metadata(&resolved) {
                Ok(m) if m.is_file() => {}
                Ok(_) => {
                    return Err(SpecError::UnreadableSource {
                        position,
                        path: path.display().to_string(),
                        detail: "path exists but is not a regular file".into(),
                    })
                }
                Err(e) => {
                    return Err(SpecError::UnreadableSource {
                        position,
                        path: path.display().to_string(),
                        detail: e.to_string(),
                    })
                }
            }
            LayerSource::Blob { path }
        }
        (None, Some(files)) => {
            if files.is_empty() {
                return Err(SpecError::EmptyFilesBlock { position });
            }
            // Resolve + check each file's source.
            for f in &files {
                let resolved = if f.source.is_absolute() {
                    f.source.clone()
                } else {
                    spec_dir.join(&f.source)
                };
                if !resolved.exists() {
                    return Err(SpecError::UnreadableSource {
                        position,
                        path: f.source.display().to_string(),
                        detail: "file or directory does not exist".into(),
                    });
                }
            }
            LayerSource::Files {
                entries: files
                    .into_iter()
                    .map(|RawLayerFile { source, dest, mode }| LayerFile { source, dest, mode })
                    .collect(),
            }
        }
    };

    // media_type: parse + validate via the public MediaType::parse.
    // Wrap the type's own error into the layer-aware SpecError variant
    // so callers see "layer #N media_type ..." with full context.
    let media_type =
        MediaType::parse(&raw.media_type).map_err(|_| SpecError::MalformedMediaType {
            position,
            got: raw.media_type.clone(),
        })?;

    // compression: explicit value, or default keyed off media_type
    // suffix.
    let compression = match raw.compression.as_deref() {
        Some("none") => Compression::None,
        Some("gzip") => Compression::Gzip,
        Some("zstd") => Compression::Zstd,
        Some(other) => {
            return Err(SpecError::UnknownCompression {
                position,
                got: other.to_string(),
            })
        }
        None => default_compression(&raw.media_type),
    };

    Ok(Layer {
        source,
        media_type,
        compression,
    })
}

fn default_compression(media_type: &str) -> Compression {
    if media_type.ends_with("+gzip") {
        Compression::Gzip
    } else if media_type.ends_with("+zstd") {
        Compression::Zstd
    } else {
        Compression::None
    }
}

fn check_layer_order(kind: Kind, layers: &[Layer]) -> Result<(), SpecError> {
    if !matches!(kind, Kind::VmImage) {
        return Ok(());
    }
    // Per the spec doc: layer 0 contains "kernel", layer 1 contains
    // "initrd", layer 2 contains "rootfs". Substring check on the
    // media_type — strict enough to catch "did you reorder them"
    // without dictating exact MIME strings.
    const VM_MARKERS: [(usize, &str); 3] = [(0, "kernel"), (1, "initrd"), (2, "rootfs")];
    for (pos, marker) in VM_MARKERS {
        let mt = layers[pos].media_type.as_str();
        if !mt.contains(marker) {
            return Err(SpecError::WrongLayerOrder {
                position: pos,
                expected_marker: marker,
                got_media_type: mt.to_string(),
            });
        }
    }
    Ok(())
}

// ── annotations ───────────────────────────────────────────────────

fn validate_reserved_annotations(annotations: &BTreeMap<String, String>) -> Result<(), SpecError> {
    // The OCI image-spec defines a small set of annotation keys with
    // semantic value rules. v0 enforces a deliberate subset — any
    // future additions must come with a test that fails first.
    if let Some(created) = annotations.get("org.opencontainers.image.created") {
        // RFC3339 sniff: must contain a T and a Z or offset. Cheap;
        // a real RFC3339 parser would catch more, but the goal is to
        // reject obvious garbage like "yesterday", not to be a
        // datetime library.
        let looks_rfc3339 = created.contains('T')
            && (created.ends_with('Z')
                || created.contains('+')
                || created.matches('-').count() >= 3);
        if !looks_rfc3339 {
            return Err(SpecError::InvalidReservedAnnotation {
                key: "org.opencontainers.image.created".to_string(),
                detail: "must be RFC3339 (e.g. '2026-04-26T12:00:00Z')".to_string(),
            });
        }
    }
    if let Some(version) = annotations.get("org.opencontainers.image.version") {
        if version.trim().is_empty() {
            return Err(SpecError::InvalidReservedAnnotation {
                key: "org.opencontainers.image.version".to_string(),
                detail: "must be non-empty".to_string(),
            });
        }
    }
    Ok(())
}

// ── attestation ───────────────────────────────────────────────────

fn validate_attestation(raw: RawAttestation) -> Result<AttestationConfig, SpecError> {
    let slsa = match raw.slsa {
        Some(RawSlsa { level, builder_id }) => {
            let level = match level {
                Some(n) => {
                    SlsaLevel::from_int(n).ok_or(SpecError::SlsaLevelOutOfRange { got: n })?
                }
                None => SlsaConfig::default().level,
            };
            SlsaConfig { level, builder_id }
        }
        None => SlsaConfig::default(),
    };

    let sbom = match raw.sbom {
        Some(RawSbom { format, scope }) => {
            let format = match format {
                Some(s) => SbomFormat::parse(&s).ok_or(SpecError::UnknownSbomFormat { got: s })?,
                None => SbomConfig::default().format,
            };
            let scope = match scope {
                Some(s) => SbomScope::parse(&s).ok_or(SpecError::UnknownSbomScope { got: s })?,
                None => SbomConfig::default().scope,
            };
            SbomConfig { format, scope }
        }
        None => SbomConfig::default(),
    };

    let sign = match raw.sign {
        Some(RawSign { kind, identity }) => {
            let kind = match kind {
                Some(s) => SignKind::parse(&s).ok_or(SpecError::UnknownSignKind { got: s })?,
                None => SignConfig::default().kind,
            };
            // cosign-key requires an identity (the key path).
            if matches!(kind, SignKind::CosignKey) && identity.is_none() {
                return Err(SpecError::MissingSigningKeyPath);
            }
            SignConfig { kind, identity }
        }
        None => SignConfig::default(),
    };

    Ok(AttestationConfig { slsa, sbom, sign })
}

// ── toml::Value -> serde_json::Value ──────────────────────────────

/// Convert a `toml::Value` (used for the `[config]` block) to a
/// `serde_json::Value`. The OCI image config is JSON on the wire,
/// and we need a JSON value either way for canonicalisation.
///
/// Mappings:
/// - String / Boolean → identity.
/// - Integer / Float → JSON number.
/// - Array → JSON array (recursive).
/// - Table → JSON object with sorted keys (BTreeMap iteration).
/// - Datetime → ISO8601 string (TOML datetimes are typed; the OCI
///   config blob isn't, so they project to their RFC3339-style
///   string form).
fn toml_to_json(v: toml::Value) -> serde_json::Value {
    match v {
        toml::Value::String(s) => serde_json::Value::String(s),
        toml::Value::Integer(i) => serde_json::Value::Number(i.into()),
        toml::Value::Float(f) => serde_json::Number::from_f64(f)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        toml::Value::Boolean(b) => serde_json::Value::Bool(b),
        toml::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(toml_to_json).collect())
        }
        toml::Value::Table(t) => {
            let mut sorted = BTreeMap::new();
            for (k, v) in t {
                sorted.insert(k, toml_to_json(v));
            }
            let map: serde_json::Map<String, serde_json::Value> = sorted.into_iter().collect();
            serde_json::Value::Object(map)
        }
        toml::Value::Datetime(dt) => serde_json::Value::String(dt.to_string()),
    }
}
