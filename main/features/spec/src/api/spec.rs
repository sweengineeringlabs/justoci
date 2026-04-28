use std::collections::BTreeMap;
use std::path::PathBuf;

use super::attestation::AttestationConfig;

/// Pinned spec version. v0 only. v1+ ships its own parser.
///
/// Stored as an enum, not a string, so adding `V1` later forces every
/// match site to be revisited. Silent fallthrough on unknown versions
/// is the kind of bug that ships months later when someone bumps the
/// spec_version in a build pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecVersion {
    V0,
}

impl SpecVersion {
    pub fn as_str(&self) -> &'static str {
        match self {
            SpecVersion::V0 => "0",
        }
    }
}

/// Artifact identity in `<name>:<tag>` form.
///
/// `name` is lowercase; `tag` may be mixed-case. Both are validated
/// against the OCI registry spec's reference grammar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactId {
    pub name: String,
    pub tag: String,
}

impl ArtifactId {
    pub fn to_string_form(&self) -> String {
        format!("{}:{}", self.name, self.tag)
    }
}

/// Artifact-type discriminator. Drives validation, not transformation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Generic OCI artifact (oras-style). Caller-defined media types,
    /// caller-defined layer order, ≥1 layer.
    OciArtifact,
    /// Bootable VM image: kernel + initrd + rootfs in that order.
    /// Exactly 3 layers.
    VmImage,
    /// Single flashable blob (firmware, disk image). Exactly 1 layer.
    RawImage,
}

impl Kind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Kind::OciArtifact => "oci_artifact",
            Kind::VmImage => "vm_image",
            Kind::RawImage => "raw_image",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "oci_artifact" => Some(Kind::OciArtifact),
            "vm_image" => Some(Kind::VmImage),
            "raw_image" => Some(Kind::RawImage),
            _ => None,
        }
    }
}

/// Optional `[platform]` table.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Platform {
    pub os: Option<String>,
    pub arch: Option<String>,
}

/// One layer of the artifact. Source mode is mutually exclusive:
/// either a pre-built blob (`Blob`) or a deterministic tar from a
/// list of files (`Files`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layer {
    pub source: LayerSource,
    pub media_type: MediaType,
    pub compression: Compression,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayerSource {
    /// Pre-built blob; `path` is relative to the spec file's directory.
    Blob { path: PathBuf },
    /// Assemble a tar layer from individual files. The tar is
    /// deterministic: sorted entries, mtime=0, uid:gid=0:0.
    Files { entries: Vec<LayerFile> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerFile {
    /// Source file or directory on the build host. Relative to the
    /// spec file's directory; directories descend recursively.
    pub source: PathBuf,
    /// Destination path inside the layer (always absolute).
    pub dest: String,
    /// Octal Unix mode (e.g. 0o644).
    pub mode: u32,
}

/// OCI media type. Stored as a typed wrapper so callers can't pass
/// a stray `String` to a function expecting a media type.
///
/// Construct via [`MediaType::parse`], which validates the OCI
/// media-type grammar (RFC 6838 restricted-name + optional `+suffix`).
/// There is no unchecked constructor: every `MediaType` value in the
/// program has been through the same grammar gate, regardless of
/// whether it came from a TOML spec or a programmatic caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaType(String);

impl MediaType {
    /// Parse and validate an OCI media-type string.
    ///
    /// Grammar accepted (matches what the spec doc declares for
    /// `[[layers]] media_type`):
    ///
    /// ```text
    /// type "/" subtype [ "+" suffix ]
    /// ```
    ///
    /// where `type`, `subtype`, and `suffix` are RFC 6838
    /// restricted-name characters (`[a-zA-Z0-9._-]`) plus `+` for
    /// the suffix marker. No whitespace, no control characters.
    ///
    /// Returns [`MediaTypeParseError::Malformed`] on rejection. The
    /// error carries the offending input and a brief reason so
    /// callers can surface meaningful diagnostics.
    ///
    /// # Examples
    ///
    /// ```
    /// use spec::MediaType;
    /// assert!(MediaType::parse("application/vnd.example+gzip").is_ok());
    /// assert!(MediaType::parse("no-slash-here").is_err());
    /// ```
    pub fn parse(s: &str) -> Result<Self, MediaTypeParseError> {
        // "type/subtype" required; "+suffix" optional.
        let Some((typ, rest)) = s.split_once('/') else {
            return Err(MediaTypeParseError::Malformed {
                got: s.to_string(),
                reason: "missing '/' between type and subtype",
            });
        };
        if typ.is_empty() {
            return Err(MediaTypeParseError::Malformed {
                got: s.to_string(),
                reason: "type before '/' cannot be empty",
            });
        }
        if rest.is_empty() {
            return Err(MediaTypeParseError::Malformed {
                got: s.to_string(),
                reason: "subtype after '/' cannot be empty",
            });
        }
        // RFC 6838 "restricted-name" plus '+' for the suffix marker.
        let valid = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-' | '_');
        if !typ.chars().all(valid) || !rest.chars().all(valid) {
            return Err(MediaTypeParseError::Malformed {
                got: s.to_string(),
                reason: "characters outside RFC 6838 restricted-name + '+' suffix marker",
            });
        }
        Ok(MediaType(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Errors raised by [`MediaType::parse`].
///
/// Carries no positional context — `MediaType::parse` is a
/// single-string operation. The validator wraps this into
/// [`super::error::SpecError::MalformedMediaType`] which adds the
/// offending layer's position when the parse happens inside a spec.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MediaTypeParseError {
    #[error("media type '{got}' violates OCI grammar: {reason}")]
    Malformed { got: String, reason: &'static str },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    None,
    Gzip,
    Zstd,
}

impl Compression {
    pub fn as_str(&self) -> &'static str {
        match self {
            Compression::None => "none",
            Compression::Gzip => "gzip",
            Compression::Zstd => "zstd",
        }
    }
}

/// The `[config]` block. Justoci does not enforce a schema on this
/// content — it serialises the TOML into JSON and embeds the result
/// as the OCI image config blob. Type-specific validation is the
/// consumer's responsibility (e.g. vmisolate validates `vm_image`
/// configs against its own `ConfigManifest`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigBlob(pub serde_json::Value);

impl Default for ConfigBlob {
    fn default() -> Self {
        ConfigBlob(serde_json::Value::Object(serde_json::Map::new()))
    }
}

/// A parsed-and-validated justoci spec.
///
/// Once a `Spec` exists in memory, every Production-Guarantees-§4
/// rule has been checked. Construction is funneled through
/// `parse_and_validate` (in the saf layer); there is no public way
/// to construct a `Spec` that bypasses validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spec {
    pub spec_version: SpecVersion,
    pub id: ArtifactId,
    pub kind: Kind,
    pub description: Option<String>,
    pub platform: Platform,
    pub layers: Vec<Layer>,
    pub config: ConfigBlob,
    /// `BTreeMap` for deterministic iteration order — JCS
    /// canonicalisation requires sorted keys, and using a btree at
    /// the type level avoids a sort step downstream.
    pub annotations: BTreeMap<String, String>,
    pub attestation: AttestationConfig,
}

#[cfg(test)]
mod media_type_tests {
    use super::*;

    /// Anchor: a typical OCI media type round-trips and is preserved
    /// byte-for-byte.
    ///
    /// Bug it catches: a parse impl that normalised the casing or
    /// stripped the suffix would change the wire bytes downstream
    /// and break OCI clients that rely on exact-string media-type
    /// matching.
    #[test]
    fn test_parse_canonical_oci_media_type_round_trips() {
        let input = "application/vnd.oci.image.manifest.v1+json";
        let mt = MediaType::parse(input).expect("canonical OCI media type must parse");
        assert_eq!(mt.as_str(), input);
    }

    /// Vendor types under our own prefix parse — proves the grammar
    /// accepts the artifact-kind media types the spec-v0 examples use.
    #[test]
    fn test_parse_vmisolate_kernel_media_type_accepts_plus_suffix() {
        let input = "application/vnd.vmisolate.kernel+binary";
        assert!(
            MediaType::parse(input).is_ok(),
            "must accept '+suffix' form"
        );
    }

    /// No slash → Malformed.
    ///
    /// Bug it catches: a parser that accepted any non-empty string
    /// would pass `"my-blob"` straight through to the OCI manifest,
    /// where registries would then reject it at upload time with a
    /// less specific error.
    #[test]
    fn test_parse_rejects_input_without_slash() {
        let err = MediaType::parse("no-slash-here").expect_err("must reject");
        assert!(matches!(err, MediaTypeParseError::Malformed { .. }));
        assert!(err.to_string().contains("no-slash-here"));
    }

    /// Empty type before slash → Malformed.
    #[test]
    fn test_parse_rejects_empty_type() {
        let err = MediaType::parse("/subtype").expect_err("must reject");
        match err {
            MediaTypeParseError::Malformed { reason, .. } => {
                assert!(
                    reason.contains("type"),
                    "reason must mention type: {reason}"
                );
            }
        }
    }

    /// Empty subtype after slash → Malformed.
    #[test]
    fn test_parse_rejects_empty_subtype() {
        let err = MediaType::parse("application/").expect_err("must reject");
        match err {
            MediaTypeParseError::Malformed { reason, .. } => {
                assert!(
                    reason.contains("subtype"),
                    "reason must mention subtype: {reason}"
                );
            }
        }
    }

    /// Whitespace anywhere → Malformed.
    ///
    /// Bug it catches: a parser that tolerated spaces would propagate
    /// trailing whitespace into manifest digests; two specs that
    /// differed only in trailing space would compute different
    /// digests, breaking reproducibility.
    #[test]
    fn test_parse_rejects_internal_whitespace() {
        let err = MediaType::parse("application/vnd. oci.foo").expect_err("must reject space");
        assert!(matches!(err, MediaTypeParseError::Malformed { .. }));
    }

    /// Control characters → Malformed.
    #[test]
    fn test_parse_rejects_control_chars() {
        let err = MediaType::parse("application/vnd\x00.foo").expect_err("must reject NUL");
        assert!(matches!(err, MediaTypeParseError::Malformed { .. }));
    }

    /// Display includes the offending input — operators see the bad
    /// value, not just "media type was wrong".
    #[test]
    fn test_parse_error_display_carries_input() {
        let err = MediaType::parse("bad value").expect_err("must reject");
        assert!(err.to_string().contains("bad value"));
    }
}
