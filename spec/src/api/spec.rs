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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaType(String);

impl MediaType {
    /// Construct without validation. Validation lives in
    /// `core::validate`; this constructor is `pub(crate)` so external
    /// callers go through `parse_and_validate`.
    pub(crate) fn unchecked(s: String) -> Self {
        MediaType(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
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
