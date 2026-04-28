//! OCI Image Spec v1.1 manifest types — hand-rolled in serde so the
//! crate stays free of the heavyweight `oci-spec` dependency tree.
//!
//! Field order in [`OciManifest`] / [`OciImageConfig`] / [`OciIndex`]
//! is **frozen by Production-Guarantees-§2 (reproducibility)**. Two
//! invocations on the same `Spec` must produce byte-identical JSON;
//! that requires:
//!
//! 1. `BTreeMap` for annotations / labels (sorted keys).
//! 2. Field declaration order on each struct preserved (`serde_json`
//!    follows declaration order on `Serialize`-derived structs).
//! 3. No timestamp / hostname / build-host fields anywhere.
//!
//! Adding a field MUST preserve serialisation output for specs that
//! don't set it — use `Option<T>` with `#[serde(skip_serializing_if =
//! "Option::is_none")]` so old specs keep producing the same JSON.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// `mediaType` of an OCI image manifest. Pinned per spec doc §8.
pub const MEDIA_TYPE_OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";

/// `mediaType` of an OCI image index. v0 builds emit one manifest +
/// one index pointing at it; multi-platform indices land in v1.
pub const MEDIA_TYPE_OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";

/// `mediaType` of an OCI image config blob.
pub const MEDIA_TYPE_OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";

/// `oci-layout` payload version. Pinned at "1.0.0" by the OCI Image
/// Layout spec; bumping requires re-validating against the spec doc.
pub const OCI_LAYOUT_VERSION: &str = "1.0.0";

/// OCI image manifest (v1.1).
///
/// Layer descriptors carry the spec's media types verbatim — a
/// vendor type like `application/vnd.vmisolate.kernel+binary` lands
/// in the manifest unchanged, so a downstream consumer can identify
/// the artifact kind by media type without inspecting bytes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OciManifest {
    /// OCI Image Spec mandates `2`. An integer (not string) so old
    /// `schemaVersion: "2"` payloads from Docker v1 manifests are
    /// rejected at parse time.
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,

    /// Always [`MEDIA_TYPE_OCI_MANIFEST`].
    #[serde(rename = "mediaType")]
    pub media_type: String,

    /// Pointer to the image config blob.
    pub config: OciDescriptor,

    /// Layer descriptors in spec-declared order. For `vm_image` this
    /// is kernel → initrd → rootfs; for `oci_artifact` whatever the
    /// caller wrote; for `raw_image` exactly one entry.
    pub layers: Vec<OciDescriptor>,

    /// Annotations from the spec's `[annotations]` block. `BTreeMap`
    /// for stable serialised key order.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

/// OCI image config blob.
///
/// `architecture` and `os` come from the spec's optional
/// `[platform]`. When the spec omits `[platform]`, OCI 1.1 still
/// requires them present in the config — we default to `"unknown"`
/// rather than emit an invalid config blob.
///
/// `config.entrypoint` / `config.env` / `config.labels` are populated
/// from the spec's `[config]` block. The whole `[config]` table is
/// also stored under `extra` so consumer-defined keys (e.g.
/// `init_mode`, `kernel_cmdline` for vm_image) round-trip without
/// loss — justoci is the *transport*, not the schema authority.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OciImageConfig {
    pub architecture: String,
    pub os: String,
    /// Container-runtime config. Optional in OCI 1.1; we omit it
    /// entirely when no relevant fields exist in the spec rather than
    /// emit an empty `{}` that varies across re-runs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<OciRuntimeConfig>,
    /// Justoci passes the spec's unknown `[config]` keys through
    /// verbatim — they appear as siblings of `architecture` / `os`
    /// in the OCI config JSON via `#[serde(flatten)]`. `BTreeMap`
    /// for sorted serialisation. The OCI image-config schema does
    /// not have a fixed list of fields beyond a small core (the
    /// "consumer" reads what it expects), so flattening is correct.
    #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// Subset of OCI 1.1's `config.config` we surface from the spec.
///
/// The `Env` shape is `KEY=VALUE` strings (not a map) per OCI 1.1.
/// `Entrypoint` and `Cmd` likewise are arrays of strings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OciRuntimeConfig {
    #[serde(rename = "Env", default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
    #[serde(rename = "Entrypoint", default, skip_serializing_if = "Vec::is_empty")]
    pub entrypoint: Vec<String>,
    #[serde(rename = "Cmd", default, skip_serializing_if = "Vec::is_empty")]
    pub cmd: Vec<String>,
    #[serde(rename = "Labels", default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

/// OCI descriptor (`{ mediaType, digest, size, ... }`). Used by both
/// the manifest's `config` / `layers` fields and the index's
/// `manifests` field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OciDescriptor {
    #[serde(rename = "mediaType")]
    pub media_type: String,
    /// `<algorithm>:<hex>`, lowercase. Matches `cas::Digest::Display`.
    pub digest: String,
    pub size: u64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

/// OCI image index (the `index.json` at the layout root).
///
/// v0 always emits exactly one manifest descriptor, since a spec
/// describes one artifact for one platform. Multi-platform fat
/// manifests are out-of-scope per the spec doc.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OciIndex {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub manifests: Vec<OciDescriptor>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

/// `oci-layout` marker file at the layout root. Two-line JSON:
/// `{"imageLayoutVersion":"1.0.0"}`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OciLayout {
    #[serde(rename = "imageLayoutVersion")]
    pub image_layout_version: String,
}

impl OciLayout {
    pub fn pinned() -> Self {
        OciLayout {
            image_layout_version: OCI_LAYOUT_VERSION.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oci_manifest_serialises_with_schema_version_2() {
        // Bug this would catch: a refactor that flips `schema_version`
        // to a string ("2" instead of 2) — Docker v1 manifest land,
        // breaks every OCI 1.1 consumer that round-trips the int.
        let m = OciManifest {
            schema_version: 2,
            media_type: MEDIA_TYPE_OCI_MANIFEST.to_string(),
            config: OciDescriptor {
                media_type: MEDIA_TYPE_OCI_CONFIG.to_string(),
                digest: "sha256:dead".repeat(8),
                size: 12,
                annotations: BTreeMap::new(),
            },
            layers: vec![],
            annotations: BTreeMap::new(),
        };
        let json = serde_json::to_string(&m).unwrap();
        assert!(
            json.contains("\"schemaVersion\":2"),
            "OCI 1.1 mandates int schemaVersion=2, got: {json}"
        );
        assert!(json.contains("application/vnd.oci.image.manifest.v1+json"));
    }

    #[test]
    fn test_descriptor_size_is_unsigned_and_unbounded() {
        // Bug this would catch: defining `size` as i32/i64 — would
        // silently overflow for blobs over 2GB / wrap negative for
        // blobs over 8EB. Real artifacts (rootfs.ext4) hit GB regularly.
        let d = OciDescriptor {
            media_type: "test".into(),
            digest: "sha256:aa".repeat(32),
            // 5 GiB — unrepresentable in i32.
            size: 5 * 1024 * 1024 * 1024,
            annotations: BTreeMap::new(),
        };
        let json = serde_json::to_string(&d).unwrap();
        assert!(json.contains("5368709120"));
    }

    #[test]
    fn test_oci_layout_pinned_is_exactly_v100() {
        // Bug this would catch: a refactor that moves the OCI layout
        // to a future version without updating consumers — every OCI
        // 1.1 tool refuses unknown layout versions.
        let l = OciLayout::pinned();
        assert_eq!(l.image_layout_version, "1.0.0");
        let json = serde_json::to_string(&l).unwrap();
        assert_eq!(json, r#"{"imageLayoutVersion":"1.0.0"}"#);
    }

    #[test]
    fn test_manifest_with_empty_annotations_omits_field() {
        // Bug this would catch: a refactor that drops the
        // `skip_serializing_if` and emits `"annotations":{}` —
        // changes the manifest digest for every spec without
        // annotations, breaking reproducibility against pre-change
        // builds.
        let m = OciManifest {
            schema_version: 2,
            media_type: MEDIA_TYPE_OCI_MANIFEST.to_string(),
            config: OciDescriptor {
                media_type: MEDIA_TYPE_OCI_CONFIG.to_string(),
                digest: "sha256:".to_string() + &"a".repeat(64),
                size: 0,
                annotations: BTreeMap::new(),
            },
            layers: vec![],
            annotations: BTreeMap::new(),
        };
        let json = serde_json::to_string(&m).unwrap();
        assert!(!json.contains("annotations"));
    }

    #[test]
    fn test_image_config_flattens_extra_keys_to_top_level() {
        // Bug this would catch: nesting unknown spec `[config]` keys
        // under an `"extra": {…}` sub-object. Consumers that read
        // type-specific keys (vmisolate reads `init_mode` /
        // `kernel_cmdline` from the OCI config) would not find them
        // because they're looking at the top level, not under
        // `"extra"`.
        let mut extra = BTreeMap::new();
        extra.insert(
            "init_mode".to_string(),
            serde_json::Value::String("xkinit".into()),
        );
        let cfg = OciImageConfig {
            architecture: "x86_64".into(),
            os: "linux".into(),
            config: None,
            extra,
        };
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&cfg).unwrap()).unwrap();
        assert!(
            v.get("init_mode").is_some(),
            "init_mode must be a top-level field, got: {v}"
        );
        assert!(
            v.get("extra").is_none(),
            "no `extra` sub-object — keys flatten to top level"
        );
    }

    #[test]
    fn test_image_config_omits_runtime_config_when_none() {
        // Bug this would catch: emitting `"config":null` for specs
        // without an entrypoint — perturbs the config digest vs
        // specs that genuinely have no runtime info.
        let c = OciImageConfig {
            architecture: "amd64".into(),
            os: "linux".into(),
            config: None,
            extra: BTreeMap::new(),
        };
        let json = serde_json::to_string(&c).unwrap();
        assert!(!json.contains("\"config\""));
    }
}
