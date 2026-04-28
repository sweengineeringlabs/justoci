//! Raw schema types — what `serde` deserialises a justoci TOML spec
//! into before validation runs. Intentionally close to the wire shape
//! (all-optional, `String`/`i64`-typed) so the deserialiser surfaces
//! TOML syntax errors, while validation surfaces *semantic* errors
//! against the typed `Spec` shape in the api layer.
//!
//! Only `core::validate` and `saf::parse` touch these — they are
//! `pub(crate)` and have no public API.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawSpec {
    pub spec_version: String,
    pub id: String,
    pub kind: String,
    pub description: Option<String>,
    pub platform: Option<RawPlatform>,
    pub layers: Vec<RawLayer>,
    pub config: Option<toml::Value>,
    pub annotations: Option<BTreeMap<String, String>>,
    pub attestation: Option<RawAttestation>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawPlatform {
    pub os: Option<String>,
    pub arch: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawLayer {
    pub source: Option<PathBuf>,
    pub media_type: String,
    pub compression: Option<String>,
    pub files: Option<Vec<RawLayerFile>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawLayerFile {
    pub source: PathBuf,
    pub dest: String,
    pub mode: u32,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawAttestation {
    pub slsa: Option<RawSlsa>,
    pub sbom: Option<RawSbom>,
    pub sign: Option<RawSign>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawSlsa {
    pub level: Option<i64>,
    pub builder_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawSbom {
    pub format: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawSign {
    pub kind: Option<String>,
    pub identity: Option<String>,
}
