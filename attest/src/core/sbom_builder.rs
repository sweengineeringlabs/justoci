//! CycloneDX SBOM builder.
//!
//! Emits a shape-correct CycloneDX v1.5 document. Full schema
//! compliance (bom-ref uniqueness, component property schemas,
//! vulnerability references) is follow-up work under #24.
//!
//! For the scaffold we emit `bomFormat`, `specVersion`,
//! `version`, and a `components[]` array with one entry per
//! package. Sufficient for Grype / Trivy to consume and
//! cross-reference CVE feeds.

use serde::{Deserialize, Serialize};

/// One component in the SBOM — typically a package, but can be
/// any addressable dependency.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComponentInfo {
    /// Component name — the package name for apk/apt.
    pub name: String,

    /// Version string as the installer reported it. Empty if unknown.
    #[serde(default)]
    pub version: String,

    /// CycloneDX component type — we use `"library"` for installed
    /// packages. Other valid values per schema: `application`,
    /// `framework`, `container`, `operating-system`, `device`, `firmware`.
    #[serde(rename = "type")]
    pub component_type: String,

    /// Optional purl (Package URL). Populated as
    /// `pkg:apk/alpine/nginx@1.24-r2` when we have all three of
    /// (family, name, version); left empty otherwise.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub purl: String,
}

/// Top-level CycloneDX v1.5 document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxSbom {
    /// Always `"CycloneDX"`. Required by the schema.
    #[serde(rename = "bomFormat")]
    pub bom_format: String,

    /// Schema version. We emit v1.5.
    #[serde(rename = "specVersion")]
    pub spec_version: String,

    /// Monotonic version for this specific document. Starts at 1;
    /// bump on regeneration for the same artifact.
    pub version: u32,

    /// Component list — what's in the artifact.
    pub components: Vec<ComponentInfo>,
}

impl Default for CycloneDxSbom {
    fn default() -> Self {
        Self {
            bom_format: "CycloneDX".into(),
            spec_version: "1.5".into(),
            version: 1,
            components: Vec::new(),
        }
    }
}

/// Builder for CycloneDX SBOMs.
pub struct SbomBuilder;

impl SbomBuilder {
    pub fn new() -> Self {
        Self
    }

    /// Build a CycloneDX v1.5 SBOM from a component list.
    /// Infallible — the scaffold doesn't validate names, schema
    /// compliance, or purl format. #24 follow-ups tighten this.
    pub fn build(&self, components: Vec<ComponentInfo>) -> CycloneDxSbom {
        CycloneDxSbom {
            components,
            ..CycloneDxSbom::default()
        }
    }

    /// Convenience: build from `PackageRecord`s as emitted by the
    /// SLSA builder's input. Produces `"library"`-type components
    /// with purls when version is known.
    pub fn build_from_packages(
        &self,
        packages: &[crate::core::slsa_builder::PackageRecord],
    ) -> CycloneDxSbom {
        let components = packages
            .iter()
            .map(|p| {
                let purl = if p.version.is_empty() {
                    String::new()
                } else {
                    format!("pkg:{}/{}@{}", p.family, p.name, p.version)
                };
                ComponentInfo {
                    name: p.name.clone(),
                    version: p.version.clone(),
                    component_type: "library".into(),
                    purl,
                }
            })
            .collect();
        self.build(components)
    }
}

impl Default for SbomBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::slsa_builder::PackageRecord;

    #[test]
    fn test_sbom_default_has_cyclonedx_shape() {
        let s = CycloneDxSbom::default();
        assert_eq!(s.bom_format, "CycloneDX");
        assert_eq!(s.spec_version, "1.5");
        assert_eq!(s.version, 1);
        assert!(s.components.is_empty());
    }

    #[test]
    fn test_sbom_serializes_top_level_shape() {
        let s = CycloneDxSbom::default();
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains(r#""bomFormat":"CycloneDX""#));
        assert!(json.contains(r#""specVersion":"1.5""#));
        assert!(json.contains(r#""version":1"#));
        assert!(json.contains(r#""components":[]"#));
    }

    #[test]
    fn test_build_from_packages_emits_purls_when_version_known() {
        let pkgs = vec![
            PackageRecord {
                name: "ca-certificates".into(),
                version: "20230506-r0".into(),
                family: "apk".into(),
            },
            PackageRecord {
                name: "openssl".into(),
                version: "".into(),
                family: "apk".into(),
            },
        ];
        let sbom = SbomBuilder::new().build_from_packages(&pkgs);
        assert_eq!(sbom.components.len(), 2);
        assert_eq!(
            sbom.components[0].purl,
            "pkg:apk/ca-certificates@20230506-r0"
        );
        // version-less: no purl
        assert!(sbom.components[1].purl.is_empty());
    }

    #[test]
    fn test_purl_is_omitted_when_empty_on_serialize() {
        let pkgs = vec![PackageRecord {
            name: "nginx".into(),
            version: "".into(),
            family: "apk".into(),
        }];
        let sbom = SbomBuilder::new().build_from_packages(&pkgs);
        let json = serde_json::to_string(&sbom).unwrap();
        // skip_serializing_if = "String::is_empty" means no `purl`
        // key appears when it'd be empty.
        assert!(!json.contains(r#""purl":"""#));
    }

    #[test]
    fn test_sbom_round_trips_through_json() {
        let pkgs = vec![PackageRecord {
            name: "openssl".into(),
            version: "3.1.4-r0".into(),
            family: "apk".into(),
        }];
        let sbom = SbomBuilder::new().build_from_packages(&pkgs);
        let json = serde_json::to_string(&sbom).unwrap();
        let back: CycloneDxSbom = serde_json::from_str(&json).unwrap();
        assert_eq!(back.components, sbom.components);
    }
}
