//! Predicate types — the claim body inside a Statement.
//!
//! Each variant wraps the concrete predicate struct. Serde
//! serializes using the untagged strategy so the on-disk JSON
//! matches the in-toto convention of inlining the predicate
//! body directly under `predicate`.

use serde::{Deserialize, Serialize};

use crate::core::sbom_builder::CycloneDxSbom;
use crate::core::slsa_builder::SlsaProvenance;

/// Which in-toto predicate schema a Statement carries.
///
/// The URI is the canonical identifier published alongside the
/// in-toto schema. Verifiers match on this to pick the right
/// deserializer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredicateType {
    /// `https://slsa.dev/provenance/v1` — SLSA v1.0 build provenance.
    SlsaProvenance,

    /// `https://cyclonedx.org/bom` — CycloneDX SBOM. We use the
    /// generic URI rather than a version-specific one so the
    /// embedded CycloneDX `specVersion` field is authoritative.
    CycloneDxSbom,

    /// Escape hatch for future predicate types (VEX, SARIF, custom
    /// build metadata). Carries the type URI inline.
    Custom,
}

impl PredicateType {
    /// Canonical URI for this predicate type.
    pub const fn uri(&self) -> &'static str {
        match self {
            Self::SlsaProvenance => "https://slsa.dev/provenance/v1",
            Self::CycloneDxSbom => "https://cyclonedx.org/bom",
            Self::Custom => "https://example.com/custom/v1",
        }
    }
}

/// Enum wrapping concrete predicate bodies.
///
/// We use an untagged serde representation so the JSON for a
/// SlsaProvenance variant serializes as the raw SlsaProvenance
/// fields — the in-toto `predicateType` discriminator lives on
/// the parent Statement, not inside this enum.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Predicate {
    SlsaProvenance(SlsaProvenance),
    CycloneDxSbom(CycloneDxSbom),
    Custom(serde_json::Value),
}

impl Predicate {
    /// Which predicate type URI this predicate claims.
    pub fn predicate_type_uri(&self) -> &'static str {
        match self {
            Self::SlsaProvenance(_) => PredicateType::SlsaProvenance.uri(),
            Self::CycloneDxSbom(_) => PredicateType::CycloneDxSbom.uri(),
            Self::Custom(_) => PredicateType::Custom.uri(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_predicate_type_uris_are_stable() {
        assert_eq!(
            PredicateType::SlsaProvenance.uri(),
            "https://slsa.dev/provenance/v1"
        );
        assert_eq!(
            PredicateType::CycloneDxSbom.uri(),
            "https://cyclonedx.org/bom"
        );
    }

    #[test]
    fn test_predicate_reports_correct_type_uri() {
        let p = Predicate::SlsaProvenance(SlsaProvenance::default());
        assert_eq!(p.predicate_type_uri(), PredicateType::SlsaProvenance.uri());

        let p = Predicate::CycloneDxSbom(CycloneDxSbom::default());
        assert_eq!(p.predicate_type_uri(), PredicateType::CycloneDxSbom.uri());
    }
}
