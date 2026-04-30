//! `--policy <policy.toml>` parser for `justoci verify`.
//!
//! The policy file declares one or more gates the verifier must
//! satisfy in addition to structural-integrity checks. v0 supports:
//!
//! ```toml
//! [slsa]
//! level = 2          # require claimed_slsa_level >= N
//!
//! [sign]
//! required = true    # require signature pillar Found
//! builder_id = "ci.example.com/runner"   # exact match against
//!                                        # SLSA runDetails.builder.id
//!
//! [sbom]
//! formats = ["cyclonedx"]   # require SBOM media type to contain
//!                           # one of these substrings
//! ```
//!
//! Unknown keys are tolerated for forward-compat (a future v0.1
//! adding `sign.identity = "<regex>"` should not break v0
//! pipelines that consume their own policy file).
//!
//! Each rule maps onto exactly one
//! [`crate::verify_engine::VerifyError::PolicyViolation`] variant
//! when the gate fails — operators see "rule slsa.level: claimed 1
//! < required 2" rather than a generic "policy failed."

use std::path::Path;

use serde::Deserialize;

use crate::error::CliError;

/// Parsed policy.toml. Each field is `Option<…>` so the verifier
/// can apply only the gates the operator declared.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    /// `[slsa] level = N` — require `claimed_slsa_level >= N`.
    pub slsa_min_level: Option<i64>,

    /// `[sign] required = true` — require signature pillar `Found`.
    pub require_signature: bool,

    /// `[sign] builder_id = "..."` — require exact match against
    /// the SLSA statement's `runDetails.builder.id`.
    pub builder_id: Option<String>,

    /// `[sbom] formats = ["cyclonedx", "spdx"]` — require SBOM
    /// pillar `Found` AND its media-type detail to contain one of
    /// these substrings.
    pub sbom_formats: Option<Vec<String>>,
}

impl Policy {
    /// Load + parse a policy.toml file.
    pub fn load(path: &Path) -> Result<Self, CliError> {
        let bytes = std::fs::read_to_string(path).map_err(|source| CliError::CliIo {
            path: path.display().to_string(),
            source,
        })?;
        Self::parse(&bytes).map_err(|e| CliError::Cli {
            detail: format!("policy {}: {e}", path.display()),
        })
    }

    /// Parse from a string. Public for tests.
    pub fn parse(toml_text: &str) -> Result<Self, toml::de::Error> {
        let raw: RawPolicy = toml::from_str(toml_text)?;
        Ok(Policy {
            slsa_min_level: raw.slsa.and_then(|s| s.level),
            require_signature: raw.sign.as_ref().and_then(|s| s.required).unwrap_or(false),
            builder_id: raw.sign.and_then(|s| s.builder_id),
            sbom_formats: raw.sbom.and_then(|s| s.formats),
        })
    }
}

#[derive(Debug, Deserialize)]
struct RawPolicy {
    #[serde(default)]
    slsa: Option<RawSlsaPolicy>,
    #[serde(default)]
    sign: Option<RawSignPolicy>,
    #[serde(default)]
    sbom: Option<RawSbomPolicy>,
}

#[derive(Debug, Deserialize)]
struct RawSlsaPolicy {
    #[serde(default)]
    level: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct RawSignPolicy {
    #[serde(default)]
    required: Option<bool>,
    #[serde(default)]
    builder_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawSbomPolicy {
    #[serde(default)]
    formats: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Catches: an empty policy.toml accidentally enabling gates by
    // default — operators expect "no [slsa]" to mean "no slsa gate"
    // not "slsa level 0 required".
    #[test]
    fn test_parse_empty_policy_enables_no_gates() {
        let p = Policy::parse("").unwrap();
        assert!(p.slsa_min_level.is_none());
        assert!(!p.require_signature);
        assert!(p.builder_id.is_none());
        assert!(p.sbom_formats.is_none());
    }

    #[test]
    fn test_parse_full_policy() {
        // Catches: parser regression that drops a gate from the
        // typed Policy struct — the gate would silently never
        // apply, letting unsigned / unattested artifacts through
        // even when the operator declared the gate.
        let toml_text = r#"
[slsa]
level = 3

[sign]
required = true
builder_id = "ci.example.com/runner-x"

[sbom]
formats = ["cyclonedx"]
"#;
        let p = Policy::parse(toml_text).unwrap();
        assert_eq!(p.slsa_min_level, Some(3));
        assert!(p.require_signature);
        assert_eq!(p.builder_id.as_deref(), Some("ci.example.com/runner-x"));
        assert_eq!(
            p.sbom_formats.as_deref(),
            Some(&["cyclonedx".to_string()][..])
        );
    }

    // Catches: a policy with an unknown key panicking the parser.
    // We tolerate forward-compat additions; future versions add new
    // gates that older verifiers should ignore (with a warning at
    // the CLI layer if needed) rather than reject.
    #[test]
    fn test_parse_tolerates_unknown_keys() {
        let toml_text = r#"
[slsa]
level = 2
some_future_key = "value"

[sign]
required = false
"#;
        let p = Policy::parse(toml_text).expect("must tolerate unknown keys");
        assert_eq!(p.slsa_min_level, Some(2));
        assert!(!p.require_signature);
    }
}
