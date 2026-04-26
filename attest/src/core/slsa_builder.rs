//! SLSA v1.0 provenance builder.
//!
//! Transforms a [`BuildContext`] into an [`SlsaProvenance`] value
//! matching the `https://slsa.dev/provenance/v1` schema. Pure
//! data transform — no I/O, no subprocess.
//!
//! # Scope of the scaffold
//!
//! Produces a shape-correct predicate body. The field values come
//! straight from the `BuildContext` the caller constructed; we
//! don't compute digests ourselves (the caller does that during
//! the build, via `oci/build`'s `build-manifest.json` output).
//!
//! Full SLSA v1.0 compliance — every optional field populated,
//! `resolvedDependencies` complete with transitive closure — is
//! follow-up work under #24.

use serde::{Deserialize, Serialize};

/// Inputs the SLSA builder needs to produce a provenance predicate.
///
/// Constructed by the caller (typically `ocimage publish --attest`)
/// from the build-time `build-manifest.json` + CI environment.
#[derive(Debug, Clone)]
pub struct BuildContext {
    /// SHA-256 of the raw TOML spec bytes — the attestable input.
    /// Hex-encoded, no prefix. Matches the `spec_sha256` field in
    /// `build-manifest.json`.
    pub spec_sha256: String,

    /// Builder identity. In CI: the GitHub Actions workflow run URL.
    /// In offline builds: the operator's signing-key fingerprint.
    pub builder_id: String,

    /// Per-artifact digests (kernel, initrd, rootfs, config.json).
    pub artifacts: Vec<ArtifactDigest>,

    /// Packages installed into the rootfs (from #17). Ordered as the
    /// installer ran them; the SLSA predicate records them as
    /// `resolvedDependencies`.
    pub packages: Vec<PackageRecord>,

    /// Build started — unix timestamp, seconds. 0 if not available.
    pub started_at_unix: u64,

    /// Build finished — unix timestamp, seconds. 0 if not available.
    pub finished_at_unix: u64,
}

/// One artifact's identity: name + content hash.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactDigest {
    /// File name relative to the build output dir
    /// (e.g. `"kernel"`, `"rootfs.ext4"`).
    pub name: String,

    /// SHA-256 digest, lowercase hex, no prefix.
    pub sha256: String,
}

/// One installed package's identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageRecord {
    /// Package name as passed to `apk add` / `apt install`.
    pub name: String,

    /// Resolved version, if the installer reported one. Empty if
    /// the builder didn't capture version info.
    #[serde(default)]
    pub version: String,

    /// Package family — `"apk"`, `"apt"`, etc. Matches
    /// [`oci_build::spi::package_installer::PackageInstaller::family`].
    pub family: String,
}

/// SLSA v1.0 provenance predicate body.
///
/// Top-level shape matches the SLSA v1 schema:
/// <https://slsa.dev/spec/v1.0/provenance>
///
/// Nested structs below mirror the schema's `buildDefinition` +
/// `runDetails` sub-objects. Serde field names use `camelCase` to
/// match the JSON schema.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SlsaProvenance {
    /// How the build was configured + which dependencies it
    /// consumed. Shape-defined by SLSA v1.0.
    #[serde(rename = "buildDefinition")]
    pub build_definition: BuildDefinition,

    /// Who ran the build, when, and where. Shape-defined by
    /// SLSA v1.0.
    #[serde(rename = "runDetails")]
    pub run_details: RunDetails,
}

/// `buildDefinition` from the SLSA schema.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BuildDefinition {
    /// URI naming the build process shape. For vmisolate we coin
    /// `https://vmisolate.io/ocimage/v1`.
    #[serde(rename = "buildType")]
    pub build_type: String,

    /// Caller-supplied parameters — for us, the spec digest.
    #[serde(rename = "externalParameters")]
    pub external_parameters: ExternalParameters,

    /// Build-resolved dependencies — for us, the package list.
    #[serde(rename = "resolvedDependencies", default)]
    pub resolved_dependencies: Vec<ResolvedDependency>,
}

/// Inputs the caller passed to the build (hash-pinned).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExternalParameters {
    /// Hex-encoded SHA-256 of the raw spec.toml bytes.
    #[serde(rename = "specDigest")]
    pub spec_digest: String,
}

/// One entry in `resolvedDependencies`. Schema allows a free-form
/// map; we emit the fields SLSA specifies + our package metadata.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResolvedDependency {
    /// Resource URI naming the dependency — e.g.
    /// `"pkg:apk/alpine/nginx@1.24-r2"` (purl format).
    pub uri: String,

    /// Digest map — at minimum `{ sha256: hex }` if content-addressable.
    /// For apk packages without a recorded sha, this may be empty.
    #[serde(default)]
    pub digest: std::collections::BTreeMap<String, String>,
}

/// `runDetails` from the SLSA schema — metadata about who / when / how.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RunDetails {
    /// The signing entity. For us: the GitHub Actions workflow URI
    /// (keyless) or the operator's signing-key fingerprint (keyed).
    pub builder: Builder,

    /// When + where the build ran.
    pub metadata: Metadata,

    /// Byproducts — per-artifact digests, surfacing
    /// `BuildContext.artifacts` so verifiers can cross-check.
    #[serde(default)]
    pub byproducts: Vec<ArtifactDigest>,
}

/// Builder identity inside `runDetails`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Builder {
    /// URI naming the builder. CI runs: the workflow URL. Offline:
    /// a pre-registered builder identity string.
    pub id: String,
}

/// Build-time metadata inside `runDetails`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Metadata {
    /// Unix timestamp (seconds) when the build started. 0 = unknown.
    #[serde(rename = "startedOn")]
    pub started_on: u64,

    /// Unix timestamp (seconds) when the build finished. 0 = unknown.
    #[serde(rename = "finishedOn")]
    pub finished_on: u64,
}

/// Pure-Rust SLSA provenance builder.
pub struct SlsaBuilder;

impl SlsaBuilder {
    pub fn new() -> Self {
        Self
    }

    /// Build an SLSA v1.0 provenance predicate from the context.
    /// Infallible for well-formed inputs — the only failure would
    /// be an empty `builder_id` or `spec_sha256`, which we surface
    /// via [`crate::api::error::AttestError::InvalidContext`].
    pub fn build(
        &self,
        ctx: &BuildContext,
    ) -> Result<SlsaProvenance, crate::api::error::AttestError> {
        if ctx.builder_id.is_empty() {
            return Err(crate::api::error::AttestError::InvalidContext {
                reason: "BuildContext.builder_id is empty".into(),
            });
        }
        if ctx.spec_sha256.is_empty() {
            return Err(crate::api::error::AttestError::InvalidContext {
                reason: "BuildContext.spec_sha256 is empty".into(),
            });
        }

        let resolved_dependencies = ctx
            .packages
            .iter()
            .map(|p| {
                let uri = match p.version.as_str() {
                    "" => format!("pkg:{}/{}", p.family, p.name),
                    v => format!("pkg:{}/{}@{}", p.family, p.name, v),
                };
                ResolvedDependency {
                    uri,
                    digest: Default::default(),
                }
            })
            .collect();

        Ok(SlsaProvenance {
            build_definition: BuildDefinition {
                build_type: "https://vmisolate.io/ocimage/v1".into(),
                external_parameters: ExternalParameters {
                    spec_digest: ctx.spec_sha256.clone(),
                },
                resolved_dependencies,
            },
            run_details: RunDetails {
                builder: Builder {
                    id: ctx.builder_id.clone(),
                },
                metadata: Metadata {
                    started_on: ctx.started_at_unix,
                    finished_on: ctx.finished_at_unix,
                },
                byproducts: ctx.artifacts.clone(),
            },
        })
    }
}

impl Default for SlsaBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ctx() -> BuildContext {
        BuildContext {
            spec_sha256: "abcd".repeat(16),
            builder_id: "https://example.com/ci/run/1".into(),
            artifacts: vec![ArtifactDigest {
                name: "kernel".into(),
                sha256: "dead".repeat(16),
            }],
            packages: vec![PackageRecord {
                name: "ca-certificates".into(),
                version: "20230506-r0".into(),
                family: "apk".into(),
            }],
            started_at_unix: 1_700_000_000,
            finished_at_unix: 1_700_000_010,
        }
    }

    #[test]
    fn test_builder_populates_all_schema_sections() {
        let p = SlsaBuilder::new().build(&sample_ctx()).unwrap();

        assert_eq!(
            p.build_definition.build_type,
            "https://vmisolate.io/ocimage/v1"
        );
        assert_eq!(
            p.build_definition.external_parameters.spec_digest,
            "abcd".repeat(16)
        );
        assert_eq!(p.build_definition.resolved_dependencies.len(), 1);
        assert_eq!(
            p.build_definition.resolved_dependencies[0].uri,
            "pkg:apk/ca-certificates@20230506-r0"
        );

        assert_eq!(p.run_details.builder.id, "https://example.com/ci/run/1");
        assert_eq!(p.run_details.metadata.started_on, 1_700_000_000);
        assert_eq!(p.run_details.metadata.finished_on, 1_700_000_010);
        assert_eq!(p.run_details.byproducts.len(), 1);
    }

    #[test]
    fn test_builder_rejects_empty_builder_id() {
        let mut ctx = sample_ctx();
        ctx.builder_id = "".into();
        let err = SlsaBuilder::new().build(&ctx).unwrap_err();
        assert!(format!("{err}").contains("builder_id"));
    }

    #[test]
    fn test_builder_rejects_empty_spec_digest() {
        let mut ctx = sample_ctx();
        ctx.spec_sha256 = "".into();
        let err = SlsaBuilder::new().build(&ctx).unwrap_err();
        assert!(format!("{err}").contains("spec_sha256"));
    }

    #[test]
    fn test_package_without_version_emits_unversioned_purl() {
        let mut ctx = sample_ctx();
        ctx.packages = vec![PackageRecord {
            name: "nginx".into(),
            version: "".into(),
            family: "apk".into(),
        }];
        let p = SlsaBuilder::new().build(&ctx).unwrap();
        assert_eq!(
            p.build_definition.resolved_dependencies[0].uri,
            "pkg:apk/nginx"
        );
    }

    #[test]
    fn test_builder_round_trips_through_json() {
        let p = SlsaBuilder::new().build(&sample_ctx()).unwrap();
        let json = serde_json::to_string(&p).unwrap();
        // Key SLSA fields must survive serialization (camelCase).
        assert!(json.contains(r#""buildDefinition""#));
        assert!(json.contains(r#""buildType""#));
        assert!(json.contains(r#""externalParameters""#));
        assert!(json.contains(r#""specDigest""#));
        assert!(json.contains(r#""resolvedDependencies""#));
        assert!(json.contains(r#""runDetails""#));
        assert!(json.contains(r#""startedOn""#));
        assert!(json.contains(r#""finishedOn""#));

        // Round-trip.
        let _back: SlsaProvenance = serde_json::from_str(&json).unwrap();
    }
}
