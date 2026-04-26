//! `OciPusher` — [`ImagePublisher`]-shaped impl for ADR-015
//! **Level 4** (OCI distribution spec).
//!
//! Packages the four build artifacts (kernel, initrd, optionally
//! rootfs, config.json) as an OCI artifact manifest with the
//! vmisolate-specific media types from ADR-015 §"Manifest schema",
//! and pushes them to any OCI-compliant registry (GHCR, Harbor,
//! ECR, Quay, Docker Hub, …) via the `oci-distribution` crate.
//!
//! Auth is discovered from the environment —
//! `OCIMAGE_REGISTRY_USER` and `OCIMAGE_REGISTRY_PASSWORD` for
//! basic auth, anonymous otherwise. Token-exchange / OIDC live
//! inside `oci-distribution` and are transparent from here.
//!
//! The push itself is async; the sync `saf::push_oci` facade drives
//! a single-shot `tokio::runtime::Runtime` to call into it. That
//! keeps the async plumbing contained to the SPI layer, matching
//! the convention the rest of the crate follows.
//!
//! **Phase 2f-β scope**: blobs are loaded fully into memory before
//! push. For a rootfs-less initrd image that's a few tens of MiB;
//! even a 512 MiB rootfs fits on any reasonable build host. Streaming
//! uploads land when someone shows up pushing multi-GiB images —
//! the `oci-distribution` chunked-upload path supports it, the
//! `BuildArtifacts` -> `ImageLayer` conversion here does not.

use std::env;
use std::fs;

use oci_distribution::client::{Client, ClientConfig, ClientProtocol, Config, ImageLayer};
use oci_distribution::errors::OciDistributionError;
use oci_distribution::manifest::{OciImageManifest, OCI_IMAGE_MEDIA_TYPE};
use oci_distribution::secrets::RegistryAuth;
use oci_distribution::Reference;
use sha2::{Digest, Sha256};

use oci_build::api::error::Error;
use oci_build::api::spec::BuildArtifacts;
use crate::saf::OciPushSummary;

/// Media type for the kernel blob layer. ADR-015 §"Manifest schema".
pub(crate) const KERNEL_MEDIA_TYPE: &str =
    "application/vnd.xkvm.vm-image.kernel.v1";
/// Media type for the initrd blob layer. ADR-015 §"Manifest schema".
pub(crate) const INITRD_MEDIA_TYPE: &str =
    "application/vnd.xkvm.vm-image.initrd.v1";
/// Media type for the rootfs blob layer. ADR-015 §"Manifest schema".
pub(crate) const ROOTFS_MEDIA_TYPE: &str =
    "application/vnd.xkvm.vm-image.rootfs.v1";
/// Media type for the config blob (NOT a layer — the manifest's
/// `config` descriptor). ADR-015 §"Manifest schema".
pub(crate) const CONFIG_MEDIA_TYPE: &str =
    "application/vnd.xkvm.vm-image.config.v1+json";
/// Artifact type advertised on the OCI manifest. Distinguishes
/// a vmisolate VM image from ordinary container images when a
/// registry lists artifacts. ADR-015 §"Manifest schema".
pub(crate) const ARTIFACT_TYPE: &str = "application/vnd.xkvm.vm-image.v1+json";

/// Environment variable that carries the basic-auth username.
const ENV_USER: &str = "OCIMAGE_REGISTRY_USER";
/// Environment variable that carries the basic-auth password.
const ENV_PASSWORD: &str = "OCIMAGE_REGISTRY_PASSWORD";

/// Pushes built image artifacts to an OCI-distribution registry.
///
/// One instance is cheap to construct — it carries an auth
/// credential only, the underlying `oci_distribution::Client` is
/// built lazily inside [`OciPusher::push`] so each call gets a
/// fresh TLS connection pool.
pub struct OciPusher {
    /// Credential applied to every push this instance performs.
    /// Resolved once at construction time from the process env —
    /// callers who want to rotate credentials should build a new
    /// `OciPusher`.
    auth: RegistryAuth,
}

impl OciPusher {
    /// Build a new `OciPusher` with auth resolved from the
    /// `OCIMAGE_REGISTRY_USER` + `OCIMAGE_REGISTRY_PASSWORD` env
    /// vars. Both unset (or either one empty) ⇒ `RegistryAuth::Anonymous`.
    ///
    /// Anonymous is fine for public registries and for CI scripts
    /// that use a short-lived bearer token via a different auth
    /// layer; the v0.11 `oci-distribution` client negotiates the
    /// WWW-Authenticate header transparently from there.
    pub fn new() -> Self {
        let auth = match (env::var(ENV_USER).ok(), env::var(ENV_PASSWORD).ok()) {
            (Some(u), Some(p)) if !u.is_empty() && !p.is_empty() => {
                RegistryAuth::Basic(u, p)
            }
            _ => RegistryAuth::Anonymous,
        };
        Self { auth }
    }

    /// Push the contents of `artifacts` to `reference`.
    ///
    /// `reference` must be a fully-qualified OCI reference —
    /// `host[:port]/namespace/name:tag` (e.g.
    /// `ghcr.io/acme/vmisolate-alpine:3.20`). A parse failure is
    /// mapped to [`Error::Publish`] (user-caused, not a transport
    /// failure).
    ///
    /// Returns the reference echoed, the sha256 of the uploaded
    /// manifest, and the **approximate** bytes transferred. The byte
    /// count is `layers + config` — it cannot cheaply distinguish
    /// cross-mounted blobs from actually-transferred blobs without
    /// an extra round trip, so we report the honest upper bound.
    pub async fn push(
        &self,
        artifacts: &BuildArtifacts,
        reference: &str,
    ) -> Result<OciPushSummary, Error> {
        // Step 1: parse the reference. A bad reference is a user
        // error, not a transport failure — map it to Publish so
        // CLI callers can tell the two classes apart.
        let parsed: Reference = Reference::try_from(reference).map_err(|e| {
            Error::Publish {
                reason: format!("invalid reference '{}': {}", reference, e),
            }
        })?;

        // Step 2: load the blobs. Small enough to fit in memory —
        // streaming is a later optimisation (see module doc).
        let kernel_bytes = fs::read(&artifacts.kernel_path)?;
        let initrd_bytes = fs::read(&artifacts.initrd_path)?;
        let config_bytes = fs::read(&artifacts.config_path)?;
        let rootfs_bytes = match &artifacts.rootfs_path {
            Some(p) => Some(fs::read(p)?),
            None => None,
        };

        // Step 3: assemble the OCI wire shapes. Order matters —
        // ADR-015 lists kernel, initrd, rootfs so that's the layer
        // order in the manifest too.
        let mut layers = Vec::with_capacity(3);
        let mut layer_bytes_total: u64 = 0;

        layer_bytes_total += kernel_bytes.len() as u64;
        layers.push(ImageLayer::new(
            kernel_bytes,
            KERNEL_MEDIA_TYPE.to_string(),
            None,
        ));

        layer_bytes_total += initrd_bytes.len() as u64;
        layers.push(ImageLayer::new(
            initrd_bytes,
            INITRD_MEDIA_TYPE.to_string(),
            None,
        ));

        if let Some(bytes) = rootfs_bytes {
            layer_bytes_total += bytes.len() as u64;
            layers.push(ImageLayer::new(
                bytes,
                ROOTFS_MEDIA_TYPE.to_string(),
                None,
            ));
        }

        let config_size = config_bytes.len() as u64;
        let config = Config::new(config_bytes, CONFIG_MEDIA_TYPE.to_string(), None);

        let manifest = build_manifest(&layers, &config);

        // Step 4: compute the manifest digest locally. The
        // registry returns the manifest URL on success but not
        // the digest; we need to hash the exact bytes we'll
        // serialise onto the wire.
        let manifest_digest = sha256_digest_of_manifest(&manifest)?;

        // Step 5: push. ClientConfig::default() gets rustls via
        // the feature flag we turned on in Cargo.toml. Cloning
        // auth on each call is cheap (two short strings) and
        // keeps `self` borrow-immutable for the async call.
        //
        // `OCIMAGE_ALLOW_INSECURE=1` flips the client to plain
        // HTTP — escape hatch for local `registry:2` testing.
        // Production usage (GHCR, Harbor, ECR) stays HTTPS.
        let client = Client::new(client_config_from_env());
        client
            .push(&parsed, &layers, config, &self.auth, Some(manifest))
            .await
            .map_err(|e| map_oci_error(e, &parsed))?;

        Ok(OciPushSummary {
            reference: reference.to_string(),
            manifest_digest,
            bytes_pushed: layer_bytes_total + config_size,
        })
    }
}

impl Default for OciPusher {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the oci-distribution `ClientConfig`, honouring
/// `OCIMAGE_ALLOW_INSECURE=1` as an explicit opt-in to plain HTTP.
///
/// We intentionally don't support a granular insecure-registry list
/// (like docker's `--insecure-registry`); the only caller is CI / dev
/// testing against a local `registry:2`, where "HTTP everywhere" is
/// exactly what's wanted. Any non-empty value other than `1` is
/// ignored so stray truthy strings don't surprise operators.
fn client_config_from_env() -> ClientConfig {
    let allow_insecure = std::env::var("OCIMAGE_ALLOW_INSECURE")
        .map(|v| v == "1")
        .unwrap_or(false);
    if allow_insecure {
        ClientConfig {
            protocol: ClientProtocol::Http,
            ..ClientConfig::default()
        }
    } else {
        ClientConfig::default()
    }
}

/// Build the ADR-015 OCI image manifest from the already-constructed
/// layers + config. Factored out of `push` so unit tests can call
/// it without a live registry.
///
/// Sets `mediaType = application/vnd.oci.image.manifest.v1+json`
/// (the `oci-distribution` default leaves it `None`, which some
/// registries reject) and `artifactType` to the vmisolate marker.
pub(crate) fn build_manifest(
    layers: &[ImageLayer],
    config: &Config,
) -> OciImageManifest {
    let mut manifest = OciImageManifest::build(layers, config, None);
    manifest.media_type = Some(OCI_IMAGE_MEDIA_TYPE.to_string());
    manifest.artifact_type = Some(ARTIFACT_TYPE.to_string());
    manifest
}

/// Serialise a manifest to JSON and return its `sha256:<hex>`
/// digest. Same algorithm the registry uses to address it.
fn sha256_digest_of_manifest(manifest: &OciImageManifest) -> Result<String, Error> {
    let bytes = serde_json::to_vec(manifest)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

/// Map an `OciDistributionError` into our crate's `Error`.
///
/// The classification split ADR-015 cares about is:
///
///   * transport / network / 5xx / TLS — `RegistryUnreachable`
///   * auth / 401 / 403 — `Publish` ("authentication failed")
///   * manifest rejected / spec violations — `Publish` (bubble through)
///
/// which lets CLI callers tell "the registry is down" from "my
/// image is wrong" without parsing the error text.
fn map_oci_error(e: OciDistributionError, reference: &Reference) -> Error {
    let registry = reference.registry().to_string();
    match e {
        OciDistributionError::AuthenticationFailure(_)
        | OciDistributionError::UnauthorizedError { .. } => Error::Publish {
            reason: format!("authentication failed: {}", e),
        },

        OciDistributionError::RequestError(_)
        | OciDistributionError::IoError(_)
        | OciDistributionError::HeaderValueError(_)
        | OciDistributionError::UrlParseError(_) => Error::RegistryUnreachable {
            registry,
            reason: e.to_string(),
        },

        OciDistributionError::ServerError { code, .. } if (500..600).contains(&code) => {
            Error::RegistryUnreachable {
                registry,
                reason: e.to_string(),
            }
        }

        // Everything else — ManifestInvalid, SpecViolation, etc. —
        // is the user's image being wrong. Keep the original
        // message verbatim so operators see what the registry said.
        _ => Error::Publish { reason: e.to_string() },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Guards env-var mutation between tests 4 and any future
    /// env-reading test. `std::env::set_var` is process-global;
    /// running two such tests in parallel on the same process
    /// flakes. `cargo test` runs tests concurrently by default.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    // ---- test 1 -----------------------------------------------------
    // Catches: a regression where we start rewriting references
    // before handing them to oci-distribution (e.g. lower-casing,
    // auto-prefixing docker.io). The ADR says "tenants reference
    // images by the exact string they typed."
    #[test]
    fn test_reference_parsing_accepts_standard_form() {
        let r = Reference::try_from("ghcr.io/acme/alpine:3.20")
            .expect("ghcr reference should parse");
        assert_eq!(r.registry(), "ghcr.io");
        assert_eq!(r.repository(), "acme/alpine");
        assert_eq!(r.tag(), Some("3.20"));
    }

    // ---- test 2 -----------------------------------------------------
    // Catches: someone flipping the media-type strings (typo,
    // copy/paste from docker.* to oci.*, dropping `.v1`), or
    // removing `artifactType` (which breaks ADR-015 §"Manifest
    // schema"). The JSON-round-trip-then-re-parse asserts against
    // the bytes that actually go over the wire, not a Rust struct
    // shape — this is what a registry sees.
    #[test]
    fn test_manifest_has_correct_artifact_type_and_media_types() {
        let layers = vec![
            ImageLayer::new(b"kernel".to_vec(), KERNEL_MEDIA_TYPE.into(), None),
            ImageLayer::new(b"initrd".to_vec(), INITRD_MEDIA_TYPE.into(), None),
            ImageLayer::new(b"rootfs".to_vec(), ROOTFS_MEDIA_TYPE.into(), None),
        ];
        let config = Config::new(b"{}".to_vec(), CONFIG_MEDIA_TYPE.into(), None);

        let manifest = build_manifest(&layers, &config);
        let json = serde_json::to_string(&manifest).expect("serialise manifest");
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("re-parse manifest");

        assert_eq!(
            parsed["mediaType"].as_str(),
            Some("application/vnd.oci.image.manifest.v1+json"),
            "OCI manifest mediaType is load-bearing — some registries reject omissions",
        );
        assert_eq!(
            parsed["artifactType"].as_str(),
            Some(ARTIFACT_TYPE),
            "artifactType identifies vmisolate images in registry UIs",
        );
        assert_eq!(parsed["schemaVersion"].as_i64(), Some(2));

        let layers_json = parsed["layers"].as_array().expect("layers is an array");
        assert_eq!(layers_json.len(), 3, "kernel + initrd + rootfs");
        assert_eq!(
            layers_json[0]["mediaType"].as_str(),
            Some(KERNEL_MEDIA_TYPE)
        );
        assert_eq!(
            layers_json[1]["mediaType"].as_str(),
            Some(INITRD_MEDIA_TYPE)
        );
        assert_eq!(
            layers_json[2]["mediaType"].as_str(),
            Some(ROOTFS_MEDIA_TYPE)
        );

        assert_eq!(
            parsed["config"]["mediaType"].as_str(),
            Some(CONFIG_MEDIA_TYPE),
        );
        // Size + digest must be populated — an OCI registry
        // rejects descriptors with size == 0 unless the blob is
        // genuinely empty. `{}` is 2 bytes.
        assert_eq!(parsed["config"]["size"].as_i64(), Some(2));
        assert!(
            parsed["config"]["digest"]
                .as_str()
                .unwrap()
                .starts_with("sha256:"),
            "config descriptor must carry a sha256 digest",
        );
    }

    // ---- test 3 -----------------------------------------------------
    // Catches: someone unconditionally pushing a rootfs layer
    // (e.g. a `.unwrap_or_default()` on an Option), which would
    // emit an empty-blob layer with the rootfs media type. ADR-015
    // lists rootfs as optional — an initrd-only image must not
    // carry a phantom rootfs descriptor.
    #[test]
    fn test_manifest_omits_rootfs_layer_when_no_rootfs() {
        let layers = vec![
            ImageLayer::new(b"kernel".to_vec(), KERNEL_MEDIA_TYPE.into(), None),
            ImageLayer::new(b"initrd".to_vec(), INITRD_MEDIA_TYPE.into(), None),
        ];
        let config = Config::new(b"{}".to_vec(), CONFIG_MEDIA_TYPE.into(), None);

        let manifest = build_manifest(&layers, &config);
        let json = serde_json::to_string(&manifest).expect("serialise manifest");
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("re-parse manifest");

        let layers_json = parsed["layers"].as_array().expect("layers is an array");
        assert_eq!(
            layers_json.len(),
            2,
            "initrd-only image must have exactly 2 layers, not 3",
        );
        // And specifically — not a rootfs media type.
        for l in layers_json {
            assert_ne!(l["mediaType"].as_str(), Some(ROOTFS_MEDIA_TYPE));
        }
    }

    // ---- test 4 -----------------------------------------------------
    // Catches: a regression where OciPusher::new stops reading
    // env vars (e.g. hard-codes Anonymous). Combines both cases
    // (set + unset) in one test so the env-var mutation is
    // serialised by ENV_LOCK and no cross-test flakes exist.
    #[test]
    fn test_new_reads_basic_auth_from_env_when_set() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());

        // Snapshot + clear so a dirty caller env can't bleed in.
        let prev_user = env::var(ENV_USER).ok();
        let prev_pass = env::var(ENV_PASSWORD).ok();
        env::remove_var(ENV_USER);
        env::remove_var(ENV_PASSWORD);

        // Unset ⇒ Anonymous.
        let anon = OciPusher::new();
        assert_eq!(
            anon.auth,
            RegistryAuth::Anonymous,
            "missing creds must not silently authenticate",
        );

        // Set ⇒ Basic.
        env::set_var(ENV_USER, "u");
        env::set_var(ENV_PASSWORD, "p");
        let basic = OciPusher::new();
        assert_eq!(basic.auth, RegistryAuth::Basic("u".into(), "p".into()));

        // Empty-string creds ⇒ Anonymous (don't authenticate with
        // a blank username — some registries accept it and bind
        // a real session).
        env::set_var(ENV_USER, "");
        env::set_var(ENV_PASSWORD, "p");
        let blank = OciPusher::new();
        assert_eq!(
            blank.auth,
            RegistryAuth::Anonymous,
            "blank username must not authenticate",
        );

        // Restore so sibling tests see the previous env.
        env::remove_var(ENV_USER);
        env::remove_var(ENV_PASSWORD);
        if let Some(v) = prev_user {
            env::set_var(ENV_USER, v);
        }
        if let Some(v) = prev_pass {
            env::set_var(ENV_PASSWORD, v);
        }
    }

    // ---- supporting test --------------------------------------------
    // Catches: a refactor that changes how the manifest is
    // serialised but forgets to keep the digest calculation in
    // sync. The digest must be the sha256 of the exact bytes we
    // serialise.
    #[test]
    fn test_sha256_digest_of_manifest_matches_manual_hash() {
        let layers = vec![ImageLayer::new(
            b"x".to_vec(),
            KERNEL_MEDIA_TYPE.into(),
            None,
        )];
        let config = Config::new(b"{}".to_vec(), CONFIG_MEDIA_TYPE.into(), None);
        let manifest = build_manifest(&layers, &config);

        let bytes = serde_json::to_vec(&manifest).unwrap();
        let expected = {
            let mut h = Sha256::new();
            h.update(&bytes);
            format!("sha256:{:x}", h.finalize())
        };

        assert_eq!(sha256_digest_of_manifest(&manifest).unwrap(), expected);
    }

    // ---- error-mapping test -----------------------------------------
    // Catches: someone flattening all OciDistributionError
    // variants into a single Publish error — which erases the
    // "registry is down" vs "my image is wrong" distinction
    // ADR-015 mandates.
    #[test]
    fn test_map_oci_error_classifies_unauthorized_as_publish() {
        let r = Reference::try_from("ghcr.io/acme/x:1").unwrap();
        let e = OciDistributionError::UnauthorizedError {
            url: "https://ghcr.io/v2/acme/x/blobs/uploads/".into(),
        };
        match map_oci_error(e, &r) {
            Error::Publish { reason } => assert!(reason.contains("authentication failed")),
            other => panic!("expected Publish, got {:?}", other),
        }
    }

    #[test]
    fn test_map_oci_error_classifies_server_5xx_as_unreachable() {
        let r = Reference::try_from("ghcr.io/acme/x:1").unwrap();
        let e = OciDistributionError::ServerError {
            code: 503,
            url: "https://ghcr.io/v2/acme/x/manifests/1".into(),
            message: "service unavailable".into(),
        };
        match map_oci_error(e, &r) {
            Error::RegistryUnreachable { registry, .. } => {
                assert_eq!(registry, "ghcr.io")
            }
            other => panic!("expected RegistryUnreachable, got {:?}", other),
        }
    }

    #[test]
    fn test_map_oci_error_classifies_manifest_invalid_as_publish() {
        let r = Reference::try_from("ghcr.io/acme/x:1").unwrap();
        let e =
            OciDistributionError::SpecViolationError("manifest rejected".into());
        match map_oci_error(e, &r) {
            Error::Publish { reason } => assert!(reason.contains("manifest rejected")),
            other => panic!("expected Publish, got {:?}", other),
        }
    }

    // ---- tests 10-12 — env-gated HTTP opt-in ------------------------
    // Catches: (a) someone deleting the `OCIMAGE_ALLOW_INSECURE`
    // branch and leaving local `registry:2` tests unrunnable, (b)
    // someone widening the env match to `truthy` strings and
    // quietly flipping production pushes to HTTP. The
    // "only literal '1' counts" semantics is a deliberate safety
    // choice; documenting it with a test locks it in.
    #[test]
    fn test_client_config_from_env_default_is_https() {
        let _guard = ENV_LOCK.lock().unwrap();
        let prev = std::env::var("OCIMAGE_ALLOW_INSECURE").ok();
        std::env::remove_var("OCIMAGE_ALLOW_INSECURE");

        assert!(matches!(
            client_config_from_env().protocol,
            ClientProtocol::Https | ClientProtocol::HttpsExcept(_)
        ));

        match prev {
            Some(v) => std::env::set_var("OCIMAGE_ALLOW_INSECURE", v),
            None => std::env::remove_var("OCIMAGE_ALLOW_INSECURE"),
        }
    }

    #[test]
    fn test_client_config_from_env_opt_in_flips_to_http() {
        let _guard = ENV_LOCK.lock().unwrap();
        let prev = std::env::var("OCIMAGE_ALLOW_INSECURE").ok();
        std::env::set_var("OCIMAGE_ALLOW_INSECURE", "1");

        assert!(matches!(
            client_config_from_env().protocol,
            ClientProtocol::Http
        ));

        match prev {
            Some(v) => std::env::set_var("OCIMAGE_ALLOW_INSECURE", v),
            None => std::env::remove_var("OCIMAGE_ALLOW_INSECURE"),
        }
    }

    #[test]
    fn test_client_config_from_env_non_one_values_stay_https() {
        let _guard = ENV_LOCK.lock().unwrap();
        let prev = std::env::var("OCIMAGE_ALLOW_INSECURE").ok();

        for truthy in ["true", "yes", "on", "0", ""] {
            std::env::set_var("OCIMAGE_ALLOW_INSECURE", truthy);
            assert!(
                matches!(
                    client_config_from_env().protocol,
                    ClientProtocol::Https | ClientProtocol::HttpsExcept(_)
                ),
                "value {truthy:?} must NOT enable insecure mode"
            );
        }

        match prev {
            Some(v) => std::env::set_var("OCIMAGE_ALLOW_INSECURE", v),
            None => std::env::remove_var("OCIMAGE_ALLOW_INSECURE"),
        }
    }
}
