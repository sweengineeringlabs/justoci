//! Assemble the OCI image config blob and the OCI manifest from a
//! validated `Spec` plus already-written layer descriptors.
//!
//! Both blobs are written to the CAS so that:
//!
//! 1. The descriptor in the index/manifest references a digest that
//!    actually corresponds to the bytes we wrote.
//! 2. Failed builds leave nothing visible in the CAS — partial
//!    config / manifest writes are dropped by the CAS atomicity
//!    contract.
//!
//! ## Determinism
//!
//! Both blobs serialise via `serde_json::to_vec` (no
//! `to_vec_pretty`). The OCI spec doesn't require canonical JSON
//! for the manifest, but `serde_json::to_vec` with our struct
//! definitions emits stable bytes for a given input — that's what
//! Production-Guarantees-§2 needs. `BTreeMap` for annotations,
//! `Option<T> + skip_serializing_if = "Option::is_none"` for absent
//! fields (so omitted fields don't churn the digest).

use cas::{Cas, Digest};
use spec::{Kind, Spec};

use crate::api::build_error::BuildError;
use crate::api::oci_manifest::{
    OciDescriptor, OciImageConfig, OciManifest, OciRuntimeConfig, MEDIA_TYPE_OCI_CONFIG,
    MEDIA_TYPE_OCI_MANIFEST,
};

/// Result of writing the config + manifest blobs.
pub struct AssembledManifest {
    pub config_digest: Digest,
    pub manifest_digest: Digest,
    pub manifest_descriptor: OciDescriptor,
}

/// Build the OCI image config from `spec.config` + `spec.platform`,
/// write it to the CAS, then build the OCI manifest pointing at the
/// config + the layer descriptors and write it too.
///
/// `layer_descriptors` is the full list of layer descriptors in
/// spec-declared order (i.e. the order of `spec.layers`).
pub fn assemble_config_and_manifest(
    spec: &Spec,
    layer_descriptors: Vec<OciDescriptor>,
    cas: &dyn Cas,
) -> Result<AssembledManifest, BuildError> {
    // ── Image config blob ────────────────────────────────────────
    let config = build_image_config(spec);
    let config_bytes = serde_json::to_vec(&config).map_err(|source| BuildError::Json { source })?;
    let config_size = config_bytes.len() as u64;
    let config_digest = cas
        .put(&config_bytes)
        .map_err(|source| BuildError::ManifestWrite { source })?;

    // ── OCI manifest ────────────────────────────────────────────
    let manifest = OciManifest {
        schema_version: 2,
        media_type: MEDIA_TYPE_OCI_MANIFEST.to_string(),
        config: OciDescriptor {
            media_type: MEDIA_TYPE_OCI_CONFIG.to_string(),
            digest: config_digest.to_string(),
            size: config_size,
            annotations: Default::default(),
        },
        layers: layer_descriptors,
        annotations: spec.annotations.clone(),
    };

    let manifest_bytes =
        serde_json::to_vec(&manifest).map_err(|source| BuildError::Json { source })?;
    let manifest_size = manifest_bytes.len() as u64;
    let manifest_digest = cas
        .put(&manifest_bytes)
        .map_err(|source| BuildError::ManifestWrite { source })?;

    let manifest_descriptor = OciDescriptor {
        media_type: MEDIA_TYPE_OCI_MANIFEST.to_string(),
        digest: manifest_digest.to_string(),
        size: manifest_size,
        annotations: Default::default(),
    };

    Ok(AssembledManifest {
        config_digest,
        manifest_digest,
        manifest_descriptor,
    })
}

/// Build the OCI image config blob from a `Spec`.
///
/// The OS / architecture come from `spec.platform`; if missing,
/// default to `"unknown"` per OCI 1.1's allowed value for
/// "no information." We don't fabricate `linux/amd64` because
/// that would silently misclassify a `raw_image` firmware artifact
/// as a Linux container.
///
/// `[config]` keys land in the `extra` map verbatim. Specific keys
/// the OCI runtime understands (`entrypoint`, `env`, `labels`) are
/// also lifted into `OciRuntimeConfig` so a Docker / containerd
/// consumer that doesn't read `extra` still sees them.
pub fn build_image_config(spec: &Spec) -> OciImageConfig {
    let architecture = spec
        .platform
        .arch
        .clone()
        .unwrap_or_else(|| "unknown".to_string());
    let os = spec
        .platform
        .os
        .clone()
        .unwrap_or_else(|| "unknown".to_string());

    // Lift OCI-runtime-aware keys from `[config]`.
    let mut runtime = OciRuntimeConfig {
        env: vec![],
        entrypoint: vec![],
        cmd: vec![],
        labels: Default::default(),
    };
    let mut extra: std::collections::BTreeMap<String, serde_json::Value> = Default::default();

    if let serde_json::Value::Object(map) = &spec.config.0 {
        for (k, v) in map.iter() {
            match k.as_str() {
                "entrypoint" => {
                    runtime.entrypoint = string_array(v);
                }
                "cmd" => {
                    runtime.cmd = string_array(v);
                }
                "env" => {
                    if let serde_json::Value::Object(env_map) = v {
                        runtime.env = env_map
                            .iter()
                            .filter_map(|(ek, ev)| ev.as_str().map(|s| format!("{ek}={s}")))
                            .collect();
                        // Sort so the manifest digest doesn't depend
                        // on serde_json::Map's iteration order.
                        runtime.env.sort();
                    }
                }
                "labels" => {
                    if let serde_json::Value::Object(label_map) = v {
                        runtime.labels = label_map
                            .iter()
                            .filter_map(|(lk, lv)| lv.as_str().map(|s| (lk.clone(), s.to_string())))
                            .collect();
                    }
                }
                _ => {
                    extra.insert(k.clone(), v.clone());
                }
            }
        }
    }

    let runtime_opt = if runtime.env.is_empty()
        && runtime.entrypoint.is_empty()
        && runtime.cmd.is_empty()
        && runtime.labels.is_empty()
    {
        None
    } else {
        Some(runtime)
    };

    OciImageConfig {
        architecture,
        os,
        config: runtime_opt,
        extra,
    }
}

fn string_array(v: &serde_json::Value) -> Vec<String> {
    match v {
        serde_json::Value::Array(items) => items
            .iter()
            .filter_map(|i| i.as_str().map(String::from))
            .collect(),
        _ => vec![],
    }
}

/// Sanity check called from the build entry point: a `vm_image` must
/// have 3 layer descriptors, a `raw_image` exactly 1. The spec
/// validator already enforces this on the input `Spec`, but we re-
/// check after layer assembly to defend against a future refactor
/// that drops a layer between input and output.
pub fn check_layer_count_post_assembly(kind: Kind, actual: usize) -> Result<(), BuildError> {
    let (expected, ok) = match kind {
        Kind::OciArtifact => (">=1", actual >= 1),
        Kind::VmImage => ("3", actual == 3),
        Kind::RawImage => ("1", actual == 1),
    };
    if ok {
        Ok(())
    } else {
        Err(BuildError::Spec(spec::SpecError::WrongLayerCount {
            kind: kind.as_str(),
            expected,
            actual,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spec::ConfigBlob;

    fn parse_spec(toml_text: &str, dir: &std::path::Path) -> Spec {
        spec::parse_and_validate_str(toml_text, dir.to_path_buf())
            .expect("test spec must validate")
            .spec
    }

    #[test]
    fn test_image_config_unknown_platform_does_not_lie() {
        // Bug this would catch: defaulting to "linux"/"amd64" when
        // the spec has no [platform] — would mislabel a bare-metal
        // firmware artifact as a Linux container.
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("blob.bin"), b"x").unwrap();
        let s = parse_spec(
            r#"
spec_version = "0"
id = "fw:1"
kind = "raw_image"
[[layers]]
source = "blob.bin"
media_type = "application/vnd.example.firmware+binary"
"#,
            tmp.path(),
        );

        let cfg = build_image_config(&s);
        assert_eq!(cfg.architecture, "unknown");
        assert_eq!(cfg.os, "unknown");
    }

    #[test]
    fn test_image_config_lifts_entrypoint_into_runtime() {
        // Bug this would catch: `entrypoint` stuck in `extra` and
        // not lifted to `OciRuntimeConfig` — Docker/containerd
        // consumers that read only the OCI runtime block would not
        // see the entrypoint.
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("k"), b"k").unwrap();
        std::fs::write(tmp.path().join("i"), b"i").unwrap();
        std::fs::write(tmp.path().join("r"), b"r").unwrap();

        let s = parse_spec(
            r#"
spec_version = "0"
id = "x:1"
kind = "vm_image"
[platform]
os = "linux"
arch = "x86_64"
[[layers]]
source = "k"
media_type = "application/vnd.vmisolate.kernel+binary"
[[layers]]
source = "i"
media_type = "application/vnd.vmisolate.initrd+gzip"
compression = "gzip"
[[layers]]
source = "r"
media_type = "application/vnd.vmisolate.rootfs+gzip"
compression = "gzip"
[config]
entrypoint = ["/usr/bin/llmd", "serve"]
"#,
            tmp.path(),
        );
        let cfg = build_image_config(&s);
        assert_eq!(cfg.architecture, "x86_64");
        assert_eq!(cfg.os, "linux");
        let runtime = cfg.config.expect("runtime config present");
        assert_eq!(runtime.entrypoint, vec!["/usr/bin/llmd", "serve"]);
    }

    #[test]
    fn test_image_config_env_serialises_as_key_equals_value_strings() {
        // Bug this would catch: emitting `Env` as a JSON object
        // (Docker-pre-OCI shape) — OCI 1.1 mandates a string array
        // of `KEY=VALUE`. Wrong shape = consumers ignore env entirely.
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("blob"), b"x").unwrap();

        let s = parse_spec(
            r#"
spec_version = "0"
id = "x:1"
kind = "raw_image"
[[layers]]
source = "blob"
media_type = "application/vnd.example.firmware+binary"
[config]
env = { RUST_LOG = "info", HOME = "/root" }
"#,
            tmp.path(),
        );

        let cfg = build_image_config(&s);
        let runtime = cfg.config.expect("env present");
        // Sorted to make the test deterministic; the impl sorts too.
        assert_eq!(
            runtime.env,
            vec!["HOME=/root".to_string(), "RUST_LOG=info".to_string()]
        );
    }

    #[test]
    fn test_image_config_unknown_keys_land_in_extra_verbatim() {
        // Bug this would catch: a refactor that drops keys it doesn't
        // recognise. The spec doc commits to passing unknown
        // `[config]` keys through verbatim — `init_mode`,
        // `kernel_cmdline`, vendor-specific keys — so consumers
        // can read them.
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("blob"), b"x").unwrap();

        let s = parse_spec(
            r#"
spec_version = "0"
id = "x:1"
kind = "raw_image"
[[layers]]
source = "blob"
media_type = "application/vnd.example.firmware+binary"
[config]
init_mode = "xkinit"
kernel_cmdline = "console=ttyS0"
"#,
            tmp.path(),
        );
        let cfg = build_image_config(&s);
        assert_eq!(
            cfg.extra.get("init_mode"),
            Some(&serde_json::Value::String("xkinit".into()))
        );
        assert_eq!(
            cfg.extra.get("kernel_cmdline"),
            Some(&serde_json::Value::String("console=ttyS0".into()))
        );
    }

    #[test]
    fn test_default_config_blob_produces_no_runtime_block() {
        // Bug this would catch: emitting an empty `OciRuntimeConfig`
        // with `Some(empty_struct)` rather than `None` — perturbs
        // the config JSON and the digest for every spec without a
        // `[config]` runtime block.
        let _ = ConfigBlob::default();
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("blob"), b"x").unwrap();
        let s = parse_spec(
            r#"
spec_version = "0"
id = "x:1"
kind = "raw_image"
[[layers]]
source = "blob"
media_type = "application/vnd.example.firmware+binary"
"#,
            tmp.path(),
        );
        let cfg = build_image_config(&s);
        assert!(cfg.config.is_none());
    }
}
