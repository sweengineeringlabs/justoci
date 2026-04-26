//! Asserts CycloneDX SBOM enumerates one component per layer when
//! `scope = "layers"`.
//!
//! Bug this catches: an SBOM emitter that under-counts components
//! (fencepost error, scope check inverted) would let layers escape
//! the SBOM, defeating the SBOM's whole reason to exist.

mod common;

use cas::{Cas, FsCas};
use spec::SbomScope;
use tempfile::TempDir;

use attest::core::sbom_cyclonedx::emit_cyclonedx;

#[test]
fn test_cyclonedx_layers_scope_emits_one_component_per_layer() {
    let (built, _spec_tmp) = common::make_built_artifact();
    let cas_root = TempDir::new().expect("tempdir");
    let cas = FsCas::new(cas_root.path()).expect("FsCas");

    let sbom = emit_cyclonedx(&built, SbomScope::Layers, &cas).expect("emit");

    let bytes = cas.get(&sbom.blob_digest).expect("CAS get");
    let v: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON");

    let comps = v["components"].as_array().expect("components is array");
    assert_eq!(
        comps.len(),
        built.layer_digests.len(),
        "one component per layer in Layers scope"
    );
}

#[test]
fn test_cyclonedx_layer_components_carry_layer_digest_in_hashes() {
    // Bug this catches: a component lacking the layer's sha256 in
    // its `hashes` block makes the SBOM useless for tamper checks.
    let (built, _spec_tmp) = common::make_built_artifact();
    let cas_root = TempDir::new().expect("tempdir");
    let cas = FsCas::new(cas_root.path()).expect("FsCas");

    let sbom = emit_cyclonedx(&built, SbomScope::Layers, &cas).expect("emit");
    let bytes = cas.get(&sbom.blob_digest).expect("CAS get");
    let v: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON");

    let comps = v["components"].as_array().expect("components");
    for ((_idx, digest), comp) in built.layer_digests.iter().zip(comps.iter()) {
        let hashes = comp["hashes"].as_array().expect("hashes is array");
        assert!(
            hashes
                .iter()
                .any(|h| h["alg"] == "SHA-256" && h["content"] == digest.hex()),
            "component must carry sha256 hash matching layer digest"
        );
    }
}

#[test]
fn test_cyclonedx_root_metadata_describes_artifact() {
    // Bug this catches: a missing or wrong metadata.component leaves
    // the SBOM unbound to the artifact — verifiers can't tell which
    // image the SBOM is about.
    let (built, _spec_tmp) = common::make_built_artifact();
    let cas_root = TempDir::new().expect("tempdir");
    let cas = FsCas::new(cas_root.path()).expect("FsCas");

    let sbom = emit_cyclonedx(&built, SbomScope::Layers, &cas).expect("emit");
    let bytes = cas.get(&sbom.blob_digest).expect("CAS get");
    let v: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON");

    assert_eq!(v["bomFormat"], "CycloneDX");
    assert_eq!(v["specVersion"], "1.5");
    assert_eq!(v["metadata"]["component"]["name"], "demo");
    assert_eq!(v["metadata"]["component"]["version"], "1.0");
    let mhash = v["metadata"]["component"]["hashes"][0]["content"]
        .as_str()
        .expect("manifest hash present");
    assert_eq!(mhash, built.manifest_digest.hex());
}
