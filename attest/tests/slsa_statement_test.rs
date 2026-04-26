//! Asserts the shape of the SLSA Provenance v1 statement we emit.
//!
//! Bug this catches: a SLSA emitter that left out `subject`,
//! `predicate.buildDefinition.externalParameters.spec_hash`, or any
//! `resolvedDependencies` entry would fail downstream
//! `cosign verify-attestation` / SLSA-verifier validation. We assert
//! the structural pieces a verifier inspects.

mod common;

use cas::{Cas, FsCas};
use spec::SlsaConfig;
use tempfile::TempDir;

use attest::core::slsa::emit_slsa;

#[test]
fn test_emit_slsa_statement_has_required_inttoto_fields() {
    let (built, _spec_tmp) = common::make_built_artifact();
    let cas_root = TempDir::new().expect("cas tempdir");
    let cas = FsCas::new(cas_root.path()).expect("FsCas");

    let stmt = emit_slsa(&built, &SlsaConfig::default(), &cas)
        .expect("emit ok")
        .expect("level=L2 produces a statement");

    let bytes = cas.get(&stmt.blob_digest).expect("retrievable from CAS");
    let v: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");

    assert_eq!(
        v["_type"], "https://in-toto.io/Statement/v1",
        "in-toto statement type missing or wrong — verifiers reject this"
    );
    assert_eq!(
        v["predicateType"], "https://slsa.dev/provenance/v1",
        "SLSA predicate type missing — verifiers reject this"
    );
}

#[test]
fn test_emit_slsa_subject_names_artifact_and_carries_manifest_digest() {
    // Bug this catches: if `subject` doesn't list the manifest
    // digest, cosign verify-attestation cannot bind the statement
    // to the artifact — the attestation is meaningless.
    let (built, _spec_tmp) = common::make_built_artifact();
    let cas_root = TempDir::new().expect("cas tempdir");
    let cas = FsCas::new(cas_root.path()).expect("FsCas");

    let stmt = emit_slsa(&built, &SlsaConfig::default(), &cas)
        .expect("emit ok")
        .expect("not opted out");

    let bytes = cas.get(&stmt.blob_digest).expect("CAS get");
    let v: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON");

    let subj = v["subject"].as_array().expect("subject is an array");
    assert_eq!(subj.len(), 1, "exactly one subject entry");
    assert_eq!(subj[0]["name"], "demo:1.0");
    assert_eq!(
        subj[0]["digest"]["sha256"],
        built.manifest_digest.hex(),
        "subject digest must match manifest digest"
    );
}

#[test]
fn test_emit_slsa_external_parameters_pin_spec_hash() {
    // Bug this catches: forgetting to embed `spec_hash` in
    // externalParameters means the SLSA statement doesn't pin the
    // build to a specific spec — two different specs could produce
    // identical statements. The whole point of provenance is lost.
    let (built, _spec_tmp) = common::make_built_artifact();
    let cas_root = TempDir::new().expect("cas tempdir");
    let cas = FsCas::new(cas_root.path()).expect("FsCas");

    let stmt = emit_slsa(&built, &SlsaConfig::default(), &cas)
        .expect("emit ok")
        .expect("not opted out");

    let bytes = cas.get(&stmt.blob_digest).expect("CAS get");
    let v: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON");

    let ep = &v["predicate"]["buildDefinition"]["externalParameters"];
    assert_eq!(
        ep["spec_hash"],
        built.spec_hash.to_string(),
        "spec_hash must be embedded in externalParameters"
    );
    assert_eq!(ep["spec_id"], "demo:1.0");
    assert_eq!(ep["spec_kind"], "vm_image");
    assert_eq!(
        ep["claimed_slsa_level"], 2,
        "claimed level must round-trip — verify is responsible for L3+ validation"
    );
}

#[test]
fn test_emit_slsa_resolved_dependencies_lists_all_layers() {
    // Bug this catches: missing a layer in resolvedDependencies
    // means the SLSA statement under-reports the build's inputs;
    // a tampered layer would slip through verification.
    let (built, _spec_tmp) = common::make_built_artifact();
    let cas_root = TempDir::new().expect("cas tempdir");
    let cas = FsCas::new(cas_root.path()).expect("FsCas");

    let stmt = emit_slsa(&built, &SlsaConfig::default(), &cas)
        .expect("emit ok")
        .expect("not opted out");

    let bytes = cas.get(&stmt.blob_digest).expect("CAS get");
    let v: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON");

    let deps = v["predicate"]["buildDefinition"]["resolvedDependencies"]
        .as_array()
        .expect("resolvedDependencies is an array");
    assert_eq!(
        deps.len(),
        built.layer_digests.len(),
        "one resolvedDependency per layer"
    );
    for ((idx, digest), dep) in built.layer_digests.iter().zip(deps.iter()) {
        assert_eq!(
            dep["digest"]["sha256"],
            digest.hex(),
            "layer {idx} digest must round-trip"
        );
    }
}

#[test]
fn test_emit_slsa_off_returns_none() {
    // Bug this catches: a misrouted "Off" branch would emit a SLSA
    // statement anyway, breaking the spec contract that opt-out
    // means opt-out.
    let (built, _spec_tmp) = common::make_built_artifact();
    let cas_root = TempDir::new().expect("cas tempdir");
    let cas = FsCas::new(cas_root.path()).expect("FsCas");

    let cfg = SlsaConfig {
        level: spec::SlsaLevel::Off,
        builder_id: None,
    };
    assert!(
        emit_slsa(&built, &cfg, &cas).expect("ok").is_none(),
        "Off level must produce no SLSA statement"
    );
}

#[test]
fn test_emit_slsa_l3_claim_passes_through_unchanged() {
    // Bug this catches: silently downgrading an L3+ claim. The spec
    // doc says verify is responsible for validating the L3 claim
    // against the build environment; attest must NOT downgrade,
    // because doing so would let an L3 claim ship as L2 without
    // anyone noticing.
    let (built, _spec_tmp) = common::make_built_artifact();
    let cas_root = TempDir::new().expect("cas tempdir");
    let cas = FsCas::new(cas_root.path()).expect("FsCas");

    let cfg = SlsaConfig {
        level: spec::SlsaLevel::L3,
        builder_id: Some(
            "https://github.com/owner/repo/.github/workflows/release.yml@refs/tags/v1".into(),
        ),
    };
    let stmt = emit_slsa(&built, &cfg, &cas)
        .expect("emit ok")
        .expect("not opted out");

    let bytes = cas.get(&stmt.blob_digest).expect("CAS get");
    let v: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON");
    assert_eq!(
        v["predicate"]["buildDefinition"]["externalParameters"]["claimed_slsa_level"],
        3
    );
}
