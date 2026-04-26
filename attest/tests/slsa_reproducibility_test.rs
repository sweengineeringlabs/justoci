//! Reproducibility guarantee for the SLSA statement.
//!
//! Bug this catches: a non-deterministic field (timestamp, UUID,
//! HashMap iteration order) sneaking into the predicate would
//! break Production Guarantee §2 ("same spec + same source files
//! → same artifact digest, bit-for-bit"). Consumers verifying a
//! build by re-running it would report a spurious mismatch.

mod common;

use cas::{Cas, FsCas};
use spec::SlsaConfig;
use tempfile::TempDir;

use attest::core::slsa::emit_slsa;

#[test]
fn test_slsa_statement_is_byte_identical_across_two_emits() {
    let (built, _spec_tmp) = common::make_built_artifact();
    let cas_root_a = TempDir::new().expect("tempdir a");
    let cas_root_b = TempDir::new().expect("tempdir b");
    let cas_a = FsCas::new(cas_root_a.path()).expect("FsCas a");
    let cas_b = FsCas::new(cas_root_b.path()).expect("FsCas b");

    let stmt_a = emit_slsa(&built, &SlsaConfig::default(), &cas_a)
        .expect("emit a")
        .expect("L2 produces statement");
    let stmt_b = emit_slsa(&built, &SlsaConfig::default(), &cas_b)
        .expect("emit b")
        .expect("L2 produces statement");

    let bytes_a = cas_a.get(&stmt_a.blob_digest).expect("get a");
    let bytes_b = cas_b.get(&stmt_b.blob_digest).expect("get b");

    assert_eq!(
        bytes_a, bytes_b,
        "two emits of the same built artifact must produce byte-identical SLSA statements"
    );
    assert_eq!(
        stmt_a.blob_digest, stmt_b.blob_digest,
        "same bytes must yield same digest"
    );
}

#[test]
fn test_slsa_statement_byte_identical_with_explicit_builder_id() {
    // Catches: the builder_id default-fallback path being
    // non-deterministic (e.g. introducing a timestamp when the spec
    // didn't pin a builder).
    let (built, _spec_tmp) = common::make_built_artifact();
    let cas_root = TempDir::new().expect("tempdir");
    let cas = FsCas::new(cas_root.path()).expect("FsCas");

    let cfg = SlsaConfig {
        level: spec::SlsaLevel::L2,
        builder_id: Some("https://example.com/builder/1".into()),
    };
    let stmt_1 = emit_slsa(&built, &cfg, &cas)
        .expect("emit 1")
        .expect("statement");

    let cas_root_2 = TempDir::new().expect("tempdir 2");
    let cas_2 = FsCas::new(cas_root_2.path()).expect("FsCas 2");
    let stmt_2 = emit_slsa(&built, &cfg, &cas_2)
        .expect("emit 2")
        .expect("statement");

    assert_eq!(stmt_1.blob_digest, stmt_2.blob_digest);
}
