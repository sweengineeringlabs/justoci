//! Cross-language JCS fixture self-consistency.
//!
//! For every fixture under `tests/fixtures/jcs/<name>/` (which lives
//! at the repo root, NOT under any crate, because it's cross-language
//! reference material), this test parses the fixture's `spec.toml`
//! through the Rust impl and asserts the produced canonical bytes
//! and spec hash match the committed `expected.canonical.json` and
//! `expected.spec_hash` files.
//!
//! Bug it catches: a contributor who edits a fixture's `spec.toml`
//! without re-running the `regenerate-jcs-fixtures` binary commits
//! a fixture set where Rust and the expected files disagree. The Go
//! and Python verifiers in CI catch the cross-language gap, but they
//! only run on the `jcs-cross-lang` job; this test runs in `cargo
//! test --workspace` and surfaces the drift the moment a contributor
//! pushes.
//!
//! Bug it catches: a refactor that changes the Rust projection rule
//! silently (e.g. someone tweaks `spec_to_json` to omit a field
//! that should be present, or to insert an extra wrapper key). The
//! committed `expected.canonical.json` is a contract — Rust changes
//! must be matched by intentional fixture refresh + cross-language
//! re-implementations updating their projections.

use std::fs;
use std::path::{Path, PathBuf};

use spec::{canonical_bytes, parse_and_validate, spec_hash};

/// Resolve the fixture root by walking up from the test binary's
/// crate dir. The Rust spec crate lives at `<repo>/spec/`; the
/// fixtures live at `<repo>/tests/fixtures/jcs/`.
fn fixtures_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is the spec crate dir at compile time, set
    // by cargo. Walk to the repo root and into tests/fixtures/jcs.
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = crate_dir
        .parent()
        .expect("spec crate has a parent (repo root)");
    repo_root.join("tests").join("fixtures").join("jcs")
}

fn list_fixtures(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let entries = fs::read_dir(root).unwrap_or_else(|e| {
        panic!(
            "could not read fixtures dir {}: {e}. \
             This test requires tests/fixtures/jcs/ to exist at the repo root.",
            root.display()
        )
    });
    for entry in entries {
        let entry = entry.unwrap();
        let p = entry.path();
        if p.is_dir() && p.join("spec.toml").is_file() {
            out.push(p);
        }
    }
    out.sort();
    out
}

/// Anchor: every fixture parses, canonicalises, and hashes through
/// the Rust impl without error.
///
/// Bug it catches: a contributor who edits `spec.toml` in a way that
/// breaks validation (wrong layer count, missing required field)
/// commits a fixture the regeneration binary cannot process. This
/// test surfaces the validation error verbatim — operators see
/// "minimal-raw-image: spec error: ..." in CI rather than a vague
/// fixture-load failure later.
#[test]
fn test_every_jcs_fixture_parses_and_canonicalises() {
    let root = fixtures_root();
    let fixtures = list_fixtures(&root);
    assert!(
        !fixtures.is_empty(),
        "no fixtures found under {}; the cross-language JCS \
         fixture set should not be empty",
        root.display()
    );

    for fixture in &fixtures {
        let spec_path = fixture.join("spec.toml");
        let loaded = parse_and_validate(&spec_path).unwrap_or_else(|e| {
            panic!("fixture {} did not parse/validate: {e}", fixture.display())
        });
        // Both should succeed for any valid Spec.
        canonical_bytes(&loaded.spec).expect("canonical_bytes must succeed");
        spec_hash(&loaded.spec).expect("spec_hash must succeed");
    }
}

/// The committed `expected.canonical.json` for every fixture matches
/// what the current Rust impl produces.
///
/// Bug it catches: a contributor edits a fixture's spec.toml without
/// running `cargo run -p swe_justoci_oci_cli --bin
/// regenerate-jcs-fixtures`. The Rust impl produces canonical bytes
/// that no longer match what's checked in, and the cross-language
/// verifiers will then fail confusingly (the Go/Python output won't
/// match the stale Rust output either). This test surfaces the drift
/// at `cargo test` time, with a precise byte-offset diff.
#[test]
fn test_every_jcs_fixture_canonical_bytes_match_committed_expected() {
    let root = fixtures_root();
    for fixture in list_fixtures(&root) {
        let loaded = parse_and_validate(fixture.join("spec.toml")).expect("fixture parses");
        let produced = canonical_bytes(&loaded.spec).expect("canonical_bytes succeeds");
        let expected_path = fixture.join("expected.canonical.json");
        let expected = fs::read(&expected_path).unwrap_or_else(|e| {
            panic!(
                "fixture {} missing expected.canonical.json: {e}. \
                 Run: cargo run -p swe_justoci_oci_cli --bin regenerate-jcs-fixtures",
                fixture.display()
            )
        });
        assert_eq!(
            produced,
            expected,
            "canonical_bytes drifted from committed expected.canonical.json for fixture {}.\n\
             Run: cargo run -p swe_justoci_oci_cli --bin regenerate-jcs-fixtures\n\
             Then update the Go and Python re-implementations under tests/fixtures/jcs/.\n\
             Got      ({} bytes): {}\n\
             Expected ({} bytes): {}",
            fixture.display(),
            produced.len(),
            String::from_utf8_lossy(&produced),
            expected.len(),
            String::from_utf8_lossy(&expected),
        );
    }
}

/// The committed `expected.spec_hash` for every fixture matches what
/// the current Rust impl produces.
///
/// Bug it catches: same drift class as the canonical-bytes test, but
/// scoped to the digest line. A redundant check on purpose — if the
/// canonical bytes match but the hash doesn't, somebody's SHA-256 is
/// broken (cas crate regression, tooling-side hash change). The
/// duplication is cheap insurance.
#[test]
fn test_every_jcs_fixture_spec_hash_matches_committed_expected() {
    let root = fixtures_root();
    for fixture in list_fixtures(&root) {
        let loaded = parse_and_validate(fixture.join("spec.toml")).expect("fixture parses");
        let produced = spec_hash(&loaded.spec)
            .expect("spec_hash succeeds")
            .to_string();
        let expected_path = fixture.join("expected.spec_hash");
        let expected = fs::read_to_string(&expected_path).unwrap_or_else(|e| {
            panic!(
                "fixture {} missing expected.spec_hash: {e}. \
                     Run: cargo run -p swe_justoci_oci_cli --bin regenerate-jcs-fixtures",
                fixture.display()
            )
        });
        let expected = expected.trim_end_matches('\n');
        assert_eq!(
            produced,
            expected,
            "spec_hash drifted from committed expected.spec_hash for fixture {}.\n\
             Run: cargo run -p swe_justoci_oci_cli --bin regenerate-jcs-fixtures",
            fixture.display(),
        );
    }
}
