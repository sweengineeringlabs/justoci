//! `regenerate-jcs-fixtures` — rewrite the cross-language JCS test
//! fixture's `expected.canonical.json` and `expected.spec_hash`
//! files from the current Rust impl.
//!
//! The fixture set under `tests/fixtures/jcs/<name>/` is reference
//! material for cross-language re-implementations of justoci
//! (issue #10). Each fixture contains a `spec.toml` + supporting
//! `layer-files/` and two artefact files this binary regenerates:
//!
//! - `expected.canonical.json` — the JCS-canonical JSON bytes the
//!   Rust impl produces (no trailing newline; byte-for-byte what
//!   `spec::canonical_bytes` returns).
//! - `expected.spec_hash` — the OCI-format `sha256:<hex>` digest
//!   `spec::spec_hash` returns (single line, no trailing newline).
//!
//! When the spec projection rules legitimately change (e.g. a new
//! field is added to `Spec`), run this binary to refresh the
//! fixtures. Then re-run the cross-language verifier scripts so the
//! Go / Python re-impls update their projection logic in lockstep.
//!
//! Usage:
//!
//! ```bash
//! cargo run -p swe_justoci_oci_cli --bin regenerate-jcs-fixtures
//! ```
//!
//! Optionally pass `--check` to fail (non-zero exit) if any fixture
//! is stale rather than rewriting it. CI uses this to catch fixtures
//! drifting from the Rust impl unannounced.

use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use spec::{canonical_bytes, parse_and_validate, spec_hash};

const USAGE: &str = "\
regenerate-jcs-fixtures [--check] [<fixtures-dir>]

  --check         Verify expected files are up to date; exit non-zero
                  if any fixture would change. Does NOT rewrite files.
  <fixtures-dir>  Path to tests/fixtures/jcs (auto-detected if omitted).
";

fn main() -> ExitCode {
    let args = env::args().skip(1);
    let mut check_only = false;
    let mut explicit_dir: Option<PathBuf> = None;
    for a in args {
        match a.as_str() {
            "--check" => check_only = true,
            "-h" | "--help" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            other if !other.starts_with("--") => {
                explicit_dir = Some(PathBuf::from(other));
            }
            other => {
                eprintln!("unknown flag: {other}\n{USAGE}");
                return ExitCode::from(64);
            }
        }
    }

    let fixtures_dir = match explicit_dir {
        Some(p) => p,
        None => match locate_fixtures_dir() {
            Some(p) => p,
            None => {
                eprintln!(
                    "could not auto-locate tests/fixtures/jcs — run from inside the \
                     justoci checkout, or pass the directory as an argument"
                );
                return ExitCode::from(64);
            }
        },
    };

    if !fixtures_dir.is_dir() {
        eprintln!(
            "fixtures dir does not exist or is not a directory: {}",
            fixtures_dir.display()
        );
        return ExitCode::from(64);
    }

    let fixtures = match list_fixtures(&fixtures_dir) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("failed to enumerate fixtures: {e}");
            return ExitCode::from(64);
        }
    };

    if fixtures.is_empty() {
        eprintln!(
            "no fixtures found under {} (each fixture is a subdir with spec.toml)",
            fixtures_dir.display()
        );
        return ExitCode::from(64);
    }

    let mut had_drift = false;
    let mut had_error = false;
    for fixture in &fixtures {
        match process_fixture(fixture, check_only) {
            Ok(Outcome::Unchanged) => {
                println!(
                    "ok        {}",
                    fixture.file_name().and_then(OsStr::to_str).unwrap_or("?")
                );
            }
            Ok(Outcome::Wrote) => {
                println!(
                    "regen     {}",
                    fixture.file_name().and_then(OsStr::to_str).unwrap_or("?")
                );
            }
            Ok(Outcome::WouldChange) => {
                had_drift = true;
                println!(
                    "STALE     {}  (run without --check to refresh)",
                    fixture.file_name().and_then(OsStr::to_str).unwrap_or("?")
                );
            }
            Err(e) => {
                had_error = true;
                eprintln!(
                    "ERROR     {}: {e}",
                    fixture.file_name().and_then(OsStr::to_str).unwrap_or("?")
                );
            }
        }
    }

    if had_error {
        ExitCode::from(2)
    } else if check_only && had_drift {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// Walk parent dirs from cwd looking for `tests/fixtures/jcs`. Returns
/// the absolute path or None.
fn locate_fixtures_dir() -> Option<PathBuf> {
    let mut here = env::current_dir().ok()?;
    loop {
        let candidate = here.join("tests").join("fixtures").join("jcs");
        if candidate.is_dir() {
            return Some(candidate);
        }
        if !here.pop() {
            return None;
        }
    }
}

fn list_fixtures(root: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let p = entry.path();
        if p.is_dir() && p.join("spec.toml").is_file() {
            out.push(p);
        }
    }
    out.sort();
    Ok(out)
}

#[derive(Debug)]
enum Outcome {
    /// Files exist and already match the current Rust impl.
    Unchanged,
    /// Files were written or rewritten.
    Wrote,
    /// `--check` mode: files would change but we didn't write them.
    WouldChange,
}

fn process_fixture(fixture: &Path, check_only: bool) -> Result<Outcome, FixtureError> {
    let spec_path = fixture.join("spec.toml");
    let loaded = parse_and_validate(&spec_path).map_err(|source| FixtureError::Parse {
        path: spec_path.display().to_string(),
        source: Box::new(source),
    })?;
    let canonical = canonical_bytes(&loaded.spec).map_err(FixtureError::Canonicalize)?;
    let digest = spec_hash(&loaded.spec).map_err(FixtureError::Canonicalize)?;
    let digest_str = digest.to_string();

    let expected_canonical = fixture.join("expected.canonical.json");
    let expected_hash = fixture.join("expected.spec_hash");

    let canonical_matches = match fs::read(&expected_canonical) {
        Ok(existing) => existing == canonical,
        Err(_) => false,
    };
    let hash_matches = match fs::read_to_string(&expected_hash) {
        Ok(existing) => existing.trim_end_matches('\n') == digest_str,
        Err(_) => false,
    };

    if canonical_matches && hash_matches {
        return Ok(Outcome::Unchanged);
    }

    if check_only {
        return Ok(Outcome::WouldChange);
    }

    fs::write(&expected_canonical, &canonical).map_err(|source| FixtureError::Write {
        path: expected_canonical.display().to_string(),
        source,
    })?;
    fs::write(&expected_hash, digest_str.as_bytes()).map_err(|source| FixtureError::Write {
        path: expected_hash.display().to_string(),
        source,
    })?;
    Ok(Outcome::Wrote)
}

#[derive(Debug, thiserror::Error)]
enum FixtureError {
    #[error("parse {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: Box<spec::SpecError>,
    },

    #[error("canonicalize: {0}")]
    Canonicalize(#[source] spec::CanonicalizationError),

    #[error("write {path}: {source}")]
    Write {
        path: String,
        #[source]
        source: std::io::Error,
    },
}
