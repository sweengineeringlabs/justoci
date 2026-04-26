//! Public spec-loading entry points.
//!
//! Both functions return `LoadedSpec` (Spec + the directory layer
//! source paths anchor against) rather than a bare `Spec`. The
//! anchor is part of the spec's runtime identity — a `Spec` parsed
//! from `/a/spec.toml` and a `Spec` parsed from `/b/spec.toml`
//! describe artifacts whose contents differ, even if the TOML text
//! is byte-identical, because their relative layer sources resolve
//! to different files.

use std::path::{Path, PathBuf};

use crate::api::{LoadedSpec, SpecError};
use crate::core::{raw::RawSpec, validate};

/// Read a spec file from disk, parse, and validate.
///
/// On `Ok`, every guarantee in the spec doc's "Validation at spec
/// load" section has been checked. Every layer's source path has
/// been existence-tested. Every media type has been parsed.
///
/// On `Err`, no partial state escapes — the caller cannot accidentally
/// build from a half-validated spec.
pub fn parse_and_validate(path: impl AsRef<Path>) -> Result<LoadedSpec, SpecError> {
    let path = path.as_ref();

    let bytes = std::fs::read_to_string(path).map_err(|e| SpecError::Io {
        path: path.display().to_string(),
        source: e,
    })?;

    parse_and_validate_str(&bytes, spec_dir_for(path))
}

/// Parse and validate from an already-loaded TOML string. `spec_dir`
/// is the directory layer source paths are resolved against —
/// callers loading spec content from a non-filesystem source (a
/// network fetch, a unit test inline-string) pass the directory
/// they want layer paths anchored to.
pub fn parse_and_validate_str(
    toml_text: &str,
    spec_dir: PathBuf,
) -> Result<LoadedSpec, SpecError> {
    let raw: RawSpec = toml::from_str(toml_text)?;
    let spec = validate::validate(raw, &spec_dir)?;
    Ok(LoadedSpec::new(spec, spec_dir))
}

fn spec_dir_for(path: &Path) -> PathBuf {
    path.parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}
