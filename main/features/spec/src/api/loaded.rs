use std::path::{Path, PathBuf};

use super::spec::Spec;

/// A `Spec` together with the directory its layer source paths
/// resolve against.
///
/// `parse_and_validate` returns a `LoadedSpec` rather than a bare
/// `Spec` because the spec's validity is *contextual*: relative
/// `LayerSource::Blob { path }` and `[[layers.files]] source`
/// entries are interpreted relative to a specific directory
/// (typically the spec file's parent), and downstream consumers
/// — most importantly the build pipeline — must use the same
/// anchor or they'll resolve paths against a different filesystem
/// location and produce a different (or failed) build.
///
/// Encoding the anchor here as a wrapper is a deliberate API choice:
/// every caller is forced to either pass `LoadedSpec` through or
/// explicitly extract `.spec` (and accept that they own anchor
/// semantics from there). There is no implicit "fall back to cwd"
/// path that can quietly produce a different build on different
/// hosts.
///
/// Hand-constructed `Spec` values (e.g. test fixtures that build a
/// `Spec` field-by-field rather than via the parser) wrap themselves
/// in a `LoadedSpec` with whatever anchor they choose; absolute paths
/// in the `Spec` short-circuit anchor application at build time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedSpec {
    pub spec: Spec,
    pub spec_dir: PathBuf,
}

impl LoadedSpec {
    /// Construct from already-validated parts. Used by the parser;
    /// also available to callers that constructed a `Spec` themselves
    /// and want to attach an anchor explicitly.
    pub fn new(spec: Spec, spec_dir: PathBuf) -> Self {
        LoadedSpec { spec, spec_dir }
    }

    /// Resolve a (possibly relative) layer source path against the
    /// spec dir. Absolute paths return unchanged. The build pipeline
    /// uses this for every layer source so the resolution rule is
    /// uniform.
    pub fn resolve(&self, layer_path: &Path) -> PathBuf {
        if layer_path.is_absolute() {
            layer_path.to_path_buf()
        } else {
            self.spec_dir.join(layer_path)
        }
    }
}
