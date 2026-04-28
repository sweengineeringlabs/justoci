use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;

use serde::Deserialize;

static REGISTRY_OVERRIDE: OnceLock<String> = OnceLock::new();

/// Set the in-process registry override (used by `RegistryGuard`). First write wins.
pub fn set_registry_override(addr: String) {
    let _ = REGISTRY_OVERRIDE.set(addr);
}

/// Resolve the registry address for a bench case.
///
/// Priority: in-process override → `BENCH_REGISTRY` env var → `registry` param in bench.toml → `localhost:5000`.
#[cfg_attr(
    not(any(
        feature = "just-build",
        feature = "just-push",
        feature = "oras",
        feature = "cosign",
    )),
    allow(dead_code)
)]
pub fn resolve_registry(case: &CaseConfig) -> String {
    REGISTRY_OVERRIDE
        .get()
        .cloned()
        .or_else(|| std::env::var("BENCH_REGISTRY").ok())
        .or_else(|| case.params.get("registry").and_then(|v| v.as_str()).map(str::to_owned))
        .unwrap_or_else(|| "localhost:5000".to_owned())
}

pub trait Runner: Send + Sync {
    fn label(&self) -> &str;
    fn bytes(&self) -> u64;
    fn run(&self, output_path: &Path);
}

#[derive(Debug, Deserialize)]
pub struct BenchConfig {
    pub case: Vec<CaseConfig>,
}

#[derive(Debug, Deserialize)]
pub struct CaseConfig {
    pub bench: String,
    pub runner: String,
    pub label: String,
    #[serde(flatten)]
    pub params: HashMap<String, toml::Value>,
}
