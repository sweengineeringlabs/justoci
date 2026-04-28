use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct BenchConfig {
    pub case: Vec<CaseConfig>,
}

#[derive(Debug, Deserialize)]
pub struct CaseConfig {
    pub runner: String,
    pub label: String,
    #[serde(flatten)]
    pub params: HashMap<String, toml::Value>,
}

/// SPI implemented by every e2e pipeline runner.
///
/// Each runner owns reusable state (keypair, pre-built spec, registry
/// coordinates, etc.). The harness supplies a fresh output directory
/// per iteration via `iter_batched` — the directory creation cost is
/// excluded from the timing window.
pub trait PipelineRunner {
    fn label(&self) -> &str;
    /// Bytes of payload per iteration — used for throughput reporting.
    fn payload_bytes(&self) -> u64;
    /// Execute one end-to-end pipeline into `output_path`, which must not yet exist.
    fn run(&self, output_path: &Path);
}

pub fn load_runners() -> Vec<Box<dyn PipelineRunner>> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/bench.toml");
    let src = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
    let config: BenchConfig = toml::from_str(&src)
        .unwrap_or_else(|e| panic!("invalid bench.toml: {e}"));
    config.case.into_iter().filter_map(build_runner).collect()
}

fn build_runner(case: CaseConfig) -> Option<Box<dyn PipelineRunner>> {
    match case.runner.as_str() {
        #[cfg(feature = "rust-pipeline")]
        "rust-pipeline" => Some(Box::new(rust_pipeline_runner::RustPipelineRunner::new(case))),
        #[cfg(feature = "oras-cosign")]
        "oras-cosign" => Some(Box::new(oras_cosign_runner::OrasCosignRunner::new(case))),
        other => {
            eprintln!("e2e bench: skipping '{other}' — feature not enabled");
            None
        }
    }
}

#[cfg(feature = "rust-pipeline")]
mod rust_pipeline_runner;
#[cfg(feature = "oras-cosign")]
mod oras_cosign_runner;
