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

/// SPI implemented by every build runner.
///
/// Each runner owns its reusable state (parsed spec, source blob, etc.).
/// The harness calls `run(output_path)` in a tight loop; `output_path`
/// is a fresh directory provided by the harness for each iteration so
/// the atomicity contract (`build()` refuses to overwrite an existing
/// directory) is upheld without measuring directory-creation overhead.
pub trait BuildRunner {
    fn label(&self) -> &str;
    /// Bytes of payload written per iteration — used for throughput reporting.
    fn bytes_written(&self) -> u64;
    /// Execute one build into `output_path`, which must not yet exist.
    fn run(&self, output_path: &Path);
}

pub fn load_runners() -> Vec<Box<dyn BuildRunner>> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/bench.toml");
    let src = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
    let config: BenchConfig = toml::from_str(&src)
        .unwrap_or_else(|e| panic!("invalid bench.toml: {e}"));
    config.case.into_iter().filter_map(build_runner).collect()
}

fn build_runner(case: CaseConfig) -> Option<Box<dyn BuildRunner>> {
    match case.runner.as_str() {
        #[cfg(feature = "justoci")]
        "justoci" => Some(Box::new(justoci_runner::JustociRunner::new(case))),
        #[cfg(feature = "oras")]
        "oras" => Some(Box::new(oras_runner::OrasRunner::new(case))),
        other => {
            eprintln!("bench: skipping '{other}' — feature not enabled");
            None
        }
    }
}

#[cfg(feature = "justoci")]
mod justoci_runner;
#[cfg(feature = "oras")]
mod oras_runner;
