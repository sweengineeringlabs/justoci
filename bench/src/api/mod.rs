use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

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
