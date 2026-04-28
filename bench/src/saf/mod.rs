pub mod registry_guard;

use crate::api::{BenchConfig, CaseConfig, Runner};

fn load_config() -> BenchConfig {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/bench.toml");
    let src = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
    toml::from_str(&src).unwrap_or_else(|e| panic!("invalid bench.toml: {e}"))
}

pub fn load_build_runners() -> Vec<Box<dyn Runner>> {
    load_config()
        .case
        .into_iter()
        .filter(|c| c.bench == "build")
        .filter_map(make_runner)
        .collect()
}

pub fn load_push_runners() -> Vec<Box<dyn Runner>> {
    load_config()
        .case
        .into_iter()
        .filter(|c| c.bench == "push")
        .filter_map(make_runner)
        .collect()
}

pub fn load_pipeline_runners() -> Vec<Box<dyn Runner>> {
    load_config()
        .case
        .into_iter()
        .filter(|c| c.bench == "pipeline")
        .filter_map(make_runner)
        .collect()
}

fn make_runner(case: CaseConfig) -> Option<Box<dyn Runner>> {
    match case.runner.as_str() {
        #[cfg(feature = "just-build")]
        "just-build" => Some(Box::new(crate::core::just_build::JustBuild::new(case))),
        #[cfg(feature = "just-push")]
        "just-push" => Some(Box::new(crate::core::just_push::JustPush::new(case))),
        #[cfg(feature = "just-pipeline")]
        "just-pipeline" => Some(Box::new(crate::core::just_pipeline::JustPipeline::new(case))),
        #[cfg(feature = "oras")]
        "oras" => Some(Box::new(crate::spi::oras::Oras::new(case))),
        #[cfg(all(feature = "oras", feature = "cosign"))]
        "oras-cosign" => Some(Box::new(crate::spi::oras_cosign::OrasCosign::new(case))),
        other => {
            eprintln!("bench: skipping '{}' ({other}) — feature not enabled", case.label);
            drop(case.params);
            None
        }
    }
}
