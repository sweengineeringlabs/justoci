use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use tempfile::TempDir;

use swe_justoci_bench::load_build_runners;

fn bench_build(c: &mut Criterion) {
    let runners = load_build_runners();
    let mut group = c.benchmark_group("build");
    for runner in &runners {
        group.throughput(Throughput::Bytes(runner.bytes()));
        group.bench_function(BenchmarkId::from_parameter(runner.label()), |b| {
            b.iter_batched(
                || TempDir::new().expect("bench: tempdir"),
                |out| runner.run(&out.path().join("out")),
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

criterion_group! {
    name    = benches;
    config  = {
        let out = dirs::data_dir()
            .unwrap_or_else(|| std::path::PathBuf::from(".local/share"))
            .join("justoci/bench_results");
        Criterion::default().output_directory(&out)
    };
    targets = bench_build
}
criterion_main!(benches);
