use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use tempfile::TempDir;

use swe_justoci_bench::load_pipeline_runners;

fn bench_pipeline(c: &mut Criterion) {
    let runners = load_pipeline_runners();
    let mut group = c.benchmark_group("pipeline");
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

criterion_group!(benches, bench_pipeline);
criterion_main!(benches);
