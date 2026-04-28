use criterion::{BenchmarkId, BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use tempfile::TempDir;

use swe_justoci_e2e_bench::load_runners;

fn bench_pipeline(c: &mut Criterion) {
    let runners = load_runners();
    let mut group = c.benchmark_group("e2e_pipeline");
    for runner in &runners {
        group.throughput(Throughput::Bytes(runner.payload_bytes()));
        group.bench_function(
            BenchmarkId::from_parameter(runner.label()),
            |b| b.iter_batched(
                || TempDir::new().unwrap(),
                |out_dir| runner.run(out_dir.path()),
                BatchSize::SmallInput,
            ),
        );
    }
    group.finish();
}

criterion_group!(benches, bench_pipeline);
criterion_main!(benches);
