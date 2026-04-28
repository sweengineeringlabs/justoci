//! Runner-agnostic Criterion build benchmark.
//!
//! Cases are driven by `bench/bench.toml`. Add entries there to bench
//! new runners or payload sizes without touching this file.
//!
//! Run:
//!   cargo bench -p swe_justoci_bench --bench build
//!   cargo bench -p swe_justoci_bench --bench build -- "build_oci_artifact/justoci/16mb"

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use tempfile::TempDir;

use swe_justoci_bench::load_runners;

fn bench_build(c: &mut Criterion) {
    let runners = load_runners();
    let mut group = c.benchmark_group("build_oci_artifact");

    for runner in &runners {
        group.throughput(Throughput::Bytes(runner.bytes_written()));
        group.bench_function(BenchmarkId::from_parameter(runner.label()), |b| {
            b.iter_batched(
                // Setup: fresh output parent dir per iteration.
                // NOT included in the timing window — matches the isolation
                // approach of the original build_layout bench.
                || TempDir::new().expect("bench: tempdir"),
                |out| {
                    let out_path = out.path().join("oci");
                    runner.run(&out_path);
                    out // keep alive until after timing window
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(benches, bench_build);
criterion_main!(benches);
