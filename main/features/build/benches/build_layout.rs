//! Criterion benchmarks for `oci_build::build`.
//!
//! Measures: OCI layout assembly throughput — spec parse + layer tar/compress
//! + manifest/config blob write — end to end, with real disk I/O to a tempdir.
//!
//! Run:
//!   cargo bench -p swe_justoci_oci_build --bench build_layout
//!
//! Market comparison (push-only, no layout assembly):
//!   scripts/bench/compare_oras.sh   (requires oras on PATH)

use std::fs;
use std::path::Path;

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use oci_build::build;
use spec::parse_and_validate_str;

/// Forward slashes so the TOML source path embeds cleanly on Windows too.
fn posix(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

fn oci_artifact_toml(blob_path: &Path, size_label: &str) -> String {
    format!(
        r#"
spec_version = "0"
id           = "bench-artifact:{size_label}"
kind         = "oci_artifact"
description  = "bench"

[[layers]]
source     = "{blob}"
media_type = "application/octet-stream"
"#,
        blob = posix(blob_path),
    )
}

fn bench_build_oci_artifact(c: &mut Criterion) {
    let mut group = c.benchmark_group("build_oci_artifact");

    // (payload_bytes, label)
    let cases: &[(usize, &str)] = &[
        (4_096,       "4KB"),
        (1_048_576,   "1MB"),
        (16_777_216,  "16MB"),
    ];

    for &(size, label) in cases {
        // Write the source blob once; re-use it across all iterations.
        let work = tempfile::TempDir::new().unwrap();
        let blob_path = work.path().join("payload.bin");
        let payload: Vec<u8> = (0..size).map(|i| i as u8).collect();
        fs::write(&blob_path, &payload).unwrap();

        let toml = oci_artifact_toml(&blob_path, label);
        let spec = parse_and_validate_str(&toml, work.path().to_path_buf())
            .expect("bench spec must parse");

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("justoci", label),
            &spec,
            |b, loaded_spec| {
                b.iter_batched(
                    // Fresh output dir each iteration — atomicity contract
                    // requires the output dir to not already exist.
                    || tempfile::TempDir::new().unwrap(),
                    |out| {
                        let out_path = out.path().join("output");
                        build(loaded_spec, &out_path).expect("build must succeed");
                        out // keep tempdir alive until after timing window
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_build_oci_artifact);
criterion_main!(benches);
