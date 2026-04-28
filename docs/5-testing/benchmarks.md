# justoci benchmarks

**Audience**: Contributors, adopters evaluating build pipeline throughput.

> **TLDR**: `oci_build::build` sustains **~223 MiB/s** for 16 MB artifacts with ~18 ms fixed overhead per build. The fixed overhead covers TempDir creation, CAS blob write, manifest/config JSON serialization, and atomic rename — not data processing. Run `cargo bench -p swe_justoci_bench --bench build` to reproduce.

## Bench architecture

The benchmark lives in `bench/benches/build.rs`. It exercises the full `oci_build::build` pipeline end-to-end with real disk I/O to a `tempfile::TempDir` on NTFS.

```rust
b.iter_batched(
    || tempfile::TempDir::new().unwrap(),   // setup: fresh output dir per iteration
    |out_dir| build(&spec, out_dir.path()), // measured: full build pipeline
    criterion::BatchSize::SmallInput,
);
```

### What `build()` measures

The timing window covers the complete OCI Layout assembly pipeline:

1. **Layer assembly** — for each `[[layers]]` entry in the spec:
   - Source read → optional compression (`flate2` Gzip level 6 or `zstd` level 3)
   - 64 KiB chunk streaming: file → encoder → CAS — no intermediate `Vec<u8>`
   - SHA-256 digest computed inline via `CountingReader`
   - Atomic CAS write: `tmp-file` → `rename`
2. **JSON serialization** — OCI Image Config + manifest via `serde_json`
3. **Layout writes** — `oci-layout` marker + `index.json`
4. **Atomic flip** — `.partial` directory → final output directory rename

### Allocation isolation

The source blob is pre-written once outside any iteration. Each iteration receives a fresh `TempDir` (the output directory is the only per-iteration allocation). Layer data flows through 64 KiB streaming chunks — no full-payload `Vec<u8>` allocated inside the timing window.

## Environment

| Field | Value |
|---|---|
| Date | 2026-04-28 |
| Host | Windows 11, x86-64 |
| Toolchain | stable (release profile) |
| Bench harness | Criterion 0.5 |
| Samples | 100 per case |
| Warmup | 3 s |
| Output | Real disk I/O to `%TEMP%` (NTFS) |

## Results — `oci_build::build` (single-layer, `application/octet-stream`, no compression)

Each iteration creates a fresh output directory; the source blob is pre-written once and re-used.

| Payload | Mean time | Throughput |
|---|---|---|
| 4 KB | **17.6 ms** | 227 KiB/s |
| 1 MB | **19.5 ms** | 51.3 MiB/s |
| 16 MB | **71.7 ms** | 223 MiB/s |

## What the numbers mean

### Fixed overhead dominates small artifacts

The 4 KB and 1 MB cases take nearly identical time (~18 ms). That ~18 ms floor covers five steps that happen regardless of payload size:

| Step | justoci pays? |
|---|---|
| `TempDir::new()` (included in `iter_batched` window) | Yes |
| CAS blob write (`tmp-file` → `rename`) | Yes |
| OCI manifest + config JSON serialization | Yes |
| `index.json` + `oci-layout` writes | Yes |
| `.partial` → output dir atomic rename | Yes |
| **Data processing (hashing, compression, streaming)** | Yes — proportional to payload |

For the 4 KB case, data processing is negligible — the fixed overhead is the entire cost.

### Throughput scales with payload

At 16 MB, data processing (~54 ms above the floor) overtakes the fixed overhead and justoci reaches ~223 MiB/s. This is NTFS write bandwidth for uncompressed `application/octet-stream` layers — the bottleneck shifts from metadata operations to disk I/O.

Adding Gzip or Zstd compression reduces disk I/O at the cost of CPU; actual throughput depends on codec and compression ratio.

### Implication for real use cases

Firmware images, ML model weights, and VM rootfs blobs are typically 10–500 MB. In that range justoci runs at **100–223 MiB/s**, meaning a 100 MB artifact takes ~450 ms end-to-end. A 500 MB rootfs takes ~2.5 s.

For pipelines building many small artifacts (< 1 MB), the ~18 ms overhead per build is the dominant cost. Batching small files into fewer, larger layers eliminates most of it.

## Comparison with oras

Measured via `OrasRunner` in the same Criterion harness — `oras push --plain-http` to a local `registry:2` container over loopback, 100 samples, same payload sizes.

**These numbers are not directly comparable.** `oras push` transmits a blob to a registry over HTTP/loopback. `justoci::build` assembles an OCI layout to local disk with no network involved. The operations differ in scope — justoci is the build step, oras is the push step. The comparison is useful for order-of-magnitude orientation.

| Payload | justoci (local disk) | oras push (loopback) | justoci advantage |
|---|---|---|---|
| 4 KB | **14.1 ms** | **132.5 ms** | 9.4× faster |
| 1 MB | **19.9 ms** | **132.5 ms** | 6.7× faster |
| 16 MB | **74.7 ms** | **167.1 ms** | 2.2× faster |

oras fixed overhead is ~130 ms — Go subprocess spawn plus the HTTP round-trip to a loopback registry. For small artifacts this dominates: both 4 KB and 1 MB take nearly identical time. At 16 MB, data transfer over loopback begins to matter and oras reaches ~96 MiB/s vs justoci's ~214 MiB/s on local NTFS.

Run the oras comparison:

```sh
# Start a local registry
docker run -d -p 5000:5000 registry:2

# Run both runners together
cargo bench -p swe_justoci_bench --bench build --features justoci,oras
```

## Reproducing

### Prerequisites

| Requirement | Notes |
|---|---|
| Rust stable toolchain | required |
| Docker + oras 1.x (oras comparison only) | `docker run -d -p 5000:5000 registry:2` |

### Steps

**1. Clone and enter the workspace**

```sh
git clone git@github.com:sweengineeringlabs/justoci.git
cd justoci
```

**2. Run the benchmark (justoci only)**

```sh
cargo bench -p swe_justoci_bench --bench build
```

**3. Run with oras comparison**

```sh
docker run -d -p 5000:5000 registry:2
cargo bench -p swe_justoci_bench --bench build --features justoci,oras
```

**4. Run a single case**

```sh
cargo bench -p swe_justoci_bench --bench build -- "build_oci_artifact/16mb"
```

### Output

Criterion prints results to stdout. An HTML report with plots is written to:

```
target/criterion/build_oci_artifact/report/index.html
```

This file is ephemeral — `cargo clean` removes it. Re-run the bench to regenerate.
