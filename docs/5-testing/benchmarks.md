# justoci benchmarks

**Audience**: Contributors, adopters evaluating build pipeline throughput.

> **TLDR**: `oci_build::build` sustains **~220 MiB/s** writing an OCI layout to local disk, ~14 ms fixed overhead. For pushing to a registry, `oci_publish::publish` (in-process HTTP) reaches **~477 MiB/s** over loopback and is **4.7–7× faster than oras** — same operation, no subprocess. Run `cargo bench -p swe_justoci_bench --bench build` to reproduce.

## Bench architecture

The benchmark lives in `bench/benches/build.rs`. It exercises the full `oci_build::build` pipeline end-to-end with real disk I/O to a `tempfile::TempDir` on NTFS. The publish and oras runners push to a local `registry:2` container over loopback.

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
| Output | Real disk I/O to `%TEMP%` (NTFS) / loopback HTTP (publish, oras) |

## Results — `oci_build::build` (single-layer, `application/octet-stream`, no compression)

Each iteration creates a fresh output directory; the source blob is pre-written once and re-used.

| Payload | Mean time | Throughput |
|---|---|---|
| 4 KB | **14.5 ms** | 276 KiB/s |
| 1 MB | **17.7 ms** | 56.7 MiB/s |
| 16 MB | **72.7 ms** | 220 MiB/s |

## What the numbers mean

### Fixed overhead dominates small artifacts

The 4 KB and 1 MB justoci cases take nearly identical time (~15–18 ms). That floor covers five steps that happen regardless of payload size:

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

At 16 MB, data processing overtakes the fixed overhead and justoci reaches ~220 MiB/s (NTFS write bandwidth). Adding Gzip or Zstd compression reduces disk I/O at the cost of CPU; actual throughput depends on codec and compression ratio.

### Implication for real use cases

Firmware images, ML model weights, and VM rootfs blobs are typically 10–500 MB. justoci runs at **100–220 MiB/s** in that range — a 100 MB artifact takes ~450 ms, a 500 MB rootfs ~2.5 s. A full build-then-push pipeline adds a further ~34 ms for the push step.

## Comparison — end-to-end: justoci + publish vs oras

oras combines build and push in one subprocess call. The equivalent Rust pipeline is `oci_build::build` + `oci_publish::publish`. Both produce the same result: artifact in a registry. The combined times are measured separately and summed.

| Payload | justoci + publish | oras (build+push) | advantage |
|---|---|---|---|
| 4 KB | **53.5 ms** (14.5 + 39.0) | 181.9 ms | 3.4× |
| 1 MB | **51.1 ms** (17.7 + 33.4) | 168.0 ms | 3.3× |
| 16 MB | **106.3 ms** (72.7 + 33.6) | 233.8 ms | 2.2× |

### Push-only (pre-built layout)

If the OCI layout already exists on disk the build cost is not paid again. The relevant comparison is push only:

| Payload | publish (push only) | oras | advantage |
|---|---|---|---|
| 4 KB | **39.0 ms** | 181.9 ms | 4.7× |
| 1 MB | **33.4 ms** | 168.0 ms | 5.0× |
| 16 MB | **33.6 ms** / 477 MiB/s | 233.8 ms / 68.4 MiB/s | 7.0× |

oras fixed cost is ~170 ms — Go subprocess spawn plus the first HTTP round-trip. publish eliminates subprocess spawn entirely; the ~34 ms floor is the loopback HTTP cost alone (HEAD×N blobs + manifest PUT). At 16 MB the advantage grows further because oras's subprocess I/O path bottlenecks before the loopback link saturates.

## Reproducing

### Prerequisites

| Requirement | Notes |
|---|---|
| Rust stable toolchain | required |
| Docker (publish + oras) | `docker run -d -p 5000:5000 registry:2` |
| oras 1.x on PATH (oras runner) | `winget install ORASProject.ORAS` |

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

**3. Run with publish + oras comparison**

```sh
docker run -d -p 5000:5000 registry:2
OCIMAGE_ALLOW_INSECURE=1 cargo bench -p swe_justoci_bench --bench build --features justoci,publish,oras
```

`OCIMAGE_ALLOW_INSECURE=1` opts the publish runner into plain HTTP — required for local `registry:2`.

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
