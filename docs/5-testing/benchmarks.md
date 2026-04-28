# justoci benchmarks

**Audience**: Contributors, adopters evaluating build pipeline throughput.

> **TLDR**: `oci_build::build` sustains **~200 MiB/s** for 16 MB artifacts with ~20 ms fixed overhead per build. The fixed overhead covers CAS init, manifest/config JSON serialization, and atomic rename — not data processing. Run `cargo bench -p swe_justoci_oci_build --bench build_layout` to reproduce.

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
| 4 KB | **21.7 ms** | 184 KiB/s |
| 1 MB | **21.9 ms** | 45.7 MiB/s |
| 16 MB | **81.2 ms** | 197 MiB/s |

## What the numbers mean

The 4 KB and 1 MB cases take nearly identical time (~21 ms), showing that **fixed overhead dominates small artifacts**. That ~20 ms covers:
- `TempDir::new()` (setup cost, included in `iter_batched` window)
- CAS blob write (atomic tmp → rename)
- OCI manifest + config JSON serialization
- `index.json` + `oci-layout` writes
- Final `.partial` → output dir rename

For 16 MB the data-processing cost (~60 ms above the baseline) takes over and throughput reaches ~200 MiB/s — this is NTFS write bandwidth for uncompressed `application/octet-stream` layers.

### Implication for real use cases

Firmware images, ML model weights, and VM rootfs blobs are typically 10–500 MB. In that range justoci runs at **100–200 MiB/s**, meaning a 100 MB artifact takes ~500 ms end-to-end including CAS write and manifest assembly. A 500 MB rootfs takes ~2.5 s.

The overhead per build (~20 ms) is a constant tax paid regardless of size. For pipelines building many small artifacts, batching into larger layers pays off.

## Market comparison

Run `scripts/bench/compare_oras.sh` on Linux with Docker available. The script times `oras push` to a local registry for the same payload sizes. Note: `oras push` and `oci_build::build` do different things — oras pushes a pre-built blob to a registry over HTTP, while justoci assembles the OCI layout locally. The numbers are not directly comparable; the script notes this explicitly.

## Reproducing

```sh
cargo bench -p swe_justoci_oci_build --bench build_layout
```

The bench generates an HTML report at `target/criterion/build_oci_artifact/report/index.html` (ephemeral — deleted by `cargo clean`; re-run the bench to regenerate).
