#!/usr/bin/env bash
# compare_oras.sh — time `oras push` for the same payload sizes that
# the Criterion bench uses. Run on Linux (or WSL2) with a local registry.
#
# Requires: oras, docker (to run a local registry), dd
# Run:   bash scripts/bench/compare_oras.sh
#
# NOTE: oras pushes to a registry over loopback; the Criterion bench
# writes to disk with no network. The numbers are not directly
# comparable — this script measures the oras pipeline (tar + HTTP
# push) vs justoci's pipeline (tar + compress + CAS write to tmpfs).
# They serve different operations; see docs/5-testing/benchmarks.md.

set -euo pipefail

require() { command -v "$1" >/dev/null 2>&1 || { echo "error: $1 not found"; exit 1; }; }
require oras
require docker
require dd

RUNS=10
REGISTRY_PORT=15000
TMPDIR=$(mktemp -d)
trap 'docker stop bench-registry 2>/dev/null; rm -rf "$TMPDIR"' EXIT

# Start a throwaway local registry.
docker run -d --rm --name bench-registry \
    -p "${REGISTRY_PORT}:5000" \
    registry:2 >/dev/null 2>&1 || {
    echo "warn: could not start local registry — ensure Docker is running"
    exit 1
}
sleep 1   # let it start

run_oras_push() {
    local label=$1 size_bytes=$2
    local payload="$TMPDIR/payload.bin"
    local total_ns=0
    local ref="localhost:${REGISTRY_PORT}/bench:${label}"

    dd if=/dev/urandom bs="$size_bytes" count=1 2>/dev/null > "$payload"

    for _ in $(seq 1 $RUNS); do
        local start end
        start=$(date +%s%N)
        oras push --plain-http "$ref" \
            "${payload}:application/octet-stream" >/dev/null 2>&1
        end=$(date +%s%N)
        total_ns=$(( total_ns + end - start ))
    done

    local mean_us=$(( total_ns / RUNS / 1000 ))
    printf "oras push  %-6s  %8d µs  (mean over %d runs, loopback registry)\n" \
        "$label" "$mean_us" "$RUNS"
}

echo "oras comparison ($(oras version 2>&1 | head -1))"
echo "-------------------------------------------------------------------"
run_oras_push "4KB"   4096
run_oras_push "1MB"   1048576
run_oras_push "16MB"  16777216
echo ""
echo "Compare against: cargo bench -p swe_justoci_oci_build --bench build_layout"
echo "Note: oras pushes to a registry; justoci writes to local disk. Operations differ."
