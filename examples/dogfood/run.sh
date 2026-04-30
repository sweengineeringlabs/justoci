#!/usr/bin/env bash
#
# Dogfood end-to-end smoke test (justoci issue #6, no-attest path).
#
# Spins up a local `registry:2` Docker container on a free port, then
# drives the full justoci pipeline against it:
#
#   1. justoci build firmware.spec.toml -o dist/ --no-attest
#   2. justoci publish dist/ --to "registry:localhost:$PORT/dogfood/firmware:v1" --no-auth
#   3. justoci verify "localhost:$PORT/dogfood/firmware:v1" --no-auth
#
# The container is torn down on EXIT (success OR failure) via a trap so
# a crashed run doesn't leave a registry+port lingering.
#
# Prereqs: docker on PATH, cargo on PATH, python on PATH (for the port
# probe — every modern dev box has it; we don't reach for nc to keep
# the script Windows-Git-Bash-friendly).
#
# Attestation is intentionally OFF (`--no-attest`); the cosign + Sigstore
# end-to-end proof lives in issue #14.

set -euo pipefail

# Always operate from the script's directory so paths in the spec
# resolve regardless of where the operator invoked the script.
cd "$(dirname "$0")"

# ─── Pick an unused local TCP port ──────────────────────────────────
# We don't hard-code 5000: the developer might already have something
# there (nc, dev-mode dnsmasq, another registry). Python's socket
# library asks the kernel for an ephemeral port, then closes the
# socket — the kernel keeps the port in TIME_WAIT briefly but the
# Docker container reusing it is fine because SO_REUSEADDR works.
PORT="$(python - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"
if [[ -z "${PORT:-}" ]]; then
    echo "✗ failed to probe a free port" >&2
    exit 1
fi
REGISTRY="localhost:${PORT}"
REPO="dogfood/firmware"
TAG="v1"
REF="${REGISTRY}/${REPO}:${TAG}"
CONTAINER_NAME="dogfood-registry-${PORT}"

cleanup() {
    local rc=$?
    # Best-effort container teardown. `|| true` because we don't want
    # cleanup failures to mask the real exit code from the pipeline.
    docker stop "${CONTAINER_NAME}" >/dev/null 2>&1 || true
    if [[ "${rc}" -ne 0 ]]; then
        echo "✗ dogfood failed (exit ${rc}). For diagnosis:" >&2
        echo "    docker logs ${CONTAINER_NAME}" >&2
    fi
    exit "${rc}"
}
trap cleanup EXIT

echo "→ port:      ${PORT}"
echo "→ ref:       ${REF}"
echo "→ container: ${CONTAINER_NAME}"

# ─── Spin up registry:2 ─────────────────────────────────────────────
echo "→ starting registry:2"
docker run -d --rm \
    -p "${PORT}:5000" \
    --name "${CONTAINER_NAME}" \
    registry:2 >/dev/null

# Poll /v2/ until the registry answers. The 200-OK probe is the
# OCI Distribution standard liveness ping; any 4xx/5xx means the
# server is up but possibly mis-deployed, which we want to surface
# rather than silently retry.
echo "→ waiting for registry to become reachable"
for i in {1..20}; do
    code="$(curl -s -o /dev/null -w '%{http_code}' "http://${REGISTRY}/v2/" || true)"
    if [[ "${code}" == "200" ]]; then
        echo "  ready after ~$((i * 500))ms"
        break
    fi
    if [[ "${i}" -eq 20 ]]; then
        echo "✗ registry never reached HTTP 200 on /v2/ (last code: ${code})" >&2
        exit 1
    fi
    sleep 0.5
done

# ─── Stage a clean dist/ ────────────────────────────────────────────
# Build crate writes to <output>.partial then renames; if a previous
# failed run left dist/ behind, the build still proceeds (atomic
# rename overwrites), but we wipe it to make the run reproducible
# and to keep the byte counts in publish's stdout meaningful.
rm -rf dist dist.partial

# ─── Build / publish / verify ───────────────────────────────────────
# Plain HTTP for localhost requires the JUSTOCI_ALLOW_INSECURE=1
# opt-in. The publish + verify wires both honour it.
export JUSTOCI_ALLOW_INSECURE=1

# Workspace root is two levels up. Cargo invocations honour
# `--manifest-path` so the script is callable from anywhere.
WORKSPACE_ROOT="$(cd ../.. && pwd)"
CARGO_RUN=(
    cargo run
    --manifest-path "${WORKSPACE_ROOT}/Cargo.toml"
    -p swe_justoci_oci_cli
    --release
    --quiet
    --
)

echo "→ build"
# `-o dist` (no trailing slash) — the build crate writes to
# `<output>.partial` and renames; `dist/` would yield a `dist/.partial`
# subdirectory and the rename never happens.
"${CARGO_RUN[@]}" build firmware.spec.toml -o dist --no-attest

echo "→ publish to ${REF}"
"${CARGO_RUN[@]}" publish dist --to "registry:${REF}" --no-auth

echo "→ verify ${REF}"
"${CARGO_RUN[@]}" verify "${REF}" --no-auth

echo
echo "✓ dogfood passed — built, pushed, pulled-and-verified through registry:2 at port ${PORT}"
