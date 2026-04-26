#!/usr/bin/env bash
# verify_go.sh — drive the Go-side cross-language JCS verifier.
#
# Compiles tests/fixtures/jcs/verify_go and runs it against every
# fixture under tests/fixtures/jcs/. CI's `jcs-cross-lang` job calls
# this from the justoci checkout root.
#
# Exit codes:
#
#   0 — every fixture matched between Go and Rust.
#   1 — at least one fixture mismatched (real bug).
#   2 — environment setup failure (missing go, etc.).
#
# Run locally with:
#
#   bash tests/fixtures/jcs/verify_go.sh
#
# Hard rule: the Go program re-implements the spec_to_json projection
# from spec/src/saf/canonicalize.rs in Go. It does NOT consume any
# Rust artifact at runtime — that would defeat the cross-language
# proof. The fixtures (spec.toml + expected.canonical.json +
# expected.spec_hash) are the wire-format contract.

set -euo pipefail

if ! command -v go >/dev/null 2>&1; then
    echo "verify_go.sh: 'go' is not on PATH; install Go ≥1.22 to run this." >&2
    exit 2
fi

# Resolve script-relative paths so the script works regardless of cwd.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURES_DIR="$SCRIPT_DIR"
GO_DIR="$SCRIPT_DIR/verify_go"

if [[ ! -d "$GO_DIR" ]]; then
    echo "verify_go.sh: missing $GO_DIR" >&2
    exit 2
fi

# Build first so a compile error is distinct from a verification
# failure. The binary is dropped in $GO_DIR and removed on exit.
BIN="$GO_DIR/verify_go.bin"
trap 'rm -f "$BIN"' EXIT

(cd "$GO_DIR" && go build -o "$BIN" .)

# Run against the fixtures dir (the script's own dir minus the
# verify_go subdirectory; the Go program filters that out itself).
"$BIN" "$FIXTURES_DIR"
