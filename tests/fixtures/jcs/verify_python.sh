#!/usr/bin/env bash
# verify_python.sh — drive the Python-side cross-language JCS verifier.
#
# Invokes verify_python.py against every fixture under
# tests/fixtures/jcs/. CI's `jcs-cross-lang` job calls this from the
# justoci checkout root.
#
# Exit codes:
#
#   0 — every fixture matched between Python and Rust.
#   1 — at least one fixture mismatched (real bug).
#   2 — environment setup failure (missing python, missing jcs).
#
# Run locally with:
#
#   bash tests/fixtures/jcs/verify_python.sh
#
# The Python program re-implements the spec_to_json projection from
# spec/src/saf/canonicalize.rs in Python. It does NOT consume any
# Rust artifact at runtime — that would defeat the cross-language
# proof.

set -euo pipefail

# Prefer python3, but fall back to python (Windows ships a Microsoft
# Store launcher named `python3` that fails on import; treat it as
# unusable and keep looking).
PY=""
if command -v python3 >/dev/null 2>&1 && python3 -c "" >/dev/null 2>&1; then
    PY=python3
elif command -v python >/dev/null 2>&1 && python -c "" >/dev/null 2>&1; then
    PY=python
else
    echo "verify_python.sh: no working Python ≥3.11 on PATH." >&2
    exit 2
fi

# Require the `jcs` package — RFC 8785 implementation. We don't auto-
# install in CI because that's a workflow-level concern; here we only
# fail loudly so the operator runs `pip install jcs` once.
if ! "$PY" -c "import jcs" >/dev/null 2>&1; then
    echo "verify_python.sh: 'jcs' package not installed. Run: $PY -m pip install jcs" >&2
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$PY" "$SCRIPT_DIR/verify_python.py" "$SCRIPT_DIR"
