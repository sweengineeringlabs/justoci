#!/usr/bin/env python3
"""verify_python — cross-language JCS fixture verifier (Python side).

For each fixture in tests/fixtures/jcs/<name>/, this program:

  1. Loads spec.toml via the stdlib `tomllib` (Python 3.11+).
  2. Projects it into a Python value tree following the same rules
     spec/src/saf/canonicalize.rs::spec_to_json applies in Rust.
  3. Runs RFC 8785 JCS via the `jcs` package (PyPI: jcs).
  4. Computes sha256 of the canonical bytes.
  5. Asserts byte-equality against expected.canonical.json and
     expected.spec_hash.

Exit code:

  0 — every fixture matches.
  1 — at least one fixture mismatched (real bug — Python and Rust
      impls disagree on the JCS canonical form).
  2 — environment / fixture-loading failure (not a JCS-impl bug).

This program intentionally does NOT depend on any Rust artifact at
runtime. It re-implements the projection in Python so the fixture
proves cross-language agreement, not that two halves of the same
impl agree.

Hard rule: do not pass `ensure_ascii=True` (the json.dumps default)
anywhere in this file, and do not call json.dumps before jcs. JCS
emits non-ASCII characters as raw UTF-8 bytes, not \\u escapes; a
preliminary json.dumps with ensure_ascii=True would create that bug.
"""

from __future__ import annotations

import hashlib
import os
import sys
import tomllib
from pathlib import Path
from typing import Any

import jcs


# ──────────────────────────────────────────────────────────────────────
# Projection — mirrors spec/src/saf/canonicalize.rs::spec_to_json.
# ──────────────────────────────────────────────────────────────────────

def project_spec(raw: dict[str, Any]) -> dict[str, Any]:
    """Project a tomllib-loaded raw spec into the canonical JSON shape."""
    out: dict[str, Any] = {}
    out["spec_version"] = raw["spec_version"]
    out["id"] = raw["id"]
    out["kind"] = raw["kind"]

    if "description" in raw:
        out["description"] = raw["description"]

    plat = project_platform(raw.get("platform"))
    if plat is not None:
        out["platform"] = plat

    out["layers"] = project_layers(raw.get("layers", []))

    cfg = project_config(raw.get("config"))
    if cfg is not None:
        out["config"] = cfg

    ann = project_annotations(raw.get("annotations"))
    if ann is not None:
        out["annotations"] = ann

    out["attestation"] = project_attestation(raw.get("attestation"))
    return out


def project_platform(p: dict[str, Any] | None) -> dict[str, Any] | None:
    if p is None:
        return None
    if p.get("os") is None and p.get("arch") is None:
        return None
    out: dict[str, Any] = {}
    if "os" in p:
        out["os"] = p["os"]
    if "arch" in p:
        out["arch"] = p["arch"]
    return out


def project_layers(layers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for i, l in enumerate(layers):
        has_source = "source" in l
        has_files = "files" in l and len(l["files"]) > 0
        if has_source and has_files:
            raise ValueError(f"layer #{i}: both `source` and `files` set")
        if not has_source and not has_files:
            raise ValueError(f"layer #{i}: neither `source` nor `files` set")

        media_type = l["media_type"]
        compression = l.get("compression") or default_compression(media_type)

        obj: dict[str, Any] = {
            "media_type": media_type,
            "compression": compression,
        }
        if has_source:
            obj["source"] = normalise_path(l["source"])
        else:
            files = []
            for f in l["files"]:
                files.append({
                    "source": normalise_path(f["source"]),
                    "dest": f["dest"],
                    # mode is u32 in Rust; tomllib gives int. JCS will
                    # serialise as a JSON number.
                    "mode": int(f["mode"]),
                })
            obj["files"] = files
        out.append(obj)
    return out


def project_config(c: Any) -> Any:
    """Empty mapping → None (omit). Otherwise recursively project."""
    if c is None:
        return None
    if isinstance(c, dict) and len(c) == 0:
        return None
    return toml_to_json(c)


def toml_to_json(v: Any) -> Any:
    """Convert a tomllib value tree into a JCS-marshalable shape.

    tomllib types map cleanly:

        bool        → bool
        int         → int    (TOML integer; JCS emits as JSON number)
        float       → float  (TOML float;   JCS emits with ECMA-262 round-trip)
        str         → str
        list        → list   (recursive)
        dict        → dict   (recursive)
        datetime    → ISO-8601 string  (TOML datetimes are typed; the
                                        OCI config blob isn't, so they
                                        project to RFC3339 string form,
                                        matching what the Rust validator
                                        does via toml::Datetime.to_string())
    """
    import datetime as _dt
    if isinstance(v, dict):
        return {k: toml_to_json(val) for k, val in v.items()}
    if isinstance(v, list):
        return [toml_to_json(e) for e in v]
    if isinstance(v, (_dt.datetime, _dt.date, _dt.time)):
        return v.isoformat()
    return v


def project_annotations(a: dict[str, str] | None) -> dict[str, str] | None:
    if not a:
        return None
    return dict(a)


def project_attestation(a: dict[str, Any] | None) -> dict[str, Any]:
    """Always emit — defaults if absent."""
    a = a or {}
    return {
        "slsa": project_slsa(a.get("slsa")),
        "sbom": project_sbom(a.get("sbom")),
        "sign": project_sign(a.get("sign")),
    }


def project_slsa(s: dict[str, Any] | None) -> dict[str, Any]:
    s = s or {}
    out: dict[str, Any] = {"level": int(s.get("level", 2))}
    if "builder_id" in s:
        out["builder_id"] = s["builder_id"]
    return out


def project_sbom(s: dict[str, Any] | None) -> dict[str, Any]:
    s = s or {}
    return {
        "format": s.get("format", "cyclonedx"),
        "scope": s.get("scope", "layers"),
    }


def project_sign(s: dict[str, Any] | None) -> dict[str, Any]:
    s = s or {}
    out: dict[str, Any] = {"kind": s.get("kind", "cosign-keyless")}
    if "identity" in s:
        out["identity"] = s["identity"]
    return out


def default_compression(media_type: str) -> str:
    if media_type.endswith("+gzip"):
        return "gzip"
    if media_type.endswith("+zstd"):
        return "zstd"
    return "none"


def normalise_path(p: str) -> str:
    return p.replace("\\", "/")


# ──────────────────────────────────────────────────────────────────────
# Driver — walk fixtures, verify each, report.
# ──────────────────────────────────────────────────────────────────────

def verify_fixture(dir_path: Path) -> tuple[bool, str]:
    spec_path = dir_path / "spec.toml"
    with open(spec_path, "rb") as f:
        raw = tomllib.load(f)

    projected = project_spec(raw)

    # jcs.canonicalize(...) returns bytes when utf8=True (default).
    canonical = jcs.canonicalize(projected)
    if not isinstance(canonical, (bytes, bytearray)):
        canonical = canonical.encode("utf-8")

    expected_canonical = (dir_path / "expected.canonical.json").read_bytes()
    if canonical != expected_canonical:
        return False, _diff(canonical, expected_canonical)

    digest = "sha256:" + hashlib.sha256(canonical).hexdigest()
    expected_hash = (dir_path / "expected.spec_hash").read_text().rstrip("\n")
    if digest != expected_hash:
        return False, f"spec_hash mismatch: got {digest}, want {expected_hash}"

    return True, ""


def _diff(got: bytes, want: bytes) -> str:
    n = min(len(got), len(want))
    idx = -1
    for i in range(n):
        if got[i] != want[i]:
            idx = i
            break
    if idx == -1 and len(got) != len(want):
        idx = n
    if idx == -1:
        return "(equal)"
    w = 40
    a0, a1 = max(0, idx - w), min(len(got), idx + w)
    b0, b1 = max(0, idx - w), min(len(want), idx + w)
    return (
        f"canonical bytes differ at offset {idx}:\n"
        f"  got  ({len(got)} bytes) ...{got[a0:a1]!r}...\n"
        f"  want ({len(want)} bytes) ...{want[b0:b1]!r}..."
    )


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: verify_python.py <fixtures-dir>", file=sys.stderr)
        return 2
    root = Path(sys.argv[1])
    if not root.is_dir():
        print(f"not a directory: {root}", file=sys.stderr)
        return 2

    dirs: list[Path] = []
    for entry in sorted(os.listdir(root)):
        d = root / entry
        if not d.is_dir():
            continue
        # Skip helper subdirs.
        if entry in {"verify_go"}:
            continue
        if (d / "spec.toml").is_file():
            dirs.append(d)

    if not dirs:
        print(f"no fixtures found under {root}", file=sys.stderr)
        return 2

    pass_count = 0
    fail_count = 0
    for d in dirs:
        try:
            ok, detail = verify_fixture(d)
        except Exception as e:  # any unexpected error is a fixture-load problem
            print(f"FAIL  {d.name}")
            print(f"       unexpected: {type(e).__name__}: {e}")
            fail_count += 1
            continue
        if ok:
            print(f"PASS  {d.name}")
            pass_count += 1
        else:
            print(f"FAIL  {d.name}")
            print(f"       {detail}")
            fail_count += 1

    print()
    print(f"{pass_count} passed, {fail_count} failed (out of {len(dirs)})")
    return 1 if fail_count else 0


if __name__ == "__main__":
    raise SystemExit(main())
