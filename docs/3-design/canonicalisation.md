# JCS canonicalisation — the spec hash pipeline

## Why we need it

Production Guarantee §3 says: **same spec → same hash, across
language re-implementations, across hosts.**

The hash is the SLSA statement's pin on the build inputs. If a
Go re-implementation of justoci computed a different hash for the
same spec, SLSA verification across implementations would fail.

So the hash must be deterministic at the *bytes* level — not just
"hash whatever the parser produced," because parsers can vary.

## The pipeline

```
spec.toml file
      │
      │  serde + toml crate
      ▼
RawSpec (Rust struct)
      │
      │  validator
      ▼
Spec (typed, validated)
      │
      │  spec_to_json projection
      ▼
serde_json::Value (stable shape)
      │
      │  serde_jcs::to_vec (RFC 8785 JCS)
      ▼
canonical bytes (UTF-8)
      │
      │  sha256
      ▼
cas::Digest  ("sha256:<hex>")
```

Each step is deterministic and language-portable.

## RFC 8785 JCS

The [JSON Canonicalization Scheme](https://datatracker.ietf.org/doc/html/rfc8785)
is an IETF standard. Key rules:

- **Object keys sorted lexicographically** (UTF-8 code-unit order).
- **No insignificant whitespace.**
- **Numbers in ECMA-262 round-trip form** (no `.0` on integers, no
  scientific notation unless required).
- **Strings escaped per JSON spec** with specific escape rules for
  the `\u` form on control characters.

Implementations exist in Rust (`serde_jcs`), Go
(`gowebpki/jcs`), Python (`jcs`), JS (`canonicalize`), and Java.

The cross-implementation test fixture set under
[`tests/fixtures/jcs/`](../../tests/fixtures/jcs/) backs this
portability claim. Each fixture ships a `spec.toml`, the JCS
canonical bytes the Rust impl produces, and the resulting
`sha256:<hex>` digest. CI's `jcs-cross-lang` job builds a Go
re-implementation of the `spec_to_json` projection (under
`tests/fixtures/jcs/verify_go/`), runs `gowebpki/jcs` against it,
and asserts byte-for-byte agreement with the committed expected
files. A Python verifier (`tests/fixtures/jcs/verify_python.py`)
ships alongside for contributors who want the same check locally
in Python; both verifiers re-implement the projection so the
fixtures prove cross-*language* agreement, not that two halves of
the same impl agree. See `docs/5-testing/strategy.md` for the
fixture set's place in the overall test plan.

When the projection rules legitimately change (a new field is
added to `Spec`, an enum gets a new variant, etc.), regenerate
the expected files via:

```bash
cargo run -p swe_justoci_oci_cli --bin regenerate-jcs-fixtures
```

Then update the Go and Python re-implementations to match, in the
same commit.

## The `spec_to_json` projection

`spec/src/saf/canonicalize.rs` projects the typed `Spec` to a
`serde_json::Value` with these rules:

### Field naming matches TOML wire shape

`spec_version`, not `specVersion`. So a future Go re-impl can
parse the same TOML file via the same field names and reach the
same JSON without translation tables.

### Optional fields are omitted, not null-serialised

JCS treats `{"foo": null}` and `{}` as different — they hash
differently. We follow OCI's convention of *omitting* absent
fields, not emitting `null` values.

This means an empty `[platform]` (no `os`, no `arch`) becomes
`platform` absent from the JSON, not `"platform": {}`.

### Enums project to canonical strings

`Kind::VmImage` → `"vm_image"`. `Compression::Gzip` → `"gzip"`.
These match the values users write in TOML, so the round-trip
is bit-identical.

### `BTreeMap` for deterministic order

`Spec.annotations` is a `BTreeMap<String, String>`, not `HashMap`.
JCS re-sorts keys at the byte level, but starting from a sorted
source means the JSON tree we hand to JCS is already stable, and
tests can predict the JSON output without invoking JCS.

### Path separator normalisation

`LayerSource::Blob { path }` paths normalise `\` → `/` before
hashing, so a Windows build host and a Linux build host produce
the same hash for the same spec.

## What goes into the hash

```text
{
  "spec_version": "0",
  "id":           "<name>:<tag>",
  "kind":         "<kind>",
  "description":  "...",            // omitted if None
  "platform":     {...},            // omitted if both fields None
  "layers":       [...],            // ordered as written
  "config":       {...},            // omitted if empty object
  "annotations":  {...},            // omitted if empty
  "attestation":  {                 // always present
    "slsa": {"level": N, "builder_id": "..."},  // builder_id omitted if None
    "sbom": {"format": "...", "scope": "..."},
    "sign": {"kind": "...", "identity": "..."}  // identity omitted if None
  }
}
```

`description`, `platform`, `config`, `annotations`, `slsa.builder_id`,
and `sign.identity` are the only fields that change shape based
on input. Everything else is always present in the canonical form.

## What does NOT go into the hash

- **Source file contents.** The hash pins the *spec*; the layer
  digests in the OCI manifest pin the source contents separately.
- **Build environment** (cwd, hostname, timestamp). Captured in
  the SLSA statement's `runDetails`, not in the spec hash.
- **Build start / end timestamps.** SLSA records these
  separately; the spec hash is reproducible across runs.

## Verification

The spec hash can be re-computed by anyone with the spec file:

```bash
ocimage inspect spec.toml
# spec_hash: sha256:<hex>
# canonical: { ... canonical JSON ... }
```

A SLSA verifier reading the published artifact's SLSA statement
sees `externalParameters.spec_hash`. If it has access to the
original spec file, it can re-canonicalise + re-hash + compare.
This is the integrity check that ties the published artifact back
to the source spec.

See [`5-testing/strategy.md`](../5-testing/strategy.md) §"Bug list
the canonicaliser must catch" for the test set.
