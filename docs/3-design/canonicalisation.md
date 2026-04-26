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

- **Object keys sorted lexicographically** (UTF-16 code-unit order
  per RFC 8785 §3.2.3 — *not* UTF-8 byte order; the difference
  matters for keys containing surrogate-pair characters).
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

- Empty `[config]` (no keys) is treated as "absent" — `config`
  is omitted from the canonical JSON. This is consistent with
  `Option<>` field handling but worth stating explicitly because
  `[config]` isn't `Option<>` at the type level: `ConfigBlob`
  defaults to an empty `serde_json::Object`, and `config_to_json`
  in `spec/src/saf/canonicalize.rs` collapses an empty object to
  `None` before insertion. A re-implementation that emits
  `"config": {}` will produce a different hash.
- `description`, `slsa.builder_id`, and `sign.identity` follow
  the same rule: `None` → key absent, never `null`.
- `[platform]` is omitted only when **both** `os` *and* `arch`
  are absent. `os` set, `arch` absent emits `{"os": "..."}` (with
  no `arch` key) — the per-field omission rule applies inside the
  block as well.
- `annotations` is omitted when the `BTreeMap` is empty.

### The `[attestation]` block is always emitted

`[attestation]` is the one structural exception to the omission
rule. Even when the source TOML has no `[attestation]` section at
all (and `RawSpec.attestation` deserialises to `None`),
`core/validate.rs` substitutes `AttestationConfig::default()`,
and the canonicalised JSON contains a fully-populated
`"attestation"` object with the default `slsa`, `sbom`, and
`sign` sub-objects.

This is a "default config when absent" rule, *not* the omission
rule. A Go/Python/TypeScript re-implementation that copies
"absent → omit" too literally produces a hash that differs from
Rust on every spec that doesn't write `[attestation]`
explicitly — the `minimal-raw-image/` fixture under
`tests/fixtures/jcs/` is the regression test for exactly this
mistake. See "Default `[attestation]` values" below for the
substituted defaults a re-implementation MUST inject.

### Default `[attestation]` values

When a spec omits `[attestation]` (or omits one of the three
sub-blocks `[attestation.slsa]`, `[attestation.sbom]`,
`[attestation.sign]`), the canonicaliser substitutes the
following defaults. The product opinion lives in each sub-type's
`Default` impl in
[`spec/src/api/attestation.rs`](../../spec/src/api/attestation.rs);
the values enumerated here MUST stay in sync with that file.

- `SlsaConfig::default()`:
  - `level = SlsaLevel::L2` → JSON `"level": 2`
  - `builder_id = None` → key omitted from JSON
  (a `None` `builder_id` means "auto-derive at build time from
  `<git remote>@<rev>`"; this is a runtime concern, but the
  canonical hash must not bake the derived value in)
- `SbomConfig::default()`:
  - `format = SbomFormat::CycloneDx` → JSON `"format": "cyclonedx"`
  - `scope = SbomScope::Layers` → JSON `"scope": "layers"`
- `SignConfig::default()`:
  - `kind = SignKind::CosignKeyless` → JSON `"kind": "cosign-keyless"`
  - `identity = None` → key omitted from JSON

A spec with no `[attestation]` at all therefore canonicalises
its `attestation` field to:

```json
{
  "slsa": {"level": 2},
  "sbom": {"format": "cyclonedx", "scope": "layers"},
  "sign": {"kind": "cosign-keyless"}
}
```

If `Default::default()` for any of these sub-types changes, the
JCS fixtures regenerate (and every recorded `expected.spec_hash`
moves) — a deliberate signal that the on-by-default posture has
shifted.

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
the same hash for the same spec. The same rule applies to
`LayerSource::Files { entries }` — every `entry.source` runs
through `normalise_path` before insertion.

## TOML → JSON value projection

The `[config]` block deserialises to a `toml::Value` (TOML is
typed) and then projects to `serde_json::Value` for
canonicalisation. The mapping lives in
`spec/src/core/validate.rs::toml_to_json` and is the only path
where TOML's type system differs meaningfully from JSON's. A
Go/Python/TypeScript re-implementation MUST apply these rules
identically:

| TOML type | JSON projection | Notes |
|---|---|---|
| `String` | JSON string | UTF-8 source bytes; JCS handles escaping per RFC 8785 (control chars `\u0000`–`\u001F` get `\uXXXX`; non-ASCII codepoints emit as raw UTF-8, NOT `\uXXXX`) |
| `Integer` | JSON integer | TOML lexical forms collapse: `1_000_000` → `1000000`, octal `0o644` → `420`, hex `0xff` → `255`, binary `0b1010` → `10`. The textual form is *not* preserved — re-impls that round-trip the lexeme will mismatch. |
| `Float` | JSON number | ECMA-262 round-trip form per RFC 8785 §3.2.2.3: no trailing `.0` when the value is a whole-number-as-double (note: TOML `1.0` is a float, but the JSON projection emits `1` because JCS uses ECMA-262 numeric formatting which drops the `.0` for integer-valued doubles); lowercase `e`; scientific notation only when shorter than the decimal form (`1e+21`, but `0.001` not `1e-3`). |
| `Boolean` | JSON `true` / `false` | identity |
| `Array` | JSON array | Order preserved; elements project recursively. |
| `Table` | JSON object | Keys sorted lexicographically (UTF-16 code-unit order per JCS) at every nesting level. The Rust impl uses `BTreeMap` to pre-sort; JCS re-sorts at the byte level, but the projection MUST produce a stable order so tests can predict the JSON output without invoking JCS. |
| `Datetime` | JSON string | TOML's typed datetime variants (offset-datetime, local-datetime, local-date, local-time) all project via `toml::value::Datetime::to_string()`, which is RFC 3339 / ISO 8601-shaped (`2026-04-26T12:00:00Z`, `2026-04-26`, `12:00:00`, etc.). The OCI image config blob is untyped JSON, so the typed TOML datetime collapses to its string form; a re-impl that emits a JSON object like `{"$date": "..."}` or a numeric epoch will mismatch. |

The `numeric-edge-cases/` and `nested-key-ordering/` fixtures
under `tests/fixtures/jcs/` are the regression tests for this
table. Worked examples for re-impl authors live next to each
fixture's `README.md`.

## What goes into the hash

```text
{
  "spec_version": "0",
  "id":           "<name>:<tag>",
  "kind":         "<kind>",
  "description":  "...",            // omitted if None
  "platform":     {...},            // omitted if both os and arch are absent
  "layers":       [...],            // ordered as written
  "config":       {...},            // omitted if empty object (see "Optional fields ...")
  "annotations":  {...},            // omitted if empty
  "attestation":  {                 // ALWAYS present — see "The [attestation] block is always emitted"
    "slsa": {"level": N, "builder_id": "..."},  // builder_id omitted if None
    "sbom": {"format": "...", "scope": "..."},
    "sign": {"kind": "...", "identity": "..."}  // identity omitted if None
  }
}
```

`description`, `platform`, `config`, `annotations`, `slsa.builder_id`,
and `sign.identity` are the only fields that change shape based
on input. Everything else is always present in the canonical
form — including the entire `attestation` object, which is
substituted with `AttestationConfig::default()` when the source
TOML omits `[attestation]`. See the
"The `[attestation]` block is always emitted" and
"Default `[attestation]` values" subsections above for the
complete substitution rules.

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
