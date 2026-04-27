# JCS cross-language fixtures

This directory holds the reference material that backs the
"justoci's spec hash is reproducible across language re-implementations"
claim from Production Guarantee §3 (see
[`docs/3-design/canonicalisation.md`](../../../docs/3-design/canonicalisation.md)).

Without it, the JCS portability claim is unverified — we trust
[`serde_jcs`](https://crates.io/crates/serde_jcs) to be RFC-8785-correct,
but never prove that another language's RFC-8785 implementation,
fed the same projected JSON, produces byte-identical canonical
output and the same SHA-256 digest.

This fixture set closes that gap.

## Layout

```
tests/fixtures/jcs/
├── README.md                      ← you are here
├── verify_go/                     ← Go cross-lang verifier (program + go.mod)
├── verify_go.sh                   ← shell wrapper CI invokes
├── verify_python.py               ← Python cross-lang verifier
├── verify_python.sh               ← shell wrapper CI invokes
├── minimal-raw-image/             ← anchor fixture
│   ├── spec.toml                  ← input
│   ├── layer-files/               ← zero-byte files the validator needs to exist
│   ├── expected.canonical.json    ← Rust impl's JCS bytes (the contract)
│   ├── expected.spec_hash         ← `sha256:<hex>` digest, single line
│   └── README.md                  ← the bug a cross-lang regression would surface
├── unicode-strings/
├── numeric-edge-cases/
├── nested-key-ordering/
└── vm-image-three-layer/
```

Every fixture's `README.md` names the bug a re-implementation would
have to reproduce to pass it. This is the same rule
`docs/4-development/developer_guide.md` and `docs/5-testing/testing_strategy.md`
apply to `#[test]` functions — a fixture that doesn't catch a real
regression class is dead weight.

## What gets verified

For each fixture, the cross-lang verifier:

1. Parses `spec.toml` via the language's TOML parser.
2. Replicates the `spec_to_json` projection rules from the Rust impl
   (`spec/src/saf/canonicalize.rs`) — field omission, BTreeMap
   key ordering, enum string forms, path normalisation, default
   `[attestation]` block, etc.
3. Runs the language's RFC 8785 implementation.
4. SHA-256s the result.
5. Compares against `expected.canonical.json` (byte equality) and
   `expected.spec_hash` (string equality).

Mismatches mean the language re-implementation diverges from Rust
on some projection rule or RFC 8785 edge case.

## Running locally

### Go (mandatory in CI)

Requires Go ≥1.22 on PATH.

```bash
bash tests/fixtures/jcs/verify_go.sh
```

The script builds `tests/fixtures/jcs/verify_go/` and runs it
against every fixture in this directory.

### Python (optional in CI; provided for completeness)

Requires Python ≥3.11 (for stdlib `tomllib`) and the `jcs` package:

```bash
python -m pip install jcs
bash tests/fixtures/jcs/verify_python.sh
```

## Regenerating expected files

When the Rust spec projection rules legitimately change (e.g. a new
optional field is added to `Spec`, or a default value is updated),
the `expected.canonical.json` and `expected.spec_hash` files in
each fixture become stale and the cross-lang verifiers will
correctly fail. To refresh them from the current Rust impl:

```bash
cargo run -p swe_justoci_oci_cli --bin regenerate-jcs-fixtures
```

This walks every subdirectory under `tests/fixtures/jcs/`, calls
`spec::canonical_bytes` and `spec::spec_hash` on each fixture's
`spec.toml`, and rewrites the `expected.*` files in place. Output
prints `regen <name>` for every fixture it changed and `ok <name>`
for fixtures already up to date.

To verify staleness without rewriting (CI uses this to fail loudly
when a fixture drifts from the Rust impl unannounced):

```bash
cargo run -p swe_justoci_oci_cli --bin regenerate-jcs-fixtures -- --check
```

Exit 0 if every fixture is fresh, exit 1 if any would change.

After regenerating, the cross-language verifiers will re-pass only
after the Go / Python re-implementations have been updated to match
the new projection rules. **A regeneration that "fixes" a CI failure
without a corresponding cross-language update is the bug the fixture
set is here to catch.**

## Why both expected.canonical.json and expected.spec_hash?

The hash alone catches mismatches but doesn't tell you *where* the
canonical bytes diverged. The verifier compares the canonical bytes
first, prints a windowed diff at the first differing byte, then
checks the hash. Operators debugging a cross-lang failure get a
"this is what your impl produced vs ours, here's the byte offset"
report instead of "your hash is wrong, good luck".

Storing both also serves as a sanity check: if the canonical bytes
match but the hash doesn't, somebody's SHA-256 is broken (rare but
possible — historically a few language SHA-256 impls have had
endianness bugs on big-endian platforms).

## Adding a new fixture

1. `mkdir tests/fixtures/jcs/<name>/layer-files/` and create the
   spec.toml plus the zero-byte stand-in files referenced by
   `[[layers]]` source / files entries (the validator existence-tests
   layer source paths).
2. Write a `README.md` explaining the projection-rule edge case the
   fixture exercises and the bug a cross-lang regression would surface.
3. Run `cargo run -p swe_justoci_oci_cli --bin regenerate-jcs-fixtures`
   to produce `expected.canonical.json` and `expected.spec_hash`.
4. Run `bash tests/fixtures/jcs/verify_go.sh` to confirm Go agrees.
5. Optionally run `bash tests/fixtures/jcs/verify_python.sh` for
   Python.
6. Commit all of the above in one change.
