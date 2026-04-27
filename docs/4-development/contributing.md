# Contributing

## The cardinal rule

**Every test names the bug it would catch.**

If you write a test and can't articulate the regression that test
would surface, the test is a smoke test and adds noise. Delete it
and write one that asserts a specific behaviour.

This is enforced socially in code review and culturally by every
existing test having a one-paragraph docstring naming the bug.
Match the pattern.

```rust
/// `gc` ignores in-flight `.tmp-*` temp files belonging to a
/// concurrent `put`.
///
/// Bug it catches: a naive `gc` that walks every file in the blob
/// directory would remove a half-written temp file *while* another
/// thread/process is writing it, losing in-progress work. The temp
/// file naming pattern (`.tmp-<pid>-<nanos>`) must be respected.
#[test]
fn test_gc_skips_in_flight_temp_files() { ... }
```

## Other rules that apply

- **No `#[allow(...)]` to silence clippy.** Refactor to express
  the intent. CI runs `RUSTFLAGS=-D warnings`; if you can't
  avoid the warning, the code is probably wrong.

- **No `anyhow::Result` in public APIs.** Each crate defines a
  typed error enum (`SpecError`, `BuildError`, `AttestError`,
  `PublishError`, `RegistryPullError`, `VerifyError`). Add
  variants when the existing ones don't fit; never `anyhow!`
  away typed errors.

- **No silent half-states.** If an operation can succeed
  partially (build → attest, sign → Rekor record), the failure
  mode must produce a typed error and leave the on-disk state
  inspectable. Production Guarantee §6 — see
  [`3-design/production_guarantees.md`](../3-design/production_guarantees.md).

- **No AI-attribution lines in commits.** Standing convention.

## PR process

1. **Fork or branch.** Internal contributors: feature branches
   under `dev` then merge across the six-branch flow
   (dev → test → int → uat → prd → main).

2. **Write the bug-it-catches docstring first.** Then the test.
   Then the fix.

3. **Match the SEA layering.** Each crate has `api/` (public
   types, traits, errors), `core/` (algorithms, no IO), `spi/`
   (concrete implementations of traits), `saf/` (the public
   facade — single function entry points). Don't put an
   IO-touching algorithm in `core/`; don't put a public trait in
   `spi/`.

4. **Update the relevant doc page.** The roadmap, the
   architecture page, the troubleshooting page — whichever
   covers what you changed.

5. **Run CI gates locally.** `cargo fmt --all -- --check &&
   cargo clippy --workspace --all-targets -- -D warnings &&
   cargo test --workspace`. CI re-runs these but locally is
   faster.

## Commit message conventions

```
type(scope): one-line subject in imperative mood

Body: what changed, why, and what bug class the change addresses.
Reference issues / commits as needed.

For test additions: each new test names the bug it catches in its
docstring; the commit body summarises the bug class.

For non-trivial design changes: link to the relevant doc page
that captures the decision.
```

`type` is one of `feat`, `fix`, `refactor`, `docs`, `test`,
`chore`, `ci`, `perf`. `scope` is the crate or sub-module.

## Adding a feature

The high-level flow:

1. Read `docs/0-ideation/roadmap.md` to confirm scope.
2. If the feature is non-trivial, draft a short design note —
   one page in `docs/3-design/<topic>.md` covering: what, why,
   the failure modes, the rollback strategy.
3. Implement with the bug-it-catches test discipline above.
4. Update the production-guarantees page if the feature changes
   any guarantee (rare; the guarantees are intentionally stable).
5. Update the spec doc if the change is user-visible (CLI flag,
   new spec field, new exit code).

## Adding a kind

[`adding-a-kind.md`](./adding-a-kind.md) walks through the recipe
for adding a new artifact `kind` (e.g. `wasm_module`,
`helm_chart`).

## Code review focus

In review, the reviewer asks:

1. Does each new test name a real bug it catches? (No
   tautological assertions, no smoke tests.)
2. Are the new error variants typed, with actionable context?
   (Path on IO error, expected vs actual on digest mismatch.)
3. Are the new code paths warning-free under `-D warnings`?
4. Does the change preserve the production guarantees?
   Reproducibility, atomicity, integrity-on-read, coupled
   signing — none can regress.
5. Is there a doc update? (Even one-line entries in the roadmap
   or troubleshooting page matter.)
