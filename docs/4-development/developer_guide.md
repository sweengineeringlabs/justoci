# Developer guide

This guide is the canonical entry point for working on justoci.
It merges what used to live in `setup.md` (local toolchain +
sibling-repo layout) and `contributing.md` (workflow, the
bug-it-catches test rule, code-review focus) into a single
narrative. If you're adding a new artifact `kind`, see the
focused recipe in [`adding_a_kind.md`](./adding_a_kind.md).

## Branch model

`main` is the only long-lived branch on this repo. There is no
`dev → test → int → uat → prd → main` cascade — feature work
happens on short-lived `feature/<topic>` branches that merge to
`main` via PR. CI's [`ci.yml`](../../.github/workflows/ci.yml)
runs on `push` to `main` and on `pull_request` targeting `main`.

This is intentionally simpler than what some sibling repos run
(notably the older vmisolate-side dev/test/int/uat/prd/main
flow). justoci is a leaf repo with no in-flight release trains
to coordinate; the simplicity matches that posture.

## Doc convention — snake_case

**Every `.md` file in `docs/` uses `snake_case`.** No kebab-case,
no exceptions in the top-level phase trees. The one exception is
nested research artefacts under `docs/0-ideation/research/` —
those are imported survey notes that keep their original kebab
filenames so attribution / links from external write-ups remain
stable.

If you add a new design or runbook page under `docs/3-design/`,
`docs/4-development/`, `docs/5-testing/`, or `docs/6-deployment/`,
it MUST be `snake_case.md`. The mdbook build renders both forms
identically; the convention is for grep, search, and parity with
`justsign` / `justext4` / vmisolate.

## MSRV

The workspace minimum supported Rust version is **1.86**, declared
once in the root `Cargo.toml` under `[workspace.package]` and
inherited by every crate via `rust-version.workspace = true`. CI
runs `cargo check --workspace --all-targets` on `1.86.0` to keep
the pin honest.

The floor is set by the dep graph — `reqwest -> url -> idna ->
icu_collections` declares 1.86, and `clap_builder` requires 1.85
— not by anything this workspace uses directly. Going lower than
1.86 is not achievable today without dropping `reqwest` (used by
`oci-publish` and `cli`) or downgrading `idna`/`icu_*`.

If you bump the MSRV, update both the `[workspace.package]`
`rust-version` value AND the `dtolnay/rust-toolchain@1.86.0` step
in `.github/workflows/ci.yml`. Keeping the two in sync is the
whole point of the dedicated `msrv` CI job.

## Local setup

### Sibling-repo layout

`justoci`'s `Cargo.toml` has a path-dep on the
[`justcas`](https://github.com/sweengineeringlabs/justcas)
sibling. Both must be checked out side-by-side under the same
parent dir:

```
swelabs/
├── justoci/        ← this repo
└── justcas/        ← sibling, content-addressed-storage primitive
```

Setup:

```bash
mkdir -p swelabs && cd swelabs
git clone git@github.com:sweengineeringlabs/justoci.git
git clone git@github.com:sweengineeringlabs/justcas.git

cd justoci
cargo build --workspace
cargo test  --workspace
```

CI uses the same layout — `actions/checkout` puts justoci in
`./justoci` and justcas in `./justcas`, then runs cargo from
`./justoci`.

### CI cross-repo setup

The justoci workflow needs to read the private justcas repo. The
default `GITHUB_TOKEN` in Actions is scoped to the running repo
only — it can't read across repos. Solution: a Personal Access
Token (PAT) stored as a secret on the justoci repo.

**One-time setup per fork / new clone:**

1. Create a fine-grained PAT at
   <https://github.com/settings/personal-access-tokens>:
   - Resource: `sweengineeringlabs/justcas`
   - Repository permissions: `Contents: Read-only`,
     `Metadata: Read-only`.
   - Expiration: as your team's policy requires.

2. On the justoci repo:
   `Settings → Secrets and variables → Actions → New repository secret`:
   - Name: `JUSTCAS_PAT`
   - Value: the PAT from step 1.

Without this secret, the workflow's first run fails on the
cross-repo checkout step. The error is loud and obvious:
`refusing to fetch from github.com:sweengineeringlabs/justcas`.

### Required toolchain

- **Rust stable** (CI tests on `stable`; the workspace MSRV is
  **1.86** as documented above).
- **`cosign`** on PATH for the cosign-on-PATH probe test (CI
  installs it via `sigstore/cosign-installer@v3`; locally,
  `brew install cosign` / `apt install cosign` / etc.).
- **Linux or macOS host** for the full attest test. Windows works
  for everything except the cosign integration (the cosign
  binary is Linux/Mac-first).

### Optional Cargo features

- **`vault`** (in `cli/`). Opt-in HashiCorp Vault credential
  provider for `--auth vault`. Pulls in the `vaultrs` (MIT-licensed)
  + `tokio` deps; the default `cargo build` does NOT compile
  either, keeping the default `ocimage` binary lean. Build with
  `cargo build -p swe_justoci_oci_cli --features vault`. The
  feature's integration test (`cli/tests/vault_provider_test.rs`)
  is `#[ignore]`-gated and runs against a local Vault dev server;
  see [`docs/6-deployment/auth_providers.md`](../6-deployment/auth_providers.md)
  for the dev-server setup.
- **`docker-config`** (in `cli/`). Opt-in `~/.docker/config.json`
  credential provider for `--auth docker-config`. Pulls in
  `base64` (MIT OR Apache-2.0) + `dirs` (MIT OR Apache-2.0); both
  are tiny (no transitive runtime / network deps), so the binary
  size cost is ~22 KiB. Build with
  `cargo build -p swe_justoci_oci_cli --features docker-config`.
  Does NOT depend on Docker the daemon being installed — the
  provider only reads the static config file. The feature's
  integration test (`cli/tests/docker_config_provider_test.rs`)
  needs no external service; it stages a tempdir + fixture
  `config.json` and runs as part of the default
  `cargo test --features docker-config` cycle. The two opt-in
  providers are additive: `--features "vault,docker-config"` is
  a supported combination.

## Running the test suite

```bash
cargo test --workspace                    # all tests
cargo test -p swe_justoci_spec            # just the spec crate
cargo test --workspace -- --ignored       # the cosign-installed
                                          # PATH probe (set
                                          # OCIMAGE_COSIGN_BIN if
                                          # you want a different
                                          # binary)

# Smoke test against a real registry:2 container. Requires Docker
# on PATH; prints a SKIP line and returns Ok if Docker is absent.
docker pull registry:2                    # one-time
cargo test -p swe_justoci_oci_cli \
    --test registry_smoke_test -- --ignored --test-threads=1
```

For the layered breakdown of unit / integration / e2e and what
each layer covers, see
[`docs/5-testing/testing_strategy.md`](../5-testing/testing_strategy.md).

## Linting

CI runs both clippy and fmt with `RUSTFLAGS=-D warnings`. Run the
same locally before pushing:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

Auto-fix:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --fix --allow-dirty
```

The workspace-wide rule (no blanket warning suppressions) is
enforced by `-D warnings`. If clippy flags something that's
genuinely intentional (e.g. a forward-compat single-element loop),
refactor to express the intent in code that clippy accepts (e.g.
`Algorithm::all() -> &'static [Algorithm]`) rather than
`#[allow(...)]`.

## Editor integration

`rust-analyzer` works out of the box with the workspace. If your
editor opens a single crate, you may see "spec" or "cas"
unresolved — open the workspace root (`justoci/`) instead.

## Common gotchas

- **Constructing a `MediaType` programmatically.** Use
  `MediaType::parse(&str) -> Result<MediaType, MediaTypeParseError>`.
  The same grammar validator used during TOML parsing runs on the
  string; there is no unchecked back-door. Single-validator
  integrity is preserved by routing every `MediaType` value
  through this gate, regardless of source.

- **Path-dep refresh.** If you `git pull` on justcas, justoci's
  build picks up the change automatically (path-dep, not
  version-pinned). If you make a breaking change in justcas, run
  `cargo check --workspace` from justoci to catch fallout.

- **`cargo fmt` on Windows.** `cargo fmt --check` is
  CRLF-sensitive. CI's Linux runner converts on checkout; locally
  on Windows, configure `git config core.autocrlf input` to keep
  the working tree LF-only.

## Where to put a fix

| Problem area | File / Module |
|--------------|---------------|
| Spec parser doesn't accept a new field | `spec/src/core/raw.rs` + `core/validate.rs` |
| New SLSA / SBOM / sign behaviour | `attest/src/core/{slsa,sbom_*,cosign}.rs` |
| New OCI media type pinning | `build/src/api/oci_manifest.rs` |
| New CLI subcommand | `cli/src/cmd/` + `cli/src/main.rs` |
| Auth / pull / publish wire | `publish/src/core/registry_sink.rs`, `cli/src/registry/pull.rs` |
| Cross-cutting error type | each crate's `src/api/error.rs` |

## Smoke-test the full pipeline

The unit + integration tests use `httpmock` to fake the registry's
HTTP layer — fast, reproducible, but mock-shaped. To confirm your
local toolchain genuinely talks to a real OCI Distribution v2
registry, run the dogfood script:

```bash
bash examples/dogfood/run.sh
```

It spins up Docker's `registry:2` on a free local port, runs
`ocimage build → publish → verify` end-to-end (no-attest path),
and tears the container down on exit. Exit code 0 + a final
"dogfood passed" line means your build, the workspace, and the
wire shape all agree.

Prereqs: Docker, `cargo`, `python` (free-port probe), `curl`
(liveness check). See `examples/dogfood/README.md` for what to do
when it fails.

The script does **not** exercise attestation; the cosign +
Sigstore end-to-end live test is tracked separately as issue #14
and runs in CI's `sigstore-e2e` job.

## Contributing

### The cardinal rule

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

### Other rules that apply

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

### PR process

1. **Branch.** Cut a `feature/<topic>` branch from `main`. Push
   it to your fork or to the upstream repo (write access
   permitting), then open a PR targeting `main`. There is no
   intermediate `dev` branch.

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
   covers what you changed. Use snake_case for any new doc files.

5. **Run CI gates locally.** `cargo fmt --all -- --check &&
   cargo clippy --workspace --all-targets -- -D warnings &&
   cargo test --workspace`. CI re-runs these but locally is
   faster.

### Commit message conventions

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

### Adding a feature

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

### Adding a kind

[`adding_a_kind.md`](./adding_a_kind.md) walks through the recipe
for adding a new artifact `kind` (e.g. `wasm_module`,
`helm_chart`).

### Code review focus

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
6. If the PR adds or renames a doc file, is the filename
   `snake_case`?
