# Local development setup

## Sibling-repo layout

`justoci`'s `Cargo.toml` has a path-dep on the
[`justcas`](https://github.com/sweengineeringlabs/justcas) sibling.
Both must be checked out side-by-side under the same parent dir:

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

## CI cross-repo setup

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

## Required toolchain

- **Rust stable** (CI tests on `stable`; the workspace MSRV is
  **1.86**, declared once in the root `Cargo.toml`'s
  `[workspace.package]` block and inherited by every crate via
  `rust-version.workspace = true`). The MSRV CI job runs `cargo
  check --workspace --all-targets` on `1.86.0` to keep the pin
  honest. The floor is set by the dep graph — `reqwest -> url ->
  idna -> icu_collections` declares 1.86 — not by a feature this
  workspace uses directly.
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
  see [`docs/7-operations/auth-providers.md`](../7-operations/auth-providers.md)
  for the dev-server setup.

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

The user's CLAUDE.md memory rule (`No blanket warning
suppressions`) is enforced by `-D warnings`. If clippy flags
something that's genuinely intentional (e.g. a forward-compat
single-element loop), refactor to express the intent in code that
clippy accepts (e.g. `Algorithm::all() -> &'static [Algorithm]`)
rather than `#[allow(...)]`.

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
"✓ dogfood passed" line means your build, the workspace, and the
wire shape all agree.

Prereqs: Docker, `cargo`, `python` (free-port probe), `curl`
(liveness check). See `examples/dogfood/README.md` for what to do
when it fails.

The script does **not** exercise attestation; the cosign + Sigstore
end-to-end live test is tracked separately as issue #14.
