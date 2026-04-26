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

- **Rust stable** (currently 1.94+; MSRV stabilisation is on the
  roadmap).
- **`cosign`** on PATH for the cosign-on-PATH probe test (CI
  installs it via `sigstore/cosign-installer@v3`; locally,
  `brew install cosign` / `apt install cosign` / etc.).
- **Linux or macOS host** for the full attest test. Windows works
  for everything except the cosign integration (the cosign
  binary is Linux/Mac-first).

## Running the test suite

```bash
cargo test --workspace                    # all tests
cargo test -p swe_justoci_spec            # just the spec crate
cargo test --workspace -- --ignored       # the cosign-installed
                                          # PATH probe (set
                                          # OCIMAGE_COSIGN_BIN if
                                          # you want a different
                                          # binary)
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

- **`spec::MediaType::unchecked` is `pub(crate)`.** External
  callers can't construct a `MediaType` directly — they must
  round-trip through TOML via `parse_and_validate_str`. This is
  the single-validator-integrity rule from spec v0; the public
  parse path is the only public construction path. The
  vmisolate-side adapter works around this by emitting TOML text
  from its `translate()` function.

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
