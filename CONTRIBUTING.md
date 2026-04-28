# Contributing to justoci

**Audience**: Anyone planning to land code, docs, or issues in justoci.

Thanks for considering a contribution. justoci is a security-aware build and verification pipeline — every change is reviewed against the test discipline and architectural-compliance gates documented below.

## Quick links

- [Developer guide](docs/4-development/developer_guide.md) — local clone-to-PR workflow, MSRV, toolchain, linting, dogfood script.
- [Testing strategy](docs/5-testing/testing_strategy.md) — what we test, why, what's NOT tested.
- [Architecture compliance checklist](docs/3-design/compliance/compliance_checklist.md) — pre-merge gate for architecture-touching PRs.
- [Adding a kind](docs/4-development/adding_a_kind.md) — recipe for adding a new artifact kind.

## How to contribute

### 1. Pick something to work on

- Open issues at <https://github.com/sweengineeringlabs/justoci/issues>.
- Issues labelled `good first issue` are deliberately scoped for newcomers.
- Want to propose something not in the issue list? Open an issue first to align on shape before writing code.

### 2. Set up locally

See [`docs/4-development/developer_guide.md`](docs/4-development/developer_guide.md) for the full setup. Short version:

```sh
mkdir -p swelabs && cd swelabs
git clone git@github.com:sweengineeringlabs/justoci.git
git clone git@github.com:sweengineeringlabs/justcas.git

cd justoci
cargo build --workspace
cargo test --workspace
```

### 3. Branch + commit

- Branch from `main`. justoci uses short-lived `feature/<topic>` branches that merge to `main` via PR — no intermediate `dev` branch.
- Commit messages follow `type(scope): description`. Examples:
  - `feat(attest): add spdx 2.4 sbom format`
  - `fix(spec): reject duplicate layer media types`
  - `docs: add auth_providers troubleshooting entry`
- Reference the issue: include `Closes #N` in the commit body when the commit resolves an issue.
- **Do not include AI-attribution lines** (no `Co-Authored-By: Claude…` etc.).

### 4. Run the gates

Before opening a PR:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test --workspace -- --ignored --test-threads=1
```

All four must pass. CI runs the same gates; fix locally first.

If your PR touches an architectural boundary (crate-graph, wire format, trait SPI, production guarantee), also walk through [`docs/3-design/compliance/compliance_checklist.md`](docs/3-design/compliance/compliance_checklist.md) before requesting review.

### 5. The cardinal test rule

**Every test names the bug it would catch.**

If you write a test and can't articulate the specific regression that test would surface, it's a smoke test and adds noise. Delete it and write one that asserts a specific behaviour. See [`docs/5-testing/testing_strategy.md`](docs/5-testing/testing_strategy.md) for the pattern and examples.

### 6. Open the PR

- PR title mirrors the commit message.
- PR body explains WHY (not what — the diff is the what). Link the issue. List any caller-visible API or CLI changes.
- If the PR adds or renames a doc file, confirm the filename is `snake_case.md`.

### 7. Review + merge

- A maintainer reviews against the compliance checklist.
- Address review comments via additional commits on the branch — no force-push to a PR branch.
- Merge is ff-only into `main`.

## What we look for in a PR

- **Tests that can fail** — every test must catch a specific bug.
- **Typed errors** — each crate's typed error enum gets new variants; no `anyhow` in public APIs.
- **No `#[allow(...)]` suppressions** — refactor to express the intent in code clippy accepts.
- **No silent half-states** — partial-failure semantics per Production Guarantee §6.
- **Production-grade defaults** — no panics in library code, no unbounded operations, no hardcoded secrets.

## Reporting security vulnerabilities

See [`SECURITY.md`](SECURITY.md) for private vulnerability disclosure.

For non-security bugs: open an issue with steps to reproduce, expected vs actual behaviour, and the relevant `justoci` / `cosign` / `rustc` versions.

## Doc conventions

- All new `.md` files in `docs/` use `snake_case`. No kebab-case.
- Every new doc must include `**Audience**: [...]` and W³H structure (WHAT, WHY, HOW sections) per the documentation framework.
- Update `docs/SUMMARY.md` if you add a new page to the mdBook.

## License

By contributing, you agree your contributions are licensed under the same [Apache-2.0](LICENSE) licence as the rest of the project.
