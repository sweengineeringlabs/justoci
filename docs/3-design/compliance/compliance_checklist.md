# Compliance Checklist

**Audience**: Contributors, architects, code reviewers

Use this checklist during code review for any PR that touches justoci's architectural boundaries. Every item must pass before merge. Derived from `docs/3-design/architecture.md`.

> For documentation compliance, see the framework-level compliance checklist in `template-engine/templates/compliance-checklist.md`.

---

## How to Use

1. Open this checklist alongside the PR diff
2. Run the automated checks where provided
3. Mark each item pass/fail; note the file if it fails
4. Address failures before merge (structure violations first)

---

## 1. Crate Seam Compliance

Reference: `docs/3-design/architecture.md` — "Where the seams are"

### 1.1 spec ↔ build seam

- [ ] `build` crate does not import `toml` or parse TOML directly — it receives `LoadedSpec` only
- [ ] `build` crate does not call `spec_hash` — the CLI wires that before calling `build::build`
- [ ] No `Spec` or `RawSpec` types appear in `build`'s public surface

### 1.2 build ↔ attest seam

- [ ] `attest` crate receives `BuiltArtifact` (manifest + config + layer digests + spec + spec_hash)
- [ ] `attest` does not know about `Cargo.toml` of `build` or call `build::build` directly
- [ ] No `LoadedSpec` in `attest`'s public surface — only `BuiltArtifact`

### 1.3 publish isolation

- [ ] `publish` crate has no direct dependency on `build` or `attest`
- [ ] `publish` reads only `ImageDir`s on disk (OCI Image Layout)
- [ ] No attestation types appear in `publish`'s public surface

**Verify**:
```bash
# Check workspace dep graph — no forbidden edges
cargo tree -p swe_justoci_oci_build | grep -E 'attest|publish' && echo "FAIL" || echo "PASS"
cargo tree -p swe_justoci_oci_publish | grep -E 'build|attest' && echo "FAIL" || echo "PASS"
```

---

## 2. CAS Integrity Compliance

Reference: `docs/3-design/architecture.md` — "Six crates, one CAS primitive"

### 2.1 All blob writes go through CAS

- [ ] Layer blobs are written via `Cas::put` (streaming, 64 KiB chunks), not via `std::fs::write` directly
- [ ] OCI config, manifest, and attestation blobs are written via `Cas::put`
- [ ] No code bypasses the CAS to write directly to `blobs/sha256/`

### 2.2 Integrity verification on reads

- [ ] `Cas::get` re-hashes the blob on every read — no cached reads skip hashing
- [ ] Digest mismatches surface as typed errors (`CasError::DigestMismatch`), not panics

**Verify**:
```bash
# No direct fs writes to blobs/sha256 outside cas/
grep -rn 'blobs/sha256' crates/ --include="*.rs" | grep -v 'cas/' | grep -v 'test' || echo "PASS"
```

---

## 3. Signing Coupling Compliance

Reference: `docs/3-design/cosign_rekor.md` — Production Guarantee §6

### 3.1 No half-signed states

- [ ] `cosign sign` success and Rekor log entry confirmation are checked together — no separate code path that marks an artifact signed on `cosign sign` success alone
- [ ] Rekor failure returns `AttestError::SignNotRecorded`, not a partial success
- [ ] No `unwrap()` or `expect()` on Rekor confirmation that would panic instead of returning a typed error

### 3.2 Atomic artifact state

- [ ] Builds write to `<output>.partial` and only rename to `<output>` on full success
- [ ] Failed builds never leave a non-`.partial` output directory
- [ ] `index.json` is written last (tempfile-then-rename), not before blobs are committed

**Verify**:
```bash
# .partial write pattern must be present in build
grep -n '\.partial' crates/build/src/ -r --include="*.rs" | head -10
# index.json write must use atomic rename
grep -n 'index\.json' crates/build/src/ -r --include="*.rs" | grep -v test | head -10
```

---

## 4. OCI Type Compliance

Reference: `docs/3-design/architecture.md` — "Why hand-rolled OCI structs"

### 4.1 No oci-spec crate in build or publish

- [ ] `build` and `publish` do not depend on the `oci-spec` crate
- [ ] OCI manifest/config/index types are the in-tree hand-rolled types in `build/src/api/oci_manifest.rs`

### 4.2 Reproducibility-critical serialisation

- [ ] OCI manifest annotations use `BTreeMap` (sorted keys), not `HashMap`
- [ ] `skip_serializing_if = "Option::is_none"` on all optional manifest fields
- [ ] No `HashMap` in any type that appears in the manifest or config JSON

**Verify**:
```bash
# No oci-spec in build/publish Cargo.toml
grep -n 'oci-spec' crates/build/Cargo.toml crates/publish/Cargo.toml && echo "FAIL" || echo "PASS"
# No HashMap in oci_manifest.rs
grep -n 'HashMap' crates/build/src/api/oci_manifest.rs && echo "FAIL" || echo "PASS"
```

---

## 5. Typed Error Compliance

Reference: `docs/3-design/production_guarantees.md` — §"Typed errors"

- [ ] No `Box<dyn Error>` in public function signatures of `spec`, `build`, `attest`, `publish`
- [ ] Each crate has its own error enum (not a shared `anyhow::Error`)
- [ ] `?` operator is used for propagation; `.unwrap()` and `.expect()` appear only in tests and examples
- [ ] CLI converts crate errors to typed exit codes (not just `process::exit(1)` everywhere)

**Verify**:
```bash
# No Box<dyn Error> in public API
grep -rn 'Box<dyn Error>' crates/ --include="*.rs" | grep -v test | grep -v examples | grep 'pub fn' || echo "PASS"
# No bare unwrap in non-test code
grep -rn '\.unwrap()' crates/ --include="*.rs" | grep -v '#\[cfg(test)\]' | grep -v 'tests/' | grep -v 'examples/' | head -20
```

---

## 6. Security Compliance

- [ ] No credentials, tokens, or keys committed to VCS
- [ ] Error responses do not leak registry auth headers or Vault tokens
- [ ] `--auth` flag values are not echoed to stdout or included in error messages
- [ ] Vault feature-gated code (behind `--features vault`) does not unconditionally pull in vault crates in default builds

**Verify**:
```bash
# No secrets patterns in source
grep -rn 'ghp_\|glpat-\|AKIA\|sk-' crates/ --include="*.rs" || echo "PASS"
# Vault is feature-gated
grep -n 'vault' Cargo.toml | head -5
```

---

## Quick Summary Table

| Category | Checks | Pass | Fail |
|----------|--------|------|------|
| Crate seam compliance | 1.1–1.3 | | |
| CAS integrity | 2.1–2.2 | | |
| Signing coupling | 3.1–3.2 | | |
| OCI type compliance | 4.1–4.2 | | |
| Typed error compliance | 5 | | |
| Security compliance | 6 | | |
| **Total** | | | |

---

## Automated Gate

```bash
# Build (catches dep direction violations, type mismatches)
cargo build --workspace

# Full test suite
cargo test --workspace

# Clippy — treated as errors
cargo clippy --workspace -- -D warnings
```
