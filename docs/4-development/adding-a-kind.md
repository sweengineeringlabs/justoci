# Adding a new artifact `kind`

v0 ships three: `oci_artifact`, `vm_image`, `raw_image`. Adding
a fourth (e.g. `wasm_module`, `helm_chart`, `unikernel_image`)
is additive.

## Decide what makes the kind unique

For each new kind, answer:

1. **Layer count rule.** Exactly N? At least N? Variable per use
   case? (vm_image is 3 because boot order is fixed;
   oci_artifact is ≥1 because oras-style is open.)
2. **Layer ordering rule.** Are layers semantically ordered?
   (vm_image is kernel/initrd/rootfs; oci_artifact is
   caller-defined.)
3. **Recommended `[config]` schema.** Optional but useful — the
   spec doc lists "recommended" config keys per kind. The
   validator doesn't enforce config field types (Production
   Guarantee §1: "the kind's role is *validation*, not
   *transformation*"), but documenting recommended keys helps
   adoption.
4. **Recommended media types.** Vendor types under
   `application/vnd.<your-domain>.<thing>+<format>`.

## Steps

### 1. Add the variant to the `Kind` enum

`spec/src/api/spec.rs`:

```rust
pub enum Kind {
    OciArtifact,
    VmImage,
    RawImage,
    WasmModule,    // ← new
}

impl Kind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Kind::OciArtifact => "oci_artifact",
            Kind::VmImage     => "vm_image",
            Kind::RawImage    => "raw_image",
            Kind::WasmModule  => "wasm_module",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "oci_artifact" => Some(Kind::OciArtifact),
            "vm_image"     => Some(Kind::VmImage),
            "raw_image"    => Some(Kind::RawImage),
            "wasm_module"  => Some(Kind::WasmModule),
            _ => None,
        }
    }
}
```

The compiler will catch every `match` on `Kind` that needs to
handle the new variant. **Don't add a `_ => unimplemented!()`
arm.** Each match site is a deliberate decision.

### 2. Add the layer count rule

`spec/src/core/validate.rs::check_layer_count`:

```rust
let (allowed, expected_str): (bool, &'static str) = match kind {
    Kind::OciArtifact => (actual >= 1, "≥1"),
    Kind::VmImage     => (actual == 3, "exactly 3"),
    Kind::RawImage    => (actual == 1, "exactly 1"),
    Kind::WasmModule  => (actual == 1, "exactly 1"),  // ← new
};
```

### 3. Add the layer ordering rule

`spec/src/core/validate.rs::check_layer_order`:

```rust
match kind {
    Kind::VmImage => {
        // existing kernel/initrd/rootfs check
    }
    Kind::WasmModule => {
        // single layer, no ordering rule
    }
    _ => Ok(()),
}
```

### 4. Update `build/src/core/oci_assembly.rs::check_layer_count_post_assembly`

This is the post-assembly defensive check. Mirror the rule from
step 2.

### 5. Add a worked example

`examples/wasm-module.toml`:

```toml
spec_version = "0"
id           = "my-app:1.0.0"
kind         = "wasm_module"
description  = "my-app — server-side WASM module"

[[layers]]
source     = "build/my-app.wasm"
media_type = "application/vnd.example.wasm+binary"

[config]
runtime    = "wasi-preview-2"
entrypoint = "_start"

[annotations]
"org.opencontainers.image.title"   = "my-app"
"org.opencontainers.image.version" = "1.0.0"
```

### 6. Add tests

In `spec/tests/parse_examples_test.rs`, add a test that parses
the new example:

```rust
#[test]
fn test_wasm_module_example_parses() {
    let toml = include_str!("../../examples/wasm-module.toml");
    let dir = stage_spec("wasm-module.toml", toml, &["build/my-app.wasm"]);
    let spec = parse_and_validate(dir.path().join("wasm-module.toml"))
        .expect("parses").spec;
    assert_eq!(spec.kind, Kind::WasmModule);
    assert_eq!(spec.layers.len(), 1);
}
```

In `spec/tests/validation_test.rs`, add a count-violation test
specific to the new kind:

```rust
#[test]
fn test_wasm_module_with_two_layers_rejected() {
    // wasm_module must be exactly 1 layer.
    // Bug it catches: a count rule that fell through to an
    // overly-permissive default.
    let bad = "...";
    let err = parse_and_validate_str(bad, dir).expect_err("must reject");
    assert!(matches!(err, SpecError::WrongLayerCount {
        kind: "wasm_module", actual: 2, ..
    }));
}
```

### 7. Update the spec doc

`docs/3-design/spec-v0.md` — extend the "Kinds" table.

### 8. Update the executive summary

`docs/executive_summary.md` — add the kind to the list under
"The spec, distilled."

### 9. Run the full test suite

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## What you do NOT have to touch

- **`build` crate proper.** Layer assembly is kind-agnostic
  beyond the count check. The compression / hashing / CAS write
  pipeline works for any layer regardless of kind.
- **`attest` crate.** SLSA + SBOM + cosign work over any
  artifact identified by a manifest digest.
- **`publish` crate.** OCI Image Layout is kind-agnostic; the
  kind doesn't affect publish.
- **`cli` crate.** Subcommands work for any kind via the
  spec layer.

This is the seam pattern paying off: kind variation lives in
`spec`'s validator, and everything downstream is kind-blind.

## Reservation: don't add a kind that needs build-time
**transformation**

Justoci's role is *transport* and *attestation*, not *building*.
If your "new kind" requires build-time logic (compile this
source, run this script, mount and overlay), that work belongs
in a separate adapter crate that calls justoci's library APIs
after producing the layer source files. See
[`vmisolate's oci-image-builder`](https://github.com/sweengineeringlabs/vmisolate/tree/main/main/features/oci-image-builder)
as the reference adapter pattern.
