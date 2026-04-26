# minimal-raw-image — anchor fixture

The simplest valid spec the canonicaliser accepts: `raw_image`, one
layer, no optional blocks. Everything that *can* be omitted *is*
omitted (`description`, `[platform]`, `[config]`, `[annotations]`,
`[attestation]`).

## Bug it catches in cross-language re-implementations

A re-implementation that disagrees on this fixture has a problem in
the basic pipeline — TOML parse, the `spec_to_json` projection, the
default-`AttestationConfig` shape, JCS serialisation, or sha256 —
before any edge case enters the picture. Failing here means the
re-impl is not viable for *any* spec, not just an unusual one.

In particular, a re-impl that emits `"description": null` instead of
omitting the field, or that emits `"platform": {}` instead of omitting
the table when both fields are `None`, will hash differently from the
Rust impl on this fixture.

The default `[attestation]` block (SLSA L2, CycloneDX layers,
cosign-keyless) appears in the canonical JSON even though the spec.toml
omits the section entirely — re-implementations that copy "absent ⇒
omit" too literally and skip the whole `attestation` object will fail
this fixture.
