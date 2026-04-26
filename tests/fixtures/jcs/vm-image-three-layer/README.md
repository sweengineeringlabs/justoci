# vm-image-three-layer — production-shape regression

A realistic `vm_image` spec — the workload shape vmisolate microVM
artifacts actually use today. Has three layers in
`kernel → initrd → rootfs` order, `[platform]`, `[annotations]`,
and an explicit `[attestation]` block with non-default values
(`SLSA L3`, SPDX SBOM scoped to `both`, cosign-keyless with an
identity regex).

## Bug it catches in cross-language re-implementations

A re-impl that handles minimal specs (the `minimal-raw-image`
fixture) and individual edge cases (unicode, numerics, key
ordering) but trips on the *combination* of all of them in a
production-shape spec — every section present, every override
exercised, three layers — would pass the focused fixtures but
fail in the field. Specifically:

- The `[attestation]` block in this fixture has every optional
  field set (`builder_id`, `identity`). A re-impl that omits
  them when None (correct) but also omits them when Some (a
  copy-paste bug) would mismatch on the JSON shape.
- The three-layer ordering test confirms the layers array
  preserves source order — a re-impl that sorts layers
  alphabetically by media_type (a tempting "make it deterministic"
  shortcut) would put `initrd.cpio+gzip` before `kernel+binary`,
  changing the canonical bytes.
- The `[config]` block contains both arrays of strings
  (`entrypoint`) and a nested table (`config.env`). A re-impl
  that mishandles the type tag and emits the array as an object
  (`{"0": "/usr/bin/llmd", "1": "serve", ...}`) would mismatch.
- Fixture is the single point where v0.1.14-shaped real
  vmisolate specs live — useful as the primary regression sample
  whenever the projection rules grow a new field.
