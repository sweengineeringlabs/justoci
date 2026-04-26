# justoci

Image build + publish + attestation pipeline for [vmisolate](../vmisolate)
microVM images. Pulled out of the vmisolate workspace so the publish-time
tooling has its own release cadence and dep graph.

## Crates

| Crate         | Package                       | Role                                                                  |
|---------------|-------------------------------|-----------------------------------------------------------------------|
| `build`       | `swe_justoci_oci_build`       | Build vmisolate VM images (kernel + initrd + rootfs + config.json) from an `ImageSpec`. |
| `publish`     | `swe_justoci_oci_publish`     | Ship a built image to a sink: ADR-015 Level-2 (HTTP) or Level-4 (OCI distribution registry). |
| `systemd`     | `swe_justoci_oci_systemd`     | Generate `.service` units that boot a built image directory via xkvm. |
| `cli`         | `swe_justoci_oci_cli`         | `ocimage` operator CLI: `build`, `publish-http`, `push`, `sbom`.      |
| `attest`      | `swe_justoci_attest`          | Supply-chain attestation: SLSA provenance + CycloneDX SBOM + cosign. ADR-016 pillars B + C. |

## Build

```
cargo build --workspace
```

## Cross-repo dependencies

Path-deps walk one level up into the sibling vmisolate workspace for:

- `userspace`, `vmm-api`, `chroot` — schemas + rootfs assembly used by `build`.

vmisolate itself path-deps back into `../justoci/` for `oci-build`,
`oci-publish`, `oci-systemd`, and `attest`.

## Layout

```
justoci/
├── Cargo.toml          # workspace root
├── attest/
├── build/
├── publish/
├── systemd/
└── cli/
```

## See also

- [`vmisolate`](../vmisolate) — single-node VMM + Fleet control plane
- [ADR-015](../vmisolate/docs/3-design/adr/015-image-registry.md) — image registry design
- [ADR-016](../vmisolate/docs/3-design/adr/016-supply-chain-attestation.md) — attestation pillars
