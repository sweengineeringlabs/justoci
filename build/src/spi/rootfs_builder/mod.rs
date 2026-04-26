//! [`RootfsBuilder`](crate::api::traits::RootfsBuilder) SPI impls.
//!
//! One impl shipped in Phase 2f-α — `AlpineBuilder` — over an
//! existing ext4 rootfs file on disk. Adding Debootstrap /
//! DockerExport / OciArtifact impls is a new sibling here + a new
//! variant on `api::spec::BaseRef`; no changes to `core/` or the
//! trait surface.

pub mod alpine_builder;
