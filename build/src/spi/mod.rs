//! SPI impls for oci-build.
//!
//! Concrete implementations of the traits defined in `api/`.
//! Organised by trait — one subdirectory per pluggable contract —
//! matching the Fleet-crate layout convention.
//!
//! The sibling `image_publisher` SPI was split out into the
//! `oci-publish` crate when ocimage was sharded into
//! oci/{build,publish,systemd,cli}. Build-only SPIs live here.

pub mod rootfs_builder;
pub mod package_installer;
pub mod file_overlay;
