//! SAF facade layer (L4) — public surface for `oci-build`.
//!
//! Only the build-side entry points live here. The publish /
//! push entry points moved to the sibling `oci-publish` crate
//! when ocimage was sharded.

mod facade;

pub use crate::api::error::Error;
pub use crate::api::manifest::{
    source_date_epoch, ArtifactDigests, BuildManifest, FileManifestEntry, PackageManifest,
};
pub use crate::api::spec::{BaseRef, BuildArtifacts, FileEntry, ImageSpec, InitMode};
pub use crate::api::traits::{FileOverlay, ImageBuilder, PackageInstaller, RootfsBuilder};
pub use crate::core::service::DefaultImageService;
pub use crate::spi::file_overlay::chroot_overlay::ChrootFileOverlay;
pub use crate::spi::package_installer::alpine_apk::AlpineApkInstaller;
pub use crate::spi::rootfs_builder::alpine_builder::AlpineBuilder;
pub use facade::build_image;
