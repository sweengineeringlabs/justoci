//! [`FileOverlay`] impls.
//!
//! One impl today — [`chroot_overlay::ChrootFileOverlay`] — which
//! copies host files into a rootfs via the chroot substrate.
//! Future variants (OCI-layer extract, overlayfs) land as sibling
//! modules.

pub mod chroot_overlay;
