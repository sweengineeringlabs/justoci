//! [`PackageInstaller`] impls.
//!
//! One impl per package-manager family. Consumers construct the impl
//! directly and hand it to `DefaultImageService`. The orchestrator
//! owns the [`chroot::ChrootHandle`] and passes it at `install()` time
//! so #18 file-overlay can share the same entered chroot without
//! re-mounting.

pub mod alpine_apk;
