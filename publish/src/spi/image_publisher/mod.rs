//! SPI impls for publishing a built image to a registry.
//!
//! Phase 2f-β lands two siblings:
//! * `http_publisher` — ADR-015 Level 2: writes `index.json` +
//!   content-addressed blobs under a local directory. Pair with any
//!   static HTTP host (nginx, S3 static-website, GitHub releases).
//! * `oci_pusher` — ADR-015 Level 4: pushes via the OCI
//!   distribution spec to GHCR, Harbor, ECR, etc.
//!
//! Both are agent-owned files added during the 2f-β parallel split.

pub mod http_publisher;
pub mod oci_pusher;
