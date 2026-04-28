//! Core layer — per-sink publish implementations.
//!
//! Each sink module exposes a single `publish_*` entry point that
//! the SAF dispatcher delegates to. Splitting the sinks keeps the
//! HTTP path (sync, filesystem-only) cleanly separated from the
//! Registry path (async-blocking, network-bound).

pub mod http_sink;
pub mod registry_sink;
