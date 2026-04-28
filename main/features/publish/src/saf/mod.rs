//! SAF facade — public publish entry point.
//!
//! [`publish::publish`] is the single function the CLI / library
//! callers reach for. It dispatches on the [`PublishSink`] variant
//! to the matching `core::*_sink` impl and never bypasses the
//! [`PublishError`] surface.
//!
//! [`PublishError`]: crate::api::error::PublishError
//! [`PublishSink`]: crate::api::sink::PublishSink

pub mod publish;
