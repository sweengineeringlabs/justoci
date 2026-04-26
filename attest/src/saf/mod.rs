//! Operator-facing entry points. [`attest_build`] is the one-call
//! pipeline that builders, CI scripts, and `ocimage publish
//! --attest` compose against.

pub mod config;
pub mod facade;
