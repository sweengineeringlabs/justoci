//! `ImageBuilder` impls.
//!
//! One shipped: [`default_service::DefaultImageService`].
//! Future variants (e.g. a `CachingImageService` that memoizes
//! builds, or an `OciPushingImageService` that wraps the default
//! with a push step) slot in here as siblings.

pub mod default_service;

pub use default_service::DefaultImageService;
