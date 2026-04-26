//! `oci-build` — build vmisolate VM images (kernel + initrd + rootfs +
//! config.json) from an `ImageSpec`. Split out of the former `ocimage`
//! crate in the 2f-δ refactor; the publish side moved to `oci-publish`.

mod spi;

// api/ is `pub` so integration tests (under `tests/`) can reach
// `api::spec::ImageSpec`, `api::error::Error`, and the SPI traits
// directly. The saf/ facade is still the primary external surface
// (`pub use saf::*` re-exports the common types), but some tests
// legitimately need to poke at the raw API layer.
pub mod api;

mod core;

mod saf;

pub use saf::*;
