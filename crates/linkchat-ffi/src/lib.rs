//! Small, optional C ABI for public Link Chat integration values.
//!
//! The ABI is intentionally narrower than the Rust API. Handles identify
//! registry-owned values and all byte buffers are caller-owned. No private
//! receiver package, message key, private key, Rust `Vec`, trait object, or
//! borrowed Rust reference crosses this boundary.

#[path = "modules/api.rs"]
mod api;
#[path = "modules/foundation.rs"]
mod foundation;
#[path = "modules/helpers.rs"]
mod helpers;
#[path = "modules/registry.rs"]
mod registry;

pub use api::*;
pub use foundation::*;

#[cfg(test)]
#[path = "modules/tests.rs"]
mod tests;
