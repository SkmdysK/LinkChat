//! Verification-only harnesses for bounded protocol conformance.
//!
//! The public observation model is intentionally separate from the test
//! fixtures. It mirrors the protocol-level data exposed to a bounded
//! verification runner without exposing internal secrets.

#[path = "modules/observations.rs"]
mod observations;

pub use observations::{
    AcceptReject, Challenge, CompleteAdversaryView, DhtObservation, NetworkObservation,
};

#[cfg(test)]
#[path = "modules/tests.rs"]
mod tests;
