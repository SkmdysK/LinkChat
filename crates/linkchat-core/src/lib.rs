//! Pure Link Chat v1.0 protocol state.
//!
//! This crate owns the deterministic state transition only. It does not
//! perform cryptography, storage, networking, mailbox access, or FFI. A
//! caller must validate/decrypt an authenticated message and generate a
//! locally fresh package before presenting the complete package to [`step`].
//! The core then validates the protocol context and performs one atomic
//! state transition.

#[path = "modules/endpoint_session.rs"]
mod endpoint_session;
#[path = "modules/envelope.rs"]
mod envelope;
#[path = "modules/errors.rs"]
mod errors;
#[path = "modules/message.rs"]
mod message;
#[path = "modules/packages.rs"]
mod packages;
#[path = "modules/snapshot.rs"]
mod snapshot;
#[path = "modules/storage_codec.rs"]
mod storage_codec;
#[path = "modules/transition.rs"]
mod transition;

pub use endpoint_session::{Endpoint, Session, TurnState};
pub use envelope::{EndpointKernel, PreparedReceive, PreparedSend};
pub use errors::{CoreError, RejectReason};
pub use message::ApplicationMessage;
pub use packages::{
    PrivateReceiverPackage, ProductionPrivateReceiverPackage, PublicReceiverPackage,
    ReceiverPackageFactory, VerifiedReceiverPackage, package_chain_root, receiver_package_hash,
    verify_receiver_package, verify_receiver_package_auth,
};
pub use snapshot::PublicStateSnapshot;
pub use transition::{PreparedStep, RefinedState, StepOutcome};

#[cfg(test)]
#[path = "modules/tests.rs"]
mod tests;
