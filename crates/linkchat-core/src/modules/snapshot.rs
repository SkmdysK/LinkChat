/// A public-only state snapshot useful for audit and storage adapters.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicStateSnapshot {
    pub(crate) session: Session,
    pub(crate) turn: TurnState,
    pub(crate) alice: PublicReceiverPackage,
    pub(crate) bob: PublicReceiverPackage,
    pub(crate) consumed_message_ids: Vec<MessageId>,
}

impl PublicStateSnapshot {
    pub(crate) fn from_parts(
        session: Session,
        turn: Turn,
        alice: PublicReceiverPackage,
        bob: PublicReceiverPackage,
        consumed_message_ids: Vec<MessageId>,
    ) -> Self {
        Self {
            session,
            turn: TurnState::new(turn),
            alice,
            bob,
            consumed_message_ids,
        }
    }

    pub const fn session(&self) -> Session {
        self.session
    }

    pub const fn turn_state(&self) -> TurnState {
        self.turn
    }

    pub const fn turn(&self) -> Turn {
        self.turn.current()
    }

    pub fn alice_public_package(&self) -> &PublicReceiverPackage {
        &self.alice
    }

    pub fn bob_public_package(&self) -> &PublicReceiverPackage {
        &self.bob
    }

    pub fn consumed_message_ids(&self) -> &[MessageId] {
        &self.consumed_message_ids
    }
}
use crate::{PublicReceiverPackage, Session, TurnState};
use linkchat_types::{MessageId, Turn};
