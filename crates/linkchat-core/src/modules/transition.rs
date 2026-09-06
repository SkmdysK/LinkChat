/// A pure state result.  Rejection includes an unchanged state snapshot;
/// acceptance includes a pending state that is not externally committed yet.
pub enum StepOutcome {
    Rejected {
        reason: RejectReason,
        state: RefinedState,
    },
    Accepted(PreparedStep),
}

impl StepOutcome {
    pub fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted(_))
    }

    pub fn reason(&self) -> Option<RejectReason> {
        match self {
            Self::Rejected { reason, .. } => Some(*reason),
            Self::Accepted(_) => None,
        }
    }

    pub fn state(&self) -> &RefinedState {
        match self {
            Self::Rejected { state, .. } => state,
            Self::Accepted(prepared) => prepared.next_state(),
        }
    }

    pub fn into_state(self) -> RefinedState {
        match self {
            Self::Rejected { state, .. } => state,
            Self::Accepted(prepared) => prepared.apply(),
        }
    }
}

/// A successful pure transition waiting for an outer storage layer to commit.
pub struct PreparedStep {
    next_state: RefinedState,
    accepted_message_id: MessageId,
    payload: WireBytes,
}

impl PreparedStep {
    pub fn next_state(&self) -> &RefinedState {
        &self.next_state
    }

    pub const fn accepted_message_id(&self) -> MessageId {
        self.accepted_message_id
    }

    pub fn payload(&self) -> &WireBytes {
        &self.payload
    }

    /// Consumes the pending transition and returns the complete next state.
    pub fn apply(self) -> RefinedState {
        self.next_state
    }
}

/// The Rust representation corresponding to Lean `RefinedState`.
#[derive(Clone, PartialEq, Eq)]
pub struct RefinedState {
    pub(crate) session: Session,
    pub(crate) turn: TurnState,
    pub(crate) alice: PrivateReceiverPackage,
    pub(crate) bob: PrivateReceiverPackage,
    pub(crate) consumed_message_ids: Vec<MessageId>,
}

impl RefinedState {
    pub fn new(
        session: Session,
        alice: PrivateReceiverPackage,
        bob: PrivateReceiverPackage,
    ) -> Result<Self, CoreError> {
        let state = Self {
            session,
            turn: TurnState::new(Turn::new(0)),
            alice,
            bob,
            consumed_message_ids: Vec::new(),
        };
        state.validate_initial_packages()?;
        Ok(state)
    }

    pub fn with_turn(
        session: Session,
        turn: Turn,
        alice: PrivateReceiverPackage,
        bob: PrivateReceiverPackage,
        consumed_message_ids: Vec<MessageId>,
    ) -> Result<Self, CoreError> {
        let state = Self {
            session,
            turn: TurnState::new(turn),
            alice,
            bob,
            consumed_message_ids,
        };
        state.validate_initial_packages()?;
        Ok(state)
    }

    fn validate_initial_packages(&self) -> Result<(), CoreError> {
        ProtocolVersion::try_supported(
            self.session.protocol_version().major(),
            self.session.protocol_version().minor(),
        )?;
        CipherSuite::try_from_id(self.session.cipher_suite().id())?;
        for package in [&self.alice, &self.bob] {
            let public = package.public_projection();
            if public.session_id() != self.session.session_id() {
                return Err(CoreError::InvalidPublicPackage {
                    field: "session_id",
                });
            }
            if public.protocol_version() != self.session.protocol_version()
                || public.cipher_suite() != self.session.cipher_suite()
            {
                return Err(CoreError::InvalidPublicPackage {
                    field: "protocol context",
                });
            }
            if public.turn() > self.turn.current() {
                return Err(CoreError::InvalidPublicPackage { field: "turn" });
            }
        }
        Ok(())
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

    pub const fn leader(&self) -> Endpoint {
        self.turn.leader()
    }

    pub fn alice_public_package(&self) -> &PublicReceiverPackage {
        self.alice.public_projection()
    }

    pub fn bob_public_package(&self) -> &PublicReceiverPackage {
        self.bob.public_projection()
    }

    pub fn consumed_message_ids(&self) -> &[MessageId] {
        &self.consumed_message_ids
    }

    pub fn public_snapshot(&self) -> PublicStateSnapshot {
        PublicStateSnapshot {
            session: self.session,
            turn: self.turn,
            alice: self.alice.public_projection().clone(),
            bob: self.bob.public_projection().clone(),
            consumed_message_ids: self.consumed_message_ids.clone(),
        }
    }

    pub(crate) fn storage_parts(
        &self,
    ) -> (
        Session,
        Turn,
        &PrivateReceiverPackage,
        &PrivateReceiverPackage,
        &[MessageId],
    ) {
        (
            self.session,
            self.turn.current(),
            &self.alice,
            &self.bob,
            &self.consumed_message_ids,
        )
    }

    fn receiver_public_package(&self, sender: Endpoint) -> &PublicReceiverPackage {
        match sender.other() {
            Endpoint::Alice => self.alice.public_projection(),
            Endpoint::Bob => self.bob.public_projection(),
        }
    }

    fn validate_message(&self, message: &ApplicationMessage) -> Result<(), RejectReason> {
        if message.protocol_version() != self.session.protocol_version() {
            return Err(RejectReason::UnsupportedProtocolVersion);
        }
        if message.cipher_suite() != self.session.cipher_suite() {
            return Err(RejectReason::UnsupportedCipherSuite);
        }
        if message.session_id() != self.session.session_id() {
            return Err(RejectReason::SessionMismatch);
        }
        if message.turn() < self.turn.current() {
            return Err(RejectReason::PastTurn);
        }
        if message.turn() > self.turn.current() {
            return Err(RejectReason::FutureTurn);
        }
        if message.direction() != self.leader() {
            return Err(RejectReason::WrongLeader);
        }

        let receiver = self.receiver_public_package(message.direction());
        if message.receiver_key_id() != receiver.key_id() {
            return Err(RejectReason::ReceiverKeyMismatch);
        }
        if message.receiver_token() != receiver.mailbox_token() {
            return Err(RejectReason::ReceiverTokenMismatch);
        }
        if self.consumed_message_ids.contains(&message.message_id()) {
            return Err(RejectReason::Replay);
        }
        Ok(())
    }

    /// Validates only the Lean-refined message predicate.
    pub fn validate(&self, message: &ApplicationMessage) -> Result<(), RejectReason> {
        self.validate_message(message)
    }

    fn validate_fresh_package(
        &self,
        receiver: Endpoint,
        next: &PrivateReceiverPackage,
    ) -> Result<(), RejectReason> {
        let public = next.public_projection();
        if public.session_id() != self.session.session_id() {
            return Err(RejectReason::FreshPackageSessionMismatch);
        }
        if public.protocol_version() != self.session.protocol_version()
            || public.cipher_suite() != self.session.cipher_suite()
        {
            return Err(RejectReason::FreshPackageContextMismatch);
        }
        let expected_turn = self
            .turn
            .next()
            .map_err(|_| RejectReason::FreshPackageTurnMismatch)?;
        if public.turn() != expected_turn.current() {
            return Err(RejectReason::FreshPackageTurnMismatch);
        }
        let current_generation = match receiver {
            Endpoint::Alice => self.alice.public_projection().generation(),
            Endpoint::Bob => self.bob.public_projection().generation(),
        };
        if public.generation() <= current_generation {
            return Err(RejectReason::FreshPackageGenerationNotAdvanced);
        }
        Ok(())
    }

    fn commit(
        &self,
        message: &ApplicationMessage,
        next: PrivateReceiverPackage,
    ) -> Result<RefinedState, CoreError> {
        let next_turn = self.turn.next()?;
        let mut next_state = self.clone();
        next_state.turn = next_turn;
        match message.direction() {
            Endpoint::Alice => next_state.bob = next,
            Endpoint::Bob => next_state.alice = next,
        }
        next_state
            .consumed_message_ids
            .insert(0, message.message_id());
        Ok(next_state)
    }

    /// Pure `refinedStep`: rejection clones the original state; acceptance
    /// returns a pending complete state for an outer atomic commit.
    pub fn step(&self, message: &ApplicationMessage, next: PrivateReceiverPackage) -> StepOutcome {
        if let Err(reason) = self.validate_message(message) {
            return StepOutcome::Rejected {
                reason,
                state: self.clone(),
            };
        }
        let receiver = message.direction().other();
        if let Err(reason) = self.validate_fresh_package(receiver, &next) {
            return StepOutcome::Rejected {
                reason,
                state: self.clone(),
            };
        }
        let payload = message.payload().clone();
        match self.commit(message, next) {
            Ok(next_state) => StepOutcome::Accepted(PreparedStep {
                next_state,
                accepted_message_id: message.message_id(),
                payload,
            }),
            Err(_) => StepOutcome::Rejected {
                reason: RejectReason::FreshPackageTurnMismatch,
                state: self.clone(),
            },
        }
    }

    /// Canonically decodes a message and then executes the same pure step.
    pub fn process_encoded(
        &self,
        encoded: &[u8],
        next: PrivateReceiverPackage,
    ) -> Result<StepOutcome, CoreError> {
        let wire = linkchat_protocol::decode_application_message(encoded)?;
        let canonical = encode(&wire)?;
        if canonical.as_bytes() != encoded {
            return Err(CoreError::NonCanonical);
        }
        Ok(self.step(&ApplicationMessage::from_wire(&wire), next))
    }
}
use crate::{
    ApplicationMessage, CoreError, Endpoint, PrivateReceiverPackage, PublicReceiverPackage,
    PublicStateSnapshot, RejectReason, Session, TurnState,
};
use linkchat_protocol::{WireBytes, encode};
use linkchat_types::{CipherSuite, MessageId, ProtocolVersion, Turn};
