/// The two protocol endpoints.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Endpoint {
    /// The even-turn sender.
    Alice,
    /// The odd-turn sender.
    Bob,
}

impl Endpoint {
    /// Returns the endpoint that receives a message from this endpoint.
    pub const fn other(self) -> Self {
        match self {
            Self::Alice => Self::Bob,
            Self::Bob => Self::Alice,
        }
    }

    /// Returns the strict alternating leader for a turn.
    pub const fn leader(turn: Turn) -> Self {
        if turn.get().is_multiple_of(2) {
            Self::Alice
        } else {
            Self::Bob
        }
    }

    pub(crate) fn from_direction(direction: Direction) -> Self {
        match direction {
            Direction::Alice => Self::Alice,
            Direction::Bob => Self::Bob,
        }
    }

    pub(crate) const fn direction(self) -> Direction {
        match self {
            Self::Alice => Direction::Alice,
            Self::Bob => Direction::Bob,
        }
    }
}

/// The session context bound to every core message and package.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Session {
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    session_id: SessionId,
}

impl Session {
    /// Creates a v1.0 session using the standardized hybrid suite.
    pub const fn new(session_id: SessionId) -> Self {
        Self {
            protocol_version: ProtocolVersion::V1_0,
            cipher_suite: CipherSuite::V1HybridMlKem768,
            session_id,
        }
    }

    /// Creates a session with an explicit context, for callers that already
    /// validated the supported version and suite.
    pub const fn with_context(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        session_id: SessionId,
    ) -> Self {
        Self {
            protocol_version,
            cipher_suite,
            session_id,
        }
    }

    pub const fn protocol_version(self) -> ProtocolVersion {
        self.protocol_version
    }

    pub const fn cipher_suite(self) -> CipherSuite {
        self.cipher_suite
    }

    pub const fn session_id(self) -> SessionId {
        self.session_id
    }
}

/// The current point in the strict Alice/Bob turn sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TurnState {
    turn: Turn,
}

impl TurnState {
    pub const fn new(turn: Turn) -> Self {
        Self { turn }
    }

    pub const fn current(self) -> Turn {
        self.turn
    }

    pub const fn leader(self) -> Endpoint {
        Endpoint::leader(self.turn)
    }

    pub const fn next(self) -> Result<Self, TypeError> {
        match self.turn.next() {
            Ok(turn) => Ok(Self::new(turn)),
            Err(error) => Err(error),
        }
    }
}
use linkchat_protocol::Direction;
use linkchat_types::{CipherSuite, ProtocolVersion, SessionId, Turn, TypeError};
