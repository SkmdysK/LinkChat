use super::errors::TypeError;

macro_rules! integer_newtype {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(u64);

        impl $name {
            /// Creates a value from the abstract counter/identifier domain.
            pub const fn new(value: u64) -> Self {
                Self(value)
            }

            /// Returns the underlying numeric value for local comparisons.
            pub const fn get(self) -> u64 {
                self.0
            }
        }
    };
}

integer_newtype! {
    /// A session-scoped session identifier.
    SessionId
}

integer_newtype! {
    /// A session-scoped message identifier.
    MessageId
}

integer_newtype! {
    /// The public identifier of a Receiver Package key.
    KeyId
}

integer_newtype! {
    /// The strictly alternating protocol turn.
    Turn
}

impl Turn {
    /// Advances the turn exactly once, or reports counter exhaustion.
    pub const fn next(self) -> Result<Self, TypeError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(TypeError::ArithmeticOverflow { type_name: "Turn" }),
        }
    }

    /// Alias emphasizing that this operation is a protocol transition.
    pub const fn advance(self) -> Result<Self, TypeError> {
        self.next()
    }
}

integer_newtype! {
    /// The local monotonic generation of a Receiver Package.
    PackageGeneration
}

impl PackageGeneration {
    /// Advances the package generation exactly once.
    pub const fn next(self) -> Result<Self, TypeError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(TypeError::ArithmeticOverflow {
                type_name: "PackageGeneration",
            }),
        }
    }

    /// Alias emphasizing that this operation is a package rotation.
    pub const fn advance(self) -> Result<Self, TypeError> {
        self.next()
    }
}

/// The protocol version carried by session and wire context.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion {
    major: u16,
    minor: u16,
}

impl ProtocolVersion {
    /// The only version currently standardized by this workspace.
    pub const V1_0: Self = Self { major: 1, minor: 0 };

    /// Constructs a non-zero protocol version.
    pub const fn new(major: u16, minor: u16) -> Result<Self, TypeError> {
        if major == 0 {
            return Err(TypeError::ValueOutOfRange {
                type_name: "ProtocolVersion.major",
                value: major as u64,
            });
        }
        Ok(Self { major, minor })
    }

    /// Returns the standardized v1.0 version.
    pub const fn current() -> Self {
        Self::V1_0
    }

    pub const fn major(self) -> u16 {
        self.major
    }

    pub const fn minor(self) -> u16 {
        self.minor
    }

    /// Accepts only the protocol version currently supported by this crate.
    pub const fn try_supported(major: u16, minor: u16) -> Result<Self, TypeError> {
        if major == Self::V1_0.major && minor == Self::V1_0.minor {
            Ok(Self::V1_0)
        } else {
            Err(TypeError::UnsupportedProtocolVersion { major, minor })
        }
    }
}

/// The standardized v1.0 hybrid cipher suite.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CipherSuite {
    /// X25519 wrapper + ML-KEM-768 + HKDF-SHA-256 + ChaCha20-Poly1305.
    V1HybridMlKem768 = 1,
}

impl CipherSuite {
    /// The suite selected by the v1.0 specification.
    pub const fn current() -> Self {
        Self::V1HybridMlKem768
    }

    /// Returns the stable protocol identifier for this suite.
    pub const fn id(self) -> u16 {
        self as u16
    }

    /// Rejects suite identifiers that are not standardized here.
    pub const fn try_from_id(id: u16) -> Result<Self, TypeError> {
        match id {
            1 => Ok(Self::V1HybridMlKem768),
            _ => Err(TypeError::UnsupportedCipherSuite { id }),
        }
    }
}
