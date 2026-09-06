use linkchat_protocol::WireReceiverPackage;

/// Successful completion.
pub const LC_OK: i32 = 0;
/// A required pointer was null.
pub const LC_ERR_NULL_POINTER: i32 = 1;
/// An input or output length is outside the ABI contract.
pub const LC_ERR_INVALID_LENGTH: i32 = 2;
/// A handle is unknown or has the wrong kind.
pub const LC_ERR_INVALID_HANDLE: i32 = 3;
/// The supplied bytes are malformed or violate canonical wire rules.
pub const LC_ERR_WIRE: i32 = 4;
/// The supplied bytes decode but are not the canonical re-encoding.
pub const LC_ERR_NON_CANONICAL: i32 = 5;
/// The caller-owned output buffer is too small; no partial output is written.
pub const LC_ERR_BUFFER_TOO_SMALL: i32 = 6;
/// An internal lock, allocation, or panic boundary failed.
pub const LC_ERR_INTERNAL: i32 = 7;
/// A cryptographic primitive, AEAD, package, or identity check failed.
pub const LC_ERR_CRYPTO: i32 = 8;
/// The endpoint rejected the input without changing protocol state.
pub const LC_ERR_REJECTED: i32 = 9;
/// Endpoint-local storage prepare, commit, load, or recovery failed.
pub const LC_ERR_STORAGE: i32 = 10;
/// An external transport or mailbox operation can be retried.
pub const LC_ERR_RETRYABLE: i32 = 11;
/// An endpoint or argument is validly shaped but not usable for this call.
pub const LC_ERR_INVALID_ARGUMENT: i32 = 12;
/// A prepare/commit handle is missing or no longer current.
pub const LC_ERR_NOT_READY: i32 = 13;

pub(crate) const MAX_FFI_INPUT: usize = 64 * 1024;

/// Public package metadata returned without token, authentication, or secret bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LinkChatPackageMetadata {
    pub protocol_major: u16,
    pub protocol_minor: u16,
    pub cipher_suite: u16,
    pub session_id: u64,
    pub turn: u64,
    pub generation: u64,
    pub key_id: u64,
    pub expiration: u64,
    pub x25519_public_key: [u8; 32],
    pub mlkem_public_key_len: u32,
    pub package_auth_len: u32,
}

/// Public endpoint snapshot metadata. No token, authentication bytes, or
/// private key material are included.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LinkChatEndpointMetadata {
    pub session_id: u64,
    pub endpoint: u8,
    pub reserved: [u8; 7],
    pub turn: u64,
    pub consumed_message_count: u64,
    pub local_identity_public: [u8; 32],
    pub peer_identity_public: [u8; 32],
    pub local_generation: u64,
    pub local_key_id: u64,
    pub local_expiration: u64,
    pub local_x25519_public_key: [u8; 32],
    pub local_mlkem_public_key_len: u32,
    pub local_package_auth_len: u32,
    pub peer_generation: u64,
    pub peer_key_id: u64,
    pub peer_expiration: u64,
    pub peer_x25519_public_key: [u8; 32],
    pub peer_mlkem_public_key_len: u32,
    pub peer_package_auth_len: u32,
}

/// Metadata returned after a committed receive. Payload and package bytes are
/// returned separately through caller-owned buffers.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LinkChatReceiveMetadata {
    pub message_id: u64,
    pub payload_len: usize,
    pub returned_package_len: usize,
}

pub(crate) struct BootstrapMaterial {
    pub(crate) session: linkchat_core::Session,
    pub(crate) endpoint: linkchat_core::Endpoint,
    pub(crate) identity: linkchat_crypto::Ed25519KeyPair,
    pub(crate) local_package: linkchat_core::PrivateReceiverPackage,
    pub(crate) bootstrap_previous_hash: linkchat_types::PackageHash,
    pub(crate) expiration: u64,
    pub(crate) now: u64,
}

pub(crate) enum HandleEntry {
    Session(linkchat_core::Session),
    Package(WireReceiverPackage),
    Bootstrap(Box<BootstrapMaterial>),
    Endpoint(
        Box<
            linkchat_engine::EndpointEngine<
                linkchat_crypto::OsCryptoBackend,
                linkchat_engine::MemoryEndpointStorage,
            >,
        >,
    ),
    PreparedSend {
        endpoint: u64,
        prepared: linkchat_engine::PreparedSend,
    },
    PreparedReceive {
        endpoint: u64,
        prepared: linkchat_engine::PreparedReceive,
    },
}
