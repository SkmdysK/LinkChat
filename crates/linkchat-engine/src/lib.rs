//! Storage-aware endpoint composition for Link Chat v1.0.
//!
//! This crate owns orchestration only.  Cryptographic operations remain in
//! `linkchat-crypto`, protocol validation remains in `linkchat-core`, and
//! network or mailbox delivery remains outside this crate.

use std::fmt;

use linkchat_core::{
    CoreError, Endpoint, EndpointKernel, PreparedReceive as CorePreparedReceive,
    PreparedSend as CorePreparedSend, PublicReceiverPackage, PublicStateSnapshot, RejectReason,
    Session,
};
use linkchat_crypto::{CryptoBackend, CryptoError, Ed25519PublicKey, Ed25519SecretKey};
use linkchat_protocol::{WireBytes, WireEnvelope, WireError, encode};
use linkchat_types::{MessageId, PackageGeneration, PackageHash, Turn};

/// Errors exposed by the high-level endpoint boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineError {
    Configuration,
    Wire(WireError),
    Cryptographic(CryptoError),
    Core(CoreError),
    Rejected(RejectReason),
    RetryableTransport,
    Storage(StorageFailure),
    NoPreparedOperation,
    StalePreparedOperation,
}

impl fmt::Display for EngineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration => formatter.write_str("invalid endpoint configuration"),
            Self::Wire(error) => write!(formatter, "wire operation failed: {error}"),
            Self::Cryptographic(error) => {
                write!(formatter, "cryptographic operation failed: {error}")
            }
            Self::Core(error) => write!(formatter, "core operation failed: {error}"),
            Self::Rejected(reason) => write!(formatter, "protocol input rejected: {reason}"),
            Self::RetryableTransport => formatter.write_str("retryable transport failure"),
            Self::Storage(failure) => write!(formatter, "storage operation failed: {failure}"),
            Self::NoPreparedOperation => formatter.write_str("no prepared operation"),
            Self::StalePreparedOperation => formatter.write_str("prepared operation is stale"),
        }
    }
}

impl std::error::Error for EngineError {}

impl From<WireError> for EngineError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

impl From<CryptoError> for EngineError {
    fn from(error: CryptoError) -> Self {
        Self::Cryptographic(error)
    }
}

impl From<CoreError> for EngineError {
    fn from(error: CoreError) -> Self {
        match error {
            CoreError::Wire(error) => Self::Wire(error),
            CoreError::Crypto(error) => Self::Cryptographic(error),
            CoreError::PackageAuthenticationInvalid => {
                Self::Cryptographic(CryptoError::AuthenticationFailed)
            }
            CoreError::EnvelopeContextMismatch { field } => Self::Rejected(match field {
                "message_id already used" => RejectReason::Replay,
                "mailbox token" => RejectReason::ReceiverTokenMismatch,
                "receiver package hash" => RejectReason::ReceiverKeyMismatch,
                _ => RejectReason::SessionMismatch,
            }),
            CoreError::PackageContextMismatch => {
                Self::Rejected(RejectReason::FreshPackageContextMismatch)
            }
            CoreError::PackageTurnMismatch => {
                Self::Rejected(RejectReason::FreshPackageTurnMismatch)
            }
            CoreError::PackageGenerationMismatch | CoreError::PackageChainMismatch => {
                Self::Rejected(RejectReason::FreshPackageGenerationNotAdvanced)
            }
            error => Self::Core(error),
        }
    }
}

/// Stable storage error categories.  Adapter-specific errors are intentionally
/// collapsed so secret paths and storage internals do not enter error text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageFailure {
    Initialize,
    Load,
    Prepare,
    Commit,
    Recover,
}

impl fmt::Display for StorageFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Initialize => "initialization",
            Self::Load => "load",
            Self::Prepare => "prepare",
            Self::Commit => "commit",
            Self::Recover => "recover",
        };
        write!(formatter, "storage {text} failed")
    }
}

/// Endpoint configuration.  Secret identity material is retained opaquely and
/// never appears in public accessors, formatting, or result values.
#[derive(Clone)]
pub struct EndpointConfig {
    session: Session,
    endpoint: Endpoint,
    local_identity: Ed25519SecretKey,
    local_identity_public: Ed25519PublicKey,
    peer_identity: Ed25519PublicKey,
    local_bootstrap_previous_hash: PackageHash,
    peer_bootstrap_previous_hash: PackageHash,
    expiration: u64,
    now: u64,
}

impl EndpointConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session: Session,
        endpoint: Endpoint,
        local_identity: Ed25519SecretKey,
        local_identity_public: Ed25519PublicKey,
        peer_identity: Ed25519PublicKey,
        bootstrap_previous_hash: PackageHash,
        expiration: u64,
        now: u64,
    ) -> Self {
        Self::new_with_bootstrap_roots(
            session,
            endpoint,
            local_identity,
            local_identity_public,
            peer_identity,
            bootstrap_previous_hash,
            bootstrap_previous_hash,
            expiration,
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_bootstrap_roots(
        session: Session,
        endpoint: Endpoint,
        local_identity: Ed25519SecretKey,
        local_identity_public: Ed25519PublicKey,
        peer_identity: Ed25519PublicKey,
        local_bootstrap_previous_hash: PackageHash,
        peer_bootstrap_previous_hash: PackageHash,
        expiration: u64,
        now: u64,
    ) -> Self {
        Self {
            session,
            endpoint,
            local_identity,
            local_identity_public,
            peer_identity,
            local_bootstrap_previous_hash,
            peer_bootstrap_previous_hash,
            expiration,
            now,
        }
    }

    pub fn from_identity_keypair(
        session: Session,
        endpoint: Endpoint,
        identity: linkchat_crypto::Ed25519KeyPair,
        peer_identity: Ed25519PublicKey,
        bootstrap_previous_hash: PackageHash,
        expiration: u64,
        now: u64,
    ) -> Self {
        Self::new_with_bootstrap_roots(
            session,
            endpoint,
            identity.secret_key,
            identity.public_key,
            peer_identity,
            bootstrap_previous_hash,
            bootstrap_previous_hash,
            expiration,
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_identity_keypair_with_bootstrap_roots(
        session: Session,
        endpoint: Endpoint,
        identity: linkchat_crypto::Ed25519KeyPair,
        peer_identity: Ed25519PublicKey,
        local_bootstrap_previous_hash: PackageHash,
        peer_bootstrap_previous_hash: PackageHash,
        expiration: u64,
        now: u64,
    ) -> Self {
        Self::new_with_bootstrap_roots(
            session,
            endpoint,
            identity.secret_key,
            identity.public_key,
            peer_identity,
            local_bootstrap_previous_hash,
            peer_bootstrap_previous_hash,
            expiration,
            now,
        )
    }

    pub const fn session(&self) -> Session {
        self.session
    }

    pub const fn endpoint(&self) -> Endpoint {
        self.endpoint
    }

    fn local_identity_public(&self) -> Ed25519PublicKey {
        self.local_identity_public
    }
}

/// Opaque endpoint state handed to a storage adapter.  It exposes only public
/// projections and snapshots; the private package remains inaccessible.
#[derive(Clone)]
pub struct EndpointState {
    kernel: EndpointKernel,
}

impl EndpointState {
    fn from_kernel(kernel: &EndpointKernel) -> Self {
        Self {
            kernel: kernel.clone(),
        }
    }

    fn into_kernel(self) -> EndpointKernel {
        self.kernel
    }

    pub fn public_snapshot(&self) -> PublicStateSnapshot {
        self.kernel.public_snapshot()
    }

    pub const fn turn(&self) -> Turn {
        self.kernel.turn()
    }

    pub fn public_receiver_package(&self) -> &PublicReceiverPackage {
        self.kernel.local_public_package()
    }
}

/// A storage adapter for endpoint-local state.  Adapters must make the
/// prepare/commit boundary durable before the engine publishes the next state.
pub trait EndpointStorage {
    type Error;
    type CommitToken: Clone;

    fn initialize(&mut self, initial: EndpointState) -> Result<(), Self::Error>;
    fn load_current(&self) -> Result<EndpointState, Self::Error>;
    fn prepare_commit(&mut self, next: EndpointState) -> Result<Self::CommitToken, Self::Error>;
    fn commit(&mut self, token: Self::CommitToken) -> Result<(), Self::Error>;
    fn recover(&mut self) -> Result<EndpointState, Self::Error>;
}

/// A prepared send.  It carries the encoded Envelope and a private pending
/// transition that can only be committed through the owning engine.
pub struct PreparedSend {
    base_turn: Turn,
    envelope: WireEnvelope,
    encoded: WireBytes,
    core: CorePreparedSend,
}

impl PreparedSend {
    pub fn envelope(&self) -> &WireEnvelope {
        &self.envelope
    }

    pub fn encoded(&self) -> &WireBytes {
        &self.encoded
    }
}

/// A prepared receive with authenticated application payload and returned
/// public Receiver Package.
pub struct PreparedReceive {
    base_turn: Turn,
    message_id: MessageId,
    plaintext: WireBytes,
    returned_receiver_package: PublicReceiverPackage,
    core: CorePreparedReceive,
}

impl PreparedReceive {
    pub const fn message_id(&self) -> MessageId {
        self.message_id
    }

    pub fn plaintext(&self) -> &WireBytes {
        &self.plaintext
    }

    pub fn returned_receiver_package(&self) -> &PublicReceiverPackage {
        &self.returned_receiver_package
    }
}

/// Result returned after a durable send commit.
pub struct SendResult {
    envelope: WireEnvelope,
    encoded: WireBytes,
    snapshot: PublicStateSnapshot,
}

impl SendResult {
    pub fn envelope(&self) -> &WireEnvelope {
        &self.envelope
    }

    pub fn encoded(&self) -> &WireBytes {
        &self.encoded
    }

    pub fn public_snapshot(&self) -> &PublicStateSnapshot {
        &self.snapshot
    }
}

/// Result returned after a durable receive commit.
pub struct ReceiveResult {
    message_id: MessageId,
    plaintext: WireBytes,
    returned_receiver_package: PublicReceiverPackage,
    snapshot: PublicStateSnapshot,
}

impl ReceiveResult {
    pub const fn message_id(&self) -> MessageId {
        self.message_id
    }

    pub fn plaintext(&self) -> &WireBytes {
        &self.plaintext
    }

    pub fn returned_receiver_package(&self) -> &PublicReceiverPackage {
        &self.returned_receiver_package
    }

    pub fn public_snapshot(&self) -> &PublicStateSnapshot {
        &self.snapshot
    }
}

/// Storage-aware endpoint engine.  Transport and Mailbox are intentionally not
/// accepted here, so delivery metadata cannot advance the protocol state.
pub struct EndpointEngine<B, S> {
    backend: B,
    storage: S,
    kernel: EndpointKernel,
    local_identity_public: Ed25519PublicKey,
    peer_identity_public: Ed25519PublicKey,
    validation_now: u64,
}

impl<B: CryptoBackend, S: EndpointStorage> EndpointEngine<B, S> {
    pub fn create(
        mut backend: B,
        storage: S,
        config: EndpointConfig,
        peer_package: PublicReceiverPackage,
    ) -> Result<Self, EngineError> {
        if config.expiration <= config.now {
            return Err(EngineError::Configuration);
        }
        let local = linkchat_core::ReceiverPackageFactory::generate(
            &mut backend,
            config.session,
            &config.local_identity,
            Turn::new(0),
            PackageGeneration::new(0),
            config.expiration,
            config.local_bootstrap_previous_hash,
        )?;
        Self::create_with_local_package(backend, storage, config, local, peer_package)
    }

    /// Creates an endpoint from a caller-owned opaque private package.  The
    /// package is verified against the configured identity before use; callers
    /// cannot provide an unrelated public projection.
    pub fn create_with_local_package(
        backend: B,
        mut storage: S,
        config: EndpointConfig,
        local: linkchat_core::PrivateReceiverPackage,
        peer_package: PublicReceiverPackage,
    ) -> Result<Self, EngineError> {
        if config.expiration <= config.now {
            return Err(EngineError::Configuration);
        }
        if !identity_pair_matches(
            &backend,
            &config.local_identity,
            &config.local_identity_public,
        ) {
            return Err(EngineError::Configuration);
        }
        linkchat_core::verify_receiver_package(
            &backend,
            local.public_projection(),
            config.session,
            &config.local_identity_public(),
            Turn::new(0),
            PackageGeneration::new(0),
            config.local_bootstrap_previous_hash,
            config.now,
        )?;
        linkchat_core::verify_receiver_package(
            &backend,
            &peer_package,
            config.session,
            &config.peer_identity,
            Turn::new(0),
            PackageGeneration::new(0),
            config.peer_bootstrap_previous_hash,
            config.now,
        )?;
        let kernel = EndpointKernel::new(
            &backend,
            config.session,
            config.endpoint,
            local,
            peer_package,
            config.local_identity.clone(),
            config.peer_identity,
            Turn::new(0),
            config.now,
        )?;
        storage
            .initialize(EndpointState::from_kernel(&kernel))
            .map_err(|_| EngineError::Storage(StorageFailure::Initialize))?;
        Ok(Self {
            backend,
            storage,
            kernel,
            local_identity_public: config.local_identity_public,
            peer_identity_public: config.peer_identity,
            validation_now: config.now,
        })
    }

    /// Opens the durable Current state held by an adapter after process
    /// restart.  The adapter remains responsible for crash recovery ordering.
    pub fn open(backend: B, storage: S, config: EndpointConfig) -> Result<Self, EngineError> {
        if config.expiration <= config.now
            || !identity_pair_matches(
                &backend,
                &config.local_identity,
                &config.local_identity_public,
            )
        {
            return Err(EngineError::Configuration);
        }
        let state = storage
            .load_current()
            .map_err(|_| EngineError::Storage(StorageFailure::Load))?;
        let kernel = state.into_kernel();
        validate_recovered_kernel(
            &backend,
            &kernel,
            config.session,
            config.endpoint,
            &config.local_identity_public,
            &config.peer_identity,
            config.now,
        )?;
        Ok(Self {
            backend,
            storage,
            kernel,
            local_identity_public: config.local_identity_public,
            peer_identity_public: config.peer_identity,
            validation_now: config.now,
        })
    }

    pub fn public_receiver_package(&self) -> &PublicReceiverPackage {
        self.kernel.local_public_package()
    }

    pub fn peer_public_receiver_package(&self) -> &PublicReceiverPackage {
        self.kernel.peer_public_package()
    }

    pub fn public_snapshot(&self) -> PublicStateSnapshot {
        self.kernel.public_snapshot()
    }

    pub const fn turn(&self) -> Turn {
        self.kernel.turn()
    }

    pub const fn endpoint(&self) -> Endpoint {
        self.kernel.endpoint()
    }

    pub const fn local_identity_public(&self) -> Ed25519PublicKey {
        self.local_identity_public
    }

    pub const fn peer_identity_public(&self) -> Ed25519PublicKey {
        self.peer_identity_public
    }

    pub fn prepare_send(
        &mut self,
        message_id: MessageId,
        payload: &[u8],
        now: u64,
    ) -> Result<PreparedSend, EngineError> {
        let core = self
            .kernel
            .prepare_send(&mut self.backend, message_id, payload, now)?;
        let envelope = core.envelope().clone();
        let encoded = WireBytes::from_bytes(encode(&envelope)?.as_bytes())?;
        Ok(PreparedSend {
            base_turn: self.kernel.turn(),
            envelope,
            encoded,
            core,
        })
    }

    pub fn commit_send(&mut self, prepared: PreparedSend) -> Result<SendResult, EngineError> {
        self.ensure_turn(prepared.base_turn)?;
        let envelope = prepared.envelope.clone();
        let encoded = prepared.encoded.clone();
        let next_kernel = prepared.core.commit();
        self.commit_kernel(next_kernel)?;
        Ok(SendResult {
            envelope,
            encoded,
            snapshot: self.public_snapshot(),
        })
    }

    pub fn prepare_receive(
        &mut self,
        encoded: &[u8],
        now: u64,
        next_expiration: u64,
    ) -> Result<PreparedReceive, EngineError> {
        let core = self
            .kernel
            .prepare_receive(&mut self.backend, encoded, now, next_expiration)?;
        Ok(PreparedReceive {
            base_turn: self.kernel.turn(),
            message_id: core.message_id(),
            plaintext: core.plaintext().clone(),
            returned_receiver_package: core.returned_receiver_package().clone(),
            core,
        })
    }

    pub fn commit_receive(
        &mut self,
        prepared: PreparedReceive,
    ) -> Result<ReceiveResult, EngineError> {
        self.ensure_turn(prepared.base_turn)?;
        let message_id = prepared.message_id;
        let plaintext = prepared.plaintext.clone();
        let returned_receiver_package = prepared.returned_receiver_package.clone();
        let next_kernel = prepared.core.commit();
        self.commit_kernel(next_kernel)?;
        Ok(ReceiveResult {
            message_id,
            plaintext,
            returned_receiver_package,
            snapshot: self.public_snapshot(),
        })
    }

    pub fn recover(&mut self) -> Result<PublicStateSnapshot, EngineError> {
        self.recover_at(self.validation_now)
    }

    /// Recovers the adapter state and validates it against a caller-supplied
    /// current time before publishing it as the in-memory kernel.
    pub fn recover_at(&mut self, now: u64) -> Result<PublicStateSnapshot, EngineError> {
        let state = self
            .storage
            .recover()
            .map_err(|_| EngineError::Storage(StorageFailure::Recover))?;
        let kernel = state.into_kernel();
        validate_recovered_kernel(
            &self.backend,
            &kernel,
            self.kernel.session(),
            self.kernel.endpoint(),
            &self.local_identity_public,
            &self.peer_identity_public,
            now,
        )?;
        self.kernel = kernel;
        self.validation_now = now;
        Ok(self.public_snapshot())
    }

    fn ensure_turn(&self, base_turn: Turn) -> Result<(), EngineError> {
        if self.kernel.turn() != base_turn {
            Err(EngineError::StalePreparedOperation)
        } else {
            Ok(())
        }
    }

    fn commit_kernel(&mut self, next_kernel: EndpointKernel) -> Result<(), EngineError> {
        let state = EndpointState::from_kernel(&next_kernel);
        let token = self
            .storage
            .prepare_commit(state)
            .map_err(|_| EngineError::Storage(StorageFailure::Prepare))?;
        self.storage
            .commit(token)
            .map_err(|_| EngineError::Storage(StorageFailure::Commit))?;
        self.kernel = next_kernel;
        Ok(())
    }
}

impl<B, S> EndpointEngine<B, S> {
    pub fn into_storage(self) -> S {
        self.storage
    }
}

fn identity_pair_matches<B: CryptoBackend>(
    backend: &B,
    secret: &Ed25519SecretKey,
    public: &Ed25519PublicKey,
) -> bool {
    const BINDING: &[u8] = b"LinkChat/engine-identity-binding/v1";
    match backend.ed25519_sign(secret, BINDING) {
        Ok(signature) => backend
            .ed25519_verify(public, BINDING, &signature)
            .unwrap_or(false),
        Err(_) => false,
    }
}

fn validate_recovered_kernel<B: CryptoBackend>(
    backend: &B,
    kernel: &EndpointKernel,
    session: Session,
    endpoint: Endpoint,
    local_identity: &Ed25519PublicKey,
    peer_identity: &Ed25519PublicKey,
    now: u64,
) -> Result<(), EngineError> {
    if kernel.session() != session || kernel.endpoint() != endpoint {
        return Err(EngineError::Configuration);
    }
    for package in [kernel.local_public_package(), kernel.peer_public_package()] {
        if package.protocol_version() != session.protocol_version()
            || package.cipher_suite() != session.cipher_suite()
            || package.session_id() != session.session_id()
            || package.turn() > kernel.turn()
            || package.expiration() <= now
        {
            return Err(EngineError::Configuration);
        }
    }
    linkchat_core::verify_receiver_package_auth(
        backend,
        kernel.local_public_package(),
        local_identity,
    )?;
    linkchat_core::verify_receiver_package_auth(
        backend,
        kernel.peer_public_package(),
        peer_identity,
    )?;
    Ok(())
}

/// A deterministic in-memory adapter for integration tests and embedders that
/// provide their own durable implementation through `EndpointStorage`.
#[derive(Clone)]
pub struct MemoryEndpointStorage {
    current: Option<EndpointState>,
    pending: Option<EndpointState>,
}

impl MemoryEndpointStorage {
    pub const fn empty() -> Self {
        Self {
            current: None,
            pending: None,
        }
    }
}

impl EndpointStorage for MemoryEndpointStorage {
    type Error = ();
    type CommitToken = Turn;

    fn initialize(&mut self, initial: EndpointState) -> Result<(), Self::Error> {
        if self.current.is_some() {
            return Err(());
        }
        self.current = Some(initial);
        Ok(())
    }

    fn load_current(&self) -> Result<EndpointState, Self::Error> {
        self.current.clone().ok_or(())
    }

    fn prepare_commit(&mut self, next: EndpointState) -> Result<Self::CommitToken, Self::Error> {
        if self.pending.is_some() {
            return Err(());
        }
        let current = self.current.as_ref().ok_or(())?;
        if next.turn().get() != current.turn().get().saturating_add(1) {
            return Err(());
        }
        let turn = next.turn();
        self.pending = Some(next);
        Ok(turn)
    }

    fn commit(&mut self, token: Self::CommitToken) -> Result<(), Self::Error> {
        let pending = self.pending.take().ok_or(())?;
        if pending.turn() != token {
            self.pending = Some(pending);
            return Err(());
        }
        self.current = Some(pending);
        Ok(())
    }

    fn recover(&mut self) -> Result<EndpointState, Self::Error> {
        self.pending = None;
        self.current.clone().ok_or(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linkchat_core::{Endpoint, ReceiverPackageFactory, package_chain_root};
    use linkchat_crypto::OsCryptoBackend;
    use linkchat_protocol::WireBytes;
    use linkchat_types::{PackageHash, SessionId};

    fn setup() -> (EndpointConfig, PublicReceiverPackage) {
        let mut backend = OsCryptoBackend::new();
        let alice = backend.generate_ed25519_keypair().unwrap();
        let bob = backend.generate_ed25519_keypair().unwrap();
        let root = PackageHash::from_array([0; 32]);
        let bob_package = ReceiverPackageFactory::generate(
            &mut backend,
            Session::new(SessionId::new(71)),
            &bob.secret_key,
            Turn::new(0),
            PackageGeneration::new(0),
            100,
            root,
        )
        .unwrap()
        .into_public_projection();
        (
            EndpointConfig::new(
                Session::new(SessionId::new(71)),
                Endpoint::Alice,
                alice.secret_key,
                alice.public_key,
                bob.public_key,
                root,
                100,
                1,
            ),
            bob_package,
        )
    }

    #[test]
    fn create_exposes_only_public_state_and_commits_explicitly() {
        let (config, bob_package) = setup();
        let engine = EndpointEngine::create(
            OsCryptoBackend::new(),
            MemoryEndpointStorage::empty(),
            config,
            bob_package,
        )
        .unwrap();
        assert_eq!(engine.turn(), Turn::new(0));
        assert_eq!(engine.public_snapshot().turn(), Turn::new(0));
    }

    #[test]
    fn rejected_receive_does_not_change_engine_state() {
        let (config, bob_package) = setup();
        let mut engine = EndpointEngine::create(
            OsCryptoBackend::new(),
            MemoryEndpointStorage::empty(),
            config,
            bob_package,
        )
        .unwrap();
        let before = engine.public_snapshot();
        let error = match engine.prepare_receive(&[0; 7], 1, 100) {
            Ok(_) => panic!("malformed envelope was accepted"),
            Err(error) => error,
        };
        assert!(matches!(error, EngineError::Wire(_)));
        assert!(engine.public_snapshot() == before);
    }

    #[test]
    fn recover_rejects_expired_state_without_replacing_kernel() {
        let (config, bob_package) = setup();
        let mut engine = EndpointEngine::create(
            OsCryptoBackend::new(),
            MemoryEndpointStorage::empty(),
            config,
            bob_package,
        )
        .unwrap();
        let before = engine.public_snapshot();
        assert!(matches!(
            engine.recover_at(100),
            Err(EngineError::Configuration)
        ));
        assert!(engine.public_snapshot() == before);
    }

    #[test]
    fn two_engines_commit_send_receive_and_recover() {
        let mut backend = OsCryptoBackend::new();
        let alice_identity = backend.generate_ed25519_keypair().unwrap();
        let bob_identity = backend.generate_ed25519_keypair().unwrap();
        let session = Session::new(SessionId::new(72));
        let alice_root = package_chain_root(
            &backend,
            session,
            &alice_identity.public_key,
            &bob_identity.public_key,
            Endpoint::Alice,
        )
        .unwrap();
        let bob_root = package_chain_root(
            &backend,
            session,
            &alice_identity.public_key,
            &bob_identity.public_key,
            Endpoint::Bob,
        )
        .unwrap();
        let alice_package = ReceiverPackageFactory::generate(
            &mut backend,
            session,
            &alice_identity.secret_key,
            Turn::new(0),
            PackageGeneration::new(0),
            100,
            alice_root,
        )
        .unwrap();
        let alice_public = alice_package.public_projection().clone();
        let bob_package = ReceiverPackageFactory::generate(
            &mut backend,
            session,
            &bob_identity.secret_key,
            Turn::new(0),
            PackageGeneration::new(0),
            100,
            bob_root,
        )
        .unwrap();
        let bob_public = bob_package.public_projection().clone();

        let alice_config = EndpointConfig::new_with_bootstrap_roots(
            session,
            Endpoint::Alice,
            alice_identity.secret_key,
            alice_identity.public_key,
            bob_identity.public_key,
            alice_root,
            bob_root,
            100,
            1,
        );
        let bob_config = EndpointConfig::new_with_bootstrap_roots(
            session,
            Endpoint::Bob,
            bob_identity.secret_key,
            bob_identity.public_key,
            alice_identity.public_key,
            bob_root,
            alice_root,
            100,
            1,
        );
        let mut alice = EndpointEngine::create_with_local_package(
            OsCryptoBackend::new(),
            MemoryEndpointStorage::empty(),
            alice_config,
            alice_package,
            bob_public,
        )
        .unwrap();
        let mut bob = EndpointEngine::create_with_local_package(
            OsCryptoBackend::new(),
            MemoryEndpointStorage::empty(),
            bob_config,
            bob_package,
            alice_public,
        )
        .unwrap();

        let prepared_send = alice.prepare_send(MessageId::new(1), b"hello", 1).unwrap();
        let encoded = prepared_send.encoded().clone();
        alice.commit_send(prepared_send).unwrap();
        assert_eq!(alice.turn(), Turn::new(1));

        let prepared_receive = bob.prepare_receive(encoded.as_bytes(), 1, 100).unwrap();
        assert_eq!(
            prepared_receive.plaintext(),
            &WireBytes::from_bytes(b"hello").unwrap()
        );
        bob.commit_receive(prepared_receive).unwrap();
        assert_eq!(bob.turn(), Turn::new(1));
        bob.recover().unwrap();
        assert_eq!(bob.turn(), Turn::new(1));
    }
}
