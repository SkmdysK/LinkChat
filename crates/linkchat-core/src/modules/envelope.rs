//! Encrypted Envelope composition for a real endpoint.
//!
//! `RefinedState` remains the pure Lean-aligned transition model.  This module
//! owns the production-facing composition around it: canonical Envelope
//! decoding, KEM decapsulation/encapsulation, hybrid KDF, Header AEAD,
//! Message AEAD, payload-frame validation, and prepared endpoint updates.

use crate::{
    CoreError, Endpoint, PrivateReceiverPackage, PublicReceiverPackage, ReceiverPackageFactory,
    Session, packages::verify_receiver_package_auth,
};
use linkchat_crypto::{CryptoBackend, Ed25519PublicKey, Ed25519SecretKey, MlKemPublicKey};
use linkchat_protocol::{
    CanonicalEncode, Direction, MessageType, WireBytes, WireEnvelope, WireHeader, decode_envelope,
    decode_header, decode_payload_frame, domain, encode, encode_payload_frame,
};
use linkchat_types::{KeyId, MessageId, MlKemCiphertext, SharedSecret, Turn, X25519PublicKey};

/// A local endpoint with the private package and authenticated peer package
/// needed to send and receive the v1.0 encrypted Envelope.
#[derive(Clone)]
pub struct EndpointKernel {
    session: Session,
    endpoint: Endpoint,
    turn: Turn,
    local: PrivateReceiverPackage,
    peer: PublicReceiverPackage,
    local_identity: Ed25519SecretKey,
    peer_identity: Ed25519PublicKey,
    used_message_ids: Vec<MessageId>,
}

/// A successfully sealed message whose turn update is not committed yet.
pub struct PreparedSend {
    envelope: WireEnvelope,
    next: EndpointKernel,
}

/// A successfully opened message whose package rotation is not committed yet.
pub struct PreparedReceive {
    message_id: MessageId,
    plaintext: WireBytes,
    next: EndpointKernel,
}

impl EndpointKernel {
    /// Creates an endpoint from a local private package and an authenticated
    /// peer package.  The package signatures are checked before the endpoint
    /// becomes usable; state restoration supplies the current protocol turn.
    #[allow(clippy::too_many_arguments)]
    pub fn new<B: CryptoBackend>(
        backend: &B,
        session: Session,
        endpoint: Endpoint,
        local: PrivateReceiverPackage,
        peer: PublicReceiverPackage,
        local_identity: Ed25519SecretKey,
        peer_identity: Ed25519PublicKey,
        current_turn: Turn,
        now: u64,
    ) -> Result<Self, CoreError> {
        validate_package_context(session, local.public_projection())?;
        validate_package_context(session, &peer)?;
        if local.public_projection().turn() > current_turn || peer.turn() > current_turn {
            return Err(CoreError::PackageTurnMismatch);
        }
        if local.public_projection().expiration() <= now || peer.expiration() <= now {
            return Err(CoreError::PackageExpired);
        }
        verify_receiver_package_auth(backend, &peer, &peer_identity)?;
        Ok(Self {
            session,
            endpoint,
            turn: current_turn,
            local,
            peer,
            local_identity,
            peer_identity,
            used_message_ids: Vec::new(),
        })
    }

    pub const fn session(&self) -> Session {
        self.session
    }

    pub const fn endpoint(&self) -> Endpoint {
        self.endpoint
    }

    pub const fn turn(&self) -> Turn {
        self.turn
    }

    pub fn local_public_package(&self) -> &PublicReceiverPackage {
        self.local.public_projection()
    }

    pub fn peer_public_package(&self) -> &PublicReceiverPackage {
        &self.peer
    }

    /// Returns the public-only state projection for the endpoint.
    pub fn public_snapshot(&self) -> crate::PublicStateSnapshot {
        let (alice, bob) = match self.endpoint {
            Endpoint::Alice => (self.local.public_projection(), &self.peer),
            Endpoint::Bob => (&self.peer, self.local.public_projection()),
        };
        crate::PublicStateSnapshot::from_parts(
            self.session,
            self.turn,
            alice.clone(),
            bob.clone(),
            self.used_message_ids.clone(),
        )
    }

    pub fn used_message_ids(&self) -> &[MessageId] {
        &self.used_message_ids
    }

    /// Seals an application payload for the current leader turn.
    ///
    /// The returned object must be committed exactly once by the caller.  A
    /// dropped preparation leaves this endpoint unchanged and the prepared
    /// Envelope can be retransmitted without re-encrypting under the same
    /// message nonce.
    pub fn prepare_send<B: CryptoBackend>(
        &self,
        backend: &mut B,
        message_id: MessageId,
        payload: &[u8],
        now: u64,
    ) -> Result<PreparedSend, CoreError> {
        if Endpoint::leader(self.turn) != self.endpoint {
            return Err(CoreError::EnvelopeContextMismatch { field: "send turn" });
        }
        if self.local.public_projection().turn() != self.turn {
            return Err(CoreError::PackageTurnMismatch);
        }
        if self.used_message_ids.contains(&message_id) {
            return Err(CoreError::EnvelopeContextMismatch {
                field: "message_id already used",
            });
        }
        if self.local.public_projection().expiration() <= now || self.peer.expiration() <= now {
            return Err(CoreError::PackageExpired);
        }

        let payload_frame = encode_payload_frame(payload)?;
        let receiver_key_id = self.peer.key_id();
        let direction = self.endpoint.direction();
        let peer_hash = crate::receiver_package_hash(backend, &self.peer)?;
        let (x25519_ciphertext, classical_shared_secret) =
            backend.x25519_encapsulate(&self.peer.x25519_public_key())?;
        let mlkem_public_key = MlKemPublicKey::from_bytes(self.peer.mlkem_public_key().as_bytes())
            .map_err(CoreError::Crypto)?;
        let (mlkem_ciphertext, pq_shared_secret) =
            backend.mlkem768_encapsulate(&mlkem_public_key)?;
        let prk = hybrid_prk(
            backend,
            self.session,
            self.turn,
            receiver_key_id,
            &x25519_ciphertext,
            &mlkem_ciphertext,
            &classical_shared_secret,
            &pq_shared_secret,
        )?;

        let header = WireHeader::new(
            self.session.protocol_version(),
            self.session.cipher_suite(),
            self.session.session_id(),
            self.turn,
            direction,
            message_id,
            receiver_key_id,
            MessageType::Application,
            self.local.package_hash(),
            peer_hash,
            self.local.public_projection().to_wire()?,
        )?;
        let encrypted_header = seal_header(
            backend,
            &prk,
            &header,
            self.session,
            self.turn,
            direction,
            receiver_key_id,
        )?;
        let ciphertext = seal_message(
            backend,
            &prk,
            payload_frame.as_bytes(),
            self.session,
            self.turn,
            direction,
            message_id,
            receiver_key_id,
        )?;
        let envelope = WireEnvelope::new(
            self.peer.mailbox_token().clone(),
            WireBytes::from_bytes(x25519_ciphertext.as_bytes())?,
            WireBytes::from_bytes(mlkem_ciphertext.as_bytes())?,
            WireBytes::from_bytes(&encrypted_header)?,
            WireBytes::from_bytes(&ciphertext)?,
            WireBytes::from_bytes(&[])?,
        )?;

        let next_turn = self.turn.next()?;
        let mut next = self.clone();
        next.turn = next_turn;
        next.used_message_ids.insert(0, message_id);
        Ok(PreparedSend { envelope, next })
    }

    /// Decodes and opens a canonical serialized Envelope.
    pub fn prepare_receive<B: CryptoBackend>(
        &self,
        backend: &mut B,
        encoded: &[u8],
        now: u64,
        next_expiration: u64,
    ) -> Result<PreparedReceive, CoreError> {
        let envelope = decode_envelope(encoded)?;
        let canonical = encode(&envelope)?;
        if canonical.as_bytes() != encoded {
            return Err(CoreError::NonCanonical);
        }
        self.prepare_receive_wire(backend, &envelope, now, next_expiration)
    }

    /// Opens an already canonically decoded Envelope.
    pub fn prepare_receive_wire<B: CryptoBackend>(
        &self,
        backend: &mut B,
        envelope: &WireEnvelope,
        now: u64,
        next_expiration: u64,
    ) -> Result<PreparedReceive, CoreError> {
        if Endpoint::leader(self.turn) != self.endpoint.other() {
            return Err(CoreError::EnvelopeContextMismatch {
                field: "receive turn",
            });
        }
        if envelope.mailbox_token() != self.local.public_projection().mailbox_token() {
            return Err(CoreError::EnvelopeContextMismatch {
                field: "mailbox token",
            });
        }
        if self.local.public_projection().expiration() <= now || next_expiration <= now {
            return Err(CoreError::PackageExpired);
        }

        let receiver_key_id = self.local.public_projection().key_id();
        let direction = self.endpoint.other().direction();
        let x25519_ciphertext =
            X25519PublicKey::from_bytes(envelope.x25519_kem_ciphertext().as_bytes())
                .map_err(CoreError::Type)?;
        let mlkem_ciphertext = MlKemCiphertext::from_bytes(envelope.mlkem_ciphertext().as_bytes())
            .map_err(CoreError::Type)?;
        let classical_shared_secret =
            backend.x25519_decapsulate(self.local.x25519_secret(), &x25519_ciphertext)?;
        let pq_shared_secret =
            backend.mlkem768_decapsulate(self.local.mlkem_secret(), &mlkem_ciphertext)?;
        let prk = hybrid_prk(
            backend,
            self.session,
            self.turn,
            receiver_key_id,
            &x25519_ciphertext,
            &mlkem_ciphertext,
            &classical_shared_secret,
            &pq_shared_secret,
        )?;

        let header_plaintext = open_header(
            backend,
            &prk,
            envelope.encrypted_header().as_bytes(),
            self.session,
            self.turn,
            direction,
            receiver_key_id,
        )?;
        let header = decode_header(&header_plaintext)?;
        validate_header_context(
            &header,
            self.session,
            self.turn,
            direction,
            receiver_key_id,
            self.local.package_hash(),
        )?;
        if self.used_message_ids.contains(&header.message_id()) {
            return Err(CoreError::EnvelopeContextMismatch {
                field: "message_id already used",
            });
        }

        let returned_package = PublicReceiverPackage::from_wire(header.return_receiver_package())?;
        let returned_hash =
            verify_receiver_package_auth(backend, &returned_package, &self.peer_identity)?;
        if returned_hash != header.sender_package_hash() {
            return Err(CoreError::PackageChainMismatch);
        }
        validate_return_package(
            backend,
            &returned_package,
            &self.peer,
            self.session,
            self.turn,
            now,
        )?;

        let plaintext_frame = open_message(
            backend,
            &prk,
            envelope.ciphertext().as_bytes(),
            self.session,
            self.turn,
            direction,
            header.message_id(),
            receiver_key_id,
        )?;
        let plaintext = decode_payload_frame(&plaintext_frame)?;

        let next_turn = self.turn.next()?;
        let next_generation = self
            .local
            .public_projection()
            .generation()
            .next()
            .map_err(CoreError::Type)?;
        let next_local = ReceiverPackageFactory::generate(
            backend,
            self.session,
            &self.local_identity,
            next_turn,
            next_generation,
            next_expiration,
            self.local.package_hash(),
        )?;
        let mut next = self.clone();
        next.turn = next_turn;
        next.local = next_local;
        next.peer = returned_package;
        next.used_message_ids.insert(0, header.message_id());
        Ok(PreparedReceive {
            message_id: header.message_id(),
            plaintext,
            next,
        })
    }
}

impl PreparedSend {
    pub fn envelope(&self) -> &WireEnvelope {
        &self.envelope
    }

    /// Commits the prepared send-side turn update.
    pub fn commit(self) -> EndpointKernel {
        self.next
    }
}

impl PreparedReceive {
    pub const fn message_id(&self) -> MessageId {
        self.message_id
    }

    pub fn plaintext(&self) -> &WireBytes {
        &self.plaintext
    }

    pub fn returned_receiver_package(&self) -> &PublicReceiverPackage {
        &self.next.peer
    }

    /// Commits the local package rotation and peer package update.
    pub fn commit(self) -> EndpointKernel {
        self.next
    }
}

fn validate_package_context(
    session: Session,
    package: &PublicReceiverPackage,
) -> Result<(), CoreError> {
    if package.protocol_version() != session.protocol_version()
        || package.cipher_suite() != session.cipher_suite()
        || package.session_id() != session.session_id()
    {
        return Err(CoreError::PackageContextMismatch);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn hybrid_prk<B: CryptoBackend>(
    backend: &B,
    session: Session,
    turn: Turn,
    receiver_key_id: KeyId,
    x25519_ciphertext: &X25519PublicKey,
    mlkem_ciphertext: &MlKemCiphertext,
    classical_shared_secret: &SharedSecret,
    pq_shared_secret: &SharedSecret,
) -> Result<SharedSecret, CoreError> {
    let input = domain::hybrid_info(
        session.protocol_version(),
        session.cipher_suite(),
        session.session_id(),
        turn,
        receiver_key_id,
        x25519_ciphertext.as_bytes(),
        mlkem_ciphertext.as_bytes(),
        classical_shared_secret.as_bytes(),
        pq_shared_secret.as_bytes(),
    )?;
    Ok(backend.hkdf_extract(domain::HYBRID, input.as_bytes())?)
}

fn seal_header<B: CryptoBackend>(
    backend: &B,
    prk: &SharedSecret,
    header: &WireHeader,
    session: Session,
    turn: Turn,
    direction: Direction,
    receiver_key_id: KeyId,
) -> Result<Vec<u8>, CoreError> {
    let key_info = domain::header_info(
        session.protocol_version(),
        session.cipher_suite(),
        session.session_id(),
        turn,
        direction,
        receiver_key_id,
    )?;
    let key = backend.derive_message_key(prk, domain::HEADER, key_info.as_bytes())?;
    let nonce_info = domain::header_nonce_info(
        session.protocol_version(),
        session.cipher_suite(),
        session.session_id(),
        turn,
        direction,
        receiver_key_id,
    )?;
    let nonce = backend.derive_nonce(prk, domain::HEADER_NONCE, nonce_info.as_bytes())?;
    let aad = domain::header_aad(
        session.protocol_version(),
        session.cipher_suite(),
        session.session_id(),
        turn,
        direction,
        receiver_key_id,
    )?;
    Ok(backend.seal(&key, &nonce, aad.as_bytes(), header.encode()?.as_bytes())?)
}

fn open_header<B: CryptoBackend>(
    backend: &B,
    prk: &SharedSecret,
    ciphertext: &[u8],
    session: Session,
    turn: Turn,
    direction: Direction,
    receiver_key_id: KeyId,
) -> Result<Vec<u8>, CoreError> {
    let key_info = domain::header_info(
        session.protocol_version(),
        session.cipher_suite(),
        session.session_id(),
        turn,
        direction,
        receiver_key_id,
    )?;
    let key = backend.derive_message_key(prk, domain::HEADER, key_info.as_bytes())?;
    let nonce_info = domain::header_nonce_info(
        session.protocol_version(),
        session.cipher_suite(),
        session.session_id(),
        turn,
        direction,
        receiver_key_id,
    )?;
    let nonce = backend.derive_nonce(prk, domain::HEADER_NONCE, nonce_info.as_bytes())?;
    let aad = domain::header_aad(
        session.protocol_version(),
        session.cipher_suite(),
        session.session_id(),
        turn,
        direction,
        receiver_key_id,
    )?;
    Ok(backend.open(&key, &nonce, aad.as_bytes(), ciphertext)?)
}

#[allow(clippy::too_many_arguments)]
fn seal_message<B: CryptoBackend>(
    backend: &B,
    prk: &SharedSecret,
    payload_frame: &[u8],
    session: Session,
    turn: Turn,
    direction: Direction,
    message_id: MessageId,
    receiver_key_id: KeyId,
) -> Result<Vec<u8>, CoreError> {
    let key_info = domain::message_info(
        session.protocol_version(),
        session.cipher_suite(),
        session.session_id(),
        turn,
        direction,
        message_id,
        receiver_key_id,
    )?;
    let key = backend.derive_message_key(prk, domain::MESSAGE, key_info.as_bytes())?;
    let nonce_prk = backend.hkdf_extract(b"", key.as_bytes())?;
    let nonce_info = domain::nonce_info(
        session.session_id(),
        turn,
        direction,
        message_id,
        receiver_key_id,
    )?;
    let nonce = backend.derive_nonce(&nonce_prk, domain::NONCE, nonce_info.as_bytes())?;
    let aad = domain::message_aad(
        session.protocol_version(),
        session.cipher_suite(),
        session.session_id(),
        turn,
        direction,
        message_id,
        receiver_key_id,
    )?;
    Ok(backend.seal(&key, &nonce, aad.as_bytes(), payload_frame)?)
}

#[allow(clippy::too_many_arguments)]
fn open_message<B: CryptoBackend>(
    backend: &B,
    prk: &SharedSecret,
    ciphertext: &[u8],
    session: Session,
    turn: Turn,
    direction: Direction,
    message_id: MessageId,
    receiver_key_id: KeyId,
) -> Result<Vec<u8>, CoreError> {
    let key_info = domain::message_info(
        session.protocol_version(),
        session.cipher_suite(),
        session.session_id(),
        turn,
        direction,
        message_id,
        receiver_key_id,
    )?;
    let key = backend.derive_message_key(prk, domain::MESSAGE, key_info.as_bytes())?;
    let nonce_prk = backend.hkdf_extract(b"", key.as_bytes())?;
    let nonce_info = domain::nonce_info(
        session.session_id(),
        turn,
        direction,
        message_id,
        receiver_key_id,
    )?;
    let nonce = backend.derive_nonce(&nonce_prk, domain::NONCE, nonce_info.as_bytes())?;
    let aad = domain::message_aad(
        session.protocol_version(),
        session.cipher_suite(),
        session.session_id(),
        turn,
        direction,
        message_id,
        receiver_key_id,
    )?;
    Ok(backend.open(&key, &nonce, aad.as_bytes(), ciphertext)?)
}

fn validate_header_context(
    header: &WireHeader,
    session: Session,
    turn: Turn,
    direction: Direction,
    receiver_key_id: KeyId,
    receiver_package_hash: linkchat_types::PackageHash,
) -> Result<(), CoreError> {
    if header.protocol_version() != session.protocol_version()
        || header.cipher_suite() != session.cipher_suite()
        || header.session_id() != session.session_id()
        || header.turn() != turn
        || header.direction() != direction
        || header.receiver_key_id() != receiver_key_id
    {
        return Err(CoreError::EnvelopeContextMismatch {
            field: "header context",
        });
    }
    if header.message_type() != MessageType::Application {
        return Err(CoreError::EnvelopeContextMismatch {
            field: "message type",
        });
    }
    if header.receiver_package_hash() != receiver_package_hash {
        return Err(CoreError::EnvelopeContextMismatch {
            field: "receiver package hash",
        });
    }
    Ok(())
}

fn validate_return_package<B: CryptoBackend>(
    backend: &B,
    returned: &PublicReceiverPackage,
    current_peer: &PublicReceiverPackage,
    session: Session,
    turn: Turn,
    now: u64,
) -> Result<(), CoreError> {
    validate_package_context(session, returned)?;
    if returned.turn() != turn || returned.expiration() <= now {
        return Err(CoreError::PackageTurnMismatch);
    }
    let current_hash = crate::receiver_package_hash(backend, current_peer)?;
    let returned_hash = crate::receiver_package_hash(backend, returned)?;
    if turn.get() == 0 {
        if returned_hash != current_hash {
            return Err(CoreError::PackageChainMismatch);
        }
        return Ok(());
    }
    let expected_generation = current_peer.generation().next().map_err(CoreError::Type)?;
    if returned.generation() != expected_generation
        || returned.previous_package_hash() != current_hash
    {
        return Err(CoreError::PackageChainMismatch);
    }
    if returned_hash == current_hash {
        return Err(CoreError::PackageChainMismatch);
    }
    Ok(())
}
