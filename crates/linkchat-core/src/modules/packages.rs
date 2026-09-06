/// Public Receiver Package data.  No private receiver secret is represented.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicReceiverPackage {
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    session_id: SessionId,
    turn: Turn,
    generation: PackageGeneration,
    key_id: KeyId,
    x25519_public_key: X25519PublicKey,
    mlkem_public_key: WireBytes,
    mailbox_token: MailboxToken,
    expiration: u64,
    previous_package_hash: PackageHash,
    package_auth: WireBytes,
}

impl PublicReceiverPackage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        session_id: SessionId,
        turn: Turn,
        generation: PackageGeneration,
        key_id: KeyId,
        x25519_public_key: X25519PublicKey,
        mlkem_public_key: WireBytes,
        mailbox_token: MailboxToken,
        expiration: u64,
        previous_package_hash: PackageHash,
        package_auth: WireBytes,
    ) -> Result<Self, CoreError> {
        if mlkem_public_key.len() != ML_KEM_768_PUBLIC_KEY_LEN {
            return Err(CoreError::InvalidPublicPackage {
                field: "mlkem_public_key",
            });
        }
        if package_auth.len() != linkchat_protocol::ED25519_SIGNATURE_LEN {
            return Err(CoreError::InvalidPublicPackage {
                field: "package_auth",
            });
        }
        Ok(Self {
            protocol_version,
            cipher_suite,
            session_id,
            turn,
            generation,
            key_id,
            x25519_public_key,
            mlkem_public_key,
            mailbox_token,
            expiration,
            previous_package_hash,
            package_auth,
        })
    }

    /// Converts an already decoded public wire package into the core type.
    pub fn from_wire(package: &WireReceiverPackage) -> Result<Self, CoreError> {
        Self::new(
            package.protocol_version(),
            package.cipher_suite(),
            package.session_id(),
            package.turn(),
            package.generation(),
            package.key_id(),
            package.x25519_public_key(),
            package.mlkem_public_key().clone(),
            package.mailbox_token().clone(),
            package.expiration(),
            package.previous_package_hash(),
            package.package_auth().clone(),
        )
    }

    /// Converts the public projection to its canonical wire representation.
    pub fn to_wire(&self) -> Result<WireReceiverPackage, CoreError> {
        WireReceiverPackage::new(
            self.protocol_version,
            self.cipher_suite,
            self.session_id,
            self.turn,
            self.generation,
            self.key_id,
            self.x25519_public_key,
            self.mlkem_public_key.clone(),
            self.mailbox_token.clone(),
            self.expiration,
            self.previous_package_hash,
            self.package_auth.clone(),
        )
        .map_err(CoreError::Wire)
    }

    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    pub const fn cipher_suite(&self) -> CipherSuite {
        self.cipher_suite
    }

    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub const fn turn(&self) -> Turn {
        self.turn
    }

    pub const fn generation(&self) -> PackageGeneration {
        self.generation
    }

    pub const fn key_id(&self) -> KeyId {
        self.key_id
    }

    pub const fn x25519_public_key(&self) -> X25519PublicKey {
        self.x25519_public_key
    }

    pub fn mlkem_public_key(&self) -> &WireBytes {
        &self.mlkem_public_key
    }

    pub fn mailbox_token(&self) -> &MailboxToken {
        &self.mailbox_token
    }

    pub const fn expiration(&self) -> u64 {
        self.expiration
    }

    pub const fn previous_package_hash(&self) -> PackageHash {
        self.previous_package_hash
    }

    pub fn package_auth(&self) -> &WireBytes {
        &self.package_auth
    }
}

/// Private Receiver Package and its public projection as one atomic value.
///
/// The private key pairs and their verified public projection are stored
/// together. There is no production constructor accepting unrelated secret
/// and public package values.
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateReceiverPackage {
    x25519: X25519KeyPair,
    mlkem: MlKemKeyPair,
    verified_public: VerifiedReceiverPackage,
}

/// A public Receiver Package after cryptographic and chain verification.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedReceiverPackage {
    public: PublicReceiverPackage,
    package_hash: PackageHash,
}

impl VerifiedReceiverPackage {
    pub fn public_package(&self) -> &PublicReceiverPackage {
        &self.public
    }

    pub const fn package_hash(&self) -> PackageHash {
        self.package_hash
    }
}

/// Compatibility name for the production private package.
pub type ProductionPrivateReceiverPackage = PrivateReceiverPackage;

impl PrivateReceiverPackage {
    pub fn public_package(&self) -> &PublicReceiverPackage {
        self.verified_public.public_package()
    }

    pub const fn package_hash(&self) -> PackageHash {
        self.verified_public.package_hash
    }

    #[allow(dead_code)]
    pub(crate) fn x25519_secret(&self) -> &linkchat_crypto::X25519SecretKey {
        &self.x25519.secret_key
    }

    #[allow(dead_code)]
    pub(crate) fn mlkem_secret(&self) -> &linkchat_crypto::MlKemSecretKey {
        &self.mlkem.secret_key
    }

    pub(crate) fn storage_secret_material(&self) -> (&[u8], &[u8]) {
        (
            self.x25519.secret_key.as_bytes(),
            self.mlkem.secret_key.as_bytes(),
        )
    }

    pub(crate) fn from_storage_secret_material(
        x25519_secret: &[u8],
        mlkem_secret: &[u8],
        public: PublicReceiverPackage,
    ) -> Result<Self, CoreError> {
        let x25519_secret = linkchat_crypto::X25519SecretKey::from_bytes(x25519_secret)?;
        let mlkem_secret = linkchat_crypto::MlKemSecretKey::from_bytes(mlkem_secret)?;
        let x25519 = X25519KeyPair {
            public_key: linkchat_crypto::x25519_public_from_secret(&x25519_secret)?,
            secret_key: x25519_secret,
        };
        let mlkem = MlKemKeyPair {
            public_key: linkchat_crypto::mlkem768_public_from_secret(&mlkem_secret)?,
            secret_key: mlkem_secret,
        };
        Self::from_keypairs(x25519, mlkem, public)
    }

    /// Constructs a package only when both private key pairs match the
    /// corresponding public keys in the package projection.
    pub fn from_keypairs(
        x25519: X25519KeyPair,
        mlkem: MlKemKeyPair,
        public: PublicReceiverPackage,
    ) -> Result<Self, CoreError> {
        let expected_mlkem =
            <[u8; ML_KEM_768_PUBLIC_KEY_LEN]>::try_from(public.mlkem_public_key().as_bytes())
                .map_err(|_| CoreError::InvalidPublicPackage {
                    field: "mlkem_public_key",
                })?;
        if x25519.public_key != public.x25519_public_key()
            || mlkem.public_key.into_array() != expected_mlkem
        {
            return Err(CoreError::PrivatePublicKeyMismatch);
        }
        let package_hash = package_hash_for_public(&OsCryptoBackend::new(), &public)?;
        Ok(Self {
            x25519,
            mlkem,
            verified_public: VerifiedReceiverPackage {
                public,
                package_hash,
            },
        })
    }

    /// Test-only construction for Lean-model fixtures. It still stores real
    /// key pairs and rewrites only the public key fields to their matching
    /// projections; arbitrary secret/public pairing is unavailable in builds
    /// without the `test-support` feature.
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_testing(public: PublicReceiverPackage) -> Result<Self, CoreError> {
        let mut backend = OsCryptoBackend::new();
        let x25519 = backend.generate_x25519_keypair()?;
        let mlkem = backend.generate_mlkem768_keypair()?;
        let public = PublicReceiverPackage::new(
            public.protocol_version(),
            public.cipher_suite(),
            public.session_id(),
            public.turn(),
            public.generation(),
            public.key_id(),
            x25519.public_key,
            WireBytes::from_bytes(mlkem.public_key.as_bytes())?,
            public.mailbox_token().clone(),
            public.expiration(),
            public.previous_package_hash(),
            public.package_auth().clone(),
        )?;
        let package_hash = package_hash_for_public(&backend, &public)?;
        Ok(Self {
            x25519,
            mlkem,
            verified_public: VerifiedReceiverPackage {
                public,
                package_hash,
            },
        })
    }
}

/// Local-only factory for atomically creating a fresh Receiver Package.
pub struct ReceiverPackageFactory;

impl ReceiverPackageFactory {
    #[allow(clippy::too_many_arguments)]
    pub fn generate<B: CryptoBackend>(
        backend: &mut B,
        session: Session,
        identity_secret: &Ed25519SecretKey,
        turn: Turn,
        generation: PackageGeneration,
        expiration: u64,
        previous_package_hash: PackageHash,
    ) -> Result<ProductionPrivateReceiverPackage, CoreError> {
        let x25519 = backend.generate_x25519_keypair()?;
        let mlkem = backend.generate_mlkem768_keypair()?;
        let random = backend.random_bytes(linkchat_types::MAILBOX_TOKEN_LEN + 8)?;
        let mailbox_token = MailboxToken::from_bytes(&random[..linkchat_types::MAILBOX_TOKEN_LEN])?;
        let key_id = KeyId::new(u64::from_be_bytes(
            random[linkchat_types::MAILBOX_TOKEN_LEN..]
                .try_into()
                .map_err(|_| CoreError::Crypto(CryptoError::RandomnessUnavailable))?,
        ));
        let public_without_auth = PublicReceiverPackage::new(
            session.protocol_version(),
            session.cipher_suite(),
            session.session_id(),
            turn,
            generation,
            key_id,
            x25519.public_key,
            WireBytes::from_bytes(mlkem.public_key.as_bytes())?,
            mailbox_token.clone(),
            expiration,
            previous_package_hash,
            WireBytes::from_bytes(&[0; linkchat_protocol::ED25519_SIGNATURE_LEN])?,
        )?;
        let body = public_without_auth.to_wire()?.encode_package_body()?;
        let package_hash = package_hash_for_body(backend, body.as_bytes())?;
        let signature = sign_package_body(backend, identity_secret, body.as_bytes())?;
        let public = PublicReceiverPackage::new(
            session.protocol_version(),
            session.cipher_suite(),
            session.session_id(),
            turn,
            generation,
            key_id,
            x25519.public_key,
            WireBytes::from_bytes(mlkem.public_key.as_bytes())?,
            mailbox_token,
            expiration,
            previous_package_hash,
            WireBytes::from_bytes(signature.as_bytes())?,
        )?;
        Ok(ProductionPrivateReceiverPackage {
            x25519,
            mlkem,
            verified_public: VerifiedReceiverPackage {
                public,
                package_hash,
            },
        })
    }
}

/// Verifies a peer package against the pinned identity, session and chain.
#[allow(clippy::too_many_arguments)]
pub fn verify_receiver_package<B: CryptoBackend>(
    backend: &B,
    package: &PublicReceiverPackage,
    session: Session,
    owner_identity: &Ed25519PublicKey,
    expected_turn: Turn,
    expected_generation: PackageGeneration,
    expected_previous_hash: PackageHash,
    now: u64,
) -> Result<VerifiedReceiverPackage, CoreError> {
    if package.protocol_version() != session.protocol_version()
        || package.cipher_suite() != session.cipher_suite()
        || package.session_id() != session.session_id()
    {
        return Err(CoreError::PackageContextMismatch);
    }
    if package.turn() != expected_turn {
        return Err(CoreError::PackageTurnMismatch);
    }
    if package.generation() != expected_generation {
        return Err(CoreError::PackageGenerationMismatch);
    }
    if package.previous_package_hash() != expected_previous_hash {
        return Err(CoreError::PackageChainMismatch);
    }
    if package.expiration() <= now {
        return Err(CoreError::PackageExpired);
    }
    let package_hash = verify_receiver_package_auth(backend, package, owner_identity)?;
    Ok(VerifiedReceiverPackage {
        public: package.clone(),
        package_hash,
    })
}

/// Verifies the canonical package hash and identity signature without
/// imposing a turn or package-chain expectation.  Endpoint receive logic
/// applies those stateful expectations after this cryptographic check.
pub fn verify_receiver_package_auth<B: CryptoBackend>(
    backend: &B,
    package: &PublicReceiverPackage,
    owner_identity: &Ed25519PublicKey,
) -> Result<PackageHash, CoreError> {
    let wire = package.to_wire()?;
    let body = wire.encode_package_body()?;
    let package_hash = package_hash_for_body(backend, body.as_bytes())?;
    let auth = Ed25519Signature::from_bytes(package.package_auth().as_bytes())?;
    let auth_message = domain_input(domain::RECEIVER_PACKAGE_AUTH, body.as_bytes())?;
    if !backend.ed25519_verify(owner_identity, auth_message.as_bytes(), &auth)? {
        return Err(CoreError::PackageAuthenticationInvalid);
    }
    Ok(package_hash)
}

fn package_hash_for_body<B: CryptoBackend>(
    backend: &B,
    body: &[u8],
) -> Result<PackageHash, CoreError> {
    let input = domain_input(domain::PACKAGE_HASH, body)?;
    Ok(backend.sha256(input.as_bytes()))
}

fn package_hash_for_public<B: CryptoBackend>(
    backend: &B,
    package: &PublicReceiverPackage,
) -> Result<PackageHash, CoreError> {
    let body = package.to_wire()?.encode_package_body()?;
    package_hash_for_body(backend, body.as_bytes())
}

/// Computes the protocol package hash over the canonical PackageBody.
pub fn receiver_package_hash<B: CryptoBackend>(
    backend: &B,
    package: &PublicReceiverPackage,
) -> Result<PackageHash, CoreError> {
    package_hash_for_public(backend, package)
}

/// Computes the bootstrap root for one endpoint's package chain.
pub fn package_chain_root<B: CryptoBackend>(
    backend: &B,
    session: Session,
    alice_identity: &Ed25519PublicKey,
    bob_identity: &Ed25519PublicKey,
    owner: crate::Endpoint,
) -> Result<PackageHash, CoreError> {
    let context = domain::package_chain_root_info(
        session.protocol_version(),
        session.cipher_suite(),
        session.session_id(),
        alice_identity.as_bytes(),
        bob_identity.as_bytes(),
        owner.direction(),
    )?;
    Ok(backend.sha256(context.as_bytes()))
}

fn sign_package_body<B: CryptoBackend>(
    backend: &B,
    identity_secret: &Ed25519SecretKey,
    body: &[u8],
) -> Result<Ed25519Signature, CoreError> {
    let input = domain_input(domain::RECEIVER_PACKAGE_AUTH, body)?;
    Ok(backend.ed25519_sign(identity_secret, input.as_bytes())?)
}

impl PrivateReceiverPackage {
    pub fn public_projection(&self) -> &PublicReceiverPackage {
        self.verified_public.public_package()
    }

    pub fn into_public_projection(self) -> PublicReceiverPackage {
        self.verified_public.public
    }

    pub fn secret_len(&self) -> usize {
        self.x25519.secret_key.as_bytes().len() + self.mlkem.secret_key.as_bytes().len()
    }
}
use crate::{CoreError, Session};
use linkchat_crypto::{
    CryptoBackend, CryptoError, Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature, MlKemKeyPair,
    OsCryptoBackend, X25519KeyPair,
};
use linkchat_protocol::{
    ML_KEM_768_PUBLIC_KEY_LEN, WireBytes, WireReceiverPackage, domain, domain_input,
};
use linkchat_types::{
    CipherSuite, KeyId, MailboxToken, PackageGeneration, PackageHash, ProtocolVersion, SessionId,
    Turn, X25519PublicKey,
};
