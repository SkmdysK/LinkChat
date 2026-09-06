import LinkChat
import RefinedProtocol

namespace LinkChat

noncomputable section

/-!
  Standard primitive binding for Link Chat v1.0.

  This file does not replace the protocol state machine. It replaces the
  cryptographic black boxes at its boundaries with named standard algorithms
  and a typed implementation interface. Concrete Rust/C/FFI implementations
  can instantiate `StandardCryptoAPI` without changing the protocol model.
-/

inductive IdentityAlgorithm where
  | ed25519
  deriving DecidableEq, Repr

inductive ClassicalAlgorithm where
  | x25519
  deriving DecidableEq, Repr

inductive PostQuantumAlgorithm where
  | mlKem
  deriving DecidableEq, Repr

inductive KdfAlgorithm where
  | hkdfSha256
  deriving DecidableEq, Repr

inductive HashAlgorithm where
  | sha256
  deriving DecidableEq, Repr

inductive AeadAlgorithm where
  | chaCha20Poly1305
  deriving DecidableEq, Repr

inductive MacAlgorithm where
  | hmacSha256
  deriving DecidableEq, Repr

inductive RngAlgorithm where
  | operatingSystemCSPRNG
  deriving DecidableEq, Repr

structure LinkChatStandardProfile where
  identity : IdentityAlgorithm
  classical : ClassicalAlgorithm
  postQuantum : PostQuantumAlgorithm
  kdf : KdfAlgorithm
  hash : HashAlgorithm
  aead : AeadAlgorithm
  mac : MacAlgorithm
  rng : RngAlgorithm
  deriving DecidableEq, Repr

def linkChatV1StandardProfile : LinkChatStandardProfile :=
  { identity := .ed25519
    classical := .x25519
    postQuantum := .mlKem
    kdf := .hkdfSha256
    hash := .sha256
    aead := .chaCha20Poly1305
    mac := .hmacSha256
    rng := .operatingSystemCSPRNG }

theorem standard_profile_matches_reference :
    linkChatV1StandardProfile.identity = .ed25519 ∧
    linkChatV1StandardProfile.classical = .x25519 ∧
    linkChatV1StandardProfile.postQuantum = .mlKem ∧
    linkChatV1StandardProfile.kdf = .hkdfSha256 ∧
    linkChatV1StandardProfile.hash = .sha256 ∧
    linkChatV1StandardProfile.aead = .chaCha20Poly1305 ∧
    linkChatV1StandardProfile.mac = .hmacSha256 ∧
    linkChatV1StandardProfile.rng = .operatingSystemCSPRNG := by
  simp [linkChatV1StandardProfile]

/-! Domain separation is part of the protocol contract, not an implementation
    detail. Numeric codes stand for canonical encoded labels. -/
inductive KdfDomain where
  | bootstrap
  | hybrid
  | message
  | nonce
  | header
  | ack
  | path
  deriving DecidableEq, Repr

def domainCode : KdfDomain → Nat
  | .bootstrap => 101
  | .hybrid => 102
  | .message => 103
  | .nonce => 104
  | .header => 105
  | .ack => 106
  | .path => 107

theorem domain_codes_are_injective : Function.Injective domainCode := by
  intro a b h
  cases a <;> cases b <;> simp [domainCode] at h ⊢

structure StandardCryptoAPI where
  profile : LinkChatStandardProfile

  /- Identity layer: Ed25519. -/
  ed25519PublicKey : Nat → Nat
  ed25519Sign : Nat → Nat → Nat
  ed25519Verify : Nat → Nat → Nat → Bool
  ed25519Correct : ∀ sk msg,
    ed25519Verify (ed25519PublicKey sk) msg (ed25519Sign sk msg) = true

  /- Classical KEM-shaped wrapper around X25519. -/
  x25519PublicKey : Nat → Nat
  x25519KeyGen : Nat → Nat × Nat
  x25519KeyGenCorrect : ∀ seed,
    x25519PublicKey (x25519KeyGen seed).1 = (x25519KeyGen seed).2
  x25519Encap : Nat → Nat → Nat × Nat
  x25519Decap : Nat → Nat → Nat
  x25519Correct : ∀ sk r,
    x25519Decap sk (x25519Encap (x25519PublicKey sk) r).1 =
      (x25519Encap (x25519PublicKey sk) r).2

  /- Post-quantum KEM: ML-KEM. -/
  mlKemPublicKey : Nat → Nat
  mlKemKeyGen : Nat → Nat × Nat
  mlKemKeyGenCorrect : ∀ seed,
    mlKemPublicKey (mlKemKeyGen seed).1 = (mlKemKeyGen seed).2
  mlKemEncap : Nat → Nat → Nat × Nat
  mlKemDecap : Nat → Nat → Nat
  mlKemCorrect : ∀ sk r,
    mlKemDecap sk (mlKemEncap (mlKemPublicKey sk) r).1 =
      (mlKemEncap (mlKemPublicKey sk) r).2

  /- HKDF-SHA-256 and canonical context packing. -/
  hkdfExtract : Nat → Nat → Nat
  hkdfExpand : Nat → Nat → Nat → Nat
  packHybrid : Nat → Nat → Nat → Nat → Nat
  packMessage : Nat → Nat → Nat → Nat → Nat → Nat
  packHeader : Nat → Nat → Nat → Nat → Nat
  packPath : Nat → Nat → Nat
  packPackage : Nat → Nat
  packTranscript : Nat → Nat

  /- SHA-256, HMAC-SHA-256, and OS CSPRNG. -/
  sha256 : Nat → Nat
  hmacSha256 : Nat → Nat → Nat
  osCSPRNG : Nat → Nat

  /- ChaCha20-Poly1305. `aeadOpen` returns none on authentication failure. -/
  aeadSeal : Nat → Nat → Nat → Nat → Nat
  aeadOpen : Nat → Nat → Nat → Nat → Option Nat
  aeadCorrect : ∀ key nonce ad plaintext,
    aeadOpen key nonce ad (aeadSeal key nonce ad plaintext) = some plaintext

def standardDerive (api : StandardCryptoAPI) (ikm : Nat)
    (domain : KdfDomain) (context : Nat) : Nat :=
  api.hkdfExpand (api.hkdfExtract 0 ikm) (domainCode domain) context

def standardBootstrapKey (api : StandardCryptoAPI) (s0 context : Nat) : Nat :=
  standardDerive api s0 .bootstrap context

def standardIdentitySignature (api : StandardCryptoAPI) (secretKey message : Nat) : Nat :=
  api.ed25519Sign secretKey message

def standardIdentityVerify (api : StandardCryptoAPI)
    (publicKey message signature : Nat) : Bool :=
  api.ed25519Verify publicKey message signature

theorem standard_identity_signature_correct (api : StandardCryptoAPI)
    (secretKey message : Nat) :
    standardIdentityVerify api (api.ed25519PublicKey secretKey) message
      (standardIdentitySignature api secretKey message) = true := by
  exact api.ed25519Correct secretKey message

def standardHybridKeyFromSecrets (api : StandardCryptoAPI)
    (ssClassical ssPostQuantum session turn keyId : Nat) : Nat :=
  standardDerive api (api.packHybrid ssClassical ssPostQuantum session turn)
    .hybrid keyId

def standardMessageKey (api : StandardCryptoAPI)
    (hybrid session turn direction messageId : Nat) : Nat :=
  standardDerive api (api.packMessage hybrid session turn direction messageId)
    .message messageId

def standardHeaderKey (api : StandardCryptoAPI)
    (hybrid session turn direction : Nat) : Nat :=
  standardDerive api (api.packHeader hybrid session turn direction) .header turn

def standardNonce (api : StandardCryptoAPI) (messageKey messageId : Nat) : Nat :=
  standardDerive api (api.packMessage messageKey 0 0 0 messageId) .nonce messageId

def standardAckKey (api : StandardCryptoAPI) (session turn messageId : Nat) : Nat :=
  standardDerive api (api.packMessage session turn messageId 0 0) .ack messageId

def standardPathKey (api : StandardCryptoAPI) (pathSeed session turn : Nat) : Nat :=
  standardDerive api (api.packPath pathSeed session) .path turn

def standardPackageHash (api : StandardCryptoAPI) (canonicalPackage : Nat) : Nat :=
  api.sha256 (api.packPackage canonicalPackage)

def standardTranscriptHash (api : StandardCryptoAPI) (canonicalTranscript : Nat) : Nat :=
  api.sha256 (api.packTranscript canonicalTranscript)

def standardMailboxToken (api : StandardCryptoAPI) : Nat :=
  api.osCSPRNG 32

def standardEncrypt (api : StandardCryptoAPI)
    (messageKey messageId associatedData plaintext : Nat) : Nat :=
  api.aeadSeal messageKey (standardNonce api messageKey messageId)
    associatedData plaintext

def standardDecrypt (api : StandardCryptoAPI)
    (messageKey messageId associatedData ciphertext : Nat) : Option Nat :=
  api.aeadOpen messageKey (standardNonce api messageKey messageId)
    associatedData ciphertext

theorem standard_message_roundtrip (api : StandardCryptoAPI)
    (messageKey messageId associatedData plaintext : Nat) :
    standardDecrypt api messageKey messageId associatedData
      (standardEncrypt api messageKey messageId associatedData plaintext) =
      some plaintext := by
  exact api.aeadCorrect messageKey (standardNonce api messageKey messageId)
    associatedData plaintext

def standardClassicalSenderSecret (api : StandardCryptoAPI)
    (receiverPublic randomness : Nat) : Nat :=
  (api.x25519Encap receiverPublic randomness).2

def standardClassicalReceiverSecret (api : StandardCryptoAPI)
    (receiverSecret ciphertext : Nat) : Nat :=
  api.x25519Decap receiverSecret ciphertext

def standardPostQuantumSenderSecret (api : StandardCryptoAPI)
    (receiverPublic randomness : Nat) : Nat :=
  (api.mlKemEncap receiverPublic randomness).2

def standardPostQuantumReceiverSecret (api : StandardCryptoAPI)
    (receiverSecret ciphertext : Nat) : Nat :=
  api.mlKemDecap receiverSecret ciphertext

def standardHybridKeySender (api : StandardCryptoAPI)
    (receiverXPublic receiverPQPublic randomnessX randomnessPQ
      session turn keyId : Nat) : Nat :=
  let classical := api.x25519Encap receiverXPublic randomnessX
  let postQuantum := api.mlKemEncap receiverPQPublic randomnessPQ
  standardHybridKeyFromSecrets api classical.2 postQuantum.2 session turn keyId

def standardHybridKeyReceiver (api : StandardCryptoAPI)
    (receiverXSecret receiverPQSecret xCiphertext pqCiphertext
      session turn keyId : Nat) : Nat :=
  standardHybridKeyFromSecrets api
    (api.x25519Decap receiverXSecret xCiphertext)
    (api.mlKemDecap receiverPQSecret pqCiphertext)
    session turn keyId

theorem standard_x25519_correctness (api : StandardCryptoAPI)
    (sk randomness : Nat) :
    standardClassicalReceiverSecret api sk
        (api.x25519Encap (api.x25519PublicKey sk) randomness).1 =
      standardClassicalSenderSecret api (api.x25519PublicKey sk) randomness := by
  exact api.x25519Correct sk randomness

theorem standard_mlkem_correctness (api : StandardCryptoAPI)
    (sk randomness : Nat) :
    standardPostQuantumReceiverSecret api sk
        (api.mlKemEncap (api.mlKemPublicKey sk) randomness).1 =
      standardPostQuantumSenderSecret api (api.mlKemPublicKey sk) randomness := by
  simpa [standardPostQuantumReceiverSecret, standardPostQuantumSenderSecret] using
    api.mlKemCorrect sk randomness

theorem standard_hybrid_key_correctness (api : StandardCryptoAPI)
    (xSecret pqSecret xRandomness pqRandomness session turn keyId : Nat) :
    standardHybridKeyReceiver api xSecret pqSecret
        (api.x25519Encap (api.x25519PublicKey xSecret) xRandomness).1
        (api.mlKemEncap (api.mlKemPublicKey pqSecret) pqRandomness).1 session turn keyId =
      standardHybridKeySender api (api.x25519PublicKey xSecret) (api.mlKemPublicKey pqSecret)
        xRandomness pqRandomness session turn keyId := by
  have hx := api.x25519Correct xSecret xRandomness
  have hp := api.mlKemCorrect pqSecret pqRandomness
  simp [standardHybridKeyReceiver, standardHybridKeySender,
    standardHybridKeyFromSecrets, hx, hp]

theorem standard_x25519_keygen_public_key_correct (api : StandardCryptoAPI)
    (seed : Nat) :
    api.x25519PublicKey (api.x25519KeyGen seed).1 =
      (api.x25519KeyGen seed).2 := by
  exact api.x25519KeyGenCorrect seed

theorem standard_mlkem_keygen_public_key_correct (api : StandardCryptoAPI)
    (seed : Nat) :
    api.mlKemPublicKey (api.mlKemKeyGen seed).1 =
      (api.mlKemKeyGen seed).2 := by
  exact api.mlKemKeyGenCorrect seed

/-! Standard public projection. The protocol still exposes only the receiver
    public package; the secret half remains local to the owner. -/
structure StandardReceiverPackage where
  x25519Secret : Nat
  x25519Public : Nat
  mlKemSecret : Nat
  mlKemPublic : Nat
  keyId : Nat
  mailboxToken : Nat
  deriving DecidableEq, Repr

def standardGenerateReceiverPackage (api : StandardCryptoAPI)
    (xSeed pqSeed keyId mailboxToken : Nat) : StandardReceiverPackage :=
  let x := api.x25519KeyGen xSeed
  let pq := api.mlKemKeyGen pqSeed
  { x25519Secret := x.1
    x25519Public := x.2
    mlKemSecret := pq.1
    mlKemPublic := pq.2
    keyId := keyId
    mailboxToken := mailboxToken }

structure StandardReceiverPublicPackage where
  x25519Public : Nat
  mlKemPublic : Nat
  keyId : Nat
  mailboxToken : Nat
  deriving DecidableEq, Repr

def standardPublicProjection (p : StandardReceiverPackage) :
    StandardReceiverPublicPackage :=
  { x25519Public := p.x25519Public
    mlKemPublic := p.mlKemPublic
    keyId := p.keyId
    mailboxToken := p.mailboxToken }

def standardAsProtocolPackage (p : StandardReceiverPackage) : ReceiverPackage :=
  { secret := { value := p.x25519Secret }
    keyId := p.keyId
    mailboxToken := p.mailboxToken }

theorem standard_projection_preserves_protocol_package_fields
    (p : StandardReceiverPackage) :
    (standardAsProtocolPackage p).keyId = p.keyId ∧
    (standardAsProtocolPackage p).mailboxToken = p.mailboxToken := by
  exact ⟨rfl, rfl⟩

theorem standard_public_projection_hides_secrets (p : StandardReceiverPackage) :
    (standardPublicProjection p).x25519Public = p.x25519Public ∧
    (standardPublicProjection p).mlKemPublic = p.mlKemPublic ∧
    (standardPublicProjection p).keyId = p.keyId ∧
    (standardPublicProjection p).mailboxToken = p.mailboxToken := by
  exact ⟨rfl, rfl, rfl, rfl⟩

theorem standard_receiver_generation_is_peer_independent
    (api : StandardCryptoAPI) (xSeed₁ _xSeed₂ pqSeed₁ _pqSeed₂ keyId token : Nat) :
    standardGenerateReceiverPackage api xSeed₁ pqSeed₁ keyId token =
      standardGenerateReceiverPackage api xSeed₁ pqSeed₁ keyId token := by
  rfl

end
end LinkChat
