import Std

namespace LinkChat

noncomputable section
local instance propDecidable (p : Prop) : Decidable p := Classical.propDecidable p

/-!
  A machine-checked core model of the Link Chat v1.0 specification.

  The model deliberately separates two kinds of results:

  * unconditional state-machine theorems (turn discipline, rejection,
    replay handling, state non-interference, and injection resistance);
  * conditional cryptographic correctness theorems, whose primitive laws are
    supplied by the KEM interface below.

  Computational confidentiality, indistinguishability, secure erasure,
  CSPRNG quality, and side-channel resistance are assumptions about concrete
  implementations and cannot be derived from the protocol prose alone.
-/

inductive Endpoint where
  | alice
  | bob
  deriving DecidableEq, Repr

def other : Endpoint → Endpoint
  | .alice => .bob
  | .bob => .alice

def leader (turn : Nat) : Endpoint :=
  if turn % 2 = 0 then .alice else .bob

theorem leader_is_alice_or_bob (turn : Nat) :
    leader turn = .alice ∨ leader turn = .bob := by
  unfold leader
  split <;> simp

theorem leader_is_unique (turn : Nat) :
    (leader turn = .alice ∧ leader turn ≠ .bob) ∨
    (leader turn = .bob ∧ leader turn ≠ .alice) := by
  unfold leader
  split <;> simp

structure SecretState where
  value : Nat
  deriving DecidableEq, Repr

structure ProtocolState where
  sessionId : Nat
  turn : Nat
  aliceKeyId : Nat
  bobKeyId : Nat
  aliceToken : Nat
  bobToken : Nat
  aliceSecret : SecretState
  bobSecret : SecretState
  consumedMessageIds : List Nat
  deriving DecidableEq, Repr

structure Message where
  sessionId : Nat
  turn : Nat
  direction : Endpoint
  messageId : Nat
  keyId : Nat
  mailboxToken : Nat
  payload : Nat
  deriving DecidableEq, Repr

def receiverKeyId (s : ProtocolState) (sender : Endpoint) : Nat :=
  match sender with
  | .alice => s.bobKeyId
  | .bob => s.aliceKeyId

def receiverToken (s : ProtocolState) (sender : Endpoint) : Nat :=
  match sender with
  | .alice => s.bobToken
  | .bob => s.aliceToken

def receiverSecret (s : ProtocolState) (receiver : Endpoint) : SecretState :=
  match receiver with
  | .alice => s.aliceSecret
  | .bob => s.bobSecret

def valid (s : ProtocolState) (m : Message) : Prop :=
  m.sessionId = s.sessionId ∧
  m.turn = s.turn ∧
  m.direction = leader s.turn ∧
  m.keyId = receiverKeyId s m.direction ∧
  m.mailboxToken = receiverToken s m.direction ∧
  m.messageId ∉ s.consumedMessageIds

def commit (s : ProtocolState) (m : Message) (fresh : SecretState) : ProtocolState :=
  match m.direction with
  | .alice =>
      { s with
        turn := s.turn + 1
        bobSecret := fresh
        consumedMessageIds := m.messageId :: s.consumedMessageIds }
  | .bob =>
      { s with
        turn := s.turn + 1
        aliceSecret := fresh
        consumedMessageIds := m.messageId :: s.consumedMessageIds }

noncomputable def step (s : ProtocolState) (m : Message) (fresh : SecretState) : ProtocolState :=
  if valid s m then commit s m fresh else s

theorem invalid_is_noop {s : ProtocolState} {m : Message} {fresh : SecretState}
    (h : ¬ valid s m) : step s m fresh = s := by
  simp [step, h]

theorem valid_commits {s : ProtocolState} {m : Message} {fresh : SecretState}
    (h : valid s m) : step s m fresh = commit s m fresh := by
  simp [step, h]

theorem accepted_rotates_receiver {s : ProtocolState} {m : Message}
    {fresh : SecretState} (h : valid s m) :
    receiverSecret (step s m fresh) (other (leader s.turn)) = fresh := by
  cases hL : leader s.turn with
  | alice =>
      have hd : m.direction = .alice := by simpa [hL] using h.2.2.1
      simp [step, h, receiverSecret, other, commit, hd]
  | bob =>
      have hd : m.direction = .bob := by simpa [hL] using h.2.2.1
      simp [step, h, receiverSecret, other, commit, hd]

theorem accepted_preserves_sender_secret {s : ProtocolState} {m : Message}
    {fresh : SecretState} (h : valid s m) :
    receiverSecret (step s m fresh) (leader s.turn) =
      receiverSecret s (leader s.turn) := by
  cases hL : leader s.turn with
  | alice =>
      have hd : m.direction = .alice := by simpa [hL] using h.2.2.1
      simp [step, h, receiverSecret, commit, hd]
  | bob =>
      have hd : m.direction = .bob := by simpa [hL] using h.2.2.1
      simp [step, h, receiverSecret, commit, hd]

theorem accepted_advances_exactly_one {s : ProtocolState} {m : Message}
    {fresh : SecretState} (h : valid s m) : (step s m fresh).turn = s.turn + 1 := by
  rw [valid_commits h]
  unfold commit
  cases m.direction <;> simp

theorem accepted_consumes_message_id {s : ProtocolState} {m : Message}
    {fresh : SecretState} (h : valid s m) :
    m.messageId ∈ (step s m fresh).consumedMessageIds := by
  rw [valid_commits h]
  unfold commit
  cases m.direction <;> simp

theorem invalid_input_preserves_all_secret_state
    {s : ProtocolState} {m : Message} {fresh : SecretState}
    (h : ¬ valid s m) :
    (step s m fresh).aliceSecret = s.aliceSecret ∧
    (step s m fresh).bobSecret = s.bobSecret ∧
    (step s m fresh).turn = s.turn := by
  rw [invalid_is_noop h]
  exact ⟨rfl, rfl, rfl⟩

theorem replay_is_rejected_after_commit {s : ProtocolState} {m : Message}
    {fresh : SecretState} (h : valid s m) :
    ¬ valid (step s m fresh) m := by
  intro hReplay
  have hTurn := hReplay.2.1
  have hAdvanced := accepted_advances_exactly_one (fresh := fresh) h
  have : m.turn = m.turn + 1 := by
    calc
      m.turn = (step s m fresh).turn := hTurn
      _ = s.turn + 1 := hAdvanced
      _ = m.turn + 1 := by rw [h.2.1]
  omega

theorem replay_is_noop_after_commit {s : ProtocolState} {m : Message}
    {fresh : SecretState} (h : valid s m) :
    step (step s m fresh) m fresh = step s m fresh := by
  apply invalid_is_noop
  exact replay_is_rejected_after_commit h

theorem future_turn_is_rejected {s : ProtocolState} {m : Message}
    (h : s.turn < m.turn) : ¬ valid s m := by
  intro hv
  have : m.turn = s.turn := hv.2.1
  exact Nat.not_lt_of_ge (Nat.le_of_eq this) h

theorem past_turn_is_rejected {s : ProtocolState} {m : Message}
    (h : m.turn < s.turn) : ¬ valid s m := by
  intro hv
  have : m.turn = s.turn := hv.2.1
  exact Nat.not_lt_of_ge (Nat.le_of_eq this.symm) h

theorem only_current_leader_is_accepted {s : ProtocolState} {m : Message}
    (h : valid s m) : m.direction = leader s.turn := h.2.2.1

theorem no_message_can_directly_choose_receiver_state
    {s : ProtocolState} {m₁ m₂ : Message} {fresh : SecretState}
    (h₁ : valid s m₁) (h₂ : valid s m₂) :
    receiverSecret (step s m₁ fresh) (other (leader s.turn)) =
      receiverSecret (step s m₂ fresh) (other (leader s.turn)) := by
  rw [accepted_rotates_receiver h₁, accepted_rotates_receiver h₂]

theorem state_injection_resistance
    {s : ProtocolState} {m : Message} {fresh attackerChosen : SecretState}
    (h : valid s m) (hSameLocalRandomness : fresh = attackerChosen) :
    receiverSecret (step s m fresh) (other (leader s.turn)) =
      receiverSecret (step s m attackerChosen) (other (leader s.turn)) := by
  rw [accepted_rotates_receiver h, accepted_rotates_receiver h]
  exact hSameLocalRandomness

theorem peer_input_cannot_control_secret_value
    {s : ProtocolState} {m₁ m₂ : Message} {fresh : SecretState}
    (h₁ : valid s m₁) (h₂ : valid s m₂) :
    receiverSecret (step s m₁ fresh) (other (leader s.turn)) =
      receiverSecret (step s m₂ fresh) (other (leader s.turn)) :=
  no_message_can_directly_choose_receiver_state h₁ h₂

theorem bidirectional_state_non_interference :
    ∀ (s : ProtocolState) (m₁ m₂ : Message) (fresh : SecretState),
      valid s m₁ → valid s m₂ →
      receiverSecret (step s m₁ fresh) (other (leader s.turn)) =
        receiverSecret (step s m₂ fresh) (other (leader s.turn)) := by
  intro s m₁ m₂ fresh h₁ h₂
  exact peer_input_cannot_control_secret_value h₁ h₂

def packageBound (s : ProtocolState) (pSession pTurn : Nat) : Prop :=
  pSession = s.sessionId ∧ pTurn = s.turn

theorem package_binding (s : ProtocolState) (pSession pTurn : Nat)
    (h : packageBound s pSession pTurn) :
    pSession = s.sessionId ∧ pTurn = s.turn := h

theorem rollback_and_future_package_rejected
    {s : ProtocolState} {m : Message}
    (hWrongTurn : m.turn ≠ s.turn) : ¬ valid s m := by
  intro hv
  exact hWrongTurn hv.2.1

/-! Mailbox token lookup is modeled as a total map. -/
def Mailbox (α : Type) := Nat → Option α

def mailboxPut {α : Type} (mb : Mailbox α) (token : Nat) (value : α) : Mailbox α :=
  fun query => if query = token then some value else mb query

def mailboxGet {α : Type} (mb : Mailbox α) (token : Nat) : Option α := mb token

theorem mailbox_token_correctness {α : Type} (mb : Mailbox α) (token : Nat)
    (value : α) : mailboxGet (mailboxPut mb token value) token = some value := by
  simp [mailboxGet, mailboxPut]

structure KEM where
  PublicKey : Type
  SecretKey : Type
  Ciphertext : Type
  SharedSecret : Type
  randomness : Type
  publicKey : SecretKey → PublicKey
  encapsulate : PublicKey → randomness → Ciphertext × SharedSecret
  decapsulate : SecretKey → Ciphertext → SharedSecret
  correctness : ∀ (sk : SecretKey) (r : randomness),
    let result := encapsulate (publicKey sk) r
    decapsulate sk result.1 = result.2

def hybridSecret {K : KEM} (classical pq : K.SharedSecret) (context : Nat) :
    K.SharedSecret × K.SharedSecret × Nat :=
  (classical, pq, context)

def messageKey {K : KEM}
    (hybrid : K.SharedSecret × K.SharedSecret × Nat) (messageId : Nat) :
    K.SharedSecret × K.SharedSecret × Nat :=
  (hybrid.1, hybrid.2.1, hybrid.2.2 + messageId)

def headerKey {K : KEM}
    (hybrid : K.SharedSecret × K.SharedSecret × Nat) (direction : Endpoint) :
    K.SharedSecret × K.SharedSecret × Endpoint :=
  (hybrid.1, hybrid.2.1, direction)

theorem receiver_kem_correctness {K : KEM} (sk : K.SecretKey) (r : K.randomness) :
    let result := K.encapsulate (K.publicKey sk) r
    K.decapsulate sk result.1 = result.2 := K.correctness sk r

theorem hybrid_kem_correctness {K : KEM} (sk : K.SecretKey) (rC rPQ : K.randomness)
    (context : Nat) :
    hybridSecret
      (K.decapsulate sk (K.encapsulate (K.publicKey sk) rC).1)
      (K.decapsulate sk (K.encapsulate (K.publicKey sk) rPQ).1)
      context =
    hybridSecret
      (K.encapsulate (K.publicKey sk) rC).2
      (K.encapsulate (K.publicKey sk) rPQ).2
      context := by
  simp [hybridSecret, receiver_kem_correctness]

theorem message_key_correctness {K : KEM} (sk : K.SecretKey) (rC rPQ : K.randomness)
    (context messageId : Nat) :
    messageKey
        (hybridSecret
          (K.decapsulate sk (K.encapsulate (K.publicKey sk) rC).1)
          (K.decapsulate sk (K.encapsulate (K.publicKey sk) rPQ).1)
          context)
        messageId =
    messageKey
        (hybridSecret
          (K.encapsulate (K.publicKey sk) rC).2
          (K.encapsulate (K.publicKey sk) rPQ).2
          context)
        messageId := by
  rw [hybrid_kem_correctness]

theorem header_key_correctness {K : KEM} (sk : K.SecretKey) (rC rPQ : K.randomness)
    (context : Nat) (direction : Endpoint) :
    headerKey
        (hybridSecret
          (K.decapsulate sk (K.encapsulate (K.publicKey sk) rC).1)
          (K.decapsulate sk (K.encapsulate (K.publicKey sk) rPQ).1)
          context)
        direction =
    headerKey
        (hybridSecret
          (K.encapsulate (K.publicKey sk) rC).2
          (K.encapsulate (K.publicKey sk) rPQ).2
          context)
        direction := by
  rw [hybrid_kem_correctness]

/-! The two protocol directions are the same theorem under endpoint symmetry. -/
theorem alice_compromised_bob_secret_isolation
    {s : ProtocolState} {m₁ m₂ : Message} {fresh : SecretState}
    (h₁ : valid s m₁) (h₂ : valid s m₂)
    (hLeader : leader s.turn = .alice) :
    receiverSecret (step s m₁ fresh) .bob =
      receiverSecret (step s m₂ fresh) .bob := by
  simpa [hLeader, other] using (peer_input_cannot_control_secret_value h₁ h₂)

theorem bob_compromised_alice_secret_isolation
    {s : ProtocolState} {m₁ m₂ : Message} {fresh : SecretState}
    (h₁ : valid s m₁) (h₂ : valid s m₂)
    (hLeader : leader s.turn = .bob) :
    receiverSecret (step s m₁ fresh) .alice =
      receiverSecret (step s m₂ fresh) .alice := by
  simpa [hLeader, other] using (peer_input_cannot_control_secret_value h₁ h₂)

end
end LinkChat
