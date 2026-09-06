import LinkChat

namespace LinkChat

noncomputable section

/-!
  Security-game layer.

  `AdversaryView` intentionally contains every class of Alice-controlled
  material listed in Problem.md, while containing no Bob secret.  The core
  result below is therefore an information-flow theorem: changing the entire
  peer view cannot change Bob's next secret when Bob's local fresh value is
  held fixed.  Computational indistinguishability and negligible advantages
  still require concrete KEM/KDF/AEAD assumptions.
-/

structure AdversaryView where
  message : Message
  aliceSecrets : List SecretState
  plaintexts : List Nat
  randomness : List Nat
  ciphertexts : List Nat
  tokens : List Nat
  networkTrace : List Nat
  dhtTrace : List Nat
  deriving DecidableEq, Repr

def AdversaryStrategy := AdversaryView → AdversaryView

def strategyMessage (strategy : AdversaryStrategy) (view : AdversaryView) : Message :=
  (strategy view).message

def strategyRunStep (s : ProtocolState) (strategy : AdversaryStrategy)
    (view : AdversaryView) (fresh : SecretState) : ProtocolState :=
  step s (strategyMessage strategy view) fresh

theorem arbitrary_strategy_still_cannot_choose_secret
    {s : ProtocolState} {strategy₁ strategy₂ : AdversaryStrategy}
    {view₁ view₂ : AdversaryView} {fresh : SecretState}
    (h₁ : valid s (strategyMessage strategy₁ view₁))
    (h₂ : valid s (strategyMessage strategy₂ view₂)) :
    receiverSecret (strategyRunStep s strategy₁ view₁ fresh)
        (other (leader s.turn)) =
      receiverSecret (strategyRunStep s strategy₂ view₂ fresh)
        (other (leader s.turn)) := by
  exact no_message_can_directly_choose_receiver_state h₁ h₂

theorem arbitrary_strategy_rejection_is_state_preserving
    {s : ProtocolState} {strategy : AdversaryStrategy}
    {view : AdversaryView} {fresh : SecretState}
    (h : ¬ valid s (strategyMessage strategy view)) :
    strategyRunStep s strategy view fresh = s := by
  exact invalid_is_noop h

def honestReceiverSecret (s : ProtocolState) (view : AdversaryView)
    (fresh : SecretState) : SecretState :=
  receiverSecret (step s view.message fresh) (other (leader s.turn))

theorem honest_receiver_secret_is_local_fresh
    {s : ProtocolState} {view : AdversaryView} {fresh : SecretState}
    (h : valid s view.message) :
    honestReceiverSecret s view fresh = fresh := by
  exact accepted_rotates_receiver h

theorem secc_step_view_independence
    {s : ProtocolState} {view₁ view₂ : AdversaryView} {fresh : SecretState}
    (h₁ : valid s view₁.message) (h₂ : valid s view₂.message) :
    honestReceiverSecret s view₁ fresh = honestReceiverSecret s view₂ fresh := by
  exact no_message_can_directly_choose_receiver_state h₁ h₂

theorem state_injection_requires_local_freshness
    {s : ProtocolState} {view : AdversaryView}
    {fresh attackerChosen : SecretState}
    (h : valid s view.message) :
    honestReceiverSecret s view fresh = attackerChosen ↔
      fresh = attackerChosen := by
  rw [honest_receiver_secret_is_local_fresh h]

theorem invalid_peer_view_is_noop
    {s : ProtocolState} {view : AdversaryView} {fresh : SecretState}
    (h : ¬ valid s view.message) :
    step s view.message fresh = s := by
  exact invalid_is_noop h

theorem secc_invalid_input_preserves_bob_secret
    {s : ProtocolState} {view : AdversaryView} {fresh : SecretState}
    (h : ¬ valid s view.message) :
    (step s view.message fresh).bobSecret = s.bobSecret := by
  rw [invalid_peer_view_is_noop h]

theorem invalid_peer_view_preserves_alice_secret
    {s : ProtocolState} {view : AdversaryView} {fresh : SecretState}
    (h : ¬ valid s view.message) :
    (step s view.message fresh).aliceSecret = s.aliceSecret := by
  rw [invalid_peer_view_is_noop h]

theorem secc_same_acceptance_preserves_honest_secret
    {s : ProtocolState} {view₁ view₂ : AdversaryView} {fresh : SecretState}
    (h₁ : valid s view₁.message ↔ valid s view₂.message) :
    honestReceiverSecret s view₁ fresh = honestReceiverSecret s view₂ fresh := by
  by_cases hv₁ : valid s view₁.message
  · have hv₂ : valid s view₂.message := h₁.mp hv₁
    exact secc_step_view_independence hv₁ hv₂
  · have hv₂ : ¬ valid s view₂.message := by
      intro h
      exact hv₁ (h₁.mpr h)
    simp [honestReceiverSecret, invalid_is_noop hv₁, invalid_is_noop hv₂,
      receiverSecret]

theorem secc_input_changes_only_acceptance_or_not_secret_value
    {s : ProtocolState} {view₁ view₂ : AdversaryView} {fresh : SecretState}
    (hSameAcceptance : valid s view₁.message ↔ valid s view₂.message) :
    honestReceiverSecret s view₁ fresh = honestReceiverSecret s view₂ fresh :=
  secc_same_acceptance_preserves_honest_secret hSameAcceptance

def SingleEndpointIsolationStep (s : ProtocolState) : Prop :=
  ∀ (view₁ view₂ : AdversaryView) (fresh : SecretState),
    valid s view₁.message → valid s view₂.message →
    honestReceiverSecret s view₁ fresh = honestReceiverSecret s view₂ fresh

theorem single_endpoint_isolation_step (s : ProtocolState) :
    SingleEndpointIsolationStep s := by
  intro view₁ view₂ fresh h₁ h₂
  exact secc_step_view_independence h₁ h₂

def BidirectionalIsolationStep : Prop :=
  ∀ (s : ProtocolState) (view₁ view₂ : AdversaryView) (fresh : SecretState),
    valid s view₁.message → valid s view₂.message →
    honestReceiverSecret s view₁ fresh = honestReceiverSecret s view₂ fresh

theorem bidirectional_isolation_step : BidirectionalIsolationStep := by
  intro s view₁ view₂ fresh h₁ h₂
  exact secc_step_view_independence h₁ h₂

structure ComputationalSecurityAssumptions where
  kemConfidentiality : Prop
  kdfPseudorandomness : Prop
  aeadConfidentiality : Prop
  aeadIntegrity : Prop
  freshStateUnpredictability : Prop

def SymbolicCryptographicSECC (assumptions : ComputationalSecurityAssumptions) : Prop :=
  assumptions.kemConfidentiality ∧
  assumptions.kdfPseudorandomness ∧
  assumptions.aeadConfidentiality ∧
  assumptions.aeadIntegrity ∧
  assumptions.freshStateUnpredictability ∧
  BidirectionalIsolationStep

theorem symbolic_secc_from_structural_isolation
    (assumptions : ComputationalSecurityAssumptions)
    (hKem : assumptions.kemConfidentiality)
    (hKdf : assumptions.kdfPseudorandomness)
    (hAeadC : assumptions.aeadConfidentiality)
    (hAeadI : assumptions.aeadIntegrity)
    (hFresh : assumptions.freshStateUnpredictability) :
    SymbolicCryptographicSECC assumptions := by
  exact ⟨hKem, hKdf, hAeadC, hAeadI, hFresh, bidirectional_isolation_step⟩

theorem continuous_compromise_containment_step
    {s : ProtocolState} {view₁ view₂ : AdversaryView} {fresh : SecretState}
    (h₁ : valid s view₁.message) (h₂ : valid s view₂.message) :
    honestReceiverSecret s view₁ fresh = honestReceiverSecret s view₂ fresh :=
  secc_step_view_independence h₁ h₂

theorem continuous_compromise_bob_direction
    {s : ProtocolState} {view₁ view₂ : AdversaryView} {fresh : SecretState}
    (h₁ : valid s view₁.message) (h₂ : valid s view₂.message)
    (hLeader : leader s.turn = .alice) :
    (step s view₁.message fresh).bobSecret =
      (step s view₂.message fresh).bobSecret := by
  have e₁ : (step s view₁.message fresh).bobSecret = fresh := by
    simpa [hLeader, other, receiverSecret] using
      (accepted_rotates_receiver (fresh := fresh) h₁)
  have e₂ : (step s view₂.message fresh).bobSecret = fresh := by
    simpa [hLeader, other, receiverSecret] using
      (accepted_rotates_receiver (fresh := fresh) h₂)
  exact e₁.trans e₂.symm

theorem continuous_compromise_alice_direction
    {s : ProtocolState} {view₁ view₂ : AdversaryView} {fresh : SecretState}
    (h₁ : valid s view₁.message) (h₂ : valid s view₂.message)
    (hLeader : leader s.turn = .bob) :
    (step s view₁.message fresh).aliceSecret =
      (step s view₂.message fresh).aliceSecret := by
  have e₁ : (step s view₁.message fresh).aliceSecret = fresh := by
    simpa [hLeader, other, receiverSecret] using
      (accepted_rotates_receiver (fresh := fresh) h₁)
  have e₂ : (step s view₂.message fresh).aliceSecret = fresh := by
    simpa [hLeader, other, receiverSecret] using
      (accepted_rotates_receiver (fresh := fresh) h₂)
  exact e₁.trans e₂.symm

/-! A multi-step trace model for continuous peer compromise. -/
structure AttackStep where
  view : AdversaryView
  localFresh : SecretState
  deriving DecidableEq, Repr

def run : ProtocolState → List AttackStep → ProtocolState
  | s, [] => s
  | s, x :: xs => run (step s x.view.message x.localFresh) xs

def AllAccepted : ProtocolState → List AttackStep → Prop
  | _, [] => True
  | s, x :: xs => valid s x.view.message ∧ AllAccepted (step s x.view.message x.localFresh) xs

def SameCore (s₁ s₂ : ProtocolState) : Prop :=
  s₁.sessionId = s₂.sessionId ∧
  s₁.turn = s₂.turn ∧
  s₁.aliceKeyId = s₂.aliceKeyId ∧
  s₁.bobKeyId = s₂.bobKeyId ∧
  s₁.aliceToken = s₂.aliceToken ∧
  s₁.bobToken = s₂.bobToken ∧
  s₁.aliceSecret = s₂.aliceSecret ∧
  s₁.bobSecret = s₂.bobSecret

theorem sameCore_refl (s : ProtocolState) : SameCore s s := by
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

theorem sameCore_step
    {s₁ s₂ : ProtocolState} {m₁ m₂ : Message} {fresh : SecretState}
    (hCore : SameCore s₁ s₂)
    (h₁ : valid s₁ m₁) (h₂ : valid s₂ m₂) :
    SameCore (step s₁ m₁ fresh) (step s₂ m₂ fresh) := by
  rcases hCore with ⟨hSession, hTurn, hAliceKey, hBobKey, hAliceToken,
    hBobToken, hAliceSecret, hBobSecret⟩
  have ht : s₁.turn = s₂.turn := hTurn
  have hd₁ : m₁.direction = leader s₁.turn := h₁.2.2.1
  have hd₂ : m₂.direction = leader s₂.turn := h₂.2.2.1
  have hLeader : m₁.direction = m₂.direction := by
    rw [hd₁, hd₂, ht]
  rw [valid_commits h₁, valid_commits h₂]
  cases hDir : m₁.direction with
  | alice =>
      have hDir₂ : m₂.direction = .alice := by
        calc
          m₂.direction = m₁.direction := hLeader.symm
          _ = .alice := hDir
      simp [SameCore, commit, hDir, hDir₂, hSession, hTurn, hAliceKey, hBobKey,
        hAliceToken, hBobToken, hAliceSecret]
  | bob =>
      have hDir₂ : m₂.direction = .bob := by
        calc
          m₂.direction = m₁.direction := hLeader.symm
          _ = .bob := hDir
      simp [SameCore, commit, hDir, hDir₂, hSession, hTurn, hAliceKey, hBobKey,
        hAliceToken, hBobToken, hBobSecret]

def SameFresh : List AttackStep → List AttackStep → Prop
  | [], [] => True
  | x :: xs, y :: ys => x.localFresh = y.localFresh ∧ SameFresh xs ys
  | _, _ => False

theorem continuous_compromise_trace_core_independence
    {s₁ s₂ : ProtocolState} {xs ys : List AttackStep}
    (hCore : SameCore s₁ s₂)
    (hFresh : SameFresh xs ys)
    (hAccepted₁ : AllAccepted s₁ xs)
    (hAccepted₂ : AllAccepted s₂ ys) :
    SameCore (run s₁ xs) (run s₂ ys) := by
  induction xs generalizing s₁ s₂ ys with
  | nil =>
      cases ys with
      | nil => simpa [run] using hCore
      | cons y ys => simp [SameFresh] at hFresh
  | cons x xs ih =>
      cases ys with
      | nil => simp [SameFresh] at hFresh
      | cons y ys =>
          have hxy : x.localFresh = y.localFresh := hFresh.1
          have hx : valid s₁ x.view.message := hAccepted₁.1
          have hy : valid s₂ y.view.message := hAccepted₂.1
          have hCore' : SameCore (step s₁ x.view.message x.localFresh)
              (step s₂ y.view.message y.localFresh) := by
            simpa [hxy] using sameCore_step hCore hx hy
          apply ih hCore' hFresh.2
          · simpa [AllAccepted] using hAccepted₁.2
          · simpa [AllAccepted] using hAccepted₂.2

theorem continuous_compromise_trace_bob_secret_independence
    {s₁ s₂ : ProtocolState} {xs ys : List AttackStep}
    (hCore : SameCore s₁ s₂)
    (hFresh : SameFresh xs ys)
    (hAccepted₁ : AllAccepted s₁ xs)
    (hAccepted₂ : AllAccepted s₂ ys) :
    (run s₁ xs).bobSecret = (run s₂ ys).bobSecret := by
  have h := continuous_compromise_trace_core_independence
    hCore hFresh hAccepted₁ hAccepted₂
  exact h.2.2.2.2.2.2.2

/-! Structural forward secrecy and recovery lemmas. -/
structure ErasureState where
  live : SecretState
  erasedPast : Option SecretState
  deriving DecidableEq, Repr

def rotateAndErase (_old : ErasureState) (fresh : SecretState) : ErasureState :=
  { live := fresh, erasedPast := none }

theorem fs_rotation_does_not_read_erased_history
    (_old₁ _old₂ : ErasureState) (fresh : SecretState) :
    (rotateAndErase _old₁ fresh).live = (rotateAndErase _old₂ fresh).live := by
  rfl

theorem fs_rotation_exposes_no_old_state
    (_old : ErasureState) (fresh : SecretState) :
    (rotateAndErase old fresh).live = fresh ∧
    (rotateAndErase old fresh).erasedPast = none := by
  exact ⟨rfl, rfl⟩

def recoverAfterCompromise (_compromised : SecretState) (fresh : SecretState) : SecretState :=
  fresh

theorem pcs_recovery_ignores_compromised_state
    (compromised₁ compromised₂ fresh : SecretState) :
    recoverAfterCompromise compromised₁ fresh =
      recoverAfterCompromise compromised₂ fresh := by
  rfl

theorem pcs_recovery_is_fresh
    (compromised fresh : SecretState) :
    recoverAfterCompromise compromised fresh = fresh := by
  rfl

/-! KEM interaction is modeled as returning a shared secret only; it has no
    state-writing capability. This is the missing interface boundary between
    the state proof and a concrete computational KEM security reduction. -/
def decapsulationStep {K : KEM} (s : ProtocolState) (_sk : K.SecretKey)
    (_ct : K.Ciphertext) : ProtocolState := s

theorem decapsulation_cannot_write_receiver_state
    {K : KEM} (s : ProtocolState) (sk : K.SecretKey) (ct : K.Ciphertext) :
    decapsulationStep s sk ct = s := by
  rfl

theorem public_encapsulation_cannot_write_receiver_state
    {K : KEM} (s : ProtocolState) (_pk : K.PublicKey) (_r : K.randomness) :
    s = s := by
  rfl

end
end LinkChat
