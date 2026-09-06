import LinkChat

namespace LinkChat

noncomputable section
local instance refinedPropDecidable (p : Prop) : Decidable p := Classical.propDecidable p

/-!
  Refined model: a receiver secret and its public projection are rotated as
  one package. This closes the modeling gap in the first state-machine file,
  where only the secret field was rotated.
-/

structure ReceiverPackage where
  secret : SecretState
  keyId : Nat
  mailboxToken : Nat
  deriving DecidableEq, Repr

structure RefinedState where
  sessionId : Nat
  turn : Nat
  alice : ReceiverPackage
  bob : ReceiverPackage
  consumedMessageIds : List Nat
  deriving DecidableEq, Repr

structure RefinedMessage where
  sessionId : Nat
  turn : Nat
  direction : Endpoint
  messageId : Nat
  receiverKeyId : Nat
  receiverToken : Nat
  payload : Nat
  deriving DecidableEq, Repr

def refinedReceiver (s : RefinedState) (endpoint : Endpoint) : ReceiverPackage :=
  match endpoint with
  | .alice => s.alice
  | .bob => s.bob

def refinedValid (s : RefinedState) (m : RefinedMessage) : Prop :=
  m.sessionId = s.sessionId ∧
  m.turn = s.turn ∧
  m.direction = leader s.turn ∧
  m.receiverKeyId = (refinedReceiver s (other m.direction)).keyId ∧
  m.receiverToken = (refinedReceiver s (other m.direction)).mailboxToken ∧
  m.messageId ∉ s.consumedMessageIds

def refinedCommit (s : RefinedState) (m : RefinedMessage)
    (next : ReceiverPackage) : RefinedState :=
  match m.direction with
  | .alice =>
      { s with
        turn := s.turn + 1
        bob := next
        consumedMessageIds := m.messageId :: s.consumedMessageIds }
  | .bob =>
      { s with
        turn := s.turn + 1
        alice := next
        consumedMessageIds := m.messageId :: s.consumedMessageIds }

noncomputable def refinedStep (s : RefinedState) (m : RefinedMessage)
    (next : ReceiverPackage) : RefinedState :=
  if refinedValid s m then refinedCommit s m next else s

theorem refinedInvalidNoop {s : RefinedState} {m : RefinedMessage}
    {next : ReceiverPackage} (h : ¬ refinedValid s m) :
    refinedStep s m next = s := by
  simp [refinedStep, h]

theorem refinedValidCommits {s : RefinedState} {m : RefinedMessage}
    {next : ReceiverPackage} (h : refinedValid s m) :
    refinedStep s m next = refinedCommit s m next := by
  simp [refinedStep, h]

theorem refinedAcceptedRotatesReceiver {s : RefinedState} {m : RefinedMessage}
    {next : ReceiverPackage} (h : refinedValid s m) :
    refinedReceiver (refinedStep s m next) (other (leader s.turn)) = next := by
  cases hL : leader s.turn with
  | alice =>
      have hd : m.direction = .alice := by simpa [hL] using h.2.2.1
      simp [refinedStep, h, refinedReceiver, other, refinedCommit, hd]
  | bob =>
      have hd : m.direction = .bob := by simpa [hL] using h.2.2.1
      simp [refinedStep, h, refinedReceiver, other, refinedCommit, hd]

theorem refinedAcceptedPreservesSender {s : RefinedState} {m : RefinedMessage}
    {next : ReceiverPackage} (h : refinedValid s m) :
    refinedReceiver (refinedStep s m next) (leader s.turn) =
      refinedReceiver s (leader s.turn) := by
  cases hL : leader s.turn with
  | alice =>
      have hd : m.direction = .alice := by simpa [hL] using h.2.2.1
      simp [refinedStep, h, refinedReceiver, refinedCommit, hd]
  | bob =>
      have hd : m.direction = .bob := by simpa [hL] using h.2.2.1
      simp [refinedStep, h, refinedReceiver, refinedCommit, hd]

theorem refinedAcceptedAdvancesOne {s : RefinedState} {m : RefinedMessage}
    {next : ReceiverPackage} (h : refinedValid s m) :
    (refinedStep s m next).turn = s.turn + 1 := by
  rw [refinedValidCommits h]
  unfold refinedCommit
  cases m.direction <;> simp

theorem refinedInvalidPreservesSecrets {s : RefinedState} {m : RefinedMessage}
    {next : ReceiverPackage} (h : ¬ refinedValid s m) :
    (refinedStep s m next).alice = s.alice ∧
    (refinedStep s m next).bob = s.bob ∧
    (refinedStep s m next).turn = s.turn := by
  rw [refinedInvalidNoop h]
  exact ⟨rfl, rfl, rfl⟩

theorem refinedReplayRejected {s : RefinedState} {m : RefinedMessage}
    {next : ReceiverPackage} (h : refinedValid s m) :
    ¬ refinedValid (refinedStep s m next) m := by
  intro hr
  have hTurn := hr.2.1
  have hAdvanced := refinedAcceptedAdvancesOne (next := next) h
  have : m.turn = m.turn + 1 := by
    calc
      m.turn = (refinedStep s m next).turn := hTurn
      _ = s.turn + 1 := hAdvanced
      _ = m.turn + 1 := by rw [h.2.1]
  omega

theorem refinedReplayNoop {s : RefinedState} {m : RefinedMessage}
    {next : ReceiverPackage} (h : refinedValid s m) :
    refinedStep (refinedStep s m next) m next = refinedStep s m next := by
  exact refinedInvalidNoop (refinedReplayRejected h)

theorem refinedStateInjectionResistance
    {s : RefinedState} {m : RefinedMessage}
    {next attackerChosen : ReceiverPackage}
    (h : refinedValid s m) :
    refinedReceiver (refinedStep s m next) (other (leader s.turn)) =
      refinedReceiver (refinedStep s m attackerChosen) (other (leader s.turn)) ↔
      next = attackerChosen := by
  rw [refinedAcceptedRotatesReceiver h, refinedAcceptedRotatesReceiver h]

theorem refinedPeerInputNonInterference
    {s : RefinedState} {m₁ m₂ : RefinedMessage}
    {next : ReceiverPackage}
    (h₁ : refinedValid s m₁) (h₂ : refinedValid s m₂) :
    refinedReceiver (refinedStep s m₁ next) (other (leader s.turn)) =
      refinedReceiver (refinedStep s m₂ next) (other (leader s.turn)) := by
  rw [refinedAcceptedRotatesReceiver h₁, refinedAcceptedRotatesReceiver h₂]

theorem refinedKeyProjectionRotatesWithSecret
    {s : RefinedState} {m : RefinedMessage} {next : ReceiverPackage}
    (h : refinedValid s m) :
    (refinedReceiver (refinedStep s m next) (other (leader s.turn))).keyId = next.keyId ∧
    (refinedReceiver (refinedStep s m next) (other (leader s.turn))).mailboxToken =
      next.mailboxToken := by
  rw [refinedAcceptedRotatesReceiver h]
  exact ⟨rfl, rfl⟩

def RefinedSameCore (s₁ s₂ : RefinedState) : Prop :=
  s₁.sessionId = s₂.sessionId ∧
  s₁.turn = s₂.turn ∧
  s₁.alice = s₂.alice ∧
  s₁.bob = s₂.bob

structure RefinedAttackStep where
  view : RefinedMessage
  localNext : ReceiverPackage
  deriving DecidableEq, Repr

def refinedRun : RefinedState → List RefinedAttackStep → RefinedState
  | s, [] => s
  | s, x :: xs => refinedRun (refinedStep s x.view x.localNext) xs

def RefinedAllAccepted : RefinedState → List RefinedAttackStep → Prop
  | _, [] => True
  | s, x :: xs => refinedValid s x.view ∧
      RefinedAllAccepted (refinedStep s x.view x.localNext) xs

def SameLocalNext : List RefinedAttackStep → List RefinedAttackStep → Prop
  | [], [] => True
  | x :: xs, y :: ys => x.localNext = y.localNext ∧ SameLocalNext xs ys
  | _, _ => False

theorem refinedSameCoreStep
    {s₁ s₂ : RefinedState} {m₁ m₂ : RefinedMessage}
    {next : ReceiverPackage}
    (hCore : RefinedSameCore s₁ s₂)
    (h₁ : refinedValid s₁ m₁) (h₂ : refinedValid s₂ m₂) :
    RefinedSameCore (refinedStep s₁ m₁ next) (refinedStep s₂ m₂ next) := by
  rcases hCore with ⟨hSession, hTurn, hAlice, hBob⟩
  have hd₁ : m₁.direction = leader s₁.turn := h₁.2.2.1
  have hd₂ : m₂.direction = leader s₂.turn := h₂.2.2.1
  have hDir : m₁.direction = m₂.direction := by
    rw [hd₁, hd₂, hTurn]
  rw [refinedValidCommits h₁, refinedValidCommits h₂]
  cases hD : m₁.direction with
  | alice =>
      have hD₂ : m₂.direction = .alice := by
        calc
          m₂.direction = m₁.direction := hDir.symm
          _ = .alice := hD
      simp [RefinedSameCore, refinedCommit, hD, hD₂, hSession, hTurn,
        hAlice]
  | bob =>
      have hD₂ : m₂.direction = .bob := by
        calc
          m₂.direction = m₁.direction := hDir.symm
          _ = .bob := hD
      simp [RefinedSameCore, refinedCommit, hD, hD₂, hSession, hTurn,
        hBob]

theorem refinedContinuousCompromiseTrace
    {s₁ s₂ : RefinedState} {xs ys : List RefinedAttackStep}
    (hCore : RefinedSameCore s₁ s₂)
    (hLocal : SameLocalNext xs ys)
    (hAccepted₁ : RefinedAllAccepted s₁ xs)
    (hAccepted₂ : RefinedAllAccepted s₂ ys) :
    RefinedSameCore (refinedRun s₁ xs) (refinedRun s₂ ys) := by
  induction xs generalizing s₁ s₂ ys with
  | nil =>
      cases ys with
      | nil => simpa [refinedRun] using hCore
      | cons y ys => simp [SameLocalNext] at hLocal
  | cons x xs ih =>
      cases ys with
      | nil => simp [SameLocalNext] at hLocal
      | cons y ys =>
          have hNext : x.localNext = y.localNext := hLocal.1
          have hx : refinedValid s₁ x.view := hAccepted₁.1
          have hy : refinedValid s₂ y.view := hAccepted₂.1
          have hCore' : RefinedSameCore
              (refinedStep s₁ x.view x.localNext)
              (refinedStep s₂ y.view y.localNext) := by
            simpa [hNext] using refinedSameCoreStep hCore hx hy
          apply ih hCore' hLocal.2
          · simpa [RefinedAllAccepted] using hAccepted₁.2
          · simpa [RefinedAllAccepted] using hAccepted₂.2

theorem refinedContinuousBobConfidentiality
    {s₁ s₂ : RefinedState} {xs ys : List RefinedAttackStep}
    (hCore : RefinedSameCore s₁ s₂)
    (hLocal : SameLocalNext xs ys)
    (hAccepted₁ : RefinedAllAccepted s₁ xs)
    (hAccepted₂ : RefinedAllAccepted s₂ ys) :
    (refinedRun s₁ xs).bob = (refinedRun s₂ ys).bob := by
  have h := refinedContinuousCompromiseTrace hCore hLocal hAccepted₁ hAccepted₂
  exact h.2.2.2

theorem refinedContinuousAliceConfidentiality
    {s₁ s₂ : RefinedState} {xs ys : List RefinedAttackStep}
    (hCore : RefinedSameCore s₁ s₂)
    (hLocal : SameLocalNext xs ys)
    (hAccepted₁ : RefinedAllAccepted s₁ xs)
    (hAccepted₂ : RefinedAllAccepted s₂ ys) :
    (refinedRun s₁ xs).alice = (refinedRun s₂ ys).alice := by
  have h := refinedContinuousCompromiseTrace hCore hLocal hAccepted₁ hAccepted₂
  exact h.2.2.1

end
end LinkChat
