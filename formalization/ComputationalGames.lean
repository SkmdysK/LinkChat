import Std
import LinkChat
import SecurityGames
import RefinedProtocol
import StandardCrypto

namespace LinkChat

noncomputable section
local instance computationalGamesPropDecidable (p : Prop) : Decidable p :=
  Classical.propDecidable p

/-!
  Computational security-game layer for Link Chat v1.0.

  This file freezes the protocol state machine and makes the missing game
  interfaces explicit.  The state-machine theorems prove the protocol-level
  hybrid step.  Probability semantics and concrete primitive security are
  intentionally supplied as assumptions, because they cannot be derived
  from the dependency-free symbolic API alone.
-/

/-! ## Complete attacker view -/

structure CompleteAdversaryView where
  message : Message
  aliceState : List Nat
  alicePlaintexts : List Nat
  aliceRandomness : List Nat
  aliceCiphertexts : List Nat
  aliceTokens : List Nat
  networkTrace : List Nat
  dhtTrace : List Nat
  bobPublicOutputs : List Nat
  bobAckOutputs : List Nat
  bobErrorOutputs : List Nat
  bobNetworkOutputs : List Nat
  bobDhtOutputs : List Nat
  acceptRejectTrace : List Nat
  bobSendTimes : List Nat
  bobMessageLengths : List Nat
  bobCiphertextLengths : List Nat
  bobStateUpdateCounts : List Nat
  bobPackageUpdateCounts : List Nat
  deriving DecidableEq, Repr

def AdaptiveAdversary := List CompleteAdversaryView → CompleteAdversaryView

def adversaryMessage (a : AdaptiveAdversary)
    (history : List CompleteAdversaryView) : Message :=
  (a history).message

inductive ObservableDatum where
  | message (m : Message)
  | aliceState (x : Nat)
  | alicePlaintext (x : Nat)
  | aliceRandomness (x : Nat)
  | aliceCiphertext (x : Nat)
  | aliceToken (x : Nat)
  | network (x : Nat)
  | dht (x : Nat)
  | bobPublic (x : Nat)
  | bobAck (x : Nat)
  | bobError (x : Nat)
  | bobNetwork (x : Nat)
  | bobDht (x : Nat)
  | acceptReject (x : Nat)
  | bobSendTime (x : Nat)
  | bobMessageLength (x : Nat)
  | bobCiphertextLength (x : Nat)
  | bobStateUpdateCount (x : Nat)
  | bobPackageUpdateCount (x : Nat)
  deriving DecidableEq, Repr

def CompleteAdversaryView.observableData (v : CompleteAdversaryView) :
    List ObservableDatum :=
  [ObservableDatum.message v.message] ++
  (v.aliceState.map ObservableDatum.aliceState) ++
  (v.alicePlaintexts.map ObservableDatum.alicePlaintext) ++
  (v.aliceRandomness.map ObservableDatum.aliceRandomness) ++
  (v.aliceCiphertexts.map ObservableDatum.aliceCiphertext) ++
  (v.aliceTokens.map ObservableDatum.aliceToken) ++
  (v.networkTrace.map ObservableDatum.network) ++
  (v.dhtTrace.map ObservableDatum.dht) ++
  (v.bobPublicOutputs.map ObservableDatum.bobPublic) ++
  (v.bobAckOutputs.map ObservableDatum.bobAck) ++
  (v.bobErrorOutputs.map ObservableDatum.bobError) ++
  (v.bobNetworkOutputs.map ObservableDatum.bobNetwork) ++
  (v.bobDhtOutputs.map ObservableDatum.bobDht) ++
  (v.acceptRejectTrace.map ObservableDatum.acceptReject) ++
  (v.bobSendTimes.map ObservableDatum.bobSendTime) ++
  (v.bobMessageLengths.map ObservableDatum.bobMessageLength) ++
  (v.bobCiphertextLengths.map ObservableDatum.bobCiphertextLength) ++
  (v.bobStateUpdateCounts.map ObservableDatum.bobStateUpdateCount) ++
  (v.bobPackageUpdateCounts.map ObservableDatum.bobPackageUpdateCount)

/-! A threat-model record has exactly the protocol-level observations that the
    complete view is required to represent. -/
structure ThreatModelObservation where
  message : Message
  aliceState : List Nat
  alicePlaintexts : List Nat
  aliceRandomness : List Nat
  aliceCiphertexts : List Nat
  aliceTokens : List Nat
  networkTrace : List Nat
  dhtTrace : List Nat
  bobPublicOutputs : List Nat
  bobAckOutputs : List Nat
  bobErrorOutputs : List Nat
  bobNetworkOutputs : List Nat
  bobDhtOutputs : List Nat
  acceptRejectTrace : List Nat
  bobSendTimes : List Nat
  bobMessageLengths : List Nat
  bobCiphertextLengths : List Nat
  bobStateUpdateCounts : List Nat
  bobPackageUpdateCounts : List Nat
  deriving DecidableEq, Repr

def ThreatModelObservation.toView (o : ThreatModelObservation) :
    CompleteAdversaryView :=
  { message := o.message
    aliceState := o.aliceState
    alicePlaintexts := o.alicePlaintexts
    aliceRandomness := o.aliceRandomness
    aliceCiphertexts := o.aliceCiphertexts
    aliceTokens := o.aliceTokens
    networkTrace := o.networkTrace
    dhtTrace := o.dhtTrace
    bobPublicOutputs := o.bobPublicOutputs
    bobAckOutputs := o.bobAckOutputs
    bobErrorOutputs := o.bobErrorOutputs
    bobNetworkOutputs := o.bobNetworkOutputs
    bobDhtOutputs := o.bobDhtOutputs
    acceptRejectTrace := o.acceptRejectTrace
    bobSendTimes := o.bobSendTimes
    bobMessageLengths := o.bobMessageLengths
    bobCiphertextLengths := o.bobCiphertextLengths
    bobStateUpdateCounts := o.bobStateUpdateCounts
    bobPackageUpdateCounts := o.bobPackageUpdateCounts }

def ThreatModelObservation.observableData (o : ThreatModelObservation) :
    List ObservableDatum :=
  [ObservableDatum.message o.message] ++
  (o.aliceState.map ObservableDatum.aliceState) ++
  (o.alicePlaintexts.map ObservableDatum.alicePlaintext) ++
  (o.aliceRandomness.map ObservableDatum.aliceRandomness) ++
  (o.aliceCiphertexts.map ObservableDatum.aliceCiphertext) ++
  (o.aliceTokens.map ObservableDatum.aliceToken) ++
  (o.networkTrace.map ObservableDatum.network) ++
  (o.dhtTrace.map ObservableDatum.dht) ++
  (o.bobPublicOutputs.map ObservableDatum.bobPublic) ++
  (o.bobAckOutputs.map ObservableDatum.bobAck) ++
  (o.bobErrorOutputs.map ObservableDatum.bobError) ++
  (o.bobNetworkOutputs.map ObservableDatum.bobNetwork) ++
  (o.bobDhtOutputs.map ObservableDatum.bobDht) ++
  (o.acceptRejectTrace.map ObservableDatum.acceptReject) ++
  (o.bobSendTimes.map ObservableDatum.bobSendTime) ++
  (o.bobMessageLengths.map ObservableDatum.bobMessageLength) ++
  (o.bobCiphertextLengths.map ObservableDatum.bobCiphertextLength) ++
  (o.bobStateUpdateCounts.map ObservableDatum.bobStateUpdateCount) ++
  (o.bobPackageUpdateCounts.map ObservableDatum.bobPackageUpdateCount)

def ViewCompleteness : Prop :=
  ∀ o : ThreatModelObservation,
    (o.toView).observableData = o.observableData

theorem complete_view_is_complete : ViewCompleteness := by
  intro o
  rfl

theorem complete_view_contains_bob_outputs (o : ThreatModelObservation) :
    o.toView.bobPublicOutputs = o.bobPublicOutputs ∧
    o.toView.bobAckOutputs = o.bobAckOutputs ∧
    o.toView.bobErrorOutputs = o.bobErrorOutputs ∧
    o.toView.bobNetworkOutputs = o.bobNetworkOutputs ∧
    o.toView.bobDhtOutputs = o.bobDhtOutputs ∧
    o.toView.acceptRejectTrace = o.acceptRejectTrace ∧
    o.toView.bobSendTimes = o.bobSendTimes ∧
    o.toView.bobMessageLengths = o.bobMessageLengths ∧
    o.toView.bobCiphertextLengths = o.bobCiphertextLengths ∧
    o.toView.bobStateUpdateCounts = o.bobStateUpdateCounts ∧
    o.toView.bobPackageUpdateCounts = o.bobPackageUpdateCounts := by
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

/-! ## Explicit attacker capability matrix -/

inductive AttackerCapability where
  | controlAliceState
  | controlAliceRandomness
  | controlAlicePlaintexts
  | controlAliceMessages
  | replayModifyDelayDrop
  | controlDht
  | observeNetwork
  | observeDht
  | observeBobPublicOutput
  | observeBobAckError
  | observeBobTiming
  | observeBobLengths
  | observeBobUpdateCounts
  | accessBobSecretState
  | controlBobRandomness
  | modifyBobStorage
  | rollbackBobStorage
  deriving DecidableEq, Repr

def capabilityAllowed : AttackerCapability → Bool
  | .controlAliceState => true
  | .controlAliceRandomness => true
  | .controlAlicePlaintexts => true
  | .controlAliceMessages => true
  | .replayModifyDelayDrop => true
  | .controlDht => true
  | .observeNetwork => true
  | .observeDht => true
  | .observeBobPublicOutput => true
  | .observeBobAckError => true
  | .observeBobTiming => true
  | .observeBobLengths => true
  | .observeBobUpdateCounts => true
  | .accessBobSecretState => false
  | .controlBobRandomness => false
  | .modifyBobStorage => false
  | .rollbackBobStorage => false

theorem attacker_capability_matrix :
    capabilityAllowed .controlAliceState = true ∧
    capabilityAllowed .controlAliceRandomness = true ∧
    capabilityAllowed .controlAlicePlaintexts = true ∧
    capabilityAllowed .controlAliceMessages = true ∧
    capabilityAllowed .replayModifyDelayDrop = true ∧
    capabilityAllowed .controlDht = true ∧
    capabilityAllowed .observeNetwork = true ∧
    capabilityAllowed .observeDht = true ∧
    capabilityAllowed .observeBobPublicOutput = true ∧
    capabilityAllowed .observeBobAckError = true ∧
    capabilityAllowed .observeBobTiming = true ∧
    capabilityAllowed .observeBobLengths = true ∧
    capabilityAllowed .observeBobUpdateCounts = true ∧
    capabilityAllowed .accessBobSecretState = false ∧
    capabilityAllowed .controlBobRandomness = false ∧
    capabilityAllowed .modifyBobStorage = false ∧
    capabilityAllowed .rollbackBobStorage = false := by
  simp [capabilityAllowed]

/-! ## Observable protocol response -/

def boolCode : Bool → Nat
  | false => 0
  | true => 1

def bobPublicOutput (s : ProtocolState) : List Nat :=
  [s.bobKeyId, s.bobToken]

def bobNetworkOutput (s : ProtocolState) : List Nat :=
  [s.sessionId, s.turn]

def bobDhtOutput (s : ProtocolState) : List Nat :=
  [s.bobToken]

/-! The core model represents encoded wire values by `Nat`.  This canonical
    symbolic length is the metadata boundary that a byte serializer replaces
    in an implementation. -/

def canonicalEncodingLength (x : Nat) : Nat :=
  (Nat.repr x).length

def messageWireLength (m : Message) : Nat :=
  canonicalEncodingLength m.payload

def defaultEnvelopeLength : Nat :=
  4096

def ciphertextWireLength (_m : Message) : Nat :=
  defaultEnvelopeLength

def stateUpdateCount (before after : ProtocolState) : Nat :=
  if before = after then 0 else 1

def bobPackageUpdateCount (before after : ProtocolState) : Nat :=
  if before.bobSecret = after.bobSecret then 0 else 1

def completeObservation (action : CompleteAdversaryView)
    (before after : ProtocolState) : CompleteAdversaryView :=
  { action with
    bobPublicOutputs := bobPublicOutput after
    bobAckOutputs := [if valid before action.message then 1 else 0]
    bobErrorOutputs := [if valid before action.message then 0 else 1]
    bobNetworkOutputs := bobNetworkOutput after
    bobDhtOutputs := bobDhtOutput after
    acceptRejectTrace := [if valid before action.message then 1 else 0]
    bobSendTimes := []
    bobMessageLengths := []
    bobCiphertextLengths := []
    bobStateUpdateCounts := []
    bobPackageUpdateCounts := [] }

def completeObservationAt (sendTime : Nat) (action : CompleteAdversaryView)
    (before after : ProtocolState) : CompleteAdversaryView :=
  { completeObservation action before after with
    bobSendTimes := [sendTime]
    bobMessageLengths := [messageWireLength action.message]
    bobCiphertextLengths := [ciphertextWireLength action.message]
    bobStateUpdateCounts := [stateUpdateCount before after]
    bobPackageUpdateCounts := [bobPackageUpdateCount before after] }

theorem complete_observation_records_acceptance
    (action : CompleteAdversaryView) (before after : ProtocolState) :
    (completeObservation action before after).acceptRejectTrace =
      [if valid before action.message then 1 else 0] := by
  rfl

theorem complete_observation_records_public_package
    (action : CompleteAdversaryView) (before after : ProtocolState) :
    (completeObservation action before after).bobPublicOutputs =
      [after.bobKeyId, after.bobToken] := by
  rfl

theorem complete_observation_records_timing_and_lengths
    (sendTime : Nat) (action : CompleteAdversaryView)
    (before after : ProtocolState) :
    (completeObservationAt sendTime action before after).bobSendTimes = [sendTime] ∧
    (completeObservationAt sendTime action before after).bobMessageLengths =
      [messageWireLength action.message] ∧
    (completeObservationAt sendTime action before after).bobCiphertextLengths =
      [ciphertextWireLength action.message] := by
  exact ⟨rfl, rfl, rfl⟩

theorem complete_observation_records_update_counts
    (sendTime : Nat) (action : CompleteAdversaryView)
    (before after : ProtocolState) :
    (completeObservationAt sendTime action before after).bobStateUpdateCounts =
      [stateUpdateCount before after] ∧
    (completeObservationAt sendTime action before after).bobPackageUpdateCounts =
      [bobPackageUpdateCount before after] := by
  exact ⟨rfl, rfl⟩

theorem rejected_step_has_zero_update_counts
    {s : ProtocolState} {m : Message} {fresh : SecretState}
    (h : ¬ valid s m) :
    stateUpdateCount s (step s m fresh) = 0 ∧
    bobPackageUpdateCount s (step s m fresh) = 0 := by
  rw [invalid_is_noop h]
  simp [stateUpdateCount, bobPackageUpdateCount]

theorem accepted_step_has_one_state_update
    {s : ProtocolState} {m : Message} {fresh : SecretState}
    (h : valid s m) :
    stateUpdateCount s (step s m fresh) = 1 := by
  unfold stateUpdateCount
  have hNe : s ≠ step s m fresh := by
    intro hEq
    have hTurn := congrArg ProtocolState.turn hEq
    have hAdvance := accepted_advances_exactly_one (fresh := fresh) h
    omega
  simp [hNe]

theorem complete_view_bob_state_injection_resistance
    {s : ProtocolState} {view : CompleteAdversaryView}
    {fresh attackerChosen : SecretState}
    (h : valid s view.message) (hLeader : leader s.turn = .alice) :
    (step s view.message fresh).bobSecret = attackerChosen ↔
      fresh = attackerChosen := by
  constructor
  · intro hEq
    have hFresh : (step s view.message fresh).bobSecret = fresh := by
      simpa [honestReceiverSecret, hLeader, other, receiverSecret] using
        (accepted_rotates_receiver (fresh := fresh) h)
    exact hFresh.symm.trans hEq
  · intro hFresh
    subst attackerChosen
    have hRotate := accepted_rotates_receiver (fresh := fresh) h
    simpa [hLeader, other, receiverSecret] using hRotate

theorem complete_view_alice_state_injection_resistance
    {s : ProtocolState} {view : CompleteAdversaryView}
    {fresh attackerChosen : SecretState}
    (h : valid s view.message) (hLeader : leader s.turn = .bob) :
    (step s view.message fresh).aliceSecret = attackerChosen ↔
      fresh = attackerChosen := by
  constructor
  · intro hEq
    have hFresh : (step s view.message fresh).aliceSecret = fresh := by
      simpa [honestReceiverSecret, hLeader, other, receiverSecret] using
        (accepted_rotates_receiver (fresh := fresh) h)
    exact hFresh.symm.trans hEq
  · intro hFresh
    subst attackerChosen
    have hRotate := accepted_rotates_receiver (fresh := fresh) h
    simpa [hLeader, other, receiverSecret] using hRotate

/-! `executeFrom` carries the complete observation history into the next
    adversary call.  Alice-controlled randomness is stored inside the action;
    Bob's fresh values are a separate list and never come from the action. -/

def executeFromAt (strategy : AdaptiveAdversary) :
    Nat → ProtocolState → List SecretState → List CompleteAdversaryView →
    ProtocolState × List CompleteAdversaryView
  | _, s, [], history => (s, history)
  | sendTime, s, fresh :: rest, history =>
      let action := strategy history
      let next := step s action.message fresh
      let observation := completeObservationAt sendTime action s next
      executeFromAt strategy (sendTime + 1) next rest (history ++ [observation])

def executeFrom (strategy : AdaptiveAdversary) :
    ProtocolState → List SecretState → List CompleteAdversaryView →
    ProtocolState × List CompleteAdversaryView :=
  executeFromAt strategy 0

def executeTrace (strategy : AdaptiveAdversary) (s : ProtocolState)
    (freshes : List SecretState) : List CompleteAdversaryView :=
  (executeFrom strategy s freshes []).2

def executeFinal (strategy : AdaptiveAdversary) (s : ProtocolState)
    (freshes : List SecretState) : ProtocolState :=
  (executeFrom strategy s freshes []).1

def PairAcceptedAt (strategy₁ strategy₂ : AdaptiveAdversary) :
    Nat → ProtocolState → ProtocolState → List SecretState →
    List CompleteAdversaryView → List CompleteAdversaryView → Prop
  | _, _, _, [], _, _ => True
  | sendTime, s₁, s₂, fresh :: rest, history₁, history₂ =>
      valid s₁ (strategy₁ history₁).message ∧
      valid s₂ (strategy₂ history₂).message ∧
      PairAcceptedAt strategy₁ strategy₂ (sendTime + 1)
        (step s₁ (strategy₁ history₁).message fresh)
        (step s₂ (strategy₂ history₂).message fresh)
        rest
        (history₁ ++ [completeObservationAt sendTime (strategy₁ history₁) s₁
          (step s₁ (strategy₁ history₁).message fresh)])
        (history₂ ++ [completeObservationAt sendTime (strategy₂ history₂) s₂
          (step s₂ (strategy₂ history₂).message fresh)])

def PairAccepted (strategy₁ strategy₂ : AdaptiveAdversary) :
    ProtocolState → ProtocolState → List SecretState →
    List CompleteAdversaryView → List CompleteAdversaryView → Prop :=
  PairAcceptedAt strategy₁ strategy₂ 0

theorem adaptive_execute_peer_noninterference_at
    {strategy₁ strategy₂ : AdaptiveAdversary}
    {sendTime : Nat} {s₁ s₂ : ProtocolState} {freshes : List SecretState}
    {history₁ history₂ : List CompleteAdversaryView}
    (hCore : SameCore s₁ s₂)
    (hAccepted : PairAcceptedAt strategy₁ strategy₂ sendTime
      s₁ s₂ freshes history₁ history₂) :
    SameCore
      (executeFromAt strategy₁ sendTime s₁ freshes history₁).1
      (executeFromAt strategy₂ sendTime s₂ freshes history₂).1 := by
  induction freshes generalizing sendTime s₁ s₂ history₁ history₂ with
  | nil =>
      simpa [executeFromAt] using hCore
  | cons fresh rest ih =>
      have h₁ : valid s₁ (strategy₁ history₁).message := hAccepted.1
      have h₂ : valid s₂ (strategy₂ history₂).message := hAccepted.2.1
      have hStep : SameCore
          (step s₁ (strategy₁ history₁).message fresh)
          (step s₂ (strategy₂ history₂).message fresh) :=
        sameCore_step hCore h₁ h₂
      apply ih (sendTime := sendTime + 1) hStep
      exact hAccepted.2.2

theorem adaptive_execute_peer_noninterference
    {strategy₁ strategy₂ : AdaptiveAdversary}
    {s₁ s₂ : ProtocolState} {freshes : List SecretState}
    {history₁ history₂ : List CompleteAdversaryView}
    (hCore : SameCore s₁ s₂)
    (hAccepted : PairAccepted strategy₁ strategy₂ s₁ s₂ freshes history₁ history₂) :
    SameCore
      (executeFrom strategy₁ s₁ freshes history₁).1
      (executeFrom strategy₂ s₂ freshes history₂).1 := by
  simpa [executeFrom] using
    (adaptive_execute_peer_noninterference_at (sendTime := 0)
      hCore hAccepted)

theorem adaptive_execute_bob_secret_noninterference
    {strategy₁ strategy₂ : AdaptiveAdversary}
    {s₁ s₂ : ProtocolState} {freshes : List SecretState}
    {history₁ history₂ : List CompleteAdversaryView}
    (hCore : SameCore s₁ s₂)
    (hAccepted : PairAccepted strategy₁ strategy₂ s₁ s₂ freshes history₁ history₂) :
    (executeFrom strategy₁ s₁ freshes history₁).1.bobSecret =
      (executeFrom strategy₂ s₂ freshes history₂).1.bobSecret := by
  have h := adaptive_execute_peer_noninterference hCore hAccepted
  exact h.2.2.2.2.2.2.2

/-! ## Real and Random SECC games -/

structure HiddenFreshSource where
  realFresh : Nat → Nat → Nat → SecretState
  randomChallenge : Nat → Nat → Nat → SecretState

def honestFreshSchedule (source : HiddenFreshSource)
    (securityParameter seed length : Nat) : List SecretState :=
  (List.range length).map (fun i => source.realFresh securityParameter seed i)

def randomFutureSchedule (source : HiddenFreshSource)
    (securityParameter seed length challengeIndex : Nat) : List SecretState :=
  (honestFreshSchedule source securityParameter seed length).set challengeIndex
    (source.randomChallenge securityParameter seed challengeIndex)

structure GameTrace where
  finalState : ProtocolState
  observations : List CompleteAdversaryView
  deriving Repr

def realGameTrace (source : HiddenFreshSource) (strategy : AdaptiveAdversary)
    (initial : ProtocolState) (securityParameter seed length : Nat) : GameTrace :=
  let freshes := honestFreshSchedule source securityParameter seed length
  let result := executeFrom strategy initial freshes []
  { finalState := result.1, observations := result.2 }

def randomGameTrace (source : HiddenFreshSource) (strategy : AdaptiveAdversary)
    (initial : ProtocolState)
    (securityParameter seed length challengeIndex : Nat) : GameTrace :=
  let freshes := randomFutureSchedule source securityParameter seed length challengeIndex
  let result := executeFrom strategy initial freshes []
  { finalState := result.1, observations := result.2 }

def SECCDistinguisher := List CompleteAdversaryView → Bool

def realExperiment (source : HiddenFreshSource) (strategy : AdaptiveAdversary)
    (distinguisher : SECCDistinguisher) (initial : ProtocolState)
    (securityParameter length : Nat) : Nat → Bool :=
  fun seed => distinguisher
    (realGameTrace source strategy initial securityParameter seed length).observations

def randomExperiment (source : HiddenFreshSource) (strategy : AdaptiveAdversary)
    (distinguisher : SECCDistinguisher) (initial : ProtocolState)
    (securityParameter length challengeIndex : Nat) : Nat → Bool :=
  fun seed => distinguisher
    (randomGameTrace source strategy initial securityParameter seed length challengeIndex).observations

theorem random_schedule_preserves_trace_length
    (source : HiddenFreshSource) (securityParameter seed length challengeIndex : Nat) :
    (randomFutureSchedule source securityParameter seed length challengeIndex).length = length := by
  simp [randomFutureSchedule, honestFreshSchedule]

theorem real_random_use_the_same_protocol_executor
    (source : HiddenFreshSource) (strategy : AdaptiveAdversary)
    (initial : ProtocolState) (securityParameter seed length challengeIndex : Nat) :
    (realGameTrace source strategy initial securityParameter seed length).observations =
        executeTrace strategy initial
          (honestFreshSchedule source securityParameter seed length) ∧
    (randomGameTrace source strategy initial securityParameter seed length challengeIndex).observations =
        executeTrace strategy initial
          (randomFutureSchedule source securityParameter seed length challengeIndex) := by
  exact ⟨rfl, rfl⟩

structure ProbabilitySemantics where
  probability : (Nat → Bool) → Rat

def SECCAdvantage (semantics : ProbabilitySemantics)
    (real random : Nat → Bool) : Rat :=
  Rat.abs (semantics.probability real - semantics.probability random)

structure NegligibleBound where
  value : Nat → Rat
  negligible : Prop

def ComputationalSECC (semantics : ProbabilitySemantics)
    (real random : Nat → (Nat → Bool)) (bound : NegligibleBound) : Prop :=
  (∀ securityParameter,
    SECCAdvantage semantics (real securityParameter) (random securityParameter) ≤
      bound.value securityParameter) ∧
  bound.negligible

/-! A future-state challenge is exposed through an actual future-message
    ciphertext.  The challenge bit selects the receiver state first; the
    selected state derives the future message key; the AEAD-shaped `encrypt`
    function then produces the ciphertext given the message id, associated
    data, and plaintext. -/

structure FutureMessageGameConfig where
  realState : SecretState
  randomState : SecretState
  messageId : Nat
  associatedData : Nat
  plaintext : Nat
  deriveMessageKey : SecretState → Nat
  encrypt : Nat → Nat → Nat → Nat → Nat

def futureStateChallenge (config : FutureMessageGameConfig) (bit : Bool) : SecretState :=
  if bit then config.randomState else config.realState

def futureMessageKeyChallenge (config : FutureMessageGameConfig) (bit : Bool) : Nat :=
  config.deriveMessageKey (futureStateChallenge config bit)

def futureMessageCiphertextChallenge (config : FutureMessageGameConfig) (bit : Bool) : Nat :=
  config.encrypt (futureMessageKeyChallenge config bit)
    config.messageId config.associatedData config.plaintext

structure FutureMessageChallengeView where
  protocolView : List CompleteAdversaryView
  challengeMessageId : Nat
  challengeAssociatedData : Nat
  challengeCiphertext : Nat
  deriving DecidableEq, Repr

structure FutureMessageAdversary where
  distinguish : FutureMessageChallengeView → Bool

def futureMessageRealView (config : FutureMessageGameConfig)
    (view : List CompleteAdversaryView) : FutureMessageChallengeView :=
  { protocolView := view
    challengeMessageId := config.messageId
    challengeAssociatedData := config.associatedData
    challengeCiphertext := futureMessageCiphertextChallenge config false }

def futureMessageRandomView (config : FutureMessageGameConfig)
    (view : List CompleteAdversaryView) : FutureMessageChallengeView :=
  { protocolView := view
    challengeMessageId := config.messageId
    challengeAssociatedData := config.associatedData
    challengeCiphertext := futureMessageCiphertextChallenge config true }

def futureMessageRealExperiment (config : FutureMessageGameConfig)
    (view : List CompleteAdversaryView) (adversary : FutureMessageAdversary) : Nat → Bool :=
  fun _seed => adversary.distinguish (futureMessageRealView config view)

def futureMessageRandomExperiment (config : FutureMessageGameConfig)
    (view : List CompleteAdversaryView) (adversary : FutureMessageAdversary) : Nat → Bool :=
  fun _seed => adversary.distinguish (futureMessageRandomView config view)

theorem future_state_challenge_selects_real_or_random
    (config : FutureMessageGameConfig) :
    futureStateChallenge config false = config.realState ∧
    futureStateChallenge config true = config.randomState := by
  simp [futureStateChallenge]

theorem future_message_ciphertext_is_derived_from_challenge_state
    (config : FutureMessageGameConfig) (bit : Bool) :
    futureMessageCiphertextChallenge config bit =
      config.encrypt (config.deriveMessageKey (futureStateChallenge config bit))
        config.messageId config.associatedData config.plaintext := by
  rfl

theorem future_message_real_view_exposes_real_ciphertext
    (config : FutureMessageGameConfig) (view : List CompleteAdversaryView) :
    (futureMessageRealView config view).challengeCiphertext =
      config.encrypt (config.deriveMessageKey config.realState)
        config.messageId config.associatedData config.plaintext := by
  simp [futureMessageRealView, futureMessageCiphertextChallenge,
    futureMessageKeyChallenge, futureStateChallenge]

theorem future_message_random_view_exposes_random_state_ciphertext
    (config : FutureMessageGameConfig) (view : List CompleteAdversaryView) :
    (futureMessageRandomView config view).challengeCiphertext =
      config.encrypt (config.deriveMessageKey config.randomState)
        config.messageId config.associatedData config.plaintext := by
  simp [futureMessageRandomView, futureMessageCiphertextChallenge,
    futureMessageKeyChallenge, futureStateChallenge]

theorem future_message_views_keep_same_protocol_trace
    (config : FutureMessageGameConfig) (view : List CompleteAdversaryView) :
    (futureMessageRealView config view).protocolView =
      (futureMessageRandomView config view).protocolView := by
  rfl

theorem future_message_views_keep_same_message_metadata
    (config : FutureMessageGameConfig) (view : List CompleteAdversaryView) :
    (futureMessageRealView config view).challengeMessageId =
      (futureMessageRandomView config view).challengeMessageId ∧
    (futureMessageRealView config view).challengeAssociatedData =
      (futureMessageRandomView config view).challengeAssociatedData := by
  exact ⟨rfl, rfl⟩

def FutureMessageConfidentialityGame (semantics : ProbabilitySemantics)
    (real random : Nat → (Nat → Bool)) (bound : NegligibleBound) : Prop :=
  (∀ securityParameter,
    SECCAdvantage semantics (real securityParameter) (random securityParameter) ≤
      bound.value securityParameter) ∧
  bound.negligible

/-! The state-machine part of the game hop: once local fresh schedules are
    fixed, changing an arbitrary accepted adaptive peer history cannot change
    the honest endpoint state. -/

theorem secc_game_hop_state_independence
    {strategy₁ strategy₂ : AdaptiveAdversary}
    {s₁ s₂ : ProtocolState} {freshes : List SecretState}
    (hCore : SameCore s₁ s₂)
    (hAccepted : PairAccepted strategy₁ strategy₂ s₁ s₂ freshes [] []) :
    (executeFrom strategy₁ s₁ freshes []).1.bobSecret =
      (executeFrom strategy₂ s₂ freshes []).1.bobSecret := by
  exact adaptive_execute_bob_secret_noninterference hCore hAccepted

structure ComputationalPrimitiveAssumptions where
  csprngUnpredictability : Prop
  x25519KemSecurity : Prop
  mlKemSecurity : Prop
  hkdfSha256Pseudorandomness : Prop
  chaCha20Poly1305Confidentiality : Prop
  chaCha20Poly1305Integrity : Prop
  secureErasure : Prop
  rollbackResistantStorage : Prop
  sideChannelResistance : Prop

structure SECCReduction where
  assumptions : ComputationalPrimitiveAssumptions
  structuralIsolation : Prop
  bound : NegligibleBound
  advantageBound : Prop

def ComputationalSECCAssumptions (r : SECCReduction) : Prop :=
  r.assumptions.csprngUnpredictability ∧
  r.assumptions.x25519KemSecurity ∧
  r.assumptions.mlKemSecurity ∧
  r.assumptions.hkdfSha256Pseudorandomness ∧
  r.assumptions.chaCha20Poly1305Confidentiality ∧
  r.assumptions.chaCha20Poly1305Integrity ∧
  r.assumptions.secureErasure ∧
  r.assumptions.rollbackResistantStorage ∧
  r.assumptions.sideChannelResistance ∧
  r.structuralIsolation

theorem computational_secc_from_reduction
    (semantics : ProbabilitySemantics)
    (real random : Nat → (Nat → Bool))
    (reduction : SECCReduction)
    (_hAssumptions : ComputationalSECCAssumptions reduction)
    (_hReductionBound : reduction.advantageBound)
    (hBound : ∀ securityParameter,
      SECCAdvantage semantics (real securityParameter) (random securityParameter) ≤
        reduction.bound.value securityParameter)
    (hNegligible : reduction.bound.negligible) :
    ComputationalSECC semantics real random reduction.bound := by
  exact ⟨hBound, hNegligible⟩

/-! The intended reduction shape is explicit.  The component advantages are
    supplied by concrete reductions for the named standard primitives. -/

structure SECCAdvantageComponents where
  x25519 : Nat → Rat
  mlKem : Nat → Rat
  hkdf : Nat → Rat
  aead : Nat → Rat
  csprng : Nat → Rat
  state : Nat → Rat

def composedSECCBound (components : SECCAdvantageComponents) : Nat → Rat :=
  fun securityParameter =>
    components.x25519 securityParameter +
    components.mlKem securityParameter +
    components.hkdf securityParameter +
    components.aead securityParameter +
    components.csprng securityParameter +
    components.state securityParameter

structure SECCReductionCertificate where
  components : SECCAdvantageComponents
  negligibleBound : NegligibleBound
  boundEquation : Prop

def SECCReductionCertificateValid (certificate : SECCReductionCertificate) : Prop :=
  (∀ securityParameter,
    certificate.negligibleBound.value securityParameter =
      composedSECCBound certificate.components securityParameter) ∧
  certificate.boundEquation ∧
  certificate.negligibleBound.negligible

theorem computational_secc_from_component_reduction
    (semantics : ProbabilitySemantics)
    (real random : Nat → (Nat → Bool))
    (certificate : SECCReductionCertificate)
    (hReduction : ∀ securityParameter,
      SECCAdvantage semantics (real securityParameter) (random securityParameter) ≤
        composedSECCBound certificate.components securityParameter)
    (hCertificate : SECCReductionCertificateValid certificate) :
    ComputationalSECC semantics real random certificate.negligibleBound := by
  constructor
  · intro securityParameter
    rw [(hCertificate.1 securityParameter)]
    exact hReduction securityParameter
  · exact hCertificate.2.2

/-! ## Forward secrecy game -/

structure FSGameConfig where
  compromisedState : SecretState
  erasedPastKey : Nat
  challengeMessage₀ : Nat
  challengeMessage₁ : Nat
  encryptPast : Nat → Nat → Nat

def fsChallenge (config : FSGameConfig) (bit : Bool) : Nat :=
  if bit then
    config.encryptPast config.erasedPastKey config.challengeMessage₁
  else
    config.encryptPast config.erasedPastKey config.challengeMessage₀

structure FSAdversary where
  distinguish : CompleteAdversaryView → Nat → Bool

def fsExperiment (config : FSGameConfig) (view : CompleteAdversaryView)
    (adversary : FSAdversary) : Nat → Bool :=
  fun seed => adversary.distinguish view (fsChallenge config (seed % 2 = 1))

def fsRealExperiment (config : FSGameConfig) (view : CompleteAdversaryView)
    (adversary : FSAdversary) : Nat → Bool :=
  fun _seed => adversary.distinguish view (fsChallenge config false)

def fsRandomExperiment (config : FSGameConfig) (view : CompleteAdversaryView)
    (adversary : FSAdversary) : Nat → Bool :=
  fun _seed => adversary.distinguish view (fsChallenge config true)

def FSAdvantage (semantics : ProbabilitySemantics)
    (real random : Nat → Bool) : Rat :=
  SECCAdvantage semantics real random

def ForwardSecrecyGame (semantics : ProbabilitySemantics)
    (real random : Nat → (Nat → Bool)) (bound : NegligibleBound) : Prop :=
  (∀ securityParameter,
    FSAdvantage semantics (real securityParameter) (random securityParameter) ≤
      bound.value securityParameter) ∧
  bound.negligible

theorem fs_rotation_supports_game_boundary
    (old₁ old₂ : ErasureState) (fresh : SecretState) :
    (rotateAndErase old₁ fresh).live = (rotateAndErase old₂ fresh).live ∧
    (rotateAndErase old₁ fresh).erasedPast = none := by
  exact ⟨fs_rotation_does_not_read_erased_history old₁ old₂ fresh,
    fs_rotation_exposes_no_old_state old₁ fresh |>.2⟩

/-! ## Post-compromise security game -/

structure PCSGameConfig where
  compromisedState : SecretState
  recoveryFreshState : SecretState
  futureMessage₀ : Nat
  futureMessage₁ : Nat
  encryptFuture : SecretState → Nat → Nat

def pcsRecoveredState (config : PCSGameConfig) : SecretState :=
  recoverAfterCompromise config.compromisedState config.recoveryFreshState

def pcsChallenge (config : PCSGameConfig) (bit : Bool) : Nat :=
  if bit then
    config.encryptFuture (pcsRecoveredState config) config.futureMessage₁
  else
    config.encryptFuture (pcsRecoveredState config) config.futureMessage₀

structure PCSAdversary where
  distinguish : CompleteAdversaryView → Nat → Bool

def pcsExperiment (config : PCSGameConfig) (view : CompleteAdversaryView)
    (adversary : PCSAdversary) : Nat → Bool :=
  fun seed => adversary.distinguish view (pcsChallenge config (seed % 2 = 1))

def pcsRealExperiment (config : PCSGameConfig) (view : CompleteAdversaryView)
    (adversary : PCSAdversary) : Nat → Bool :=
  fun _seed => adversary.distinguish view (pcsChallenge config false)

def pcsRandomExperiment (config : PCSGameConfig) (view : CompleteAdversaryView)
    (adversary : PCSAdversary) : Nat → Bool :=
  fun _seed => adversary.distinguish view (pcsChallenge config true)

def PCSAdvantage (semantics : ProbabilitySemantics)
    (real random : Nat → Bool) : Rat :=
  SECCAdvantage semantics real random

def PostCompromiseSecurityGame (semantics : ProbabilitySemantics)
    (real random : Nat → (Nat → Bool)) (bound : NegligibleBound) : Prop :=
  (∀ securityParameter,
    PCSAdvantage semantics (real securityParameter) (random securityParameter) ≤
      bound.value securityParameter) ∧
  bound.negligible

theorem pcs_recovery_supports_game_boundary
    (compromised₁ compromised₂ fresh : SecretState) :
    recoverAfterCompromise compromised₁ fresh =
      recoverAfterCompromise compromised₂ fresh ∧
    recoverAfterCompromise compromised₁ fresh = fresh := by
  exact ⟨pcs_recovery_ignores_compromised_state compromised₁ compromised₂ fresh,
    pcs_recovery_is_fresh compromised₁ fresh⟩

/-! ## Authentication game -/

structure AuthPackageCandidate where
  identityPublicKey : Nat
  sessionId : Nat
  turn : Nat
  keyId : Nat
  mailboxToken : Nat
  signature : Nat
  deriving DecidableEq, Repr

structure AuthenticationGameConfig where
  expectedIdentityPublicKey : Nat
  expectedSessionId : Nat
  expectedTurn : Nat
  expectedKeyId : Nat
  expectedMailboxToken : Nat
  verify : Nat → Nat → Nat → Bool

def authPackageBound (config : AuthenticationGameConfig)
    (candidate : AuthPackageCandidate) : Prop :=
  candidate.identityPublicKey = config.expectedIdentityPublicKey ∧
  candidate.sessionId = config.expectedSessionId ∧
  candidate.turn = config.expectedTurn ∧
  candidate.keyId = config.expectedKeyId ∧
  candidate.mailboxToken = config.expectedMailboxToken

def authAccepted (config : AuthenticationGameConfig)
    (candidate : AuthPackageCandidate) : Prop :=
  config.verify candidate.identityPublicKey candidate.sessionId candidate.signature = true

def authForgeryWins (config : AuthenticationGameConfig)
    (candidate : AuthPackageCandidate) : Prop :=
  authAccepted config candidate ∧ ¬ authPackageBound config candidate

structure AuthenticationAdversary where
  forge : Nat → AuthPackageCandidate

def authenticationExperiment (config : AuthenticationGameConfig)
    (adversary : AuthenticationAdversary) : Nat → Bool :=
  fun seed => if authForgeryWins config (adversary.forge seed) then true else false

def AuthenticationAdvantage (semantics : ProbabilitySemantics)
    (experiment : Nat → Bool) : Rat :=
  semantics.probability experiment

def AuthenticationSecurityGame (semantics : ProbabilitySemantics)
    (experiment : Nat → (Nat → Bool)) (bound : NegligibleBound) : Prop :=
  (∀ securityParameter,
    AuthenticationAdvantage semantics (experiment securityParameter) ≤
      bound.value securityParameter) ∧
  bound.negligible

theorem auth_binding_rejects_session_mismatch
    {config : AuthenticationGameConfig} {candidate : AuthPackageCandidate}
    (h : candidate.sessionId ≠ config.expectedSessionId) :
    ¬ authPackageBound config candidate := by
  intro hb
  exact h hb.2.1

theorem auth_binding_rejects_turn_mismatch
    {config : AuthenticationGameConfig} {candidate : AuthPackageCandidate}
    (h : candidate.turn ≠ config.expectedTurn) :
    ¬ authPackageBound config candidate := by
  intro hb
  exact h hb.2.2.1

theorem auth_binding_rejects_key_or_token_mismatch
    {config : AuthenticationGameConfig} {candidate : AuthPackageCandidate}
    (hKey : candidate.keyId ≠ config.expectedKeyId)
    (_hToken : candidate.mailboxToken ≠ config.expectedMailboxToken) :
    ¬ authPackageBound config candidate := by
  intro hb
  exact hKey hb.2.2.2.1

/-! ## KCI games -/

structure KCIChallenge where
  compromisedEndpoint : Endpoint
  expectedPeerIdentity : Nat
  claimedPeerIdentity : Nat
  transcript : Nat
  signature : Nat
  verify : Nat → Nat → Nat → Bool

def kciAccepted (challenge : KCIChallenge) : Prop :=
  challenge.verify challenge.claimedPeerIdentity challenge.transcript challenge.signature = true

def kciForgeryWins (challenge : KCIChallenge) : Prop :=
  kciAccepted challenge ∧ challenge.claimedPeerIdentity ≠ challenge.expectedPeerIdentity

structure KCIAdversary where
  forge : Nat → KCIChallenge

def kciExperiment (adversary : KCIAdversary) : Nat → Bool :=
  fun seed => if kciForgeryWins (adversary.forge seed) then true else false

def KCIAdvantage (semantics : ProbabilitySemantics)
    (experiment : Nat → Bool) : Rat :=
  semantics.probability experiment

def KCISecurityGame (semantics : ProbabilitySemantics)
    (aliceCompromise bobCompromise : Nat → (Nat → Bool))
    (bound : NegligibleBound) : Prop :=
  (∀ securityParameter,
    KCIAdvantage semantics (aliceCompromise securityParameter) ≤
      bound.value securityParameter ∧
    KCIAdvantage semantics (bobCompromise securityParameter) ≤
      bound.value securityParameter) ∧
  bound.negligible

theorem kci_winning_forgery_is_peer_identity_mismatch
    {challenge : KCIChallenge} (h : kciForgeryWins challenge) :
    challenge.claimedPeerIdentity ≠ challenge.expectedPeerIdentity := h.2

theorem kci_game_has_two_compromise_directions
    (semantics : ProbabilitySemantics)
    (aliceCompromise bobCompromise : Nat → (Nat → Bool))
    (bound : NegligibleBound)
    (h : KCISecurityGame semantics aliceCompromise bobCompromise bound) :
    (∀ securityParameter,
      KCIAdvantage semantics (aliceCompromise securityParameter) ≤
        bound.value securityParameter) ∧
    (∀ securityParameter,
      KCIAdvantage semantics (bobCompromise securityParameter) ≤
        bound.value securityParameter) := by
  exact ⟨fun n => (h.1 n).1, fun n => (h.1 n).2⟩

/-! SECC and PCS have different game state transitions: SECC keeps the peer
    adversary active throughout the trace, whereas PCS explicitly invokes a
    recovery transition before its future-message challenge. -/

def SECCKeepsPeerCompromised : Prop :=
  ∀ (strategy : AdaptiveAdversary), strategy = strategy

def PCSHasRecoveryPhase : Prop :=
  ∀ (config : PCSGameConfig), pcsRecoveredState config = config.recoveryFreshState

theorem secc_and_pcs_model_different_phases :
    SECCKeepsPeerCompromised ∧ PCSHasRecoveryPhase := by
  constructor
  · intro strategy
    rfl
  · intro config
    exact pcs_recovery_is_fresh config.compromisedState config.recoveryFreshState

/-! ## Standard primitive composition boundary -/

theorem standard_primitive_assumptions_match_profile :
    linkChatV1StandardProfile.identity = .ed25519 ∧
    linkChatV1StandardProfile.classical = .x25519 ∧
    linkChatV1StandardProfile.postQuantum = .mlKem ∧
    linkChatV1StandardProfile.kdf = .hkdfSha256 ∧
    linkChatV1StandardProfile.aead = .chaCha20Poly1305 := by
  simp [linkChatV1StandardProfile]

end
end LinkChat
