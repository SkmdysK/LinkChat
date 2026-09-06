import Std
import ComputationalGames
import ConcreteSECCReduction

namespace LinkChat

noncomputable section

/-!
  Concrete reduction layer for the remaining security games.

  The endpoint games are supplied by the protocol/game definitions.  The
  middle games are the standard hybrids used by the reduction.  This file
  proves the arithmetic composition of their explicit per-hop advantages and
  connects the result to the existing FS, PCS, Authentication, and KCI
  predicates.
-/

structure FourHopGames where
  real : ExperimentFamily
  hop₁ : ExperimentFamily
  hop₂ : ExperimentFamily
  hop₃ : ExperimentFamily
  random : ExperimentFamily

theorem rat_add_left_mono
    {a b c : Rat} (h : a ≤ b) : c + a ≤ c + b := by
  exact (Rat.add_le_add_left).2 h

theorem four_hop_advantage_bound
    (laws : ProbabilitySemanticsLaws) (games : FourHopGames)
    (securityParameter : Nat)
    (e₁ e₂ e₃ e₄ : Rat)
    (h₁ : hopAdvantage laws games.real games.hop₁ securityParameter ≤ e₁)
    (h₂ : hopAdvantage laws games.hop₁ games.hop₂ securityParameter ≤ e₂)
    (h₃ : hopAdvantage laws games.hop₂ games.hop₃ securityParameter ≤ e₃)
    (h₄ : hopAdvantage laws games.hop₃ games.random securityParameter ≤ e₄) :
    hopAdvantage laws games.real games.random securityParameter ≤
      e₁ + (e₂ + (e₃ + e₄)) := by
  have h₃₄ : hopAdvantage laws games.hop₂ games.random securityParameter ≤
      e₃ + e₄ := by
    exact Rat.le_trans
      (hop_triangle laws games.hop₂ games.hop₃ games.random securityParameter)
      (rat_add_mono h₃ h₄)
  have h₂₄ : hopAdvantage laws games.hop₁ games.random securityParameter ≤
      e₂ + (e₃ + e₄) := by
    exact Rat.le_trans
      (hop_triangle laws games.hop₁ games.hop₂ games.random securityParameter)
      (rat_add_mono h₂ h₃₄)
  exact Rat.le_trans
    (hop_triangle laws games.real games.hop₁ games.random securityParameter)
    (rat_add_mono h₁ h₂₄)

def twoHopAdvantageBound (e₁ e₂ : Nat → Rat) : Nat → Rat :=
  fun securityParameter => e₁ securityParameter + e₂ securityParameter

theorem two_hop_advantage_bound
    (laws : ProbabilitySemanticsLaws)
    (first middle last : ExperimentFamily)
    (securityParameter : Nat)
    (e₁ e₂ : Rat)
    (h₁ : hopAdvantage laws first middle securityParameter ≤ e₁)
    (h₂ : hopAdvantage laws middle last securityParameter ≤ e₂) :
    hopAdvantage laws first last securityParameter ≤ e₁ + e₂ := by
  exact Rat.le_trans
    (hop_triangle laws first middle last securityParameter)
    (rat_add_mono h₁ h₂)

/-! ## Forward secrecy reduction -/

structure FSReductionComponents where
  erasure : Nat → Rat
  keyDerivation : Nat → Rat
  aead : Nat → Rat
  randomness : Nat → Rat

def composedFSBound (components : FSReductionComponents) : Nat → Rat :=
  fun securityParameter =>
    components.erasure securityParameter +
    (components.keyDerivation securityParameter +
      (components.aead securityParameter + components.randomness securityParameter))

structure ConcreteFSReduction where
  laws : ProbabilitySemanticsLaws
  games : FourHopGames
  components : FSReductionComponents
  erasureHop : ∀ securityParameter,
    hopAdvantage laws games.real games.hop₁ securityParameter ≤
      components.erasure securityParameter
  keyDerivationHop : ∀ securityParameter,
    hopAdvantage laws games.hop₁ games.hop₂ securityParameter ≤
      components.keyDerivation securityParameter
  aeadHop : ∀ securityParameter,
    hopAdvantage laws games.hop₂ games.hop₃ securityParameter ≤
      components.aead securityParameter
  randomnessHop : ∀ securityParameter,
    hopAdvantage laws games.hop₃ games.random securityParameter ≤
      components.randomness securityParameter
  negligible : Prop
  negligibleProof : negligible

theorem concrete_fs_advantage_bound
    (reduction : ConcreteFSReduction) (securityParameter : Nat) :
    hopAdvantage reduction.laws reduction.games.real reduction.games.random
        securityParameter ≤ composedFSBound reduction.components securityParameter := by
  exact four_hop_advantage_bound reduction.laws reduction.games securityParameter
    (reduction.components.erasure securityParameter)
    (reduction.components.keyDerivation securityParameter)
    (reduction.components.aead securityParameter)
    (reduction.components.randomness securityParameter)
    (reduction.erasureHop securityParameter)
    (reduction.keyDerivationHop securityParameter)
    (reduction.aeadHop securityParameter)
    (reduction.randomnessHop securityParameter)

theorem concrete_forward_secrecy_reduction
    (reduction : ConcreteFSReduction) :
    ForwardSecrecyGame reduction.laws.semantics
      reduction.games.real reduction.games.random
      { value := composedFSBound reduction.components
        negligible := reduction.negligible } := by
  constructor
  · exact concrete_fs_advantage_bound reduction
  · exact reduction.negligibleProof

/-! ## Post-compromise security reduction -/

structure PCSReductionComponents where
  recovery : Nat → Rat
  x25519 : Nat → Rat
  mlKem : Nat → Rat
  hkdf : Nat → Rat
  aead : Nat → Rat
  randomness : Nat → Rat

def composedPCSBound (components : PCSReductionComponents) : Nat → Rat :=
  fun securityParameter =>
    components.recovery securityParameter +
    (components.x25519 securityParameter +
      (components.mlKem securityParameter +
        (components.hkdf securityParameter +
          (components.aead securityParameter + components.randomness securityParameter))))

structure ConcretePCSReduction where
  laws : ProbabilitySemanticsLaws
  games : FourHopGames
  components : PCSReductionComponents
  recoveryHop : ∀ securityParameter,
    hopAdvantage laws games.real games.hop₁ securityParameter ≤
      components.recovery securityParameter
  x25519Hop : ∀ securityParameter,
    hopAdvantage laws games.hop₁ games.hop₂ securityParameter ≤
      components.x25519 securityParameter
  mlKemHop : ∀ securityParameter,
    hopAdvantage laws games.hop₂ games.hop₃ securityParameter ≤
      components.mlKem securityParameter
  hkdfAeadRandomHop : ∀ securityParameter,
    hopAdvantage laws games.hop₃ games.random securityParameter ≤
      components.hkdf securityParameter +
        (components.aead securityParameter + components.randomness securityParameter)
  negligible : Prop
  negligibleProof : negligible

theorem concrete_pcs_advantage_bound
    (reduction : ConcretePCSReduction) (securityParameter : Nat) :
    hopAdvantage reduction.laws reduction.games.real reduction.games.random
        securityParameter ≤ composedPCSBound reduction.components securityParameter := by
  have hTail :
      hopAdvantage reduction.laws reduction.games.hop₃ reduction.games.random securityParameter ≤
        reduction.components.hkdf securityParameter +
          (reduction.components.aead securityParameter + reduction.components.randomness securityParameter) :=
    reduction.hkdfAeadRandomHop securityParameter
  have hThree :
      hopAdvantage reduction.laws reduction.games.hop₂ reduction.games.random securityParameter ≤
        reduction.components.mlKem securityParameter +
          (reduction.components.hkdf securityParameter +
            (reduction.components.aead securityParameter + reduction.components.randomness securityParameter)) := by
    exact Rat.le_trans
      (hop_triangle reduction.laws reduction.games.hop₂ reduction.games.hop₃
        reduction.games.random securityParameter)
      (rat_add_mono (reduction.mlKemHop securityParameter) hTail)
  have hTwo :
      hopAdvantage reduction.laws reduction.games.hop₁ reduction.games.random securityParameter ≤
        reduction.components.x25519 securityParameter +
          (reduction.components.mlKem securityParameter +
            (reduction.components.hkdf securityParameter +
              (reduction.components.aead securityParameter + reduction.components.randomness securityParameter))) := by
    exact Rat.le_trans
      (hop_triangle reduction.laws reduction.games.hop₁ reduction.games.hop₂
        reduction.games.random securityParameter)
      (rat_add_mono (reduction.x25519Hop securityParameter) hThree)
  exact Rat.le_trans
    (hop_triangle reduction.laws reduction.games.real reduction.games.hop₁
      reduction.games.random securityParameter)
    (rat_add_mono (reduction.recoveryHop securityParameter) hTwo)

theorem concrete_post_compromise_reduction
    (reduction : ConcretePCSReduction) :
    PostCompromiseSecurityGame reduction.laws.semantics
      reduction.games.real reduction.games.random
      { value := composedPCSBound reduction.components
        negligible := reduction.negligible } := by
  constructor
  · exact concrete_pcs_advantage_bound reduction
  · exact reduction.negligibleProof

/-! ## Authentication reduction -/

structure AuthenticationReductionComponents where
  ed25519 : Nat → Rat
  packageBinding : Nat → Rat

def composedAuthenticationBound
    (components : AuthenticationReductionComponents) : Nat → Rat :=
  fun securityParameter =>
    components.ed25519 securityParameter + components.packageBinding securityParameter

structure ConcreteAuthenticationReduction where
  semantics : ProbabilitySemantics
  experiment : Nat → (Nat → Bool)
  components : AuthenticationReductionComponents
  signatureAndBindingReduction : ∀ securityParameter,
    AuthenticationAdvantage semantics (experiment securityParameter) ≤
      composedAuthenticationBound components securityParameter
  negligible : Prop
  negligibleProof : negligible

theorem concrete_authentication_advantage_bound
    (reduction : ConcreteAuthenticationReduction) (securityParameter : Nat) :
    AuthenticationAdvantage reduction.semantics
        (reduction.experiment securityParameter) ≤
      composedAuthenticationBound reduction.components securityParameter :=
  reduction.signatureAndBindingReduction securityParameter

theorem concrete_authentication_reduction
    (reduction : ConcreteAuthenticationReduction) :
    AuthenticationSecurityGame reduction.semantics reduction.experiment
      { value := composedAuthenticationBound reduction.components
        negligible := reduction.negligible } := by
  constructor
  · exact concrete_authentication_advantage_bound reduction
  · exact reduction.negligibleProof

/-! ## KCI reduction in both compromise directions -/

structure KCIReductionComponents where
  ed25519 : Nat → Rat
  transcriptBinding : Nat → Rat

def composedKCIBound (components : KCIReductionComponents) : Nat → Rat :=
  fun securityParameter =>
    components.ed25519 securityParameter + components.transcriptBinding securityParameter

structure ConcreteKCIReduction where
  semantics : ProbabilitySemantics
  aliceCompromise : Nat → (Nat → Bool)
  bobCompromise : Nat → (Nat → Bool)
  components : KCIReductionComponents
  aliceReduction : ∀ securityParameter,
    KCIAdvantage semantics (aliceCompromise securityParameter) ≤
      composedKCIBound components securityParameter
  bobReduction : ∀ securityParameter,
    KCIAdvantage semantics (bobCompromise securityParameter) ≤
      composedKCIBound components securityParameter
  negligible : Prop
  negligibleProof : negligible

theorem concrete_kci_alice_advantage_bound
    (reduction : ConcreteKCIReduction) (securityParameter : Nat) :
    KCIAdvantage reduction.semantics (reduction.aliceCompromise securityParameter) ≤
      composedKCIBound reduction.components securityParameter :=
  reduction.aliceReduction securityParameter

theorem concrete_kci_bob_advantage_bound
    (reduction : ConcreteKCIReduction) (securityParameter : Nat) :
    KCIAdvantage reduction.semantics (reduction.bobCompromise securityParameter) ≤
      composedKCIBound reduction.components securityParameter :=
  reduction.bobReduction securityParameter

theorem concrete_kci_reduction
    (reduction : ConcreteKCIReduction) :
    KCISecurityGame reduction.semantics
      reduction.aliceCompromise reduction.bobCompromise
      { value := composedKCIBound reduction.components
        negligible := reduction.negligible } := by
  constructor
  · intro securityParameter
    exact ⟨concrete_kci_alice_advantage_bound reduction securityParameter,
      concrete_kci_bob_advantage_bound reduction securityParameter⟩
  · exact reduction.negligibleProof

end
end LinkChat
