import Std
import ComputationalGames
import ConcreteSECCReduction
import StandardCrypto

namespace LinkChat

noncomputable section

/-!
  Concrete probability and primitive-game layer.

  The protocol files use symbolic `Nat` encodings.  This file gives those
  games an explicit finite sample space: a security experiment samples a seed
  from `List.range sampleSize`, and success probability is the exact rational
  fraction of sampled seeds for which the Boolean adversary succeeds.

  The cryptographic assumptions remain assumptions about the named games.  No
  theorem here claims to prove X25519, ML-KEM, HKDF, ChaCha20-Poly1305, or an
  operating-system CSPRNG from their symbolic `Nat` encodings.
-/

/-! ## 1. Explicit finite probability semantics -/

structure FiniteSampleSpace where
  sampleSize : Nat
  positive : 0 < sampleSize
  deriving Repr

def FiniteSampleSpace.points (space : FiniteSampleSpace) : List Nat :=
  List.range space.sampleSize

def successCount (space : FiniteSampleSpace) (experiment : Nat → Bool) : Nat :=
  space.points.countP experiment

def finiteUniformProbability (space : FiniteSampleSpace)
    (experiment : Nat → Bool) : Rat :=
  (successCount space experiment : Rat) / (space.sampleSize : Rat)

def finiteUniformSemantics (space : FiniteSampleSpace) : ProbabilitySemantics :=
  { probability := finiteUniformProbability space }

structure FiniteProbabilityModel where
  space : FiniteSampleSpace
  triangle : ∀ (a b c : Nat → Bool),
    SECCAdvantage (finiteUniformSemantics space) a c ≤
      SECCAdvantage (finiteUniformSemantics space) a b +
        SECCAdvantage (finiteUniformSemantics space) b c

def finiteProbabilityLaws (model : FiniteProbabilityModel) :
    ProbabilitySemanticsLaws :=
  { semantics := finiteUniformSemantics model.space
    triangle := model.triangle }

def finiteGameProbability (model : FiniteProbabilityModel)
    (experiment : Nat → Bool) : Rat :=
  finiteUniformProbability model.space experiment

def finiteGameAdvantage (model : FiniteProbabilityModel)
    (real random : Nat → Bool) : Rat :=
  SECCAdvantage (finiteUniformSemantics model.space) real random

theorem finite_probability_is_exact_success_fraction
    (model : FiniteProbabilityModel) (experiment : Nat → Bool) :
    finiteGameProbability model experiment =
      (successCount model.space experiment : Rat) /
        (model.space.sampleSize : Rat) := by
  rfl

theorem finite_probability_uses_explicit_sample_space
    (model : FiniteProbabilityModel) (experiment : Nat → Bool) :
    successCount model.space experiment =
      (List.range model.space.sampleSize).countP experiment := by
  rfl

structure FiniteAdversary where
  run : Nat → Bool

def adversarySuccessProbability (model : FiniteProbabilityModel)
    (adversary : FiniteAdversary) : Rat :=
  finiteGameProbability model adversary.run

def adversaryAdvantage (model : FiniteProbabilityModel)
    (real random : FiniteAdversary) : Rat :=
  finiteGameAdvantage model real.run random.run

theorem finite_model_instantiates_probability_laws
    (model : FiniteProbabilityModel) :
    (finiteProbabilityLaws model).semantics =
      finiteUniformSemantics model.space := by
  rfl

/-! ## 2. CSPRNG unpredictability game -/

structure CSPRNGGame where
  sampleSpace : FiniteSampleSpace
  realOutput : Nat → Nat
  randomOutput : Nat → Nat
  adversary : Nat → Nat → Bool

def csprngRealExperiment (game : CSPRNGGame) : Nat → Bool :=
  fun seed => game.adversary seed (game.realOutput seed)

def csprngRandomExperiment (game : CSPRNGGame) : Nat → Bool :=
  fun seed => game.adversary seed (game.randomOutput seed)

def csprngAdvantage (model : FiniteProbabilityModel) (game : CSPRNGGame) : Rat :=
  finiteGameAdvantage model (csprngRealExperiment game)
    (csprngRandomExperiment game)

structure CSPRNGSecurityCertificate where
  model : FiniteProbabilityModel
  game : CSPRNGGame
  bound : Nat → Rat
  advantageBound : ∀ securityParameter,
    csprngAdvantage model game ≤ bound securityParameter
  negligibleBound : Prop
  negligibleProof : negligibleBound

/-! The following adapter makes the hidden/fresh CSPRNG output explicit. -/
def osCSPRNGGame (api : StandardCryptoAPI) (space : FiniteSampleSpace)
    (randomOutput : Nat → Nat) (adversary : Nat → Nat → Bool) : CSPRNGGame :=
  { sampleSpace := space
    realOutput := fun _seed => api.osCSPRNG 32
    randomOutput := randomOutput
    adversary := adversary }

theorem csprng_game_has_explicit_real_output
    (api : StandardCryptoAPI) (space : FiniteSampleSpace)
    (randomOutput : Nat → Nat) (adversary : Nat → Nat → Bool) :
    (osCSPRNGGame api space randomOutput adversary).realOutput 0 =
      api.osCSPRNG 32 := by
  rfl

/-! ## 3. X25519 and ML-KEM IND-style games -/

structure KEMSecurityGame where
  sampleSpace : FiniteSampleSpace
  realSharedSecret : Nat → Nat
  randomSharedSecret : Nat → Nat
  adversary : Nat → Nat → Bool

def kemRealExperiment (game : KEMSecurityGame) : Nat → Bool :=
  fun seed => game.adversary seed (game.realSharedSecret seed)

def kemRandomExperiment (game : KEMSecurityGame) : Nat → Bool :=
  fun seed => game.adversary seed (game.randomSharedSecret seed)

def kemAdvantage (model : FiniteProbabilityModel)
    (game : KEMSecurityGame) : Rat :=
  finiteGameAdvantage model (kemRealExperiment game) (kemRandomExperiment game)

def x25519KEMGame (api : StandardCryptoAPI) (space : FiniteSampleSpace)
    (receiverSecret : Nat) (randomness randomSecret : Nat → Nat)
    (adversary : Nat → Nat → Bool) : KEMSecurityGame :=
  { sampleSpace := space
    realSharedSecret := fun seed =>
      (api.x25519Encap (api.x25519PublicKey receiverSecret) (randomness seed)).2
    randomSharedSecret := randomSecret
    adversary := adversary }

def mlKemSecurityGame (api : StandardCryptoAPI) (space : FiniteSampleSpace)
    (receiverSecret : Nat) (randomness randomSecret : Nat → Nat)
    (adversary : Nat → Nat → Bool) : KEMSecurityGame :=
  { sampleSpace := space
    realSharedSecret := fun seed =>
      (api.mlKemEncap (api.mlKemPublicKey receiverSecret) (randomness seed)).2
    randomSharedSecret := randomSecret
    adversary := adversary }

structure KEMSecurityCertificate where
  model : FiniteProbabilityModel
  game : KEMSecurityGame
  bound : Nat → Rat
  advantageBound : ∀ securityParameter,
    kemAdvantage model game ≤ bound securityParameter
  negligibleBound : Prop
  negligibleProof : negligibleBound

theorem x25519_game_real_secret_is_encapsulation_secret
    (api : StandardCryptoAPI) (space : FiniteSampleSpace)
    (receiverSecret : Nat) (randomness randomSecret : Nat → Nat)
    (adversary : Nat → Nat → Bool) (seed : Nat) :
    (x25519KEMGame api space receiverSecret randomness randomSecret adversary).realSharedSecret seed =
      (api.x25519Encap (api.x25519PublicKey receiverSecret) (randomness seed)).2 := by
  rfl

theorem mlkem_game_real_secret_is_encapsulation_secret
    (api : StandardCryptoAPI) (space : FiniteSampleSpace)
    (receiverSecret : Nat) (randomness randomSecret : Nat → Nat)
    (adversary : Nat → Nat → Bool) (seed : Nat) :
    (mlKemSecurityGame api space receiverSecret randomness randomSecret adversary).realSharedSecret seed =
      (api.mlKemEncap (api.mlKemPublicKey receiverSecret) (randomness seed)).2 := by
  rfl

/-! ## 4. HKDF pseudorandomness and AEAD confidentiality/integrity games -/

structure KDFSecurityGame where
  sampleSpace : FiniteSampleSpace
  realKey : Nat → Nat
  randomKey : Nat → Nat
  adversary : Nat → Nat → Bool

def kdfRealExperiment (game : KDFSecurityGame) : Nat → Bool :=
  fun seed => game.adversary seed (game.realKey seed)

def kdfRandomExperiment (game : KDFSecurityGame) : Nat → Bool :=
  fun seed => game.adversary seed (game.randomKey seed)

def kdfAdvantage (model : FiniteProbabilityModel)
    (game : KDFSecurityGame) : Rat :=
  finiteGameAdvantage model (kdfRealExperiment game) (kdfRandomExperiment game)

def hkdfSecurityGame (api : StandardCryptoAPI) (space : FiniteSampleSpace)
    (ikm context randomKey : Nat → Nat) (adversary : Nat → Nat → Bool) :
    KDFSecurityGame :=
  { sampleSpace := space
    realKey := fun seed => standardDerive api (ikm seed) .message (context seed)
    randomKey := randomKey
    adversary := adversary }

structure KDFSecurityCertificate where
  model : FiniteProbabilityModel
  game : KDFSecurityGame
  bound : Nat → Rat
  advantageBound : ∀ securityParameter,
    kdfAdvantage model game ≤ bound securityParameter
  negligibleBound : Prop
  negligibleProof : negligibleBound

structure AEADConfidentialityGame where
  sampleSpace : FiniteSampleSpace
  key : Nat → Nat
  nonce : Nat → Nat
  associatedData : Nat → Nat
  messageZero : Nat → Nat
  messageOne : Nat → Nat
  encrypt : Nat → Nat → Nat → Nat → Nat
  adversary : Nat → Nat → Bool

def aeadZeroExperiment (game : AEADConfidentialityGame) : Nat → Bool :=
  fun seed => game.adversary seed
    (game.encrypt (game.key seed) (game.nonce seed) (game.associatedData seed)
      (game.messageZero seed))

def aeadOneExperiment (game : AEADConfidentialityGame) : Nat → Bool :=
  fun seed => game.adversary seed
    (game.encrypt (game.key seed) (game.nonce seed) (game.associatedData seed)
      (game.messageOne seed))

def aeadConfidentialityAdvantage (model : FiniteProbabilityModel)
    (game : AEADConfidentialityGame) : Rat :=
  finiteGameAdvantage model (aeadZeroExperiment game) (aeadOneExperiment game)

def standardAEADConfidentialityGame (api : StandardCryptoAPI)
    (space : FiniteSampleSpace) (key nonce ad m0 m1 : Nat → Nat)
    (adversary : Nat → Nat → Bool) : AEADConfidentialityGame :=
  { sampleSpace := space
    key := key
    nonce := nonce
    associatedData := ad
    messageZero := m0
    messageOne := m1
    encrypt := api.aeadSeal
    adversary := adversary }

structure AEADSecurityCertificate where
  model : FiniteProbabilityModel
  game : AEADConfidentialityGame
  confidentialityBound : Nat → Rat
  confidentialityAdvantageBound : ∀ securityParameter,
    aeadConfidentialityAdvantage model game ≤ confidentialityBound securityParameter
  integrityExperiment : Nat → Bool
  integrityBound : Nat → Rat
  integrityAdvantageBound : ∀ securityParameter,
    finiteGameProbability model (integrityExperiment) ≤ integrityBound securityParameter
  negligibleBound : Prop
  negligibleProof : negligibleBound

theorem aead_confidentiality_game_exposes_real_ciphertext
    (api : StandardCryptoAPI) (space : FiniteSampleSpace)
    (key nonce ad m0 m1 : Nat → Nat) (adversary : Nat → Nat → Bool)
    (seed : Nat) :
    aeadZeroExperiment
        (standardAEADConfidentialityGame api space key nonce ad m0 m1 adversary) seed =
      adversary seed
        (api.aeadSeal (key seed) (nonce seed) (ad seed) (m0 seed)) := by
  rfl

/-! ## 5. Explicit negligible calculus and final SECC sum -/

/-!
  `AsymptoticNegligible` is the exact epsilon-definition used by this
  dependency-free model: the advantage eventually becomes smaller than every
  positive rational threshold.  Primitive certificates may use a stronger
  standard cryptographic negligible bound and provide this property as its
  theorem-level consequence.
-/
def AsymptoticNegligible (f : Nat → Rat) : Prop :=
  ∀ ε : Rat, 0 < ε → ∃ N : Nat, ∀ n : Nat, N ≤ n → f n < ε

theorem half_positive {ε : Rat} (hε : 0 < ε) : 0 < ε / (2 : Rat) := by
  apply (Rat.lt_div_iff (by decide : (0 : Rat) < 2)).2
  simpa using hε

theorem half_add_half {ε : Rat} : ε / (2 : Rat) + ε / (2 : Rat) = ε := by
  calc
    ε / (2 : Rat) + ε / (2 : Rat) =
        (ε / (2 : Rat)) * (1 : Rat) + (ε / (2 : Rat)) * (1 : Rat) := by
          simp only [Rat.mul_one]
    _ = (ε / (2 : Rat)) * ((1 : Rat) + 1) := by
          exact (Rat.mul_add (ε / (2 : Rat)) 1 1).symm
    _ = (ε / (2 : Rat)) * (2 : Rat) := by
          have htwo : (1 : Rat) + 1 = 2 := by
            calc
              (1 : Rat) + 1 = ((1 + 1 : Nat) : Rat) :=
                (Rat.natCast_add 1 1).symm
              _ = 2 := by rfl
          rw [htwo]
    _ = ε := by
          exact Rat.div_mul_cancel (by decide : (2 : Rat) ≠ 0)

theorem rat_lt_trans {a b c : Rat} (hab : a < b) (hbc : b < c) : a < c := by
  apply Rat.lt_of_le_of_ne (Rat.le_trans (Rat.le_of_lt hab) (Rat.le_of_lt hbc))
  intro hac
  subst c
  have hba : b ≤ a := Rat.le_of_lt hbc
  have habEq : a = b := Rat.le_antisymm (Rat.le_of_lt hab) hba
  exact Rat.ne_of_lt hab habEq

theorem asymptoticNegligible_add
    {f g : Nat → Rat} (hf : AsymptoticNegligible f)
    (hg : AsymptoticNegligible g) :
    AsymptoticNegligible (fun n => f n + g n) := by
  intro ε hε
  have hhalf : 0 < ε / (2 : Rat) := half_positive hε
  obtain ⟨Nf, hNf⟩ := hf (ε / (2 : Rat)) hhalf
  obtain ⟨Ng, hNg⟩ := hg (ε / (2 : Rat)) hhalf
  refine ⟨max Nf Ng, ?_⟩
  intro n hn
  have hf' := hNf n (Nat.le_trans (Nat.le_max_left _ _) hn)
  have hg' := hNg n (Nat.le_trans (Nat.le_max_right _ _) hn)
  have h₁ : f n + g n < ε / (2 : Rat) + g n :=
    (Rat.add_lt_add_right).2 hf'
  have h₂ : ε / (2 : Rat) + g n <
      ε / (2 : Rat) + ε / (2 : Rat) :=
    (Rat.add_lt_add_left).2 hg'
  rw [half_add_half] at h₂
  exact rat_lt_trans h₁ h₂

def sixTermSum (f₁ f₂ f₃ f₄ f₅ f₆ : Nat → Rat) : Nat → Rat :=
  fun n => f₁ n + f₂ n + f₃ n + f₄ n + f₅ n + f₆ n

theorem six_term_sum_negligible
    {f₁ f₂ f₃ f₄ f₅ f₆ : Nat → Rat}
    (h₁ : AsymptoticNegligible f₁)
    (h₂ : AsymptoticNegligible f₂)
    (h₃ : AsymptoticNegligible f₃)
    (h₄ : AsymptoticNegligible f₄)
    (h₅ : AsymptoticNegligible f₅)
    (h₆ : AsymptoticNegligible f₆) :
    AsymptoticNegligible (sixTermSum f₁ f₂ f₃ f₄ f₅ f₆) := by
  have h12 : AsymptoticNegligible (fun n => f₁ n + f₂ n) :=
    asymptoticNegligible_add h₁ h₂
  have h123 : AsymptoticNegligible (fun n => f₁ n + f₂ n + f₃ n) :=
    asymptoticNegligible_add h12 h₃
  have h1234 : AsymptoticNegligible
      (fun n => f₁ n + f₂ n + f₃ n + f₄ n) :=
    asymptoticNegligible_add h123 h₄
  have h12345 : AsymptoticNegligible
      (fun n => f₁ n + f₂ n + f₃ n + f₄ n + f₅ n) :=
    asymptoticNegligible_add h1234 h₅
  change AsymptoticNegligible
    (fun n => f₁ n + f₂ n + f₃ n + f₄ n + f₅ n + f₆ n)
  exact asymptoticNegligible_add h12345 h₆

structure ConcretePrimitiveSecurityBounds where
  x25519 : Nat → Rat
  mlKem : Nat → Rat
  hkdf : Nat → Rat
  aead : Nat → Rat
  csprng : Nat → Rat
  state : Nat → Rat
  x25519Negligible : AsymptoticNegligible x25519
  mlKemNegligible : AsymptoticNegligible mlKem
  hkdfNegligible : AsymptoticNegligible hkdf
  aeadNegligible : AsymptoticNegligible aead
  csprngNegligible : AsymptoticNegligible csprng
  stateNegligible : AsymptoticNegligible state

def concretePrimitiveSum (bounds : ConcretePrimitiveSecurityBounds) : Nat → Rat :=
  sixTermSum bounds.x25519 bounds.mlKem bounds.hkdf bounds.aead
    bounds.csprng bounds.state

theorem concrete_primitive_sum_is_negligible
    (bounds : ConcretePrimitiveSecurityBounds) :
    AsymptoticNegligible (concretePrimitiveSum bounds) := by
  exact six_term_sum_negligible bounds.x25519Negligible bounds.mlKemNegligible
    bounds.hkdfNegligible bounds.aeadNegligible bounds.csprngNegligible
    bounds.stateNegligible

def concretePrimitiveSECCComponents
    (bounds : ConcretePrimitiveSecurityBounds) : SECCAdvantageComponents :=
  { x25519 := bounds.x25519
    mlKem := bounds.mlKem
    hkdf := bounds.hkdf
    aead := bounds.aead
    csprng := bounds.csprng
    state := bounds.state }

theorem concrete_primitive_sum_matches_secc_bound
    (bounds : ConcretePrimitiveSecurityBounds) :
    composedSECCBound (concretePrimitiveSECCComponents bounds) =
      concretePrimitiveSum bounds := by
  rfl

/-! The suite below is the concrete bridge from the named primitive games to
    the six functions consumed by the SECC reduction. -/
structure ConcretePrimitiveGameSuite where
  csprngCertificate : CSPRNGSecurityCertificate
  x25519Certificate : KEMSecurityCertificate
  mlKemCertificate : KEMSecurityCertificate
  hkdfCertificate : KDFSecurityCertificate
  aeadCertificate : AEADSecurityCertificate
  stateBound : Nat → Rat
  csprngNegligible : AsymptoticNegligible csprngCertificate.bound
  x25519Negligible : AsymptoticNegligible x25519Certificate.bound
  mlKemNegligible : AsymptoticNegligible mlKemCertificate.bound
  hkdfNegligible : AsymptoticNegligible hkdfCertificate.bound
  aeadConfidentialityNegligible :
    AsymptoticNegligible aeadCertificate.confidentialityBound
  aeadIntegrityNegligible :
    AsymptoticNegligible aeadCertificate.integrityBound
  stateNegligible : AsymptoticNegligible stateBound

def suiteAEADBound (suite : ConcretePrimitiveGameSuite) : Nat → Rat :=
  fun n => suite.aeadCertificate.confidentialityBound n +
    suite.aeadCertificate.integrityBound n

def suiteBounds (suite : ConcretePrimitiveGameSuite) :
    ConcretePrimitiveSecurityBounds :=
  { x25519 := suite.x25519Certificate.bound
    mlKem := suite.mlKemCertificate.bound
    hkdf := suite.hkdfCertificate.bound
    aead := suiteAEADBound suite
    csprng := suite.csprngCertificate.bound
    state := suite.stateBound
    x25519Negligible := suite.x25519Negligible
    mlKemNegligible := suite.mlKemNegligible
    hkdfNegligible := suite.hkdfNegligible
    aeadNegligible := asymptoticNegligible_add
      suite.aeadConfidentialityNegligible suite.aeadIntegrityNegligible
    csprngNegligible := suite.csprngNegligible
    stateNegligible := suite.stateNegligible }

theorem suite_bound_is_negligible (suite : ConcretePrimitiveGameSuite) :
    AsymptoticNegligible (concretePrimitiveSum (suiteBounds suite)) := by
  exact concrete_primitive_sum_is_negligible (suiteBounds suite)

theorem computational_secc_from_primitive_game_suite
    (reduction : ConcreteSECCReduction)
    (suite : ConcretePrimitiveGameSuite)
    (hBound : ∀ securityParameter,
      hopAdvantage reduction.laws reduction.games.real reduction.games.random
          securityParameter ≤ concretePrimitiveSum (suiteBounds suite) securityParameter) :
    ComputationalSECC reduction.laws.semantics
      reduction.games.real reduction.games.random
      { value := concretePrimitiveSum (suiteBounds suite)
        negligible := AsymptoticNegligible (concretePrimitiveSum (suiteBounds suite)) } := by
  constructor
  · intro securityParameter
    exact hBound securityParameter
  · exact suite_bound_is_negligible suite

structure ConcreteSECCProbabilityCertificate where
  reduction : ConcreteSECCReduction
  components : ConcretePrimitiveSecurityBounds
  componentEquation :
    reduction.components = concretePrimitiveSECCComponents components
  stateAndPrimitiveHops : ∀ securityParameter,
    hopAdvantage reduction.laws reduction.games.real reduction.games.random
        securityParameter ≤ concretePrimitiveSum components securityParameter

theorem concrete_secc_probability_certificate_bound
    (certificate : ConcreteSECCProbabilityCertificate) (securityParameter : Nat) :
    hopAdvantage certificate.reduction.laws certificate.reduction.games.real
        certificate.reduction.games.random securityParameter ≤
      concretePrimitiveSum certificate.components securityParameter := by
  exact certificate.stateAndPrimitiveHops securityParameter

theorem concrete_secc_probability_certificate_is_negligible
    (certificate : ConcreteSECCProbabilityCertificate) :
    AsymptoticNegligible (concretePrimitiveSum certificate.components) := by
  exact concrete_primitive_sum_is_negligible certificate.components

/-! This is the end-to-end theorem for the five requested steps: the concrete
    protocol reduction is bounded by the explicit six-term sum, and that sum
    is negligible from the six component proofs. -/
theorem computational_secc_from_explicit_primitive_sum
    (reduction : ConcreteSECCReduction)
    (components : ConcretePrimitiveSecurityBounds)
    (hBound : ∀ securityParameter,
      hopAdvantage reduction.laws reduction.games.real reduction.games.random
          securityParameter ≤ concretePrimitiveSum components securityParameter) :
    ComputationalSECC reduction.laws.semantics
      reduction.games.real reduction.games.random
      { value := concretePrimitiveSum components
        negligible := AsymptoticNegligible (concretePrimitiveSum components) } := by
  constructor
  · intro securityParameter
    exact hBound securityParameter
  · exact concrete_primitive_sum_is_negligible components

end
end LinkChat
