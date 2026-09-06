import Std
import ComputationalGames

namespace LinkChat

noncomputable section

/-!
  Concrete reduction bookkeeping for the SECC game.

  The protocol-specific state hop is already machine-checked in
  `ComputationalGames.lean`.  This file makes the remaining computational
  reduction explicit as a sequence of hybrid experiments.  Each primitive
  hop is a parameterized reduction obligation; the theorem below proves the
  additive composition of those obligations.
-/

abbrev Experiment := Nat → Bool
abbrev ExperimentFamily := Nat → Experiment

structure SECCHybridGames where
  real : ExperimentFamily
  stateIsolated : ExperimentFamily
  x25519Replaced : ExperimentFamily
  mlKemReplaced : ExperimentFamily
  hkdfReplaced : ExperimentFamily
  aeadReplaced : ExperimentFamily
  random : ExperimentFamily

structure ProbabilitySemanticsLaws where
  semantics : ProbabilitySemantics
  triangle : ∀ (a b c : Experiment),
    SECCAdvantage semantics a c ≤
      SECCAdvantage semantics a b + SECCAdvantage semantics b c

def hopAdvantage (laws : ProbabilitySemanticsLaws)
    (a b : ExperimentFamily) (securityParameter : Nat) : Rat :=
  SECCAdvantage laws.semantics (a securityParameter) (b securityParameter)

theorem hop_triangle (laws : ProbabilitySemanticsLaws)
    (a b c : ExperimentFamily) (securityParameter : Nat) :
    hopAdvantage laws a c securityParameter ≤
      hopAdvantage laws a b securityParameter +
        hopAdvantage laws b c securityParameter := by
  simpa [hopAdvantage] using
    laws.triangle (a securityParameter) (b securityParameter) (c securityParameter)

theorem exact_game_hop_has_zero_advantage
    (laws : ProbabilitySemanticsLaws) (a b : Experiment)
    (h : a = b) :
    SECCAdvantage laws.semantics a b = 0 := by
  rw [h]
  simp [SECCAdvantage, Rat.sub_self, Rat.abs_zero]

theorem rat_add_mono
    {a b c d : Rat} (h₁ : a ≤ b) (h₂ : c ≤ d) :
    a + c ≤ b + d := by
  exact Rat.le_trans
    ((Rat.add_le_add_right).2 h₁)
    ((Rat.add_le_add_left).2 h₂)

structure ConcreteSECCReduction where
  games : SECCHybridGames
  laws : ProbabilitySemanticsLaws
  components : SECCAdvantageComponents
  stateHop : ∀ securityParameter,
    hopAdvantage laws games.real games.stateIsolated securityParameter ≤
      components.state securityParameter
  x25519Hop : ∀ securityParameter,
    hopAdvantage laws games.stateIsolated games.x25519Replaced securityParameter ≤
      components.x25519 securityParameter
  mlKemHop : ∀ securityParameter,
    hopAdvantage laws games.x25519Replaced games.mlKemReplaced securityParameter ≤
      components.mlKem securityParameter
  hkdfHop : ∀ securityParameter,
    hopAdvantage laws games.mlKemReplaced games.hkdfReplaced securityParameter ≤
      components.hkdf securityParameter
  aeadHop : ∀ securityParameter,
    hopAdvantage laws games.hkdfReplaced games.aeadReplaced securityParameter ≤
      components.aead securityParameter
  csprngHop : ∀ securityParameter,
    hopAdvantage laws games.aeadReplaced games.random securityParameter ≤
      components.csprng securityParameter
  negligible : Prop
  negligibleProof : negligible

theorem concrete_secc_advantage_bound
    (reduction : ConcreteSECCReduction) (securityParameter : Nat) :
    hopAdvantage reduction.laws reduction.games.real reduction.games.random
        securityParameter ≤
      composedSECCBound reduction.components securityParameter := by
  let l := reduction.laws
  let g := reduction.games
  let n := securityParameter
  let h01 := hopAdvantage l g.real g.stateIsolated n
  let h12 := hopAdvantage l g.stateIsolated g.x25519Replaced n
  let h23 := hopAdvantage l g.x25519Replaced g.mlKemReplaced n
  let h34 := hopAdvantage l g.mlKemReplaced g.hkdfReplaced n
  let h45 := hopAdvantage l g.hkdfReplaced g.aeadReplaced n
  let h56 := hopAdvantage l g.aeadReplaced g.random n
  have ht56 : hopAdvantage l g.aeadReplaced g.random n ≤
      reduction.components.csprng n := reduction.csprngHop n
  have ht45 : hopAdvantage l g.hkdfReplaced g.aeadReplaced n ≤
      reduction.components.aead n := reduction.aeadHop n
  have ht34 : hopAdvantage l g.mlKemReplaced g.hkdfReplaced n ≤
      reduction.components.hkdf n := reduction.hkdfHop n
  have ht23 : hopAdvantage l g.x25519Replaced g.mlKemReplaced n ≤
      reduction.components.mlKem n := reduction.mlKemHop n
  have ht12 : hopAdvantage l g.stateIsolated g.x25519Replaced n ≤
      reduction.components.x25519 n := reduction.x25519Hop n
  have ht01 : hopAdvantage l g.real g.stateIsolated n ≤
      reduction.components.state n := reduction.stateHop n
  have tail45 : h45 + h56 ≤
      reduction.components.aead n + reduction.components.csprng n :=
    rat_add_mono ht45 ht56
  have tail34 : h34 + (h45 + h56) ≤
      reduction.components.hkdf n +
        (reduction.components.aead n + reduction.components.csprng n) :=
    rat_add_mono ht34 tail45
  have tail23 : h23 + (h34 + (h45 + h56)) ≤
      reduction.components.mlKem n +
        (reduction.components.hkdf n +
          (reduction.components.aead n + reduction.components.csprng n)) :=
    rat_add_mono ht23 tail34
  have tail12 : h12 + (h23 + (h34 + (h45 + h56))) ≤
      reduction.components.x25519 n +
        (reduction.components.mlKem n +
          (reduction.components.hkdf n +
            (reduction.components.aead n + reduction.components.csprng n))) :=
    rat_add_mono ht12 tail23
  have tail01 : h01 + (h12 + (h23 + (h34 + (h45 + h56)))) ≤
      reduction.components.state n +
        (reduction.components.x25519 n +
          (reduction.components.mlKem n +
            (reduction.components.hkdf n +
              (reduction.components.aead n + reduction.components.csprng n)))) :=
    rat_add_mono ht01 tail12
  have chain56 :
      hopAdvantage l g.aeadReplaced g.random n = h56 := rfl
  have chain45 :
      hopAdvantage l g.hkdfReplaced g.random n ≤ h45 + h56 := by
    have hTri := hop_triangle l g.hkdfReplaced g.aeadReplaced g.random n
    simpa [h45, h56] using hTri
  have chain34 :
      hopAdvantage l g.mlKemReplaced g.random n ≤ h34 + (h45 + h56) := by
    have hTri := hop_triangle l g.mlKemReplaced g.hkdfReplaced g.random n
    have hTri' : hopAdvantage l g.mlKemReplaced g.random n ≤
        h34 + hopAdvantage l g.hkdfReplaced g.random n := by
      simpa [h34] using hTri
    exact Rat.le_trans hTri' ((Rat.add_le_add_left).2 chain45)
  have chain23 :
      hopAdvantage l g.x25519Replaced g.random n ≤
        h23 + (h34 + (h45 + h56)) := by
    have hTri := hop_triangle l g.x25519Replaced g.mlKemReplaced g.random n
    have hTri' : hopAdvantage l g.x25519Replaced g.random n ≤
        h23 + hopAdvantage l g.mlKemReplaced g.random n := by
      simpa [h23] using hTri
    exact Rat.le_trans hTri' ((Rat.add_le_add_left).2 chain34)
  have chain12 :
      hopAdvantage l g.stateIsolated g.random n ≤
        h12 + (h23 + (h34 + (h45 + h56))) := by
    have hTri := hop_triangle l g.stateIsolated g.x25519Replaced g.random n
    have hTri' : hopAdvantage l g.stateIsolated g.random n ≤
        h12 + hopAdvantage l g.x25519Replaced g.random n := by
      simpa [h12] using hTri
    exact Rat.le_trans hTri' ((Rat.add_le_add_left).2 chain23)
  have chain01 :
      hopAdvantage l g.real g.random n ≤
        h01 + (h12 + (h23 + (h34 + (h45 + h56)))) := by
    have hTri := hop_triangle l g.real g.stateIsolated g.random n
    have hTri' : hopAdvantage l g.real g.random n ≤
        h01 + hopAdvantage l g.stateIsolated g.random n := by
      simpa [h01] using hTri
    exact Rat.le_trans hTri' ((Rat.add_le_add_left).2 chain12)
  calc
    hopAdvantage reduction.laws reduction.games.real reduction.games.random n ≤
        h01 + (h12 + (h23 + (h34 + (h45 + h56)))) := by
          simpa [h01, h12, h23, h34, h45, h56] using chain01
    _ ≤ reduction.components.state n +
        (reduction.components.x25519 n +
          (reduction.components.mlKem n +
            (reduction.components.hkdf n +
              (reduction.components.aead n + reduction.components.csprng n)))) :=
      tail01
    _ = composedSECCBound reduction.components n := by
      simp [composedSECCBound, Rat.add_comm, Rat.add_assoc]

theorem concrete_secc_advantage_bound_in_reference_order
    (reduction : ConcreteSECCReduction) (securityParameter : Nat) :
    SECCAdvantage reduction.laws.semantics
        (reduction.games.real securityParameter)
        (reduction.games.random securityParameter) ≤
      composedSECCBound reduction.components securityParameter := by
  exact concrete_secc_advantage_bound reduction securityParameter

theorem computational_secc_from_concrete_reduction
    (reduction : ConcreteSECCReduction) :
    ComputationalSECC reduction.laws.semantics
      reduction.games.real reduction.games.random
      { value := composedSECCBound reduction.components
        negligible := reduction.negligible } := by
  constructor
  · exact concrete_secc_advantage_bound_in_reference_order reduction
  · change reduction.negligible
    exact reduction.negligibleProof

end
end LinkChat
