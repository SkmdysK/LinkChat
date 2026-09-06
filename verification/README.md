# Verification Scope

`linkchat-verification` contains deterministic bounded property checks,
wire-decoder fuzz smoke tests, storage crash fault matrix checks, and a
Lean/Rust differential harness.

The differential harness compares finite summaries of the same state-machine
cases: acceptance, turn, Alice/Bob public package key and token projections,
and consumed message ids. Its Lean oracle is an executable bounded model
corresponding to `RefinedProtocol.refinedValid` and `refinedStep`.

These checks establish finite implementation conformance only. They do not
replace Lean's universal theorems, a proof against every PPT adversary, or
the computational assumptions for Ed25519, X25519, ML-KEM-768, HKDF,
ChaCha20-Poly1305, OS CSPRNG, secure erasure, or production storage.
