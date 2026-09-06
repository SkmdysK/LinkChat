# Fuzz Smoke Harness

The deterministic fuzz smoke test lives in
`crates/linkchat-verification/src/lib.rs` as
`fuzz_smoke_rejects_mutated_wire_inputs_without_panics`.

It exercises canonical Envelope, ReceiverPackage, ApplicationMessage,
ACK/SACK and MailboxRecord decoders, length fields, truncation, versions,
KEM-sized inputs and low-order X25519 input. The corpus is intentionally
small and checked in for reproducibility; it is not a replacement for a
long-running coverage-guided fuzz campaign.

The smoke harness checks no panic and bounded constructors only. It does not
claim arbitrary-adversary security, primitive security, or a proof of memory
safety beyond the tested Rust paths.
