# Crypto Provider Security Boundary

This crate is a typed wrapper around standard RustCrypto implementations. It
does not prove the computational security of those implementations, their
dependencies, the compiler, the operating system, or the hardware.

## Pinned libraries and features

The current workspace pins the primitive wrappers to these Cargo dependencies:

| Primitive | Dependency and enabled features |
| --- | --- |
| Ed25519 | `ed25519-dalek 3.0.0`, `default-features = false`, `fast`, `zeroize` |
| X25519 | `x25519-dalek 3.0.0`, `default-features = false`, `static_secrets`, `zeroize` |
| ML-KEM-768 | `ml-kem 0.3.2`, `default-features = false`, `zeroize` |
| HKDF/HMAC | `hkdf 0.13.0` and `hmac 0.13.0`, default features disabled |
| SHA-256 | `sha2 0.11.0`, default features disabled |
| ChaCha20-Poly1305 | `chacha20poly1305 0.11.0`, default features disabled, `alloc` |
| OS randomness | `getrandom 0.4.0`, `sys_rng` |

Dependency versions and feature selections are part of the implementation
review surface. Updating them requires rerunning primitive vectors and
reviewing low-order-point, implicit-rejection, nonce, and error mappings.

## Implemented boundary

- Ed25519 uses `ed25519-dalek 3.0.0` for key generation, signing, and
  verification. Public-key parsing errors are typed; a validly sized but
  invalid signature returns `Ok(false)`.
- X25519 uses `x25519-dalek 3.0.0`. The wrapper ciphertext is exactly the
  ephemeral 32-byte public key. A low-order input or all-zero DH output is
  rejected before HKDF with `CryptoError::LowOrderPoint`.
- ML-KEM is fixed to `ml-kem 0.3.2` ML-KEM-768. The secret representation is
  the library's 64-byte seed, the public key is 1184 bytes, and the ciphertext
  is 1088 bytes. Decapsulation uses the library's implicit-rejection behavior
  and does not expose library-specific failure details.
- HKDF-SHA-256 uses an all-zero 32-byte extract salt. Domain and context are
  length-framed with big-endian lengths. Key outputs are 32 bytes and nonce
  outputs are 12 bytes. The protocol layer remains responsible for passing
  canonical context and never reusing a nonce with a key.
- ChaCha20-Poly1305 authenticates caller-provided AAD and maps every open
  failure to the stable `AuthenticationFailed` error.
- Production key generation and encapsulation use `getrandom 0.4` OS CSPRNG
  output. The deterministic RNG is `cfg(test)` only and is not reachable from
  `OsCryptoBackend::new()` or any production constructor.

Secret wrappers are zeroized on drop where the dependency and platform permit
it. This is an implementation aid, not a proof of complete erasure from
registers, allocator copies, swap, crash dumps, or hardware.

Nonce construction is kept in the typed `Nonce` boundary. Protocol callers
must obtain nonce values through `derive_nonce` with the frozen domain and
canonical context; the backend never accepts arbitrary nonce byte slices. Key,
nonce, AAD, and ciphertext separation remains the caller's protocol-level
responsibility, and nonce reuse is not made safe by the AEAD wrapper.

## External primitive certificates

Any later certificate must define a security parameter `lambda`, a PPT
adversary `A`, the exact oracle and wrapper game, and its advantage. The
required games are:

| Wrapper | External game and advantage |
| --- | --- |
| Ed25519 | EUF-CMA: `Adv[A] = Pr[A forges a fresh message/signature accepted by Verify]`. |
| X25519 wrapper | Contributory DH/KEM game with low-order inputs rejected: `Adv[A]` is the distinguisher's advantage between a valid recipient shared secret and uniform, with rejected low-order queries excluded from successful decapsulation. |
| ML-KEM-768 | IND-CCA KEM game: `Adv[A]` is the difference between guessing the real challenge shared key and a uniform challenge under valid decapsulation-query restrictions. |
| HKDF-SHA-256 | Extractor/PRF games: `Adv[A]` is the difference between extract output or expand output and the corresponding uniform random oracle, under the stated entropy and domain-framing assumptions. |
| HMAC-SHA-256 | PRF/MAC game: `Adv[A]` is the difference between keyed HMAC and a random function, or the probability of a fresh valid tag forgery. |
| ChaCha20-Poly1305 | AEAD IND-CCA and INT-CTXT games: `Adv[A]` is respectively the real-vs-random confidentiality distinguishing advantage and the probability of a fresh ciphertext being accepted. |
| OS CSPRNG | Unpredictability/backtracking game: `Adv[A]` is the probability of predicting unrevealed output or reconstructing prior output after state exposure, under the OS provider's assumptions. |

Rust tests in this crate establish only lengths, round trips, known-answer
vectors, domain binding, failure mapping, and separation of production and
test RNG paths. They do not establish any of the advantages above.
