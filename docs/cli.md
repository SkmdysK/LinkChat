# Link Chat Development CLI

`linkchat-cli` is an optional development and integration tool. It is not a
chat client and has no account, contact, server, DHT, relay, or GUI features.

Commands:

```text
linkchat-cli keygen
linkchat-cli pair <session-id>
linkchat-cli inspect-package <canonical-package-hex>
linkchat-cli encode message <session> <turn> <direction> <message-id> <receiver-key-id> <token-hex> <payload-hex>
linkchat-cli encode package <session> <turn> <generation> <key-id> <x25519-hex> <mlkem-hex> <token-hex> <expiration> <previous-hash-hex> <package-auth-hex>
linkchat-cli decode <message|package|envelope|ack|sack|mailbox-record> <canonical-hex>
linkchat-cli verify <message|package|envelope|ack|sack|mailbox-record> <canonical-hex>
linkchat-cli test-vector [manifest-path]
```

`keygen` generates standard-provider key material but prints only Ed25519,
X25519, and ML-KEM public keys. Private keys are dropped without being
serialized. `pair` prints only a session context. `inspect-package` and
`decode` intentionally report lengths and public metadata instead of mailbox
tokens or package authentication bytes.

`encode`, `decode`, and `verify` call the existing canonical wire API. `verify`
means canonical wire validation; it is not a claim that package authentication
has been cryptographically verified because no identity public key is supplied
to that command. `test-vector` reads the existing `vectors/manifest.tsv` and
does not invent new protocol semantics.

The CLI inherits the Rust wire/type/crypto-library trust boundaries and the OS
CSPRNG boundary. A finite set of CLI tests and vector rows cannot replace the
Lean proof obligations, a PPT adversary proof, or the computational security
assumptions for Ed25519, X25519, ML-KEM-768, HKDF-SHA-256,
ChaCha20-Poly1305, and secure erasure.
