# Application Message Vector

- Protocol version: `1.0`
- Cipher suite: `V1HybridMlKem768`
- Canonical input: session, current turn, leader direction, receiver key/token, message id and payload.
- Expected result: canonical round trip; valid input advances exactly one turn.
- State transition: `0 -> 1`.
- Turn: `0 -> 1`
- Generation: receiver package `0 -> 1`
