# Storage Recovery Vector

- Protocol version: `1.0`
- Cipher suite: `V1HybridMlKem768`
- Canonical input: crash points across pending, marker, current publication and retirement.
- Expected result: recovery selects complete old current or complete new committed current.
- State transition: atomic recovery only.
- Turn: `0 -> 1`
- Generation: `0 -> 1`
