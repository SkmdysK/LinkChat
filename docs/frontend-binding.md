# Frontend Binding

The optional `linkchat-ffi` crate is a narrow protocol binding for native or
managed frontends. It is not a GUI toolkit and does not own UI state,
accounts, contacts, sockets, or server connections.

## Native C ABI

Use the declarations in `include/linkchat_ffi.h`. The ABI uses:

- fixed-width integer fields and `repr(C)` metadata;
- opaque `uint64_t` handles;
- explicit bootstrap, endpoint, package, and session destruction;
- caller-owned input/output buffers with explicit lengths;
- stable integer error codes;
- prepare/commit for message send and receive.

For a two-party startup, each side calls `linkchat_bootstrap_create`, exports
only its public identity and canonical public Receiver Package, exchanges those
public values through the application's rendezvous layer, and calls
`linkchat_endpoint_create_from_bootstrap`. The bootstrap handle is consumed on
successful endpoint creation.

## Message Flow

```text
send_prepare
-> caller transports exactly 4096 Envelope bytes
-> send_commit

receive_prepare
-> query output sizes with receive_commit
-> provide sufficient buffers
-> receive_commit
-> deliver payload and returned public package to UI/application
```

If a receive output buffer is too small, the API reports required lengths,
writes no payload or package bytes, and does not consume the prepare handle or
advance endpoint state. A short send buffer similarly creates no prepare
handle.

## What Crosses the Boundary

Public endpoint metadata includes session, turn, public identities, public
package key IDs, generations, expiration values, and public-key lengths. It
does not include mailbox tokens, package-authentication bytes, private keys,
Receiver Secrets, Message Keys, KEM shared secrets, or Rust-owned pointers.

The Rust side owns all secret material. The frontend remains responsible for
pointer validity, buffer capacity, handle lifetime, and not racing a handle
with destroy. The ABI does not make an unsafe caller memory-safe.

## WASM

No WASM crate is currently included. A future WASM binding should be a separate
optional crate, preserve the same fixed-layout/versioned data contracts, and
depend on the public engine/FFI-facing API rather than adding WASM dependencies
to `linkchat-core`.

## Frontend Trust Boundary

The frontend should treat payload delivery as accepted only after receive
commit returns success. It should display transport retry separately from
protocol rejection and cryptographic failure. The binding does not provide
anonymity, traffic-analysis protection, side-channel protection, or a secure
UI storage policy for application data.
