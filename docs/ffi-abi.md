# Link Chat FFI ABI

The optional `linkchat-ffi` crate is an integration boundary for public
session context and public Receiver Packages. It is not a C implementation of
the protocol state machine and it does not expose storage, transport, crypto
providers, private receiver packages, message keys, or private keys.

The C declarations are in `include/linkchat_ffi.h`. Error values are stable
integer constants and are intentionally not Rust enum discriminants:

| Code | Meaning |
| ---: | --- |
| `0` | `LC_OK` |
| `1` | `LC_ERR_NULL_POINTER` |
| `2` | `LC_ERR_INVALID_LENGTH` |
| `3` | `LC_ERR_INVALID_HANDLE` |
| `4` | `LC_ERR_WIRE` |
| `5` | `LC_ERR_NON_CANONICAL` |
| `6` | `LC_ERR_BUFFER_TOO_SMALL` |
| `7` | `LC_ERR_INTERNAL` |
| `8` | `LC_ERR_CRYPTO` |
| `9` | `LC_ERR_REJECTED` |
| `10` | `LC_ERR_STORAGE` |
| `11` | `LC_ERR_RETRYABLE` |
| `12` | `LC_ERR_INVALID_ARGUMENT` |
| `13` | `LC_ERR_NOT_READY` |

`LC_ERR_CRYPTO` covers primitive, AEAD, package-authentication, and identity
verification failures. `LC_ERR_REJECTED` covers a validly decoded input that
does not match the endpoint's session, turn, receiver package, or replay
state. `LC_ERR_STORAGE` is reserved for endpoint adapter prepare, commit,
load, or recovery failures. `LC_ERR_NOT_READY` covers a missing or stale
prepare/commit handle.

## Endpoint API

`linkchat_bootstrap_create` generates an opaque local bootstrap containing the
Ed25519 identity and private Receiver Package. The identity and package are
exported only as public bytes through caller-owned buffers. Private keys,
Message Keys, Receiver Secrets, and secret byte arrays never cross the ABI.
`linkchat_endpoint_create_from_bootstrap` consumes that bootstrap after it
validates the peer identity and canonical public Receiver Package. A bootstrap
handle is single-use and must be destroyed with `linkchat_bootstrap_destroy`
if it is not consumed.

`linkchat_endpoint_create` remains a convenience constructor that generates
local identity/package material internally when the caller already has the
peer's public package. Endpoint handles are opaque `uint64_t` values and must
be destroyed with `linkchat_endpoint_destroy`.

`linkchat_endpoint_metadata` returns public snapshot metadata only. It omits
mailbox tokens, package-authentication bytes, consumed message identifiers,
private keys, and all secret material. Endpoint package export uses the same
caller-owned sizing and no-partial-write convention as the public package API.

Sending and receiving are explicitly split into prepare and commit. Prepare
performs validation and cryptographic work but does not publish a state
transition. The returned prepare handle is single-use and owned by its
endpoint. A short envelope buffer returns `LC_ERR_BUFFER_TOO_SMALL`, creates
no prepare handle, and does not advance state. `send_commit` is the only FFI
operation that commits a prepared send.

`receive_prepare` copies and validates the canonical 4096-byte Envelope but
does not advance state. `receive_commit` checks both output capacities first;
if either is too small, it reports required lengths, writes no payload or
package bytes, and leaves endpoint state unchanged. Only after capacity checks
does it perform the engine's storage-adapter commit, then copy the authenticated
payload, returned public Receiver Package, and `LinkChatReceiveMetadata` to
caller-owned buffers.

The current FFI endpoint uses `MemoryEndpointStorage` intentionally. It is an
in-process adapter for integration and testing, not a production persistence
backend. The current ABI carries one `bootstrap_previous_hash`, so it maps to
the engine's compatibility constructor where local and peer roots are equal.
Applications that require distinct owner-bound roots must use a Rust engine
integration or a future ABI extension; the FFI must not guess or silently
reuse one root for both owners. `linkchat_endpoint_recover` exercises that
adapter's recovery contract; it does not provide crash durability across
process termination.

## Ownership and lifecycle

`uint64_t` values are opaque handles. They have no public layout and must only
be passed back to the matching API. A successful create/open call transfers
ownership of a registry entry to the caller. The caller must release it with
the matching destroy function. Destroying an unknown handle, destroying a
handle twice, or using a handle with the wrong API returns
`LC_ERR_INVALID_HANDLE`.

`linkchat_package_open` copies the input bytes before decoding. Inputs must be
non-empty, no larger than 64 KiB, and point to readable memory for the
duration of the call. The bytes must decode as a canonical public
`WireReceiverPackage`; malformed or non-canonical input creates no handle.

Package output uses caller-owned memory. First call
`linkchat_package_encoded_len`, or call `linkchat_package_write` with a null
buffer and zero capacity as a sizing query. A short buffer returns
`LC_ERR_BUFFER_TOO_SMALL`, writes the required length, and copies no bytes.
There is no FFI allocator and therefore no FFI free function for output
buffers.

`LinkChatPackageMetadata` is `repr(C)` and contains only public metadata. It
does not contain the mailbox token, package authentication bytes, private
receiver material, or any Rust-owned pointer.

`LinkChatEndpointMetadata` and `LinkChatReceiveMetadata` are also fixed-layout
`repr(C)` values with no Rust-owned pointers. C callers remain responsible for
pointer validity, writable capacities, and not racing a handle with destroy.

## Thread safety

The handle registry is protected by a process-wide `Mutex`; individual calls
may be made from different threads. A handle must not be used concurrently
with its destroy call. The ABI does not provide a borrowing or aliasing
guarantee for caller-owned buffers beyond the duration of each call.

## Unsafe boundary

Rust raw pointers are unavoidable for a C ABI, so the crate contains a small,
audited boundary rather than unsafe protocol logic:

1. `copy_input` checks length and nullness, then copies exactly the caller's
   input slice. The pointer does not escape.
2. `write_u64` and `write_usize` check nullness before one scalar write.
3. `write_bytes` writes the required length, checks capacity before copying,
   rejects a null destination for non-empty output, and never partially writes.
4. Metadata functions write one `repr(C)` value after a null check.

Each helper uses explicit unsafe blocks. The core, wire codec, and handle
registry logic do not use unsafe operations. The tests cover malformed input,
null output, lifecycle/double destroy, endpoint prepare/commit, output sizing,
no-partial-write, and public metadata projection.

## Error and trust boundary

The ABI maps wire failures to stable categories and does not export Rust error
layout or error strings as an API contract. Canonical decoding, fixed field
lengths, and the 4096-byte envelope rules remain enforced by
`linkchat-protocol`. The FFI inherits the Rust type and codec trust boundary,
the platform allocator and mutex implementation, and the caller's memory
safety. It does not turn Rust tests into a proof of cryptographic security or
secure erasure.
