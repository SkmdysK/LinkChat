# Storage Backend Contract

`linkchat-storage` provides two backends:

- `FaultInjectingMemoryStorage` is a crash-order model for tests. It is not a
  production persistence backend.
- `FileStateStorage` stores endpoint-local state in a directory using separate
  `current.bin`, `pending.bin`, and `commit.marker` records.

## File Transaction

The file backend follows this order:

```text
validate Current and candidate
-> write Pending temporary file
-> sync Pending file
-> atomic rename Pending
-> sync directory
-> write and sync commit.marker
-> atomic publish complete Current
-> sync directory
-> remove Pending and marker
-> sync directory
```

Each state record contains the protocol package hash, previous package hash,
generation, session and turn context, consumed message identifiers, both local
private Receiver Packages, and an independent `LinkChat/storage-record/v1`
integrity hash. The storage record hash is not used as a protocol package hash.

Private X25519 and ML-KEM material is written only through the core-owned
storage codec. On restore, the public keys are recomputed from the private
material and the atomic private/public package binding is checked before the
state is returned.

## Recovery

Recovery accepts only a complete Current record, or a complete Pending record
with a matching durable commit marker. An unmarked Pending record is removed;
it cannot become Current. A marker mismatch, generation regression, hash-chain
failure, malformed record, or public/private key mismatch is rejected.

`FileStateStorage::rollback_resistant()` returns `false`. Ordinary filesystems
do not provide a protocol-level rollback guarantee, trusted monotonic storage,
secure erasure, or protection from a privileged operator restoring an older
directory snapshot. Callers that require rollback resistance must reject this
backend with `require_rollback_resistant` or provide a platform-specific
backend that can honestly return `true`.

The backend also does not provide inter-process locking. A deployment must
serialize access to one storage directory at the application boundary.
