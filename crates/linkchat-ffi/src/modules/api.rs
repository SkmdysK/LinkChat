use linkchat_core::{Endpoint, PublicReceiverPackage, ReceiverPackageFactory, Session};
use linkchat_crypto::{CryptoBackend, Ed25519PublicKey, OsCryptoBackend};
use linkchat_engine::{EndpointConfig, EndpointEngine, MemoryEndpointStorage};
use linkchat_protocol::encode;
use linkchat_types::{MessageId, PackageGeneration, PackageHash, SessionId, Turn};

use super::foundation::{
    BootstrapMaterial, HandleEntry, LC_ERR_INTERNAL, LC_ERR_INVALID_ARGUMENT,
    LC_ERR_INVALID_HANDLE, LC_ERR_NOT_READY, LC_ERR_NULL_POINTER, LC_OK, LinkChatEndpointMetadata,
    LinkChatPackageMetadata, LinkChatReceiveMetadata,
};
use super::helpers::{
    canonical_package, copy_fixed, copy_input, copy_optional_input, ensure_output, ffi_call,
    map_engine_error, map_wire_error, package_from_registry, write_bytes, write_u64, write_usize,
};
use super::registry::registry;

/// Create a context-only session handle. It contains no receiver secret or
/// complete protocol state and must be released with [`linkchat_session_destroy`].
///
/// # Safety
///
/// `out_handle` must be null or point to one writable `u64` for the duration
/// of the call. A null pointer returns an error without allocating a handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn linkchat_session_create(session_id: u64, out_handle: *mut u64) -> i32 {
    ffi_call(|| {
        if out_handle.is_null() {
            return LC_ERR_NULL_POINTER;
        }
        let mut guard = match registry().lock() {
            Ok(guard) => guard,
            Err(_) => return LC_ERR_INTERNAL,
        };
        let handle = match guard.insert(HandleEntry::Session(Session::new(SessionId::new(
            session_id,
        )))) {
            Ok(handle) => handle,
            Err(_) => return LC_ERR_INTERNAL,
        };
        // SAFETY: forwarded pointer has the same contract as this function.
        unsafe { write_u64(out_handle, handle) }
    })
}

/// Destroy a session handle. A second destroy returns [`LC_ERR_INVALID_HANDLE`].
///
/// # Safety
///
/// This function has no pointer arguments. The handle must be an opaque value
/// previously returned by this ABI or the function returns an error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn linkchat_session_destroy(handle: u64) -> i32 {
    ffi_call(|| {
        let mut guard = match registry().lock() {
            Ok(guard) => guard,
            Err(_) => return LC_ERR_INTERNAL,
        };
        match guard.remove(handle) {
            Some(HandleEntry::Session(_)) => LC_OK,
            Some(entry) => {
                guard.restore(handle, entry);
                LC_ERR_INVALID_HANDLE
            }
            None => LC_ERR_INVALID_HANDLE,
        }
    })
}

/// Return the session identifier from a session handle.
///
/// # Safety
///
/// `out_session_id` must be null or point to one writable `u64` for the
/// duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn linkchat_session_id(handle: u64, out_session_id: *mut u64) -> i32 {
    ffi_call(|| {
        let guard = match registry().lock() {
            Ok(guard) => guard,
            Err(_) => return LC_ERR_INTERNAL,
        };
        let session_id = match guard.get(handle) {
            Some(HandleEntry::Session(session)) => session.session_id().get(),
            _ => return LC_ERR_INVALID_HANDLE,
        };
        // SAFETY: forwarded pointer has the same contract as this function.
        unsafe { write_u64(out_session_id, session_id) }
    })
}

/// Decode and retain one canonical public Receiver Package.
///
/// # Safety
///
/// `input` must point to `input_len` readable bytes for the duration of the
/// call when `input_len` is non-zero. `out_handle` must point to one writable
/// `u64`. The function copies input bytes before returning.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn linkchat_package_open(
    input: *const u8,
    input_len: usize,
    out_handle: *mut u64,
) -> i32 {
    ffi_call(|| {
        if out_handle.is_null() {
            return LC_ERR_NULL_POINTER;
        }
        let bytes = match unsafe { copy_input(input, input_len) } {
            Ok(bytes) => bytes,
            Err(code) => return code,
        };
        let package = match canonical_package(&bytes) {
            Ok(package) => package,
            Err(code) => return code,
        };
        let mut guard = match registry().lock() {
            Ok(guard) => guard,
            Err(_) => return LC_ERR_INTERNAL,
        };
        let handle = match guard.insert(HandleEntry::Package(package)) {
            Ok(handle) => handle,
            Err(_) => return LC_ERR_INTERNAL,
        };
        // SAFETY: forwarded pointer has the same contract as this function.
        unsafe { write_u64(out_handle, handle) }
    })
}

/// Destroy a public Receiver Package handle.
///
/// # Safety
///
/// This function has no pointer arguments. The handle must be an opaque value
/// previously returned by this ABI or the function returns an error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn linkchat_package_destroy(handle: u64) -> i32 {
    ffi_call(|| {
        let mut guard = match registry().lock() {
            Ok(guard) => guard,
            Err(_) => return LC_ERR_INTERNAL,
        };
        match guard.remove(handle) {
            Some(HandleEntry::Package(_)) => LC_OK,
            Some(entry) => {
                guard.restore(handle, entry);
                LC_ERR_INVALID_HANDLE
            }
            None => LC_ERR_INVALID_HANDLE,
        }
    })
}

/// Return the canonical encoded size without writing bytes.
///
/// # Safety
///
/// `out_len` must be null or point to one writable `usize` for the duration of
/// the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn linkchat_package_encoded_len(handle: u64, out_len: *mut usize) -> i32 {
    ffi_call(|| {
        let package = match package_from_registry(handle) {
            Ok(package) => package,
            Err(code) => return code,
        };
        let encoded = match encode(&package) {
            Ok(encoded) => encoded,
            Err(error) => return map_wire_error(error),
        };
        // SAFETY: forwarded pointer has the same contract as this function.
        unsafe { write_usize(out_len, encoded.as_bytes().len()) }
    })
}

/// Write a canonical package to a caller-owned buffer. On a short buffer only
/// the required length is written and no package bytes are copied.
///
/// # Safety
///
/// `written` must point to one writable `usize`. If the output fits,
/// `out` must point to `capacity` writable bytes; a null `out` is permitted
/// for a sizing query with zero capacity.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn linkchat_package_write(
    handle: u64,
    out: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> i32 {
    ffi_call(|| {
        let package = match package_from_registry(handle) {
            Ok(package) => package,
            Err(code) => return code,
        };
        let encoded = match encode(&package) {
            Ok(encoded) => encoded,
            Err(error) => return map_wire_error(error),
        };
        // SAFETY: forwarded pointers have the same contract as this function.
        unsafe { write_bytes(encoded.as_bytes(), out, capacity, written) }
    })
}

/// Return public package metadata. Tokens, package authentication bytes, and
/// all private receiver material are intentionally absent from this struct.
///
/// # Safety
///
/// `out` must point to one writable `LinkChatPackageMetadata` for the duration
/// of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn linkchat_package_metadata(
    handle: u64,
    out: *mut LinkChatPackageMetadata,
) -> i32 {
    ffi_call(|| {
        if out.is_null() {
            return LC_ERR_NULL_POINTER;
        }
        let package = match package_from_registry(handle) {
            Ok(package) => package,
            Err(code) => return code,
        };
        let metadata = LinkChatPackageMetadata {
            protocol_major: package.protocol_version().major(),
            protocol_minor: package.protocol_version().minor(),
            cipher_suite: package.cipher_suite().id(),
            session_id: package.session_id().get(),
            turn: package.turn().get(),
            generation: package.generation().get(),
            key_id: package.key_id().get(),
            expiration: package.expiration(),
            x25519_public_key: package.x25519_public_key().into_array(),
            mlkem_public_key_len: package.mlkem_public_key().len() as u32,
            package_auth_len: package.package_auth().len() as u32,
        };
        // SAFETY: null was checked and the ABI requires a writable metadata
        // struct at `out`; the struct is repr(C) and contains no Rust-owned data.
        unsafe { out.write(metadata) };
        LC_OK
    })
}

type FfiEndpoint = EndpointEngine<OsCryptoBackend, MemoryEndpointStorage>;

fn parse_endpoint(value: u8) -> Result<Endpoint, i32> {
    match value {
        0 => Ok(Endpoint::Alice),
        1 => Ok(Endpoint::Bob),
        _ => Err(LC_ERR_INVALID_ARGUMENT),
    }
}

fn package_bytes(package: &PublicReceiverPackage) -> Result<Vec<u8>, i32> {
    let wire = package
        .to_wire()
        .map_err(|error| map_engine_error(error.into()))?;
    encode(&wire)
        .map(|encoded| encoded.into_vec())
        .map_err(map_wire_error)
}

fn bootstrap_package_bytes(bootstrap: &BootstrapMaterial) -> Result<Vec<u8>, i32> {
    package_bytes(bootstrap.local_package.public_projection())
}

/// Generate an opaque local bootstrap containing a private identity and
/// Receiver Package. Only its public identity and canonical package can be
/// exported; private material remains inside Rust.
///
/// # Safety
///
/// `bootstrap_previous_hash` must point to 32 readable bytes and `out_handle`
/// must point to one writable `u64`. Both pointers are used only during this
/// call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn linkchat_bootstrap_create(
    session_id: u64,
    endpoint: u8,
    bootstrap_previous_hash: *const u8,
    expiration: u64,
    now: u64,
    out_handle: *mut u64,
) -> i32 {
    ffi_call(|| {
        if out_handle.is_null() {
            return LC_ERR_NULL_POINTER;
        }
        if expiration <= now {
            return LC_ERR_INVALID_ARGUMENT;
        }
        let endpoint = match parse_endpoint(endpoint) {
            Ok(endpoint) => endpoint,
            Err(code) => return code,
        };
        let root = match unsafe { copy_fixed::<32>(bootstrap_previous_hash) } {
            Ok(bytes) => PackageHash::from_array(bytes),
            Err(code) => return code,
        };
        let session = Session::new(SessionId::new(session_id));
        let mut backend = OsCryptoBackend::new();
        let identity = match backend.generate_ed25519_keypair() {
            Ok(identity) => identity,
            Err(_) => return super::foundation::LC_ERR_CRYPTO,
        };
        let local_package = match ReceiverPackageFactory::generate(
            &mut backend,
            session,
            &identity.secret_key,
            Turn::new(0),
            PackageGeneration::new(0),
            expiration,
            root,
        ) {
            Ok(package) => package,
            Err(error) => return map_engine_error(error.into()),
        };
        let bootstrap = BootstrapMaterial {
            session,
            endpoint,
            identity,
            local_package,
            bootstrap_previous_hash: root,
            expiration,
            now,
        };
        let mut guard = match registry().lock() {
            Ok(guard) => guard,
            Err(_) => return LC_ERR_INTERNAL,
        };
        let handle = match guard.insert(HandleEntry::Bootstrap(Box::new(bootstrap))) {
            Ok(handle) => handle,
            Err(_) => return LC_ERR_INTERNAL,
        };
        unsafe { write_u64(out_handle, handle) }
    })
}

/// Destroy an unused bootstrap handle.
///
/// # Safety
///
/// This function has no pointer arguments. The handle must be a bootstrap
/// handle previously returned by this ABI.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn linkchat_bootstrap_destroy(handle: u64) -> i32 {
    ffi_call(|| {
        let mut guard = match registry().lock() {
            Ok(guard) => guard,
            Err(_) => return LC_ERR_INTERNAL,
        };
        match guard.remove(handle) {
            Some(HandleEntry::Bootstrap(_)) => LC_OK,
            Some(entry) => {
                guard.restore(handle, entry);
                LC_ERR_INVALID_HANDLE
            }
            None => LC_ERR_INVALID_HANDLE,
        }
    })
}

/// Export the bootstrap's public Ed25519 identity key.
///
/// # Safety
///
/// `out` must point to 32 writable bytes and `written` to one writable
/// `usize`. On a short buffer no key bytes are written.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn linkchat_bootstrap_identity_write(
    handle: u64,
    out: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> i32 {
    ffi_call(|| {
        let guard = match registry().lock() {
            Ok(guard) => guard,
            Err(_) => return LC_ERR_INTERNAL,
        };
        let bootstrap = match guard.get(handle) {
            Some(HandleEntry::Bootstrap(bootstrap)) => bootstrap,
            _ => return LC_ERR_INVALID_HANDLE,
        };
        unsafe {
            write_bytes(
                bootstrap.identity.public_key.as_bytes(),
                out,
                capacity,
                written,
            )
        }
    })
}

/// Return the canonical encoded size of the bootstrap's public Receiver Package.
///
/// # Safety
///
/// `out_len` must point to one writable `usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn linkchat_bootstrap_package_encoded_len(
    handle: u64,
    out_len: *mut usize,
) -> i32 {
    ffi_call(|| {
        let guard = match registry().lock() {
            Ok(guard) => guard,
            Err(_) => return LC_ERR_INTERNAL,
        };
        let bootstrap = match guard.get(handle) {
            Some(HandleEntry::Bootstrap(bootstrap)) => bootstrap,
            _ => return LC_ERR_INVALID_HANDLE,
        };
        let bytes = match bootstrap_package_bytes(bootstrap) {
            Ok(bytes) => bytes,
            Err(code) => return code,
        };
        unsafe { write_usize(out_len, bytes.len()) }
    })
}

/// Export the bootstrap's canonical public Receiver Package.
///
/// # Safety
///
/// `written` must point to one writable `usize`. If the output fits, `out`
/// must point to `capacity` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn linkchat_bootstrap_package_write(
    handle: u64,
    out: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> i32 {
    ffi_call(|| {
        let guard = match registry().lock() {
            Ok(guard) => guard,
            Err(_) => return LC_ERR_INTERNAL,
        };
        let bootstrap = match guard.get(handle) {
            Some(HandleEntry::Bootstrap(bootstrap)) => bootstrap,
            _ => return LC_ERR_INVALID_HANDLE,
        };
        let bytes = match bootstrap_package_bytes(bootstrap) {
            Ok(bytes) => bytes,
            Err(code) => return code,
        };
        unsafe { write_bytes(&bytes, out, capacity, written) }
    })
}

/// Create an endpoint from a private bootstrap and the peer's public identity
/// and Receiver Package. The bootstrap is consumed only after success.
///
/// # Safety
///
/// `peer_identity` must point to 32 readable bytes, `peer_package` to
/// `peer_package_len` readable bytes, and `out_handle` to one writable `u64`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn linkchat_endpoint_create_from_bootstrap(
    bootstrap_handle: u64,
    peer_identity: *const u8,
    peer_package: *const u8,
    peer_package_len: usize,
    out_handle: *mut u64,
) -> i32 {
    ffi_call(|| {
        if out_handle.is_null() {
            return LC_ERR_NULL_POINTER;
        }
        let peer_identity = match unsafe { copy_fixed::<32>(peer_identity) } {
            Ok(bytes) => Ed25519PublicKey::from_array(bytes),
            Err(code) => return code,
        };
        let package_bytes = match unsafe { copy_input(peer_package, peer_package_len) } {
            Ok(bytes) => bytes,
            Err(code) => return code,
        };
        let package = match canonical_package(&package_bytes) {
            Ok(package) => match PublicReceiverPackage::from_wire(&package) {
                Ok(package) => package,
                Err(error) => return map_engine_error(error.into()),
            },
            Err(code) => return code,
        };
        let mut guard = match registry().lock() {
            Ok(guard) => guard,
            Err(_) => return LC_ERR_INTERNAL,
        };
        let bootstrap = match guard.get(bootstrap_handle) {
            Some(HandleEntry::Bootstrap(bootstrap)) => bootstrap,
            _ => return LC_ERR_INVALID_HANDLE,
        };
        let config = EndpointConfig::from_identity_keypair(
            bootstrap.session,
            bootstrap.endpoint,
            bootstrap.identity.clone(),
            peer_identity,
            bootstrap.bootstrap_previous_hash,
            bootstrap.expiration,
            bootstrap.now,
        );
        let backend = OsCryptoBackend::new();
        let engine = match FfiEndpoint::create_with_local_package(
            backend,
            MemoryEndpointStorage::empty(),
            config,
            bootstrap.local_package.clone(),
            package,
        ) {
            Ok(engine) => engine,
            Err(error) => return map_engine_error(error),
        };
        let handle = match guard.insert(HandleEntry::Endpoint(Box::new(engine))) {
            Ok(handle) => handle,
            Err(_) => return LC_ERR_INTERNAL,
        };
        let _ = guard.remove(bootstrap_handle);
        unsafe { write_u64(out_handle, handle) }
    })
}

/// Create an endpoint handle. The local identity and local Receiver Package
/// are generated inside Rust; no private key crosses the ABI.
///
/// `endpoint` is 0 for Alice and 1 for Bob. `peer_identity` and
/// `bootstrap_previous_hash` are fixed 32-byte public inputs. The peer package
/// must be a canonical encoded public Receiver Package.
///
/// # Safety
///
/// `peer_identity` and `bootstrap_previous_hash` must each point to 32
/// readable bytes. `peer_package` must point to `peer_package_len` readable
/// bytes. `out_handle` must point to one writable `u64`. All pointers are
/// accessed only for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn linkchat_endpoint_create(
    session_id: u64,
    endpoint: u8,
    peer_identity: *const u8,
    bootstrap_previous_hash: *const u8,
    peer_package: *const u8,
    peer_package_len: usize,
    expiration: u64,
    now: u64,
    out_handle: *mut u64,
) -> i32 {
    ffi_call(|| {
        if out_handle.is_null() {
            return LC_ERR_NULL_POINTER;
        }
        let endpoint = match endpoint {
            0 => Endpoint::Alice,
            1 => Endpoint::Bob,
            _ => return LC_ERR_INVALID_ARGUMENT,
        };
        let peer_identity = match unsafe { copy_fixed::<32>(peer_identity) } {
            Ok(bytes) => Ed25519PublicKey::from_array(bytes),
            Err(code) => return code,
        };
        let root = match unsafe { copy_fixed::<32>(bootstrap_previous_hash) } {
            Ok(bytes) => PackageHash::from_array(bytes),
            Err(code) => return code,
        };
        let package_bytes = match unsafe { copy_input(peer_package, peer_package_len) } {
            Ok(bytes) => bytes,
            Err(code) => return code,
        };
        let package = match canonical_package(&package_bytes) {
            Ok(package) => match PublicReceiverPackage::from_wire(&package) {
                Ok(package) => package,
                Err(error) => return map_engine_error(error.into()),
            },
            Err(code) => return code,
        };
        let mut backend = OsCryptoBackend::new();
        let identity = match backend.generate_ed25519_keypair() {
            Ok(identity) => identity,
            Err(_) => return super::foundation::LC_ERR_CRYPTO,
        };
        let config = EndpointConfig::from_identity_keypair(
            Session::new(SessionId::new(session_id)),
            endpoint,
            identity,
            peer_identity,
            root,
            expiration,
            now,
        );
        let engine =
            match FfiEndpoint::create(backend, MemoryEndpointStorage::empty(), config, package) {
                Ok(engine) => engine,
                Err(error) => return map_engine_error(error),
            };
        let mut guard = match registry().lock() {
            Ok(guard) => guard,
            Err(_) => return LC_ERR_INTERNAL,
        };
        let handle = match guard.insert(HandleEntry::Endpoint(Box::new(engine))) {
            Ok(handle) => handle,
            Err(_) => return LC_ERR_INTERNAL,
        };
        // SAFETY: forwarded pointer has the same contract as this function.
        unsafe { write_u64(out_handle, handle) }
    })
}

/// Destroy an endpoint and any uncommitted prepare handles owned by it.
///
/// # Safety
///
/// This function has no pointer arguments. The handle must be an endpoint
/// handle previously returned by this ABI.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn linkchat_endpoint_destroy(handle: u64) -> i32 {
    ffi_call(|| {
        let mut guard = match registry().lock() {
            Ok(guard) => guard,
            Err(_) => return LC_ERR_INTERNAL,
        };
        match guard.remove(handle) {
            Some(HandleEntry::Endpoint(_)) => {
                guard.remove_endpoint_children(handle);
                LC_OK
            }
            Some(entry) => {
                guard.restore(handle, entry);
                LC_ERR_INVALID_HANDLE
            }
            None => LC_ERR_INVALID_HANDLE,
        }
    })
}

/// Return public endpoint snapshot metadata. Tokens, authentication bytes,
/// private keys, and consumed message identifiers are not returned.
///
/// # Safety
///
/// `out` must point to one writable `LinkChatEndpointMetadata` for the
/// duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn linkchat_endpoint_metadata(
    handle: u64,
    out: *mut LinkChatEndpointMetadata,
) -> i32 {
    ffi_call(|| {
        if out.is_null() {
            return LC_ERR_NULL_POINTER;
        }
        let guard = match registry().lock() {
            Ok(guard) => guard,
            Err(_) => return LC_ERR_INTERNAL,
        };
        let engine = match guard.get(handle) {
            Some(HandleEntry::Endpoint(engine)) => engine,
            _ => return LC_ERR_INVALID_HANDLE,
        };
        let snapshot = engine.public_snapshot();
        let local = engine.public_receiver_package();
        let peer = engine.peer_public_receiver_package();
        let metadata = LinkChatEndpointMetadata {
            session_id: snapshot.session().session_id().get(),
            endpoint: match engine.endpoint() {
                Endpoint::Alice => 0,
                Endpoint::Bob => 1,
            },
            reserved: [0; 7],
            turn: snapshot.turn().get(),
            consumed_message_count: snapshot.consumed_message_ids().len() as u64,
            local_identity_public: engine.local_identity_public().into_array(),
            peer_identity_public: engine.peer_identity_public().into_array(),
            local_generation: local.generation().get(),
            local_key_id: local.key_id().get(),
            local_expiration: local.expiration(),
            local_x25519_public_key: local.x25519_public_key().into_array(),
            local_mlkem_public_key_len: local.mlkem_public_key().len() as u32,
            local_package_auth_len: local.package_auth().len() as u32,
            peer_generation: peer.generation().get(),
            peer_key_id: peer.key_id().get(),
            peer_expiration: peer.expiration(),
            peer_x25519_public_key: peer.x25519_public_key().into_array(),
            peer_mlkem_public_key_len: peer.mlkem_public_key().len() as u32,
            peer_package_auth_len: peer.package_auth().len() as u32,
        };
        // SAFETY: null was checked and the ABI requires one writable repr(C)
        // metadata value.
        unsafe { out.write(metadata) };
        LC_OK
    })
}

fn endpoint_package_bytes(engine: &FfiEndpoint) -> Result<Vec<u8>, i32> {
    let wire = engine
        .public_receiver_package()
        .to_wire()
        .map_err(|error| map_engine_error(error.into()))?;
    encode(&wire)
        .map(|encoded| encoded.into_vec())
        .map_err(map_wire_error)
}

/// Return the canonical encoded size of the endpoint's public Receiver Package.
///
/// # Safety
///
/// `out_len` must point to one writable `usize` for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn linkchat_endpoint_package_encoded_len(
    handle: u64,
    out_len: *mut usize,
) -> i32 {
    ffi_call(|| {
        let guard = match registry().lock() {
            Ok(guard) => guard,
            Err(_) => return LC_ERR_INTERNAL,
        };
        let engine = match guard.get(handle) {
            Some(HandleEntry::Endpoint(engine)) => engine,
            _ => return LC_ERR_INVALID_HANDLE,
        };
        let bytes = match endpoint_package_bytes(engine) {
            Ok(bytes) => bytes,
            Err(code) => return code,
        };
        // SAFETY: forwarded pointer has the same contract as this function.
        unsafe { write_usize(out_len, bytes.len()) }
    })
}

/// Write the endpoint's public Receiver Package to caller-owned memory.
///
/// # Safety
///
/// `written` must point to one writable `usize`. If the output fits, `out`
/// must point to `capacity` writable bytes. A null `out` is allowed only for a
/// sizing query with zero capacity.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn linkchat_endpoint_package_write(
    handle: u64,
    out: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> i32 {
    ffi_call(|| {
        let guard = match registry().lock() {
            Ok(guard) => guard,
            Err(_) => return LC_ERR_INTERNAL,
        };
        let engine = match guard.get(handle) {
            Some(HandleEntry::Endpoint(engine)) => engine,
            _ => return LC_ERR_INVALID_HANDLE,
        };
        let bytes = match endpoint_package_bytes(engine) {
            Ok(bytes) => bytes,
            Err(code) => return code,
        };
        // SAFETY: forwarded pointers have the same contract as this function.
        unsafe { write_bytes(&bytes, out, capacity, written) }
    })
}

/// Prepare an application send and return its canonical 4096-byte Envelope.
/// The returned handle must be committed or destroyed with the endpoint.
///
/// # Safety
///
/// `payload` must point to `payload_len` readable bytes when `payload_len` is
/// non-zero. `out_written` and `out_prepare_handle` must be writable scalar
/// outputs. If the envelope fits, `out_envelope` must point to writable
/// `envelope_capacity` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn linkchat_endpoint_send_prepare(
    endpoint_handle: u64,
    message_id: u64,
    payload: *const u8,
    payload_len: usize,
    now: u64,
    out_envelope: *mut u8,
    envelope_capacity: usize,
    out_written: *mut usize,
    out_prepare_handle: *mut u64,
) -> i32 {
    ffi_call(|| {
        if out_prepare_handle.is_null() {
            return LC_ERR_NULL_POINTER;
        }
        let payload = match unsafe { copy_optional_input(payload, payload_len) } {
            Ok(payload) => payload,
            Err(code) => return code,
        };
        let mut guard = match registry().lock() {
            Ok(guard) => guard,
            Err(_) => return LC_ERR_INTERNAL,
        };
        let prepared = match guard.get_mut(endpoint_handle) {
            Some(HandleEntry::Endpoint(engine)) => {
                match engine.prepare_send(MessageId::new(message_id), &payload, now) {
                    Ok(prepared) => prepared,
                    Err(error) => return map_engine_error(error),
                }
            }
            _ => return LC_ERR_INVALID_HANDLE,
        };
        let code = unsafe {
            write_bytes(
                prepared.encoded().as_bytes(),
                out_envelope,
                envelope_capacity,
                out_written,
            )
        };
        if code != LC_OK {
            return code;
        }
        let handle = match guard.insert(HandleEntry::PreparedSend {
            endpoint: endpoint_handle,
            prepared,
        }) {
            Ok(handle) => handle,
            Err(_) => return LC_ERR_INTERNAL,
        };
        unsafe { write_u64(out_prepare_handle, handle) }
    })
}

/// Commit a prepared send. This is the only send operation that advances the
/// endpoint state through its configured storage adapter.
///
/// # Safety
///
/// This function has no pointer arguments. The handle must be a current
/// prepared-send handle returned by this ABI.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn linkchat_endpoint_send_commit(prepare_handle: u64) -> i32 {
    ffi_call(|| {
        let mut guard = match registry().lock() {
            Ok(guard) => guard,
            Err(_) => return LC_ERR_INTERNAL,
        };
        let entry = match guard.remove(prepare_handle) {
            Some(HandleEntry::PreparedSend { endpoint, prepared }) => (endpoint, prepared),
            Some(entry) => {
                guard.restore(prepare_handle, entry);
                return LC_ERR_INVALID_HANDLE;
            }
            None => return LC_ERR_INVALID_HANDLE,
        };
        let (endpoint, prepared) = entry;
        let result = match guard.get_mut(endpoint) {
            Some(HandleEntry::Endpoint(engine)) => engine.commit_send(prepared),
            _ => return LC_ERR_NOT_READY,
        };
        match result {
            Ok(_) => LC_OK,
            Err(error) => map_engine_error(error),
        }
    })
}

/// Prepare an Envelope receive. No endpoint state changes until commit.
///
/// # Safety
///
/// `envelope` must point to `envelope_len` readable bytes for the duration of
/// the call. `out_prepare_handle` must point to one writable `u64`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn linkchat_endpoint_receive_prepare(
    endpoint_handle: u64,
    envelope: *const u8,
    envelope_len: usize,
    now: u64,
    next_expiration: u64,
    out_prepare_handle: *mut u64,
) -> i32 {
    ffi_call(|| {
        if out_prepare_handle.is_null() {
            return LC_ERR_NULL_POINTER;
        }
        let envelope = match unsafe { copy_input(envelope, envelope_len) } {
            Ok(envelope) => envelope,
            Err(code) => return code,
        };
        let mut guard = match registry().lock() {
            Ok(guard) => guard,
            Err(_) => return LC_ERR_INTERNAL,
        };
        let prepared = match guard.get_mut(endpoint_handle) {
            Some(HandleEntry::Endpoint(engine)) => {
                match engine.prepare_receive(&envelope, now, next_expiration) {
                    Ok(prepared) => prepared,
                    Err(error) => return map_engine_error(error),
                }
            }
            _ => return LC_ERR_INVALID_HANDLE,
        };
        let handle = match guard.insert(HandleEntry::PreparedReceive {
            endpoint: endpoint_handle,
            prepared,
        }) {
            Ok(handle) => handle,
            Err(_) => return LC_ERR_INTERNAL,
        };
        unsafe { write_u64(out_prepare_handle, handle) }
    })
}

/// Commit a prepared receive and copy the authenticated payload and returned
/// public Receiver Package to caller-owned buffers.
///
/// # Safety
///
/// `payload_written`, `package_written`, and `metadata_out` must be writable
/// outputs. If either output fits, its buffer must point to the corresponding
/// number of writable bytes. A null output buffer is allowed only when the
/// corresponding output length is zero.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn linkchat_endpoint_receive_commit(
    prepare_handle: u64,
    payload_out: *mut u8,
    payload_capacity: usize,
    payload_written: *mut usize,
    package_out: *mut u8,
    package_capacity: usize,
    package_written: *mut usize,
    metadata_out: *mut LinkChatReceiveMetadata,
) -> i32 {
    ffi_call(|| {
        if metadata_out.is_null() {
            return LC_ERR_NULL_POINTER;
        }
        let mut guard = match registry().lock() {
            Ok(guard) => guard,
            Err(_) => return LC_ERR_INTERNAL,
        };
        let (payload_len, package_bytes) = match guard.get(prepare_handle) {
            Some(HandleEntry::PreparedReceive { prepared, .. }) => {
                let package = match prepared.returned_receiver_package().to_wire() {
                    Ok(package) => package,
                    Err(error) => return map_engine_error(error.into()),
                };
                let package_bytes = match encode(&package) {
                    Ok(bytes) => bytes.into_vec(),
                    Err(error) => return map_wire_error(error),
                };
                (prepared.plaintext().len(), package_bytes)
            }
            _ => return LC_ERR_INVALID_HANDLE,
        };
        let payload_code =
            unsafe { ensure_output(payload_len, payload_out, payload_capacity, payload_written) };
        let package_code = unsafe {
            ensure_output(
                package_bytes.len(),
                package_out,
                package_capacity,
                package_written,
            )
        };
        if payload_code != LC_OK {
            return payload_code;
        }
        if package_code != LC_OK {
            return package_code;
        }
        let (endpoint, prepared) = match guard.remove(prepare_handle) {
            Some(HandleEntry::PreparedReceive { endpoint, prepared }) => (endpoint, prepared),
            _ => return LC_ERR_INVALID_HANDLE,
        };
        let result = match guard.get_mut(endpoint) {
            Some(HandleEntry::Endpoint(engine)) => match engine.commit_receive(prepared) {
                Ok(result) => result,
                Err(error) => return map_engine_error(error),
            },
            _ => return LC_ERR_NOT_READY,
        };
        // SAFETY: capacity and nullness were checked before the state commit.
        unsafe {
            if payload_len != 0 {
                std::ptr::copy_nonoverlapping(
                    result.plaintext().as_bytes().as_ptr(),
                    payload_out,
                    payload_len,
                );
            }
            if !package_bytes.is_empty() {
                std::ptr::copy_nonoverlapping(
                    package_bytes.as_ptr(),
                    package_out,
                    package_bytes.len(),
                );
            }
            metadata_out.write(LinkChatReceiveMetadata {
                message_id: result.message_id().get(),
                payload_len,
                returned_package_len: package_bytes.len(),
            });
        }
        LC_OK
    })
}

/// Recover endpoint-local state through its storage adapter.
///
/// # Safety
///
/// This function has no pointer arguments. The handle must be an endpoint
/// handle previously returned by this ABI.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn linkchat_endpoint_recover(handle: u64) -> i32 {
    ffi_call(|| {
        let mut guard = match registry().lock() {
            Ok(guard) => guard,
            Err(_) => return LC_ERR_INTERNAL,
        };
        match guard.get_mut(handle) {
            Some(HandleEntry::Endpoint(engine)) => match engine.recover() {
                Ok(_) => LC_OK,
                Err(error) => map_engine_error(error),
            },
            _ => LC_ERR_INVALID_HANDLE,
        }
    })
}
