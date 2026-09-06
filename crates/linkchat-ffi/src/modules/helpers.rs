use std::panic::{AssertUnwindSafe, catch_unwind};

use linkchat_engine::EngineError;
use linkchat_protocol::{WireError, WireReceiverPackage, decode_receiver_package, encode};

use super::foundation::{
    HandleEntry, LC_ERR_BUFFER_TOO_SMALL, LC_ERR_INTERNAL, LC_ERR_INVALID_HANDLE,
    LC_ERR_INVALID_LENGTH, LC_ERR_NON_CANONICAL, LC_ERR_NULL_POINTER, LC_ERR_WIRE, MAX_FFI_INPUT,
};
use super::registry::registry;

pub(crate) fn ffi_call(operation: impl FnOnce() -> i32) -> i32 {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(code) => code,
        Err(_) => LC_ERR_INTERNAL,
    }
}

pub(crate) fn map_wire_error(_: WireError) -> i32 {
    LC_ERR_WIRE
}

pub(crate) fn map_engine_error(error: EngineError) -> i32 {
    match error {
        EngineError::Wire(_) => LC_ERR_WIRE,
        EngineError::Cryptographic(_) => super::foundation::LC_ERR_CRYPTO,
        EngineError::Rejected(_) => super::foundation::LC_ERR_REJECTED,
        EngineError::Storage(_) => super::foundation::LC_ERR_STORAGE,
        EngineError::RetryableTransport => super::foundation::LC_ERR_RETRYABLE,
        EngineError::StalePreparedOperation | EngineError::NoPreparedOperation => {
            super::foundation::LC_ERR_NOT_READY
        }
        EngineError::Configuration | EngineError::Core(_) => {
            super::foundation::LC_ERR_INVALID_ARGUMENT
        }
    }
}

pub(crate) unsafe fn copy_fixed<const N: usize>(ptr: *const u8) -> Result<[u8; N], i32> {
    if ptr.is_null() {
        return Err(LC_ERR_NULL_POINTER);
    }
    let mut bytes = [0; N];
    // SAFETY: the ABI contract requires a readable N-byte input at ptr.
    unsafe { std::ptr::copy_nonoverlapping(ptr, bytes.as_mut_ptr(), N) };
    Ok(bytes)
}

pub(crate) unsafe fn ensure_output(
    bytes_len: usize,
    out: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> i32 {
    if written.is_null() {
        return LC_ERR_NULL_POINTER;
    }
    // SAFETY: null was checked and the ABI requires a writable usize at
    // `written`; this records the required size even on a short-buffer error.
    unsafe { written.write(bytes_len) };
    if bytes_len > capacity {
        return LC_ERR_BUFFER_TOO_SMALL;
    }
    if bytes_len != 0 && out.is_null() {
        return LC_ERR_NULL_POINTER;
    }
    0
}

pub(crate) fn canonical_package(bytes: &[u8]) -> Result<WireReceiverPackage, i32> {
    let package = decode_receiver_package(bytes).map_err(map_wire_error)?;
    let canonical = encode(&package).map_err(map_wire_error)?;
    if canonical.as_bytes() != bytes {
        return Err(LC_ERR_NON_CANONICAL);
    }
    Ok(package)
}

pub(crate) unsafe fn copy_input(ptr: *const u8, len: usize) -> Result<Vec<u8>, i32> {
    if len == 0 || len > MAX_FFI_INPUT {
        return Err(LC_ERR_INVALID_LENGTH);
    }
    if ptr.is_null() {
        return Err(LC_ERR_NULL_POINTER);
    }
    // SAFETY: the caller contract requires `ptr` to reference `len` readable
    // bytes for the duration of this call. The bytes are copied immediately;
    // no borrowed pointer escapes the ABI boundary.
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec())
}

pub(crate) unsafe fn copy_optional_input(ptr: *const u8, len: usize) -> Result<Vec<u8>, i32> {
    if len > MAX_FFI_INPUT {
        return Err(LC_ERR_INVALID_LENGTH);
    }
    if len == 0 {
        return Ok(Vec::new());
    }
    unsafe { copy_input(ptr, len) }
}

pub(crate) unsafe fn write_u64(out: *mut u64, value: u64) -> i32 {
    if out.is_null() {
        return LC_ERR_NULL_POINTER;
    }
    // SAFETY: null was checked and the ABI requires a writable u64 at `out`.
    unsafe { out.write(value) };
    0
}

pub(crate) unsafe fn write_usize(out: *mut usize, value: usize) -> i32 {
    if out.is_null() {
        return LC_ERR_NULL_POINTER;
    }
    // SAFETY: null was checked and the ABI requires a writable usize at `out`.
    unsafe { out.write(value) };
    0
}

pub(crate) unsafe fn write_bytes(
    bytes: &[u8],
    out: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> i32 {
    if written.is_null() {
        return LC_ERR_NULL_POINTER;
    }
    // SAFETY: null was checked and the ABI requires a writable usize at `written`.
    unsafe { written.write(bytes.len()) };
    if bytes.len() > capacity {
        return LC_ERR_BUFFER_TOO_SMALL;
    }
    if !bytes.is_empty() && out.is_null() {
        return LC_ERR_NULL_POINTER;
    }
    // SAFETY: the caller contract requires `out` to reference `capacity`
    // writable bytes. The capacity check above proves the copy fits.
    if !bytes.is_empty() {
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len()) };
    }
    0
}

pub(crate) fn package_from_registry(handle: u64) -> Result<WireReceiverPackage, i32> {
    let guard = registry().lock().map_err(|_| LC_ERR_INTERNAL)?;
    match guard.get(handle) {
        Some(HandleEntry::Package(package)) => Ok(package.clone()),
        _ => Err(LC_ERR_INVALID_HANDLE),
    }
}
