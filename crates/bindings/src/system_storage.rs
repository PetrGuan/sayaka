// SPDX-License-Identifier: MPL-2.0

//! Bounded, on-demand system storage for the native macOS client.

use super::*;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SayakaSystemStorageRequestV1 {
    pub abi_version: u32,
    pub struct_size: u32,
    pub reserved: u64,
}

/// Samples read-only system facts on demand. No process names or paths are
/// collected. This call may block for the 20-second observation deadline and bounded
/// probe time; clients must invoke it off the UI thread.
///
/// # Safety
/// The request must be readable/aligned. This volatile query is one-shot:
/// `buffer` must hold exactly `MAX_QUERY_BYTES` bytes; a size-probe call is
/// invalid. `required` is writable and disjoint from the request and buffer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_system_storage_overview_v1(
    request: *const SayakaSystemStorageRequestV1,
    buffer: *mut u8,
    capacity: usize,
    required: *mut usize,
) -> i32 {
    boundary(|| {
        // SAFETY: Caller promises valid, non-overlapping output storage.
        unsafe { prepare_output(buffer, capacity, required, MAX_QUERY_BYTES)? };
        if capacity != MAX_QUERY_BYTES {
            return Err(INVALID_ARGUMENT);
        }
        pointer(request)?;
        // SAFETY: Caller promises readable, aligned request storage.
        let request = unsafe { *request };
        if request.abi_version != ABI_VERSION
            || request.struct_size as usize != size_of::<SayakaSystemStorageRequestV1>()
        {
            return Err(UNSUPPORTED_VERSION);
        }
        if request.reserved != 0 {
            return Err(INVALID_ARGUMENT);
        }
        let bytes = bounded_json(&sayaka_engine::system_storage::overview(), MAX_QUERY_BYTES)?;
        // SAFETY: validated caller output and privately owned serialized bytes.
        unsafe { copy_output(&bytes, buffer, capacity, required) }
    })
}

/// Samples read-only system facts on demand. No process names or paths are
/// collected. This call may block for the 2-second cooperative metadata budget and native
/// probe time; clients must invoke it off the UI thread.
///
/// # Safety
/// The request must be readable/aligned. This volatile query is one-shot:
/// `buffer` must hold exactly `MAX_QUERY_BYTES` bytes; a size-probe call is
/// invalid. `required` is writable and disjoint from the request and buffer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_firmware_preview_v1(
    request: *const SayakaSystemStorageRequestV1,
    buffer: *mut u8,
    capacity: usize,
    required: *mut usize,
) -> i32 {
    boundary(|| {
        // SAFETY: Caller promises valid, non-overlapping output storage.
        unsafe { prepare_output(buffer, capacity, required, MAX_QUERY_BYTES)? };
        if capacity != MAX_QUERY_BYTES {
            return Err(INVALID_ARGUMENT);
        }
        pointer(request)?;
        // SAFETY: Caller promises readable, aligned request storage.
        let request = unsafe { *request };
        if request.abi_version != ABI_VERSION
            || request.struct_size as usize != size_of::<SayakaSystemStorageRequestV1>()
        {
            return Err(UNSUPPORTED_VERSION);
        }
        if request.reserved != 0 {
            return Err(INVALID_ARGUMENT);
        }
        let bytes = bounded_json(&sayaka_engine::firmware::preview(), MAX_QUERY_BYTES)?;
        // SAFETY: validated caller output and privately owned serialized bytes.
        unsafe { copy_output(&bytes, buffer, capacity, required) }
    })
}

/// Samples read-only system facts on demand. No process names or paths are
/// collected. This call may block for the 5-second cooperative metadata budget and native
/// probe time; clients must invoke it off the UI thread.
///
/// # Safety
/// The request must be readable/aligned. This volatile query is one-shot:
/// `buffer` must hold exactly `MAX_QUERY_BYTES` bytes; a size-probe call is
/// invalid. `required` is writable and disjoint from the request and buffer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_macos_installer_preview_v1(
    request: *const SayakaSystemStorageRequestV1,
    buffer: *mut u8,
    capacity: usize,
    required: *mut usize,
) -> i32 {
    boundary(|| {
        // SAFETY: Caller promises valid, non-overlapping output storage.
        unsafe { prepare_output(buffer, capacity, required, MAX_QUERY_BYTES)? };
        if capacity != MAX_QUERY_BYTES {
            return Err(INVALID_ARGUMENT);
        }
        pointer(request)?;
        // SAFETY: Caller promises readable, aligned request storage.
        let request = unsafe { *request };
        if request.abi_version != ABI_VERSION
            || request.struct_size as usize != size_of::<SayakaSystemStorageRequestV1>()
        {
            return Err(UNSUPPORTED_VERSION);
        }
        if request.reserved != 0 {
            return Err(INVALID_ARGUMENT);
        }
        let bytes = bounded_json(&sayaka_engine::macos_installers::preview(), MAX_QUERY_BYTES)?;
        // SAFETY: validated caller output and privately owned serialized bytes.
        unsafe { copy_output(&bytes, buffer, capacity, required) }
    })
}
