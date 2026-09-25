// SPDX-License-Identifier: MPL-2.0

//! Bounded, on-demand system status for the native macOS client.

use super::*;
use sayaka_engine::model::Cancellation;
use sayaka_engine::status::{Config, NativeProvider, Sampler};
use std::time::Duration;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SayakaSystemStatusRequestV1 {
    pub abi_version: u32,
    pub struct_size: u32,
    pub reserved: u64,
}

/// Samples read-only system facts on demand. No process names or paths are
/// collected. This call may block for the 250 ms CPU counter window and native
/// probe time; clients must invoke it off the UI thread.
///
/// # Safety
/// The request must be readable/aligned. This volatile query is one-shot:
/// `buffer` must hold exactly `MAX_QUERY_BYTES` bytes; a size-probe call is
/// invalid. `required` is writable and disjoint from the request and buffer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_system_status_v1(
    request: *const SayakaSystemStatusRequestV1,
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
            || request.struct_size as usize != size_of::<SayakaSystemStatusRequestV1>()
        {
            return Err(UNSUPPORTED_VERSION);
        }
        if request.reserved != 0 {
            return Err(INVALID_ARGUMENT);
        }
        #[cfg(not(target_os = "macos"))]
        return Err(UNSUPPORTED_PLATFORM);
        #[cfg(target_os = "macos")]
        {
            let config = Config {
                interval: Duration::from_millis(250),
                process_top: None,
                ..Config::default()
            };
            let mut sampler = Sampler::new(NativeProvider, config).map_err(|_| INTERNAL_ERROR)?;
            let cancellation = Cancellation::default();
            sampler.sample(&cancellation).map_err(|_| INTERNAL_ERROR)?;
            std::thread::sleep(Duration::from_millis(250));
            let snapshot = sampler.sample(&cancellation).map_err(|_| INTERNAL_ERROR)?;
            let bytes = bounded_json(
                &serde_json::json!({
                    "schema_version": 1,
                    "kind": "system_status",
                    "snapshot": snapshot,
                }),
                MAX_QUERY_BYTES,
            )?;
            // SAFETY: Output was validated above; bytes are privately owned.
            unsafe { copy_output(&bytes, buffer, capacity, required) }
        }
    })
}
