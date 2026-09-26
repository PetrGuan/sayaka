// SPDX-License-Identifier: MPL-2.0

//! Static App Store maintenance availability, with no filesystem access or effects.

use super::*;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SayakaMaintenanceCatalogRequestV1 {
    pub abi_version: u32,
    pub struct_size: u32,
    pub reserved: u64,
}

/// Returns a versioned JSON catalog. No application or user data is read.
///
/// # Safety
/// The request must be readable and aligned. `required` must be writable and
/// disjoint from request/buffer. Nonzero capacity needs a writable buffer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_maintenance_catalog_v1(
    request: *const SayakaMaintenanceCatalogRequestV1,
    buffer: *mut u8,
    capacity: usize,
    required: *mut usize,
) -> i32 {
    boundary(|| {
        // SAFETY: Caller promises valid, non-overlapping output storage.
        unsafe { prepare_output(buffer, capacity, required, MAX_QUERY_BYTES)? };
        pointer(request)?;
        // SAFETY: Caller promises a readable, aligned request.
        let request = unsafe { *request };
        if request.abi_version != ABI_VERSION
            || request.struct_size as usize != size_of::<SayakaMaintenanceCatalogRequestV1>()
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
            let bytes = sayaka_engine::maintenance_catalog::JSON_V1.as_bytes();
            // SAFETY: Output was validated above; bytes are static.
            unsafe { copy_output(bytes, buffer, capacity, required) }
        }
    })
}
