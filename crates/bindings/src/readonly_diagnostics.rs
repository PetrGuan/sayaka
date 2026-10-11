// SPDX-License-Identifier: MPL-2.0
use super::*;
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SayakaDiagnosticsRequestV1 {
    pub abi_version: u32,
    pub struct_size: u32,
    pub id: u32,
    pub reserved: u32,
}
/// One-shot read-only observation; run off UI thread. No size-probe execution.
/// # Safety
/// Request and output pointers must be valid, aligned and disjoint. Buffer must
/// hold MAX_QUERY_BYTES; output JSON is independently capped at 512 KiB.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_diagnostics_run_v1(
    request: *const SayakaDiagnosticsRequestV1,
    buffer: *mut u8,
    capacity: usize,
    required: *mut usize,
) -> i32 {
    boundary(|| {
        unsafe { prepare_output(buffer, capacity, required, MAX_QUERY_BYTES)? };
        if capacity != MAX_QUERY_BYTES {
            return Err(INVALID_ARGUMENT);
        }
        pointer(request)?;
        let r = unsafe { *request };
        if r.abi_version != ABI_VERSION
            || r.struct_size as usize != size_of::<SayakaDiagnosticsRequestV1>()
        {
            return Err(UNSUPPORTED_VERSION);
        }
        if r.reserved != 0 {
            return Err(INVALID_ARGUMENT);
        }
        let id = sayaka_engine::readonly_diagnostics::Id::from_u32(r.id).ok_or(INVALID_ARGUMENT)?;
        let result = sayaka_engine::readonly_diagnostics::run(id);
        let bytes = bounded_json(&result, 512 * 1024)?;
        unsafe { copy_output(&bytes, buffer, capacity, required) }
    })
}
