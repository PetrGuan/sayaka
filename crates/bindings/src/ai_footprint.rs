// SPDX-License-Identifier: MPL-2.0

//! Read-only AI footprint projection over a completed explicit scan.

use super::*;
use sayaka_engine::ai_footprint::{Tool, project};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SayakaAIFootprintRequestV1 {
    pub abi_version: u32,
    pub struct_size: u32,
    pub tool: u32,
    pub reserved: u32,
}

/// Projects one immutable scan snapshot. The result cannot be used as an
/// execution selection; it contains no cleanup IDs or authorization tokens.
///
/// # Safety
/// `request` is readable/aligned; output storage follows the query buffer
/// contract and does not overlap the request or `required`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_scan_ai_footprint_v1(
    handle: u64,
    request: *const SayakaAIFootprintRequestV1,
    buffer: *mut u8,
    capacity: usize,
    required: *mut usize,
) -> i32 {
    boundary(|| {
        // SAFETY: Caller supplies valid non-overlapping output storage.
        unsafe { prepare_output(buffer, capacity, required, MAX_QUERY_BYTES)? };
        pointer(request)?;
        // SAFETY: Caller supplies a readable/aligned request.
        let request = unsafe { *request };
        if request.abi_version != ABI_VERSION
            || request.struct_size as usize != size_of::<SayakaAIFootprintRequestV1>()
        {
            return Err(UNSUPPORTED_VERSION);
        }
        if request.reserved != 0 {
            return Err(INVALID_ARGUMENT);
        }
        let tool = Tool::from_code(request.tool).ok_or(INVALID_ARGUMENT)?;
        let slot = get(handle)?;
        let mut job = lock_job(&slot)?;
        ensure_open(&job)?;
        #[cfg(debug_assertions)]
        let started = std::time::Instant::now();
        let tree = browse::tree(&mut job)?;
        #[cfg(debug_assertions)]
        let tree_us = started.elapsed().as_micros();
        let footprint = project(tree, tool).ok_or(QUERY_UNAVAILABLE)?;
        #[cfg(debug_assertions)]
        let project_us = started.elapsed().as_micros() - tree_us;
        let bytes = bounded_json(&footprint, MAX_QUERY_BYTES)?;
        #[cfg(debug_assertions)]
        eprintln!("[SayakaTraversal] event=ai_projection handle={} tool={} entries={} tree_us={} project_us={} total_us={} bytes={} probe={}", handle, request.tool, tree.report().entries.len(), tree_us, project_us, started.elapsed().as_micros(), bytes.len(), capacity == 0);
        // SAFETY: Output was validated above; bytes are privately owned.
        unsafe { copy_output(&bytes, buffer, capacity, required) }
    })
}
