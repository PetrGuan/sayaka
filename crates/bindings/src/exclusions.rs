// SPDX-License-Identifier: MPL-2.0

//! App-scoped access to the shared identity-bound exclusion policy.

use super::*;
use sayaka_engine::clean_policy;
use sayaka_engine::scan::wire;
use serde_json::json;

pub const EXCLUSIONS_LIST: u32 = 1;
pub const EXCLUSIONS_ADD: u32 = 2;
pub const EXCLUSIONS_REMOVE: u32 = 3;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SayakaExclusionsRequestV1 {
    pub abi_version: u32,
    pub struct_size: u32,
    pub operation: u32,
    pub reserved: u32,
    pub config_dir: SayakaPathV1,
    pub root: SayakaPathV1,
    pub entry: SayakaPathV1,
}

/// Reads or changes an exclusion under an explicitly authorized root. The
/// caller must hold macOS security-scoped access for root and entry.
///
/// # Safety
/// Request and contained path bytes must be readable. `required` is writable
/// and disjoint from request and output; nonzero capacity needs a writable buffer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_exclusions_v1(
    request: *const SayakaExclusionsRequestV1,
    buffer: *mut u8,
    capacity: usize,
    required: *mut usize,
) -> i32 {
    boundary(|| {
        // SAFETY: Caller promises valid, non-overlapping output storage.
        unsafe { prepare_output(buffer, capacity, required, MAX_QUERY_BYTES)? };
        pointer(request)?;
        // SAFETY: Caller promises a readable, aligned request.
        let request = unsafe { &*request };
        if request.abi_version != ABI_VERSION
            || request.struct_size as usize != size_of::<SayakaExclusionsRequestV1>()
        {
            return Err(UNSUPPORTED_VERSION);
        }
        if request.reserved != 0
            || ![EXCLUSIONS_LIST, EXCLUSIONS_ADD, EXCLUSIONS_REMOVE].contains(&request.operation)
        {
            return Err(INVALID_ARGUMENT);
        }
        // Mutations are one-shot: an undersized output buffer must never
        // report failure after committing a policy change. Listing retains
        // the usual size-probe convention.
        if request.operation != EXCLUSIONS_LIST && capacity != MAX_QUERY_BYTES {
            return Err(INVALID_ARGUMENT);
        }
        #[cfg(not(target_os = "macos"))]
        return Err(UNSUPPORTED_PLATFORM);
        #[cfg(target_os = "macos")]
        {
            // SAFETY: Caller promises each selected path remains readable for this call.
            let config_dir = unsafe { decode_path(request.config_dir)? };
            let root = unsafe { decode_path(request.root)? };
            let config = clean_policy::resolve_config_path(Some(&config_dir))
                .map_err(|_| INVALID_ARGUMENT)?;
            match request.operation {
                EXCLUSIONS_LIST => {}
                EXCLUSIONS_ADD | EXCLUSIONS_REMOVE => {
                    // SAFETY: The entry is supplied for mutation operations.
                    let entry = unsafe { decode_path(request.entry)? };
                    if request.operation == EXCLUSIONS_ADD {
                        clean_policy::add_entries(&config, &root, &[entry])
                            .map_err(policy_error)?;
                    } else {
                        clean_policy::remove_entries(&config, &root, &[entry])
                            .map_err(policy_error)?;
                    }
                }
                _ => unreachable!(),
            };
            let (_, entries) =
                clean_policy::list_root_entries(&config, &root).map_err(policy_error)?;
            let bytes = bounded_json(
                &json!({
                    "schema_version": 1,
                    "kind": "exclusions",
                    "operation": request.operation,
                    "root": wire::NativePath(&root),
                    "entries": entries.iter().map(|entry| json!({
                        "relative_path": wire::NativePath(&entry.relative_path),
                        "missing_attention": entry.missing_attention,
                    })).collect::<Vec<_>>(),
                }),
                MAX_QUERY_BYTES,
            )?;
            // SAFETY: Output was validated above; bytes are privately owned.
            unsafe { copy_output(&bytes, buffer, capacity, required) }
        }
    })
}

#[cfg(target_os = "macos")]
fn policy_error(error: std::io::Error) -> i32 {
    match error.kind() {
        std::io::ErrorKind::InvalidInput | std::io::ErrorKind::InvalidData => INVALID_ARGUMENT,
        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::NotFound => INVALID_CANDIDATE,
        _ => INTERNAL_ERROR,
    }
}
