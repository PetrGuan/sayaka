// SPDX-License-Identifier: MPL-2.0

//! Additive, retained related-data capability. No v1 call implicitly opts in.
use super::*;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SayakaUninstallRelatedRequestV2 {
    pub abi_version: u32,
    pub struct_size: u32,
    pub handle: u64,
    pub app_roots: *const SayakaPathV1,
    pub app_root_count: usize,
    pub policy_dir: SayakaPathV1,
    pub reserved: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SayakaUninstallItemIdV2 {
    pub bytes: *const u8,
    pub byte_length: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SayakaUninstallExecuteRequestV2 {
    pub abi_version: u32,
    pub struct_size: u32,
    pub handle: u64,
    pub plan_digest: *const u8,
    pub plan_digest_length: usize,
    pub item_ids: *const SayakaUninstallItemIdV2,
    pub item_count: usize,
    pub approval_token: *const u8,
    pub approval_token_length: usize,
    pub state_dir: SayakaPathV1,
    pub reserved: u64,
}

pub(super) fn ensure_idle(job: &UninstallJob) -> Result<(), i32> {
    if job.closed || job.result_bytes.is_some() {
        return Err(INVALID_HANDLE);
    }
    #[cfg(target_os = "macos")]
    if job.related_admin.is_some()
        || matches!(
            job.admin,
            AdminState::AwaitingDelegate(_) | AdminState::Consumed
        )
    {
        return Err(INVALID_HANDLE);
    }
    Ok(())
}

unsafe fn text_input(bytes: *const u8, len: usize, max: usize) -> Result<String, i32> {
    if len == 0 || len > max {
        return Err(INVALID_ARGUMENT);
    }
    pointer(bytes)?;
    let bytes = unsafe { std::slice::from_raw_parts(bytes, len) };
    Ok(std::str::from_utf8(bytes)
        .map_err(|_| INVALID_ARGUMENT)?
        .to_owned())
}

/// Replaces the retained related capability; native home is derived by the core.
/// # Safety
/// Request and nested inputs must be readable and disjoint from output. The
/// output buffer must have exactly 4 MiB writable bytes. No size-probe call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_uninstall_related_preview_v2(
    request: *const SayakaUninstallRelatedRequestV2,
    buffer: *mut u8,
    capacity: usize,
    required: *mut usize,
) -> i32 {
    boundary(|| {
        unsafe {
            prepare_output(buffer, capacity, required, RELATED_RESULT_BYTES)?;
        }
        if capacity != RELATED_RESULT_BYTES {
            return Err(INVALID_ARGUMENT);
        }
        pointer(request)?;
        let request = unsafe { *request };
        if request.abi_version != ABI_VERSION
            || request.struct_size as usize != size_of::<SayakaUninstallRelatedRequestV2>()
            || request.reserved != 0
        {
            return Err(UNSUPPORTED_VERSION);
        }
        if request.app_root_count > 8 {
            return Err(INVALID_ARGUMENT);
        }
        let mut roots = Vec::new();
        if request.app_root_count != 0 {
            pointer(request.app_roots)?;
            for root in
                unsafe { std::slice::from_raw_parts(request.app_roots, request.app_root_count) }
            {
                let path = unsafe { decode_path(*root)? };
                if !normal_absolute(&path) {
                    return Err(INVALID_ARGUMENT);
                }
                roots.push(path);
            }
        }
        let policy = unsafe { decode_path(request.policy_dir)? };
        if !normal_absolute(&policy) {
            return Err(INVALID_ARGUMENT);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (roots, policy);
            Err(UNSUPPORTED_PLATFORM)
        }
        #[cfg(target_os = "macos")]
        {
            let slot = get_job(request.handle)?;
            let mut job = lock_job(&slot)?;
            ensure_idle(&job)?;
            // A fresh observation never leaves the preceding capability reusable.
            job.related = None;
            let result = sayaka_engine::related_uninstall::RelatedUninstallSession::prepare(
                &job.preview,
                &roots,
                &policy,
                slot.cancellation.clone(),
            );
            let bytes = match result {
                Ok(session) => {
                    let bytes = bounded_json(session.preview(), RELATED_RESULT_BYTES)?;
                    job.related = Some(session);
                    bytes
                }
                Err(error) => bounded_json(
                    &json!({
                        "schema_version": 2, "kind": "sayaka.app_uninstall_related_refusal",
                        "complete": false, "effects_performed": false, "error": error.to_string(),
                    }),
                    RELATED_RESULT_BYTES,
                )?,
            };
            unsafe { copy_output(&bytes, buffer, capacity, required) }
        }
    })
}

#[cfg(target_os = "macos")]
pub(super) fn execution_bytes(result: sayaka_engine::related_uninstall::RelatedResult) -> Vec<u8> {
    let reports = [&result.bundle, &result.related];
    let state = if reports.iter().any(|r| {
        r.journal_error.is_some()
            || r.record.items.iter().any(|i| {
                matches!(
                    i.state,
                    ItemState::Unknown | ItemState::Started | ItemState::Planned
                )
            })
    }) {
        "unknown"
    } else if reports.iter().all(|r| {
        r.record
            .items
            .iter()
            .all(|i| i.state == ItemState::Succeeded)
    }) {
        "completed"
    } else if reports.iter().any(|r| {
        r.record
            .items
            .iter()
            .any(|i| i.state == ItemState::Succeeded)
    }) {
        "partial"
    } else if reports
        .iter()
        .any(|r| r.record.items.iter().any(|i| i.state == ItemState::Failed))
    {
        "failed"
    } else {
        "skipped"
    };
    bounded_json(&json!({
        "schema_version": 2, "kind": "sayaka.app_uninstall_execution", "state": state,
        "report": result.bundle, "related_report": result.related,
        "recovery": "Inspect each item and both linked journal records. Use Finder Put Back only for verified items moved to Trash. Never retry an unknown result automatically.",
    }), MAX_RESULT_BYTES).unwrap_or_else(|_| br#"{"schema_version":2,"kind":"sayaka.app_uninstall_execution","state":"unknown","error":"output budget exceeded; inspect the linked journals and Trash"}"#.to_vec())
}

unsafe fn execute(request: *const SayakaUninstallExecuteRequestV2, admin: bool) -> Result<(), i32> {
    pointer(request)?;
    let r = unsafe { *request };
    if r.abi_version != ABI_VERSION
        || r.struct_size as usize != size_of::<SayakaUninstallExecuteRequestV2>()
        || r.reserved != 0
    {
        return Err(UNSUPPORTED_VERSION);
    }
    // Empty selection uses the explicit v1 bundle-only API and its old token.
    if r.item_count == 0 || r.item_count > 32 {
        return Err(INVALID_ARGUMENT);
    }
    let digest = unsafe { text_input(r.plan_digest, r.plan_digest_length, 64)? };
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(INVALID_ARGUMENT);
    }
    let token = unsafe { text_input(r.approval_token, r.approval_token_length, 4096)? };
    pointer(r.item_ids)?;
    let mut ids = Vec::new();
    for id in unsafe { std::slice::from_raw_parts(r.item_ids, r.item_count) } {
        let id = unsafe { text_input(id.bytes, id.byte_length, 256)? };
        if ids.contains(&id) {
            return Err(INVALID_ARGUMENT);
        }
        ids.push(id);
    }
    let state = unsafe { decode_path(r.state_dir)? };
    if !normal_absolute(&state) {
        return Err(INVALID_ARGUMENT);
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (admin, digest, token, ids, state);
        Err(UNSUPPORTED_PLATFORM)
    }
    #[cfg(target_os = "macos")]
    {
        let slot = get_job(r.handle)?;
        let mut job = lock_job(&slot)?;
        ensure_idle(&job)?;
        let session = job.related.as_ref().ok_or(INVALID_HANDLE)?;
        if session.admin_required() != admin {
            return Err(INVALID_CANDIDATE);
        }
        // A validly formed attempt consumes all execution capabilities even on
        // refusal; refreshed authorization requires a new uninstall handle.
        let session = job.related.take().ok_or(INVALID_HANDLE)?;
        job.session = None;
        job.admin = AdminState::Consumed;
        let mut operation = match session.begin(&ids, &digest, &token, &state) {
            Ok(operation) => operation,
            Err(error) => {
                job.result_bytes = Some(bounded_json(
                    &json!({
                        "schema_version": 2, "kind": "sayaka.app_uninstall_execution", "state": "refused",
                        "effects_performed": false, "error": error.to_string(),
                        "recovery": "No native Trash call occurred. Obtain a new preview before retrying.",
                    }),
                    MAX_RESULT_BYTES,
                )?);
                return Err(INVALID_CANDIDATE);
            }
        };
        if admin {
            if let Err(error) = operation.admin_begin() {
                // Finder has not been dispatched. Finalize both durable records.
                let mut value = serde_json::from_slice::<serde_json::Value>(&execution_bytes(
                    operation.admin_finish(sayaka_engine::admin_uninstall::DelegateStatus::Error),
                ))
                .map_err(|_| INTERNAL_ERROR)?;
                value["error"] = json!(error.to_string());
                job.result_bytes = Some(bounded_json(&value, MAX_RESULT_BYTES)?);
                return Err(INVALID_CANDIDATE);
            }
            job.related_admin = Some(operation);
        } else {
            job.result_bytes = Some(execution_bytes(operation.execute()));
        }
        Ok(())
    }
}

/// Executes a nonempty subset of the exact retained preview, bundle first.
/// # Safety
/// Request and nested bounded inputs must be readable for the duration of call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_uninstall_execute_v2(
    request: *const SayakaUninstallExecuteRequestV2,
) -> i32 {
    boundary(|| unsafe { execute(request, false) })
}

/// Only on OK may the host invoke Finder for the retained bundle, then finish
/// through admin_finish_v1. Finder's reported status is never execution proof.
/// # Safety
/// Request and nested bounded inputs must be readable for the duration of call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_uninstall_admin_begin_v2(
    request: *const SayakaUninstallExecuteRequestV2,
) -> i32 {
    boundary(|| unsafe { execute(request, true) })
}

/// Sticky cancellation for v2 observation/execution. Callable while the worker
/// owns the job mutex. Does not release the handle or cancel Finder's dialog.
#[unsafe(no_mangle)]
pub extern "C" fn sayaka_uninstall_cancel_v2(handle: u64) -> i32 {
    boundary(|| {
        get_job(handle)?.cancellation.cancel();
        Ok(())
    })
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    fn fixture(admin: AdminState) -> u64 {
        let preview = app_uninstall::preview_bundle_uninstall(std::path::Path::new(
            "/nonexistent-sayaka-abi-fixture/Absent.app",
        ));
        let slot = Arc::new(UninstallSlot {
            job: Mutex::new(UninstallJob {
                preview,
                session: None,
                preview_bytes: b"{}".to_vec(),
                result_bytes: None,
                closed: false,
                admin,
                related: None,
                related_admin: None,
            }),
            cancellation: Cancellation::default(),
        });
        let mut registry = registry().lock().unwrap();
        let handle = registry.allocate_handle().unwrap();
        registry.uninstalls.insert(handle, slot);
        handle
    }

    #[test]
    fn cancellation_does_not_wait_for_worker_and_release_still_joins() {
        let handle = fixture(AdminState::Unavailable);
        let slot = get_job(handle).unwrap();
        let guard = slot.job.lock().unwrap();
        assert_eq!(sayaka_uninstall_cancel_v2(handle), OK);
        assert!(slot.cancellation.is_cancelled());
        assert_eq!(sayaka_uninstall_release_v1(handle), BUSY);
        drop(guard);
        assert_eq!(sayaka_uninstall_release_v1(handle), OK);
        assert_eq!(sayaka_uninstall_cancel_v2(handle), INVALID_HANDLE);
    }

    #[test]
    fn consumed_cross_version_handle_cannot_reenter_bundle_execution() {
        let handle = fixture(AdminState::Consumed);
        let token = b"uninstall Absent.app";
        let path = b"/nonexistent-sayaka-abi-fixture/state";
        let state = SayakaPathV1 {
            encoding: UNIX_BYTES,
            bytes: path.as_ptr(),
            byte_length: path.len(),
        };
        unsafe {
            assert_eq!(
                sayaka_uninstall_execute_v1(handle, token.as_ptr(), token.len(), state),
                INVALID_HANDLE
            );
            assert_eq!(
                sayaka_uninstall_admin_begin_v1(handle, token.as_ptr(), token.len(), state),
                INVALID_HANDLE
            );
        }
        assert_eq!(sayaka_uninstall_release_v1(handle), OK);
    }

    #[test]
    fn v2_selection_bounds_are_checked_before_reading_input_arrays() {
        let mut r = SayakaUninstallExecuteRequestV2 {
            abi_version: ABI_VERSION,
            struct_size: size_of::<SayakaUninstallExecuteRequestV2>() as u32,
            handle: 0,
            plan_digest: std::ptr::null(),
            plan_digest_length: 64,
            item_ids: std::ptr::null(),
            item_count: 33,
            approval_token: std::ptr::null(),
            approval_token_length: 0,
            state_dir: SayakaPathV1 {
                encoding: UNIX_BYTES,
                bytes: std::ptr::null(),
                byte_length: 0,
            },
            reserved: 0,
        };
        unsafe {
            assert_eq!(sayaka_uninstall_execute_v2(&r), INVALID_ARGUMENT);
            r.item_count = 0;
            assert_eq!(sayaka_uninstall_admin_begin_v2(&r), INVALID_ARGUMENT);
            r.struct_size -= 1;
            assert_eq!(sayaka_uninstall_execute_v2(&r), UNSUPPORTED_VERSION);
        }
    }
}
