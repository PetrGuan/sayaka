// SPDX-License-Identifier: MPL-2.0
//! Permanent simulator erase/delete (`permanent_tool_operation_v1`). See
//! docs/SIMULATOR_CLEANUP.md. One operation kind per handle; the handle
//! retains the sealed preview until a single execution or release.
use super::*;
#[cfg(target_os = "macos")]
use sayaka_engine::devtools::session::{ExecuteRequest, MacHost, SessionError, SimulatorSession};
use sayaka_engine::devtools::{EFFECT_CLASS, MAX_REQUEST_DEVICES, Operation, PREVIEW_TTL};
use sayaka_engine::journal::{self, ItemState, NativePath};
use sayaka_engine::model::Cancellation;
use serde_json::json;
use std::thread::JoinHandle;

pub const SIMULATOR_ERASE: u32 = 1;
pub const SIMULATOR_DELETE: u32 = 2;

#[repr(C)]
pub struct SayakaSimulatorPreviewRequestV1 {
    pub abi_version: u32,
    pub struct_size: u32,
    pub operation: u32,
    pub reserved: u32,
}

#[repr(C)]
pub struct SayakaSimulatorExecuteRequestV1 {
    pub abi_version: u32,
    pub struct_size: u32,
    pub plan_digest: *const u8,
    pub plan_digest_length: usize,
    pub item_ids: *const u64,
    pub item_count: usize,
    pub approval: u32,
    pub reserved: u32,
    pub approval_token: *const u8,
    pub approval_token_length: usize,
    pub has_state_dir: u32,
    pub reserved2: u32,
    pub state_dir: SayakaPathV1,
}

struct Preview {
    #[cfg(target_os = "macos")]
    session: SimulatorSession<MacHost>,
    /// `udids[id - 1]` is the device behind preview item `id`.
    udids: Vec<String>,
    bytes: Vec<u8>,
}

enum Outcome {
    Preview(Box<Preview>),
    /// Terminal JSON: a refused preview or a finished execution.
    Terminal(Vec<u8>),
}

struct State {
    worker: Option<JoinHandle<Result<Outcome, i32>>>,
    outcome: Option<Result<Outcome, i32>>,
    closed: bool,
}

pub(super) struct SimulatorJob {
    cancel: Cancellation,
    state: Mutex<State>,
}

fn get(handle: u64) -> Result<Arc<SimulatorJob>, i32> {
    registry()
        .lock()
        .map_err(|_| INTERNAL_ERROR)?
        .simulators
        .get(&handle)
        .cloned()
        .ok_or(INVALID_HANDLE)
}

fn collect(state: &mut State) -> Result<(), i32> {
    if state.closed {
        return Err(INVALID_HANDLE);
    }
    if state
        .worker
        .as_ref()
        .is_some_and(|worker| worker.is_finished())
    {
        state.outcome = Some(state.worker.take().unwrap().join().unwrap_or(Err(PANIC)));
    }
    if state.worker.is_some() {
        return Err(NOT_READY);
    }
    Ok(())
}

/// A sandboxed host cannot launch `xcrun` or reach CoreSimulator's data.
fn capability() -> Result<(), &'static str> {
    if !cfg!(target_os = "macos") {
        return Err("simulator cleanup is macOS only");
    }
    if std::env::var_os("APP_SANDBOX_CONTAINER_ID").is_some() {
        return Err("simulator cleanup needs a host outside the App Sandbox");
    }
    Ok(())
}

fn refused(
    kind: &str,
    handle: u64,
    code: &str,
    message: String,
    detail: serde_json::Value,
) -> Result<Outcome, i32> {
    bounded_json(
        &json!({
            "schema_version": 1, "kind": kind, "handle": handle.to_string(),
            "state": "refused", "effects_performed": false, "execution_eligible": false,
            "error": { "code": code, "message": message, "detail": detail }
        }),
        MAX_RESULT_BYTES,
    )
    .map(Outcome::Terminal)
}

#[cfg(target_os = "macos")]
fn session_refused(kind: &str, handle: u64, error: SessionError) -> Result<Outcome, i32> {
    let detail = serde_json::to_value(&error).unwrap_or_default();
    refused(kind, handle, error.code(), error.to_string(), detail)
}

#[cfg(target_os = "macos")]
fn prepare(handle: u64, operation: Operation, cancel: Cancellation) -> Result<Outcome, i32> {
    const KIND: &str = "sayaka.simulator_preview";
    // The engine's TTL starts before listing; never advertise a later expiry.
    let expires = std::time::SystemTime::now() + PREVIEW_TTL;
    if let Err(reason) = capability() {
        return refused(
            KIND,
            handle,
            "capability_unavailable",
            reason.into(),
            json!(null),
        );
    }
    let host = match MacHost::new() {
        Ok(host) => host,
        Err(error) => return session_refused(KIND, handle, error),
    };
    let session = match SimulatorSession::prepare(host, operation, &cancel) {
        Ok(session) => session,
        Err(error) => return session_refused(KIND, handle, error),
    };
    let preview = session.preview();
    let ids: std::collections::HashMap<&str, usize> = preview
        .candidates
        .iter()
        .enumerate()
        .map(|(index, c)| (c.device.udid.as_str(), index + 1))
        .collect();
    let items: Vec<_> = preview
        .candidates
        .iter()
        .enumerate()
        .map(|(index, c)| {
            let device = &c.device;
            json!({
                "id": (index + 1).to_string(), "udid": device.udid, "name": device.name,
                "runtime_identifier": device.runtime_identifier,
                "device_type_identifier": device.device_type_identifier,
                "state": device.state, "is_available": device.is_available,
                "availability_error": device.availability_error,
                "data_path": NativePath::from_path(std::path::Path::new(&device.data_path)),
                "data_bytes": device.data_path_size, "log_bytes": device.log_path_size,
                "size_estimated": true, "size_unknown": device.data_path_size.is_none(),
                "last_used_at": device.last_used_at, "last_used_unknown": device.last_used_at.is_none(),
                "paired_with": c.paired_with,
                "paired_with_id": c.paired_with.as_deref().and_then(|udid| ids.get(udid)).map(ToString::to_string),
                "refusals": c.refusals, "execution_eligible": c.eligible(),
                "loses": match operation {
                    Operation::Erase => "all apps, data and settings on this simulator; the device itself stays",
                    Operation::Delete => "the simulator device with all of its apps, data and settings",
                },
            })
        })
        .collect();
    let eligible = preview.developer_activity.is_empty()
        && preview.candidates.iter().any(|c| c.eligible())
        && !cancel.is_cancelled();
    let bytes = bounded_json(
        &json!({
            "schema_version": 1, "kind": KIND, "handle": handle.to_string(), "state": "ready",
            "preview_schema_version": preview.schema_version,
            "operation": operation, "effect_class": EFFECT_CLASS, "permanent": true,
            "recovery": "none: nothing moves to Trash and nothing can be restored by Sayaka",
            "effects_performed": false, "execution_eligible": eligible,
            "plan_digest": preview.plan_digest,
            "approval_phrase_template": format!("{} N simulators", operation.verb()),
            "max_request_items": MAX_REQUEST_DEVICES,
            "expires_unix_ms": expires.duration_since(std::time::UNIX_EPOCH).map_err(|_| INTERNAL_ERROR)?.as_millis(),
            "tool": { "fingerprint": preview.tool.fingerprint, "versions": preview.versions },
            "developer_activity": preview.developer_activity,
            "items": items,
            "size_note": "CoreSimulator sizes cover the data directory only and can include clone-shared blocks; freed space is not guaranteed",
            "residual_race_disclosed": preview.residual_race_disclosed,
        }),
        MAX_RESULT_BYTES,
    )?;
    Ok(Outcome::Preview(Box::new(Preview {
        udids: preview
            .candidates
            .iter()
            .map(|c| c.device.udid.clone())
            .collect(),
        session,
        bytes,
    })))
}

#[cfg(target_os = "macos")]
fn execute(
    handle: u64,
    mut preview: Box<Preview>,
    request: ExecuteRequest,
    state_dir: PathBuf,
    cancel: Cancellation,
) -> Result<Outcome, i32> {
    const KIND: &str = "sayaka.simulator_execution";
    match preview.session.execute(&request, &cancel, &state_dir) {
        Ok(report) => {
            let unknown = report.journal_error.is_some()
                || report
                    .record
                    .items
                    .iter()
                    .any(|item| item.state == ItemState::Unknown);
            let effects = report.record.items.iter().any(|item| {
                matches!(
                    item.state,
                    ItemState::Succeeded | ItemState::Failed | ItemState::Unknown
                )
            });
            let value = json!({
                "schema_version": 1, "kind": KIND, "handle": handle.to_string(),
                "state": if unknown { "unknown" } else { "finished" },
                "effects_performed": effects, "exit_code": report.exit_code(), "report": report,
                "recovery": "Permanent: nothing was moved to Trash. Unknown items are reconciled by a fresh preview, never retried automatically.",
            });
            Ok(Outcome::Terminal(bounded_json(&value, MAX_RESULT_BYTES).unwrap_or_else(|_| {
                br#"{"schema_version":1,"kind":"sayaka.simulator_execution","state":"unknown","recovery":"Inspect the operation journal and make a fresh preview; the result could not be serialized"}"#.to_vec()
            })))
        }
        Err(error) => session_refused(KIND, handle, error),
    }
}

fn read_bytes(pointer_value: *const u8, length: usize, max: usize) -> Result<Vec<u8>, i32> {
    if length == 0 || length > max {
        return Err(INVALID_ARGUMENT);
    }
    pointer(pointer_value)?;
    // SAFETY: The caller supplies readable bytes for the bounded length.
    Ok(unsafe { std::slice::from_raw_parts(pointer_value, length) }.to_vec())
}

/// Reports whether this host may use simulator cleanup, without effects.
///
/// # Safety
/// Outputs follow sayaka_scan_result_v1's caller-owned buffer contract and cap.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_simulators_capability_v1(
    buffer: *mut u8,
    capacity: usize,
    required: *mut usize,
) -> i32 {
    boundary(|| {
        // SAFETY: Caller-owned output slots are validated before use.
        unsafe { prepare_output(buffer, capacity, required, MAX_RESULT_BYTES)? };
        let available = capability();
        let bytes = bounded_json(
            &json!({
                "schema_version": 1, "kind": "sayaka.simulator_capability",
                "available": available.is_ok(), "reason": available.err(),
                "operations": ["erase", "delete"], "effect_class": EFFECT_CLASS,
                "max_request_items": MAX_REQUEST_DEVICES,
                "preview_ttl_ms": PREVIEW_TTL.as_millis(),
            }),
            MAX_RESULT_BYTES,
        )?;
        // SAFETY: Output was validated above.
        unsafe { copy_output(&bytes, buffer, capacity, required) }
    })
}

/// Starts an asynchronous, effect-free preview of one operation kind.
///
/// # Safety
/// The request is readable and aligned; out_handle is writable and disjoint.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_simulators_preview_start_v1(
    request: *const SayakaSimulatorPreviewRequestV1,
    out_handle: *mut u64,
) -> i32 {
    boundary(|| {
        pointer(out_handle)?;
        // SAFETY: Caller supplies writable output.
        unsafe { out_handle.write(0) };
        pointer(request)?;
        // SAFETY: Caller supplies a readable request structure.
        let request = unsafe { &*request };
        if request.abi_version != ABI_VERSION
            || request.struct_size as usize != size_of::<SayakaSimulatorPreviewRequestV1>()
            || request.reserved != 0
        {
            return Err(UNSUPPORTED_VERSION);
        }
        let operation = match request.operation {
            SIMULATOR_ERASE => Operation::Erase,
            SIMULATOR_DELETE => Operation::Delete,
            _ => return Err(INVALID_ARGUMENT),
        };
        if !cfg!(target_os = "macos") {
            return Err(UNSUPPORTED_PLATFORM);
        }
        #[cfg(target_os = "macos")]
        {
            let mut registry = registry().lock().map_err(|_| INTERNAL_ERROR)?;
            let handle = registry.allocate_handle()?;
            let cancel = Cancellation::default();
            let worker_cancel = cancel.clone();
            let worker = std::thread::Builder::new()
                .name("sayaka-simulator-preview".into())
                .spawn(move || prepare(handle, operation, worker_cancel))
                .map_err(|_| INTERNAL_ERROR)?;
            registry.simulators.insert(
                handle,
                Arc::new(SimulatorJob {
                    cancel,
                    state: Mutex::new(State {
                        worker: Some(worker),
                        outcome: None,
                        closed: false,
                    }),
                }),
            );
            // SAFETY: Output remains valid through this call.
            unsafe { out_handle.write(handle) };
        }
        #[cfg(not(target_os = "macos"))]
        let _ = operation;
        Ok(())
    })
}

/// Copies preview or terminal JSON; NOT_READY while work is active.
///
/// # Safety
/// Caller-owned outputs follow the standard result buffer contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_simulators_result_v1(
    handle: u64,
    buffer: *mut u8,
    capacity: usize,
    required: *mut usize,
) -> i32 {
    boundary(|| {
        // SAFETY: Caller-owned output slots are validated before use.
        unsafe { prepare_output(buffer, capacity, required, MAX_RESULT_BYTES)? };
        let job = get(handle)?;
        let mut state = lock_job(&job.state)?;
        collect(&mut state)?;
        let bytes = match state.outcome.as_ref().ok_or(INTERNAL_ERROR)? {
            Ok(Outcome::Preview(preview)) => &preview.bytes,
            Ok(Outcome::Terminal(bytes)) => bytes,
            Err(code) => return Err(*code),
        };
        // SAFETY: Output was validated above; bytes are privately owned.
        unsafe { copy_output(bytes, buffer, capacity, required) }
    })
}

/// Starts the single permanent execution of a subset of this preview.
/// OK means execution started, not success; read every journal item.
///
/// # Safety
/// The request, digest, item ids, token and state_dir bytes are readable for
/// the call; no input pointer is retained.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_simulators_execute_v1(
    handle: u64,
    request: *const SayakaSimulatorExecuteRequestV1,
) -> i32 {
    boundary(|| {
        pointer(request)?;
        // SAFETY: Caller supplies a readable request structure.
        let request = unsafe { &*request };
        if request.abi_version != ABI_VERSION
            || request.struct_size as usize != size_of::<SayakaSimulatorExecuteRequestV1>()
            || request.reserved != 0
            || request.reserved2 != 0
        {
            return Err(UNSUPPORTED_VERSION);
        }
        if !cfg!(target_os = "macos") {
            return Err(UNSUPPORTED_PLATFORM);
        }
        if request.approval != 1
            || request.item_count == 0
            || request.item_count > MAX_REQUEST_DEVICES
        {
            return Err(INVALID_ARGUMENT);
        }
        let digest = String::from_utf8(read_bytes(
            request.plan_digest,
            request.plan_digest_length,
            64,
        )?)
        .map_err(|_| INVALID_ARGUMENT)?;
        let token = String::from_utf8(read_bytes(
            request.approval_token,
            request.approval_token_length,
            256,
        )?)
        .map_err(|_| INVALID_ARGUMENT)?;
        pointer(request.item_ids)?;
        // SAFETY: Caller supplies item_count readable, aligned identifiers.
        let ids =
            unsafe { std::slice::from_raw_parts(request.item_ids, request.item_count) }.to_vec();
        let state_dir = match request.has_state_dir {
            0 => journal::default_directory().map_err(|_| INVALID_ARGUMENT)?,
            // SAFETY: Caller supplies a readable path for this call.
            1 => unsafe { decode_path(request.state_dir)? },
            _ => return Err(INVALID_ARGUMENT),
        };
        journal::validate_state_directory_path(&state_dir).map_err(|_| INVALID_ARGUMENT)?;
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (handle, digest, token, ids, state_dir);
            Err(UNSUPPORTED_PLATFORM)
        }
        #[cfg(target_os = "macos")]
        {
            let job = get(handle)?;
            let mut state = lock_job(&job.state)?;
            collect(&mut state)?;
            let Some(Ok(Outcome::Preview(preview))) = state.outcome.as_ref() else {
                return Err(INVALID_CANDIDATE);
            };
            if job.cancel.is_cancelled() {
                return Err(INVALID_CANDIDATE);
            }
            let mut items = Vec::with_capacity(ids.len());
            for id in &ids {
                let index = usize::try_from(*id)
                    .ok()
                    .and_then(|id| id.checked_sub(1))
                    .filter(|index| *index < preview.udids.len())
                    .ok_or(INVALID_CANDIDATE)?;
                items.push(preview.udids[index].clone());
            }
            // The journal must not live inside any previewed device.
            preview
                .session
                .check_state_dir(&state_dir)
                .map_err(|_| INVALID_ARGUMENT)?;
            let execute_request = ExecuteRequest {
                plan_digest: digest,
                items,
                approval_token: token,
            };
            preview
                .session
                .check_approval(&execute_request)
                .map_err(|_| INVALID_CANDIDATE)?;
            let Some(Ok(Outcome::Preview(preview))) = state.outcome.take() else {
                return Err(INTERNAL_ERROR);
            };
            let cancel = job.cancel.clone();
            match std::thread::Builder::new()
                .name("sayaka-simulator-execute".into())
                .spawn(move || execute(handle, preview, execute_request, state_dir, cancel))
            {
                Ok(worker) => state.worker = Some(worker),
                Err(_) => {
                    state.outcome = Some(Err(INTERNAL_ERROR));
                    return Err(INTERNAL_ERROR);
                }
            }
            Ok(())
        }
    })
}

/// Monotonic. Before execution it makes the preview unusable; during
/// execution it skips batches that have not started. A running `simctl`
/// call is never interrupted by cancellation.
#[unsafe(no_mangle)]
pub extern "C" fn sayaka_simulators_cancel_v1(handle: u64) -> i32 {
    boundary(|| {
        get(handle)?.cancel.cancel();
        Ok(())
    })
}

/// Cancels and joins owned work; BUSY means keep the handle and retry.
#[unsafe(no_mangle)]
pub extern "C" fn sayaka_simulators_release_v1(handle: u64) -> i32 {
    boundary(|| {
        let job = get(handle)?;
        job.cancel.cancel();
        let mut state = match job.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => return Err(BUSY),
            Err(TryLockError::Poisoned(error)) => error.into_inner(),
        };
        match collect(&mut state) {
            Err(NOT_READY) => return Err(BUSY),
            other => other?,
        }
        state.closed = true;
        state.outcome = None;
        registry()
            .lock()
            .map_err(|_| INTERNAL_ERROR)?
            .simulators
            .remove(&handle)
            .ok_or(INVALID_HANDLE)?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn execute_request(approval: u32, count: usize) -> SayakaSimulatorExecuteRequestV1 {
        SayakaSimulatorExecuteRequestV1 {
            abi_version: ABI_VERSION,
            struct_size: size_of::<SayakaSimulatorExecuteRequestV1>() as u32,
            plan_digest: std::ptr::null(),
            plan_digest_length: 64,
            item_ids: std::ptr::null(),
            item_count: count,
            approval,
            reserved: 0,
            approval_token: std::ptr::null(),
            approval_token_length: 0,
            has_state_dir: 0,
            reserved2: 0,
            state_dir: SayakaPathV1 {
                encoding: UNIX_BYTES,
                bytes: std::ptr::null(),
                byte_length: 0,
            },
        }
    }

    #[test]
    fn unknown_operation_and_reserved_fields_are_rejected_without_a_handle() {
        for (operation, reserved, expected) in [
            (0, 0, INVALID_ARGUMENT),
            (3, 0, INVALID_ARGUMENT),
            (SIMULATOR_DELETE, 1, UNSUPPORTED_VERSION),
        ] {
            let request = SayakaSimulatorPreviewRequestV1 {
                abi_version: ABI_VERSION,
                struct_size: size_of::<SayakaSimulatorPreviewRequestV1>() as u32,
                operation,
                reserved,
            };
            let mut handle = 99;
            assert_eq!(
                unsafe { sayaka_simulators_preview_start_v1(&request, &mut handle) },
                expected
            );
            assert_eq!(handle, 0);
        }
    }

    #[test]
    fn execute_requires_explicit_approval_and_bounded_items_before_reading_pointers() {
        for request in [
            execute_request(0, 1),
            execute_request(2, 1),
            execute_request(1, 0),
            execute_request(1, MAX_REQUEST_DEVICES + 1),
        ] {
            let code = unsafe { sayaka_simulators_execute_v1(1, &request) };
            if cfg!(target_os = "macos") {
                assert_eq!(code, INVALID_ARGUMENT);
            } else {
                assert_eq!(code, UNSUPPORTED_PLATFORM);
            }
        }
    }

    #[test]
    fn unknown_handles_are_invalid() {
        assert_eq!(sayaka_simulators_cancel_v1(u64::MAX), INVALID_HANDLE);
        assert_eq!(sayaka_simulators_release_v1(u64::MAX), INVALID_HANDLE);
    }

    #[test]
    fn capability_reports_the_effect_class() {
        let mut required = 0;
        let mut buffer = vec![0u8; 4096];
        assert_eq!(
            unsafe {
                sayaka_simulators_capability_v1(buffer.as_mut_ptr(), buffer.len(), &mut required)
            },
            OK
        );
        let value: serde_json::Value = serde_json::from_slice(&buffer[..required]).unwrap();
        assert_eq!(value["effect_class"], "permanent_tool_operation_v1");
        assert_eq!(value["max_request_items"], 32);
    }
}
