// SPDX-License-Identifier: MPL-2.0
//! Versioned retained orphan sessions. No JSON document can instantiate authority.
use super::*;
use sayaka_engine::model::Cancellation;
#[cfg(target_os = "macos")]
use sayaka_engine::orphan_execution::OrphanSession as CoreSession;
use std::thread::JoinHandle;
#[cfg(not(target_os = "macos"))]
struct CoreSession;
#[repr(C)]
pub struct SayakaOrphanPreviewRequestV2 {
    pub abi_version: u32,
    pub struct_size: u32,
    pub extra_app_roots: *const SayakaPathV1,
    pub extra_app_root_count: usize,
    pub policy_dir: SayakaPathV1,
    pub reserved: u32,
}
#[repr(C)]
pub struct SayakaOrphanExecuteRequestV1 {
    pub abi_version: u32,
    pub struct_size: u32,
    pub handle: u64,
    pub plan_digest: *const u8,
    pub plan_digest_length: usize,
    pub selected_ids_json: *const u8,
    pub selected_ids_json_length: usize,
    pub approval_token: *const u8,
    pub approval_token_length: usize,
    pub state_dir: SayakaPathV1,
    pub reserved: u32,
}
#[repr(C)]
#[derive(Default)]
pub struct SayakaOrphanSnapshotV1 {
    pub abi_version: u32,
    pub struct_size: u32,
    pub phase: u32,
    pub state: u32,
    pub cancellation_requested: u32,
    pub reserved: u32,
}
enum Completed {
    Preview(CoreSession),
    Execution(Vec<u8>),
}
pub(super) struct OrphanJob {
    cancel: Cancellation,
    worker: Option<JoinHandle<Result<Completed, String>>>,
    session: Option<CoreSession>,
    bytes: Option<Vec<u8>>,
    phase: u32,
    failed: bool,
    closed: bool,
}
fn error_bytes(message: &str) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct ErrorWire {
        kind: &'static str,
        schema_version: u32,
        message: String,
    }
    bounded_json(&ErrorWire { kind: "sayaka.orphan_error", schema_version: 1, message: message.chars().take(4096).collect() }, MAX_RESULT_BYTES)
        .unwrap_or_else(|_| br#"{"kind":"sayaka.orphan_error","schema_version":1,"message":"result serialization failed"}"#.to_vec())
}
#[derive(serde::Serialize)]
struct ExecutionWire {
    kind: &'static str,
    schema_version: u32,
    record: sayaka_engine::journal::Record,
    journal_error: Option<String>,
}

impl OrphanJob {
    fn open(&self) -> Result<(), i32> {
        if self.closed {
            Err(INVALID_HANDLE)
        } else {
            Ok(())
        }
    }
    fn collect(&mut self) {
        if self.worker.as_ref().is_none_or(|w| !w.is_finished()) {
            return;
        }
        let result = self.worker.take().unwrap().join().unwrap_or_else(|_| {
            Err("orphan worker panicked; inspect history before retrying".into())
        });
        match result {
            Ok(Completed::Preview(session)) => {
                #[cfg(target_os = "macos")]
                {
                    match bounded_json(session.preview(), MAX_RESULT_BYTES) {
                        Ok(bytes) if bytes.len() <= MAX_RESULT_BYTES => {
                            self.bytes = Some(bytes);
                            self.session = Some(session);
                        }
                        _ => {
                            self.failed = true;
                            self.bytes = Some(error_bytes("preview serialization failed"));
                        }
                    }
                }
                #[cfg(not(target_os = "macos"))]
                {
                    let _ = session;
                    self.failed = true;
                    self.bytes = Some(error_bytes("unsupported platform"));
                }
            }
            Ok(Completed::Execution(bytes)) if bytes.len() <= MAX_RESULT_BYTES => {
                self.bytes = Some(bytes)
            }
            Ok(Completed::Execution(_)) => {
                self.failed = true;
                self.bytes = Some(error_bytes("result limit exceeded; inspect history"));
            }
            Err(e) => {
                self.failed = true;
                self.bytes = Some(error_bytes(&e));
            }
        }
    }
}
fn get_orphan(handle: u64) -> Result<Arc<Mutex<OrphanJob>>, i32> {
    registry()
        .lock()
        .map_err(|_| INTERNAL_ERROR)?
        .orphans
        .get(&handle)
        .cloned()
        .ok_or(INVALID_HANDLE)
}
unsafe fn text_input(ptr: *const u8, len: usize, max: usize) -> Result<String, i32> {
    if len == 0 || len > max {
        return Err(INVALID_ARGUMENT);
    }
    pointer(ptr)?;
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| INVALID_ARGUMENT)
}
/// Starts native-home preview on an owned worker. All request data is copied.
/// # Safety
/// Request/path arrays are readable and aligned; out_handle is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_orphan_preview_v2(
    request: *const SayakaOrphanPreviewRequestV2,
    out_handle: *mut u64,
) -> i32 {
    boundary(|| {
        pointer(out_handle)?;
        unsafe { out_handle.write(0) };
        pointer(request)?;
        let r = unsafe { &*request };
        if r.abi_version != ABI_VERSION
            || r.struct_size as usize != size_of::<SayakaOrphanPreviewRequestV2>()
            || r.reserved != 0
        {
            return Err(UNSUPPORTED_VERSION);
        }
        if !cfg!(target_os = "macos") {
            return Err(UNSUPPORTED_PLATFORM);
        }
        if r.extra_app_root_count > 8 {
            return Err(INVALID_ARGUMENT);
        }
        let policy = unsafe { decode_path(r.policy_dir)? };
        let mut roots = Vec::new();
        if r.extra_app_root_count != 0 {
            pointer(r.extra_app_roots)?;
            for p in
                unsafe { std::slice::from_raw_parts(r.extra_app_roots, r.extra_app_root_count) }
            {
                roots.push(unsafe { decode_path(*p)? });
            }
        }
        let cancel = Cancellation::default();
        let worker_cancel = cancel.clone();
        let mut registry = registry().lock().map_err(|_| INTERNAL_ERROR)?;
        let handle = registry.allocate_handle()?;
        let worker = std::thread::Builder::new()
            .name("sayaka-orphan-preview".into())
            .spawn(move || {
                #[cfg(target_os = "macos")]
                {
                    CoreSession::prepare(&roots, &policy, worker_cancel)
                        .map(Completed::Preview)
                        .map_err(|e| e.to_string())
                }
                #[cfg(not(target_os = "macos"))]
                {
                    let _ = (roots, policy, worker_cancel);
                    Err("unsupported platform".into())
                }
            })
            .map_err(|_| INTERNAL_ERROR)?;
        registry.orphans.insert(
            handle,
            Arc::new(Mutex::new(OrphanJob {
                cancel,
                worker: Some(worker),
                session: None,
                bytes: None,
                phase: 1,
                failed: false,
                closed: false,
            })),
        );
        unsafe { out_handle.write(handle) };
        Ok(())
    })
}
/// Consumes this handle's preview once; completion is available through poll/result.
/// # Safety
/// Request, path and bounded UTF-8 input buffers are readable for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_orphan_execute_v1(
    request: *const SayakaOrphanExecuteRequestV1,
) -> i32 {
    boundary(|| {
        pointer(request)?;
        let r = unsafe { &*request };
        if r.abi_version != ABI_VERSION
            || r.struct_size as usize != size_of::<SayakaOrphanExecuteRequestV1>()
            || r.reserved != 0
        {
            return Err(UNSUPPORTED_VERSION);
        }
        let digest = unsafe { text_input(r.plan_digest, r.plan_digest_length, 64)? };
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(INVALID_ARGUMENT);
        }
        let selection =
            unsafe { text_input(r.selected_ids_json, r.selected_ids_json_length, 8192)? };
        let ids: Vec<String> = serde_json::from_str(&selection).map_err(|_| INVALID_ARGUMENT)?;
        let mut seen = std::collections::HashSet::new();
        if ids.is_empty()
            || ids.len() > 32
            || ids.iter().any(|id| {
                id.len() != 64
                    || !id
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    || !seen.insert(id)
            })
        {
            return Err(INVALID_ARGUMENT);
        }
        let token = unsafe { text_input(r.approval_token, r.approval_token_length, 128)? };
        if token != format!("trash {} leftovers", ids.len()) {
            return Err(INVALID_ARGUMENT);
        }
        let state = unsafe { decode_path(r.state_dir)? };
        let slot = get_orphan(r.handle)?;
        let mut job = lock_job(&slot)?;
        job.open()?;
        job.collect();
        if job.worker.is_some() {
            return Err(NOT_READY);
        }
        if job.phase != 1 || job.cancel.is_cancelled() {
            return Err(INVALID_HANDLE);
        }
        let session = job.session.take().ok_or(INVALID_CANDIDATE)?;
        job.phase = 2;
        job.bytes = None;
        job.failed = false;
        match std::thread::Builder::new()
            .name("sayaka-orphan-execute".into())
            .spawn(move || {
                #[cfg(target_os = "macos")]
                {
                    let operation = session
                        .begin(&ids, &digest, &token, &state)
                        .map_err(|e| e.to_string())?;
                    let report = operation.execute();
                    bounded_json(
                        &ExecutionWire {
                            kind: "sayaka.orphan_execution",
                            schema_version: 1,
                            record: report.record,
                            journal_error: report.journal_error,
                        },
                        MAX_RESULT_BYTES,
                    )
                    .map(Completed::Execution)
                    .map_err(|code| {
                        format!("execution result serialization failed ({code}); inspect history")
                    })
                }
                #[cfg(not(target_os = "macos"))]
                {
                    let _ = (session, ids, digest, token, state);
                    Err("unsupported platform".into())
                }
            }) {
            Ok(worker) => job.worker = Some(worker),
            Err(_) => {
                job.failed = true;
                job.bytes = Some(error_bytes("cannot start execution worker"));
                return Err(INTERNAL_ERROR);
            }
        }
        Ok(())
    })
}
/// # Safety
/// out_snapshot is aligned writable storage of the declared size.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_orphan_poll_v1(
    handle: u64,
    out_snapshot: *mut SayakaOrphanSnapshotV1,
) -> i32 {
    boundary(|| {
        pointer(out_snapshot)?;
        unsafe { out_snapshot.write(SayakaOrphanSnapshotV1::default()) };
        let slot = get_orphan(handle)?;
        let mut job = lock_job(&slot)?;
        job.open()?;
        job.collect();
        unsafe {
            out_snapshot.write(SayakaOrphanSnapshotV1 {
                abi_version: ABI_VERSION,
                struct_size: size_of::<SayakaOrphanSnapshotV1>() as u32,
                phase: job.phase,
                state: if job.worker.is_some() {
                    1
                } else if job.failed {
                    5
                } else {
                    2
                },
                cancellation_requested: u32::from(job.cancel.is_cancelled()),
                reserved: 0,
            })
        };
        Ok(())
    })
}
/// # Safety
/// Output buffers follow the common probe/copy ABI convention.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_orphan_result_v1(
    handle: u64,
    buffer: *mut u8,
    capacity: usize,
    required: *mut usize,
) -> i32 {
    boundary(|| {
        unsafe { prepare_output(buffer, capacity, required, MAX_RESULT_BYTES)? };
        let slot = get_orphan(handle)?;
        let mut job = lock_job(&slot)?;
        job.open()?;
        job.collect();
        let bytes = job.bytes.as_ref().ok_or(NOT_READY)?;
        unsafe { copy_output(bytes, buffer, capacity, required) }
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn sayaka_orphan_cancel_v1(handle: u64) -> i32 {
    boundary(|| {
        let slot = get_orphan(handle)?;
        let job = lock_job(&slot)?;
        job.open()?;
        job.cancel.cancel();
        Ok(())
    })
}
/// Returns BUSY after requesting cancellation until the owned worker has stopped.
#[unsafe(no_mangle)]
pub extern "C" fn sayaka_orphan_release_v1(handle: u64) -> i32 {
    boundary(|| {
        let slot = get_orphan(handle)?;
        let mut job = match slot.try_lock() {
            Ok(job) => job,
            Err(TryLockError::WouldBlock) => return Err(BUSY),
            Err(TryLockError::Poisoned(p)) => p.into_inner(),
        };
        job.open()?;
        job.cancel.cancel();
        job.collect();
        if job.worker.is_some() {
            return Err(BUSY);
        }
        job.closed = true;
        job.session = None;
        job.bytes = None;
        registry()
            .lock()
            .map_err(|_| INTERNAL_ERROR)?
            .orphans
            .remove(&handle);
        Ok(())
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lifecycle_rejects_unknown_handle() {
        assert_eq!(sayaka_orphan_cancel_v1(u64::MAX), INVALID_HANDLE);
        assert_eq!(sayaka_orphan_release_v1(u64::MAX), INVALID_HANDLE);
    }
    #[test]
    fn preview_rejects_version_without_starting_worker() {
        let r = SayakaOrphanPreviewRequestV2 {
            abi_version: 99,
            struct_size: size_of::<SayakaOrphanPreviewRequestV2>() as u32,
            extra_app_roots: std::ptr::null(),
            extra_app_root_count: 0,
            policy_dir: SayakaPathV1 {
                encoding: UNIX_BYTES,
                bytes: std::ptr::null(),
                byte_length: 0,
            },
            reserved: 0,
        };
        let mut handle = 9;
        assert_eq!(
            unsafe { sayaka_orphan_preview_v2(&r, &mut handle) },
            UNSUPPORTED_VERSION
        );
        assert_eq!(handle, 0);
    }
}
