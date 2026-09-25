// SPDX-License-Identifier: MPL-2.0

use super::*;
use sayaka_engine::installer_preview::task::{
    InstallerPhase, InstallerTask, InstallerTaskKind, InstallerTaskResult,
};
use sayaka_engine::installer_preview::{
    INSTALLER_PREVIEW_SCHEMA_VERSION, InstallerPreview, InstallerStatus, wire as installer_wire,
};
use sayaka_engine::scan::index::{Metric, Sort};
use serde_json::{Value, json};
use std::collections::HashSet;

pub const MAX_INSTALLER_SELECTIONS: usize = 32;

#[repr(C)]
pub struct SayakaInstallerRequestV1 {
    pub abi_version: u32,
    pub struct_size: u32,
    pub root: SayakaPathV1,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SayakaInstallerCandidateRefV1 {
    pub task_handle: u64,
    pub candidate_id: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SayakaInstallerSnapshotV1 {
    pub abi_version: u32,
    pub struct_size: u32,
    pub kind: u32,
    pub state: u32,
    pub cancellation_requested: u32,
    pub has_progress: u32,
    pub phase: u32,
    pub reserved: u32,
    pub progress_sequence: u64,
    pub observed_entries: u64,
    pub total_candidates: u64,
    pub inspected_candidates: u64,
    pub elapsed_ms: u64,
}

pub(super) struct InstallerJob {
    task: InstallerTask,
    source_handle: Option<u64>,
    result: Option<Result<Vec<u8>, i32>>,
    closed: bool,
}

impl InstallerJob {
    fn ensure_open(&self) -> Result<(), i32> {
        if self.closed {
            Err(INVALID_HANDLE)
        } else {
            Ok(())
        }
    }

    fn discovery(&mut self) -> Result<&Arc<InstallerPreview>, i32> {
        self.ensure_open()?;
        if self.task.kind() != InstallerTaskKind::Discovery {
            return Err(INVALID_HANDLE);
        }
        match self.task.result().ok_or(NOT_READY)? {
            Ok(InstallerTaskResult::Discovery(preview))
                if preview.status != InstallerStatus::Failed =>
            {
                Ok(preview)
            }
            _ => Err(QUERY_UNAVAILABLE),
        }
    }
}

fn get_installer(handle: u64) -> Result<Arc<Mutex<InstallerJob>>, i32> {
    registry()
        .lock()
        .map_err(|_| INTERNAL_ERROR)?
        .installers
        .get(&handle)
        .cloned()
        .ok_or(INVALID_HANDLE)
}

fn insert(registry: &mut Registry, handle: u64, task: InstallerTask, source_handle: Option<u64>) {
    registry.installers.insert(
        handle,
        Arc::new(Mutex::new(InstallerJob {
            task,
            source_handle,
            result: None,
            closed: false,
        })),
    );
}

fn start_error(error: sayaka_engine::scan::ScanError) -> i32 {
    match error.code {
        ScanCode::InvalidRoot | ScanCode::InvalidLimits => INVALID_ARGUMENT,
        ScanCode::UnsupportedPlatform => UNSUPPORTED_PLATFORM,
        _ => INTERNAL_ERROR,
    }
}

/// Starts bounded, read-only installer discovery on one explicit native root.
///
/// # Safety
/// request/root bytes must be readable and aligned; out_handle must be writable
/// and non-overlapping. Inputs are copied before return.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_installer_start_v1(
    request: *const SayakaInstallerRequestV1,
    out_handle: *mut u64,
) -> i32 {
    boundary(|| {
        pointer(out_handle)?;
        // SAFETY: Caller supplies an aligned writable output slot.
        unsafe { out_handle.write(0) };
        pointer(request)?;
        // SAFETY: Caller supplies a readable request structure.
        let request = unsafe { &*request };
        if request.abi_version != ABI_VERSION
            || request.struct_size as usize != size_of::<SayakaInstallerRequestV1>()
        {
            return Err(UNSUPPORTED_VERSION);
        }
        if !cfg!(target_os = "macos") {
            return Err(UNSUPPORTED_PLATFORM);
        }
        let root = unsafe { decode_path(request.root)? };
        let mut registry = registry().lock().map_err(|_| INTERNAL_ERROR)?;
        let handle = registry.allocate_handle()?;
        let task = InstallerTask::start(root).map_err(start_error)?;
        insert(&mut registry, handle, task, None);
        // SAFETY: Output remains valid for this call.
        unsafe { out_handle.write(handle) };
        Ok(())
    })
}

/// Returns coalesced installer task progress without joining active work.
///
/// # Safety
/// out_snapshot is aligned, writable v1 storage with no concurrent access.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_installer_poll_v1(
    handle: u64,
    out_snapshot: *mut SayakaInstallerSnapshotV1,
) -> i32 {
    boundary(|| {
        pointer(out_snapshot)?;
        // SAFETY: Caller supplies aligned writable snapshot storage.
        unsafe { out_snapshot.write(SayakaInstallerSnapshotV1::default()) };
        let slot = get_installer(handle)?;
        let mut job = lock_job(&slot)?;
        job.ensure_open()?;
        let snapshot = job.task.poll().map_err(|_| INTERNAL_ERROR)?;
        let mut out = SayakaInstallerSnapshotV1 {
            abi_version: ABI_VERSION,
            struct_size: size_of::<SayakaInstallerSnapshotV1>() as u32,
            kind: match snapshot.kind {
                InstallerTaskKind::Discovery => 1,
                InstallerTaskKind::Selection => 2,
            },
            state: match snapshot.state {
                ScanTaskState::Running => 1,
                ScanTaskState::Complete => 2,
                ScanTaskState::Partial => 3,
                ScanTaskState::Cancelled => 4,
                ScanTaskState::Failed => 5,
            },
            cancellation_requested: u32::from(snapshot.cancellation_requested),
            progress_sequence: snapshot.progress_sequence,
            ..Default::default()
        };
        if let Some(progress) = snapshot.progress {
            out.has_progress = 1;
            out.phase = match progress.phase {
                InstallerPhase::Scanning => 1,
                InstallerPhase::Inspecting => 2,
                InstallerPhase::CheckingSelection => 3,
            };
            out.observed_entries = progress.observed_entries;
            out.total_candidates = progress.total_candidates;
            out.inspected_candidates = progress.inspected_candidates;
            out.elapsed_ms = progress.elapsed_ms;
        }
        // SAFETY: Caller owns the writable output for this call.
        unsafe { out_snapshot.write(out) };
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn sayaka_installer_cancel_v1(handle: u64) -> i32 {
    boundary(|| {
        let slot = get_installer(handle)?;
        let job = lock_job(&slot)?;
        job.ensure_open()?;
        job.task.cancel();
        Ok(())
    })
}

fn candidate_json(preview: &InstallerPreview, handle: u64, index: usize) -> Value {
    let candidate = &preview.candidates[index];
    let mut value = installer_wire::candidate_json(candidate);
    value["reference"] = json!({ "task_handle": handle.to_string(), "candidate_id": (index as u64 + 1).to_string() });
    value["selection_check_eligible"] = json!(preview.selection_ready() && candidate.selectable());
    value
}

fn query_json(preview: &InstallerPreview, handle: u64, data: Value) -> Result<Vec<u8>, i32> {
    bounded_json(
        &json!({
            "schema_version": INSTALLER_PREVIEW_SCHEMA_VERSION, "kind": "installer_query",
            "task_handle": handle.to_string(), "scan_task_id": preview.scan_task_id,
            "status": preview.status.as_str(), "complete": preview.complete,
            "effects_performed": false, "execution_authority": false,
            "scan_issues": preview.scan_issues.len(), "issues": preview.issues.len(),
            "issues_omitted": preview.issues_omitted, "data": data,
        }),
        MAX_QUERY_BYTES,
    )
}

unsafe fn read_candidate(
    handle: u64,
    reference: *const SayakaInstallerCandidateRefV1,
) -> Result<usize, i32> {
    pointer(reference)?;
    // SAFETY: Caller supplies a readable aligned reference structure.
    let reference = unsafe { *reference };
    if reference.task_handle != handle {
        return Err(INVALID_CANDIDATE);
    }
    let id = reference
        .candidate_id
        .checked_sub(1)
        .ok_or(INVALID_CANDIDATE)?;
    usize::try_from(id).map_err(|_| INVALID_CANDIDATE)
}

/// Returns a deterministic page of installer observations, with no filesystem I/O.
///
/// # Safety
/// request is readable/aligned. Outputs follow scan query buffer rules
/// (MAX_QUERY_BYTES); all input/output memory is non-overlapping.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_installer_candidates_v1(
    handle: u64,
    request: *const SayakaPageRequestV1,
    buffer: *mut u8,
    capacity: usize,
    required: *mut usize,
) -> i32 {
    boundary(|| {
        // SAFETY: Caller supplies valid non-overlapping input/output storage.
        unsafe { prepare_output(buffer, capacity, required, MAX_QUERY_BYTES)? };
        pointer(request)?;
        let request = unsafe { *request };
        let (offset, sort, metric) = request.validate()?;
        let slot = get_installer(handle)?;
        let mut job = lock_job(&slot)?;
        let preview = job.discovery()?;
        let total = preview.candidates.len();
        if offset > total {
            return Err(INVALID_ARGUMENT);
        }
        let mut order: Vec<_> = (0..total).collect();
        order.sort_unstable_by(|&a, &b| {
            let a = &preview.candidates[a];
            let b = &preview.candidates[b];
            let names = || a.path.cmp(&b.path);
            match sort {
                Sort::Name => names(),
                Sort::Size => match metric {
                    Metric::Logical => b.logical_bytes.cmp(&a.logical_bytes),
                    Metric::Allocated => b.allocated_bytes.cmp(&a.allocated_bytes),
                }
                .then_with(names),
            }
        });
        let end = (offset + request.limit as usize).min(total);
        let candidates: Vec<_> = order[offset..end]
            .iter()
            .map(|&index| candidate_json(preview, handle, index))
            .collect();
        let bytes = query_json(
            preview,
            handle,
            json!({
                "offset": offset, "total": total, "next_offset": (end < total).then_some(end), "candidates": candidates,
            }),
        )?;
        // SAFETY: Output storage was validated above.
        unsafe { copy_output(&bytes, buffer, capacity, required) }
    })
}

/// Returns one task-bound installer observation, not a live validity check.
///
/// # Safety
/// reference is readable/aligned; output follows candidate-page buffer rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_installer_candidate_v1(
    handle: u64,
    reference: *const SayakaInstallerCandidateRefV1,
    buffer: *mut u8,
    capacity: usize,
    required: *mut usize,
) -> i32 {
    boundary(|| {
        // SAFETY: Caller supplies valid non-overlapping storage.
        unsafe { prepare_output(buffer, capacity, required, MAX_QUERY_BYTES)? };
        let index = unsafe { read_candidate(handle, reference)? };
        let slot = get_installer(handle)?;
        let mut job = lock_job(&slot)?;
        let preview = job.discovery()?;
        if index >= preview.candidates.len() {
            return Err(INVALID_CANDIDATE);
        }
        let bytes = query_json(preview, handle, candidate_json(preview, handle, index))?;
        // SAFETY: Output storage was validated above.
        unsafe { copy_output(&bytes, buffer, capacity, required) }
    })
}

/// Launches an independent read-only revalidation of 1..32 explicit candidates.
/// No executable session, plan or approval is retained by the returned task.
///
/// # Safety
/// candidates is readable/aligned for count references. out_handle is writable
/// and non-overlapping; all input references are copied before return.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_installer_selection_start_v1(
    discovery_handle: u64,
    candidates: *const SayakaInstallerCandidateRefV1,
    count: usize,
    out_handle: *mut u64,
) -> i32 {
    boundary(|| {
        pointer(out_handle)?;
        // SAFETY: Caller supplies a writable output slot.
        unsafe { out_handle.write(0) };
        if count == 0 || count > MAX_INSTALLER_SELECTIONS {
            return Err(INVALID_ARGUMENT);
        }
        pointer(candidates)?;
        // SAFETY: count is bounded and caller supplies this many references.
        let references = unsafe { std::slice::from_raw_parts(candidates, count) };
        let mut unique = HashSet::new();
        let mut indices = Vec::with_capacity(count);
        for reference in references {
            let index = unsafe { read_candidate(discovery_handle, reference)? };
            if !unique.insert(index) {
                return Err(INVALID_CANDIDATE);
            }
            indices.push(index);
        }
        let slot = get_installer(discovery_handle)?;
        let mut job = lock_job(&slot)?;
        let discovery = job.discovery()?;
        if indices
            .iter()
            .any(|&index| index >= discovery.candidates.len())
        {
            return Err(INVALID_CANDIDATE);
        }
        let discovery = Arc::clone(discovery);
        let mut registry = registry().lock().map_err(|_| INTERNAL_ERROR)?;
        let handle = registry.allocate_handle()?;
        let task = InstallerTask::start_selection(discovery, indices).map_err(start_error)?;
        insert(&mut registry, handle, task, Some(discovery_handle));
        // SAFETY: Output slot remains writable through this call.
        unsafe { out_handle.write(handle) };
        Ok(())
    })
}

fn result_bytes(job: &mut InstallerJob, handle: u64) -> Result<&[u8], i32> {
    if job.result.is_none() {
        let result = job.task.result().ok_or(NOT_READY)?;
        let data = match result {
            Ok(InstallerTaskResult::Discovery(preview)) => installer_wire::preview_json(preview),
            Ok(InstallerTaskResult::Selection(preview)) => installer_wire::selection_json(preview),
            Err(error) => json!({
                "schema_version": 1, "kind": "installer_error",
                "status": if error.code == ScanCode::Cancelled { "cancelled" } else { "failed" },
                "complete": false, "effects_performed": false,
                "error": { "code": error.code.as_str(), "message": error.message, "os_code": error.os_code },
            }),
        };
        job.result = Some(bounded_json(
            &json!({
                "schema_version": 1, "task_handle": handle.to_string(),
                "source_task_handle": job.source_handle.map(|id| id.to_string()), "data": data,
            }),
            MAX_RESULT_BYTES,
        ));
    }
    job.result
        .as_ref()
        .expect("initialized installer result")
        .as_deref()
        .map_err(|code| *code)
}

/// Copies a terminal discovery/selection/fatal result, without trailing NUL.
///
/// # Safety
/// Outputs follow sayaka_scan_result_v1's caller-owned buffer contract and cap.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_installer_result_v1(
    handle: u64,
    buffer: *mut u8,
    capacity: usize,
    required: *mut usize,
) -> i32 {
    boundary(|| {
        // SAFETY: Caller supplies valid non-overlapping output storage.
        unsafe { prepare_output(buffer, capacity, required, MAX_RESULT_BYTES)? };
        let slot = get_installer(handle)?;
        let mut job = lock_job(&slot)?;
        job.ensure_open()?;
        let bytes = result_bytes(&mut job, handle)?;
        // SAFETY: Output storage was validated above.
        unsafe { copy_output(bytes, buffer, capacity, required) }
    })
}

/// Requests cancellation while active and returns BUSY until owned work exits.
#[unsafe(no_mangle)]
pub extern "C" fn sayaka_installer_release_v1(handle: u64) -> i32 {
    boundary(|| {
        let slot = get_installer(handle)?;
        let mut job = match slot.try_lock() {
            Ok(job) => job,
            Err(TryLockError::WouldBlock) => return Err(BUSY),
            Err(TryLockError::Poisoned(poison)) => poison.into_inner(),
        };
        job.ensure_open()?;
        if !job.task.is_finished() {
            job.task.cancel();
            return Err(BUSY);
        }
        job.task.result();
        job.closed = true;
        registry()
            .lock()
            .map_err(|_| INTERNAL_ERROR)?
            .installers
            .remove(&handle)
            .ok_or(INVALID_HANDLE)?;
        Ok(())
    })
}

#[cfg(test)]
mod tests;
