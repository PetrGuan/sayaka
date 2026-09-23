// SPDX-License-Identifier: MPL-2.0

use super::*;
use sayaka_engine::execute::{CacheSession, PurgeSession};
use sayaka_engine::journal::{self, Store};
use sayaka_engine::model::Cancellation;
use sayaka_engine::purge_preview::{
    self, PurgeItemId, PurgeOptions, PurgePreview, PurgeProfile, PurgeStatus,
};
use sayaka_engine::scan::index::ScanTree;
use sayaka_engine::scan::task::{ScanTask, ScanTaskState};
use sayaka_engine::scan::{ScanCode, ScanError, ScanLimits, wire};
use serde_json::{Value, json};
use std::thread::JoinHandle;
use std::time::SystemTime;

pub const MAX_PURGE_SELECTIONS: usize = journal::MAX_ITEMS;

#[repr(C)]
pub struct SayakaPurgePreviewRequestV1 {
    pub abi_version: u32,
    pub struct_size: u32,
    pub root: SayakaPathV1,
    pub stale_days: u32,
    pub reserved: u32,
}

#[repr(C)]
pub struct SayakaPurgePreviewProfileRequestV1 {
    pub abi_version: u32,
    pub struct_size: u32,
    pub root: SayakaPathV1,
    pub stale_days: u32,
    /// 1 = projects, 2 = developer_caches. 0 is accepted as projects for
    /// callers that zero-initialize optional fields.
    pub profile: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SayakaPurgeItemRefV1 {
    pub preview_handle: u64,
    pub item_id: u64,
}

#[repr(C)]
pub struct SayakaPurgeExecuteRequestV1 {
    pub abi_version: u32,
    pub struct_size: u32,
    pub preview_handle: u64,
    pub plan_digest: *const u8,
    pub plan_digest_length: usize,
    pub items: *const SayakaPurgeItemRefV1,
    pub item_count: usize,
    pub approval: u32,
    pub reserved: u32,
    pub approval_token: *const u8,
    pub approval_token_length: usize,
    pub has_state_dir: u32,
    pub state_dir: SayakaPathV1,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SayakaPurgeSnapshotV1 {
    pub abi_version: u32,
    pub struct_size: u32,
    pub kind: u32,
    pub state: u32,
    pub cancellation_requested: u32,
    pub has_progress: u32,
    pub reserved: u32,
    pub progress_sequence: u64,
    pub observed_entries: u64,
    pub unique_files: u64,
    pub logical_bytes_known: u64,
    pub total_items: u64,
    pub completed_items: u64,
    pub elapsed_ms: u64,
}

pub(super) struct PurgePreviewJob {
    task: ScanTask,
    options: PurgeOptions,
    preview: Option<Result<Arc<PurgePreview>, i32>>,
    result: Option<Result<Vec<u8>, i32>>,
    closed: bool,
}

pub(super) struct PurgeExecutionJob {
    cancel: Cancellation,
    worker: Option<JoinHandle<Result<Vec<u8>, ScanError>>>,
    result: Option<Result<Vec<u8>, i32>>,
    closed: bool,
}

pub(super) enum PurgeJob {
    Preview(Box<PurgePreviewJob>),
    Execution(Box<PurgeExecutionJob>),
}

impl PurgeJob {
    fn ensure_open(&self) -> Result<(), i32> {
        let closed = match self {
            Self::Preview(job) => job.closed,
            Self::Execution(job) => job.closed,
        };
        if closed { Err(INVALID_HANDLE) } else { Ok(()) }
    }
}

fn get_purge(handle: u64) -> Result<Arc<Mutex<PurgeJob>>, i32> {
    registry()
        .lock()
        .map_err(|_| INTERNAL_ERROR)?
        .purges
        .get(&handle)
        .cloned()
        .ok_or(INVALID_HANDLE)
}

fn scan_error_code(error: &ScanError) -> i32 {
    match error.code {
        ScanCode::InvalidRoot | ScanCode::InvalidLimits => INVALID_ARGUMENT,
        ScanCode::UnsupportedPlatform => UNSUPPORTED_PLATFORM,
        ScanCode::EntryLimit | ScanCode::PathBytesLimit | ScanCode::Overflow => LIMIT_EXCEEDED,
        _ => INTERNAL_ERROR,
    }
}

fn ensure_preview(job: &mut PurgePreviewJob) -> Result<Arc<PurgePreview>, i32> {
    if job.preview.is_none() {
        let report = job.task.result().ok_or(NOT_READY)?;
        let preview = match report {
            Ok(report) => {
                let cancellation = Cancellation::default();
                let index = ScanTree::build(report.clone(), &cancellation)
                    .map_err(|error| scan_error_code(&error))?;
                purge_preview::purge_preview(&index, &job.options, SystemTime::now())
                    .map_err(|_| INVALID_ARGUMENT)
                    .map(Arc::new)
            }
            Err(error) => Err(scan_error_code(error)),
        };
        job.preview = Some(preview);
    }
    job.preview
        .as_ref()
        .expect("initialized purge preview")
        .clone()
}

fn preview_json(preview: &PurgePreview, handle: u64) -> Value {
    let digest = preview.plan_digest();
    let mut next_id = 1u64;
    json!({
        "schema_version": preview.schema_version,
        "kind": "purge_preview",
        "task_handle": handle.to_string(),
        "status": preview.status.as_str(),
        "complete": preview.complete,
        "effects_performed": false,
        "execution_authority": false,
        "contract": match preview.profile {
            PurgeProfile::Projects => "revalidated_purge_trash_v1",
            PurgeProfile::DeveloperCaches => "revalidated_cache_trash_v1",
        },
        "profile": preview.profile.as_str(),
        "plan_identifier": digest,
        "plan_digest": digest,
        "roots": preview.roots.iter().map(|path| wire::NativePath(path)).collect::<Vec<_>>(),
        "stale_days": preview.stale_days,
        "totals": {
            "projects": preview.counts.projects,
            "items": preview.counts.artifacts,
            "stale_items": preview.counts.stale_artifacts,
            "excluded": preview.counts.excluded,
            "developer_caches": preview.counts.developer_caches,
            "unsupported_operations": preview.counts.unsupported_operations,
            "logical_bytes": sum_known(preview, true),
            "allocated_bytes": sum_known(preview, false),
        },
        "projects": preview.projects.iter().map(|project| {
            let value = json!({
                "root": wire::NativePath(&project.root),
                "markers": project.markers.iter().map(|marker| marker.as_str()).collect::<Vec<_>>(),
                "items": project.artifacts.iter().map(|artifact| {
                    let id = next_id;
                    next_id += 1;
                    json!({
                        "id": id.to_string(),
                        "reference": { "preview_handle": handle.to_string(), "item_id": id.to_string() },
                        "path": wire::NativePath(&artifact.path),
                        "name": artifact.name,
                        "kind": "directory",
                        "rule": "marker_bound_project_artifact_v1",
                        "markers": artifact.markers.iter().map(|marker| marker.as_str()).collect::<Vec<_>>(),
                        "sizes": {
                            "logical": artifact.logical_bytes,
                            "allocated": artifact.allocated_bytes,
                        },
                        "complete": artifact.complete,
                        "modified_unix_ms": artifact.modified_unix_ms,
                        "stale": artifact.stale,
                        "reasons": reasons(artifact),
                        "evidence": {
                            "project_markers": artifact.markers.iter().map(|marker| json!({
                                "kind": marker.as_str(),
                                "path": wire::NativePath(&project.root.join(marker.file_name())),
                            })).collect::<Vec<_>>(),
                            "residual_race_disclosed": true,
                        },
                    })
                }).collect::<Vec<_>>(),
            });
            value
        }).collect::<Vec<_>>(),
        "developer_caches": developer_cache_items_json(preview, handle),
        "unsupported_operations": unsupported_operations_json(preview.unsupported_operations),
        "scan_issues": preview.scan_issues.iter().map(|issue| json!({
            "path": issue.path.as_deref().map(wire::NativePath),
            "code": issue.code.as_str(),
            "message": issue.message,
            "os_code": issue.os_code,
        })).collect::<Vec<_>>(),
        "scan_issues_omitted": preview.scan_issues_omitted,
    })
}

fn developer_cache_items_json(preview: &PurgePreview, handle: u64) -> Vec<Value> {
    preview
        .developer_caches
        .iter()
        .enumerate()
        .map(|(index, cache)| {
            let id = index + 1;
            json!({
                "id": id.to_string(),
                "reference": { "preview_handle": handle.to_string(), "item_id": id.to_string() },
                "tool": cache.tool,
                "rule_id": cache.rule_id,
                "rule_version": cache.rule_version,
                "ruleset_revision": cache.ruleset_revision,
                "title": cache.title,
                "path": wire::NativePath(&cache.path),
                "location": cache.location,
                "location_kind": cache.location_kind,
                "kind": cache.kind,
                "rebuildability_note": cache.rebuildability_note,
                "user_product": cache.user_product,
                "cleanup_supported": cache.cleanup_supported,
                "unsupported_reason": cache.unsupported_reason,
                "sizes": {
                    "logical": cache.logical_bytes,
                    "allocated": cache.allocated_bytes,
                },
                "complete": cache.complete,
                "modified_unix_ms": cache.modified_unix_ms,
                "activity": cache.activity.as_str(),
                "evidence": cache.evidence.iter().map(|source| json!({
                    "title": source.title,
                    "url": source.url,
                    "reviewed_utc": source.reviewed_utc,
                    "license_note": source.license_note,
                })).collect::<Vec<_>>(),
                "filesystem_identity": filesystem_identity_json(cache.identity),
                "execution_supported": cache.complete && cache.cleanup_supported,
                "execution_unsupported_reason": if !cache.complete {
                    Some("developer cache scan coverage is incomplete; refresh or grant narrower access before execution")
                } else if !cache.cleanup_supported {
                    Some("developer cache cleanup is refused while activity evidence such as a lock file is observed")
                } else {
                    None
                },
                "execution_contract": "revalidated_cache_trash_v1",
            })
        })
        .collect()
}

fn unsupported_operations_json(
    operations: &[sayaka_engine::purge_preview::UnsupportedOperation],
) -> Vec<Value> {
    operations
        .iter()
        .map(|operation| {
            json!({
                "tool": operation.tool,
                "operation": operation.operation,
                "reason": operation.reason,
            })
        })
        .collect()
}

fn filesystem_identity_json(identity: sayaka_engine::model::FileIdentity) -> Value {
    match identity {
        sayaka_engine::model::FileIdentity::Unix { device, inode } => {
            json!({"platform": "unix", "device": device, "inode": inode})
        }
        sayaka_engine::model::FileIdentity::Windows {
            volume_serial,
            file_id,
        } => json!({
            "platform": "windows",
            "volume_serial": volume_serial,
            "file_id": file_id.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
        }),
    }
}

fn sum_known(preview: &PurgePreview, logical: bool) -> Option<u64> {
    let mut total = 0u64;
    for artifact in preview
        .projects
        .iter()
        .flat_map(|project| &project.artifacts)
    {
        let value = if logical {
            artifact.logical_bytes
        } else {
            artifact.allocated_bytes
        }?;
        total = total.checked_add(value)?;
    }
    for cache in &preview.developer_caches {
        let value = if logical {
            cache.logical_bytes
        } else {
            cache.allocated_bytes
        }?;
        total = total.checked_add(value)?;
    }
    Some(total)
}

fn reasons(artifact: &purge_preview::PurgeArtifact) -> Vec<&'static str> {
    let mut reasons = vec!["project_marker_bound"];
    reasons.push(match artifact.stale {
        Some(true) => "stale",
        Some(false) => "not_stale",
        None => "mtime_unknown",
    });
    if !artifact.complete {
        reasons.push("partial_coverage");
    }
    reasons
}

fn preview_result_bytes(job: &mut PurgePreviewJob, handle: u64) -> Result<&[u8], i32> {
    if job.result.is_none() {
        let data = ensure_preview(job).map(|preview| preview_json(&preview, handle));
        job.result = Some(data.and_then(|data| bounded_json(&data, MAX_RESULT_BYTES)));
    }
    job.result
        .as_ref()
        .expect("initialized purge preview result")
        .as_deref()
        .map_err(|code| *code)
}

fn execution_json(
    task_handle: u64,
    preview_handle: u64,
    preview: &PurgePreview,
    item_ids: &[PurgeItemId],
    report: sayaka_engine::execute::ExecutionReport,
) -> Value {
    let mut moved = 0usize;
    let mut skipped = 0usize;
    let mut failed = 0usize;
    let mut unknown = 0usize;
    let items = report
        .record
        .items
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let item_id = item_ids
                .get(index)
                .copied()
                .unwrap_or(PurgeItemId((index + 1) as u64));
            let status = match item.state {
                journal::ItemState::Succeeded => {
                    moved += 1;
                    "moved"
                }
                journal::ItemState::Skipped => {
                    skipped += 1;
                    "skipped"
                }
                journal::ItemState::Failed => {
                    failed += 1;
                    "failed"
                }
                journal::ItemState::Unknown => {
                    unknown += 1;
                    "unknown"
                }
                journal::ItemState::Planned | journal::ItemState::Started => {
                    unknown += 1;
                    "unknown"
                }
            };
            json!({
                "id": item_id.0.to_string(),
                "reference": { "preview_handle": preview_handle.to_string(), "item_id": item_id.0.to_string() },
                "path": journal_native_path_json(&item.path),
                "status": status,
                "reason": item.reason.as_ref(),
                "destination": item.destination.as_ref().map(journal_native_path_json),
                "logical_bytes": item.logical_bytes,
                "recovery_evidence": item.recovery_evidence.as_ref(),
            })
        })
        .collect::<Vec<_>>();
    json!({
        "schema_version": 1,
        "kind": "purge_execution",
        "task_handle": task_handle.to_string(),
        "source_preview_handle": preview_handle.to_string(),
        "status": if report.journal_error.is_some() || unknown > 0 {
            "failed"
        } else if failed > 0 || skipped > 0 {
            "partial"
        } else {
            "complete"
        },
        "complete": report.journal_error.is_none() && unknown == 0 && failed == 0,
        "effects_performed": moved > 0,
        "contract": report.record.contract,
        "plan_identifier": preview.plan_digest(),
        "plan_digest": preview.plan_digest(),
        "journal": {
            "operation_id": report.record.operation_id,
            "schema_version": report.record.schema_version,
            "error": report.journal_error,
        },
        "totals": {
            "requested": report.record.items.len(),
            "moved": moved,
            "skipped": skipped,
            "failed": failed,
            "unknown": unknown,
            "logical_bytes_moved": report.record.items.iter()
                .filter(|item| item.state == journal::ItemState::Succeeded)
                .try_fold(0u64, |sum, item| sum.checked_add(item.logical_bytes)),
        },
        "items": items,
        "residual_race_disclosed": true,
    })
}

struct RefusalDetails<'a> {
    status: &'a str,
    message: &'a str,
    reason: &'a str,
}

fn refusal_json(
    task_handle: u64,
    preview_handle: u64,
    preview: &PurgePreview,
    item_ids: &[PurgeItemId],
    details: RefusalDetails<'_>,
    issues: Vec<Value>,
    refusals: Vec<Value>,
) -> Value {
    let items = item_ids
        .iter()
        .map(|item_id| {
            preview_item_json(preview_handle, preview, *item_id, "skipped", details.reason)
        })
        .collect::<Vec<_>>();
    json!({
        "schema_version": 1,
        "kind": "purge_execution",
        "task_handle": task_handle.to_string(),
        "source_preview_handle": preview_handle.to_string(),
        "status": details.status,
        "complete": false,
        "effects_performed": false,
        "contract": match preview.profile {
            PurgeProfile::Projects => "revalidated_purge_trash_v1",
            PurgeProfile::DeveloperCaches => "revalidated_cache_trash_v1",
        },
        "plan_identifier": preview.plan_digest(),
        "plan_digest": preview.plan_digest(),
        "error": { "message": details.message, "reason": details.reason },
        "issues": issues,
        "refusals": refusals,
        "totals": { "requested": item_ids.len(), "moved": 0, "skipped": item_ids.len(), "failed": 0, "unknown": 0, "logical_bytes_moved": 0 },
        "items": items,
        "residual_race_disclosed": true,
    })
}

fn preview_item_json(
    preview_handle: u64,
    preview: &PurgePreview,
    item_id: PurgeItemId,
    status: &str,
    reason: &str,
) -> Value {
    let mut current = 1u64;
    for project in &preview.projects {
        for artifact in &project.artifacts {
            if current == item_id.0 {
                return json!({
                    "id": item_id.0.to_string(),
                    "reference": { "preview_handle": preview_handle.to_string(), "item_id": item_id.0.to_string() },
                    "path": wire::NativePath(&artifact.path),
                    "status": status,
                    "reason": reason,
                    "destination": null,
                    "logical_bytes": artifact.logical_bytes,
                    "recovery_evidence": null,
                });
            }
            current = current.saturating_add(1);
        }
    }
    if preview.profile == PurgeProfile::DeveloperCaches
        && let Some(cache) = preview
            .developer_caches
            .get((item_id.0.saturating_sub(1)) as usize)
    {
        return json!({
            "id": item_id.0.to_string(),
            "reference": { "preview_handle": preview_handle.to_string(), "item_id": item_id.0.to_string() },
            "path": wire::NativePath(&cache.path),
            "status": status,
            "reason": reason,
            "destination": null,
            "logical_bytes": cache.logical_bytes,
            "recovery_evidence": null,
        });
    }
    json!({
        "id": item_id.0.to_string(),
        "reference": { "preview_handle": preview_handle.to_string(), "item_id": item_id.0.to_string() },
        "path": null,
        "status": "unknown",
        "reason": "selected preview item was unavailable while reporting refusal",
        "destination": null,
        "logical_bytes": null,
        "recovery_evidence": null,
    })
}

fn journal_native_path_json(path: &journal::NativePath) -> Value {
    let raw = path
        .bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let encoding = match path.encoding.as_str() {
        "unix_bytes" => "unix_bytes_hex",
        other => other,
    };
    json!({
        "display": path.display.as_str(),
        "encoding": encoding,
        "raw": raw,
    })
}

fn execution_worker(
    task_handle: u64,
    preview_handle: u64,
    preview: Arc<PurgePreview>,
    item_ids: Vec<PurgeItemId>,
    state_dir: std::path::PathBuf,
    cancellation: Cancellation,
) -> Result<Vec<u8>, ScanError> {
    if preview.status != PurgeStatus::Complete || !preview.complete {
        return bounded_json(
            &refusal_json(
                task_handle,
                preview_handle,
                &preview,
                &item_ids,
                RefusalDetails {
                    status: "refused",
                    message: "purge execution requires a complete preview; nothing moved",
                    reason: "preview_incomplete",
                },
                vec![],
                vec![],
            ),
            MAX_RESULT_BYTES,
        )
        .map_err(|code| ScanError::new(ScanCode::Internal, sayaka_status_text(code)));
    }
    let mut session = match PreparedExecutionSession::prepare(&preview, &item_ids, &cancellation) {
        Ok(session) => session,
        Err(reason) => {
            return bounded_json(
                &refusal_json(
                    task_handle,
                    preview_handle,
                    &preview,
                    &item_ids,
                    RefusalDetails {
                        status: "refused",
                        message: "native purge selection was refused; nothing moved",
                        reason: &reason,
                    },
                    vec![],
                    vec![],
                ),
                MAX_RESULT_BYTES,
            )
            .map_err(|code| ScanError::new(ScanCode::Internal, sayaka_status_text(code)));
        }
    };
    let issues = session.issues();
    let refusals = session.refusals();
    if !issues.is_empty() || !refusals.is_empty() {
        return bounded_json(
            &refusal_json(
                task_handle,
                preview_handle,
                &preview,
                &item_ids,
                RefusalDetails {
                    status: "refused",
                    message: "native purge selection was refused; nothing moved",
                    reason: "selection_refused_before_approval",
                },
                issues,
                refusals,
            ),
            MAX_RESULT_BYTES,
        )
        .map_err(|code| ScanError::new(ScanCode::Internal, sayaka_status_text(code)));
    }
    let plan = session.preview().clone();
    let approval = match session.approve(&plan) {
        Ok(approval) => approval,
        Err(error) => {
            let reason = error.to_string();
            return bounded_json(
                &refusal_json(
                    task_handle,
                    preview_handle,
                    &preview,
                    &item_ids,
                    RefusalDetails {
                        status: "refused",
                        message: "native purge approval was refused during revalidation; nothing moved",
                        reason: &reason,
                    },
                    issues,
                    refusals,
                ),
                MAX_RESULT_BYTES,
            )
            .map_err(|code| ScanError::new(ScanCode::Internal, sayaka_status_text(code)));
        }
    };
    let store = Store::open(&state_dir, true)
        .map_err(|error| ScanError::new(ScanCode::Internal, error.to_string()))?;
    let report = session
        .execute(&plan, &approval, &cancellation, &store)
        .map_err(|error| ScanError::new(ScanCode::Internal, error.to_string()))?;
    bounded_json(
        &execution_json(task_handle, preview_handle, &preview, &item_ids, report),
        MAX_RESULT_BYTES,
    )
    .map_err(|code| ScanError::new(ScanCode::Internal, sayaka_status_text(code)))
}

enum PreparedExecutionSession {
    Projects(PurgeSession),
    Caches(CacheSession),
}

impl PreparedExecutionSession {
    fn prepare(
        preview: &PurgePreview,
        item_ids: &[PurgeItemId],
        cancellation: &Cancellation,
    ) -> Result<Self, String> {
        match preview.profile {
            PurgeProfile::Projects => {
                let selections = purge_preview::resolve_selections_by_ids(preview, item_ids)?;
                PurgeSession::prepare(&selections, cancellation)
                    .map(Self::Projects)
                    .map_err(|error| error.to_string())
            }
            PurgeProfile::DeveloperCaches => {
                let selections = purge_preview::resolve_cache_selections_by_ids(preview, item_ids)?;
                CacheSession::prepare(&selections, cancellation)
                    .map(Self::Caches)
                    .map_err(|error| error.to_string())
            }
        }
    }

    fn issues(&self) -> Vec<Value> {
        match self {
            Self::Projects(session) => session.issues(),
            Self::Caches(session) => session.issues(),
        }
        .iter()
        .map(|issue| {
            serde_json::to_value(issue)
                .unwrap_or_else(|_| json!({"message":"issue serialization failed"}))
        })
        .collect()
    }

    fn refusals(&self) -> Vec<Value> {
        match self {
            Self::Projects(session) => session.refusals(),
            Self::Caches(session) => session.refusals(),
        }
        .iter()
        .map(|refusal| {
            serde_json::to_value(refusal)
                .unwrap_or_else(|_| json!({"reason":"refusal serialization failed"}))
        })
        .collect()
    }

    fn preview(&self) -> &sayaka_engine::model::Plan {
        match self {
            Self::Projects(session) => session.preview(),
            Self::Caches(session) => session.preview(),
        }
    }

    fn approve(
        &mut self,
        plan: &sayaka_engine::model::Plan,
    ) -> Result<sayaka_engine::model::Approval, sayaka_engine::model::Error> {
        match self {
            Self::Projects(session) => session.approve(plan),
            Self::Caches(session) => session.approve(plan),
        }
    }

    fn execute(
        &mut self,
        plan: &sayaka_engine::model::Plan,
        approval: &sayaka_engine::model::Approval,
        cancellation: &Cancellation,
        store: &Store,
    ) -> std::io::Result<sayaka_engine::execute::ExecutionReport> {
        match self {
            Self::Projects(session) => session.execute(plan, approval, cancellation, store),
            Self::Caches(session) => session.execute(plan, approval, cancellation, store),
        }
    }
}

fn sayaka_status_text(code: i32) -> String {
    // SAFETY: Status messages are static NUL-terminated strings.
    unsafe {
        std::ffi::CStr::from_ptr(sayaka_status_message_v1(code))
            .to_string_lossy()
            .into_owned()
    }
}

fn collect_execution(job: &mut PurgeExecutionJob) {
    if job.worker.as_ref().is_some_and(JoinHandle::is_finished)
        && let Some(worker) = job.worker.take()
    {
        job.result = Some(match worker.join() {
            Ok(Ok(bytes)) => Ok(bytes),
            Ok(Err(error)) => Err(scan_error_code(&error)),
            Err(_) => Err(PANIC),
        });
    }
}

fn execution_result_bytes(job: &mut PurgeExecutionJob) -> Result<&[u8], i32> {
    collect_execution(job);
    job.result
        .as_ref()
        .ok_or(NOT_READY)?
        .as_deref()
        .map_err(|code| *code)
}

unsafe fn read_plan_digest(request: &SayakaPurgeExecuteRequestV1) -> Result<String, i32> {
    if request.plan_digest_length != 64 {
        return Err(INVALID_ARGUMENT);
    }
    pointer(request.plan_digest)?;
    // SAFETY: Caller provided readable digest bytes for the bounded length.
    let bytes =
        unsafe { std::slice::from_raw_parts(request.plan_digest, request.plan_digest_length) };
    let text = std::str::from_utf8(bytes).map_err(|_| INVALID_ARGUMENT)?;
    if !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(INVALID_ARGUMENT);
    }
    Ok(text.to_owned())
}

unsafe fn validate_approval(
    request: &SayakaPurgeExecuteRequestV1,
    profile: PurgeProfile,
) -> Result<(), i32> {
    if request.approval != 1 {
        return Err(INVALID_ARGUMENT);
    }
    let expected = match profile {
        PurgeProfile::Projects => format!("purge {} artifacts", request.item_count),
        PurgeProfile::DeveloperCaches => format!("trash {} caches", request.item_count),
    };
    if request.approval_token_length != expected.len() {
        return Err(INVALID_ARGUMENT);
    }
    pointer(request.approval_token)?;
    // SAFETY: Caller provided readable approval-token bytes for the bounded length.
    let bytes = unsafe {
        std::slice::from_raw_parts(request.approval_token, request.approval_token_length)
    };
    let token = std::str::from_utf8(bytes).map_err(|_| INVALID_ARGUMENT)?;
    if token != expected {
        return Err(INVALID_ARGUMENT);
    }
    Ok(())
}

unsafe fn read_item_ids(
    preview_handle: u64,
    items: *const SayakaPurgeItemRefV1,
    count: usize,
) -> Result<Vec<PurgeItemId>, i32> {
    if count == 0 || count > MAX_PURGE_SELECTIONS {
        return Err(INVALID_ARGUMENT);
    }
    pointer(items)?;
    // SAFETY: Count is bounded and caller supplies this many references.
    let refs = unsafe { std::slice::from_raw_parts(items, count) };
    let mut ids = Vec::with_capacity(count);
    let mut seen = std::collections::HashSet::new();
    for reference in refs {
        if reference.preview_handle != preview_handle
            || reference.item_id == 0
            || !seen.insert(reference.item_id)
        {
            return Err(INVALID_CANDIDATE);
        }
        ids.push(PurgeItemId(reference.item_id));
    }
    Ok(ids)
}

fn start_preview(
    root: std::path::PathBuf,
    options: PurgeOptions,
    out_handle: *mut u64,
) -> Result<(), i32> {
    options.validate().map_err(|_| INVALID_ARGUMENT)?;
    let mut registry = registry().lock().map_err(|_| INTERNAL_ERROR)?;
    let handle = registry.allocate_handle()?;
    let task = ScanTask::start(vec![root], ScanLimits::default())
        .map_err(|error| scan_error_code(&error))?;
    registry.purges.insert(
        handle,
        Arc::new(Mutex::new(PurgeJob::Preview(Box::new(PurgePreviewJob {
            task,
            options,
            preview: None,
            result: None,
            closed: false,
        })))),
    );
    // SAFETY: The caller provided writable storage for this call.
    unsafe { out_handle.write(handle) };
    Ok(())
}

/// Starts a read-only purge preview for one explicit native root.
///
/// # Safety
/// request/root bytes are readable/aligned; out_handle is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_purge_preview_start_v1(
    request: *const SayakaPurgePreviewRequestV1,
    out_handle: *mut u64,
) -> i32 {
    boundary(|| {
        pointer(out_handle)?;
        // SAFETY: Caller supplies a writable output slot.
        unsafe { out_handle.write(0) };
        pointer(request)?;
        // SAFETY: Caller supplies a readable request structure.
        let request = unsafe { &*request };
        if request.abi_version != ABI_VERSION
            || request.struct_size as usize != size_of::<SayakaPurgePreviewRequestV1>()
            || request.reserved != 0
        {
            return Err(UNSUPPORTED_VERSION);
        }
        if !cfg!(target_os = "macos") {
            return Err(UNSUPPORTED_PLATFORM);
        }
        let options = PurgeOptions {
            stale_days: if request.stale_days == 0 {
                purge_preview::DEFAULT_STALE_DAYS
            } else {
                request.stale_days
            },
            profile: PurgeProfile::Projects,
        };
        let root = unsafe { decode_path(request.root)? };
        start_preview(root, options, out_handle)?;
        Ok(())
    })
}

/// Starts a read-only purge preview for one explicit native root and profile.
///
/// # Safety
/// request/root bytes are readable/aligned; out_handle is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_purge_preview_start_profile_v1(
    request: *const SayakaPurgePreviewProfileRequestV1,
    out_handle: *mut u64,
) -> i32 {
    boundary(|| {
        pointer(out_handle)?;
        // SAFETY: Caller supplies a writable output slot.
        unsafe { out_handle.write(0) };
        pointer(request)?;
        // SAFETY: Caller supplies a readable request structure.
        let request = unsafe { &*request };
        if request.abi_version != ABI_VERSION
            || request.struct_size as usize != size_of::<SayakaPurgePreviewProfileRequestV1>()
            || request.reserved != 0
        {
            return Err(UNSUPPORTED_VERSION);
        }
        if !cfg!(target_os = "macos") {
            return Err(UNSUPPORTED_PLATFORM);
        }
        let profile = PurgeProfile::from_ffi(request.profile).ok_or(INVALID_ARGUMENT)?;
        let options = PurgeOptions {
            stale_days: if request.stale_days == 0 {
                purge_preview::DEFAULT_STALE_DAYS
            } else {
                request.stale_days
            },
            profile,
        };
        let root = unsafe { decode_path(request.root)? };
        start_preview(root, options, out_handle)?;
        Ok(())
    })
}

/// Returns purge preview/execution lifecycle progress.
///
/// # Safety
/// out_snapshot is aligned writable v1 storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_purge_poll_v1(
    handle: u64,
    out_snapshot: *mut SayakaPurgeSnapshotV1,
) -> i32 {
    boundary(|| {
        pointer(out_snapshot)?;
        // SAFETY: Caller supplies aligned writable snapshot storage.
        unsafe { out_snapshot.write(SayakaPurgeSnapshotV1::default()) };
        let slot = get_purge(handle)?;
        let mut job = lock_job(&slot)?;
        job.ensure_open()?;
        let mut out = SayakaPurgeSnapshotV1 {
            abi_version: ABI_VERSION,
            struct_size: size_of::<SayakaPurgeSnapshotV1>() as u32,
            ..Default::default()
        };
        match &mut *job {
            PurgeJob::Preview(job) => {
                out.kind = 1;
                let snapshot = job.task.poll().map_err(|_| INTERNAL_ERROR)?;
                out.state = match snapshot.state {
                    ScanTaskState::Running => 1,
                    ScanTaskState::Complete => 2,
                    ScanTaskState::Partial => 3,
                    ScanTaskState::Cancelled => 4,
                    ScanTaskState::Failed => 5,
                };
                out.cancellation_requested = u32::from(snapshot.cancellation_requested);
                out.progress_sequence = snapshot.progress_sequence;
                if let Some(progress) = snapshot.progress {
                    out.has_progress = 1;
                    out.observed_entries = progress.entries as u64;
                    out.unique_files = progress.unique_files;
                    out.logical_bytes_known = progress.logical_bytes_known;
                    out.elapsed_ms = progress.elapsed_ms;
                }
            }
            PurgeJob::Execution(job) => {
                collect_execution(job);
                out.kind = 2;
                out.state = match &job.result {
                    None => 1,
                    Some(Ok(_)) => 2,
                    Some(Err(_)) => 5,
                };
                out.cancellation_requested = u32::from(job.cancel.is_cancelled());
            }
        }
        // SAFETY: Caller owns writable output for this call.
        unsafe { out_snapshot.write(out) };
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn sayaka_purge_cancel_v1(handle: u64) -> i32 {
    boundary(|| {
        let slot = get_purge(handle)?;
        let job = lock_job(&slot)?;
        job.ensure_open()?;
        match &*job {
            PurgeJob::Preview(job) => job.task.cancel(),
            PurgeJob::Execution(job) => job.cancel.cancel(),
        }
        Ok(())
    })
}

/// Starts revalidated Trash execution for an approved subset of preview items.
///
/// # Safety
/// request, item refs and token/digest bytes are readable; out_handle writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_purge_execute_start_v1(
    request: *const SayakaPurgeExecuteRequestV1,
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
            || request.struct_size as usize != size_of::<SayakaPurgeExecuteRequestV1>()
            || request.reserved != 0
        {
            return Err(UNSUPPORTED_VERSION);
        }
        if !cfg!(target_os = "macos") {
            return Err(UNSUPPORTED_PLATFORM);
        }
        let requested_digest = unsafe { read_plan_digest(request)? };
        let item_ids =
            unsafe { read_item_ids(request.preview_handle, request.items, request.item_count)? };
        let state_dir = if request.has_state_dir == 0 {
            journal::default_directory().map_err(|_| INVALID_ARGUMENT)?
        } else if request.has_state_dir == 1 {
            unsafe { decode_path(request.state_dir)? }
        } else {
            return Err(INVALID_ARGUMENT);
        };
        journal::validate_state_directory_path(&state_dir).map_err(|_| INVALID_ARGUMENT)?;
        let preview = {
            let slot = get_purge(request.preview_handle)?;
            let mut job = lock_job(&slot)?;
            match &mut *job {
                PurgeJob::Preview(job) => {
                    let preview = ensure_preview(job)?;
                    unsafe { validate_approval(request, preview.profile)? };
                    if preview.plan_digest() != requested_digest {
                        return Err(INVALID_CANDIDATE);
                    }
                    if preview.profile == PurgeProfile::DeveloperCaches
                        && request.has_state_dir != 1
                    {
                        return Err(INVALID_ARGUMENT);
                    }
                    preview
                }
                PurgeJob::Execution(_) => return Err(INVALID_HANDLE),
            }
        };
        let mut registry = registry().lock().map_err(|_| INTERNAL_ERROR)?;
        let handle = registry.allocate_handle()?;
        let cancellation = Cancellation::default();
        let worker_cancel = cancellation.clone();
        let preview_handle = request.preview_handle;
        let worker = std::thread::Builder::new()
            .name("sayaka-host-purge-execute".into())
            .spawn(move || {
                execution_worker(
                    handle,
                    preview_handle,
                    preview,
                    item_ids,
                    state_dir,
                    worker_cancel,
                )
            })
            .map_err(|_| INTERNAL_ERROR)?;
        registry.purges.insert(
            handle,
            Arc::new(Mutex::new(PurgeJob::Execution(Box::new(
                PurgeExecutionJob {
                    cancel: cancellation,
                    worker: Some(worker),
                    result: None,
                    closed: false,
                },
            )))),
        );
        // SAFETY: Output remains valid through this call.
        unsafe { out_handle.write(handle) };
        Ok(())
    })
}

/// Copies static unsupported in-app purge operations JSON, with no trailing NUL.
///
/// # Safety
/// Outputs follow sayaka_scan_result_v1's caller-owned buffer contract and cap.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_purge_unsupported_operations_v1(
    buffer: *mut u8,
    capacity: usize,
    required: *mut usize,
) -> i32 {
    boundary(|| {
        // SAFETY: Caller supplies valid non-overlapping output storage.
        unsafe { prepare_output(buffer, capacity, required, MAX_RESULT_BYTES)? };
        let value = json!({
            "schema_version": 1,
            "kind": "purge_unsupported_operations",
            "profile": "developer_caches",
            "operations": unsupported_operations_json(purge_preview::unsupported_operations()),
        });
        let bytes = bounded_json(&value, MAX_RESULT_BYTES)?;
        // SAFETY: Output storage was validated above.
        unsafe { copy_output(&bytes, buffer, capacity, required) }
    })
}

/// Copies terminal purge preview/execution JSON, with no trailing NUL.
///
/// # Safety
/// Outputs follow sayaka_scan_result_v1's caller-owned buffer contract and cap.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_purge_result_v1(
    handle: u64,
    buffer: *mut u8,
    capacity: usize,
    required: *mut usize,
) -> i32 {
    boundary(|| {
        // SAFETY: Caller supplies valid non-overlapping output storage.
        unsafe { prepare_output(buffer, capacity, required, MAX_RESULT_BYTES)? };
        let slot = get_purge(handle)?;
        let mut job = lock_job(&slot)?;
        job.ensure_open()?;
        let bytes = match &mut *job {
            PurgeJob::Preview(job) => preview_result_bytes(job, handle)?,
            PurgeJob::Execution(job) => execution_result_bytes(job)?,
        };
        // SAFETY: Output storage was validated above.
        unsafe { copy_output(bytes, buffer, capacity, required) }
    })
}

/// Requests cancellation while active and returns BUSY until owned work exits.
#[unsafe(no_mangle)]
pub extern "C" fn sayaka_purge_release_v1(handle: u64) -> i32 {
    boundary(|| {
        let slot = get_purge(handle)?;
        let mut job = match slot.try_lock() {
            Ok(job) => job,
            Err(TryLockError::WouldBlock) => return Err(BUSY),
            Err(TryLockError::Poisoned(poison)) => poison.into_inner(),
        };
        job.ensure_open()?;
        let finished = match &mut *job {
            PurgeJob::Preview(job) => {
                if !job.task.is_finished() {
                    job.task.cancel();
                    false
                } else {
                    job.task.result();
                    job.closed = true;
                    true
                }
            }
            PurgeJob::Execution(job) => {
                collect_execution(job);
                if job.worker.is_some() {
                    job.cancel.cancel();
                    false
                } else {
                    job.closed = true;
                    true
                }
            }
        };
        if !finished {
            return Err(BUSY);
        }
        registry()
            .lock()
            .map_err(|_| INTERNAL_ERROR)?
            .purges
            .remove(&handle)
            .ok_or(INVALID_HANDLE)?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_request_requires_explicit_approval_token() {
        let digest = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let item = SayakaPurgeItemRefV1 {
            preview_handle: 7,
            item_id: 1,
        };
        let request = SayakaPurgeExecuteRequestV1 {
            abi_version: ABI_VERSION,
            struct_size: size_of::<SayakaPurgeExecuteRequestV1>() as u32,
            preview_handle: 7,
            plan_digest: digest.as_ptr(),
            plan_digest_length: digest.len(),
            items: &item,
            item_count: 1,
            approval: 0,
            reserved: 0,
            approval_token: b"purge 1 artifacts".as_ptr(),
            approval_token_length: b"purge 1 artifacts".len(),
            has_state_dir: 0,
            state_dir: SayakaPathV1 {
                encoding: 0,
                bytes: std::ptr::null(),
                byte_length: 0,
            },
        };
        assert_eq!(
            unsafe { validate_approval(&request, PurgeProfile::Projects) },
            Err(INVALID_ARGUMENT)
        );
    }

    #[test]
    fn approval_token_length_is_checked_before_reading_token() {
        let digest = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let item = SayakaPurgeItemRefV1 {
            preview_handle: 7,
            item_id: 1,
        };
        let mut request = SayakaPurgeExecuteRequestV1 {
            abi_version: ABI_VERSION,
            struct_size: size_of::<SayakaPurgeExecuteRequestV1>() as u32,
            preview_handle: 7,
            plan_digest: digest.as_ptr(),
            plan_digest_length: digest.len(),
            items: &item,
            item_count: 1,
            approval: 1,
            reserved: 0,
            approval_token: std::ptr::null(),
            approval_token_length: usize::MAX,
            has_state_dir: 0,
            state_dir: SayakaPathV1 {
                encoding: 0,
                bytes: std::ptr::null(),
                byte_length: 0,
            },
        };
        assert_eq!(
            unsafe { validate_approval(&request, PurgeProfile::Projects) },
            Err(INVALID_ARGUMENT)
        );

        request.approval_token_length = b"purge 1 artifacts".len();
        assert_eq!(
            unsafe { validate_approval(&request, PurgeProfile::Projects) },
            Err(INVALID_ARGUMENT)
        );
    }

    #[test]
    fn developer_cache_approval_uses_distinct_token() {
        let digest = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let item = SayakaPurgeItemRefV1 {
            preview_handle: 7,
            item_id: 1,
        };
        let request = SayakaPurgeExecuteRequestV1 {
            abi_version: ABI_VERSION,
            struct_size: size_of::<SayakaPurgeExecuteRequestV1>() as u32,
            preview_handle: 7,
            plan_digest: digest.as_ptr(),
            plan_digest_length: digest.len(),
            items: &item,
            item_count: 1,
            approval: 1,
            reserved: 0,
            approval_token: b"trash 1 caches".as_ptr(),
            approval_token_length: b"trash 1 caches".len(),
            has_state_dir: 0,
            state_dir: SayakaPathV1 {
                encoding: 0,
                bytes: std::ptr::null(),
                byte_length: 0,
            },
        };
        assert_eq!(
            unsafe { validate_approval(&request, PurgeProfile::DeveloperCaches) },
            Ok(())
        );
        assert_eq!(
            unsafe { validate_approval(&request, PurgeProfile::Projects) },
            Err(INVALID_ARGUMENT)
        );
    }

    #[test]
    fn execution_items_include_preview_reference_and_preview_path_shape() {
        let preview = purge_preview_fixture();
        let report = sayaka_engine::execute::ExecutionReport {
            record: journal::Record {
                schema_version: 5,
                plan_schema_version: 5,
                engine_version: 2,
                rules_version: 1,
                operation_id: "op".into(),
                contract: "revalidated_purge_trash_v1".into(),
                scope: journal::NativePath::from_path(std::path::Path::new("/repo")),
                clean_policy: None,
                created_unix_ms: 1,
                items: vec![journal::ItemRecord {
                    path: journal::NativePath::from_path(std::path::Path::new("/repo/target")),
                    device: 1,
                    inode: 2,
                    logical_bytes: 42,
                    state: journal::ItemState::Succeeded,
                    reason: None,
                    destination: Some(journal::NativePath::from_path(std::path::Path::new(
                        "/Users/me/.Trash/target",
                    ))),
                    rule_binding: None,
                    recovery_evidence: None,
                    updated_unix_ms: 2,
                }],
            },
            journal_error: None,
        };
        let value = execution_json(11, 7, &preview, &[PurgeItemId(1)], report);
        let item = &value["items"][0];
        assert_eq!(item["id"], "1");
        assert_eq!(
            item["reference"],
            json!({"preview_handle": "7", "item_id": "1"})
        );
        assert_eq!(item["path"]["encoding"], "unix_bytes_hex");
        assert_eq!(item["path"]["raw"], "2f7265706f2f746172676574");
        assert_eq!(item["destination"]["encoding"], "unix_bytes_hex");
        assert_eq!(
            item["destination"]["raw"],
            "2f55736572732f6d652f2e54726173682f746172676574"
        );
    }

    #[test]
    fn refusal_items_include_selected_preview_ids() {
        let preview = purge_preview_fixture();
        let value = refusal_json(
            11,
            7,
            &preview,
            &[PurgeItemId(1)],
            RefusalDetails {
                status: "refused",
                message: "native purge approval was refused during revalidation; nothing moved",
                reason: "resource_changed",
            },
            Vec::new(),
            Vec::new(),
        );
        let item = &value["items"][0];
        assert_eq!(value["effects_performed"], false);
        assert_eq!(value["totals"]["requested"], 1);
        assert_eq!(value["totals"]["skipped"], 1);
        assert_eq!(item["id"], "1");
        assert_eq!(item["status"], "skipped");
        assert_eq!(item["reason"], "resource_changed");
        assert_eq!(item["path"]["encoding"], "unix_bytes_hex");
        assert_eq!(item["path"]["raw"], "2f7265706f2f746172676574");
    }

    fn purge_preview_fixture() -> PurgePreview {
        PurgePreview {
            schema_version: 1,
            kind: purge_preview::PURGE_KIND,
            platform: "macos",
            status: PurgeStatus::Complete,
            complete: true,
            effects_performed: false,
            profile: purge_preview::PurgeProfile::Projects,
            roots: vec![std::path::PathBuf::from("/repo")],
            stale_days: purge_preview::DEFAULT_STALE_DAYS,
            projects: vec![purge_preview::PurgeProject {
                root: std::path::PathBuf::from("/repo"),
                markers: vec![purge_preview::ProjectMarker::CargoToml],
                artifacts: vec![purge_preview::PurgeArtifact {
                    path: std::path::PathBuf::from("/repo/target"),
                    name: "target".into(),
                    markers: vec![purge_preview::ProjectMarker::CargoToml],
                    logical_bytes: Some(42),
                    allocated_bytes: Some(64),
                    complete: true,
                    modified_unix_ms: Some(1),
                    stale: Some(true),
                }],
            }],
            counts: purge_preview::PurgeCounts {
                projects: 1,
                artifacts: 1,
                stale_artifacts: 1,
                excluded: 0,
                developer_caches: 0,
                unsupported_operations: 0,
            },
            developer_caches: Vec::new(),
            unsupported_operations: purge_preview::profile_unsupported_operations(
                purge_preview::PurgeProfile::Projects,
            ),
            scan_issues: Vec::new(),
            scan_issues_omitted: 0,
        }
    }

    #[test]
    fn item_refs_reject_cross_preview_duplicate_and_empty_subset() {
        assert_eq!(
            unsafe { read_item_ids(7, std::ptr::null(), 0) },
            Err(INVALID_ARGUMENT)
        );
        let refs = [
            SayakaPurgeItemRefV1 {
                preview_handle: 7,
                item_id: 1,
            },
            SayakaPurgeItemRefV1 {
                preview_handle: 8,
                item_id: 2,
            },
        ];
        assert_eq!(
            unsafe { read_item_ids(7, refs.as_ptr(), refs.len()) },
            Err(INVALID_CANDIDATE)
        );
        let refs = [
            SayakaPurgeItemRefV1 {
                preview_handle: 7,
                item_id: 1,
            },
            SayakaPurgeItemRefV1 {
                preview_handle: 7,
                item_id: 1,
            },
        ];
        assert_eq!(
            unsafe { read_item_ids(7, refs.as_ptr(), refs.len()) },
            Err(INVALID_CANDIDATE)
        );
    }
}
