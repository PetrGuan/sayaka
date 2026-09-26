// SPDX-License-Identifier: MPL-2.0

//! One retained, explicit-bundle App Store uninstall preview and Trash contract.
//! Other copies are read-only evidence, never execution selections.

use super::*;
use sayaka_engine::app_inventory::{
    AppInventoryLimits, AppInventoryMetadataReadMode, AppInventoryOptions, inventory_apps,
};
use sayaka_engine::app_related::preview_app_related_data;
use sayaka_engine::app_uninstall::{self, UninstallPreview};
use sayaka_engine::execute::BundleUninstallSession;
use sayaka_engine::journal::ItemState;
use sayaka_engine::journal::Store;
use sayaka_engine::model::{Cancellation, Scope};
use sayaka_engine::scan::{ScanLimits, scan_prune_app_bundles};
use serde_json::json;
use std::path::Component;
use std::time::Duration;
use std::time::Instant;

const RELATED_RESULT_BYTES: usize = 4 * 1024 * 1024;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SayakaUninstallRelatedRequestV1 {
    pub abi_version: u32,
    pub struct_size: u32,
    pub handle: u64,
    pub library_root: SayakaPathV1,
    pub reserved: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SayakaUninstallRequestV1 {
    pub abi_version: u32,
    pub struct_size: u32,
    pub bundle: SayakaPathV1,
    pub copies_root: SayakaPathV1,
}

pub(super) struct UninstallJob {
    preview: UninstallPreview,
    session: Option<BundleUninstallSession>,
    preview_bytes: Vec<u8>,
    result_bytes: Option<Vec<u8>>,
    closed: bool,
}

fn display(path: &std::path::Path) -> String {
    sayaka_engine::scan::display_path(path)
}

fn normal_absolute(path: &std::path::Path) -> bool {
    let mut parts = path.components();
    matches!(parts.next(), Some(std::path::Component::RootDir))
        && parts.all(|part| matches!(part, std::path::Component::Normal(_)))
}

fn preview_bytes(preview: &UninstallPreview, eligible: bool) -> Result<Vec<u8>, i32> {
    let value = json!({
        "schema_version": 1,
        "kind": "sayaka.app_uninstall_preview",
        "bundle_path": display(&preview.bundle_path),
        "display_name": preview.display_name,
        "effects_performed": false,
        "execution_eligible": eligible,
        "identity": preview.identity.as_ref().map(|id| json!({"device": id.device, "inode": id.inode})),
        "running": preview.running.as_str(),
        "copies": {
            "state": preview.copies.status.as_str(),
            "reason": preview.copies.reason,
            "note": preview.copies.note,
            "items": preview.copies.copies.iter().map(|copy| json!({
                "path": display(&copy.bundle_path),
                "running": copy.running.as_str(),
            })).collect::<Vec<_>>(),
        },
        "vendor_uninstaller": preview.vendor_uninstaller.map(|vendor| json!({
            "name": vendor.name,
            "instruction": vendor.instruction,
            "source_url": vendor.source_url,
            "may_remove_user_data": vendor.may_remove_user_data,
            "authorization": vendor.authorization,
            "restart": vendor.restart,
        })),
        "refusals": preview.refusals.iter().map(|refusal| json!({
            "code": refusal.code.as_str(), "message": refusal.message,
        })).collect::<Vec<_>>(),
        "recovery": preview.recovery,
    });
    bounded_json(&value, MAX_QUERY_BYTES)
}

fn get_job(handle: u64) -> Result<Arc<Mutex<UninstallJob>>, i32> {
    registry()
        .lock()
        .map_err(|_| INTERNAL_ERROR)?
        .uninstalls
        .get(&handle)
        .cloned()
        .ok_or(INVALID_HANDLE)
}

/// Bounded read-only related-data evidence for the retained app. The caller
/// must hold readable security scopes for its app folder and Library root.
/// Every candidate remains protected; this API grants no Trash authority.
///
/// # Safety
/// Request and nested path bytes must be readable. Output storage must be
/// disjoint from them and exactly RELATED_RESULT_BYTES long.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_uninstall_related_preview_v1(
    request: *const SayakaUninstallRelatedRequestV1,
    buffer: *mut u8,
    capacity: usize,
    required: *mut usize,
) -> i32 {
    boundary(|| {
        unsafe { prepare_output(buffer, capacity, required, RELATED_RESULT_BYTES)? };
        if capacity != RELATED_RESULT_BYTES {
            return Err(INVALID_ARGUMENT);
        }
        pointer(request)?;
        let request = unsafe { *request };
        if request.abi_version != ABI_VERSION
            || request.struct_size as usize != size_of::<SayakaUninstallRelatedRequestV1>()
            || request.reserved != 0
        {
            return Err(UNSUPPORTED_VERSION);
        }
        if !cfg!(target_os = "macos") {
            return Err(UNSUPPORTED_PLATFORM);
        }
        let library_root = unsafe { decode_path(request.library_root)? };
        if !normal_absolute(&library_root)
            || library_root
                .file_name()
                .is_none_or(|name| name != "Library")
            || library_root
                .components()
                .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
        {
            return Err(INVALID_ARGUMENT);
        }
        let slot = get_job(request.handle)?;
        let (bundle, app_root) = {
            let job = lock_job(&slot)?;
            if job.closed || job.result_bytes.is_some() {
                return Err(INVALID_HANDLE);
            }
            let bundle = job.preview.bundle_path.clone();
            let root = bundle.parent().ok_or(INVALID_ARGUMENT)?.to_path_buf();
            (bundle, root)
        };
        let cancellation = Cancellation::default();
        let started = Instant::now();
        let scan_report = scan_prune_app_bundles(
            &[app_root.clone()],
            &ScanLimits {
                time_budget: Duration::from_secs(15),
                ..ScanLimits::default()
            },
            &cancellation,
            |_| {},
        )
        .map_err(|_| QUERY_UNAVAILABLE)?;
        let inventory = inventory_apps(
            scan_report,
            &AppInventoryOptions {
                metadata_read_mode: AppInventoryMetadataReadMode::AppRelated,
                limits: AppInventoryLimits::default(),
                ..AppInventoryOptions::default()
            },
            &cancellation,
            Duration::from_secs(30).saturating_sub(started.elapsed()),
        );
        let selected = inventory
            .apps
            .iter()
            .find(|app| app.bundle_path == bundle)
            .ok_or(QUERY_UNAVAILABLE)?;
        let bundle_id = selected
            .bundle_id
            .value
            .as_deref()
            .ok_or(QUERY_UNAVAILABLE)?
            .to_owned();
        let preview = preview_app_related_data(
            inventory,
            vec![app_root],
            vec![library_root],
            bundle_id.clone(),
            &cancellation,
            Duration::from_secs(5),
        );
        let selected_copy_ids = preview
            .app_copies
            .iter()
            .filter(|copy| copy.bundle_path == bundle)
            .map(|copy| copy.app_copy_id.as_str())
            .collect::<Vec<_>>();
        let candidates = preview
            .candidates
            .iter()
            .filter(|candidate| {
                candidate
                    .matched_app_copy_ids
                    .iter()
                    .any(|id| selected_copy_ids.contains(&id.as_str()))
            })
            .map(|candidate| {
                json!({
                    "candidate_id": candidate.candidate_id,
                    "path": display(&candidate.path),
                    "relative_library_path": candidate.relative_library_path,
                    "role": candidate.role,
                    "path_state": candidate.path_state,
                    "ownership_certainty": candidate.ownership_certainty,
                    "ownership_statement": candidate.ownership_statement,
                    "matched_app_copy_ids": candidate.matched_app_copy_ids,
                    "protection_reasons": candidate.protection_reasons,
                    "selected": false,
                    "authorized_action": serde_json::Value::Null,
                })
            })
            .collect::<Vec<_>>();
        let bytes = bounded_json(
            &json!({
                "schema_version": 1,
                "kind": "sayaka.app_uninstall_related_preview",
                "status": preview.status.as_str(),
                "complete": preview.complete,
                "inventory_complete": preview.inventory_complete,
                "effects_performed": false,
                "bundle_path": display(&bundle),
                "bundle_id": bundle_id,
                "candidate_count": candidates.len(),
                "candidates": candidates,
                "issue_count": preview.issues.len() + preview.scan_issues.len(),
            }),
            RELATED_RESULT_BYTES,
        )?;
        unsafe { copy_output(&bytes, buffer, capacity, required) }
    })
}

/// Starts a retained preview. The caller must hold a read-write security scope
/// for the explicit bundle and a readable scope for the copies root.
///
/// # Safety
/// Request, nested paths and out_handle must be valid disjoint storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_uninstall_preview_start_v1(
    request: *const SayakaUninstallRequestV1,
    out_handle: *mut u64,
) -> i32 {
    boundary(|| {
        pointer(out_handle)?;
        unsafe { out_handle.write(0) };
        pointer(request)?;
        let request = unsafe { *request };
        if request.abi_version != ABI_VERSION
            || request.struct_size as usize != size_of::<SayakaUninstallRequestV1>()
        {
            return Err(UNSUPPORTED_VERSION);
        }
        if !cfg!(target_os = "macos") {
            return Err(UNSUPPORTED_PLATFORM);
        }
        let bundle = unsafe { decode_path(request.bundle)? };
        let copies_root = unsafe { decode_path(request.copies_root)? };
        if !normal_absolute(&bundle)
            || !normal_absolute(&copies_root)
            || bundle.parent() != Some(copies_root.as_path())
        {
            return Err(INVALID_ARGUMENT);
        }
        let mut preview = app_uninstall::preview_bundle_uninstall(&bundle);
        preview.copies = app_uninstall::observe_copies(
            &preview,
            &[copies_root],
            &Cancellation::default(),
            Duration::from_secs(60),
        );
        let session = if preview.refusals.is_empty() {
            let parent = bundle.parent().ok_or(INVALID_ARGUMENT)?;
            let scope = Scope::new(parent.to_path_buf(), vec![]).map_err(|_| INVALID_ARGUMENT)?;
            match BundleUninstallSession::prepare(scope, &bundle, &Cancellation::default()) {
                Ok(session) if !session.preview().items().is_empty() => Some(session),
                _ => None,
            }
        } else {
            None
        };
        let bytes = preview_bytes(&preview, session.is_some())?;
        let mut registry = registry().lock().map_err(|_| INTERNAL_ERROR)?;
        let handle = registry.allocate_handle()?;
        registry.uninstalls.insert(
            handle,
            Arc::new(Mutex::new(UninstallJob {
                preview,
                session,
                preview_bytes: bytes,
                result_bytes: None,
                closed: false,
            })),
        );
        unsafe { out_handle.write(handle) };
        Ok(())
    })
}

/// Returns retained preview or terminal execution JSON. A size probe is safe.
///
/// # Safety
/// Output pointers follow the scan result buffer contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_uninstall_result_v1(
    handle: u64,
    buffer: *mut u8,
    capacity: usize,
    required: *mut usize,
) -> i32 {
    boundary(|| {
        unsafe { prepare_output(buffer, capacity, required, MAX_RESULT_BYTES)? };
        let slot = get_job(handle)?;
        let job = lock_job(&slot)?;
        if job.closed {
            return Err(INVALID_HANDLE);
        }
        let bytes = job.result_bytes.as_ref().unwrap_or(&job.preview_bytes);
        unsafe { copy_output(bytes, buffer, capacity, required) }
    })
}

/// Confirms and moves exactly the retained bundle through the native core.
/// Never launches a vendor uninstaller or touches copies/related data.
///
/// # Safety
/// Token/state_dir refer to valid readable storage for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_uninstall_execute_v1(
    handle: u64,
    approval_token: *const u8,
    approval_token_length: usize,
    state_dir: SayakaPathV1,
) -> i32 {
    boundary(|| {
        if approval_token_length == 0 || approval_token_length > 256 {
            return Err(INVALID_ARGUMENT);
        }
        pointer(approval_token)?;
        let token = unsafe { std::slice::from_raw_parts(approval_token, approval_token_length) };
        let token = std::str::from_utf8(token).map_err(|_| INVALID_ARGUMENT)?;
        let state_dir = unsafe { decode_path(state_dir)? };
        if !state_dir.is_absolute() {
            return Err(INVALID_ARGUMENT);
        }
        let slot = get_job(handle)?;
        let mut job = lock_job(&slot)?;
        if job.closed {
            return Err(INVALID_HANDLE);
        }
        if job.result_bytes.is_some() {
            return Err(INVALID_HANDLE);
        }
        let name = job
            .preview
            .bundle_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(INVALID_ARGUMENT)?;
        if token != format!("uninstall {name}") {
            return Err(INVALID_ARGUMENT);
        }
        let store = Store::open(&state_dir, true).map_err(|_| INTERNAL_ERROR)?;
        let Some(mut session) = job.session.take() else {
            return Err(INVALID_CANDIDATE);
        };
        let plan = session.preview().clone();
        let approval = match session.approve(&plan) {
            Ok(approval) => approval,
            Err(error) => {
                job.result_bytes = Some(bounded_json(
                    &json!({
                        "schema_version": 1, "kind": "sayaka.app_uninstall_execution",
                        "state": "refused", "effects_performed": false,
                        "error": error.to_string(),
                        "recovery": "No native Trash call occurred. Preview the app again before retrying.",
                    }),
                    MAX_RESULT_BYTES,
                )?);
                return Ok(());
            }
        };
        let result = match session.execute(&plan, &approval, &Cancellation::default(), &store) {
            Ok(report) => {
                let state = if report.journal_error.is_some() {
                    "unknown"
                } else {
                    match report.record.items.as_slice() {
                        [item] if item.reason.as_deref() == Some("cancelled") => "cancelled",
                        [item] => match item.state {
                            ItemState::Succeeded => "completed",
                            ItemState::Skipped => "skipped",
                            ItemState::Failed => "failed",
                            _ => "unknown",
                        },
                        _ => "unknown",
                    }
                };
                json!({
                "schema_version": 1, "kind": "sayaka.app_uninstall_execution",
                "state": state,
                "report": report,
                "recovery": "Use Finder Put Back for an item moved to Trash; related data and other copies were untouched",
                })
            }
            Err(error) => json!({
                "schema_version": 1, "kind": "sayaka.app_uninstall_execution",
                "state": "unknown", "error": error.to_string(),
                "recovery": "Inspect the Trash and operation journal before retrying",
            }),
        };
        job.result_bytes = Some(bounded_json(&result, MAX_RESULT_BYTES).unwrap_or_else(|_| {
            br#"{"schema_version":1,"kind":"sayaka.app_uninstall_execution","state":"unknown","error":"native execution result exceeded the output budget; inspect the operation journal and Trash"}"#.to_vec()
        }));
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn sayaka_uninstall_release_v1(handle: u64) -> i32 {
    boundary(|| {
        let slot = get_job(handle)?;
        let mut guard = lock_job(&slot)?;
        if guard.closed {
            return Err(INVALID_HANDLE);
        }
        guard.closed = true;
        registry()
            .lock()
            .map_err(|_| INTERNAL_ERROR)?
            .uninstalls
            .remove(&handle)
            .ok_or(INVALID_HANDLE)?;
        Ok(())
    })
}
