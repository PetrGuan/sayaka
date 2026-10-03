// SPDX-License-Identifier: MPL-2.0
//! Explicit regular-file selections. Retains the native session across approval.
use super::*;
use sayaka_engine::clean_policy::{self, ConfigPath, PolicyGuardStatus, PolicySnapshot};
use sayaka_engine::execute::TrashSession;
use sayaka_engine::journal::{self, NativePath, Store};
use sayaka_engine::model::{Cancellation, Scope};
use serde_json::json;
use std::thread::JoinHandle;

#[repr(C)]
pub struct SayakaPickedPreviewRequestV1 {
    pub abi_version: u32,
    pub struct_size: u32,
    pub root: SayakaPathV1,
    pub paths: *const SayakaPathV1,
    pub path_count: usize,
    pub config_dir: SayakaPathV1,
    pub reserved: u64,
}

struct Policy {
    config: ConfigPath,
    root: PathBuf,
    snapshot: PolicySnapshot,
}

struct Preview {
    session: TrashSession,
    policy: Policy,
    token: String,
    bytes: Vec<u8>,
    eligible: bool,
}

enum Outcome {
    Preview(Preview),
    Execution(Vec<u8>),
}

struct State {
    worker: Option<JoinHandle<Result<Outcome, i32>>>,
    outcome: Option<Result<Outcome, i32>>,
    closed: bool,
}

pub(super) struct PickedJob {
    cancel: Cancellation,
    state: Mutex<State>,
}

fn get(handle: u64) -> Result<Arc<PickedJob>, i32> {
    registry()
        .lock()
        .map_err(|_| INTERNAL_ERROR)?
        .picked
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

fn normal_absolute(path: &std::path::Path) -> bool {
    let mut components = path.components();
    matches!(components.next(), Some(std::path::Component::RootDir))
        && components.all(|part| matches!(part, std::path::Component::Normal(_)))
}

fn prepare(
    handle: u64,
    root: PathBuf,
    paths: Vec<PathBuf>,
    config_dir: PathBuf,
    cancel: Cancellation,
) -> Result<Outcome, i32> {
    let config =
        clean_policy::resolve_config_path(Some(&config_dir)).map_err(|_| INVALID_ARGUMENT)?;
    let snapshot =
        clean_policy::snapshot_for_root(&config, &root).map_err(|_| INVALID_CANDIDATE)?;
    let mut protected = snapshot.effective_exclusions.clone();
    protected.push(config.directory.clone());
    let scope = Scope::new(root.clone(), protected).map_err(|_| INVALID_ARGUMENT)?;
    let session = TrashSession::prepare(scope, &paths, &snapshot.effective_exclusions, &cancel)
        .map_err(|_| INVALID_CANDIDATE)?;
    let plan = session.preview();
    let eligible = !cancel.is_cancelled()
        && snapshot.missing_attention_entries.is_empty()
        && session.issues().is_empty()
        && session.refusals().is_empty()
        && plan.items().len() == paths.len();
    let token = format!("trash {} picked files (preview {handle})", paths.len());
    let bytes = bounded_json(
        &json!({
            "schema_version": 1, "kind": "sayaka.picked_preview", "preview_handle": handle.to_string(),
            "contract": plan.execution_contract().as_str(), "warning": plan.execution_contract().warning(),
            "root": NativePath::from_path(&root), "effects_performed": false, "execution_eligible": eligible,
            "approval_token": token, "expires_unix_ms": plan.expires_at().duration_since(std::time::UNIX_EPOCH).map_err(|_| INTERNAL_ERROR)?.as_millis(),
            "selection_count": paths.len(), "requested_paths": paths.iter().map(|p| NativePath::from_path(p)).collect::<Vec<_>>(),
            "items": plan.items().iter().enumerate().map(|(index, item)| json!({
                "id": (index + 1).to_string(), "path": NativePath::from_path(item.observation().path()),
                "identity": item.observation().snapshot().identity, "logical_bytes": item.observation().snapshot().logical_bytes,
                "reason": "explicit_user_selection", "risk": "user_file_not_assumed_recreatable",
                "recovery": "platform_dependent_trash", "kind": "file"
            })).collect::<Vec<_>>(),
            "refusals": session.refusals(), "issues": session.issues(),
            "policy_needs_attention": !snapshot.missing_attention_entries.is_empty(),
            "residual_race_disclosed": true
        }),
        MAX_RESULT_BYTES,
    )?;
    Ok(Outcome::Preview(Preview {
        session,
        policy: Policy {
            config,
            root,
            snapshot,
        },
        token,
        bytes,
        eligible,
    }))
}

fn execute(mut preview: Preview, state_dir: PathBuf, cancel: Cancellation) -> Result<Outcome, i32> {
    let refusal = |message: String| -> Result<Outcome, i32> {
        bounded_json(
            &json!({"schema_version": 1, "kind": "sayaka.picked_execution", "state": "refused",
            "effects_performed": false, "error": message}),
            MAX_RESULT_BYTES,
        )
        .map(Outcome::Execution)
    };
    if cancel.is_cancelled()
        || !matches!(
            clean_policy::guard_snapshot(
                &preview.policy.config,
                &preview.policy.root,
                &preview.policy.snapshot
            ),
            Ok(PolicyGuardStatus::Unchanged)
        )
    {
        return refusal("Cancelled or protected-path policy changed; make a fresh preview".into());
    }
    if preview
        .session
        .preview()
        .items()
        .iter()
        .any(|item| sayaka_engine::scan::has_native_package_ancestor(item.observation().path()))
    {
        return refusal(
            "Selected file is inside a package or package status is unavailable".into(),
        );
    }
    let plan = preview.session.preview().clone();
    let approval = match preview.session.approve(&plan) {
        Ok(approval) => approval,
        Err(error) => return refusal(error.to_string()),
    };
    let store = match Store::open(&state_dir, true) {
        Ok(store) => store,
        Err(error) => return refusal(format!("Journal unavailable: {error}")),
    };
    #[cfg(target_os = "macos")]
    let report = preview.session.execute_with_exclusions(
        &plan,
        &approval,
        &cancel,
        &store,
        Some((
            &preview.policy.config,
            preview.policy.root.as_path(),
            &preview.policy.snapshot,
        )),
    );
    #[cfg(not(target_os = "macos"))]
    let report = preview.session.execute(&plan, &approval, &cancel, &store);
    let value = match report {
        Ok(report) => json!({"schema_version": 1, "kind": "sayaka.picked_execution",
            "state": if report.journal_error.is_some() { "unknown" } else { "finished" }, "report": report,
            "recovery": "Inspect each journal item. Use Finder Put Back when available; bytes moved are not measured freed space."}),
        Err(error) => {
            json!({"schema_version": 1, "kind": "sayaka.picked_execution", "state": "unknown",
            "error": error.to_string(), "recovery": "Inspect the operation journal and Trash before retrying; never retry automatically"})
        }
    };
    let bytes = bounded_json(&value, MAX_RESULT_BYTES).unwrap_or_else(|_| br#"{"schema_version":1,"kind":"sayaka.picked_execution","state":"unknown","recovery":"Inspect operation journal and Trash; result could not be serialized"}"#.to_vec());
    Ok(Outcome::Execution(bytes))
}

/// Starts a bounded asynchronous preview. All input bytes are copied.
/// # Safety
/// The request and nested arrays/paths must be readable and aligned; output is writable and disjoint.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_picked_preview_start_v1(
    request: *const SayakaPickedPreviewRequestV1,
    out_handle: *mut u64,
) -> i32 {
    boundary(|| {
        pointer(out_handle)?;
        unsafe { out_handle.write(0) };
        pointer(request)?;
        let request = unsafe { &*request };
        if request.abi_version != ABI_VERSION
            || request.struct_size as usize != size_of::<SayakaPickedPreviewRequestV1>()
            || request.reserved != 0
        {
            return Err(UNSUPPORTED_VERSION);
        }
        if !cfg!(target_os = "macos") {
            return Err(UNSUPPORTED_PLATFORM);
        }
        if request.path_count == 0 || request.path_count > journal::MAX_ITEMS {
            return Err(INVALID_ARGUMENT);
        }
        pointer(request.paths)?;
        let root = unsafe { decode_path(request.root)? };
        let config_dir = unsafe { decode_path(request.config_dir)? };
        let paths = unsafe { std::slice::from_raw_parts(request.paths, request.path_count) }
            .iter()
            .map(|path| unsafe { decode_path(*path) })
            .collect::<Result<Vec<_>, _>>()?;
        if !normal_absolute(&root)
            || root.parent().is_none()
            || !normal_absolute(&config_dir)
            || paths
                .iter()
                .any(|path| !normal_absolute(path) || path == &root || !path.starts_with(&root))
            || paths.iter().collect::<std::collections::HashSet<_>>().len() != paths.len()
        {
            return Err(INVALID_ARGUMENT);
        }
        // Package contents must use the dedicated uninstall/related-data contracts.
        if paths
            .iter()
            .any(|path| sayaka_engine::scan::has_native_package_ancestor(path))
        {
            return Err(INVALID_CANDIDATE);
        }
        let mut registry = registry().lock().map_err(|_| INTERNAL_ERROR)?;
        let handle = registry.allocate_handle()?;
        let cancel = Cancellation::default();
        let worker_cancel = cancel.clone();
        let worker = std::thread::Builder::new()
            .name("sayaka-picked-preview".into())
            .spawn(move || prepare(handle, root, paths, config_dir, worker_cancel))
            .map_err(|_| INTERNAL_ERROR)?;
        registry.picked.insert(
            handle,
            Arc::new(PickedJob {
                cancel,
                state: Mutex::new(State {
                    worker: Some(worker),
                    outcome: None,
                    closed: false,
                }),
            }),
        );
        unsafe { out_handle.write(handle) };
        Ok(())
    })
}

/// Copies preview or terminal execution JSON; NOT_READY while work is active.
/// # Safety
/// Caller-owned outputs follow the standard result buffer contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_picked_result_v1(
    handle: u64,
    buffer: *mut u8,
    capacity: usize,
    required: *mut usize,
) -> i32 {
    boundary(|| {
        unsafe { prepare_output(buffer, capacity, required, MAX_RESULT_BYTES)? };
        let job = get(handle)?;
        let mut state = lock_job(&job.state)?;
        collect(&mut state)?;
        let bytes = match state.outcome.as_ref().ok_or(INTERNAL_ERROR)? {
            Ok(Outcome::Preview(preview)) => &preview.bytes,
            Ok(Outcome::Execution(bytes)) => bytes,
            Err(code) => return Err(*code),
        };
        unsafe { copy_output(bytes, buffer, capacity, required) }
    })
}

/// Starts one-shot execution of exactly the retained preview, never an imported plan or subset.
/// # Safety
/// Token and state_dir must remain readable for the call; no input pointers are retained.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_picked_execute_v1(
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
        let directory = unsafe { decode_path(state_dir)? };
        journal::validate_state_directory_path(&directory).map_err(|_| INVALID_ARGUMENT)?;
        let job = get(handle)?;
        let mut state = lock_job(&job.state)?;
        collect(&mut state)?;
        match state.outcome.as_ref() {
            Some(Ok(Outcome::Preview(preview)))
                if preview.eligible
                    && !job.cancel.is_cancelled()
                    && preview.token.as_bytes() == token
                    && !preview
                        .session
                        .preview()
                        .items()
                        .iter()
                        .any(|item| item.observation().path().starts_with(&directory)) => {}
            _ => return Err(INVALID_CANDIDATE),
        }
        let Some(Ok(Outcome::Preview(preview))) = state.outcome.take() else {
            return Err(INTERNAL_ERROR);
        };
        let cancel = job.cancel.clone();
        match std::thread::Builder::new()
            .name("sayaka-picked-execute".into())
            .spawn(move || execute(preview, directory, cancel))
        {
            Ok(worker) => state.worker = Some(worker),
            Err(_) => {
                state.outcome = Some(Err(INTERNAL_ERROR));
                return Err(INTERNAL_ERROR);
            }
        }
        Ok(())
    })
}

/// Cancellation is monotonic; a cancelled preview cannot later execute.
#[unsafe(no_mangle)]
pub extern "C" fn sayaka_picked_cancel_v1(handle: u64) -> i32 {
    boundary(|| {
        get(handle)?.cancel.cancel();
        Ok(())
    })
}

/// Cancels active work; BUSY means keep the handle and retry release until joined.
#[unsafe(no_mangle)]
pub extern "C" fn sayaka_picked_release_v1(handle: u64) -> i32 {
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
            .picked
            .remove(&handle)
            .ok_or(INVALID_HANDLE)?;
        Ok(())
    })
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;

    fn native(path: &std::path::Path) -> SayakaPathV1 {
        let bytes = path.as_os_str().as_bytes();
        SayakaPathV1 {
            bytes: bytes.as_ptr(),
            byte_length: bytes.len(),
            encoding: UNIX_BYTES,
        }
    }

    #[test]
    fn traversal_and_relative_paths_are_rejected() {
        assert!(!normal_absolute(std::path::Path::new("relative/file")));
        assert!(!normal_absolute(std::path::Path::new(
            "/fixture/../other/file"
        )));
        assert!(normal_absolute(std::path::Path::new("/fixture/file")));
    }

    #[test]
    fn empty_or_oversized_selection_is_rejected_before_dereferencing_paths() {
        let root = PathBuf::from("/fixture");
        for count in [0, journal::MAX_ITEMS + 1] {
            let request = SayakaPickedPreviewRequestV1 {
                abi_version: ABI_VERSION,
                struct_size: size_of::<SayakaPickedPreviewRequestV1>() as u32,
                root: native(&root),
                paths: std::ptr::null(),
                path_count: count,
                config_dir: native(&root),
                reserved: 0,
            };
            let mut handle = 999;
            assert_eq!(
                unsafe { sayaka_picked_preview_start_v1(&request, &mut handle) },
                INVALID_ARGUMENT
            );
            assert_eq!(handle, 0);
        }
    }

    #[test]
    fn cross_root_and_duplicate_paths_are_rejected_without_effects() {
        let root = PathBuf::from("/fixture");
        let outside = PathBuf::from("/other/file");
        let inside = PathBuf::from("/fixture/file");
        for paths in [
            vec![native(&outside)],
            vec![native(&inside), native(&inside)],
        ] {
            let request = SayakaPickedPreviewRequestV1 {
                abi_version: ABI_VERSION,
                struct_size: size_of::<SayakaPickedPreviewRequestV1>() as u32,
                root: native(&root),
                paths: paths.as_ptr(),
                path_count: paths.len(),
                config_dir: native(&root),
                reserved: 0,
            };
            let mut handle = 0;
            assert_eq!(
                unsafe { sayaka_picked_preview_start_v1(&request, &mut handle) },
                INVALID_ARGUMENT
            );
            assert_eq!(handle, 0);
        }
    }

    #[test]
    fn regular_file_preview_retains_identity_size_risk_and_has_no_effects() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().canonicalize().unwrap();
        let target = root.join("selected.log");
        std::fs::write(&target, b"owned fixture").unwrap();
        let config = root.join("policy");
        let Outcome::Preview(preview) = prepare(
            91,
            root,
            vec![target.clone()],
            config,
            Cancellation::default(),
        )
        .unwrap() else {
            panic!("wrong result")
        };
        let value: serde_json::Value = serde_json::from_slice(&preview.bytes).unwrap();
        assert_eq!(value["effects_performed"], false);
        assert_eq!(value["items"][0]["logical_bytes"], 13);
        assert_eq!(
            value["items"][0]["risk"],
            "user_file_not_assumed_recreatable"
        );
        assert!(!value["items"][0]["identity"].is_null());
        assert_eq!(std::fs::read(target).unwrap(), b"owned fixture");
    }
}
