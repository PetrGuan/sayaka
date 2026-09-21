// SPDX-License-Identifier: MPL-2.0

use super::*;
use serde_json::Value;
use std::ptr;

fn request(offset: u64, limit: u32) -> SayakaIssuePageRequestV1 {
    SayakaIssuePageRequestV1 {
        abi_version: ABI_VERSION,
        struct_size: size_of::<SayakaIssuePageRequestV1>() as u32,
        offset,
        limit,
        reserved: 0,
    }
}

#[test]
fn diagnostic_request_layout_and_error_outputs_are_explicit() {
    assert_eq!(size_of::<SayakaIssuePageRequestV1>(), 24);
    assert_eq!(std::mem::offset_of!(SayakaIssuePageRequestV1, offset), 8);
    assert_eq!(std::mem::offset_of!(SayakaIssuePageRequestV1, reserved), 20);
    for limit in [0, MAX_PAGE_ISSUES + 1] {
        assert_eq!(request(0, limit).validate(), Err(INVALID_ARGUMENT));
    }
    let mut invalid = request(0, 1);
    invalid.reserved = 1;
    assert_eq!(invalid.validate(), Err(INVALID_ARGUMENT));
    invalid = request(0, 1);
    invalid.abi_version += 1;
    assert_eq!(invalid.validate(), Err(UNSUPPORTED_VERSION));
    invalid = request(0, 1);
    invalid.struct_size -= 1;
    assert_eq!(invalid.validate(), Err(UNSUPPORTED_VERSION));
    let valid = request(0, 1);
    let mut required = 99;
    let mut guard = [0x42; 3];
    unsafe {
        assert_eq!(
            sayaka_scan_issues_v1(0, &valid, ptr::null_mut(), 0, &mut required),
            INVALID_HANDLE
        );
        assert_eq!(required, 0);
        required = 99;
        assert_eq!(
            sayaka_scan_issues_v1(0, ptr::null(), guard[1..].as_mut_ptr(), 1, &mut required),
            INVALID_ARGUMENT
        );
        assert_eq!(guard, [0x42; 3]);
        assert_eq!(required, 0);
        assert_eq!(
            sayaka_scan_issues_v1(0, &valid, ptr::null_mut(), 0, ptr::null_mut()),
            INVALID_ARGUMENT
        );
        assert_eq!(
            sayaka_scan_issues_v1(0, &valid, ptr::null_mut(), 1, &mut required),
            INVALID_ARGUMENT
        );
        assert_eq!(
            sayaka_scan_issues_v1(
                0,
                &valid,
                ptr::null_mut(),
                MAX_QUERY_BYTES + 1,
                &mut required
            ),
            INVALID_ARGUMENT
        );
        assert_eq!(required, 0);
    }
}

#[test]
fn fatal_diagnostic_pages_keep_null_task_and_shared_issue_shape() {
    let error = ScanError {
        code: ScanCode::PermissionDenied,
        message: "owned fixture denied".into(),
        os_code: Some(13),
    };
    let mut full = Vec::new();
    wire::fatal(&mut full, &error).unwrap();
    let full: Value = serde_json::from_slice(&full).unwrap();
    let outcome = Err(error);
    let bytes = page(Some(&outcome), u64::MAX, 0, 1).unwrap();
    assert!(!bytes.ends_with(b"\n"));
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["task_handle"], u64::MAX.to_string());
    assert_eq!(value["scan_task_id"], Value::Null);
    assert_eq!(value["scan_status"], "failed");
    assert_eq!(value["scan_complete"], false);
    assert_eq!(value["observed_issues"], 1);
    assert_eq!(value["issues_omitted"], 0);
    assert_eq!(value["data"]["issues"], full["issues"]);
    assert_eq!(value["data"]["next_offset"], Value::Null);
    let end: Value = serde_json::from_slice(&page(Some(&outcome), 1, 1, 1).unwrap()).unwrap();
    assert_eq!(end["data"]["offset"], 1);
    assert_eq!(end["data"]["total"], 1);
    assert_eq!(end["data"]["issues"], serde_json::json!([]));
    assert_eq!(page(Some(&outcome), 1, 2, 1), Err(INVALID_ARGUMENT));
    assert_eq!(page(None, 1, 0, 1), Err(NOT_READY));
}

#[test]
fn diagnostic_payload_limit_accepts_exact_bound_and_refuses_one_more_byte() {
    let empty = Err(ScanError::new(ScanCode::Internal, ""));
    let overhead = page(Some(&empty), 1, 0, 1).unwrap().len();
    let at_limit = Err(ScanError::new(
        ScanCode::Internal,
        "x".repeat(MAX_QUERY_BYTES - overhead),
    ));
    assert_eq!(
        page(Some(&at_limit), 1, 0, 1).unwrap().len(),
        MAX_QUERY_BYTES
    );
    let too_large = Err(ScanError::new(
        ScanCode::Internal,
        "x".repeat(MAX_QUERY_BYTES - overhead + 1),
    ));
    assert_eq!(page(Some(&too_large), 1, 0, 1), Err(LIMIT_EXCEEDED));
}

#[cfg(target_os = "macos")]
mod native {
    use super::*;
    use sayaka_engine::scan::{ScanIssue, ScanStatus};
    use std::time::{Duration, Instant};

    struct OwnedTask(u64);

    impl OwnedTask {
        fn start(path: &std::path::Path) -> Self {
            let task = ScanTask::start(vec![path.to_path_buf()], ScanLimits::default()).unwrap();
            let mut registry = registry().lock().unwrap();
            let handle = registry.allocate_handle().unwrap();
            registry.jobs.insert(
                handle,
                Arc::new(Mutex::new(Job {
                    task,
                    result: None,
                    tree: None,
                    closed: false,
                })),
            );
            Self(handle)
        }

        fn finish(&self) -> u32 {
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                let mut snapshot = SayakaScanSnapshotV1::default();
                assert_eq!(unsafe { sayaka_scan_poll_v1(self.0, &mut snapshot) }, OK);
                if snapshot.state != 1 {
                    return snapshot.state;
                }
                assert!(Instant::now() < deadline, "owned diagnostic scan deadline");
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }

    impl Drop for OwnedTask {
        fn drop(&mut self) {
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                match sayaka_scan_release_v1(self.0) {
                    OK => return,
                    BUSY if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(1))
                    }
                    code => panic!("owned diagnostic task release failed: {code}"),
                }
            }
        }
    }

    fn query(handle: u64, offset: u64, limit: u32) -> Value {
        let request = request(offset, limit);
        let mut required = 0;
        unsafe {
            assert_eq!(
                sayaka_scan_issues_v1(handle, &request, ptr::null_mut(), 0, &mut required),
                BUFFER_TOO_SMALL
            );
            assert!((1..=MAX_QUERY_BYTES).contains(&required));
            let length = required;
            let mut guard = [0x42; 3];
            assert_eq!(
                sayaka_scan_issues_v1(handle, &request, guard[1..].as_mut_ptr(), 1, &mut required),
                BUFFER_TOO_SMALL
            );
            assert_eq!(guard, [0x42; 3]);
            assert_eq!(required, length);
            let mut bytes = vec![0; length];
            assert_eq!(
                sayaka_scan_issues_v1(
                    handle,
                    &request,
                    bytes.as_mut_ptr(),
                    bytes.len(),
                    &mut required
                ),
                OK
            );
            assert_eq!(required, length);
            assert!(!bytes.ends_with(b"\n") && !bytes.ends_with(&[0]));
            serde_json::from_slice(&bytes).unwrap()
        }
    }

    #[test]
    fn owned_diagnostics_page_without_tree_or_full_result_and_preserve_lifecycle() {
        let _serial = NATIVE_TEST_LOCK.lock().unwrap();
        let fixture = tempfile::Builder::new()
            .prefix("diagnostics-owned-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .unwrap();
        std::fs::write(fixture.path().join("payload"), b"owned diagnostics").unwrap();
        for index in 0..140 {
            std::os::unix::fs::symlink("payload", fixture.path().join(format!("link-{index:03}")))
                .unwrap();
        }
        let task = OwnedTask::start(fixture.path());
        assert_eq!(task.finish(), 2);
        let report = {
            let slot = get(task.0).unwrap();
            let mut job = slot.lock().unwrap();
            assert!(job.result.is_none() && job.tree.is_none());
            job.task.result().unwrap().as_ref().unwrap().clone()
        };
        assert_eq!(report.issues.len(), 128);
        assert_eq!(report.issues_omitted, 12);
        let mut full = Vec::new();
        wire::report(&mut full, &report).unwrap();
        let full: Value = serde_json::from_slice(&full).unwrap();
        let mut observed = Vec::new();
        let mut offset = 0;
        loop {
            let value = query(task.0, offset, 17);
            assert_eq!(value["schema_version"], 1);
            assert_eq!(value["task_handle"], task.0.to_string());
            assert_eq!(value["scan_task_id"], full["task_id"]);
            assert_eq!(value["scan_status"], "complete");
            assert_eq!(value["scan_complete"], true);
            assert_eq!(value["observed_issues"], 128);
            assert_eq!(value["issues_omitted"], 12);
            assert_eq!(value["data"]["offset"], offset);
            assert_eq!(value["data"]["total"], 128);
            assert!(value.get("entries").is_none());
            observed.extend(value["data"]["issues"].as_array().unwrap().iter().cloned());
            if let Some(next) = value["data"]["next_offset"].as_u64() {
                assert!(next > offset);
                offset = next;
            } else {
                break;
            }
        }
        assert_eq!(Value::Array(observed), full["issues"]);
        let end = query(task.0, 128, 17);
        assert_eq!(end["data"]["issues"], serde_json::json!([]));
        let mut required = 99;
        let mut guard = [0x42; 3];
        for offset in [129, u64::MAX] {
            assert_eq!(
                unsafe {
                    sayaka_scan_issues_v1(
                        task.0,
                        &request(offset, 1),
                        guard[1..].as_mut_ptr(),
                        1,
                        &mut required,
                    )
                },
                INVALID_ARGUMENT
            );
            assert_eq!(required, 0);
            assert_eq!(guard, [0x42; 3]);
        }
        {
            let slot = get(task.0).unwrap();
            let mut job = slot.lock().unwrap();
            assert!(job.result.is_none() && job.tree.is_none());
            job.result = Some(Err(LIMIT_EXCEEDED));
            assert_eq!(
                unsafe {
                    sayaka_scan_issues_v1(task.0, &request(0, 1), ptr::null_mut(), 0, &mut required)
                },
                BUSY
            );
            assert_eq!(required, 0);
        }
        assert_eq!(query(task.0, 0, 1)["data"]["issues"][0], full["issues"][0]);
        {
            let slot = get(task.0).unwrap();
            let job = slot.lock().unwrap();
            assert!(matches!(job.result, Some(Err(LIMIT_EXCEEDED))));
            assert!(job.tree.is_none());
        }
        assert_eq!(
            unsafe { sayaka_scan_result_v1(task.0, ptr::null_mut(), 0, &mut required) },
            LIMIT_EXCEEDED
        );
        assert_eq!(required, 0);
        synthetic_contracts(report);
        let stale = task.0;
        drop(task);
        assert_eq!(
            unsafe {
                sayaka_scan_issues_v1(stale, &request(0, 1), ptr::null_mut(), 0, &mut required)
            },
            INVALID_HANDLE
        );
        assert_eq!(required, 0);

        let missing = OwnedTask::start(&fixture.path().join("missing"));
        assert_eq!(missing.finish(), 5);
        let failed = query(missing.0, 0, 1);
        assert_eq!(failed["scan_status"], "failed");
        assert_eq!(failed["scan_complete"], false);
        assert!(!failed["data"]["issues"].as_array().unwrap().is_empty());
        drop(missing);
        let empty = fixture.path().join("empty");
        std::fs::create_dir(&empty).unwrap();
        let empty = OwnedTask::start(&empty);
        assert_eq!(empty.finish(), 2);
        let value = query(empty.0, 0, 1);
        assert_eq!(value["data"]["total"], 0);
        assert_eq!(value["data"]["issues"], serde_json::json!([]));
        assert_eq!(value["data"]["next_offset"], Value::Null);
        drop(empty);
        assert_eq!(
            std::fs::read(fixture.path().join("payload")).unwrap(),
            b"owned diagnostics"
        );
    }

    fn synthetic_contracts(mut report: ScanReport) {
        for status in [
            ScanStatus::Complete,
            ScanStatus::Partial,
            ScanStatus::Cancelled,
            ScanStatus::Failed,
        ] {
            report.status = status;
            report.complete = status == ScanStatus::Complete;
            let outcome = Ok(report.clone());
            let value: Value =
                serde_json::from_slice(&page(Some(&outcome), 1, 0, 1).unwrap()).unwrap();
            assert_eq!(value["scan_status"], status.as_str());
            assert_eq!(value["scan_complete"], report.complete);
            assert_eq!(value["issues_omitted"], 12);
        }
        report.issues = (0..128)
            .map(|_| ScanIssue {
                path: None,
                code: ScanCode::Io,
                message: "x".repeat(16_384),
                os_code: Some(5),
            })
            .collect();
        let outcome = Ok(report);
        assert_eq!(page(Some(&outcome), 1, 0, 128), Err(LIMIT_EXCEEDED));
        let small: Value = serde_json::from_slice(&page(Some(&outcome), 1, 0, 1).unwrap()).unwrap();
        assert_eq!(small["data"]["total"], 128);
        assert_eq!(small["data"]["next_offset"], 1);
        assert_eq!(small["data"]["issues"].as_array().unwrap().len(), 1);
    }
}
