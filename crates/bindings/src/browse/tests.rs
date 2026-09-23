// SPDX-License-Identifier: MPL-2.0

use super::*;
use serde_json::Value;
use std::ptr;

fn request(offset: u64, limit: u32, sort: u32) -> SayakaPageRequestV1 {
    SayakaPageRequestV1 {
        abi_version: ABI_VERSION,
        struct_size: size_of::<SayakaPageRequestV1>() as u32,
        offset,
        limit,
        sort,
    }
}

#[test]
fn query_layout_arguments_and_error_outputs_are_explicit() {
    assert_eq!(size_of::<SayakaNodeRefV1>(), 16);
    assert_eq!(size_of::<SayakaPageRequestV1>(), 24);
    assert_eq!(std::mem::offset_of!(SayakaPageRequestV1, offset), 8);
    assert_eq!(std::mem::offset_of!(SayakaPageRequestV1, sort), 20);
    for invalid in [request(0, 0, 1), request(0, 257, 1), request(0, 1, 0)] {
        assert_eq!(invalid.validate(), Err(INVALID_ARGUMENT));
    }
    let mut wrong = request(0, 1, 1);
    wrong.abi_version = 2;
    assert_eq!(wrong.validate(), Err(UNSUPPORTED_VERSION));
    wrong = request(0, 1, 1);
    wrong.struct_size -= 1;
    assert_eq!(wrong.validate(), Err(UNSUPPORTED_VERSION));
    let valid = request(0, 1, 1);
    let mut required = 99;
    let reference = SayakaNodeRefV1 {
        task_handle: 0,
        node_id: 1,
    };
    unsafe {
        assert_eq!(
            sayaka_scan_roots_v1(0, &valid, ptr::null_mut(), 0, &mut required),
            INVALID_HANDLE
        );
        assert_eq!(
            sayaka_scan_largest_files_v1(0, &valid, ptr::null_mut(), 0, &mut required),
            INVALID_ARGUMENT
        );
        assert_eq!(required, 0);
        required = 99;
        assert_eq!(
            sayaka_scan_roots_v1(0, ptr::null(), ptr::null_mut(), 0, &mut required),
            INVALID_ARGUMENT
        );
        assert_eq!(required, 0);
        assert_eq!(
            sayaka_scan_roots_v1(0, &valid, ptr::null_mut(), 0, ptr::null_mut()),
            INVALID_ARGUMENT
        );
        assert_eq!(
            sayaka_scan_roots_v1(0, &valid, ptr::null_mut(), 1, &mut required),
            INVALID_ARGUMENT
        );
        assert_eq!(
            sayaka_scan_node_v1(
                0,
                &reference,
                ptr::null_mut(),
                MAX_QUERY_BYTES + 1,
                &mut required
            ),
            INVALID_ARGUMENT
        );
        assert_eq!(
            sayaka_scan_node_v1(1, &reference, ptr::null_mut(), 0, &mut required),
            INVALID_NODE
        );
        assert_eq!(
            sayaka_scan_node_v1(0, ptr::null(), ptr::null_mut(), 0, &mut required),
            INVALID_ARGUMENT
        );
        assert_eq!(
            sayaka_scan_node_evidence_v1(
                0,
                &reference,
                ptr::null_mut(),
                MAX_QUERY_BYTES + 1,
                &mut required
            ),
            INVALID_ARGUMENT
        );
        assert_eq!(
            sayaka_scan_node_evidence_v1(1, &reference, ptr::null_mut(), 0, &mut required),
            INVALID_NODE
        );
        assert_eq!(
            sayaka_scan_node_evidence_v1(0, ptr::null(), ptr::null_mut(), 0, &mut required),
            INVALID_ARGUMENT
        );
        assert_eq!(
            sayaka_scan_children_v1(0, &reference, &valid, ptr::null_mut(), 0, &mut required),
            INVALID_HANDLE
        );
        assert_eq!(
            sayaka_scan_largest_files_v1(
                0,
                &request(0, 1, SORT_LOGICAL_SIZE),
                ptr::null_mut(),
                0,
                &mut required
            ),
            INVALID_HANDLE
        );
    }
}

fn query(mut call: impl FnMut(*mut u8, usize, *mut usize) -> i32) -> Value {
    let mut required = 0;
    assert_eq!(call(ptr::null_mut(), 0, &mut required), BUFFER_TOO_SMALL);
    assert!((1..=MAX_QUERY_BYTES).contains(&required));
    let length = required;
    let mut guard = [0x42; 3];
    assert_eq!(
        call(guard[1..].as_mut_ptr(), 1, &mut required),
        BUFFER_TOO_SMALL
    );
    assert_eq!(guard, [0x42; 3]);
    assert_eq!(required, length);
    let mut bytes = vec![0; length];
    assert_eq!(call(bytes.as_mut_ptr(), bytes.len(), &mut required), OK);
    assert_eq!(required, length);
    assert_ne!(bytes.last(), Some(&0));
    serde_json::from_slice(&bytes).unwrap()
}

#[cfg(any(target_os = "macos", windows))]
mod native {
    use super::*;
    use std::time::{Duration, Instant};

    struct Task(u64);
    impl Task {
        fn start(path: &std::path::Path) -> Self {
            #[cfg(unix)]
            let (bytes, encoding) = {
                use std::os::unix::ffi::OsStrExt;
                (path.as_os_str().as_bytes().to_vec(), UNIX_BYTES)
            };
            #[cfg(windows)]
            let (bytes, encoding) = {
                use std::os::windows::ffi::OsStrExt;
                (
                    path.as_os_str()
                        .encode_wide()
                        .flat_map(u16::to_le_bytes)
                        .collect::<Vec<_>>(),
                    WINDOWS_UTF16LE,
                )
            };
            let root = SayakaPathV1 {
                encoding,
                bytes: bytes.as_ptr(),
                byte_length: bytes.len(),
            };
            let request = SayakaScanRequestV1 {
                abi_version: ABI_VERSION,
                struct_size: size_of::<SayakaScanRequestV1>() as u32,
                roots: &root,
                root_count: 1,
            };
            let mut handle = 0;
            assert_eq!(unsafe { sayaka_scan_start_v1(&request, &mut handle) }, OK);
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
                assert!(Instant::now() < deadline, "owned scan deadline");
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
    impl Drop for Task {
        fn drop(&mut self) {
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                match sayaka_scan_release_v1(self.0) {
                    OK => return,
                    BUSY if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(1))
                    }
                    code => panic!("owned task release failed: {code}"),
                }
            }
        }
    }

    fn node_ref(node: &Value) -> SayakaNodeRefV1 {
        SayakaNodeRefV1 {
            task_handle: node["reference"]["task_handle"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
            node_id: node["reference"]["node_id"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
        }
    }

    #[test]
    fn owned_native_queries_page_sort_account_refresh_and_preserve_results() {
        let _serial = NATIVE_TEST_LOCK.lock().unwrap();
        let fixture = tempfile::Builder::new()
            .prefix("query-owned-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .unwrap();
        let root = fixture.path();
        for directory in ["a", "b", "empty"] {
            std::fs::create_dir(root.join(directory)).unwrap();
        }
        std::fs::write(root.join("a/shared"), [7; 11]).unwrap();
        std::fs::hard_link(root.join("a/shared"), root.join("b/shared")).unwrap();
        std::fs::write(root.join("b/own"), [1; 5]).unwrap();
        let first = Task::start(root);
        assert_eq!(first.finish(), 2);
        let original = query(|b, c, r| unsafe { sayaka_scan_result_v1(first.0, b, c, r) });
        assert!(get(first.0).unwrap().lock().unwrap().tree.is_none());
        let roots = query(|b, c, r| unsafe {
            sayaka_scan_roots_v1(first.0, &request(0, 1, SORT_NAME), b, c, r)
        });
        assert_eq!(roots["schema_version"], 1);
        assert_eq!(roots["scan_status"], "complete");
        assert_eq!(roots["scan_task_id"], original["task_id"]);
        assert_eq!(roots["data"]["total"], 1);
        let root_node = &roots["data"]["nodes"][0];
        let root_ref = node_ref(root_node);
        assert_eq!(root_node["logical_bytes"], 16);
        assert_eq!(root_node["directory_summary"]["unique_files"], 2);
        assert_eq!(root_node["parent"], Value::Null);
        assert_eq!(root_node["child_count"], 3);
        let sorted = query(|b, c, r| unsafe {
            sayaka_scan_children_v1(
                first.0,
                &root_ref,
                &request(0, 2, SORT_LOGICAL_SIZE),
                b,
                c,
                r,
            )
        });
        assert_eq!(sorted["data"]["total"], 3);
        assert_eq!(sorted["data"]["next_offset"], 2);
        assert_eq!(sorted["data"]["nodes"][0]["logical_bytes"], 16);
        assert_eq!(sorted["data"]["nodes"][1]["logical_bytes"], 11);
        assert_eq!(sorted["data"]["nodes"][0]["parent"], root_node["reference"]);
        let largest = query(|b, c, r| unsafe {
            sayaka_scan_largest_files_v1(first.0, &request(0, 1, SORT_LOGICAL_SIZE), b, c, r)
        });
        assert_eq!(largest["data"]["total"], 2);
        assert_eq!(largest["data"]["next_offset"], 1);
        assert_eq!(largest["data"]["unmeasured"], 0);
        assert_eq!(largest["data"]["nodes"][0]["kind"], "file");
        assert_eq!(largest["data"]["nodes"][0]["logical_bytes"], 11);
        let largest_last = query(|b, c, r| unsafe {
            sayaka_scan_largest_files_v1(first.0, &request(1, 1, SORT_LOGICAL_SIZE), b, c, r)
        });
        assert_eq!(largest_last["data"]["nodes"][0]["logical_bytes"], 5);
        assert_eq!(largest_last["data"]["next_offset"], Value::Null);
        let mut required = 99;
        assert_eq!(
            unsafe {
                sayaka_scan_largest_files_v1(
                    first.0,
                    &request(0, 1, SORT_NAME),
                    ptr::null_mut(),
                    0,
                    &mut required,
                )
            },
            INVALID_ARGUMENT
        );
        let last = query(|b, c, r| unsafe {
            sayaka_scan_children_v1(
                first.0,
                &root_ref,
                &request(2, 2, SORT_LOGICAL_SIZE),
                b,
                c,
                r,
            )
        });
        assert_eq!(last["data"]["nodes"].as_array().unwrap().len(), 1);
        assert_eq!(last["data"]["nodes"][0]["logical_bytes"], 0);
        assert_eq!(last["data"]["next_offset"], Value::Null);
        let empty_ref = node_ref(&last["data"]["nodes"][0]);
        let empty = query(|b, c, r| unsafe {
            sayaka_scan_children_v1(first.0, &empty_ref, &request(0, 256, SORT_NAME), b, c, r)
        });
        assert_eq!(empty["data"]["total"], 0);
        assert_eq!(empty["data"]["nodes"], serde_json::json!([]));
        let detail = query(|b, c, r| unsafe { sayaka_scan_node_v1(first.0, &root_ref, b, c, r) });
        assert_eq!(detail["data"], *root_node);
        let root_evidence =
            query(|b, c, r| unsafe { sayaka_scan_node_evidence_v1(first.0, &root_ref, b, c, r) });
        assert_eq!(root_evidence["data"]["node"], *root_node);
        assert_eq!(root_evidence["data"]["observed_alias_count"], 0);
        assert_eq!(root_evidence["data"]["aliases"], serde_json::json!([]));
        let end = query(|b, c, r| unsafe {
            sayaka_scan_children_v1(first.0, &root_ref, &request(3, 1, SORT_NAME), b, c, r)
        });
        assert_eq!(end["data"]["nodes"], serde_json::json!([]));
        required = 99;
        assert_eq!(
            unsafe {
                sayaka_scan_children_v1(
                    first.0,
                    &root_ref,
                    &request(u64::MAX, 1, SORT_NAME),
                    ptr::null_mut(),
                    0,
                    &mut required,
                )
            },
            INVALID_ARGUMENT
        );
        assert_eq!(required, 0);
        let a_ref = node_ref(&sorted["data"]["nodes"][1]);
        let children = query(|b, c, r| unsafe {
            sayaka_scan_children_v1(first.0, &a_ref, &request(0, 1, SORT_NAME), b, c, r)
        });
        let file_ref = node_ref(&children["data"]["nodes"][0]);
        let file_evidence =
            query(|b, c, r| unsafe { sayaka_scan_node_evidence_v1(first.0, &file_ref, b, c, r) });
        assert_eq!(file_evidence["data"]["observed_alias_count"], 2);
        assert_eq!(
            file_evidence["data"]["aliases"].as_array().unwrap().len(),
            2
        );
        assert!(
            file_evidence["data"]["aliases"][0]["path"]["raw"]
                .as_str()
                .unwrap()
                < file_evidence["data"]["aliases"][1]["path"]["raw"]
                    .as_str()
                    .unwrap()
        );
        assert_eq!(
            unsafe {
                sayaka_scan_children_v1(
                    first.0,
                    &file_ref,
                    &request(0, 1, SORT_NAME),
                    ptr::null_mut(),
                    0,
                    &mut required,
                )
            },
            NOT_DIRECTORY
        );
        let missing = SayakaNodeRefV1 {
            node_id: u64::MAX,
            ..root_ref
        };
        assert_eq!(
            unsafe { sayaka_scan_node_v1(first.0, &missing, ptr::null_mut(), 0, &mut required) },
            INVALID_NODE
        );
        assert_eq!(
            unsafe {
                sayaka_scan_node_evidence_v1(first.0, &missing, ptr::null_mut(), 0, &mut required)
            },
            INVALID_NODE
        );
        // Queries are cached observations, not filesystem re-enumeration.
        std::fs::write(root.join("new"), [9; 20]).unwrap();
        assert_eq!(
            query(|b, c, r| unsafe { sayaka_scan_node_v1(first.0, &root_ref, b, c, r) }),
            detail
        );
        assert_eq!(
            query(|b, c, r| unsafe { sayaka_scan_result_v1(first.0, b, c, r) }),
            original
        );
        let refreshed = Task::start(root);
        assert_ne!(first.0, refreshed.0);
        assert_eq!(refreshed.finish(), 2);
        assert_eq!(
            unsafe {
                sayaka_scan_node_v1(refreshed.0, &root_ref, ptr::null_mut(), 0, &mut required)
            },
            INVALID_NODE
        );
        assert_eq!(
            unsafe {
                sayaka_scan_node_evidence_v1(
                    refreshed.0,
                    &root_ref,
                    ptr::null_mut(),
                    0,
                    &mut required,
                )
            },
            INVALID_NODE
        );
        assert_eq!(
            unsafe {
                sayaka_scan_children_v1(
                    refreshed.0,
                    &root_ref,
                    &request(0, 1, SORT_NAME),
                    ptr::null_mut(),
                    0,
                    &mut required,
                )
            },
            INVALID_NODE
        );
        let new_roots = query(|b, c, r| unsafe {
            sayaka_scan_roots_v1(refreshed.0, &request(0, 1, SORT_NAME), b, c, r)
        });
        assert_eq!(new_roots["data"]["nodes"][0]["logical_bytes"], 36);
        {
            let slot = get(refreshed.0).unwrap();
            let mut job = slot.lock().unwrap();
            synthetic_query_contracts(job.task.result().unwrap().as_ref().unwrap().clone());
        }
        {
            let slot = get(first.0).unwrap();
            let _locked = slot.lock().unwrap();
            assert_eq!(
                unsafe {
                    sayaka_scan_node_v1(first.0, &root_ref, ptr::null_mut(), 0, &mut required)
                },
                BUSY
            );
            assert_eq!(required, 0);
        }
        let stale_handle = first.0;
        drop(first);
        assert_eq!(
            unsafe {
                sayaka_scan_node_v1(stale_handle, &root_ref, ptr::null_mut(), 0, &mut required)
            },
            INVALID_HANDLE
        );
        assert_eq!(
            unsafe {
                sayaka_scan_roots_v1(
                    stale_handle,
                    &request(0, 1, SORT_NAME),
                    ptr::null_mut(),
                    0,
                    &mut required,
                )
            },
            INVALID_HANDLE
        );
        assert_eq!(
            unsafe {
                sayaka_scan_largest_files_v1(
                    stale_handle,
                    &request(0, 1, SORT_LOGICAL_SIZE),
                    ptr::null_mut(),
                    0,
                    &mut required,
                )
            },
            INVALID_HANDLE
        );
        drop(refreshed);
        let failed = Task::start(&root.join("missing"));
        assert_eq!(failed.finish(), 5);
        assert_eq!(
            unsafe {
                sayaka_scan_roots_v1(
                    failed.0,
                    &request(0, 1, SORT_NAME),
                    ptr::null_mut(),
                    0,
                    &mut required,
                )
            },
            QUERY_UNAVAILABLE
        );
        assert_eq!(
            unsafe {
                sayaka_scan_largest_files_v1(
                    failed.0,
                    &request(0, 1, SORT_LOGICAL_SIZE),
                    ptr::null_mut(),
                    0,
                    &mut required,
                )
            },
            QUERY_UNAVAILABLE
        );
        assert_eq!(required, 0);
        assert_eq!(
            query(|b, c, r| unsafe { sayaka_scan_result_v1(failed.0, b, c, r) })["status"],
            "failed"
        );
    }

    fn synthetic_query_contracts(mut report: sayaka_engine::scan::ScanReport) {
        report.entries.retain(|entry| entry.path == report.roots[0]);
        let root = report.entries[0].clone();
        let root_id = root.id;
        for (status, complete, expected) in [
            (ScanStatus::Complete, true, serde_json::json!(0)),
            (ScanStatus::Partial, false, Value::Null),
            (ScanStatus::Cancelled, false, Value::Null),
        ] {
            report.status = status;
            report.complete = complete;
            let tree = ScanTree::build(report.clone(), &Cancellation::default()).unwrap();
            let payload: Value =
                serde_json::from_slice(&page(&tree, u64::MAX, &[root_id], 0, 1).unwrap()).unwrap();
            assert_eq!(payload["task_handle"], u64::MAX.to_string());
            assert_eq!(payload["scan_status"], status.as_str());
            assert_eq!(payload["scan_complete"], complete);
            assert_eq!(payload["data"]["nodes"][0]["logical_bytes"], expected);
            assert_eq!(
                payload["data"]["nodes"][0]["directory_summary"]["complete"],
                complete
            );
        }
        report.status = ScanStatus::Complete;
        report.complete = true;
        for (id, logical) in [(root_id + 1, Some(11)), (root_id + 2, None)] {
            report.entries.push(ScanEntry {
                id,
                path: root.path.join(format!("alias-{id}")),
                kind: ResourceKind::File,
                logical_bytes: logical,
                allocated_bytes: Some(4096),
                // Same identity, different observations: unknown logical total.
                ..root.clone()
            });
        }
        let tree = ScanTree::build(report.clone(), &Cancellation::default()).unwrap();
        let payload: Value = serde_json::from_slice(
            &serialize(&tree, 1, node(&tree, 1, tree.entry(root_id).unwrap())).unwrap(),
        )
        .unwrap();
        let detail = &payload["data"];
        assert_eq!(detail["logical_bytes"], Value::Null);
        assert_eq!(detail["allocated_bytes"], 4096);
        assert_eq!(detail["directory_summary"]["logical_bytes_known"], 0);
        assert_eq!(
            detail["directory_summary"]["logical_bytes_unknown_files"],
            1
        );
        assert_eq!(detail["directory_summary"]["unique_files"], 1);
        assert_eq!(detail["directory_summary"]["complete"], true);
        report.entries.truncate(1);
        for (name, id, logical, allocated) in [
            ("b-tie", root_id + 1, Some(10), Some(100)),
            ("a-tie", root_id + 2, Some(10), Some(50)),
            ("unknown", root_id + 3, None, Some(200)),
            ("alias", root_id + 4, Some(99), Some(99)),
        ] {
            report.entries.push(ScanEntry {
                id,
                path: root.path.join(name),
                kind: ResourceKind::File,
                logical_bytes: logical,
                allocated_bytes: allocated,
                counted: name != "alias",
                depth: root.depth + 1,
                ..root.clone()
            });
        }
        let tree = ScanTree::build(report.clone(), &Cancellation::default()).unwrap();
        let order = build_largest_files_order(&tree, Metric::Logical);
        assert_eq!(order.ids.len(), 2);
        assert_eq!(order.unmeasured, 1);
        assert!(tree.entry(order.ids[0]).unwrap().path.ends_with("a-tie"));
        assert!(tree.entry(order.ids[1]).unwrap().path.ends_with("b-tie"));
        let nodes = order
            .ids
            .iter()
            .map(|id| node(&tree, 1, tree.entry(*id).unwrap()))
            .collect();
        let payload: Value = serde_json::from_slice(
            &serialize(
                &tree,
                1,
                LargestFilesPage {
                    offset: 0,
                    total: order.ids.len(),
                    next_offset: None,
                    unmeasured: order.unmeasured,
                    nodes,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(payload["data"]["unmeasured"], 1);
        assert_eq!(payload["data"]["total"], 2);

        report.entries.truncate(1);
        for index in 1..=MAX_PAGE_NODES {
            report.entries.push(ScanEntry {
                id: root_id + u64::from(index),
                path: root.path.join(format!("{}-{index}", "x".repeat(2048))),
                kind: ResourceKind::File,
                logical_bytes: Some(1),
                allocated_bytes: Some(1),
                ..root.clone()
            });
        }
        let tree = ScanTree::build(report, &Cancellation::default()).unwrap();
        let ids = tree.children(root_id).unwrap();
        assert_eq!(ids.len(), MAX_PAGE_NODES as usize);
        assert_eq!(page(&tree, 1, ids, 0, MAX_PAGE_NODES), Err(LIMIT_EXCEEDED));
        let small: Value = serde_json::from_slice(&page(&tree, 1, ids, 0, 1).unwrap()).unwrap();
        assert_eq!(small["data"]["total"], MAX_PAGE_NODES);
        assert_eq!(small["data"]["nodes"].as_array().unwrap().len(), 1);
        assert_eq!(small["data"]["next_offset"], 1);

        let mut report = tree.report().clone();
        report.entries.truncate(1);
        let root = report.entries[0].clone();
        let selected_id = root_id + 1;
        for index in (0..20).rev() {
            report.entries.push(ScanEntry {
                id: root_id + 1 + index,
                path: root.path.join(format!("{index:02}-alias")),
                kind: ResourceKind::File,
                logical_bytes: Some(1),
                allocated_bytes: Some(1),
                counted: index == 0,
                depth: root.depth + 1,
                ..root.clone()
            });
        }
        let selected_path = report
            .entries
            .iter()
            .find(|entry| entry.id == selected_id)
            .unwrap()
            .path
            .clone();
        for index in 0..10 {
            report.issues.push(sayaka_engine::scan::ScanIssue {
                path: Some(selected_path.clone()),
                code: ScanCode::PermissionDenied,
                message: format!("denied {index}"),
                os_code: Some(13),
            });
        }
        report.issues.push(sayaka_engine::scan::ScanIssue {
            path: Some(root.path.join("unrelated")),
            code: ScanCode::NotFound,
            message: "missing".to_string(),
            os_code: None,
        });
        let tree = ScanTree::build(report, &Cancellation::default()).unwrap();
        let selected = tree.entry(selected_id).unwrap();
        let evidence: Value = serde_json::from_slice(
            &serialize(&tree, 7, node_evidence(&tree, 7, selected)).unwrap(),
        )
        .unwrap();
        let data = &evidence["data"];
        assert_eq!(
            data["node"]["reference"]["node_id"],
            selected_id.to_string()
        );
        assert_eq!(data["identity"]["variant"], "unix");
        assert_eq!(data["depth"], root.depth + 1);
        assert_eq!(data["observed_alias_count"], 20);
        assert_eq!(data["aliases"].as_array().unwrap().len(), MAX_NODE_ALIASES);
        let aliases = data["aliases"].as_array().unwrap();
        assert!(aliases.windows(2).all(|pair| {
            pair[0]["path"]["raw"].as_str().unwrap() < pair[1]["path"]["raw"].as_str().unwrap()
        }));
        assert!(
            aliases[0]["path"]["display"]
                .as_str()
                .unwrap()
                .contains("00-alias")
        );
        assert!(
            aliases[15]["path"]["display"]
                .as_str()
                .unwrap()
                .contains("15-alias")
        );
        assert_eq!(data["matching_issue_count"], 10);
        assert_eq!(data["issues"].as_array().unwrap().len(), MAX_NODE_ISSUES);
        assert_eq!(data["issues"][0]["message"], "denied 0");
        assert_eq!(data["issues"][7]["message"], "denied 7");
    }
}
