// SPDX-License-Identifier: MPL-2.0

use super::*;
use std::ptr;

fn page(offset: u64, limit: u32, sort: u32) -> SayakaPageRequestV1 {
    SayakaPageRequestV1 {
        abi_version: ABI_VERSION,
        struct_size: size_of::<SayakaPageRequestV1>() as u32,
        offset,
        limit,
        sort,
    }
}

#[test]
fn installer_layout_and_input_refusals_are_explicit() {
    assert_eq!(size_of::<SayakaInstallerSnapshotV1>(), 72);
    assert_eq!(
        std::mem::offset_of!(SayakaInstallerSnapshotV1, progress_sequence),
        32
    );
    assert_eq!(size_of::<SayakaInstallerCandidateRefV1>(), 16);
    if size_of::<usize>() == 8 {
        assert_eq!(size_of::<SayakaInstallerRequestV1>(), 32);
    }
    let mut out = 99;
    assert_eq!(
        unsafe { sayaka_installer_start_v1(ptr::null(), &mut out) },
        INVALID_ARGUMENT
    );
    assert_eq!(out, 0);
    let mut request = SayakaInstallerRequestV1 {
        abi_version: 2,
        struct_size: size_of::<SayakaInstallerRequestV1>() as u32,
        root: SayakaPathV1 {
            encoding: UNIX_BYTES,
            bytes: ptr::null(),
            byte_length: 0,
        },
    };
    assert_eq!(
        unsafe { sayaka_installer_start_v1(&request, &mut out) },
        UNSUPPORTED_VERSION
    );
    request.abi_version = ABI_VERSION;
    assert_eq!(
        unsafe { sayaka_installer_start_v1(&request, &mut out) },
        if cfg!(target_os = "macos") {
            INVALID_ARGUMENT
        } else {
            UNSUPPORTED_PLATFORM
        }
    );
    let candidate = SayakaInstallerCandidateRefV1 {
        task_handle: 1,
        candidate_id: 1,
    };
    let mut required = 99;
    assert_eq!(
        unsafe { sayaka_installer_candidate_v1(2, &candidate, ptr::null_mut(), 0, &mut required) },
        INVALID_CANDIDATE
    );
    assert_eq!(required, 0);
    assert_eq!(
        unsafe {
            sayaka_installer_candidate_v1(
                1,
                &candidate,
                ptr::null_mut(),
                MAX_QUERY_BYTES + 1,
                &mut required,
            )
        },
        INVALID_ARGUMENT
    );
    assert_eq!(required, 0);
    assert_eq!(
        unsafe {
            sayaka_installer_candidates_v1(
                0,
                &page(0, 257, SORT_NAME),
                ptr::null_mut(),
                0,
                &mut required,
            )
        },
        INVALID_ARGUMENT
    );
    assert_eq!(
        unsafe {
            sayaka_installer_candidates_v1(0, &page(0, 1, 0), ptr::null_mut(), 0, &mut required)
        },
        INVALID_ARGUMENT
    );
    assert_eq!(
        unsafe { sayaka_installer_selection_start_v1(1, &candidate, 33, &mut out) },
        INVALID_ARGUMENT
    );
    assert_eq!(out, 0);
    assert_eq!(
        unsafe {
            sayaka_installer_selection_start_v1(1, [candidate, candidate].as_ptr(), 2, &mut out)
        },
        INVALID_CANDIDATE
    );
    assert_eq!(sayaka_installer_release_v1(0), INVALID_HANDLE);
    assert_eq!(sayaka_installer_cancel_v1(0), INVALID_HANDLE);
    assert_eq!(
        unsafe { sayaka_installer_result_v1(0, ptr::null_mut(), 0, &mut required) },
        INVALID_HANDLE
    );
    assert_eq!(required, 0);
}

#[cfg(target_os = "macos")]
mod native {
    use super::*;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::time::{Duration, Instant};

    struct Task(u64);
    impl Task {
        fn start(root: &Path) -> Self {
            let bytes = root.as_os_str().as_bytes();
            let request = SayakaInstallerRequestV1 {
                abi_version: ABI_VERSION,
                struct_size: size_of::<SayakaInstallerRequestV1>() as u32,
                root: SayakaPathV1 {
                    encoding: UNIX_BYTES,
                    bytes: bytes.as_ptr(),
                    byte_length: bytes.len(),
                },
            };
            let mut handle = 0;
            assert_eq!(
                unsafe { sayaka_installer_start_v1(&request, &mut handle) },
                OK
            );
            Self(handle)
        }
        fn selection(&self, references: &[SayakaInstallerCandidateRefV1]) -> Self {
            let mut handle = 0;
            assert_eq!(
                unsafe {
                    sayaka_installer_selection_start_v1(
                        self.0,
                        references.as_ptr(),
                        references.len(),
                        &mut handle,
                    )
                },
                OK
            );
            Self(handle)
        }
        fn finish(&self) -> SayakaInstallerSnapshotV1 {
            let deadline = Instant::now() + Duration::from_secs(30);
            let mut previous = 0;
            loop {
                let mut snapshot = SayakaInstallerSnapshotV1::default();
                assert_eq!(
                    unsafe { sayaka_installer_poll_v1(self.0, &mut snapshot) },
                    OK
                );
                assert!(snapshot.progress_sequence >= previous);
                previous = snapshot.progress_sequence;
                if snapshot.state != 1 {
                    return snapshot;
                }
                assert!(Instant::now() < deadline, "installer fixture task deadline");
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        fn result(&self) -> Value {
            query(|b, c, r| unsafe { sayaka_installer_result_v1(self.0, b, c, r) })
        }
        fn candidates(&self, offset: u64, limit: u32, sort: u32) -> Value {
            query(|b, c, r| unsafe {
                sayaka_installer_candidates_v1(self.0, &page(offset, limit, sort), b, c, r)
            })
        }
    }
    impl Drop for Task {
        fn drop(&mut self) {
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                match sayaka_installer_release_v1(self.0) {
                    OK => break,
                    BUSY if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(1))
                    }
                    code => panic!("owned installer release failed: {code}"),
                }
            }
        }
    }
    fn query(mut operation: impl FnMut(*mut u8, usize, *mut usize) -> i32) -> Value {
        let mut required = 0;
        assert_eq!(
            operation(ptr::null_mut(), 0, &mut required),
            BUFFER_TOO_SMALL
        );
        assert!((1..=MAX_RESULT_BYTES).contains(&required));
        let length = required;
        let mut guard = [0x91; 3];
        assert_eq!(
            operation(guard[1..].as_mut_ptr(), 1, &mut required),
            BUFFER_TOO_SMALL
        );
        assert_eq!(guard, [0x91; 3]);
        assert_eq!(required, length);
        let mut bytes = vec![0; required];
        assert_eq!(
            operation(bytes.as_mut_ptr(), bytes.len(), &mut required),
            OK
        );
        assert_eq!(required, length);
        serde_json::from_slice(&bytes).unwrap()
    }
    fn reference(value: &Value) -> SayakaInstallerCandidateRefV1 {
        SayakaInstallerCandidateRefV1 {
            task_handle: value["reference"]["task_handle"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
            candidate_id: value["reference"]["candidate_id"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
        }
    }
    fn dmg(path: &Path) {
        let mut bytes = vec![0; 2048];
        let footer = &mut bytes[1536..];
        footer[..4].copy_from_slice(b"koly");
        footer[4..8].copy_from_slice(&4u32.to_be_bytes());
        footer[8..12].copy_from_slice(&512u32.to_be_bytes());
        footer[0xd8..0xe0].copy_from_slice(&128u64.to_be_bytes());
        footer[0xe0..0xe8].copy_from_slice(&64u64.to_be_bytes());
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn owned_installer_tasks_query_select_revalidate_and_release_without_effects() {
        let _serial = NATIVE_TEST_LOCK.lock().unwrap();
        let fixture = tempfile::Builder::new()
            .prefix("installer-owned-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .unwrap();
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let root = fixture.path().join("downloads");
        fs::create_dir(&root).unwrap();
        dmg(&root.join("a.dmg"));
        fs::write(root.join("bad.pkg"), b"not a package").unwrap();
        fs::write(root.join("sentinel.txt"), b"leave unchanged").unwrap();
        let discovery = Task::start(&root);
        let snapshot = discovery.finish();
        assert_eq!(snapshot.state, 2);
        assert_eq!(snapshot.kind, 1);
        assert_eq!(snapshot.phase, 2);
        assert_eq!(snapshot.inspected_candidates, 2);
        let report = discovery.result();
        assert_eq!(report["data"]["status"], "complete");
        assert_eq!(report["data"]["effects_performed"], false);
        let first = discovery.candidates(0, 1, SORT_NAME);
        assert_eq!(first["data"]["total"], 2);
        assert_eq!(first["data"]["next_offset"], 1);
        let good = &first["data"]["candidates"][0];
        let good_ref = reference(good);
        assert_eq!(good["logical_bytes"], 2048);
        assert_eq!(good["format"]["status"], "recognized");
        assert_eq!(good["selection_check_eligible"], true);
        assert_eq!(
            good["path"]["raw"],
            root.join("a.dmg")
                .as_os_str()
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        let detail = query(|b, c, r| unsafe {
            sayaka_installer_candidate_v1(discovery.0, &good_ref, b, c, r)
        });
        assert_eq!(detail["data"], *good);
        let last = discovery.candidates(1, 1, SORT_NAME);
        let bad_ref = reference(&last["data"]["candidates"][0]);
        assert_eq!(last["data"]["next_offset"], Value::Null);
        assert_eq!(
            last["data"]["candidates"][0]["selection_check_eligible"],
            false
        );
        assert_eq!(
            discovery.candidates(2, 1, SORT_NAME)["data"]["candidates"],
            json!([])
        );
        let mut invalid_required = 99;
        assert_eq!(
            unsafe {
                sayaka_installer_candidates_v1(
                    discovery.0,
                    &page(u64::MAX, 1, SORT_NAME),
                    ptr::null_mut(),
                    0,
                    &mut invalid_required,
                )
            },
            INVALID_ARGUMENT
        );
        assert_eq!(invalid_required, 0);
        assert_eq!(
            discovery.candidates(0, 2, SORT_LOGICAL_SIZE)["data"]["candidates"][0],
            *good
        );
        let selection = discovery.selection(&[good_ref]);
        let mut wrong_kind = 99;
        assert_eq!(
            unsafe {
                sayaka_installer_candidates_v1(
                    selection.0,
                    &page(0, 1, SORT_NAME),
                    ptr::null_mut(),
                    0,
                    &mut wrong_kind,
                )
            },
            INVALID_HANDLE
        );
        assert_eq!(wrong_kind, 0);
        assert_eq!(selection.finish().state, 2);
        let checked = selection.result();
        assert_eq!(checked["source_task_handle"], discovery.0.to_string());
        assert_eq!(checked["data"]["status"], "checked");
        assert_eq!(checked["data"]["execution_authority"], false);
        assert_eq!(checked["data"]["effects_performed"], false);
        assert_eq!(checked["data"]["selected"].as_array().unwrap().len(), 1);
        assert_eq!(checked["data"]["bytes"]["matched_logical_bytes"], 2048);
        assert!(checked["data"].get("plan").is_none());
        drop(selection);
        let refused = discovery.selection(&[good_ref, bad_ref]);
        assert_eq!(refused.finish().state, 3);
        assert_eq!(refused.result()["data"]["status"], "refused");
        assert_eq!(
            refused.result()["data"]["selected"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        drop(refused);
        let mut bytes = fs::read(root.join("a.dmg")).unwrap();
        bytes[0] ^= 1;
        fs::write(root.join("a.dmg"), bytes).unwrap();
        let stale = discovery.selection(&[good_ref]);
        assert_eq!(stale.finish().state, 3);
        assert_eq!(
            stale.result()["data"]["issues"][0]["code"],
            "native_revalidation_failed"
        );
        drop(stale);
        assert_eq!(discovery.result(), report);
        let refreshed = Task::start(&root);
        assert_eq!(refreshed.finish().state, 2);
        let mut out = 99;
        assert_eq!(
            unsafe { sayaka_installer_selection_start_v1(refreshed.0, &good_ref, 1, &mut out) },
            INVALID_CANDIDATE
        );
        assert_eq!(out, 0);
        let new_ref = reference(&refreshed.candidates(0, 1, SORT_NAME)["data"]["candidates"][0]);
        let independent = refreshed.selection(&[new_ref]);
        let old_handle = refreshed.0;
        drop(refreshed);
        assert_eq!(independent.finish().state, 2);
        assert_eq!(independent.result()["data"]["status"], "checked");
        assert_eq!(sayaka_installer_cancel_v1(old_handle), INVALID_HANDLE);
        drop(independent);
        let mut required = 99;
        {
            let slot = get_installer(discovery.0).unwrap();
            let _locked = slot.lock().unwrap();
            assert_eq!(
                unsafe {
                    sayaka_installer_result_v1(discovery.0, ptr::null_mut(), 0, &mut required)
                },
                BUSY
            );
            assert_eq!(required, 0);
        }
        assert_eq!(
            unsafe { sayaka_scan_result_v1(discovery.0, ptr::null_mut(), 0, &mut required) },
            INVALID_HANDLE
        );
        let old_handle = discovery.0;
        drop(discovery);
        assert_eq!(
            unsafe {
                sayaka_installer_candidate_v1(
                    old_handle,
                    &good_ref,
                    ptr::null_mut(),
                    0,
                    &mut required,
                )
            },
            INVALID_HANDLE
        );
        let failed = Task::start(&root.join("missing"));
        assert_eq!(failed.finish().state, 5);
        assert_eq!(failed.result()["data"]["status"], "failed");
        assert_eq!(
            unsafe {
                sayaka_installer_candidates_v1(
                    failed.0,
                    &page(0, 1, SORT_NAME),
                    ptr::null_mut(),
                    0,
                    &mut required,
                )
            },
            QUERY_UNAVAILABLE
        );
        drop(failed);
        assert_eq!(
            fs::read(root.join("sentinel.txt")).unwrap(),
            b"leave unchanged"
        );
        assert!(root.join("a.dmg").is_file() && root.join("bad.pkg").is_file());
        assert_eq!(fs::read_dir(fixture.path()).unwrap().count(), 1);
    }
}
