// SPDX-License-Identifier: MPL-2.0

#![cfg(target_os = "macos")]

#[path = "support/fixture.rs"]
mod fixture;

use fixture::Fixture;
use sayaka_engine::model::{Cancellation, ResourceKind};
use sayaka_engine::scan::{self, ScanCode, ScanLimits, ScanReport, ScanStatus};
use std::fs;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

fn scope(fixture: &Fixture) -> PathBuf {
    let root = fixture.path().canonicalize().unwrap().join("scan");
    fs::create_dir(&root).unwrap();
    root
}

fn run(root: &Path) -> ScanReport {
    scan::scan(
        &[root.to_path_buf()],
        &ScanLimits::default(),
        &Cancellation::default(),
        |_| {},
    )
    .unwrap()
}

#[test]
fn native_accounting_handles_empty_sparse_hard_links_and_scope_overlap() {
    let fixture = Fixture::new().unwrap();
    let root = scope(&fixture);
    let empty = run(&root);
    assert_eq!(empty.status, ScanStatus::Complete, "{:?}", empty.issues);
    assert_eq!(empty.totals.regular_files, 0);
    assert_eq!(empty.totals.directories, 1);
    fs::create_dir(root.join("nested")).unwrap();
    fs::write(root.join("one"), b"abc").unwrap();
    fs::write(root.join("nested/two"), b"hello").unwrap();
    fs::write(root.join("zero"), []).unwrap();
    let sparse = fs::File::create(root.join("sparse")).unwrap();
    sparse.set_len(1_048_576).unwrap();
    drop(sparse);
    fs::hard_link(root.join("one"), root.join("nested/one-again")).unwrap();
    symlink(fixture.path().join("protected"), root.join("link")).unwrap();
    let expected_allocation: u64 = ["one", "nested/two", "zero", "sparse"]
        .iter()
        .map(|path| fs::metadata(root.join(path)).unwrap().blocks() * 512)
        .sum();
    let report = scan::scan(
        &[root.clone(), root.join("nested"), root.clone()],
        &ScanLimits::default(),
        &Cancellation::default(),
        |_| {},
    )
    .unwrap();
    assert_eq!(report.status, ScanStatus::Complete, "{:?}", report.issues);
    assert_eq!(report.roots.as_slice(), std::slice::from_ref(&root));
    assert_eq!(report.totals.regular_files, 5);
    assert_eq!(report.totals.unique_files, 4);
    assert_eq!(report.totals.duplicate_files, 1);
    assert_eq!(report.totals.logical_bytes_known, 1_048_584);
    assert_eq!(report.totals.allocated_bytes_known, expected_allocation);
    assert_eq!(report.totals.logical_bytes_unknown_files, 0);
    assert_eq!(report.totals.allocated_bytes_unknown_files, 0);
    assert_eq!(report.totals.links, 1);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.code == ScanCode::LinkSkipped)
    );
    assert!(
        !report
            .entries
            .iter()
            .any(|entry| entry.path.ends_with("keep.txt"))
    );
    assert_eq!(fs::read(root.join("one")).unwrap(), b"abc");
    assert_eq!(
        fs::read(fixture.path().join("protected/keep.txt")).unwrap(),
        b"must remain unchanged"
    );
    assert!(report.metrics.peak_workers <= 4);
    assert!(report.metrics.peak_queued_dirs <= 64);
    assert!(report.metrics.peak_open_dirs <= 128);
    assert!(report.metrics.peak_pending_events <= 128);
    fixture.close().unwrap();
}

#[test]
fn native_path_bytes_and_link_ancestors_are_not_reinterpreted() {
    let fixture = Fixture::new().unwrap();
    let root = scope(&fixture);
    let raw_name = std::ffi::OsString::from_vec(vec![b'a', b'\n', 0x1b]);
    fs::write(root.join(&raw_name), b"bytes").unwrap();
    let report = run(&root);
    assert!(report.complete, "{:?}", report.issues);
    let entry = report
        .entries
        .iter()
        .find(|entry| entry.kind == ResourceKind::File)
        .unwrap();
    assert_eq!(
        entry.path.file_name().unwrap().as_bytes(),
        raw_name.as_bytes()
    );
    assert!(!scan::display_path(&entry.path).contains('\n'));
    assert!(!scan::display_path(&entry.path).contains('\u{1b}'));
    let alias = fixture.path().canonicalize().unwrap().join("alias");
    symlink(&root, &alias).unwrap();
    assert_eq!(run(&alias).status, ScanStatus::Failed);
    fs::create_dir(root.join("nested")).unwrap();
    let report = run(&alias.join("nested"));
    assert_eq!(report.status, ScanStatus::Failed);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.code == ScanCode::LinkSkipped)
    );
    fixture.close().unwrap();
}

#[test]
fn native_permission_failures_are_partial_not_empty_success() {
    let fixture = Fixture::new().unwrap();
    let root = scope(&fixture);
    fs::write(root.join("readable"), b"1234").unwrap();
    let denied = root.join("denied");
    fs::create_dir(&denied).unwrap();
    fs::write(denied.join("secret"), b"fixture only").unwrap();
    let original = fs::metadata(&denied).unwrap().permissions();
    fs::set_permissions(&denied, fs::Permissions::from_mode(0o0)).unwrap();
    let denied_precondition = fs::read_dir(&denied).is_err();
    let result = scan::scan(
        std::slice::from_ref(&root),
        &ScanLimits::default(),
        &Cancellation::default(),
        |_| {},
    );
    fs::set_permissions(&denied, original).unwrap();
    assert!(
        denied_precondition,
        "permission fixture did not deny access; do not run this test with elevated privileges"
    );
    let report = result.unwrap();
    assert_eq!(report.status, ScanStatus::Partial, "{:?}", report.issues);
    assert!(!report.complete);
    assert_eq!(report.totals.logical_bytes_known, 4);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.code == ScanCode::PermissionDenied)
    );
    fixture.close().unwrap();
}

#[test]
fn native_resource_budgets_and_cancel_are_explicit() {
    let fixture = Fixture::new().unwrap();
    let root = scope(&fixture);
    fs::create_dir_all(root.join("a/b/c")).unwrap();
    fs::write(root.join("a/b/c/file"), b"owned").unwrap();
    fs::write(root.join("top"), b"top").unwrap();
    for (limits, expected) in [
        (
            ScanLimits {
                max_entries: 1,
                ..ScanLimits::default()
            },
            ScanCode::EntryLimit,
        ),
        (
            ScanLimits {
                max_depth: 1,
                ..ScanLimits::default()
            },
            ScanCode::DepthLimit,
        ),
        (
            ScanLimits {
                max_path_bytes: root.as_os_str().len() + 8,
                ..ScanLimits::default()
            },
            ScanCode::PathBytesLimit,
        ),
    ] {
        let report = scan::scan(
            std::slice::from_ref(&root),
            &limits,
            &Cancellation::default(),
            |_| {},
        )
        .unwrap();
        assert_eq!(report.status, ScanStatus::Partial, "{:?}", report.issues);
        assert!(
            report.issues.iter().any(|issue| issue.code == expected),
            "{:?}",
            report.issues
        );
        assert!(report.entries.len() <= limits.max_entries);
        assert!(report.metrics.retained_path_bytes <= limits.max_path_bytes);
    }
    let cancel = Cancellation::default();
    let signal = cancel.clone();
    let mut events = Vec::new();
    let report = scan::scan(
        std::slice::from_ref(&root),
        &ScanLimits::default(),
        &cancel,
        |event| {
            events.push(event.task_id);
            signal.cancel();
        },
    )
    .unwrap();
    assert_eq!(report.status, ScanStatus::Cancelled);
    assert!(events.iter().all(|id| *id == report.task_id));
    let next = run(&root);
    assert_ne!(report.task_id, next.task_id);
    assert!(next.complete, "{:?}", next.issues);
    fixture.close().unwrap();
}
