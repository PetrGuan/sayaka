// SPDX-License-Identifier: MPL-2.0

#![cfg(windows)]

#[path = "support/fixture.rs"]
mod fixture;

use fixture::Fixture;
use sayaka_engine::model::{Cancellation, FileIdentity};
use sayaka_engine::scan::{self, ScanCode, ScanLimits, ScanReport, ScanStatus};
use std::ffi::OsString;
use std::fs;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

fn scope(fixture: &Fixture) -> PathBuf {
    let root = fixture.path().join("scan");
    fs::create_dir(&root).unwrap();
    root
}

fn run(roots: &[PathBuf]) -> ScanReport {
    scan::scan(
        roots,
        &ScanLimits::default(),
        &Cancellation::default(),
        |_| {},
    )
    .unwrap()
}

fn hold_exclusive_directory(path: &Path) -> fs::File {
    fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .custom_flags(0x0200_0000)
        .open(path)
        .unwrap()
}

#[test]
fn windows_native_accounting_preserves_full_identity_and_hardlinks() {
    let fixture = Fixture::new().unwrap();
    let root = scope(&fixture);
    let empty = run(std::slice::from_ref(&root));
    assert_eq!(empty.status, ScanStatus::Complete, "{:?}", empty.issues);
    assert_eq!(empty.totals.regular_files, 0);
    fs::create_dir(root.join("nested")).unwrap();
    fs::write(root.join("one"), b"abc").unwrap();
    fs::write(root.join("nested/two"), b"hello").unwrap();
    fs::write(root.join("empty"), []).unwrap();
    fs::hard_link(root.join("one"), root.join("nested/alias")).unwrap();
    let report = run(&[root.clone(), root.join("nested")]);
    assert_eq!(report.status, ScanStatus::Complete, "{:?}", report.issues);
    assert_eq!(report.totals.regular_files, 4);
    assert_eq!(report.totals.unique_files, 3);
    assert_eq!(report.totals.duplicate_files, 1);
    assert_eq!(report.totals.logical_bytes_known, 8);
    assert_eq!(report.totals.allocated_bytes_unknown_files, 0);
    let original = report
        .entries
        .iter()
        .find(|entry| entry.path == root.join("one"))
        .unwrap();
    let alias = report
        .entries
        .iter()
        .find(|entry| entry.path == root.join("nested/alias"))
        .unwrap();
    assert_eq!(original.identity, alias.identity);
    assert!(
        matches!(original.identity, FileIdentity::Windows { file_id, .. } if file_id != [0; 16])
    );
    assert_eq!(fs::read(root.join("one")).unwrap(), b"abc");
    fixture.close().unwrap();
}

#[test]
fn windows_native_enumeration_crosses_buffer_boundaries_and_preserves_utf16() {
    let fixture = Fixture::new().unwrap();
    let root = scope(&fixture);
    for index in 0..900 {
        fs::write(root.join(format!("file-{index:04}")), b"x").unwrap();
    }
    let name = OsString::from_wide(&[0x0061, 0xd800, 0x0062]);
    fs::write(root.join(&name), b"raw").unwrap();
    let report = run(std::slice::from_ref(&root));
    assert_eq!(report.status, ScanStatus::Complete, "{:?}", report.issues);
    assert_eq!(report.totals.unique_files, 901);
    assert_eq!(report.totals.logical_bytes_known, 903);
    assert!(
        report
            .entries
            .iter()
            .any(|entry| entry.path.file_name() == Some(name.as_os_str()))
    );
    fixture.close().unwrap();
}

#[test]
fn windows_real_sharing_violation_is_observable_and_mixed_scan_is_partial() {
    let fixture = Fixture::new().unwrap();
    let root = scope(&fixture);
    let busy = root.join("busy");
    fs::create_dir(&busy).unwrap();
    fs::write(busy.join("unseen"), b"private fixture").unwrap();
    fs::write(root.join("readable"), b"1234").unwrap();
    let locked = hold_exclusive_directory(&busy);
    assert!(
        fs::read_dir(&busy).is_err(),
        "fixture did not deny directory access"
    );
    let report = run(std::slice::from_ref(&root));
    assert_eq!(report.status, ScanStatus::Partial, "{:?}", report.issues);
    assert_eq!(report.totals.logical_bytes_known, 4);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.code == ScanCode::Busy && issue.os_code == Some(32))
    );
    assert_eq!(run(std::slice::from_ref(&busy)).status, ScanStatus::Failed);
    drop(locked);
    assert_eq!(
        run(std::slice::from_ref(&root)).status,
        ScanStatus::Complete
    );
    fixture.close().unwrap();
}

#[test]
fn windows_native_cancellation_and_entry_budget_remain_incomplete() {
    let fixture = Fixture::new().unwrap();
    let root = scope(&fixture);
    for index in 0..40 {
        fs::write(root.join(format!("file-{index}")), b"fixture").unwrap();
    }
    let cancel = Cancellation::default();
    let limits = ScanLimits {
        progress_every: 1,
        ..ScanLimits::default()
    };
    let report = scan::scan(std::slice::from_ref(&root), &limits, &cancel, |progress| {
        if progress.entries >= 3 {
            cancel.cancel();
        }
    })
    .unwrap();
    assert_eq!(report.status, ScanStatus::Cancelled);
    assert!(!report.complete);
    let limits = ScanLimits {
        max_entries: 2,
        ..ScanLimits::default()
    };
    let report = scan::scan(&[root], &limits, &Cancellation::default(), |_| {}).unwrap();
    assert_eq!(report.status, ScanStatus::Partial);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.code == ScanCode::EntryLimit)
    );
    fixture.close().unwrap();
}

#[test]
fn windows_junctions_and_reparse_ancestors_are_never_followed() {
    let fixture = Fixture::new().unwrap();
    let root = scope(&fixture);
    fs::create_dir(root.join("nested")).unwrap();
    fs::write(root.join("visible"), b"1234").unwrap();
    let alias = fixture.path().join("alias");
    let escape = root.join("escape");
    let cycle = root.join("cycle");
    junction::create(&root, &alias).unwrap();
    junction::create(fixture.path().join("protected"), &escape).unwrap();
    junction::create(&root, &cycle).unwrap();
    let report = run(std::slice::from_ref(&root));
    assert_eq!(report.status, ScanStatus::Complete, "{:?}", report.issues);
    assert_eq!(report.totals.logical_bytes_known, 4);
    assert_eq!(report.totals.links, 2);
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
    for path in [alias.clone(), alias.join("nested")] {
        let rejected = run(std::slice::from_ref(&path));
        assert_eq!(rejected.status, ScanStatus::Failed, "{:?}", rejected.issues);
        assert!(
            rejected
                .issues
                .iter()
                .any(|issue| issue.code == ScanCode::LinkSkipped)
        );
        let mixed = run(&[root.clone(), path]);
        assert_eq!(mixed.status, ScanStatus::Partial, "{:?}", mixed.issues);
    }
    assert_eq!(
        fs::read(fixture.path().join("protected/keep.txt")).unwrap(),
        b"must remain unchanged"
    );
    for path in [alias, escape, cycle] {
        junction::delete(path).unwrap();
    }
    fixture.close().unwrap();
}

#[test]
fn windows_relative_handles_do_not_reopen_a_replaced_ancestor_path() {
    use sayaka_platform_windows::Directory;
    let fixture = Fixture::new().unwrap();
    let root = scope(&fixture);
    fs::create_dir(root.join("nested")).unwrap();
    fs::write(root.join("nested/original"), b"owned").unwrap();
    let directory = Directory::open_root(&root).unwrap();
    let old_identity = directory.metadata().clone();
    let moved = fixture.path().join("moved");
    fs::rename(&root, &moved).unwrap();
    fs::create_dir(&root).unwrap();
    fs::create_dir(root.join("nested")).unwrap();
    fs::write(root.join("nested/replacement"), b"other owned fixture").unwrap();
    let replacement = Directory::open_root(&root).unwrap();
    assert_ne!(old_identity.file_id, replacement.metadata().file_id);
    let mut child = directory
        .open_child(std::ffi::OsStr::new("nested"))
        .unwrap();
    let entry = child.next_entry().unwrap().unwrap();
    assert_eq!(entry.name, "original");
    assert!(child.next_entry().is_none());
    assert!(!directory.unchanged().unwrap());
    drop(child);
    drop(replacement);
    drop(directory);
    fixture.close().unwrap();
}
