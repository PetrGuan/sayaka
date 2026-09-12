// SPDX-License-Identifier: MPL-2.0

use super::*;
use crate::scan::{ScanIssue, ScanMetrics, ScanTaskId, ScanTotals};
use std::path::PathBuf;

fn path(relative: &str) -> PathBuf {
    let base = if cfg!(windows) {
        PathBuf::from("C:/scan-index-fixture")
    } else {
        PathBuf::from("/scan-index-fixture")
    };
    if relative.is_empty() {
        base
    } else {
        base.join(relative)
    }
}

fn identity(inode: u64) -> FileIdentity {
    FileIdentity::Unix { device: 7, inode }
}

fn entry(id: u64, relative: &str, kind: ResourceKind) -> ScanEntry {
    ScanEntry {
        id,
        path: path(relative),
        kind,
        identity: identity(id),
        logical_bytes: None,
        allocated_bytes: None,
        dataless: false,
        counted: false,
        depth: usize::MAX,
    }
}

fn directory(id: u64, relative: &str) -> ScanEntry {
    entry(id, relative, ResourceKind::Directory)
}

fn file(
    id: u64,
    relative: &str,
    inode: u64,
    logical: Option<u64>,
    allocated: Option<u64>,
) -> ScanEntry {
    ScanEntry {
        identity: identity(inode),
        logical_bytes: logical,
        allocated_bytes: allocated,
        ..entry(id, relative, ResourceKind::File)
    }
}

fn report(entries: Vec<ScanEntry>) -> ScanReport {
    ScanReport {
        task_id: ScanTaskId::new().unwrap(),
        roots: vec![path("")],
        status: ScanStatus::Complete,
        complete: true,
        entries,
        issues: Vec::new(),
        issues_omitted: 0,
        totals: ScanTotals::default(),
        metrics: ScanMetrics::default(),
    }
}

fn tree(entries: Vec<ScanEntry>) -> ScanTree {
    ScanTree::build(report(entries), &Cancellation::default()).unwrap()
}

fn issue(code: ScanCode) -> ScanIssue {
    ScanIssue {
        code,
        path: None,
        message: "synthetic observation".into(),
        os_code: None,
    }
}

fn summary(unique: u64, logical: u64, allocated: u64) -> DirectorySummary {
    DirectorySummary {
        unique_files: unique,
        logical_bytes_known: logical,
        allocated_bytes_known: allocated,
        complete: true,
        ..DirectorySummary::default()
    }
}

fn assert_error(report: ScanReport, code: ScanCode) {
    assert_eq!(
        ScanTree::build(report, &Cancellation::default())
            .unwrap_err()
            .code,
        code
    );
}

#[test]
fn sibling_hardlinks_count_locally_even_when_globally_uncounted() {
    let mut report = report(vec![
        directory(50, ""),
        directory(7, "a"),
        directory(99, "b"),
        file(100, "a/shared", 300, Some(11), Some(4096)),
        file(13, "a/alias", 300, Some(11), Some(4096)),
        file(8, "b/shared", 300, Some(11), Some(4096)),
        file(77, "b/own", 301, Some(5), Some(512)),
    ]);
    report.entries[3].counted = true;
    report.totals.unique_files = 123;
    report.totals.logical_bytes_known = 987;
    let task_id = report.task_id;
    let tree = ScanTree::build(report, &Cancellation::default()).unwrap();
    assert_eq!(tree.summary(7), Some(&summary(1, 11, 4096)));
    assert_eq!(tree.summary(99), Some(&summary(2, 16, 4608)));
    assert_eq!(tree.summary(50), Some(&summary(2, 16, 4608)));
    assert!(!tree.entry(8).unwrap().counted);
    assert_eq!(tree.report().totals.unique_files, 123);
    assert_eq!(tree.report().totals.logical_bytes_known, 987);
    assert_eq!(tree.report().task_id, task_id);
    assert_eq!(tree.entry(100).unwrap().logical_bytes, Some(11));
}

#[test]
fn identity_measurements_normalize_independently_in_every_input_order() {
    let observations = [
        ([Some(8), Some(8), Some(8)], Some(8)),
        ([Some(8), None, Some(8)], None),
        ([None, Some(8), Some(8)], None),
        ([Some(8), Some(9), Some(8)], None),
        ([None, None, None], None),
        ([Some(0), Some(0), Some(0)], Some(0)),
    ];
    for (logical, expected_logical) in observations {
        for (allocated, expected_allocated) in observations {
            let entries = vec![
                directory(1, ""),
                directory(2, "a"),
                directory(3, "b"),
                file(4, "a/one", 42, logical[0], allocated[0]),
                file(5, "b/two", 42, logical[1], allocated[1]),
                file(6, "b/three", 42, logical[2], allocated[2]),
            ];
            for reverse in [false, true] {
                for offset in 0..entries.len() {
                    let mut shuffled = entries.clone();
                    shuffled.rotate_left(offset);
                    if reverse {
                        shuffled.reverse();
                    }
                    let tree = tree(shuffled);
                    let expected = DirectorySummary {
                        unique_files: 1,
                        logical_bytes_known: expected_logical.unwrap_or(0),
                        logical_bytes_unknown_files: u64::from(expected_logical.is_none()),
                        allocated_bytes_known: expected_allocated.unwrap_or(0),
                        allocated_bytes_unknown_files: u64::from(expected_allocated.is_none()),
                        complete: true,
                    };
                    for id in [1, 2, 3] {
                        assert_eq!(tree.summary(id), Some(&expected));
                    }
                    // Normalization belongs to directory accounting only.
                    assert_eq!(tree.entry(4).unwrap().logical_bytes, logical[0]);
                    assert_eq!(tree.entry(6).unwrap().allocated_bytes, allocated[2]);
                }
            }
        }
    }
}

#[test]
fn normalization_crosses_forest_roots() {
    let mut report = report(vec![
        directory(1, "a"),
        directory(2, "b"),
        file(3, "a/file", 40, Some(100), Some(512)),
        file(4, "b/file", 40, None, Some(1024)),
    ]);
    report.roots = vec![path("b"), path("a")];
    let tree = ScanTree::build(report, &Cancellation::default()).unwrap();
    assert_eq!(tree.roots(), &[1, 2]);
    for id in [1, 2] {
        assert_eq!(
            tree.summary(id),
            Some(&DirectorySummary {
                unique_files: 1,
                logical_bytes_unknown_files: 1,
                allocated_bytes_unknown_files: 1,
                complete: true,
                ..DirectorySummary::default()
            })
        );
    }
}

#[test]
fn sparse_zero_unknown_and_non_file_payloads_stay_distinct() {
    let mut root = directory(1, "");
    root.logical_bytes = Some(u64::MAX);
    root.allocated_bytes = Some(u64::MAX);
    let mut link = entry(7, "link", ResourceKind::Link);
    link.logical_bytes = Some(u64::MAX);
    link.allocated_bytes = Some(u64::MAX);
    let mut other = entry(8, "other", ResourceKind::Other);
    other.logical_bytes = Some(u64::MAX);
    other.allocated_bytes = Some(u64::MAX);
    let tree = tree(vec![
        root,
        directory(2, "empty"),
        file(3, "sparse", 3, Some(1 << 30), Some(4096)),
        file(4, "zero", 4, Some(0), Some(0)),
        file(5, "unknown-logical", 5, None, Some(512)),
        file(6, "unknown-allocated", 6, Some(7), None),
        link,
        other,
    ]);
    assert_eq!(
        tree.summary(1),
        Some(&DirectorySummary {
            unique_files: 4,
            logical_bytes_known: (1 << 30) + 7,
            logical_bytes_unknown_files: 1,
            allocated_bytes_known: 4608,
            allocated_bytes_unknown_files: 1,
            complete: true,
        })
    );
    assert_eq!(tree.summary(2), Some(&summary(0, 0, 0)));
    assert_eq!(tree.children(2), Some([].as_slice()));
    for id in [3, 7, 8, 100] {
        assert_eq!(tree.summary(id), None);
        assert_eq!(tree.children(id), None);
    }
    assert_eq!(tree.entry(100).map(|entry| entry.id), None);
    assert_eq!(tree.parent(100), None);
}

#[test]
fn completeness_is_conservative_and_separate_from_measurements() {
    for status in [
        ScanStatus::Complete,
        ScanStatus::Partial,
        ScanStatus::Cancelled,
        ScanStatus::Failed,
    ] {
        for declared_complete in [false, true] {
            for omitted in [0, 1] {
                for code in [None, Some(ScanCode::LinkSkipped), Some(ScanCode::Io)] {
                    let mut report = report(vec![
                        directory(1, ""),
                        directory(2, "empty"),
                        file(3, "file", 3, None, Some(4)),
                    ]);
                    report.status = status;
                    report.complete = declared_complete;
                    report.issues_omitted = omitted;
                    if let Some(code) = code {
                        report.issues.push(issue(code));
                    }
                    let tree = ScanTree::build(report, &Cancellation::default()).unwrap();
                    let complete = status == ScanStatus::Complete
                        && declared_complete
                        && omitted == 0
                        && code != Some(ScanCode::Io);
                    for id in [1, 2] {
                        assert_eq!(tree.summary(id).unwrap().complete, complete);
                    }
                    assert_eq!(tree.summary(1).unwrap().logical_bytes_unknown_files, 1);
                    assert_eq!(tree.summary(2).unwrap().logical_bytes_unknown_files, 0);
                    assert_eq!(tree.summary(1).unwrap().allocated_bytes_known, 4);
                }
            }
        }
    }
}

#[test]
fn all_gap_codes_mark_coverage_incomplete() {
    for code in [
        ScanCode::InvalidLimits,
        ScanCode::InvalidRoot,
        ScanCode::UnsupportedPlatform,
        ScanCode::UnsupportedVolume,
        ScanCode::VolumeUnknown,
        ScanCode::PermissionDenied,
        ScanCode::NotFound,
        ScanCode::MountBoundary,
        ScanCode::CloudDirectorySkipped,
        ScanCode::ChangedEntry,
        ScanCode::Io,
        ScanCode::PolicyFailure,
        ScanCode::DepthLimit,
        ScanCode::OpenHandleLimit,
        ScanCode::EntryLimit,
        ScanCode::PathBytesLimit,
        ScanCode::DurationLimit,
        ScanCode::Cancelled,
        ScanCode::Overflow,
        ScanCode::WorkerPanic,
        ScanCode::WorkerStartFailed,
        ScanCode::Internal,
    ] {
        let mut report = report(vec![directory(1, "")]);
        report.issues.push(issue(code));
        let tree = ScanTree::build(report, &Cancellation::default()).unwrap();
        assert!(!tree.summary(1).unwrap().complete, "{code:?}");
    }
    for code in [ScanCode::DuplicateRoot, ScanCode::DuplicateDirectory] {
        let mut report = report(vec![directory(1, "")]);
        report.issues.push(issue(code));
        let tree = ScanTree::build(report, &Cancellation::default()).unwrap();
        assert!(tree.summary(1).unwrap().complete);
    }
}

#[test]
fn hierarchy_uses_paths_not_depth_or_ids_and_order_is_deterministic() {
    let mut entries = vec![
        directory(u64::MAX, ""),
        directory(0, "nested"),
        directory(97, "nested/deeper"),
        file(20, "nested/deeper/file", 50, Some(7), Some(9)),
        file(9, "z", 51, Some(1), Some(2)),
        file(77, "A", 52, Some(2), Some(3)),
    ];
    entries[0].depth = 500;
    entries[1].depth = 0;
    entries[2].depth = 1;
    for offset in 0..entries.len() {
        let mut entries = entries.clone();
        entries.rotate_left(offset);
        let mut report = report(entries);
        report.roots = vec![path("nested"), path("")];
        let tree = ScanTree::build(report, &Cancellation::default()).unwrap();
        assert_eq!(tree.roots(), &[u64::MAX]);
        assert_eq!(tree.children(u64::MAX), Some([77, 0, 9].as_slice()));
        assert_eq!(tree.children(0), Some([97].as_slice()));
        assert_eq!(tree.parent(0), Some(u64::MAX));
        assert_eq!(tree.parent(97), Some(0));
        assert_eq!(tree.parent(20), Some(97));
        assert_eq!(tree.parent(u64::MAX), None);
        assert_eq!(tree.summary(u64::MAX), Some(&summary(3, 10, 14)));
        assert_eq!(tree.summary(0), Some(&summary(1, 7, 9)));
    }
}

#[test]
fn explicit_root_can_survive_an_unobserved_ancestor_without_inventing_nodes() {
    let mut report = report(vec![
        directory(2, "missing/nested"),
        file(3, "missing/nested/file", 3, Some(2), Some(4)),
    ]);
    report.roots.push(path("missing/nested"));
    report.status = ScanStatus::Partial;
    report.complete = false;
    let tree = ScanTree::build(report, &Cancellation::default()).unwrap();
    assert_eq!(tree.roots(), &[2]);
    assert_eq!(tree.parent(2), None);
    assert_eq!(tree.summary(2).unwrap().unique_files, 1);
    assert!(!tree.summary(2).unwrap().complete);
    assert_eq!(tree.report().entries.len(), 2);
}

#[test]
fn absent_requested_roots_do_not_create_complete_empty_directories() {
    let mut empty = report(Vec::new());
    empty.status = ScanStatus::Failed;
    empty.complete = false;
    let tree = ScanTree::build(empty, &Cancellation::default()).unwrap();
    assert!(tree.roots().is_empty());
    assert!(tree.report().entries.is_empty());

    let mut missing = report(vec![directory(1, "")]);
    missing.roots.push(path("missing"));
    let tree = ScanTree::build(missing, &Cancellation::default()).unwrap();
    assert_eq!(tree.roots(), &[1]);
    assert!(!tree.summary(1).unwrap().complete);

    let mut alias = report(vec![directory(1, "")]);
    alias.roots.push(path("alias"));
    alias.issues.push(ScanIssue {
        path: Some(path("alias")),
        ..issue(ScanCode::DuplicateRoot)
    });
    let tree = ScanTree::build(alias, &Cancellation::default()).unwrap();
    assert!(tree.summary(1).unwrap().complete);
}

#[test]
fn malformed_duplicates_paths_and_structure_are_rejected() {
    for entries in [
        vec![directory(1, ""), directory(1, "child")],
        vec![directory(1, ""), directory(2, "")],
        vec![
            directory(1, ""),
            file(2, "a", 2, Some(1), Some(1)),
            file(3, "./a", 3, Some(1), Some(1)),
        ],
        vec![directory(1, ""), directory(2, "missing/child")],
        vec![directory(1, ""), file(2, "missing/file", 2, None, None)],
        vec![
            directory(1, ""),
            file(2, "file", 2, None, None),
            directory(3, "file/child"),
        ],
        vec![
            directory(1, ""),
            entry(2, "link", ResourceKind::Link),
            directory(3, "link/child"),
        ],
        vec![file(1, "", 1, None, None)],
    ] {
        assert_error(report(entries), ScanCode::InvalidRoot);
    }
    for invalid_path in [
        PathBuf::from("relative"),
        path("child/../escape"),
        path("nul\0name"),
        path("").ancestors().last().unwrap().to_path_buf(),
    ] {
        let mut root = directory(1, "");
        root.path = invalid_path;
        assert_error(report(vec![root]), ScanCode::InvalidRoot);
    }
    let mut duplicate_roots = report(vec![directory(1, "")]);
    duplicate_roots.roots.push(path(""));
    assert_error(duplicate_roots, ScanCode::InvalidRoot);
    let mut invalid_root = report(vec![]);
    invalid_root.roots = vec![PathBuf::from("relative")];
    assert_error(invalid_root, ScanCode::InvalidRoot);
    let mut no_roots = report(vec![directory(1, "")]);
    no_roots.roots.clear();
    assert_error(no_roots, ScanCode::InvalidRoot);
}

#[test]
fn checked_overflow_is_explicit_for_direct_files_and_subtree_merges() {
    for nested in [false, true] {
        for logical_overflow in [false, true] {
            let (logical, allocated) = if logical_overflow {
                (Some(u64::MAX), Some(0))
            } else {
                (Some(0), Some(u64::MAX))
            };
            let mut entries = vec![directory(1, "")];
            let first = if nested { "a/file" } else { "a" };
            let second = if nested { "b/file" } else { "b" };
            if nested {
                entries.extend([directory(2, "a"), directory(3, "b")]);
            }
            entries.extend([
                file(4, first, 4, logical, allocated),
                file(5, second, 5, Some(1), Some(1)),
            ]);
            assert_error(report(entries), ScanCode::Overflow);
        }
    }
    let exact_max = tree(vec![
        directory(1, ""),
        file(2, "a", 2, Some(u64::MAX), Some(u64::MAX)),
        file(3, "b", 2, Some(u64::MAX), Some(u64::MAX)),
    ]);
    assert_eq!(exact_max.summary(1), Some(&summary(1, u64::MAX, u64::MAX)));

    // Conflicts are normalized before any sum, not after an erroneous overflow.
    let tree = tree(vec![
        directory(1, ""),
        file(2, "a", 2, Some(u64::MAX), Some(u64::MAX)),
        file(3, "b", 3, Some(1), Some(1)),
        file(4, "c", 2, Some(1), Some(1)),
    ]);
    assert_eq!(tree.summary(1).unwrap().logical_bytes_known, 1);
    assert_eq!(tree.summary(1).unwrap().allocated_bytes_known, 1);
    assert_eq!(tree.summary(1).unwrap().logical_bytes_unknown_files, 1);
    assert_eq!(tree.summary(1).unwrap().allocated_bytes_unknown_files, 1);
}

#[test]
fn limits_use_actual_entries_and_path_bytes_not_claimed_metrics() {
    assert_error(
        report(vec![directory(1, ""); MAX_ENTRIES + 1]),
        ScanCode::EntryLimit,
    );
    let mut entries = Vec::with_capacity(MAX_ENTRIES);
    entries.push(directory(0, ""));
    for id in 1..MAX_ENTRIES as u64 {
        entries.push(entry(id, &format!("link-{id}"), ResourceKind::Link));
    }
    let tree = tree(entries);
    assert_eq!(tree.children(0).unwrap().len(), MAX_ENTRIES - 1);
    assert_eq!(tree.summary(0), Some(&summary(0, 0, 0)));
    drop(tree);

    let root = directory(1, "");
    let mut huge = entry(2, "huge", ResourceKind::Link);
    let remaining = MAX_PATH_BYTES - root.path.as_os_str().len();
    let prefix = path("").as_os_str().len() + 1;
    huge.path = path(&"x".repeat(remaining - prefix));
    let mut at_limit = report(vec![root.clone(), huge.clone()]);
    at_limit.metrics.retained_path_bytes = usize::MAX;
    let tree = ScanTree::build(at_limit, &Cancellation::default()).unwrap();
    assert_eq!(tree.children(1), Some([2].as_slice()));
    huge.path.as_mut_os_string().push("x");
    let mut over_limit = report(vec![root, huge]);
    over_limit.metrics.retained_path_bytes = 0;
    assert_error(over_limit, ScanCode::PathBytesLimit);
}

#[test]
fn deep_hierarchy_moves_bags_without_recursive_expansion() {
    let mut entries = vec![directory(1, "")];
    let mut relative = String::new();
    for level in 1..=1500_u64 {
        if !relative.is_empty() {
            relative.push('/');
        }
        relative.push('d');
        entries.push(directory(level + 1, &relative));
    }
    for number in 0..64_u64 {
        entries.push(file(
            number + 2000,
            &format!("{relative}/file-{number}"),
            number + 2000,
            Some(3),
            Some(7),
        ));
    }
    entries.reverse();
    let tree = tree(entries);
    for id in 1..=1501 {
        assert_eq!(tree.summary(id), Some(&summary(64, 192, 448)));
    }
}

#[test]
fn cancellation_rejects_build_and_merge_without_mutation() {
    let cancellation = Cancellation::default();
    cancellation.cancel();
    assert_eq!(
        ScanTree::build(report(vec![directory(1, "")]), &cancellation)
            .unwrap_err()
            .code,
        ScanCode::Cancelled
    );
    assert_eq!(
        ScanTree::build(report(Vec::new()), &cancellation)
            .unwrap_err()
            .code,
        ScanCode::Cancelled
    );
    let mut bag = IdentityBag::default();
    assert_eq!(
        bag.insert(identity(1), &HashMap::new(), &cancellation)
            .unwrap_err()
            .code,
        ScanCode::Cancelled
    );
    assert_eq!(
        bag.merge(IdentityBag::default(), &HashMap::new(), &cancellation)
            .unwrap_err()
            .code,
        ScanCode::Cancelled
    );
    assert!(bag.identities.is_empty());
}

#[cfg(unix)]
#[test]
fn native_non_utf8_path_order_is_preserved() {
    use std::os::unix::ffi::OsStringExt;
    let mut entries = vec![directory(1, "")];
    for (id, bytes) in [(2, vec![0xff]), (3, vec![0x80]), (4, vec![b'a'])] {
        let mut child = entry(id, "unused", ResourceKind::File);
        child.path = path("").join(std::ffi::OsString::from_vec(bytes));
        entries.push(child);
    }
    let tree = tree(entries);
    assert_eq!(tree.children(1), Some([4, 3, 2].as_slice()));
}
