// SPDX-License-Identifier: MPL-2.0

use super::*;
use crate::scan::{ScanIssue, ScanMetrics, ScanReport, ScanStatus, ScanTotals};
use std::path::PathBuf;

fn path(relative: &str) -> PathBuf {
    let base = if cfg!(windows) {
        PathBuf::from("C:/directory-review-fixture")
    } else {
        PathBuf::from("/directory-review-fixture")
    };
    if relative.is_empty() {
        base
    } else {
        base.join(relative)
    }
}

fn entry(id: u64, relative: &str, kind: ResourceKind) -> ScanEntry {
    ScanEntry {
        id,
        path: path(relative),
        kind,
        identity: FileIdentity::Unix {
            device: 7,
            inode: id,
        },
        logical_bytes: (kind == ResourceKind::File).then_some(8),
        allocated_bytes: (kind == ResourceKind::File).then_some(4096),
        dataless: false,
        counted: false,
        depth: usize::MAX,
    }
}

fn report(entries: Vec<ScanEntry>) -> ScanReport {
    ScanReport {
        task_id: ScanTaskId::synthetic(1),
        roots: vec![path("")],
        status: ScanStatus::Complete,
        complete: true,
        entries,
        issues: vec![],
        issues_omitted: 0,
        totals: ScanTotals::default(),
        metrics: ScanMetrics::default(),
    }
}

fn fixture() -> Vec<ScanEntry> {
    vec![
        entry(1, "", ResourceKind::Directory),
        entry(2, "target", ResourceKind::Directory),
        entry(3, "target/nested", ResourceKind::Directory),
        entry(4, "target/nested/a", ResourceKind::File),
        entry(5, "outside", ResourceKind::File),
    ]
}

fn selection(tree: &ScanTree, directory_id: u64) -> DirectorySelection {
    DirectorySelection {
        task_id: tree.report().task_id,
        scope_id: 1,
        directory_id,
    }
}

fn has(review: &DirectoryAssessment<'_>, code: DirectoryBlockerCode) -> bool {
    review.blockers().iter().any(|blocker| blocker.code == code)
}

#[test]
fn unsafe_observed_ancestry_is_not_hidden_by_a_clean_subtree() {
    let mut entries = fixture();
    entries[0].dataless = true;
    entries[1].identity = FileIdentity::Unix {
        device: 8,
        inode: 2,
    };
    let tree = ScanTree::build(report(entries), &Cancellation::default()).unwrap();
    let review =
        assess_directory(&tree, selection(&tree, 3), &[], &Cancellation::default()).unwrap();
    assert_eq!(
        review.ancestors().map(|entry| entry.id).collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert_eq!(
        review.counts().dataless,
        0,
        "counts describe the selected subtree only"
    );
    assert!(
        review
            .blockers()
            .iter()
            .any(|blocker| blocker.entry_id == 1 && blocker.code == DirectoryBlockerCode::Dataless)
    );
    assert!(review.blockers().iter().any(|blocker| blocker.entry_id == 2
        && blocker.code == DirectoryBlockerCode::VolumeIdentityMismatch));
}

#[test]
fn coarse_protection_policy_and_multiple_roots_are_not_bypassed() {
    let mut input = report(fixture());
    input.roots.push(path("target"));
    let tree = ScanTree::build(input, &Cancellation::default()).unwrap();
    assert!(assess_directory(&tree, selection(&tree, 2), &[], &Cancellation::default()).is_err());
    #[cfg(unix)]
    {
        let mut entries = vec![
            entry(1, "", ResourceKind::Directory),
            entry(2, "target", ResourceKind::Directory),
        ];
        entries[0].path = PathBuf::from("/System");
        entries[1].path = PathBuf::from("/System/owned-name-does-not-authorize");
        let mut input = report(entries);
        input.roots = vec![PathBuf::from("/System")];
        let tree = ScanTree::build(input, &Cancellation::default()).unwrap();
        let review =
            assess_directory(&tree, selection(&tree, 2), &[], &Cancellation::default()).unwrap();
        assert!(has(&review, DirectoryBlockerCode::ProtectedLocation));
    }
}

#[test]
fn complete_observations_never_become_native_authority() {
    let tree = ScanTree::build(report(fixture()), &Cancellation::default()).unwrap();
    let assessment =
        assess_directory(&tree, selection(&tree, 2), &[], &Cancellation::default()).unwrap();
    assert_eq!(
        assessment
            .members()
            .map(|entry| entry.id)
            .collect::<Vec<_>>(),
        vec![2, 3, 4]
    );
    assert_eq!(assessment.counts().entries, 3);
    assert_eq!(assessment.counts().directories, 2);
    assert_eq!(assessment.counts().file_names, 1);
    assert_eq!(assessment.summary().unique_files, 1);
    assert_eq!(assessment.summary().logical_bytes_known, 8);
    assert!(assessment.blockers().is_empty());
    assert_eq!(
        assessment.execution_contract(),
        ExecutionContract::ModelOnly
    );
    for gate in [
        UnverifiedDirectoryGate::OwnershipPermissionsAndAcl,
        UnverifiedDirectoryGate::FullSubtreeCoverage,
        UnverifiedDirectoryGate::ExternalLinksAndExclusionResolution,
        UnverifiedDirectoryGate::ApprovedDirectoryExecutionAndRecoveryContract,
    ] {
        assert!(assessment.unverified_gates().contains(&gate));
    }
    assert_eq!(tree.report().totals.logical_bytes_known, 0);
}

#[test]
fn selection_is_task_root_type_and_id_bound() {
    let tree = ScanTree::build(report(fixture()), &Cancellation::default()).unwrap();
    let mut stale = selection(&tree, 2);
    stale.task_id = ScanTaskId::synthetic(2);
    assert_eq!(
        assess_directory(&tree, stale, &[], &Cancellation::default())
            .unwrap_err()
            .code,
        ScanCode::ChangedEntry
    );
    for request in [
        DirectorySelection {
            scope_id: 2,
            ..selection(&tree, 3)
        },
        selection(&tree, 4),
        selection(&tree, 999),
    ] {
        assert_eq!(
            assess_directory(&tree, request, &[], &Cancellation::default())
                .unwrap_err()
                .code,
            ScanCode::InvalidRoot
        );
    }
    let root = assess_directory(&tree, selection(&tree, 1), &[], &Cancellation::default()).unwrap();
    assert!(has(&root, DirectoryBlockerCode::ScopeRoot));
    assert_eq!(root.scope().id, root.directory().id);
}

#[test]
fn descendant_ancestor_and_aliased_exclusions_block_whole_container() {
    let mut entries = fixture();
    entries[4].identity = entries[3].identity;
    let tree = ScanTree::build(report(entries), &Cancellation::default()).unwrap();
    for excluded in [1, 2, 3, 4] {
        let review = assess_directory(
            &tree,
            selection(&tree, 2),
            &[excluded],
            &Cancellation::default(),
        )
        .unwrap();
        assert!(has(&review, DirectoryBlockerCode::ExcludedOverlap));
        assert_eq!(
            review.members().count(),
            3,
            "exclusions do not subtract children from a container"
        );
    }
    let alias =
        assess_directory(&tree, selection(&tree, 2), &[5], &Cancellation::default()).unwrap();
    assert!(has(&alias, DirectoryBlockerCode::ExcludedIdentityAlias));
    assert!(has(&alias, DirectoryBlockerCode::ObservedFileAlias));
    assert!(
        assess_directory(&tree, selection(&tree, 2), &[999], &Cancellation::default()).is_err()
    );
    assert!(
        assess_directory(
            &tree,
            selection(&tree, 2),
            &[5, 5],
            &Cancellation::default()
        )
        .is_err()
    );
    assert_eq!(
        assess_directory(
            &tree,
            selection(&tree, 2),
            &[5; 33],
            &Cancellation::default()
        )
        .unwrap_err()
        .code,
        ScanCode::InvalidLimits
    );
}

#[test]
fn partial_failed_cancelled_and_omitted_coverage_stay_blocked() {
    for status in [
        ScanStatus::Partial,
        ScanStatus::Failed,
        ScanStatus::Cancelled,
    ] {
        let mut input = report(fixture());
        input.status = status;
        let tree = ScanTree::build(input, &Cancellation::default()).unwrap();
        let review =
            assess_directory(&tree, selection(&tree, 2), &[], &Cancellation::default()).unwrap();
        assert!(has(&review, DirectoryBlockerCode::IncompleteScan));
    }
    // A partial scan whose only gap lies outside the selection still blocks.
    let mut input = report(fixture());
    input.status = ScanStatus::Partial;
    input.complete = false;
    input.issues.push(ScanIssue {
        path: Some(path("unread")),
        code: ScanCode::PermissionDenied,
        message: "synthetic coverage gap".into(),
        os_code: None,
    });
    let tree = ScanTree::build(input, &Cancellation::default()).unwrap();
    assert!(tree.summary(2).unwrap().complete);
    assert!(has(
        &assess_directory(&tree, selection(&tree, 2), &[], &Cancellation::default()).unwrap(),
        DirectoryBlockerCode::IncompleteScan
    ));
    for omitted in [false, true] {
        let mut input = report(fixture());
        if omitted {
            input.issues_omitted = 1;
        } else {
            input.issues.push(ScanIssue {
                path: Some(path("outside")),
                code: ScanCode::PermissionDenied,
                message: "synthetic coverage gap".into(),
                os_code: None,
            });
        }
        let tree = ScanTree::build(input, &Cancellation::default()).unwrap();
        assert!(has(
            &assess_directory(&tree, selection(&tree, 2), &[], &Cancellation::default()).unwrap(),
            DirectoryBlockerCode::IncompleteScan
        ));
    }
}

#[test]
fn links_special_dataless_and_volume_changes_are_not_ignored() {
    let mut entries = fixture();
    entries.push(entry(6, "target/link", ResourceKind::Link));
    entries.push(entry(7, "target/socket", ResourceKind::Other));
    let mut cloud = entry(8, "target/cloud", ResourceKind::Directory);
    cloud.dataless = true;
    entries.push(cloud);
    let mut external = entry(9, "target/other-volume", ResourceKind::Directory);
    external.identity = FileIdentity::Unix {
        device: 8,
        inode: 9,
    };
    entries.push(external);
    let tree = ScanTree::build(report(entries), &Cancellation::default()).unwrap();
    let review =
        assess_directory(&tree, selection(&tree, 2), &[], &Cancellation::default()).unwrap();
    for code in [
        DirectoryBlockerCode::Link,
        DirectoryBlockerCode::SpecialEntry,
        DirectoryBlockerCode::Dataless,
        DirectoryBlockerCode::VolumeIdentityMismatch,
    ] {
        assert!(has(&review, code));
    }
    assert_eq!(
        (
            review.counts().links,
            review.counts().other,
            review.counts().dataless
        ),
        (1, 1, 1)
    );
}

#[test]
fn alias_and_unknown_counts_use_existing_index_accounting() {
    let mut entries = fixture();
    let mut alias = entry(6, "target/nested/alias", ResourceKind::File);
    alias.identity = entries[3].identity;
    entries.push(alias);
    let mut directory_alias = entry(7, "directory-alias", ResourceKind::Directory);
    directory_alias.identity = entries[2].identity;
    entries.push(directory_alias);
    let tree = ScanTree::build(report(entries), &Cancellation::default()).unwrap();
    let review =
        assess_directory(&tree, selection(&tree, 2), &[], &Cancellation::default()).unwrap();
    assert_eq!(review.counts().file_names, 2);
    assert_eq!(review.summary().unique_files, 1);
    assert_eq!(review.summary().logical_bytes_known, 8);
    assert!(has(&review, DirectoryBlockerCode::ObservedFileAlias));
    assert!(has(&review, DirectoryBlockerCode::ObservedDirectoryAlias));
    let mut unknown = fixture();
    unknown[3].logical_bytes = None;
    let tree = ScanTree::build(report(unknown), &Cancellation::default()).unwrap();
    let review =
        assess_directory(&tree, selection(&tree, 2), &[], &Cancellation::default()).unwrap();
    assert_eq!(review.summary().logical_bytes_unknown_files, 1);
    assert!(has(&review, DirectoryBlockerCode::UnknownMeasurements));
}

#[test]
fn pruned_or_empty_observations_do_not_prove_native_closure() {
    let mut entries = fixture();
    entries.truncate(2);
    entries[1].path = path("Example.app");
    let tree = ScanTree::build(report(entries), &Cancellation::default()).unwrap();
    let review =
        assess_directory(&tree, selection(&tree, 2), &[], &Cancellation::default()).unwrap();
    assert!(review.summary().complete);
    assert_eq!(review.summary().unique_files, 0);
    assert!(
        review
            .unverified_gates()
            .contains(&UnverifiedDirectoryGate::NativePackageAndProtectedLocations)
    );
    assert!(
        review
            .unverified_gates()
            .contains(&UnverifiedDirectoryGate::FullSubtreeCoverage)
    );
    assert_eq!(review.execution_contract(), ExecutionContract::ModelOnly);
}

#[test]
fn blocker_examples_are_bounded_without_hiding_their_count() {
    let mut entries = fixture();
    for index in 0..200 {
        entries.push(entry(
            10 + index,
            &format!("target/link-{index}"),
            ResourceKind::Link,
        ));
    }
    let tree = ScanTree::build(report(entries), &Cancellation::default()).unwrap();
    let review =
        assess_directory(&tree, selection(&tree, 2), &[], &Cancellation::default()).unwrap();
    assert_eq!(review.blockers().len(), MAX_BLOCKER_EXAMPLES);
    assert_eq!(review.blockers_omitted(), 200 - MAX_BLOCKER_EXAMPLES);
    assert_eq!(review.counts().links, 200);
}

#[test]
fn cancelled_review_returns_an_error_not_an_empty_success() {
    let tree = ScanTree::build(report(fixture()), &Cancellation::default()).unwrap();
    let cancel = Cancellation::default();
    cancel.cancel();
    assert_eq!(
        assess_directory(&tree, selection(&tree, 2), &[], &cancel)
            .unwrap_err()
            .code,
        ScanCode::Cancelled
    );
}
