// SPDX-License-Identifier: MPL-2.0

#![cfg(target_os = "macos")]

use sayaka_engine::execute::TrashSession;
use sayaka_engine::model::{Cancellation, ExecutionContract, FileIdentity, Scope};
use sayaka_engine::scan::directory_review::{DirectorySelection, assess_directory};
use sayaka_engine::scan::index::ScanTree;
use sayaka_engine::scan::{self, ScanLimits};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

#[path = "support/owned_temp.rs"]
mod owned_temp;

fn scanned(root: &Path) -> ScanTree {
    let cancellation = Cancellation::default();
    ScanTree::build(
        scan::scan(
            &[root.to_path_buf()],
            &ScanLimits::default(),
            &cancellation,
            |_| {},
        )
        .unwrap(),
        &cancellation,
    )
    .unwrap()
}

fn selection(tree: &ScanTree, scope: &Path, target: &Path) -> DirectorySelection {
    let id = |path| {
        tree.report()
            .entries
            .iter()
            .find(|entry| entry.path == path)
            .unwrap()
            .id
    };
    DirectorySelection {
        task_id: tree.report().task_id,
        scope_id: id(scope),
        directory_id: id(target),
    }
}

fn directory_stamp(path: &Path) -> (u64, u64, i64, i64, i64, i64) {
    let meta = fs::symlink_metadata(path).unwrap();
    (
        meta.dev(),
        meta.ino(),
        meta.mtime(),
        meta.mtime_nsec(),
        meta.ctime(),
        meta.ctime_nsec(),
    )
}

#[test]
fn inode_stable_directory_can_move_contents_absent_from_the_prior_inventory() {
    let fixture = owned_temp::OwnedTempDir::new(
        Path::new(env!("CARGO_MANIFEST_DIR")),
        "sayaka-directory-observation-",
    )
    .unwrap();
    let scope = fixture.path().join("scope");
    let directory = scope.join("container");
    let nested = directory.join("nested");
    fs::create_dir_all(&nested).unwrap();
    fs::write(nested.join("observed.txt"), b"observed").unwrap();
    let original_stamp = directory_stamp(&directory);
    let original_tree = scanned(&scope);
    let selected = selection(&original_tree, &scope, &directory);
    let review = assess_directory(&original_tree, selected, &[], &Cancellation::default()).unwrap();
    assert_eq!(review.summary().unique_files, 1);
    assert!(review.blockers().is_empty());
    assert_eq!(review.execution_contract(), ExecutionContract::ModelOnly);

    fs::write(nested.join("late.txt"), b"not in the prior inventory").unwrap();
    assert_eq!(
        directory_stamp(&directory),
        original_stamp,
        "only a nested directory changed"
    );
    assert!(
        !review
            .members()
            .any(|entry| entry.path.ends_with("late.txt"))
    );
    // This is an owned in-fixture namespace experiment, not a Trash operation.
    let parent = rustix::fs::open(
        &scope,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::from_bits_retain(0x2000_0000),
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    rustix::fs::renameat_with(
        &parent,
        "container",
        &parent,
        "relocated",
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .unwrap();
    let relocated = scope.join("relocated");
    let metadata = fs::symlink_metadata(&relocated).unwrap();
    assert_eq!(
        (metadata.dev(), metadata.ino()),
        (original_stamp.0, original_stamp.1)
    );
    assert_eq!(
        fs::read(relocated.join("nested/observed.txt")).unwrap(),
        b"observed"
    );
    assert_eq!(
        fs::read(relocated.join("nested/late.txt")).unwrap(),
        b"not in the prior inventory"
    );
    assert_eq!(
        review.directory().identity,
        FileIdentity::Unix {
            device: metadata.dev(),
            inode: metadata.ino()
        }
    );
    assert!(!directory.exists());

    let fresh_tree = scanned(&scope);
    let fresh = assess_directory(
        &fresh_tree,
        selection(&fresh_tree, &scope, &relocated),
        &[],
        &Cancellation::default(),
    )
    .unwrap();
    assert_eq!(fresh.summary().unique_files, 2);
    assert!(assess_directory(&fresh_tree, selected, &[], &Cancellation::default()).is_err());

    let session = TrashSession::prepare(
        Scope::new(scope.clone(), vec![]).unwrap(),
        &[relocated],
        &[],
        &Cancellation::default(),
    )
    .unwrap();
    assert!(
        session.preview().items().is_empty(),
        "file-only Trash must still refuse directories"
    );
    assert!(!session.refusals().is_empty());
    drop(session);
    drop(parent);
    fixture.close().unwrap();
}

#[test]
fn excluded_descendant_blocks_the_container_without_removing_it_from_observations() {
    let fixture = owned_temp::OwnedTempDir::new(
        Path::new(env!("CARGO_MANIFEST_DIR")),
        "sayaka-directory-exclusion-",
    )
    .unwrap();
    let scope = fixture.path().join("scope");
    let target = scope.join("container");
    fs::create_dir_all(&target).unwrap();
    let keep = target.join("keep.txt");
    fs::write(&keep, b"must stay").unwrap();
    let tree = scanned(&scope);
    let excluded = tree
        .report()
        .entries
        .iter()
        .find(|entry| entry.path == keep)
        .unwrap()
        .id;
    let review = assess_directory(
        &tree,
        selection(&tree, &scope, &target),
        &[excluded],
        &Cancellation::default(),
    )
    .unwrap();
    assert!(review.blockers().iter().any(
        |blocker| blocker.code == scan::directory_review::DirectoryBlockerCode::ExcludedOverlap
    ));
    assert!(review.members().any(|entry| entry.path == keep));
    assert_eq!(fs::read(&keep).unwrap(), b"must stay");
    assert!(target.is_dir());
    fixture.close().unwrap();
}
