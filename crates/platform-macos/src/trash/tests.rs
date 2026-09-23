// SPDX-License-Identifier: MPL-2.0

use super::*;
use crate::{
    BundleTrashCandidate, CacheTrashCandidate, PurgeTrashCandidate, TrashCandidate, full_sync,
    has_extended_acl,
};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

#[path = "installer_roundtrip.rs"]
mod installer_roundtrip;

struct Fixture {
    root: PathBuf,
    anchors: Vec<Evidence>,
    objects: Vec<(PathBuf, (u64, u64), bool)>,
    cleaned: bool,
    preserve: bool,
    _lock: MutexGuard<'static, ()>,
}

impl Fixture {
    fn new() -> Self {
        let lock = FIXTURE_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let base = fs::canonicalize(std::env::current_dir().unwrap()).unwrap();
        let anchors = base
            .ancestors()
            .map(|path| Evidence::open(path).unwrap())
            .collect();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = base.join(format!(
            "native-trash-fixture-{}-{nonce}",
            std::process::id()
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let identity = Stamp::read(&fs::symlink_metadata(&root).unwrap()).identity();
        let mut fixture = Self {
            root: root.clone(),
            anchors,
            objects: vec![(root, identity, true)],
            cleaned: false,
            preserve: false,
            _lock: lock,
        };
        fixture.file(
            "ownership-marker",
            b"synthetic native fixture; this process only",
        );
        fixture
    }

    fn record(&mut self, path: PathBuf, directory: bool) -> PathBuf {
        let identity = Stamp::read(&fs::symlink_metadata(&path).unwrap()).identity();
        self.objects.push((path.clone(), identity, directory));
        path
    }

    fn file(&mut self, name: &str, bytes: &[u8]) -> PathBuf {
        self.file_named(OsStr::new(name), bytes)
    }

    fn file_named(&mut self, name: &OsStr, bytes: &[u8]) -> PathBuf {
        use std::io::Write;
        let path = self.root.join(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(bytes).unwrap();
        self.record(path, false)
    }

    fn directory(&mut self, name: &str) -> PathBuf {
        let path = self.root.join(name);
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        self.record(path, true)
    }

    fn rename(&mut self, source: &Path, destination: &Path) {
        fs::rename(source, destination).unwrap();
        for (path, _, _) in &mut self.objects {
            if let Ok(suffix) = path.strip_prefix(source) {
                *path = if suffix.as_os_str().is_empty() {
                    destination.to_owned()
                } else {
                    destination.join(suffix)
                };
            }
        }
    }

    fn cleanup(&mut self) -> io::Result<()> {
        for anchor in &self.anchors {
            let current = Evidence::open(&anchor.path)?;
            if current.stamp.identity() != anchor.stamp.identity()
                || current.physical != anchor.physical
            {
                return Err(refused("fixture cleanup ancestor changed"));
            }
        }
        // No broad cleanup: only exact registered identities, deepest first.
        self.objects.sort_by_key(|(path, _, directory)| {
            (std::cmp::Reverse(path.components().count()), *directory)
        });
        while let Some((path, identity, directory)) = self.objects.first() {
            if !path.starts_with(&self.root) {
                return Err(refused("fixture cleanup escaped its registered root"));
            }
            let metadata = fs::symlink_metadata(path)?;
            if Stamp::read(&metadata).identity() != *identity {
                return Err(refused("fixture cleanup identity mismatch"));
            }
            if let Some(parent) = path.parent() {
                let _parent = Evidence::open(parent)?;
            }
            if *directory {
                fs::remove_dir(path)?;
            } else {
                fs::remove_file(path)?;
            }
            self.objects.remove(0);
        }
        self.cleaned = true;
        Ok(())
    }

    fn finish(mut self) {
        self.cleanup()
            .expect("identity-specific fixture cleanup must succeed");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if !self.cleaned
            && !self.preserve
            && let Err(error) = self.cleanup()
        {
            eprintln!("native fixture cleanup failed: {error}");
        }
    }
}

#[test]
fn native_capture_revalidation_and_cancellation_have_no_trash_effect() {
    let mut fixture = Fixture::new();
    let path = fixture.file("ordinary.txt", b"synthetic");
    let before_policy = crate::get_policy().unwrap();
    let candidate = TrashCandidate::capture(&fixture.root, &path, &[]).unwrap();
    assert_eq!(candidate.path(), path);
    assert_eq!(candidate.info().logical_bytes, 9);
    candidate.revalidate().unwrap();
    let mut called = false;
    let result = candidate.move_to_trash(|| {
        called = true;
        true
    });
    assert!(called);
    assert!(matches!(result, NativeTrashOutcome::Refused(reason) if reason == "cancelled"));
    assert_eq!(crate::get_policy().unwrap(), before_policy);
    assert_eq!(fs::read(&path).unwrap(), b"synthetic");
    assert!(matches!(
        candidate.move_to_trash(|| panic!("a consumed candidate must never retry")),
        NativeTrashOutcome::Refused(_)
    ));
    drop(candidate);
    fixture.finish();
}

#[test]
fn source_bound_capture_retains_rule_witnesses_without_native_effect() {
    let mut fixture = Fixture::new();
    let pkg = fixture.directory("pkg");
    let cache = fixture.directory("pkg/__pycache__");
    let source = fixture.file("pkg/module.py", b"print('ok')\n");
    let target = fixture.file("pkg/__pycache__/module.cpython-39.pyc", &[1, 2, 3, 4]);
    let candidate =
        TrashCandidate::capture_with_source(&fixture.root, &target, &source, &[]).unwrap();
    candidate.revalidate().unwrap();
    let witness = candidate
        .rule_binding_witness()
        .expect("source-bound candidate must retain rule witness");
    assert_eq!(witness.target.path, target);
    assert_eq!(witness.source.path, source);
    assert_eq!(witness.root.path, fixture.root);
    assert!(
        witness
            .target_ancestors
            .iter()
            .any(|entry| entry.path == cache)
    );
    assert!(
        witness
            .source_ancestors
            .iter()
            .any(|entry| entry.path == pkg)
    );
    drop(candidate);
    fixture.finish();
}

#[test]
fn source_bound_revalidate_refuses_changed_source_before_effect() {
    let mut fixture = Fixture::new();
    fixture.directory("pkg");
    fixture.directory("pkg/__pycache__");
    let source = fixture.file("pkg/module.py", b"print('ok')\n");
    let target = fixture.file("pkg/__pycache__/module.cpython-39.pyc", &[1, 2, 3, 4]);
    let candidate =
        TrashCandidate::capture_with_source(&fixture.root, &target, &source, &[]).unwrap();
    fs::write(&source, b"print('changed')\n").unwrap();
    assert!(candidate.revalidate().is_err());
    let outcome = candidate.move_to_trash(|| panic!("must refuse before native callback"));
    assert!(matches!(outcome, NativeTrashOutcome::Refused(_)));
    drop(candidate);
    fixture.finish();
}

#[test]
fn source_bound_revalidate_refuses_replaced_source_identity_before_effect() {
    let mut fixture = Fixture::new();
    fixture.directory("pkg");
    fixture.directory("pkg/__pycache__");
    let source = fixture.file("pkg/module.py", b"print('ok')\n");
    let target = fixture.file("pkg/__pycache__/module.cpython-39.pyc", &[9, 8, 7, 6]);
    let candidate =
        TrashCandidate::capture_with_source(&fixture.root, &target, &source, &[]).unwrap();
    let retained = fixture.root.join("retained-source.py");
    fixture.rename(&source, &retained);
    fixture.file("pkg/module.py", b"print('replacement')\n");
    assert!(candidate.revalidate().is_err());
    let outcome = candidate.move_to_trash(|| panic!("must refuse before native callback"));
    assert!(matches!(outcome, NativeTrashOutcome::Refused(_)));
    drop(candidate);
    fixture.finish();
}

#[test]
fn source_bound_marker_refuses_mismatch_before_native_effect() {
    let mut fixture = Fixture::new();
    fixture.directory("pkg");
    let source = fixture.file("pkg/Foo.java", b"class Foo {}\n");
    let target = fixture.file("pkg/Foo.class", &[0, 1, 2, 3, 4, 5]);
    let candidate = TrashCandidate::capture_with_source_and_marker(
        &fixture.root,
        &target,
        &source,
        Some(super::NativeTargetMarker::Prefix4([0xCA, 0xFE, 0xBA, 0xBE])),
        &[],
    );
    assert!(candidate.is_err());
    fixture.finish();
}

#[test]
fn destination_probe_tolerates_changed_time_during_acl_capture_after_owned_rename() {
    let mut fixture = Fixture::new();
    let source = fixture.file("before.pyc", b"synthetic-cache");
    let renamed = fixture.root.join("after.pyc");
    fixture.rename(&source, &renamed);
    super::set_test_probe_hook(Some((
        super::TestProbeStage::Complete,
        super::TestProbeMutation::Changed,
    )));
    let probe = super::verify_destination_probe_for_test(&renamed);
    super::set_test_probe_hook(None);
    probe.unwrap();
    fixture.finish();
}

#[test]
fn post_move_capture_anchor_accepts_consistent_changed_time_transition() {
    super::post_move_capture_anchor_probe_for_test().unwrap();
}

#[test]
fn post_move_matrix_strict_fields_fail_and_changed_time_only_passes() {
    let strict_failures = [
        super::TestProbeMutation::Device,
        super::TestProbeMutation::Inode,
        super::TestProbeMutation::Mode,
        super::TestProbeMutation::Uid,
        super::TestProbeMutation::Gid,
        super::TestProbeMutation::Nlink,
        super::TestProbeMutation::Flags,
        super::TestProbeMutation::Size,
        super::TestProbeMutation::Blocks,
        super::TestProbeMutation::Modified,
        super::TestProbeMutation::Created,
    ];
    for mutation in strict_failures {
        assert!(super::post_move_consistency_probe_for_test(None, Some(mutation), true).is_err());
    }
    assert!(
        super::post_move_consistency_probe_for_test(
            Some(super::TestProbeMutation::Changed),
            None,
            true
        )
        .is_err()
    );
    assert!(
        super::post_move_consistency_probe_for_test(
            None,
            Some(super::TestProbeMutation::ChangedAndSize),
            true
        )
        .is_err()
    );
    assert!(super::post_move_consistency_probe_for_test(None, None, false).is_err());
    assert!(super::post_move_consistency_probe_for_test(None, None, true).is_ok());
}

#[test]
fn post_move_anchor_revalidate_refuses_changed_time_after_capture() {
    let mut fixture = Fixture::new();
    let source = fixture.file("before-anchor.pyc", b"synthetic-cache");
    let renamed = fixture.root.join("after-anchor.pyc");
    fixture.rename(&source, &renamed);
    let probe = super::verify_destination_anchor_probe_for_test(
        &renamed,
        Some((
            super::TestProbeStage::OpenHandle,
            super::TestProbeMutation::Changed,
        )),
    );
    assert!(probe.is_err());
    fixture.finish();
}

#[test]
fn post_move_anchor_revalidate_accepts_stable_destination() {
    let mut fixture = Fixture::new();
    let source = fixture.file("before-anchor-ok.pyc", b"synthetic-cache");
    let renamed = fixture.root.join("after-anchor-ok.pyc");
    fixture.rename(&source, &renamed);
    super::verify_destination_anchor_probe_for_test(&renamed, None).unwrap();
    fixture.finish();
}

#[test]
fn pre_effect_full_target_refuses_changed_time_and_blocks() {
    let mut fixture = Fixture::new();
    let file = fixture.file("strict-pre-effect.pyc", b"strict");

    super::set_test_probe_hook(Some((
        super::TestProbeStage::OpenHandle,
        super::TestProbeMutation::Changed,
    )));
    assert!(super::full_target_capture_probe_for_test(&file).is_err());

    super::set_test_probe_hook(Some((
        super::TestProbeStage::OpenHandle,
        super::TestProbeMutation::Blocks,
    )));
    assert!(super::full_target_capture_probe_for_test(&file).is_err());
    super::set_test_probe_hook(None);
    fixture.finish();
}

#[test]
fn native_non_utf8_path_is_preserved_or_explicitly_rejected_by_apfs() {
    let mut fixture = Fixture::new();
    let path = fixture.root.join(OsStr::from_bytes(b"native-\xff.txt"));
    valid_path(&path).unwrap();
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
    {
        Ok(file) => {
            drop(file);
            fixture.record(path.clone(), false);
            let candidate = TrashCandidate::capture(&fixture.root, &path, &[]).unwrap();
            assert_eq!(
                candidate.path().as_os_str().as_bytes(),
                path.as_os_str().as_bytes()
            );
            candidate.revalidate().unwrap();
        }
        Err(error) => {
            // APFS normally rejects invalid UTF-8 with EILSEQ. This is native
            // refusal evidence, not a claim that such a file was captured.
            assert_eq!(error.raw_os_error(), Some(libc::EILSEQ));
            assert!(TrashCandidate::capture(&fixture.root, &path, &[]).is_err());
        }
    }
    fixture.finish();
}

#[test]
fn changed_contents_are_refused_before_cancellation_or_native_call() {
    let mut fixture = Fixture::new();
    let path = fixture.file("changed.txt", b"first");
    let candidate = TrashCandidate::capture(&fixture.root, &path, &[]).unwrap();
    fs::write(&path, b"changed length").unwrap();
    assert!(candidate.revalidate().is_err());
    let outcome = candidate.move_to_trash(|| panic!("must refuse before callback"));
    assert!(matches!(outcome, NativeTrashOutcome::Refused(_)));
    drop(candidate);
    fixture.finish();
}

#[test]
fn replaced_target_is_not_readmitted() {
    let mut fixture = Fixture::new();
    let path = fixture.file("selected.txt", b"original");
    let candidate = TrashCandidate::capture(&fixture.root, &path, &[]).unwrap();
    let retained = fixture.root.join("retained.txt");
    fixture.rename(&path, &retained);
    fixture.file("selected.txt", b"substitute");
    assert!(candidate.revalidate().is_err());
    assert_eq!(fs::read(retained).unwrap(), b"original");
    drop(candidate);
    fixture.finish();
}

#[test]
fn replaced_ancestor_is_not_readmitted() {
    let mut fixture = Fixture::new();
    let parent = fixture.directory("parent");
    let path = fixture.file("parent/selected.txt", b"original");
    let candidate = TrashCandidate::capture(&fixture.root, &path, &[]).unwrap();
    let retained = fixture.root.join("retained-parent");
    fixture.rename(&parent, &retained);
    fixture.directory("parent");
    fixture.file("parent/selected.txt", b"substitute");
    assert!(candidate.revalidate().is_err());
    drop(candidate);
    fixture.finish();
}

#[test]
fn hard_links_are_rejected_initially_and_after_capture() {
    let mut fixture = Fixture::new();
    let path = fixture.file("selected.txt", b"original");
    let candidate = TrashCandidate::capture(&fixture.root, &path, &[]).unwrap();
    let alias = fixture.root.join("alias.txt");
    fs::hard_link(&path, &alias).unwrap();
    fixture.record(alias, false);
    assert!(candidate.revalidate().is_err());
    assert!(TrashCandidate::capture(&fixture.root, &path, &[]).is_err());
    drop(candidate);
    fixture.finish();
}

#[test]
fn target_and_ancestor_symlinks_are_refused() {
    let mut fixture = Fixture::new();
    let parent = fixture.directory("parent");
    let path = fixture.file("parent/selected.txt", b"original");
    let file_alias = fixture.root.join("file-link");
    symlink(&path, &file_alias).unwrap();
    fixture.record(file_alias.clone(), false);
    let directory_alias = fixture.root.join("directory-link");
    symlink(parent, &directory_alias).unwrap();
    fixture.record(directory_alias.clone(), false);
    assert!(TrashCandidate::capture(&fixture.root, &file_alias, &[]).is_err());
    assert!(
        TrashCandidate::capture(&fixture.root, &directory_alias.join("selected.txt"), &[]).is_err()
    );
    fixture.finish();
}

#[test]
fn protected_case_alias_and_physical_alias_are_refused() {
    let mut fixture = Fixture::new();
    let parent = fixture.directory("Excluded");
    let path = fixture.file("Excluded/selected.txt", b"original");
    assert!(TrashCandidate::capture(&fixture.root, &path, std::slice::from_ref(&parent)).is_err());
    // The comparison policy is case-insensitive even on case-sensitive APFS.
    assert!(folded_beneath(&path, &fixture.root.join("excluded")));
    let alias = fixture.root.join("protection-link");
    symlink(&parent, &alias).unwrap();
    fixture.record(alias.clone(), false);
    assert!(TrashCandidate::capture(&fixture.root, &path, &[alias]).is_err());
    fixture.finish();
}

#[test]
fn exclusions_match_case_overlap_without_confusing_missing_siblings() {
    let mut fixture = Fixture::new();
    let parent = fixture.directory("SelectedParent");
    let path = fixture.file("SelectedParent/Selected.txt", b"selected");
    let unrelated = fixture.file("unrelated.txt", b"not selected");
    let candidate = TrashCandidate::capture(&fixture.root, &path, &[]).unwrap();
    for (original, alias) in [
        (&path, parent.join("selected.txt")),
        (&parent, fixture.root.join("selectedparent")),
    ] {
        match fs::symlink_metadata(&alias) {
            Ok(metadata) => assert_eq!(
                Stamp::read(&metadata).identity(),
                Stamp::read(&fs::symlink_metadata(original).unwrap()).identity(),
                "native case alias must refer to the same existing object",
            ),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                // Case-sensitive APFS need not resolve this spelling. Our
                // lexical overlap remains intentionally conservative there.
                assert!(folded_beneath(original, &alias));
            }
            Err(error) => panic!("unexpected native case lookup error: {error}"),
        }
        assert!(candidate.matches_exclusion(&alias).unwrap());
    }
    assert!(candidate.matches_exclusion(&path).unwrap());
    assert!(!candidate.matches_exclusion(&unrelated).unwrap());
    assert!(
        !candidate
            .matches_exclusion(&fixture.root.join("missing-sibling"))
            .unwrap()
    );
    assert!(
        !candidate
            .matches_exclusion(&parent.join("missing-child"))
            .unwrap()
    );
    fixture.finish();
}

#[test]
fn exclusions_match_native_unicode_aliases_and_selected_file_prefixes() {
    let mut fixture = Fixture::new();
    let parent = fixture.directory("R\u{e9}sum\u{e9}");
    let path = fixture.file("R\u{e9}sum\u{e9}/Caf\u{e9}.txt", b"selected");
    let candidate = TrashCandidate::capture(&fixture.root, &path, &[]).unwrap();
    let approved = candidate.info().clone();
    let parent_alias = fixture.root.join("Re\u{301}sume\u{301}");
    let file_alias = parent_alias.join("Cafe\u{301}.txt");
    assert!(
        !folded_beneath(&path, &file_alias),
        "lowercasing alone cannot match this alias"
    );
    assert_eq!(
        Stamp::read(&fs::symlink_metadata(&file_alias).unwrap()).identity(),
        (approved.device, approved.inode),
        "APFS Unicode normalization alias must be established natively",
    );
    assert!(candidate.matches_exclusion(&parent_alias).unwrap());
    assert!(candidate.matches_exclusion(&file_alias).unwrap());
    assert!(
        candidate
            .matches_exclusion(&file_alias.join("nonexistent-descendant"))
            .unwrap()
    );
    assert!(
        !candidate
            .matches_exclusion(&parent_alias.join("missing-child"))
            .unwrap()
    );
    assert_eq!(*candidate.info(), approved);
    drop(parent);
    fixture.finish();
}

#[test]
fn ambiguous_exclusion_links_and_invalid_paths_are_errors() {
    let mut fixture = Fixture::new();
    let path = fixture.file("selected.txt", b"selected");
    let unrelated = fixture.file("other.txt", b"other");
    let link = fixture.root.join("dangling-link");
    symlink(fixture.root.join("missing-target"), &link).unwrap();
    fixture.record(link.clone(), false);
    let candidate = TrashCandidate::capture(&fixture.root, &path, &[]).unwrap();
    assert!(candidate.matches_exclusion(Path::new("relative")).is_err());
    assert!(candidate.matches_exclusion(&link).is_err());
    assert!(candidate.matches_exclusion(&link.join("missing")).is_err());
    assert!(
        candidate
            .matches_exclusion(&unrelated.join("not-a-directory"))
            .is_err()
    );
    fixture.finish();
}

#[test]
fn disk_image_and_virtual_machine_package_internals_are_refused() {
    let mut fixture = Fixture::new();
    for package in ["Disk.sparsebundle", "Machine.vmwarevm"] {
        fixture.directory(package);
        fixture.directory(&format!("{package}/bands"));
        let path = fixture.file(&format!("{package}/bands/0"), b"synthetic package data");
        assert!(
            standard_protected(&path),
            "fallback must not depend on native type registration"
        );
        assert!(TrashCandidate::capture(&fixture.root, &path, &[]).is_err());
    }
    fixture.finish();
}

#[test]
fn native_package_classification_covers_unlisted_package_extensions() {
    let mut fixture = Fixture::new();
    let plain = fixture.directory("ordinary");
    let package = fixture.directory("Synthetic.rtfd");
    let path = fixture.file("Synthetic.rtfd/TXT.rtf", b"synthetic package data");
    assert!(!crate::volume::is_package(&plain).unwrap());
    assert!(
        crate::volume::is_package(&package).unwrap(),
        "this host must provide the standard native RTFD package classification"
    );
    assert!(
        !standard_protected(&path),
        "regression must exercise native classification, not the suffix fallback"
    );
    assert!(TrashCandidate::capture(&fixture.root, &path, &[]).is_err());
    assert!(crate::volume::is_package(&fixture.root.join("missing")).is_err());
    fixture.finish();
}

#[test]
fn missing_protection_is_unknown_not_permission() {
    let mut fixture = Fixture::new();
    let path = fixture.file("selected.txt", b"original");
    assert!(
        TrashCandidate::capture(&fixture.root, &path, &[fixture.root.join("missing")]).is_err()
    );
    fixture.finish();
}

#[test]
fn target_permissions_remain_bound_while_sibling_create_and_rename_are_allowed() {
    let mut fixture = Fixture::new();
    let path = fixture.file("selected.txt", b"original");
    let candidate = TrashCandidate::capture(&fixture.root, &path, &[]).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(candidate.revalidate().is_err());
    drop(candidate);
    let candidate = TrashCandidate::capture(&fixture.root, &path, &[]).unwrap();
    let before = candidate.info().clone();
    let sibling = fixture.file("unrelated-sibling.txt", b"ancestor mtime changes");
    candidate.revalidate().unwrap();
    let renamed = fixture.root.join("renamed-sibling.txt");
    fixture.rename(&sibling, &renamed);
    fixture.directory("unrelated-subdirectory");
    candidate.revalidate().unwrap();
    assert_eq!(
        *candidate.info(),
        before,
        "target approval must not be refreshed"
    );
    drop(candidate);
    fixture.finish();
}

#[test]
fn capture_and_revalidation_tolerate_concurrent_sibling_directory_churn() {
    use std::sync::{atomic::AtomicBool, mpsc};
    let mut fixture = Fixture::new();
    let path = fixture.file("selected.txt", b"unchanged selected target");
    let sibling = fixture.root.join("concurrent-sibling");
    let renamed = fixture.root.join("renamed-concurrent-sibling");
    let stopped = AtomicBool::new(false);
    let (ready_sender, ready_receiver) = mpsc::sync_channel(0);
    let (captured, churned) = std::thread::scope(|threads| {
        let worker = threads.spawn(|| -> io::Result<usize> {
            let mut ready_sender = Some(ready_sender);
            let mut iterations = 0;
            while !stopped.load(Ordering::Acquire) {
                fs::DirBuilder::new().mode(0o700).create(&sibling)?;
                let owned = Evidence::open_safety(&sibling)?;
                if let Some(sender) = ready_sender.take() {
                    sender.send(()).map_err(io::Error::other)?;
                }
                fs::rename(&sibling, &renamed)?;
                let current = Evidence::open_safety(&renamed)?;
                if current.stamp.identity() != owned.stamp.identity() {
                    return Err(refused("concurrent fixture cleanup identity changed"));
                }
                fs::remove_dir(&renamed)?;
                iterations += 1;
            }
            Ok(iterations)
        });
        let captured = (|| -> io::Result<()> {
            ready_receiver.recv().map_err(io::Error::other)?;
            for _ in 0..32 {
                let candidate = TrashCandidate::capture(&fixture.root, &path, &[])?;
                candidate.revalidate()?;
            }
            Ok(())
        })();
        stopped.store(true, Ordering::Release);
        let churned = worker
            .join()
            .map_err(|_| io::Error::other("concurrent fixture worker panicked"))
            .and_then(|result| result);
        (captured, churned)
    });
    captured.expect("directory contents must not invalidate capture or revalidation");
    assert!(churned.expect("identity-specific churn cleanup must succeed") > 0);
    fixture.finish();
}

#[test]
fn ancestor_mode_and_exact_acl_changes_are_refused() {
    let mut fixture = Fixture::new();
    let path = fixture.file("selected.txt", b"original");
    let directory = File::open(&fixture.root).unwrap();
    let candidate = TrashCandidate::capture(&fixture.root, &path, &[]).unwrap();
    directory
        .set_permissions(fs::Permissions::from_mode(0o500))
        .unwrap();
    assert!(candidate.revalidate().is_err());
    directory
        .set_permissions(fs::Permissions::from_mode(0o700))
        .unwrap();
    drop(candidate);

    set_synthetic_acl(&directory, Some(1)).unwrap();
    let candidate = TrashCandidate::capture(&fixture.root, &path, &[]).unwrap();
    candidate.revalidate().unwrap();
    set_synthetic_acl(&directory, Some(2)).unwrap();
    assert!(has_extended_acl(&directory).unwrap());
    assert!(
        candidate.revalidate().is_err(),
        "ACL presence alone is insufficient"
    );
    set_synthetic_acl(&directory, None).unwrap();
    drop(candidate);
    drop(directory);
    fixture.finish();
}

#[test]
fn protections_ignore_contents_but_bind_safety_properties_and_identity() {
    let mut fixture = Fixture::new();
    let protection = fixture.directory("protected");
    let path = fixture.file("selected.txt", b"original");
    let candidate =
        TrashCandidate::capture(&fixture.root, &path, std::slice::from_ref(&protection)).unwrap();
    fixture.file("protected/unrelated.txt", b"ordinary sibling");
    candidate.revalidate().unwrap();
    let directory = File::open(&protection).unwrap();
    directory
        .set_permissions(fs::Permissions::from_mode(0o500))
        .unwrap();
    assert!(candidate.revalidate().is_err());
    directory
        .set_permissions(fs::Permissions::from_mode(0o700))
        .unwrap();
    drop(candidate);

    let candidate =
        TrashCandidate::capture(&fixture.root, &path, std::slice::from_ref(&protection)).unwrap();
    set_synthetic_acl(&directory, Some(1)).unwrap();
    assert!(candidate.revalidate().is_err());
    set_synthetic_acl(&directory, None).unwrap();
    drop(candidate);
    drop(directory);

    let candidate =
        TrashCandidate::capture(&fixture.root, &path, std::slice::from_ref(&protection)).unwrap();
    let moved = fixture.root.join("retained-protection");
    fixture.rename(&protection, &moved);
    fixture.directory("protected");
    assert!(candidate.revalidate().is_err());
    drop(candidate);
    fixture.finish();
}

#[test]
fn special_files_directories_and_group_writable_files_are_refused() {
    let mut fixture = Fixture::new();
    let directory = fixture.directory("not-a-file");
    assert!(TrashCandidate::capture(&fixture.root, &directory, &[]).is_err());
    let path = fixture.file("writable.txt", b"synthetic");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o620)).unwrap();
    assert!(TrashCandidate::capture(&fixture.root, &path, &[]).is_err());
    let fifo = fixture.root.join("fifo");
    let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: A valid owned fixture pathname and ordinary user permissions.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    fixture.record(fifo.clone(), false);
    assert!(TrashCandidate::capture(&fixture.root, &fifo, &[]).is_err());
    fixture.finish();
}

#[test]
fn full_sync_reports_actual_native_result() {
    let mut fixture = Fixture::new();
    let path = fixture.file("journal.txt", b"durable synthetic record");
    let file = OpenOptions::new().write(true).open(path).unwrap();
    full_sync(&file).unwrap();
    drop(file);
    fixture.finish();
}

#[test]
fn bounds_and_unambiguous_scope_are_enforced() {
    for path in [
        "relative",
        "/a/../b",
        "/a/./b",
        "/a//b",
        "/a/",
        "/bad\0path",
    ] {
        assert!(valid_path(Path::new(path)).is_err());
    }
    let long = format!("/{}", "x".repeat(MAX_PATH_BYTES));
    assert!(valid_path(Path::new(&long)).is_err());
    let deep = PathBuf::from(format!("/{}", vec!["part"; 66].join("/")));
    assert!(TrashCandidate::capture(Path::new("/"), &deep, &[]).is_err());
    let mut fixture = Fixture::new();
    let path = fixture.file("selected.txt", b"original");
    assert!(TrashCandidate::capture(&path, &path, &[]).is_err());
    assert!(TrashCandidate::capture(&fixture.root.join("other"), &path, &[]).is_err());
    fixture.finish();
}

#[test]
fn protected_system_cloud_and_application_roots_are_case_insensitive() {
    for path in [
        "/sYsTeM/a",
        "/Library/a",
        "/Applications/a",
        "/private/a",
        "/usr/a",
        "/System/Volumes/Data/Library/a",
        "/Users/synthetic/Library/a",
        "/Users/synthetic/Dropbox/a",
        "/Users/synthetic/OneDrive - Company/a",
        "/Users/synthetic/project/.git/a",
        "/Users/synthetic/project/.sayaka-fixture/a",
        "/Users/synthetic/Thing.APP/a",
    ] {
        assert!(standard_protected(Path::new(path)), "{path}");
    }
    assert!(!standard_protected(Path::new(
        "/Users/synthetic/Documents/ordinary.txt"
    )));
    assert!(!standard_protected(Path::new(
        "/System/Volumes/Data/Users/synthetic/Documents/ordinary.txt"
    )));
    assert!(!standard_protected(Path::new(
        "/Users/synthetic/project/sayaka-native-fixture-123-456/ordinary.txt"
    )));
}

#[test]
fn cache_candidates_use_cache_specific_protection_without_weakening_ordinary_targets() {
    let mut fixture = Fixture::new();
    let pip = fixture.directory("Library");
    let caches = fixture.directory("Library/Caches");
    let pip_cache = fixture.directory("Library/Caches/pip");
    let pip_blob = fixture.file("Library/Caches/pip/blob", b"pip");
    let npm = fixture.directory(".npm");
    let npm_cache = fixture.directory(".npm/_cacache");
    let npm_blob = fixture.file(".npm/_cacache/blob", b"npm");
    let other_cache = fixture.directory(".other-cache");

    assert!(standard_protected(&pip_blob));
    assert!(standard_protected(&npm_blob));
    assert!(TrashCandidate::capture(&fixture.root, &pip_blob, &[]).is_err());
    assert!(TrashCandidate::capture(&fixture.root, &npm_blob, &[]).is_err());

    CacheTrashCandidate::capture(&caches, &pip_cache, &[]).expect("Library cache target");
    CacheTrashCandidate::capture(&npm, &npm_cache, &[]).expect("dot cache target");
    assert!(
        CacheTrashCandidate::capture(&fixture.root, &other_cache, &[]).is_err(),
        "cache capture still requires a documented rule suffix"
    );

    drop((
        pip,
        caches,
        pip_cache,
        pip_blob,
        npm,
        npm_cache,
        npm_blob,
        other_cache,
    ));
    fixture.finish();
}

#[test]
fn policy_rejects_unknown_flags_dataless_wrong_owner_and_special_modes() {
    let mut fixture = Fixture::new();
    let path = fixture.file("selected.txt", b"original");
    let stamp = Stamp::read(&fs::symlink_metadata(path).unwrap());
    let uid = ordinary_authority().unwrap();
    for flags in [SF_DATALESS, SF_RESTRICTED, 0x80000000, 0x80, 0x02, 0x04] {
        let mut changed = stamp.clone();
        changed.flags = flags;
        assert!(admissible_file(&changed, uid).is_err());
    }
    let mut wrong_owner = stamp.clone();
    wrong_owner.uid = 0;
    assert!(admissible_file(&wrong_owner, uid).is_err());
    for mode in [0o104600, 0o102600, 0o101600] {
        let mut changed = stamp.clone();
        changed.mode = mode;
        assert!(admissible_file(&changed, uid).is_err());
    }
    fixture.finish();
}

#[test]
fn post_effect_attribute_policy_allows_only_the_exact_macl_exception() {
    assert!(check_attribute_names(b"com.apple.macl\0", AttributePhase::Source).is_err());
    assert!(
        check_attribute_names(b"com.apple.macl\0", AttributePhase::PostEffectDestination).is_ok()
    );
    for name in [
        b"com.apple.macl.extra\0".as_slice(),
        b"com.apple.MACL\0",
        b"com.apple.fileprovider.synthetic\0",
        b"com.apple.icloud.synthetic\0",
        b"com.apple.ResourceFork\0",
        b"sayaka.test.unknown\0",
        b"com.apple.macl\0com.apple.ResourceFork\0",
    ] {
        assert!(check_attribute_names(name, AttributePhase::Source).is_err());
        assert!(check_attribute_names(name, AttributePhase::PostEffectDestination).is_err());
    }
    for name in [
        b"com.apple.quarantine\0".as_slice(),
        b"com.apple.FinderInfo\0",
        b"com.apple.provenance\0",
        b"com.apple.metadata:test\0",
    ] {
        assert!(check_attribute_names(name, AttributePhase::Source).is_ok());
        assert!(check_attribute_names(name, AttributePhase::PostEffectDestination).is_ok());
    }
}

fn unknown_evidence(outcome: NativeTrashOutcome) -> (String, NativeRecoveryEvidence) {
    match outcome {
        NativeTrashOutcome::Unknown { message, evidence } => (message, evidence),
        other => panic!("expected an ambiguous injected outcome, got {other:?}"),
    }
}

#[test]
fn ambiguous_foundation_response_matrix_preserves_returned_and_held_hints() {
    let mut fixture = Fixture::new();
    let source = fixture.file("selected.txt", b"synthetic");
    let candidate = TrashCandidate::capture(&fixture.root, &source, &[]).unwrap();
    let hint = fixture.root.join("unverified-returned.txt");
    // Fault-injected BOOL/NSError/URL combinations, not real Foundation calls.
    let cases = [
        (
            false,
            Some("injected NSError".into()),
            Some(Ok(hint.clone())),
        ),
        (false, None, Some(Ok(hint.clone()))),
        (
            false,
            Some("injected NSError".into()),
            Some(Err(io::Error::other("invalid URL"))),
        ),
        (
            true,
            Some("injected NSError".into()),
            Some(Ok(hint.clone())),
        ),
        (true, Some("injected NSError".into()), None),
        (true, None, None),
        (true, None, Some(Err(io::Error::other("invalid URL")))),
    ];
    for (moved, error, destination) in cases {
        let expected = destination
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .cloned();
        let response = foundation::classify_response(moved, error, destination);
        let (_, evidence) = unknown_evidence(candidate.native.interpret_response(response));
        assert_eq!(evidence.approved, *candidate.info());
        assert_eq!(evidence.returned_destination, expected);
        assert_eq!(evidence.held_source.as_ref(), Some(candidate.info()));
        assert_eq!(
            evidence.held_source_path.as_ref(),
            Some(&candidate.native.target.physical)
        );
        if expected.is_none() {
            assert!(
                evidence
                    .observation_errors
                    .iter()
                    .any(|error| error.contains("destination"))
            );
        }
    }
    let reported_failure = candidate
        .native
        .interpret_response(foundation::classify_response(
            false,
            Some("reported failure".into()),
            None,
        ));
    assert!(matches!(reported_failure, NativeTrashOutcome::Failed(_)));
    fixture.finish();
}

#[test]
fn destination_verification_failures_keep_hints_and_check_identity_first() {
    let mut fixture = Fixture::new();
    let source = fixture.file("selected.txt", b"synthetic");
    let different = fixture.file("different.txt", b"not selected");
    let name = std::ffi::CString::new(different.as_os_str().as_bytes()).unwrap();
    // SAFETY: A non-security attribute on this run's owned synthetic file only.
    assert_eq!(
        unsafe {
            libc::setxattr(
                name.as_ptr(),
                c"sayaka.test.unknown".as_ptr(),
                b"x".as_ptr().cast(),
                1,
                0,
                libc::XATTR_NOFOLLOW,
            )
        },
        0
    );
    let candidate = TrashCandidate::capture(&fixture.root, &source, &[]).unwrap();
    for (hint, expected_message) in [
        (different, "identity"),
        (source.clone(), "source path still exists"),
        (
            fixture.root.join("not-returned-by-foundation"),
            "destination verification failed",
        ),
        (
            PathBuf::from("invalid-relative-hint"),
            "path must be absolute",
        ),
    ] {
        let (message, evidence) = unknown_evidence(
            candidate
                .native
                .interpret_response(foundation::Outcome::Destination(hint.clone())),
        );
        assert!(message.contains(expected_message), "{message}");
        assert_eq!(evidence.returned_destination, Some(hint));
        assert_eq!(evidence.approved, *candidate.info());
        assert_eq!(evidence.held_source.as_ref(), Some(candidate.info()));
        assert!(evidence.held_source_path.is_some());
        assert!(!evidence.observation_errors.is_empty());
    }
    fixture.finish();
}

#[test]
fn optional_post_effect_metadata_failure_preserves_the_retained_object_path() {
    let mut fixture = Fixture::new();
    let source = fixture.file("selected.txt", b"synthetic");
    let candidate = TrashCandidate::capture(&fixture.root, &source, &[]).unwrap();
    let result_path = fixture.root.join("simulated-result.txt");
    // A local owned-fixture rename exercises the verifier; this is not Trash.
    fixture.rename(&source, &result_path);
    let name = std::ffi::CString::new(result_path.as_os_str().as_bytes()).unwrap();
    // SAFETY: Only this run's renamed, identity-retained synthetic file.
    assert_eq!(
        unsafe {
            libc::setxattr(
                name.as_ptr(),
                c"sayaka.test.post-effect".as_ptr(),
                b"x".as_ptr().cast(),
                1,
                0,
                libc::XATTR_NOFOLLOW,
            )
        },
        0
    );
    let (message, evidence) = unknown_evidence(
        candidate
            .native
            .interpret_response(foundation::Outcome::Destination(result_path.clone())),
    );
    assert!(
        message.contains("unknown or cloud/resource-fork"),
        "{message}"
    );
    assert_eq!(evidence.returned_destination, Some(result_path));
    assert_eq!(evidence.approved, *candidate.info());
    assert_eq!(evidence.held_source.as_ref(), Some(candidate.info()));
    assert_eq!(
        evidence.held_source_path,
        Some(physical_path(&candidate.native.target.file).unwrap())
    );
    fixture.finish();
}

#[test]
fn observation_and_policy_restore_failures_preserve_available_evidence() {
    let mut fixture = Fixture::new();
    let source = fixture.file("selected.txt", b"synthetic");
    let candidate = TrashCandidate::capture(&fixture.root, &source, &[]).unwrap();
    let hint = fixture.root.join("unverified-hint");
    let missing = recovery_observations(
        candidate.info(),
        Some(hint.clone()),
        Err(io::Error::other("injected fstat failure")),
        Err(io::Error::other("injected F_GETPATH failure")),
    );
    assert!(missing.held_source.is_none() && missing.held_source_path.is_none());
    assert_eq!(missing.observation_errors.len(), 2);
    let (_, retained) = unknown_evidence(candidate.native.finish_restore(
        NativeTrashOutcome::Unknown {
            message: "injected ambiguity".into(),
            evidence: missing,
        },
        Err(io::Error::other("injected restore failure")),
    ));
    assert_eq!(retained.returned_destination, Some(hint.clone()));
    assert_eq!(retained.approved, *candidate.info());
    assert_eq!(retained.observation_errors.len(), 3);
    assert!(retained.held_source.is_none() && retained.held_source_path.is_none());
    let (_, after_success) = unknown_evidence(candidate.native.finish_restore(
        NativeTrashOutcome::Moved {
            destination: hint.clone(),
        },
        Err(io::Error::other(
            "injected restore failure after simulated success",
        )),
    ));
    assert_eq!(after_success.returned_destination, Some(hint.clone()));
    assert_eq!(after_success.held_source.as_ref(), Some(candidate.info()));
    assert!(after_success.held_source_path.is_some());
    let only_info = recovery_observations(
        candidate.info(),
        None,
        Ok(candidate.info().clone()),
        Err(io::Error::other("path unavailable")),
    );
    assert!(
        only_info.returned_destination.is_none(),
        "never infer a returned URL from a source observation"
    );
    assert_eq!(only_info.held_source.as_ref(), Some(candidate.info()));
    assert!(only_info.held_source_path.is_none());
    let only_path = recovery_observations(
        candidate.info(),
        Some(hint),
        Err(io::Error::other("fstat unavailable")),
        Ok(candidate.native.target.physical.clone()),
    );
    assert!(only_path.held_source.is_none());
    assert!(only_path.held_source_path.is_some());
    let mut bounded = only_path;
    for _ in 0..20 {
        bounded.record_error("x".repeat(2048));
    }
    assert_eq!(bounded.observation_errors.len(), 8);
    assert!(
        bounded
            .observation_errors
            .iter()
            .all(|error| error.chars().count() <= 1040)
    );
    fixture.finish();
}

#[test]
fn unknown_extended_attributes_are_refused_without_rewriting_them() {
    let mut fixture = Fixture::new();
    let path = fixture.file("selected.txt", b"original");
    let candidate = TrashCandidate::capture(&fixture.root, &path, &[]).unwrap();
    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    let value = b"synthetic";
    // SAFETY: Only this run's synthetic fixture; valid name/value buffers.
    assert_eq!(
        unsafe {
            libc::setxattr(
                name.as_ptr(),
                c"sayaka.test.unknown".as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
                libc::XATTR_NOFOLLOW,
            )
        },
        0
    );
    assert!(candidate.revalidate().is_err());
    assert!(TrashCandidate::capture(&fixture.root, &path, &[]).is_err());
    drop(candidate);
    fixture.finish();
}

fn set_synthetic_acl(file: &File, tag: Option<i32>) -> io::Result<()> {
    set_synthetic_acl_permission(file, tag, 1 << 1)
}

fn set_synthetic_acl_permission(file: &File, tag: Option<i32>, permission: i32) -> io::Result<()> {
    use std::ffi::c_void;
    use std::ptr;
    unsafe extern "C" {
        fn acl_init(count: i32) -> *mut c_void;
        fn acl_create_entry(acl: *mut *mut c_void, entry: *mut *mut c_void) -> i32;
        fn acl_set_tag_type(entry: *mut c_void, tag: i32) -> i32;
        fn acl_set_qualifier(entry: *mut c_void, qualifier: *const c_void) -> i32;
        fn acl_get_permset(entry: *mut c_void, permissions: *mut *mut c_void) -> i32;
        fn acl_add_perm(permissions: *mut c_void, permission: i32) -> i32;
        fn acl_set_fd_np(fd: i32, acl: *mut c_void, acl_type: i32) -> i32;
        fn acl_free(acl: *mut c_void) -> i32;
        fn mbr_gid_to_uuid(gid: u32, uuid: *mut u8) -> i32;
    }
    fn checked(result: i32) -> io::Result<()> {
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    // SAFETY: Allocate one owned ACL for this run's synthetic file/directory.
    let mut acl = unsafe { acl_init(1) };
    if acl.is_null() {
        return Err(io::Error::last_os_error());
    }
    let result = (|| {
        if let Some(tag) = tag {
            let mut uuid = [0u8; 16];
            // SAFETY: Integer group lookup and a writable UUID-sized buffer.
            let mapped = unsafe { mbr_gid_to_uuid(libc::getgid(), uuid.as_mut_ptr()) };
            if mapped != 0 {
                return Err(io::Error::from_raw_os_error(mapped));
            }
            let mut entry = ptr::null_mut();
            let mut permissions = ptr::null_mut();
            // SAFETY: Live owned ACL and initialized out-pointers. Creation may
            // replace the allocation; the updated pointer is released below.
            checked(unsafe { acl_create_entry(&mut acl, &mut entry) })?;
            if entry.is_null() {
                return Err(io::Error::other("native fixture ACL entry is null"));
            }
            // SAFETY: Live entry, known ALLOW/DENY tag and native group UUID.
            checked(unsafe { acl_set_tag_type(entry, tag) })?;
            checked(unsafe { acl_set_qualifier(entry, uuid.as_ptr().cast()) })?;
            checked(unsafe { acl_get_permset(entry, &mut permissions) })?;
            if permissions.is_null() {
                return Err(io::Error::other(
                    "native fixture ACL permission set is null",
                ));
            }
            // SAFETY: Borrowed permission set; caller supplies a documented
            // read/list or delete permission for this owned synthetic fixture.
            checked(unsafe { acl_add_perm(permissions, permission) })?;
        }
        // SAFETY: Apply only to the exact open synthetic fixture descriptor.
        // Production code never invokes any ACL or permission-writing function.
        checked(unsafe { acl_set_fd_np(file.as_raw_fd(), acl, 0x100) })
    })();
    // SAFETY: Release the latest sole-owned ACL pointer, including error paths.
    let freed = checked(unsafe { acl_free(acl) });
    result.and(freed)
}

#[test]
fn native_acl_query_distinguishes_empty_and_present_despite_private_modes() {
    let mut fixture = Fixture::new();
    let path = fixture.file("private-record", b"synthetic record");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let directory = File::open(&fixture.root).unwrap();
    let before_policy = crate::get_policy().unwrap();
    for object in [&file, &directory] {
        set_synthetic_acl(object, None).unwrap();
        assert!(!has_extended_acl(object).unwrap());
        set_synthetic_acl(object, Some(1)).unwrap();
        assert!(has_extended_acl(object).unwrap());
        assert!(
            has_extended_acl(object).unwrap(),
            "inspection must not rewrite ACLs"
        );
        set_synthetic_acl(object, Some(2)).unwrap();
        assert!(
            has_extended_acl(object).unwrap(),
            "deny-only ACLs also count"
        );
        set_synthetic_acl(object, None).unwrap();
        assert!(!has_extended_acl(object).unwrap());
    }
    assert_eq!(file.metadata().unwrap().mode() & 0o777, 0o600);
    assert_eq!(directory.metadata().unwrap().mode() & 0o777, 0o700);
    assert_eq!(crate::get_policy().unwrap(), before_policy);
    drop(file);
    drop(directory);
    fixture.finish();
}

#[test]
fn native_acl_query_on_unsupported_descriptor_is_an_error() {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    let (stream, _peer) = UnixStream::pair().unwrap();
    let descriptor: OwnedFd = stream.into();
    let file = File::from(descriptor);
    let before_policy = crate::get_policy().unwrap();
    assert!(has_extended_acl(&file).is_err());
    assert!(crate::acl::recovery_acl_is_non_granting(&file).is_err());
    assert_eq!(crate::get_policy().unwrap(), before_policy);
}

fn private_recovery_directory(
    role: &str,
    directory: &Evidence,
    uid: u32,
    device: u64,
) -> io::Result<()> {
    let diagnosis = |property: &str| refused(&format!("{role}: {property}"));
    directory.revalidate().map_err(|error| {
        diagnosis(&format!(
            "retained evidence changed or unavailable: {error}"
        ))
    })?;
    if directory.stamp.mode & u32::from(libc::S_IFMT) != u32::from(libc::S_IFDIR) {
        return Err(diagnosis("not a directory"));
    }
    if directory.stamp.uid != uid {
        return Err(diagnosis("not owned by the current ordinary user"));
    }
    if directory.stamp.device != device {
        return Err(diagnosis("not on the selected file's device"));
    }
    if directory.stamp.mode & 0o7777 != 0o700 {
        return Err(diagnosis(
            "requires private mode 0700 without special permission bits",
        ));
    }
    if directory.stamp.flags & !(ORDINARY_FLAGS | SF_RESTRICTED | SF_NOUNLINK) != 0 {
        return Err(diagnosis("unsupported directory flags"));
    }
    if directory.stamp.inode == 0 {
        return Err(diagnosis("missing directory inode identity"));
    }
    if !crate::acl::recovery_acl_is_non_granting(&directory.file)
        .map_err(|error| diagnosis(&format!("extended ACL inspection failed: {error}")))?
    {
        return Err(diagnosis(
            "extended ACL contains an allow entry; recovery permits only non-granting ACLs",
        ));
    }
    supported_volume(directory)
        .map_err(|error| diagnosis(&format!("unsupported volume: {error}")))?;
    directory.revalidate().map_err(|error| {
        diagnosis(&format!(
            "retained evidence changed during prerequisite checks: {error}"
        ))
    })
}

#[test]
fn recovery_acl_gate_accepts_empty_and_deny_only_but_rejects_allow_entries() {
    let fixture = Fixture::new();
    let directory = File::open(&fixture.root).unwrap();
    let uid = ordinary_authority().unwrap();
    let device = directory.metadata().unwrap().dev();
    for (tag, expected) in [(None, true), (Some(2), true), (Some(1), false)] {
        set_synthetic_acl_permission(&directory, tag, 1 << 4).unwrap();
        let observed = Evidence::open_safety(&fixture.root);
        let result = observed.and_then(|evidence| {
            private_recovery_directory("Trash directory", &evidence, uid, device)
        });
        let ordinary_policy = has_extended_acl(&directory);
        set_synthetic_acl(&directory, None).unwrap();
        assert_eq!(
            ordinary_policy.unwrap(),
            tag.is_some(),
            "public ACL presence policy must remain unchanged"
        );
        assert_eq!(result.is_ok(), expected, "{result:?}");
    }
    set_synthetic_acl_permission(&directory, Some(2), 1 << 4).unwrap();
    let observed = Evidence::open_safety(&fixture.root);
    set_synthetic_acl_permission(&directory, Some(2), 1 << 1).unwrap();
    let changed = observed
        .and_then(|evidence| private_recovery_directory("Trash directory", &evidence, uid, device));
    set_synthetic_acl(&directory, None).unwrap();
    assert!(
        changed.is_err(),
        "even a deny-to-deny ACL change must invalidate the snapshot"
    );
    drop(directory);
    fixture.finish();
}

#[test]
fn recovery_diagnostics_identify_directory_and_failed_property_without_acl_values() {
    let fixture = Fixture::new();
    let directory = File::open(&fixture.root).unwrap();
    let uid = ordinary_authority().unwrap();
    let device = directory.metadata().unwrap().dev();
    set_synthetic_acl_permission(&directory, Some(1), 1 << 4).unwrap();
    let diagnosis = Evidence::open_safety(&fixture.root)
        .and_then(|observed| private_recovery_directory("Trash directory", &observed, uid, device));
    set_synthetic_acl(&directory, None).unwrap();
    let error = diagnosis.unwrap_err().to_string();
    assert!(error.starts_with("Trash directory: extended ACL contains an allow entry"));
    assert!(
        !error.contains("deny"),
        "diagnosis must not print actual ACL entries"
    );
    directory
        .set_permissions(fs::Permissions::from_mode(0o500))
        .unwrap();
    let diagnosis = Evidence::open_safety(&fixture.root).and_then(|observed| {
        private_recovery_directory("original directory", &observed, uid, device)
    });
    directory
        .set_permissions(fs::Permissions::from_mode(0o700))
        .unwrap();
    let error = diagnosis.unwrap_err().to_string();
    assert!(error.starts_with("original directory: requires private mode 0700"));
    drop(directory);
    fixture.finish();
}

fn no_overwrite_rename(
    source_directory: &File,
    source_name: &OsStr,
    destination_directory: &File,
    destination_name: &OsStr,
) -> io::Result<()> {
    let source = std::ffi::CString::new(source_name.as_bytes())
        .map_err(|_| io::Error::other("invalid synthetic source name"))?;
    let destination = std::ffi::CString::new(destination_name.as_bytes())
        .map_err(|_| io::Error::other("invalid synthetic destination name"))?;
    if source_name.as_bytes().contains(&b'/') || destination_name.as_bytes().contains(&b'/') {
        return Err(refused(
            "recovery accepts only individual filename components",
        ));
    }
    // SAFETY: Live retained directory descriptors and NUL-terminated single
    // components. RENAME_EXCL never overwrites an occupied destination.
    if unsafe {
        libc::renameatx_np(
            source_directory.as_raw_fd(),
            source.as_ptr(),
            destination_directory.as_raw_fd(),
            destination.as_ptr(),
            libc::RENAME_EXCL,
        )
    } != 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

// Explicitly opt-in; never run all ignored tests. Ordinary user authority and
// writable internal APFS are required. Foundation must identify an EXISTING
// accessible Trash directory; this case neither guesses nor creates one.
//
// QUIESCENT=1 acknowledges an externally assured absence of competing same-user
// namespace writers throughout the test. Permissions cannot establish that fact:
// if it cannot be assured on this account, use a disposable account/VM instead.
// The restore is revalidated and no-overwrite, NOT an atomic inode-bound action.
//
// Exact invocation (only after explicit approval):
// SAYAKA_M3_TRASH_TEST=1 SAYAKA_M3_TRASH_TEST_QUIESCENT=1 cargo test \
//   -p sayaka-platform-macos --locked \
//   trash::native::tests::real_foundation_trash_owned_fixture_round_trip \
//   -- --ignored --exact --nocapture --test-threads=1
#[test]
#[ignore = "REAL SYSTEM TRASH: explicit owned-fixture authorization and externally assured quiescent namespace required"]
fn real_foundation_trash_owned_fixture_round_trip() {
    use std::io::{Read, Write};
    assert_eq!(
        std::env::var("SAYAKA_M3_TRASH_TEST").as_deref(),
        Ok("1"),
        "BLOCKED before fixture/Trash mutation: set SAYAKA_M3_TRASH_TEST=1 only after explicit approval"
    );
    assert_eq!(
        std::env::var("SAYAKA_M3_TRASH_TEST_QUIESCENT").as_deref(),
        Ok("1"),
        "BLOCKED before fixture/Trash mutation: assure no competing namespace writers; otherwise use a disposable account/VM"
    );

    let mut fixture = Fixture::new();
    let name = format!(
        "{}-selected.txt",
        fixture.root.file_name().unwrap().to_str().unwrap()
    );
    let contents = format!("Synthetic owned Trash fixture: {name}\n");
    let source = fixture.file(&name, contents.as_bytes());
    let held = Evidence::open(&source).unwrap();
    let marker = Evidence::open(&fixture.root.join("ownership-marker")).unwrap();
    let evidence_path = fixture.file("recovery-evidence.txt", b"");
    let mut recovery = OpenOptions::new()
        .write(true)
        .custom_flags(O_NOFOLLOW_ANY | libc::O_CLOEXEC)
        .open(&evidence_path)
        .unwrap();
    writeln!(
        recovery,
        "intent: source={source:?}; device={}; inode={}; marker={:?}",
        held.stamp.device,
        held.stamp.inode,
        marker.stamp.identity()
    )
    .unwrap();
    full_sync(&recovery).unwrap();
    File::open(&fixture.root).unwrap().sync_all().unwrap();

    let prerequisite = with_policy(|| {
        let uid = ordinary_authority()?;
        let original_directory = Evidence::open_safety(&fixture.root).map_err(|error| {
            refused(&format!(
                "original directory: no-follow evidence unavailable: {error}"
            ))
        })?;
        private_recovery_directory(
            "original directory",
            &original_directory,
            uid,
            held.stamp.device,
        )?;
        let trash_path = objc2::rc::autoreleasepool(|_| {
            foundation::Prepared::new(&source)?.existing_trash_directory()
        })
        .map_err(|error| refused(&format!("Trash directory: native lookup failed: {error}")))?;
        let trash = Evidence::open_safety(&trash_path).map_err(|error| {
            refused(&format!(
                "Trash directory: no-follow evidence unavailable: {error}"
            ))
        })?;
        private_recovery_directory("Trash directory", &trash, uid, held.stamp.device)?;
        let mut ancestry = Vec::new();
        for path in trash_path.ancestors().skip(1) {
            let ancestor = Evidence::open_safety(path)?;
            admissible_ancestor(&ancestor.stamp, uid)?;
            ancestry.push(ancestor);
        }
        // An occupied OWNED marker checks the native no-overwrite primitive and
        // directory descriptor support without moving the selected fixture.
        let preflight = no_overwrite_rename(
            &original_directory.file,
            source.file_name().unwrap(),
            &original_directory.file,
            OsStr::new("ownership-marker"),
        );
        held.revalidate()?;
        marker.revalidate()?;
        if !matches!(preflight, Err(ref error) if error.raw_os_error() == Some(libc::EEXIST)) {
            return Err(refused(
                "no-overwrite recovery preflight did not report EEXIST",
            ));
        }
        let candidate = TrashCandidate::capture(&fixture.root, &source, &[])?;
        Ok((uid, original_directory, trash, ancestry, candidate))
    });
    let (uid, original_directory, trash, ancestry, candidate) = prerequisite
        .unwrap_or_else(|error| panic!("BLOCKED before Foundation Trash call: {error}"));

    // From here on every unexpected outcome preserves all fixture/recovery
    // evidence. Drop must NOT try to delete a missing or substituted source.
    fixture.preserve = true;
    let check_recovery = || -> io::Result<()> {
        for ancestor in &ancestry {
            ancestor.revalidate()?;
        }
        private_recovery_directory(
            "original directory",
            &original_directory,
            uid,
            held.stamp.device,
        )?;
        private_recovery_directory("Trash directory", &trash, uid, held.stamp.device)?;
        marker.revalidate()
    };
    let mut prerequisite_failure = None;
    let outcome = candidate.move_to_trash(|| match check_recovery() {
        Ok(()) => false,
        Err(error) => {
            prerequisite_failure = Some(error);
            true
        }
    });
    let result = (|| -> io::Result<()> {
        writeln!(
            recovery,
            "native outcome={outcome:?}; pre-call refusal={prerequisite_failure:?}"
        )?;
        if let NativeTrashOutcome::Unknown { message, evidence } = &outcome {
            writeln!(
                recovery,
                "UNKNOWN: {message}\nUNVERIFIED returned destination: {:?}\nStructured recovery observations: {evidence:#?}",
                evidence.returned_destination
            )?;
        }
        full_sync(&recovery)?;
        let NativeTrashOutcome::Moved { destination } = &outcome else {
            return Err(io::Error::other(format!(
                "expected verified Moved, got {outcome:?}"
            )));
        };
        with_policy(|| {
            check_recovery()?;
            let returned = Evidence::open(destination)?;
            admissible_file(&returned.stamp, uid)?;
            let destination_parent = destination
                .parent()
                .ok_or_else(|| refused("returned destination has no parent"))?;
            let returned_parent = Evidence::open_safety(destination_parent)?;
            if returned.stamp.identity() != held.stamp.identity()
                || returned.acl != held.acl
                || Stamp::read(&held.file.metadata()?).identity() != held.stamp.identity()
                || returned_parent.stamp.identity() != trash.stamp.identity()
                || returned_parent.physical != trash.physical
            {
                return Err(refused(
                    "returned destination does not match retained fixture/recovery directory",
                ));
            }
            match fs::symlink_metadata(&source) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                _ => {
                    return Err(refused(
                        "original fixture pathname is not demonstrably vacant",
                    ));
                }
            }
            returned.revalidate()?;
            check_recovery()?;
            no_overwrite_rename(
                &trash.file,
                destination
                    .file_name()
                    .ok_or_else(|| refused("missing returned name"))?,
                &original_directory.file,
                source.file_name().unwrap(),
            )?;
            let restored = Evidence::open(&source)?;
            if restored.stamp.identity() != held.stamp.identity() || restored.acl != held.acl {
                return Err(refused("restored fixture identity/ACL mismatch"));
            }
            let mut content_file = OpenOptions::new()
                .read(true)
                .custom_flags(O_NOFOLLOW_ANY | libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open(&source)?;
            if Stamp::read(&content_file.metadata()?).identity() != held.stamp.identity() {
                return Err(refused(
                    "restored fixture changed before content verification",
                ));
            }
            let mut actual = Vec::new();
            (&mut content_file)
                .take(contents.len() as u64 + 1)
                .read_to_end(&mut actual)?;
            if actual != contents.as_bytes() {
                return Err(refused("restored synthetic contents differ"));
            }
            restored.revalidate()?;
            writeln!(
                recovery,
                "restored and verified: device={} inode={}",
                held.stamp.device, held.stamp.inode
            )?;
            full_sync(&recovery)
        })
    })();
    if let Err(error) = result {
        let saved = writeln!(recovery, "FAILED; retain evidence: {error}")
            .and_then(|_| full_sync(&recovery));
        panic!(
            "Owned-fixture Trash test failed: {error}; source={source:?}; identity={:?}; outcome={outcome:?}; recovery evidence={evidence_path:?}; evidence-write={saved:?}. No search, guessed restore or Trash cleanup was attempted.",
            held.stamp.identity()
        );
    }
    drop(recovery);
    drop(candidate);
    fixture.preserve = false;
    fixture.finish();
}

#[test]
fn bundle_capture_accepts_owned_app_directory_and_cancel_has_no_effect() {
    let mut fixture = Fixture::new();
    let app = fixture.directory("Fixture.app");
    fixture.directory("Fixture.app/Contents");
    fixture.directory("Fixture.app/Contents/MacOS");
    fixture.file("Fixture.app/Contents/Info.plist", b"synthetic plist");
    let candidate = BundleTrashCandidate::capture(&fixture.root, &app, &[]).unwrap();
    assert_eq!(candidate.path(), app);
    candidate.revalidate().unwrap();
    let mut called = false;
    let result = candidate.move_to_trash_with_last_guard(
        || {
            called = true;
            true
        },
        || NativeLastGuard::Proceed,
    );
    assert!(called);
    assert!(matches!(result, NativeTrashOutcome::Refused(reason) if reason == "cancelled"));
    assert_eq!(
        fs::read(app.join("Contents/Info.plist")).unwrap(),
        b"synthetic plist"
    );
    assert!(matches!(
        candidate.move_to_trash_with_last_guard(
            || panic!("a consumed candidate must never retry"),
            || NativeLastGuard::Proceed,
        ),
        NativeTrashOutcome::Refused(_)
    ));
    drop(candidate);
    fixture.finish();
}

#[test]
fn purge_capture_accepts_artifact_with_marker_and_cancel_has_no_effect() {
    let mut fixture = Fixture::new();
    fixture.directory("app");
    let artifact = fixture.directory("app/target");
    let marker = fixture.file("app/Cargo.toml", b"[package]");
    fixture.file("app/target/bin", b"x");
    let candidate =
        PurgeTrashCandidate::capture(&fixture.root, &artifact, std::slice::from_ref(&marker), &[])
            .unwrap();
    assert_eq!(candidate.path(), artifact);
    candidate.revalidate().unwrap();
    let mut called = false;
    let result = candidate.move_to_trash_with_last_guard(
        || {
            called = true;
            true
        },
        || NativeLastGuard::Proceed,
    );
    assert!(called);
    assert!(matches!(result, NativeTrashOutcome::Refused(reason) if reason == "cancelled"));
    // Cancellation before the sole call leaves artifact and marker intact.
    assert_eq!(fs::read(&marker).unwrap(), b"[package]");
    assert_eq!(fs::read(artifact.join("bin")).unwrap(), b"x");
    assert!(matches!(
        candidate.move_to_trash_with_last_guard(
            || panic!("a consumed candidate must never retry"),
            || NativeLastGuard::Proceed,
        ),
        NativeTrashOutcome::Refused(_)
    ));
    drop(candidate);
    fixture.finish();
}

#[test]
fn purge_capture_rejects_bad_shapes_missing_markers_and_out_of_scope_markers() {
    let mut fixture = Fixture::new();
    fixture.directory("app");
    let artifact = fixture.directory("app/target");
    let marker = fixture.file("app/Cargo.toml", b"[package]");
    // No markers, or markers that are missing / directories / the artifact
    // itself / outside the scope.
    assert!(PurgeTrashCandidate::capture(&fixture.root, &artifact, &[], &[]).is_err());
    assert!(
        PurgeTrashCandidate::capture(
            &fixture.root,
            &artifact,
            &[fixture.root.join("app/missing.toml")],
            &[],
        )
        .is_err()
    );
    let marker_dir = fixture.directory("app/markerdir");
    assert!(PurgeTrashCandidate::capture(&fixture.root, &artifact, &[marker_dir], &[]).is_err());
    assert!(
        PurgeTrashCandidate::capture(
            &fixture.root,
            &artifact,
            std::slice::from_ref(&artifact),
            &[]
        )
        .is_err()
    );
    assert!(
        PurgeTrashCandidate::capture(
            &fixture.root,
            &artifact,
            &[std::path::PathBuf::from("/etc/hosts")],
            &[],
        )
        .is_err()
    );
    // A regular file is never an artifact target.
    let file = fixture.file("ordinary.txt", b"x");
    assert!(
        PurgeTrashCandidate::capture(&fixture.root, &file, std::slice::from_ref(&marker), &[])
            .is_err()
    );
    fixture.finish();
}

#[test]
fn purge_marker_identity_change_after_capture_is_refused() {
    let mut fixture = Fixture::new();
    fixture.directory("app");
    let artifact = fixture.directory("app/target");
    let marker = fixture.file("app/Cargo.toml", b"one");
    let candidate =
        PurgeTrashCandidate::capture(&fixture.root, &artifact, std::slice::from_ref(&marker), &[])
            .unwrap();
    // Same-path content swap keeps the inode here; replace with a rename to
    // force an identity change.
    let swapped = fixture.root.join("app/Cargo.toml.tmp");
    fs::write(&swapped, b"two").unwrap();
    fs::rename(&swapped, &marker).unwrap();
    assert!(candidate.revalidate().is_err());
    // Re-register the swapped identity so verified fixture cleanup accepts it.
    let identity = Stamp::read(&fs::symlink_metadata(&marker).unwrap()).identity();
    for object in fixture.objects.iter_mut() {
        if object.0 == marker {
            object.1 = identity;
        }
    }
    drop(candidate);
    fixture.finish();
}

#[test]
fn bundle_capture_rejects_files_unsuffixed_dirs_and_missing_manifests() {
    let mut fixture = Fixture::new();
    let file = fixture.file("ordinary.txt", b"x");
    assert!(BundleTrashCandidate::capture(&fixture.root, &file, &[]).is_err());
    let plain = fixture.directory("plain");
    assert!(BundleTrashCandidate::capture(&fixture.root, &plain, &[]).is_err());
    let no_manifest = fixture.directory("NoManifest.app");
    assert!(BundleTrashCandidate::capture(&fixture.root, &no_manifest, &[]).is_err());
    fixture.finish();
}

#[test]
fn bundle_manifest_identity_change_after_capture_is_refused() {
    let mut fixture = Fixture::new();
    let app = fixture.directory("Fixture.app");
    fixture.directory("Fixture.app/Contents");
    fixture.directory("Fixture.app/Contents/MacOS");
    fixture.file("Fixture.app/Contents/Info.plist", b"one");
    let candidate = BundleTrashCandidate::capture(&fixture.root, &app, &[]).unwrap();
    // Same-path content swap keeps the inode here; replace with a rename to
    // force an identity change.
    let swapped = app.join("Contents/Info.plist.tmp");
    fs::write(&swapped, b"two").unwrap();
    fs::rename(&swapped, app.join("Contents/Info.plist")).unwrap();
    assert!(candidate.revalidate().is_err());
    // Re-register the swapped identity so verified fixture cleanup accepts it.
    let plist = app.join("Contents/Info.plist");
    let identity = Stamp::read(&fs::symlink_metadata(&plist).unwrap()).identity();
    for object in fixture.objects.iter_mut() {
        if object.0 == plist {
            object.1 = identity;
        }
    }
    drop(candidate);
    fixture.finish();
}
