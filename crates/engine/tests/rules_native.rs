// SPDX-License-Identifier: MPL-2.0

#![cfg(target_os = "macos")]

#[path = "support/fixture.rs"]
mod fixture;

use fixture::Fixture;
use sayaka_engine::clean_policy;
use sayaka_engine::execute::{CleanSession, TrashSession};
use sayaka_engine::journal::Store;
use sayaka_engine::model::Cancellation;
use sayaka_engine::model::Scope;
use sayaka_engine::rules::{self, RefusalCode};
use sayaka_engine::scan::{self, ScanLimits};
use serde::Serialize;
use std::ffi::OsStr;
use std::fs;
use std::mem::ManuallyDrop;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn scope(fixture: &Fixture) -> std::path::PathBuf {
    let root = fixture.path().canonicalize().unwrap().join("rules");
    fs::create_dir(&root).unwrap();
    root
}

fn native_fixture_parent() -> PathBuf {
    let parent = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("native-test-fixtures");
    fs::create_dir_all(&parent).unwrap();
    parent
}

fn setup_rule_bound_layout(root: &Path) -> (PathBuf, PathBuf, &'static [u8], &'static [u8]) {
    fs::create_dir_all(root.join("pkg/__pycache__")).unwrap();
    let source = root.join("pkg/module.py");
    let target = root.join("pkg/__pycache__/module.cpython-39.pyc");
    let source_bytes = b"print('owned synthetic source')\n";
    let target_bytes = b"synthetic-pyc-layout-not-bytecode-validated\n";
    fs::write(&source, source_bytes).unwrap();
    fs::write(&target, target_bytes).unwrap();
    (source, target, source_bytes, target_bytes)
}

fn clean_config_path(fixture: &Fixture) -> clean_policy::ConfigPath {
    clean_policy::resolve_config_path(Some(&fixture.path().join("clean-config"))).unwrap()
}

fn preview(root: &std::path::Path) -> rules::RulePreview {
    let report = scan::scan(
        &[root.to_path_buf()],
        &ScanLimits::default(),
        &Cancellation::default(),
        |_| {},
    )
    .unwrap();
    rules::preview(
        report,
        rules::CPYTHON_SOURCE_BACKED_PYC_RULE_ID,
        &Cancellation::default(),
    )
    .unwrap()
}

fn native_path(path: &sayaka_engine::journal::NativePath) -> PathBuf {
    PathBuf::from(OsStr::from_bytes(&path.bytes))
}

fn restore_no_replace(source: &Path, destination: &Path) -> std::io::Result<()> {
    use rustix::fs::{self, Mode, OFlags, RenameFlags};
    let source_parent = source.parent().expect("source has parent");
    let destination_parent = destination.parent().expect("destination has parent");
    let source_name = source.file_name().expect("source has name");
    let destination_name = destination.file_name().expect("destination has name");
    let source_dir = fs::open(
        source_parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    let destination_dir = fs::open(
        destination_parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    fs::renameat_with(
        &source_dir,
        source_name,
        &destination_dir,
        destination_name,
        RenameFlags::NOREPLACE,
    )
    .map_err(std::io::Error::from)?;
    Ok(())
}

#[derive(Serialize)]
struct NativeEvidenceLog {
    fixture_root: String,
    state_dir: String,
    target: String,
    source: String,
    target_identity_before: Option<(u64, u64, u64, i64, u64, u32, u32)>,
    source_identity_before: Option<(u64, u64, u64, i64, u64, u32, u32)>,
    record_schema_version: Option<u32>,
    record_plan_schema_version: Option<u32>,
    operation_id: Option<String>,
    item_state: Option<String>,
    returned_destination: Option<String>,
    restore_error: Option<String>,
}

struct PreservedFixture {
    fixture: ManuallyDrop<Fixture>,
    root: PathBuf,
    state_dir: PathBuf,
    evidence_path: PathBuf,
}

impl PreservedFixture {
    fn new() -> Self {
        let fixture = ManuallyDrop::new(Fixture::new_in(&native_fixture_parent()).unwrap());
        let root = scope(&fixture);
        let state_dir = fixture.path().join("state").join("rules-trash");
        let evidence_path = fixture.path().join("native-roundtrip-evidence.json");
        Self {
            fixture,
            root,
            state_dir,
            evidence_path,
        }
    }

    fn root(&self) -> &Path {
        &self.root
    }

    fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    fn write_evidence(&self, evidence: &NativeEvidenceLog) {
        let bytes = serde_json::to_vec_pretty(evidence).unwrap();
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&self.evidence_path)
            .unwrap();
        use std::io::Write;
        file.write_all(&bytes).unwrap();
        file.sync_all().unwrap();
    }

    fn announce(&self) {
        let fixture = self
            .fixture
            .path()
            .canonicalize()
            .unwrap_or_else(|_| self.fixture.path().to_path_buf());
        let state = self
            .state_dir
            .canonicalize()
            .unwrap_or_else(|_| self.state_dir.clone());
        eprintln!(
            "native one-shot fixture_root={} state_dir={} evidence={}",
            fixture.display(),
            state.display(),
            self.evidence_path.display()
        );
    }

    fn close_success(self) {
        let fixture = ManuallyDrop::into_inner(self.fixture);
        fixture.close().unwrap();
    }
}

#[test]
fn cpython_source_backed_preview_matches_multiple_distinct_pyc_identities() {
    let fixture = Fixture::new().unwrap();
    let root = scope(&fixture);
    fs::create_dir(root.join("pkg")).unwrap();
    fs::create_dir(root.join("pkg/__pycache__")).unwrap();
    fs::write(root.join("pkg/module.py"), b"print('x')\n").unwrap();
    let pyc = vec![0x6a; 218];
    fs::write(root.join("pkg/__pycache__/module.cpython-39.pyc"), &pyc).unwrap();
    fs::write(
        root.join("pkg/__pycache__/module.cpython-39.opt-2.pyc"),
        &pyc,
    )
    .unwrap();
    let result = preview(&root);
    assert_eq!(result.candidates.len(), 2, "{:?}", result.refusals);
    assert!(result.refusals.is_empty());
    assert_eq!(result.matched_bytes_known, 436);
    assert_eq!(result.candidates[0].source_path, root.join("pkg/module.py"));
    assert_eq!(result.candidates[1].source_path, root.join("pkg/module.py"));
    assert_ne!(
        result.candidates[0].target_identity,
        result.candidates[1].target_identity
    );
    fixture.close().unwrap();
}

#[test]
fn cpython_preview_refuses_hardlink_aliases_and_identity_changes() {
    let fixture = Fixture::new().unwrap();
    let root = scope(&fixture);
    fs::create_dir_all(root.join("pkg/__pycache__")).unwrap();
    fs::write(root.join("pkg/module.py"), b"print('x')\n").unwrap();
    let pyc = root.join("pkg/__pycache__/module.cpython-39.pyc");
    fs::write(&pyc, vec![0x11; 32]).unwrap();
    fs::hard_link(&pyc, fixture.path().join("pyc-alias")).unwrap();
    let first = preview(&root);
    assert!(first.candidates.is_empty());
    assert!(
        first
            .refusals
            .iter()
            .any(|item| item.code == RefusalCode::DuplicateOrHardlinkAmbiguous)
    );
    fs::remove_file(fixture.path().join("pyc-alias")).unwrap();

    let report = scan::scan(
        std::slice::from_ref(&root),
        &ScanLimits::default(),
        &Cancellation::default(),
        |_| {},
    )
    .unwrap();
    fs::write(root.join("pkg/module.py.tmp"), b"changed\n").unwrap();
    fs::rename(root.join("pkg/module.py.tmp"), root.join("pkg/module.py")).unwrap();
    let second = rules::preview(
        report,
        rules::CPYTHON_SOURCE_BACKED_PYC_RULE_ID,
        &Cancellation::default(),
    )
    .unwrap();
    assert!(second.candidates.is_empty());
    assert!(
        second
            .refusals
            .iter()
            .any(|item| item.code == RefusalCode::IdentityChanged)
    );
    fixture.close().unwrap();
}

#[test]
fn cpython_preview_refuses_missing_or_linked_sources() {
    let fixture = Fixture::new().unwrap();
    let root = scope(&fixture);
    fs::create_dir_all(root.join("pkg/__pycache__")).unwrap();
    fs::write(
        root.join("pkg/__pycache__/module.cpython-39.pyc"),
        vec![0x22; 64],
    )
    .unwrap();
    let missing = preview(&root);
    assert!(missing.candidates.is_empty());
    assert!(
        missing
            .refusals
            .iter()
            .any(|item| item.code == RefusalCode::SourceMissing)
    );
    #[cfg(target_os = "macos")]
    {
        std::os::unix::fs::symlink("module.py.real", root.join("pkg/module.py")).unwrap();
        let linked = preview(&root);
        assert!(
            linked
                .refusals
                .iter()
                .any(|item| item.code == RefusalCode::SourceIsLink)
        );
    }
    fixture.close().unwrap();
}

#[test]
fn cpython_preview_refuses_ancestor_swap_to_symlinked_moved_directory() {
    let fixture = Fixture::new().unwrap();
    let root = scope(&fixture);
    let package = root.join("pkg");
    fs::create_dir_all(package.join("__pycache__")).unwrap();
    fs::write(package.join("module.py"), b"print('x')\n").unwrap();
    fs::write(
        package.join("__pycache__/module.cpython-39.pyc"),
        vec![0x33; 64],
    )
    .unwrap();
    let report = scan::scan(
        std::slice::from_ref(&root),
        &ScanLimits::default(),
        &Cancellation::default(),
        |_| {},
    )
    .unwrap();
    let outside = fixture.path().join("outside-sentinel");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("keep.txt"), b"outside must stay untouched").unwrap();
    let moved = outside.join("moved-pkg");
    fs::rename(&package, &moved).unwrap();
    std::os::unix::fs::symlink(&moved, &package).unwrap();
    let result = rules::preview(
        report,
        rules::CPYTHON_SOURCE_BACKED_PYC_RULE_ID,
        &Cancellation::default(),
    )
    .unwrap();
    assert!(result.candidates.is_empty());
    assert!(
        result
            .refusals
            .iter()
            .any(|item| item.code == RefusalCode::IdentityChanged)
    );
    assert_eq!(
        fs::read(outside.join("keep.txt")).unwrap(),
        b"outside must stay untouched"
    );
    fixture.close().unwrap();
}

#[test]
fn rule_bound_prepare_and_approve_succeed_without_native_effect() {
    let fixture = Fixture::new_in(&native_fixture_parent()).unwrap();
    let root = scope(&fixture);
    let (source, target, source_bytes, target_bytes) = setup_rule_bound_layout(&root);
    let scope = Scope::new(root.clone(), vec![]).unwrap();
    let cancellation = Cancellation::default();
    let mut session = TrashSession::prepare_rule_selection(
        scope,
        rules::CPYTHON_SOURCE_BACKED_PYC_RULE_ID,
        std::slice::from_ref(&target),
        &[],
        &cancellation,
    )
    .unwrap();
    let preview = session.preview().clone();
    assert_eq!(preview.schema_version(), 3);
    assert_eq!(preview.items().len(), 1);
    assert!(preview.items()[0].rule_binding().is_some());
    let approval = session.approve(&preview).unwrap();
    let cancellation = Cancellation::default();
    cancellation.cancel();
    let store = Store::open(&fixture.path().join("state").join("rules-trash"), true).unwrap();
    let report = session
        .execute(&preview, &approval, &cancellation, &store)
        .unwrap();
    assert_eq!(report.exit_code(), 130);
    assert_eq!(report.record.schema_version, 2);
    assert_eq!(report.record.plan_schema_version, 3);
    assert_eq!(
        report.record.items[0].state,
        sayaka_engine::journal::ItemState::Skipped
    );
    assert_eq!(report.record.items[0].reason.as_deref(), Some("cancelled"));
    assert_eq!(fs::read(&source).unwrap(), source_bytes);
    assert_eq!(fs::read(&target).unwrap(), target_bytes);
    fixture.close().unwrap();
}

#[test]
fn clean_session_rejects_candidate_identity_change_before_native_plan() {
    let fixture = Fixture::new_in(&native_fixture_parent()).unwrap();
    let root = scope(&fixture);
    let (_source, target, _source_bytes, _target_bytes) = setup_rule_bound_layout(&root);
    let preview = preview(&root);
    let config =
        clean_policy::resolve_config_path(Some(&fixture.path().join("clean-config"))).unwrap();
    let policy = clean_policy::snapshot_for_root(&config, &root).unwrap();
    let replacement = target.with_extension("tmp");
    fs::write(&replacement, b"replacement").unwrap();
    fs::rename(&replacement, &target).unwrap();
    let scope = Scope::new(root.clone(), vec![]).unwrap();
    let error = CleanSession::prepare_rule_selection(
        scope,
        &preview.candidates,
        std::slice::from_ref(&target),
        config,
        policy,
        &Cancellation::default(),
    )
    .err()
    .expect("prepare should fail on inode replacement");
    assert!(
        error
            .to_string()
            .contains("selected candidate changed after discovery")
    );
    fixture.close().unwrap();
}

#[test]
fn clean_session_approval_refuses_when_policy_created_after_preview() {
    let fixture = Fixture::new_in(&native_fixture_parent()).unwrap();
    let root = scope(&fixture);
    let (_source, target, _source_bytes, _target_bytes) = setup_rule_bound_layout(&root);
    let preview = preview(&root);
    let config = clean_config_path(&fixture);
    let policy = clean_policy::snapshot_for_root(&config, &root).unwrap();
    let scope = Scope::new(root.clone(), vec![]).unwrap();
    let mut session = CleanSession::prepare_rule_selection(
        scope,
        &preview.candidates,
        std::slice::from_ref(&target),
        config.clone(),
        policy,
        &Cancellation::default(),
    )
    .unwrap();
    clean_policy::add_entries(&config, &root, std::slice::from_ref(&root.join("pkg"))).unwrap();
    let error = session.approve().unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("policy_created_after_approval"));
    fixture.close().unwrap();
}

#[test]
fn clean_session_approval_refuses_when_policy_removed_after_preview() {
    let fixture = Fixture::new_in(&native_fixture_parent()).unwrap();
    let root = scope(&fixture);
    let (_source, target, _source_bytes, _target_bytes) = setup_rule_bound_layout(&root);
    let config = clean_config_path(&fixture);
    let keep = root.join("keep");
    fs::create_dir(&keep).unwrap();
    clean_policy::add_entries(&config, &root, std::slice::from_ref(&keep)).unwrap();
    let preview = preview(&root);
    let policy = clean_policy::snapshot_for_root(&config, &root).unwrap();
    let scope = Scope::new(root.clone(), vec![]).unwrap();
    let mut session = CleanSession::prepare_rule_selection(
        scope,
        &preview.candidates,
        std::slice::from_ref(&target),
        config.clone(),
        policy,
        &Cancellation::default(),
    )
    .unwrap();
    fs::remove_file(&config.file).unwrap();
    let error = session.approve().unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("policy_removed_after_approval"));
    fixture.close().unwrap();
}

#[test]
fn clean_session_approval_refuses_when_policy_corrupt_after_preview() {
    let fixture = Fixture::new_in(&native_fixture_parent()).unwrap();
    let root = scope(&fixture);
    let (_source, target, _source_bytes, _target_bytes) = setup_rule_bound_layout(&root);
    let config = clean_config_path(&fixture);
    let keep = root.join("keep");
    fs::create_dir(&keep).unwrap();
    clean_policy::add_entries(&config, &root, std::slice::from_ref(&keep)).unwrap();
    let preview = preview(&root);
    let policy = clean_policy::snapshot_for_root(&config, &root).unwrap();
    let scope = Scope::new(root.clone(), vec![]).unwrap();
    let mut session = CleanSession::prepare_rule_selection(
        scope,
        &preview.candidates,
        std::slice::from_ref(&target),
        config.clone(),
        policy,
        &Cancellation::default(),
    )
    .unwrap();
    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(&config.file)
        .unwrap();
    use std::io::Write;
    file.write_all(b"{corrupt").unwrap();
    file.sync_all().unwrap();
    let error = session.approve().unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    fixture.close().unwrap();
}

#[test]
fn clean_session_approval_refuses_when_policy_same_inode_edited_after_preview() {
    let fixture = Fixture::new_in(&native_fixture_parent()).unwrap();
    let root = scope(&fixture);
    let (_source, target, _source_bytes, _target_bytes) = setup_rule_bound_layout(&root);
    let config = clean_config_path(&fixture);
    let keep = root.join("keep");
    fs::create_dir(&keep).unwrap();
    clean_policy::add_entries(&config, &root, std::slice::from_ref(&keep)).unwrap();
    let preview = preview(&root);
    let policy = clean_policy::snapshot_for_root(&config, &root).unwrap();
    let scope = Scope::new(root.clone(), vec![]).unwrap();
    let mut session = CleanSession::prepare_rule_selection(
        scope,
        &preview.candidates,
        std::slice::from_ref(&target),
        config.clone(),
        policy,
        &Cancellation::default(),
    )
    .unwrap();
    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(&config.file)
        .unwrap();
    use std::io::Write;
    file.write_all(br#"{"schema_version":1,"kind":"sayaka_clean_exclusions","roots":[]}"#)
        .unwrap();
    file.sync_all().unwrap();
    let error = session.approve().unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("policy_"));
    fixture.close().unwrap();
}

#[test]
fn clean_session_approval_refuses_when_policy_replaced_after_preview() {
    let fixture = Fixture::new_in(&native_fixture_parent()).unwrap();
    let root = scope(&fixture);
    let (_source, target, _source_bytes, _target_bytes) = setup_rule_bound_layout(&root);
    let config = clean_config_path(&fixture);
    let keep = root.join("keep");
    fs::create_dir(&keep).unwrap();
    clean_policy::add_entries(&config, &root, std::slice::from_ref(&keep)).unwrap();
    let preview = preview(&root);
    let policy = clean_policy::snapshot_for_root(&config, &root).unwrap();
    let scope = Scope::new(root.clone(), vec![]).unwrap();
    let mut session = CleanSession::prepare_rule_selection(
        scope,
        &preview.candidates,
        std::slice::from_ref(&target),
        config.clone(),
        policy,
        &Cancellation::default(),
    )
    .unwrap();
    let replacement = config.directory.join("policy-replacement.json");
    fs::write(
        &replacement,
        br#"{"schema_version":1,"kind":"sayaka_clean_exclusions","roots":[]}"#,
    )
    .unwrap();
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
    fs::rename(&replacement, &config.file).unwrap();
    let error = session.approve().unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("policy_"));
    fixture.close().unwrap();
}

#[test]
fn clean_session_approval_refuses_when_exclusion_ancestor_becomes_symlink() {
    let fixture = Fixture::new_in(&native_fixture_parent()).unwrap();
    let root = scope(&fixture);
    let (_source, target, _source_bytes, target_bytes) = setup_rule_bound_layout(&root);
    let config = clean_config_path(&fixture);
    let protected_dir = root.join("cache/owned");
    fs::create_dir_all(&protected_dir).unwrap();
    clean_policy::add_entries(&config, &root, std::slice::from_ref(&protected_dir)).unwrap();
    let preview = preview(&root);
    let policy = clean_policy::snapshot_for_root(&config, &root).unwrap();
    let outside = fixture.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::rename(root.join("cache"), root.join("cache-real")).unwrap();
    std::os::unix::fs::symlink(&outside, root.join("cache")).unwrap();
    let scope = Scope::new(root.clone(), vec![]).unwrap();
    let error = match CleanSession::prepare_rule_selection(
        scope,
        &preview.candidates,
        std::slice::from_ref(&target),
        config,
        policy,
        &Cancellation::default(),
    ) {
        Ok(_) => panic!("prepare should fail when exclusion ancestry becomes symlink"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("cannot verify exclusion"));
    assert_eq!(fs::read(&target).unwrap(), target_bytes);
    fixture.close().unwrap();
}

#[test]
fn preserve_fixture_evidence_pattern_keeps_state_until_explicit_close() {
    let preserved = PreservedFixture::new();
    assert!(
        preserved
            .fixture
            .path()
            .starts_with(native_fixture_parent())
    );
    let evidence = NativeEvidenceLog {
        fixture_root: preserved.root().display().to_string(),
        state_dir: preserved.state_dir().display().to_string(),
        target: preserved.root().join("dummy.pyc").display().to_string(),
        source: preserved.root().join("dummy.py").display().to_string(),
        target_identity_before: None,
        source_identity_before: None,
        record_schema_version: None,
        record_plan_schema_version: None,
        operation_id: None,
        item_state: Some("prepared_only".into()),
        returned_destination: None,
        restore_error: None,
    };
    preserved.write_evidence(&evidence);
    assert!(preserved.evidence_path.exists());
    assert!(preserved.fixture.path().exists());
    preserved.close_success();
}

// Explicitly opt-in: this performs one real Trash move and one no-replace
// restore using exact returned destination identity, not Trash enumeration.
#[test]
#[ignore = "REAL SYSTEM TRASH: parent-controlled single run only"]
fn real_rule_bound_trash_session_round_trip_owned_fixture() {
    assert_eq!(
        std::env::var("SAYAKA_M3_TRASH_TEST").as_deref(),
        Ok("1"),
        "set SAYAKA_M3_TRASH_TEST=1 only for the one approved run"
    );
    assert_eq!(
        std::env::var("SAYAKA_M3_TRASH_TEST_QUIESCENT").as_deref(),
        Ok("1"),
        "set SAYAKA_M3_TRASH_TEST_QUIESCENT=1 only after confirming no concurrent Trash operations"
    );

    let preserved = PreservedFixture::new();
    preserved.announce();
    let root = preserved.root().to_path_buf();
    let (source, target, source_bytes, target_bytes) = setup_rule_bound_layout(&root);
    let source_before = fs::symlink_metadata(&source).unwrap();
    let source_identity_before = (
        source_before.dev(),
        source_before.ino(),
        source_before.len(),
        source_before.mtime(),
        source_before.nlink(),
        source_before.uid(),
    );
    let before = fs::metadata(&target).unwrap();
    let expected_identity = (before.dev(), before.ino(), before.len(), before.mtime());

    let mut evidence = NativeEvidenceLog {
        fixture_root: root.display().to_string(),
        state_dir: preserved.state_dir().display().to_string(),
        target: target.display().to_string(),
        source: source.display().to_string(),
        target_identity_before: Some((
            before.dev(),
            before.ino(),
            before.len(),
            before.mtime(),
            before.nlink(),
            before.uid(),
            before.mode(),
        )),
        source_identity_before: Some((
            source_before.dev(),
            source_before.ino(),
            source_before.len(),
            source_before.mtime(),
            source_before.nlink(),
            source_before.uid(),
            source_before.mode(),
        )),
        record_schema_version: None,
        record_plan_schema_version: None,
        operation_id: None,
        item_state: None,
        returned_destination: None,
        restore_error: None,
    };
    preserved.write_evidence(&evidence);

    let scope = Scope::new(root.clone(), vec![]).unwrap();
    let cancellation = Cancellation::default();
    let mut session = TrashSession::prepare_rule_selection(
        scope,
        rules::CPYTHON_SOURCE_BACKED_PYC_RULE_ID,
        std::slice::from_ref(&target),
        &[],
        &cancellation,
    )
    .unwrap();
    let preview = session.preview().clone();
    assert_eq!(preview.schema_version(), 3);
    assert_eq!(preview.items().len(), 1);
    assert!(preview.items()[0].rule_binding().is_some());
    let approval = session.approve(&preview).unwrap();
    let store = Store::open(preserved.state_dir(), true).unwrap();
    let report = session
        .execute(&preview, &approval, &cancellation, &store)
        .unwrap();
    let item = &report.record.items[0];
    evidence.record_schema_version = Some(report.record.schema_version);
    evidence.record_plan_schema_version = Some(report.record.plan_schema_version);
    evidence.operation_id = Some(report.record.operation_id.clone());
    evidence.item_state = Some(format!("{:?}", item.state));
    evidence.returned_destination = item
        .destination
        .as_ref()
        .map(native_path)
        .map(|path| path.display().to_string());
    preserved.write_evidence(&evidence);

    assert_eq!(report.exit_code(), 0);
    let binding = item.rule_binding.as_ref().expect("rule binding required");
    assert_eq!(
        binding.rule_version,
        rules::CPYTHON_SOURCE_BACKED_PYC_RULE_VERSION
    );
    assert_eq!(
        binding.semantics_digest,
        rules::CPYTHON_SOURCE_BACKED_PYC_TRASH_SEMANTICS_DIGEST
    );
    assert_eq!(binding.target.path, item.path);
    assert_eq!(native_path(&binding.source.path), source);
    let destination = native_path(item.destination.as_ref().expect("destination required"));

    assert!(
        !target.exists(),
        "original target must be absent after successful move"
    );
    let moved = fs::symlink_metadata(&destination).unwrap();
    assert!(
        moved.file_type().is_file(),
        "returned destination must be regular"
    );
    assert_eq!(
        moved.nlink(),
        1,
        "returned destination must not be hard-linked"
    );
    assert_eq!(
        (moved.dev(), moved.ino(), moved.len(), moved.mtime()),
        expected_identity
    );
    let source_after_move = fs::symlink_metadata(&source).unwrap();
    assert_eq!(
        (
            source_after_move.dev(),
            source_after_move.ino(),
            source_after_move.len(),
            source_after_move.mtime(),
            source_after_move.nlink(),
            source_after_move.uid()
        ),
        source_identity_before
    );
    assert_eq!(fs::read(&source).unwrap(), source_bytes);

    if let Err(error) = restore_no_replace(&destination, &target) {
        evidence.restore_error = Some(error.to_string());
        preserved.write_evidence(&evidence);
        panic!(
            "restore_no_replace failed; fixture and journal preserved at {}",
            preserved.fixture.path().display()
        );
    }
    let restored = fs::symlink_metadata(&target).unwrap();
    assert!(
        restored.file_type().is_file(),
        "restored target must be regular"
    );
    assert_eq!(
        (
            restored.dev(),
            restored.ino(),
            restored.len(),
            restored.mtime()
        ),
        expected_identity
    );
    assert_eq!(fs::read(&target).unwrap(), target_bytes);
    let source_after_restore = fs::symlink_metadata(&source).unwrap();
    assert_eq!(
        (
            source_after_restore.dev(),
            source_after_restore.ino(),
            source_after_restore.len(),
            source_after_restore.mtime(),
            source_after_restore.nlink(),
            source_after_restore.uid()
        ),
        source_identity_before
    );
    assert_eq!(fs::read(&source).unwrap(), source_bytes);
    let records = store.records().unwrap();
    assert_eq!(records.records.len(), 1);
    assert_eq!(records.records[0].schema_version, 2);
    assert_eq!(records.records[0].plan_schema_version, 3);
    let stored_binding = records.records[0].items[0]
        .rule_binding
        .as_ref()
        .expect("stored rule binding required");
    assert_eq!(
        stored_binding.rule_version,
        rules::CPYTHON_SOURCE_BACKED_PYC_RULE_VERSION
    );
    assert_eq!(native_path(&stored_binding.target.path), target);
    assert_eq!(native_path(&stored_binding.source.path), source);
    drop(records);
    drop(store);
    drop(session);
    preserved.close_success();
}
