// SPDX-License-Identifier: MPL-2.0

use super::*;
use crate::rules;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn fixture_path(path: &str) -> PathBuf {
    if cfg!(windows) {
        Path::new(r"C:\").join(path.strip_prefix('/').expect("absolute fixture path"))
    } else {
        PathBuf::from(path)
    }
}

#[derive(Clone)]
struct TestClock(Rc<Cell<SystemTime>>);
impl Clock for TestClock {
    fn now(&self) -> SystemTime {
        self.0.get()
    }
}

struct FakePlatform {
    snapshots: HashMap<PathBuf, Snapshot>,
    journal_paths: HashMap<PathBuf, NativePath>,
    effects: Vec<PathBuf>,
    fail_on: Option<usize>,
    next_unknown: bool,
    unknown_evidence: Option<journal::RecoveryEvidence>,
    before_effect: Option<Box<dyn FnMut()>>,
    refuse_before_effect: Option<String>,
}
impl Probe for FakePlatform {
    fn inspect(&mut self, _: &Scope, path: &Path) -> Result<Snapshot, ProbeError> {
        self.snapshots
            .get(path)
            .cloned()
            .ok_or(ProbeError::NotFound)
    }
}
impl Platform for FakePlatform {
    fn effect(
        &mut self,
        path: &Path,
        stop: &mut dyn FnMut() -> bool,
        guard: &mut dyn FnMut() -> GuardDecision,
    ) -> Effect {
        if let Some(callback) = &mut self.before_effect {
            callback();
        }
        match guard() {
            GuardDecision::Proceed => {}
            GuardDecision::Refused(reason) => return Effect::Refused(reason),
        }
        if let Some(reason) = self.refuse_before_effect.take() {
            return Effect::Refused(reason);
        }
        if stop() {
            return Effect::Refused("stopped".into());
        }
        self.effects.push(path.to_owned());
        if self.fail_on == Some(self.effects.len()) {
            Effect::Failed("injected item failure".into())
        } else if self.next_unknown {
            Effect::Unknown {
                message: "injected ambiguous native result".into(),
                evidence: self.unknown_evidence.take().map(Box::new),
            }
        } else {
            Effect::Moved(fixture_path("/fixture-trash").join(path.file_name().unwrap()))
        }
    }

    fn journal_path(&self, path: &Path) -> NativePath {
        self.journal_paths
            .get(path)
            .expect("registered virtual filesystem path")
            .clone()
    }
}

#[derive(Default)]
struct FakeJournal {
    calls: Cell<usize>,
    fail_on: usize,
    cleanup_fail_on: usize,
    durable: RefCell<Vec<Record>>,
}
impl Journal for FakeJournal {
    fn new_id(&self) -> io::Result<String> {
        Ok("1-a".into())
    }
    fn publish(&self, record: &Record, _: bool) -> io::Result<journal::Publication> {
        record.validate()?;
        self.calls.set(self.calls.get() + 1);
        if self.calls.get() == self.fail_on {
            return Err(io::Error::other("injected journal failure"));
        }
        self.durable.borrow_mut().push(record.clone());
        Ok(journal::Publication {
            cleanup_error: (self.calls.get() == self.cleanup_fail_on)
                .then(|| io::Error::other("outcome durable; marker cleanup failed")),
        })
    }
}

fn clean_policy_context() -> journal::CleanPolicyContextRecord {
    journal::CleanPolicyContextRecord {
        schema_version: 1,
        kind: "sayaka_clean_policy_context".into(),
        root_path: journal::CleanPolicyPathRecord {
            encoding: "unix_bytes".into(),
            bytes_hex: "2f66697874757265".into(),
            display: "\"/fixture\"".into(),
        },
        root_identity: journal::CleanPolicyIdentityRecord {
            device: 1,
            inode: 1,
        },
        file_state: serde_json::json!({
            "state": "present",
            "path": {
                "encoding": "unix_bytes",
                "bytes_hex": "2f636f6e6669672f6578636c7573696f6e732d76312e6a736f6e",
                "display": "\"/config/exclusions-v1.json\""
            },
            "identity": {"device": 1, "inode": 44},
            "length": 100,
            "sha256": "abc123"
        }),
        effective_exclusions: vec![],
    }
}

fn setup() -> (Session<FakePlatform, TestClock>, TestClock) {
    let clock = TestClock(Rc::new(Cell::new(UNIX_EPOCH + Duration::from_secs(100))));
    let mut planner = Planner::with_sources(
        Scope::new(fixture_path("/fixture"), vec![]).unwrap(),
        Versions {
            engine: 2,
            rules: 1,
        },
        clock.clone(),
        SequentialIds::default(),
    )
    .unwrap()
    .for_revalidated_trash();
    let mut platform = FakePlatform {
        snapshots: HashMap::new(),
        journal_paths: HashMap::from([(
            fixture_path("/fixture"),
            NativePath::unix_fixture("/fixture"),
        )]),
        effects: Vec::new(),
        fail_on: None,
        next_unknown: false,
        unknown_evidence: None,
        before_effect: None,
        refuse_before_effect: None,
    };
    let mut selected = Vec::new();
    for index in 1..=2 {
        let wire_path = format!("/fixture/file{index}");
        let path = fixture_path(&wire_path);
        platform
            .journal_paths
            .insert(path.clone(), NativePath::unix_fixture(&wire_path));
        let destination = format!("/fixture-trash/file{index}");
        platform.journal_paths.insert(
            fixture_path(&destination),
            NativePath::unix_fixture(&destination),
        );
        platform.snapshots.insert(
            path.clone(),
            Snapshot {
                identity: Some(FileIdentity::Unix {
                    device: 1,
                    inode: index,
                }),
                kind: ResourceKind::File,
                logical_bytes: Some(7),
                modified_at: Some(UNIX_EPOCH),
                complete: true,
                boundary: Boundary::Verified,
                protection: Protection::Clear,
                trash: Capability::Available,
                owner: OwnerState::NotApplicable,
            },
        );
        selected.push(
            planner
                .discover(&path, &mut platform)
                .unwrap()
                .observation()
                .id(),
        );
    }
    let preview = planner
        .prepare(&selected, &[], Duration::from_secs(60))
        .unwrap();
    (
        Session {
            planner,
            platform,
            preview,
        },
        clock,
    )
}

fn execute(
    session: &mut Session<FakePlatform, TestClock>,
    journal: &FakeJournal,
) -> ExecutionReport {
    let preview = session.preview.clone();
    let approval = session.planner.approve(&preview).unwrap();
    session
        .execute(&preview, &approval, &Cancellation::default(), journal)
        .unwrap()
}

fn setup_rule_bound() -> (Session<FakePlatform, TestClock>, TestClock) {
    let clock = TestClock(Rc::new(Cell::new(UNIX_EPOCH + Duration::from_secs(100))));
    let mut planner = Planner::with_sources(
        Scope::new(fixture_path("/fixture"), vec![]).unwrap(),
        Versions {
            engine: 2,
            rules: 2,
        },
        clock.clone(),
        SequentialIds::default(),
    )
    .unwrap()
    .for_revalidated_trash();
    let mut platform = FakePlatform {
        snapshots: HashMap::new(),
        journal_paths: HashMap::from([(
            fixture_path("/fixture"),
            NativePath::unix_fixture("/fixture"),
        )]),
        effects: Vec::new(),
        fail_on: None,
        next_unknown: false,
        unknown_evidence: None,
        before_effect: None,
        refuse_before_effect: None,
    };
    let target_wire = "/fixture/pkg/__pycache__/module.cpython-39.pyc";
    let target_path = fixture_path(target_wire);
    let destination = "/fixture-trash/module.cpython-39.pyc";
    platform
        .journal_paths
        .insert(target_path.clone(), NativePath::unix_fixture(target_wire));
    platform.journal_paths.insert(
        fixture_path(destination),
        NativePath::unix_fixture(destination),
    );
    platform.snapshots.insert(
        target_path.clone(),
        Snapshot {
            identity: Some(FileIdentity::Unix {
                device: 1,
                inode: 99,
            }),
            kind: ResourceKind::File,
            logical_bytes: Some(12),
            modified_at: Some(UNIX_EPOCH),
            complete: true,
            boundary: Boundary::Verified,
            protection: Protection::Clear,
            trash: Capability::Available,
            owner: OwnerState::NotApplicable,
        },
    );
    let selected = vec![
        planner
            .discover(&target_path, &mut platform)
            .unwrap()
            .observation()
            .id(),
    ];
    let preview = planner
        .prepare(&selected, &[], Duration::from_secs(60))
        .unwrap();
    let mut bindings = HashMap::new();
    let item = &preview.items()[0];
    bindings.insert(
        item.resource(),
        RuleBinding {
            schema_version: 1,
            rule_id: rules::CPYTHON_SOURCE_BACKED_PYC_RULE_ID.into(),
            rule_version: rules::CPYTHON_SOURCE_BACKED_PYC_RULE_VERSION,
            ruleset_schema_version: rules::RULESET_SCHEMA_VERSION,
            ruleset_revision: rules::BUILTIN_RULESET_REVISION,
            semantics: rules::CPYTHON_SOURCE_BACKED_PYC_TRASH_SEMANTICS.into(),
            semantics_digest: rules::CPYTHON_SOURCE_BACKED_PYC_TRASH_SEMANTICS_DIGEST.into(),
            selected_root: fixture_path("/fixture"),
            exclusions: vec![],
            target: RuleWitness {
                path: fixture_path("/fixture/pkg/__pycache__/module.cpython-39.pyc"),
                identity: FileIdentity::Unix {
                    device: 1,
                    inode: 99,
                },
                kind: ResourceKind::File,
                logical_bytes: 12,
                modified_at: UNIX_EPOCH,
                changed_at: UNIX_EPOCH,
                created_at: UNIX_EPOCH,
                uid: 501,
                gid: 20,
                mode: 0o100600,
                nlink: 1,
                flags: 0,
            },
            source: RuleWitness {
                path: fixture_path("/fixture/pkg/module.py"),
                identity: FileIdentity::Unix {
                    device: 1,
                    inode: 98,
                },
                kind: ResourceKind::File,
                logical_bytes: 40,
                modified_at: UNIX_EPOCH,
                changed_at: UNIX_EPOCH,
                created_at: UNIX_EPOCH,
                uid: 501,
                gid: 20,
                mode: 0o100600,
                nlink: 1,
                flags: 0,
            },
            root: RuleWitness {
                path: fixture_path("/fixture"),
                identity: FileIdentity::Unix {
                    device: 1,
                    inode: 1,
                },
                kind: ResourceKind::Directory,
                logical_bytes: 0,
                modified_at: UNIX_EPOCH,
                changed_at: UNIX_EPOCH,
                created_at: UNIX_EPOCH,
                uid: 501,
                gid: 20,
                mode: 0o040700,
                nlink: 1,
                flags: 0,
            },
            target_ancestors: vec![
                RuleWitness {
                    path: fixture_path("/fixture/pkg"),
                    identity: FileIdentity::Unix {
                        device: 1,
                        inode: 40,
                    },
                    kind: ResourceKind::Directory,
                    logical_bytes: 0,
                    modified_at: UNIX_EPOCH,
                    changed_at: UNIX_EPOCH,
                    created_at: UNIX_EPOCH,
                    uid: 501,
                    gid: 20,
                    mode: 0o040700,
                    nlink: 1,
                    flags: 0,
                },
                RuleWitness {
                    path: fixture_path("/fixture/pkg/__pycache__"),
                    identity: FileIdentity::Unix {
                        device: 1,
                        inode: 41,
                    },
                    kind: ResourceKind::Directory,
                    logical_bytes: 0,
                    modified_at: UNIX_EPOCH,
                    changed_at: UNIX_EPOCH,
                    created_at: UNIX_EPOCH,
                    uid: 501,
                    gid: 20,
                    mode: 0o040700,
                    nlink: 1,
                    flags: 0,
                },
            ],
            source_ancestors: vec![RuleWitness {
                path: fixture_path("/fixture/pkg"),
                identity: FileIdentity::Unix {
                    device: 1,
                    inode: 40,
                },
                kind: ResourceKind::Directory,
                logical_bytes: 0,
                modified_at: UNIX_EPOCH,
                changed_at: UNIX_EPOCH,
                created_at: UNIX_EPOCH,
                uid: 501,
                gid: 20,
                mode: 0o040700,
                nlink: 1,
                flags: 0,
            }],
            warnings: vec!["metadata-only".into()],
        },
    );
    let preview = planner
        .seal_rule_bindings_for_prepared(preview.id(), &bindings)
        .unwrap();
    (
        Session {
            planner,
            platform,
            preview,
        },
        clock,
    )
}

#[test]
fn exact_versioned_approval_and_intent_precede_every_effect() {
    let (mut session, _) = setup();
    assert_eq!(session.preview.schema_version(), 2);
    assert_eq!(
        session.preview.items()[0].action(),
        Action::RevalidatedMoveToTrash
    );
    assert!(
        session
            .preview
            .execution_contract()
            .warning()
            .contains("different file")
    );
    let journal = FakeJournal::default();
    let report = execute(&mut session, &journal);
    assert_eq!(report.exit_code(), 0);
    assert_eq!(report.record.scope, NativePath::unix_fixture("/fixture"));
    assert_eq!(
        report.record.items[0].path,
        NativePath::unix_fixture("/fixture/file1")
    );
    assert_eq!(
        report.record.items[0].destination,
        Some(NativePath::unix_fixture("/fixture-trash/file1"))
    );
    assert_eq!(report.record.handled_bytes(), Some(14));
    let records = journal.durable.borrow();
    assert_eq!(records.len(), 5);
    assert_eq!(records[1].items[0].state, ItemState::Started);
    assert_eq!(records[2].items[0].state, ItemState::Succeeded);
    assert_eq!(records[3].items[1].state, ItemState::Started);
}

#[test]
fn intent_failure_never_enters_native_effect() {
    let (mut session, _) = setup();
    let journal = FakeJournal {
        fail_on: 2,
        ..Default::default()
    };
    let report = execute(&mut session, &journal);
    assert!(session.platform.effects.is_empty());
    assert!(report.journal_error.is_some());
    assert!(
        report
            .record
            .items
            .iter()
            .all(|item| item.state == ItemState::Skipped)
    );
}

#[test]
fn item_failure_preserves_successful_results_without_retry_or_delete_fallback() {
    for failed_index in 0..2 {
        let (mut session, _) = setup();
        session.platform.fail_on = Some(failed_index + 1);
        let journal = FakeJournal::default();
        let report = execute(&mut session, &journal);
        assert_eq!(report.exit_code(), 3);
        assert!(report.journal_error.is_none());
        assert_eq!(report.record.handled_bytes(), Some(7));
        let failed = &report.record.items[failed_index];
        assert_eq!(failed.state, ItemState::Failed);
        assert_eq!(failed.reason.as_deref(), Some("injected item failure"));
        assert!(failed.destination.is_none());
        assert_eq!(
            report.record.items[1 - failed_index].state,
            ItemState::Succeeded
        );
        assert_eq!(
            session.platform.effects,
            [
                fixture_path("/fixture/file1"),
                fixture_path("/fixture/file2")
            ]
        );
        let records = journal.durable.borrow();
        assert_eq!(records.len(), 5);
        assert_eq!(
            records.last().unwrap().items[failed_index].state,
            ItemState::Failed
        );
        assert_eq!(
            records.last().unwrap().items[1 - failed_index].state,
            ItemState::Succeeded
        );
        records.last().unwrap().validate().unwrap();
    }
}

#[test]
fn outcome_failure_stops_batch_and_preserves_interrupted_intent() {
    let (mut session, _) = setup();
    let journal = FakeJournal {
        fail_on: 3,
        ..Default::default()
    };
    let report = execute(&mut session, &journal);
    assert_eq!(session.platform.effects.len(), 1);
    assert_eq!(report.record.items[0].state, ItemState::Unknown);
    assert_eq!(report.record.items[1].state, ItemState::Skipped);
    assert_eq!(
        journal
            .durable
            .borrow()
            .last()
            .unwrap()
            .clone()
            .reconciled()
            .items[0]
            .state,
        ItemState::Unknown
    );
}

#[test]
fn durable_outcome_cleanup_warning_preserves_success_but_stops_batch() {
    let (mut session, _) = setup();
    let journal = FakeJournal {
        cleanup_fail_on: 3,
        ..Default::default()
    };
    let report = execute(&mut session, &journal);
    assert_eq!(session.platform.effects.len(), 1);
    assert_eq!(report.record.items[0].state, ItemState::Succeeded);
    assert_eq!(report.record.items[1].state, ItemState::Skipped);
    assert!(report.journal_error.is_some());
    assert_eq!(report.exit_code(), 1);
}

#[test]
fn intent_cleanup_warning_prevents_native_call() {
    let (mut session, _) = setup();
    let journal = FakeJournal {
        cleanup_fail_on: 2,
        ..Default::default()
    };
    let report = execute(&mut session, &journal);
    assert!(session.platform.effects.is_empty());
    assert!(report.journal_error.is_some());
    assert!(
        report
            .record
            .items
            .iter()
            .all(|item| item.state == ItemState::Skipped)
    );
}

#[test]
fn ambiguous_native_result_never_retries_or_starts_next_item() {
    let (mut session, _) = setup();
    session.platform.next_unknown = true;
    let report = execute(&mut session, &FakeJournal::default());
    assert_eq!(session.platform.effects.len(), 1);
    assert_eq!(report.record.items[0].state, ItemState::Unknown);
    assert_eq!(report.record.items[1].state, ItemState::Skipped);
}

#[test]
fn unverified_native_destination_and_held_evidence_survive_journaling() {
    let (mut session, _) = setup();
    let approved = journal::FileEvidence {
        device: 1,
        inode: 1,
        logical_bytes: 7,
        modified: journal::NativeTime::from_system_time(UNIX_EPOCH),
    };
    let evidence = journal::RecoveryEvidence {
        approved: approved.clone(),
        returned_destination: Some(NativePath::unix_fixture("/fixture-trash/reported")),
        held_source: Some(approved),
        held_source_path: Some(NativePath::unix_fixture("/fixture/held")),
        observation_errors: vec!["destination verification failed".into()],
    };
    session.platform.next_unknown = true;
    session.platform.unknown_evidence = Some(evidence.clone());
    let journal = FakeJournal::default();
    let report = execute(&mut session, &journal);
    assert_eq!(report.exit_code(), 1);
    assert_eq!(session.platform.effects.len(), 1);
    assert_eq!(report.record.items[0].state, ItemState::Unknown);
    assert!(report.record.items[0].destination.is_none());
    let encoded = serde_json::to_vec(journal.durable.borrow().last().unwrap()).unwrap();
    let reopened: Record = serde_json::from_slice(&encoded).unwrap();
    reopened.validate().unwrap();
    let reopened = reopened.reconciled();
    assert_eq!(
        reopened.items[0].recovery_evidence.as_ref(),
        Some(&evidence)
    );
    assert_eq!(reopened.items[0].state, ItemState::Unknown);
    assert_eq!(reopened.items[1].state, ItemState::Skipped);
}

#[test]
fn changed_target_is_skipped_without_expanding_approval() {
    let (mut session, _) = setup();
    session
        .platform
        .snapshots
        .get_mut(&fixture_path("/fixture/file1"))
        .unwrap()
        .identity = Some(FileIdentity::Unix {
        device: 1,
        inode: 99,
    });
    let report = execute(&mut session, &FakeJournal::default());
    assert_eq!(report.record.items[0].state, ItemState::Skipped);
    assert_eq!(
        report.record.items[0].reason.as_deref(),
        Some("resource_changed")
    );
    assert_eq!(session.platform.effects, [fixture_path("/fixture/file2")]);
}

#[test]
fn approval_is_one_shot_and_model_contract_cannot_execute() {
    let (mut session, _) = setup();
    let preview = session.preview.clone();
    let approval = session.planner.approve(&preview).unwrap();
    let journal = FakeJournal::default();
    session
        .execute(&preview, &approval, &Cancellation::default(), &journal)
        .unwrap();
    assert!(
        session
            .execute(&preview, &approval, &Cancellation::default(), &journal)
            .is_err()
    );
    let mut forged = preview;
    forged.contract = ExecutionContract::ModelOnly;
    assert!(
        session
            .execute(&forged, &approval, &Cancellation::default(), &journal)
            .is_err()
    );
    assert_eq!(session.platform.effects.len(), 2);
}

#[test]
fn expiry_at_final_native_boundary_stops_effect_after_intent() {
    let (mut session, clock) = setup();
    session.platform.before_effect = Some(Box::new(move || {
        clock.0.set(UNIX_EPOCH + Duration::from_secs(160))
    }));
    let report = execute(&mut session, &FakeJournal::default());
    assert!(session.platform.effects.is_empty());
    assert!(
        report
            .record
            .items
            .iter()
            .all(|item| item.state == ItemState::Skipped)
    );
    assert_eq!(
        report.record.items[0].reason.as_deref(),
        Some("expired_plan")
    );
}

#[test]
fn cancellation_at_final_native_boundary_is_not_success() {
    let (mut session, _) = setup();
    let cancellation = Cancellation::default();
    let trigger = cancellation.clone();
    session.platform.before_effect = Some(Box::new(move || trigger.cancel()));
    let preview = session.preview.clone();
    let approval = session.planner.approve(&preview).unwrap();
    let report = session
        .execute(&preview, &approval, &cancellation, &FakeJournal::default())
        .unwrap();
    assert!(session.platform.effects.is_empty());
    assert_eq!(report.exit_code(), 130);
}

#[test]
fn rule_bound_plan_can_be_approved_without_plan_mismatch() {
    let (mut session, _) = setup_rule_bound();
    assert_eq!(session.preview.schema_version(), 3);
    assert!(session.preview.items()[0].rule_binding().is_some());
    let approval = session.planner.approve(&session.preview.clone()).unwrap();
    assert_eq!(approval.plan, session.preview.id());
}

#[test]
fn mutated_rule_binding_cannot_be_approved() {
    let (mut session, _) = setup_rule_bound();
    let mut forged = session.preview.clone();
    let binding = forged.items[0].rule_binding.as_mut().unwrap();
    binding.semantics_digest = "sha256:forged".into();
    let error = session.planner.approve(&forged).unwrap_err();
    assert_eq!(error.code, ReasonCode::PlanMismatch);
}

#[test]
fn rule_bound_execute_publishes_schema_v3_v2_with_binding() {
    let (mut session, _) = setup_rule_bound();
    let preview = session.preview.clone();
    let approval = session.planner.approve(&preview).unwrap();
    let journal = FakeJournal::default();
    let report = session
        .execute(&preview, &approval, &Cancellation::default(), &journal)
        .unwrap();
    assert_eq!(report.exit_code(), 0);
    assert_eq!(report.record.plan_schema_version, 3);
    assert_eq!(report.record.schema_version, journal::SCHEMA_VERSION);
    let binding = report.record.items[0].rule_binding.as_ref().unwrap();
    assert_eq!(binding.rule_id, rules::CPYTHON_SOURCE_BACKED_PYC_RULE_ID);
    assert_eq!(
        binding.semantics_digest,
        rules::CPYTHON_SOURCE_BACKED_PYC_TRASH_SEMANTICS_DIGEST
    );
}

#[test]
fn cancel_before_native_effect_keeps_rule_bound_batch_at_zero_effect() {
    let (mut session, _) = setup_rule_bound();
    let cancellation = Cancellation::default();
    cancellation.cancel();
    let preview = session.preview.clone();
    let approval = session.planner.approve(&preview).unwrap();
    let journal = FakeJournal::default();
    let report = session
        .execute(&preview, &approval, &cancellation, &journal)
        .unwrap();
    assert!(session.platform.effects.is_empty());
    assert_eq!(report.record.items[0].state, ItemState::Skipped);
    assert_eq!(report.record.items[0].reason.as_deref(), Some("cancelled"));
    assert_eq!(
        journal.durable.borrow()[1].items[0].state,
        ItemState::Skipped
    );
}

#[test]
fn rule_bound_after_started_source_refusal_has_zero_effect_and_truthful_skip() {
    let (mut session, _) = setup_rule_bound();
    session.platform.refuse_before_effect = Some("source_changed_after_durable_intent".into());
    let preview = session.preview.clone();
    let approval = session.planner.approve(&preview).unwrap();
    let journal = FakeJournal::default();
    let report = session
        .execute(&preview, &approval, &Cancellation::default(), &journal)
        .unwrap();
    assert!(session.platform.effects.is_empty());
    assert_eq!(report.record.items[0].state, ItemState::Skipped);
    assert_eq!(
        report.record.items[0].reason.as_deref(),
        Some("source_changed_after_durable_intent")
    );
    let durable = journal.durable.borrow();
    assert_eq!(durable[1].items[0].state, ItemState::Started);
    assert_eq!(durable.last().unwrap().items[0].state, ItemState::Skipped);
}

#[test]
fn clean_execution_writes_policy_bound_schema_v3_record() {
    let (mut session, _) = setup_rule_bound();
    let preview = session.preview.clone();
    let approval = session.planner.approve(&preview).unwrap();
    let journal = FakeJournal::default();
    let mut guard = |_point: GuardPoint, _path: &Path| Ok(GuardDecision::Proceed);
    let report = session
        .execute_with_clean_policy(
            &preview,
            &approval,
            &Cancellation::default(),
            &journal,
            Some(clean_policy_context()),
            Some(&mut guard),
        )
        .unwrap();
    assert_eq!(report.exit_code(), 0);
    assert_eq!(report.record.schema_version, 3);
    assert!(report.record.clean_policy.is_some());
    report.record.validate().unwrap();
}

#[test]
fn clean_policy_refusal_after_started_makes_zero_effect_calls_and_stops_batch() {
    let (mut session, _) = setup_rule_bound();
    let preview = session.preview.clone();
    let approval = session.planner.approve(&preview).unwrap();
    let journal = FakeJournal::default();
    let mut guard = |point: GuardPoint, _path: &Path| {
        if matches!(point, GuardPoint::AfterStarted) {
            Ok(GuardDecision::Refused(
                "policy_refused_after_started:policy_content_changed_after_approval".into(),
            ))
        } else {
            Ok(GuardDecision::Proceed)
        }
    };
    let report = session
        .execute_with_clean_policy(
            &preview,
            &approval,
            &Cancellation::default(),
            &journal,
            Some(clean_policy_context()),
            Some(&mut guard),
        )
        .unwrap();
    assert!(session.platform.effects.is_empty());
    assert_eq!(report.record.items[0].state, ItemState::Skipped);
    assert!(report.record.clean_policy.is_some());
    assert!(
        report.record.items[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("policy_refused_after_started")
    );
    assert_ne!(report.record.items[0].reason.as_deref(), Some("cancelled"));
    let durable = journal.durable.borrow();
    assert_eq!(durable[1].items[0].state, ItemState::Started);
    assert_eq!(durable[2].items[0].state, ItemState::Skipped);
}

#[test]
fn clean_policy_refusal_at_last_native_guard_makes_zero_effect_calls() {
    let (mut session, _) = setup_rule_bound();
    let preview = session.preview.clone();
    let approval = session.planner.approve(&preview).unwrap();
    let journal = FakeJournal::default();
    let mut guard = |point: GuardPoint, _path: &Path| {
        if matches!(point, GuardPoint::LastNative) {
            Ok(GuardDecision::Refused(
                "policy_refused_last_native_guard:policy_content_changed_after_approval".into(),
            ))
        } else {
            Ok(GuardDecision::Proceed)
        }
    };
    let report = session
        .execute_with_clean_policy(
            &preview,
            &approval,
            &Cancellation::default(),
            &journal,
            Some(clean_policy_context()),
            Some(&mut guard),
        )
        .unwrap();
    assert!(session.platform.effects.is_empty());
    assert_eq!(report.record.items[0].state, ItemState::Skipped);
    assert!(
        report.record.items[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("policy_refused_last_native_guard")
    );
}

#[test]
fn clean_policy_guard_error_after_started_records_skipped_and_stops_without_effect() {
    for (kind, message) in [
        (io::ErrorKind::PermissionDenied, "policy unreadable"),
        (io::ErrorKind::InvalidData, "policy corrupt"),
        (io::ErrorKind::Other, "injected policy I/O"),
    ] {
        let (mut session, _) = setup_rule_bound();
        let preview = session.preview.clone();
        let approval = session.planner.approve(&preview).unwrap();
        let journal = FakeJournal::default();
        let mut guard = |point: GuardPoint, _path: &Path| {
            if matches!(point, GuardPoint::AfterStarted) {
                Err(io::Error::new(kind, message))
            } else {
                Ok(GuardDecision::Proceed)
            }
        };
        let report = session
            .execute_with_clean_policy(
                &preview,
                &approval,
                &Cancellation::default(),
                &journal,
                None,
                Some(&mut guard),
            )
            .unwrap();
        assert!(session.platform.effects.is_empty());
        assert_eq!(report.record.items[0].state, ItemState::Skipped);
        let reason = report.record.items[0].reason.as_deref().unwrap();
        assert!(reason.contains("policy_guard_error_after_started"));
        assert!(reason.contains("no_native_call"));
        assert_ne!(Some(reason), Some("cancelled"));
        let durable = journal.durable.borrow();
        assert_eq!(durable[1].items[0].state, ItemState::Started);
        assert_eq!(durable[2].items[0].state, ItemState::Skipped);
    }
}

#[test]
fn clean_policy_guard_error_after_started_publication_failure_keeps_ambiguity_and_no_effect() {
    let (mut session, _) = setup_rule_bound();
    let preview = session.preview.clone();
    let approval = session.planner.approve(&preview).unwrap();
    let journal = FakeJournal {
        fail_on: 3,
        ..Default::default()
    };
    let mut guard = |point: GuardPoint, _path: &Path| {
        if matches!(point, GuardPoint::AfterStarted) {
            Err(io::Error::other("injected policy read I/O failure"))
        } else {
            Ok(GuardDecision::Proceed)
        }
    };
    let report = session
        .execute_with_clean_policy(
            &preview,
            &approval,
            &Cancellation::default(),
            &journal,
            Some(clean_policy_context()),
            Some(&mut guard),
        )
        .unwrap();
    assert!(session.platform.effects.is_empty());
    assert!(report.journal_error.is_some());
    assert!(report.record.clean_policy.is_some());
    assert_eq!(report.record.items[0].state, ItemState::Skipped);
    let durable = journal.durable.borrow();
    assert_eq!(durable[1].items[0].state, ItemState::Started);
    assert_eq!(durable.len(), 2);
}
