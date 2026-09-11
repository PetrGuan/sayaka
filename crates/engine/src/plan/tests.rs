// SPDX-License-Identifier: MPL-2.0

use super::*;
use crate::receipt::{Outcome, Receipt, ReceiptState};
use std::cell::Cell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::time::UNIX_EPOCH;

#[derive(Clone)]
struct ManualClock(Rc<Cell<SystemTime>>);

impl ManualClock {
    fn new() -> Self {
        Self(Rc::new(Cell::new(UNIX_EPOCH + Duration::from_secs(1_000))))
    }
    fn advance(&self, seconds: u64) {
        self.0.set(self.now() + Duration::from_secs(seconds));
    }
}

impl Clock for ManualClock {
    fn now(&self) -> SystemTime {
        self.0.get()
    }
}

#[derive(Default)]
struct FakeProbe {
    values: HashMap<PathBuf, Result<Snapshot, ProbeError>>,
    inspected: Vec<PathBuf>,
    after_probe: Option<Box<dyn FnMut()>>,
}

impl Probe for FakeProbe {
    fn inspect(&mut self, scope: &Scope, path: &Path) -> Result<Snapshot, ProbeError> {
        assert!(path.starts_with(scope.root()));
        self.inspected.push(path.to_path_buf());
        let result = self
            .values
            .get(path)
            .cloned()
            .unwrap_or(Err(ProbeError::NotFound));
        if let Some(callback) = &mut self.after_probe {
            callback();
        }
        result
    }
}

fn root() -> PathBuf {
    #[cfg(windows)]
    {
        PathBuf::from(r"C:\sayaka-model-fixture")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/sayaka-model-fixture")
    }
}

fn snapshot(inode: u64) -> Snapshot {
    Snapshot {
        identity: Some(FileIdentity::Unix { device: 1, inode }),
        kind: ResourceKind::File,
        logical_bytes: Some(42),
        modified_at: Some(UNIX_EPOCH),
        complete: true,
        boundary: Boundary::Verified,
        protection: Protection::Clear,
        trash: Capability::Available,
        owner: OwnerState::NotApplicable,
    }
}

type TestPlanner = Planner<ManualClock, SequentialIds>;

fn setup() -> (TestPlanner, FakeProbe, ManualClock) {
    let clock = ManualClock::new();
    let scope = Scope::new(root(), vec![root().join("keep")]).unwrap();
    let planner = Planner::with_sources(
        scope,
        Versions {
            engine: 1,
            rules: 1,
        },
        clock.clone(),
        SequentialIds::default(),
    )
    .unwrap();
    (planner, FakeProbe::default(), clock)
}

fn discover(
    planner: &mut TestPlanner,
    probe: &mut FakeProbe,
    name: &str,
    state: Snapshot,
) -> Finding {
    let path = root().join(name);
    probe.values.insert(path.clone(), Ok(state));
    planner.discover(&path, probe).unwrap()
}

fn prepare(planner: &mut TestPlanner, ids: &[ResourceId]) -> Plan {
    planner.prepare(ids, &[], Duration::from_secs(60)).unwrap()
}

fn assert_code<T>(result: Result<T, Error>, expected: ReasonCode) {
    match result {
        Err(error) => assert_eq!(error.code, expected, "{error}"),
        Ok(_) => panic!("expected {}", expected.as_str()),
    }
}

#[test]
fn discovery_plan_approval_and_preflight_round_trip() {
    let (mut planner, mut probe, clock) = setup();
    let finding = discover(&mut planner, &mut probe, "file", snapshot(1));
    assert_eq!(finding.action(), Some(Action::MoveToTrash));
    assert_eq!(finding.reason().as_str(), "explicit_selection");
    assert_eq!(finding.observation().observed_at(), clock.now());
    assert_eq!(finding.refusal(), None);
    let id = finding.observation().id();
    let plan = prepare(&mut planner, &[id]);
    assert_eq!(plan.schema_version(), 1);
    assert_eq!(plan.scope(), root());
    assert_eq!(plan.bytes().exact(), Some(42));
    assert_eq!(plan.items()[0].recovery(), Recovery::PlatformDependentTrash);
    assert_eq!(plan.items()[0].reason(), FindingReason::ExplicitSelection);
    assert_eq!(planner.state(plan.id()).unwrap(), PlanState::Prepared);
    let approval = planner.approve(&plan).unwrap();
    assert_eq!(planner.state(plan.id()).unwrap(), PlanState::Approved);
    probe.inspected.clear();
    let report = planner
        .validate(&plan, &approval, &mut probe, &Cancellation::default())
        .unwrap();
    assert_eq!(report.plan, plan.id());
    assert_eq!(report.ready, plan.items());
    assert!(report.skipped.is_empty());
    assert_eq!(probe.inspected, [root().join("file")]);
    assert_eq!(planner.state(plan.id()).unwrap(), PlanState::Validated);
}

#[test]
fn invalid_paths_and_scope_boundaries_fail_before_probe() {
    for path in [PathBuf::new(), PathBuf::from("relative"), root().join("..")] {
        assert_code(Scope::new(path, vec![]), ReasonCode::InvalidScope);
    }
    let filesystem_root = root().ancestors().last().unwrap().to_path_buf();
    assert_code(
        Scope::new(filesystem_root, vec![]),
        ReasonCode::InvalidScope,
    );
    assert_code(
        Scope::new(root(), vec![PathBuf::from("relative")]),
        ReasonCode::InvalidPath,
    );
    let (mut planner, mut probe, _) = setup();
    for path in [
        PathBuf::new(),
        PathBuf::from("relative"),
        root().join("../outside"),
        root().join("nul\0file"),
    ] {
        assert_code(planner.discover(&path, &mut probe), ReasonCode::InvalidPath);
    }
    let sibling = root()
        .with_file_name("sayaka-model-fixture-other")
        .join("file");
    assert_code(
        planner.discover(&sibling, &mut probe),
        ReasonCode::OutsideScope,
    );
    assert!(probe.inspected.is_empty());
}

#[test]
fn protected_scope_and_paths_cannot_be_overridden_by_exclusions() {
    let (mut planner, mut probe, _) = setup();
    for (index, name) in ["", "keep", "keep/nested"].iter().enumerate() {
        let finding = discover(&mut planner, &mut probe, name, snapshot(index as u64 + 1));
        let id = finding.observation().id();
        assert_eq!(finding.refusal(), Some(ReasonCode::Protected));
        let plan = planner
            .prepare(&[id], &[id], Duration::from_secs(60))
            .unwrap();
        assert!(plan.items().is_empty());
        assert_eq!(plan.rejected()[0].code, ReasonCode::Protected);
        assert_code(planner.approve(&plan), ReasonCode::EmptyPlan);
    }
    let finding = discover(&mut planner, &mut probe, "keepish", snapshot(9));
    assert_eq!(finding.refusal(), None);
    let mut physically_protected = snapshot(10);
    physically_protected.protection = Protection::Protected;
    let finding = discover(&mut planner, &mut probe, "alias", physically_protected);
    let id = finding.observation().id();
    let plan = planner
        .prepare(&[id], &[id], Duration::from_secs(60))
        .unwrap();
    assert_eq!(plan.rejected()[0].code, ReasonCode::Protected);
}

#[test]
fn platform_system_protection_is_not_a_configurable_allow_list() {
    #[cfg(unix)]
    let path = PathBuf::from("/usr/sayaka-synthetic-file");
    #[cfg(windows)]
    let path = PathBuf::from(r"C:\Windows\sayaka-synthetic-file");
    #[cfg(not(any(unix, windows)))]
    let path = root().join("file");
    let scope = Scope::new(path.parent().unwrap().to_path_buf(), vec![]).unwrap();
    let mut planner = Planner::new(
        scope,
        Versions {
            engine: 1,
            rules: 1,
        },
    )
    .unwrap();
    let mut probe = FakeProbe::default();
    probe.values.insert(path.clone(), Ok(snapshot(1)));
    assert_eq!(
        planner.discover(&path, &mut probe).unwrap().refusal(),
        Some(ReasonCode::Protected)
    );
}

#[test]
fn eligibility_matrix_preserves_each_unknown_and_refusal() {
    let mut cases = Vec::new();
    for (capability, code) in [
        (Capability::Unsupported, ReasonCode::UnsupportedCapability),
        (Capability::NotAuthorized, ReasonCode::NotAuthorized),
        (
            Capability::TemporarilyUnavailable,
            ReasonCode::TemporarilyUnavailable,
        ),
        (Capability::Unknown, ReasonCode::UnknownCapability),
    ] {
        let mut state = snapshot(1);
        state.trash = capability;
        cases.push((state, code));
    }
    for (owner, code) in [
        (OwnerState::Running, ReasonCode::OwnerRunning),
        (OwnerState::Unknown, ReasonCode::OwnerUnknown),
    ] {
        let mut state = snapshot(1);
        state.owner = owner;
        cases.push((state, code));
    }
    for (boundary, code) in [
        (Boundary::OutsideScope, ReasonCode::OutsideScope),
        (Boundary::TraversesLink, ReasonCode::BoundaryUnverified),
        (Boundary::Unknown, ReasonCode::BoundaryUnverified),
    ] {
        let mut state = snapshot(1);
        state.boundary = boundary;
        cases.push((state, code));
    }
    for kind in [
        ResourceKind::Directory,
        ResourceKind::Link,
        ResourceKind::Other,
    ] {
        let mut state = snapshot(1);
        state.kind = kind;
        cases.push((state, ReasonCode::UnsupportedResource));
    }
    let mut state = snapshot(1);
    state.identity = None;
    cases.push((state, ReasonCode::IdentityUnknown));
    let mut state = snapshot(1);
    state.complete = false;
    cases.push((state, ReasonCode::IncompleteObservation));
    let mut state = snapshot(1);
    state.modified_at = None;
    cases.push((state, ReasonCode::IncompleteObservation));
    let mut state = snapshot(1);
    state.protection = Protection::Unknown;
    cases.push((state, ReasonCode::ProtectionUnknown));

    for (state, code) in cases {
        let (mut planner, mut probe, _) = setup();
        let finding = discover(&mut planner, &mut probe, "file", state.clone());
        assert_eq!(finding.refusal(), Some(code));
        assert_eq!(finding.action(), None);
        let plan = prepare(&mut planner, &[finding.observation().id()]);
        assert!(plan.items().is_empty());
        assert_eq!(plan.rejected()[0].code, code);
        assert_code(planner.approve(&plan), ReasonCode::EmptyPlan);

        let (mut planner, mut probe, _) = setup();
        let id = discover(&mut planner, &mut probe, "file", snapshot(1))
            .observation()
            .id();
        let plan = prepare(&mut planner, &[id]);
        let approval = planner.approve(&plan).unwrap();
        probe.values.insert(root().join("file"), Ok(state));
        let report = planner
            .validate(&plan, &approval, &mut probe, &Cancellation::default())
            .unwrap();
        assert!(report.ready.is_empty());
        assert_eq!(report.skipped[0].code, code);
    }
    for owner in [OwnerState::Stopped, OwnerState::NotApplicable] {
        let (mut planner, mut probe, _) = setup();
        let mut state = snapshot(1);
        state.owner = owner;
        assert_eq!(
            discover(&mut planner, &mut probe, "file", state).refusal(),
            None
        );
    }
}

#[test]
fn exclusions_use_component_boundaries_and_protect_descendants() {
    let (mut planner, mut probe, _) = setup();
    let mut directory = snapshot(1);
    directory.kind = ResourceKind::Directory;
    let excluded = discover(&mut planner, &mut probe, "cache", directory)
        .observation()
        .id();
    let child = discover(&mut planner, &mut probe, "cache/file", snapshot(2))
        .observation()
        .id();
    let sibling = discover(&mut planner, &mut probe, "cache-other/file", snapshot(3))
        .observation()
        .id();
    let plan = planner
        .prepare(&[child, sibling], &[excluded], Duration::from_secs(60))
        .unwrap();
    assert_eq!(
        plan.items()
            .iter()
            .map(PlanItem::resource)
            .collect::<Vec<_>>(),
        [sibling]
    );
    assert_eq!(
        plan.rejected(),
        [Rejection::new(child, ReasonCode::Excluded)]
    );
    assert_eq!(plan.exclusions(), [excluded]);
    assert_eq!(plan.bytes().exact(), Some(42));
}

#[test]
fn ambiguous_selection_and_duplicate_observations_are_rejected() {
    let (mut planner, mut probe, _) = setup();
    let parent = discover(&mut planner, &mut probe, "folder", snapshot(1))
        .observation()
        .id();
    let child = discover(&mut planner, &mut probe, "folder/file", snapshot(2))
        .observation()
        .id();
    assert_code(
        planner.discover(&root().join("folder"), &mut probe),
        ReasonCode::DuplicateResource,
    );
    assert_code(
        planner.prepare(&[parent, parent], &[], Duration::from_secs(1)),
        ReasonCode::DuplicateSelection,
    );
    assert_code(
        planner.prepare(&[child], &[parent, parent], Duration::from_secs(1)),
        ReasonCode::DuplicateSelection,
    );
    for selected in [[parent, child], [child, parent]] {
        assert_code(
            planner.prepare(&selected, &[], Duration::from_secs(1)),
            ReasonCode::OverlappingSelection,
        );
        assert_code(
            planner.prepare(&selected, &[parent], Duration::from_secs(1)),
            ReasonCode::OverlappingSelection,
        );
    }
    let alias = discover(&mut planner, &mut probe, "alias", snapshot(2))
        .observation()
        .id();
    assert_code(
        planner.prepare(&[child, alias], &[], Duration::from_secs(1)),
        ReasonCode::DuplicateIdentity,
    );
}

#[test]
fn unknown_and_cross_session_resources_never_resolve_by_local_number() {
    let (mut first, mut probe, _) = setup();
    let one = discover(&mut first, &mut probe, "one", snapshot(1))
        .observation()
        .id();
    let (mut second, mut probe, _) = setup();
    let two = discover(&mut second, &mut probe, "two", snapshot(2))
        .observation()
        .id();
    assert_eq!(one.value, two.value);
    assert_ne!(one, two);
    assert_code(
        second.prepare(&[one], &[], Duration::from_secs(1)),
        ReasonCode::UnknownResource,
    );
    assert_code(
        second.prepare(&[two], &[one], Duration::from_secs(1)),
        ReasonCode::UnknownResource,
    );
    let missing = ResourceId {
        session: second.session,
        value: u64::MAX,
    };
    assert_code(
        second.prepare(&[missing], &[], Duration::from_secs(1)),
        ReasonCode::UnknownResource,
    );
}

#[test]
fn byte_estimates_keep_unknown_separate_and_reject_overflow() {
    let (mut planner, mut probe, _) = setup();
    let mut unknown = snapshot(1);
    unknown.logical_bytes = None;
    let a = discover(&mut planner, &mut probe, "unknown", unknown)
        .observation()
        .id();
    let b = discover(&mut planner, &mut probe, "known", snapshot(2))
        .observation()
        .id();
    let plan = prepare(&mut planner, &[a, b]);
    assert_eq!(
        plan.bytes(),
        ByteEstimate {
            known_bytes: 42,
            unknown_items: 1
        }
    );
    assert_eq!(plan.bytes().exact(), None);
    assert_eq!(prepare(&mut planner, &[a]).bytes().exact(), None);
    let mut zero = snapshot(3);
    zero.logical_bytes = Some(0);
    let c = discover(&mut planner, &mut probe, "zero", zero)
        .observation()
        .id();
    assert_eq!(prepare(&mut planner, &[c]).bytes().exact(), Some(0));
    let mut huge = snapshot(4);
    huge.logical_bytes = Some(u64::MAX);
    let d = discover(&mut planner, &mut probe, "huge", huge)
        .observation()
        .id();
    assert_code(
        planner.prepare(&[b, d], &[], Duration::from_secs(1)),
        ReasonCode::SizeOverflow,
    );
}

#[test]
fn lifetime_validation_and_expiry_boundary_are_deterministic() {
    let (mut planner, mut probe, clock) = setup();
    let id = discover(&mut planner, &mut probe, "file", snapshot(1))
        .observation()
        .id();
    assert_code(
        planner.prepare(&[], &[], Duration::from_secs(1)),
        ReasonCode::EmptyPlan,
    );
    assert_code(
        planner.prepare(&[id], &[], Duration::ZERO),
        ReasonCode::InvalidLifetime,
    );
    assert_code(
        planner.prepare(&[id], &[], Duration::MAX),
        ReasonCode::InvalidLifetime,
    );
    let plan = prepare(&mut planner, &[id]);
    assert_eq!(
        plan.expires_at(),
        plan.created_at() + Duration::from_secs(60)
    );
    clock.advance(59);
    let approval = planner.approve(&plan).unwrap();
    clock.advance(1);
    probe.inspected.clear();
    assert_code(
        planner.validate(&plan, &approval, &mut probe, &Cancellation::default()),
        ReasonCode::ExpiredPlan,
    );
    assert!(probe.inspected.is_empty());
    assert_code(planner.approve(&plan), ReasonCode::ExpiredPlan);
}

#[test]
fn backwards_clock_does_not_extend_plan_validity() {
    let (mut planner, mut probe, clock) = setup();
    let id = discover(&mut planner, &mut probe, "file", snapshot(1))
        .observation()
        .id();
    let plan = prepare(&mut planner, &[id]);
    clock.0.set(clock.now() - Duration::from_secs(1));
    assert_code(planner.approve(&plan), ReasonCode::ClockInvalid);
    assert_code(
        planner.prepare(&[id], &[], Duration::from_secs(1)),
        ReasonCode::ClockInvalid,
    );
    clock.advance(1);
    assert!(planner.approve(&plan).is_ok());
}

#[test]
fn semantic_changes_and_rollbacks_invalidate_existing_plans() {
    for changed in [
        Versions {
            engine: 2,
            rules: 1,
        },
        Versions {
            engine: 1,
            rules: 2,
        },
    ] {
        let (mut planner, mut probe, _) = setup();
        let id = discover(&mut planner, &mut probe, "file", snapshot(1))
            .observation()
            .id();
        let plan = prepare(&mut planner, &[id]);
        let approval = planner.approve(&plan).unwrap();
        planner.set_versions(changed).unwrap();
        assert_code(planner.approve(&plan), ReasonCode::StalePlan);
        assert_code(
            planner.validate(&plan, &approval, &mut probe, &Cancellation::default()),
            ReasonCode::StalePlan,
        );
        planner
            .set_versions(Versions {
                engine: 1,
                rules: 1,
            })
            .unwrap();
        assert_code(planner.approve(&plan), ReasonCode::StalePlan);
        let fresh = prepare(&mut planner, &[id]);
        planner.set_versions(fresh.versions()).unwrap();
        assert!(planner.approve(&fresh).is_ok());
    }
}

#[test]
fn invalid_versions_leave_the_current_generation_unchanged() {
    for versions in [
        Versions {
            engine: 0,
            rules: 1,
        },
        Versions {
            engine: 1,
            rules: 0,
        },
    ] {
        assert_code(
            Planner::new(Scope::new(root(), vec![]).unwrap(), versions),
            ReasonCode::InvalidVersions,
        );
        let (mut planner, mut probe, _) = setup();
        let id = discover(&mut planner, &mut probe, "file", snapshot(1))
            .observation()
            .id();
        let plan = prepare(&mut planner, &[id]);
        assert_code(planner.set_versions(versions), ReasonCode::InvalidVersions);
        assert!(planner.approve(&plan).is_ok());
    }
}

#[test]
fn approval_matches_the_entire_immutable_preview() {
    let (mut planner, mut probe, _) = setup();
    let id = discover(&mut planner, &mut probe, "file", snapshot(1))
        .observation()
        .id();
    let plan = prepare(&mut planner, &[id]);
    let mut tampered = Vec::new();
    let mut copy = plan.clone();
    copy.items.clear();
    tampered.push(copy);
    let mut copy = plan.clone();
    copy.scope = root().join("elsewhere");
    tampered.push(copy);
    let mut copy = plan.clone();
    copy.expires_at += Duration::from_secs(1);
    tampered.push(copy);
    let mut copy = plan.clone();
    copy.created_at -= Duration::from_secs(1);
    tampered.push(copy);
    let mut copy = plan.clone();
    copy.bytes.known_bytes = 0;
    tampered.push(copy);
    let mut copy = plan.clone();
    copy.versions.rules += 1;
    tampered.push(copy);
    let mut copy = plan.clone();
    copy.excluded.push(id);
    tampered.push(copy);
    let mut copy = plan.clone();
    copy.rejected.push(Rejection::new(id, ReasonCode::Excluded));
    tampered.push(copy);
    let mut copy = plan.clone();
    copy.items[0].observation.path = root().join("replacement");
    tampered.push(copy);
    for copy in &tampered {
        assert_code(planner.approve(copy), ReasonCode::PlanMismatch);
    }
    let approval = planner.approve(&plan).unwrap();
    for copy in &tampered {
        assert_code(
            planner.validate(copy, &approval, &mut probe, &Cancellation::default()),
            ReasonCode::PlanMismatch,
        );
    }
    assert_eq!(planner.state(plan.id()).unwrap(), PlanState::Approved);
}

#[test]
fn approval_cannot_be_transferred_forged_or_replayed() {
    let (mut planner, mut probe, _) = setup();
    let id = discover(&mut planner, &mut probe, "file", snapshot(1))
        .observation()
        .id();
    let first = prepare(&mut planner, &[id]);
    let second = prepare(&mut planner, &[id]);
    let forged = Approval { plan: first.id() };
    assert_code(
        planner.validate(&first, &forged, &mut probe, &Cancellation::default()),
        ReasonCode::InvalidPlanState,
    );
    let approval = planner.approve(&first).unwrap();
    assert_code(planner.approve(&first), ReasonCode::InvalidPlanState);
    assert_code(
        planner.validate(&second, &approval, &mut probe, &Cancellation::default()),
        ReasonCode::ApprovalMismatch,
    );
    planner
        .validate(&first, &approval, &mut probe, &Cancellation::default())
        .unwrap();
    assert_code(
        planner.validate(&first, &approval, &mut probe, &Cancellation::default()),
        ReasonCode::InvalidPlanState,
    );
    assert_code(planner.approve(&first), ReasonCode::InvalidPlanState);
    let (mut foreign, mut foreign_probe, _) = setup();
    assert_code(foreign.approve(&first), ReasonCode::UnknownPlan);
    assert_code(
        foreign.validate(
            &first,
            &approval,
            &mut foreign_probe,
            &Cancellation::default(),
        ),
        ReasonCode::UnknownPlan,
    );
    assert_code(foreign.state(first.id()), ReasonCode::UnknownPlan);
}

#[test]
fn revalidation_only_shrinks_the_approved_set() {
    let (mut planner, mut probe, _) = setup();
    let a = discover(&mut planner, &mut probe, "a", snapshot(1))
        .observation()
        .id();
    let b = discover(&mut planner, &mut probe, "b", snapshot(2))
        .observation()
        .id();
    let excluded = discover(&mut planner, &mut probe, "excluded", snapshot(3))
        .observation()
        .id();
    let plan = planner
        .prepare(&[a, b, excluded], &[excluded], Duration::from_secs(60))
        .unwrap();
    let approval = planner.approve(&plan).unwrap();
    probe.values.insert(root().join("a"), Ok(snapshot(100)));
    probe
        .values
        .insert(root().join("new-file"), Ok(snapshot(4)));
    probe.inspected.clear();
    let report = planner
        .validate(&plan, &approval, &mut probe, &Cancellation::default())
        .unwrap();
    assert_eq!(
        report
            .ready
            .iter()
            .map(PlanItem::resource)
            .collect::<Vec<_>>(),
        [b]
    );
    assert_eq!(
        report.skipped,
        [Rejection::new(a, ReasonCode::ResourceChanged)]
    );
    assert_eq!(probe.inspected, [root().join("a"), root().join("b")]);
}

#[test]
fn changed_metadata_is_not_treated_as_the_same_approved_resource() {
    let mut changed = Vec::new();
    let mut state = snapshot(1);
    state.logical_bytes = Some(43);
    changed.push(state);
    let mut state = snapshot(1);
    state.logical_bytes = None;
    changed.push(state);
    let mut state = snapshot(1);
    state.modified_at = Some(UNIX_EPOCH + Duration::from_secs(1));
    changed.push(state);
    let mut state = snapshot(1);
    state.identity = Some(FileIdentity::Windows {
        volume_serial: 1,
        file_id: [1; 16],
    });
    changed.push(state);
    let mut state = snapshot(1);
    state.owner = OwnerState::Stopped;
    changed.push(state);
    for state in changed {
        let (mut planner, mut probe, _) = setup();
        let id = discover(&mut planner, &mut probe, "file", snapshot(1))
            .observation()
            .id();
        let plan = prepare(&mut planner, &[id]);
        let approval = planner.approve(&plan).unwrap();
        probe.values.insert(root().join("file"), Ok(state));
        let report = planner
            .validate(&plan, &approval, &mut probe, &Cancellation::default())
            .unwrap();
        assert!(report.ready.is_empty());
        assert_eq!(
            report.skipped,
            [Rejection::new(id, ReasonCode::ResourceChanged)]
        );
    }
}

#[test]
fn probe_failures_retain_their_cause_and_do_not_hide_other_results() {
    for failure in [
        ProbeError::NotFound,
        ProbeError::PermissionDenied,
        ProbeError::Unavailable,
        ProbeError::Other("fault\ninjected".into()),
    ] {
        let (mut planner, mut probe, _) = setup();
        probe
            .values
            .insert(root().join("missing"), Err(failure.clone()));
        let error = planner
            .discover(&root().join("missing"), &mut probe)
            .unwrap_err();
        assert_eq!(error.code, ReasonCode::ProbeFailed);
        assert_eq!(error.probe_error, Some(failure.clone()));
        assert!(std::error::Error::source(&error).is_some());
        assert!(!error.to_string().contains('\n'));
        let a = discover(&mut planner, &mut probe, "a", snapshot(1))
            .observation()
            .id();
        let b = discover(&mut planner, &mut probe, "b", snapshot(2))
            .observation()
            .id();
        let plan = prepare(&mut planner, &[a, b]);
        let approval = planner.approve(&plan).unwrap();
        probe.values.insert(root().join("a"), Err(failure.clone()));
        let report = planner
            .validate(&plan, &approval, &mut probe, &Cancellation::default())
            .unwrap();
        assert_eq!(report.ready[0].resource(), b);
        assert_eq!(report.skipped[0].resource, a);
        assert_eq!(report.skipped[0].code, ReasonCode::ProbeFailed);
        assert_eq!(report.skipped[0].probe_error, Some(failure));
    }
}

#[test]
fn cancellation_before_work_never_calls_the_probe() {
    let (mut planner, mut probe, _) = setup();
    let id = discover(&mut planner, &mut probe, "file", snapshot(1))
        .observation()
        .id();
    let plan = prepare(&mut planner, &[id]);
    let approval = planner.approve(&plan).unwrap();
    let cancellation = Cancellation::default();
    cancellation.cancel();
    probe.inspected.clear();
    let report = planner
        .validate(&plan, &approval, &mut probe, &cancellation)
        .unwrap();
    assert_eq!(report.skipped, [Rejection::new(id, ReasonCode::Cancelled)]);
    assert!(report.ready.is_empty());
    assert!(probe.inspected.is_empty());
}

#[test]
fn cancellation_during_probe_preserves_prior_results_and_stops_new_work() {
    let (mut planner, mut probe, _) = setup();
    let ids: Vec<_> = (1..=3)
        .map(|n| {
            discover(&mut planner, &mut probe, &n.to_string(), snapshot(n))
                .observation()
                .id()
        })
        .collect();
    let plan = prepare(&mut planner, &ids);
    let approval = planner.approve(&plan).unwrap();
    let cancellation = Cancellation::default();
    let signal = cancellation.clone();
    let mut calls = 0;
    probe.after_probe = Some(Box::new(move || {
        calls += 1;
        if calls == 2 {
            signal.cancel();
        }
    }));
    probe.inspected.clear();
    let report = planner
        .validate(&plan, &approval, &mut probe, &cancellation)
        .unwrap();
    assert_eq!(
        report
            .ready
            .iter()
            .map(PlanItem::resource)
            .collect::<Vec<_>>(),
        [ids[0]]
    );
    assert_eq!(
        report.skipped,
        [
            Rejection::new(ids[1], ReasonCode::Cancelled),
            Rejection::new(ids[2], ReasonCode::Cancelled)
        ]
    );
    assert_eq!(probe.inspected.len(), 2);
}

#[test]
fn expiry_or_clock_failure_during_a_probe_stops_further_probes() {
    for backwards in [false, true] {
        let (mut planner, mut probe, clock) = setup();
        let a = discover(&mut planner, &mut probe, "a", snapshot(1))
            .observation()
            .id();
        let b = discover(&mut planner, &mut probe, "b", snapshot(2))
            .observation()
            .id();
        let plan = prepare(&mut planner, &[a, b]);
        let approval = planner.approve(&plan).unwrap();
        probe.after_probe = Some(Box::new(move || {
            if backwards {
                clock.0.set(clock.now() - Duration::from_secs(1));
            } else {
                clock.advance(60);
            }
        }));
        probe.inspected.clear();
        let report = planner
            .validate(&plan, &approval, &mut probe, &Cancellation::default())
            .unwrap();
        let code = if backwards {
            ReasonCode::ClockInvalid
        } else {
            ReasonCode::ExpiredPlan
        };
        assert!(report.ready.is_empty());
        assert_eq!(
            report.skipped,
            [Rejection::new(a, code), Rejection::new(b, code)]
        );
        assert_eq!(probe.inspected, [root().join("a")]);
    }
}

struct FixedIds(VecDeque<u64>);
impl IdSource for FixedIds {
    fn next_id(&mut self) -> Option<u64> {
        self.0.pop_front()
    }
}

#[test]
fn id_sources_cannot_overwrite_resources_or_plans() {
    let scope = Scope::new(root(), vec![]).unwrap();
    let mut planner = Planner::with_sources(
        scope,
        Versions {
            engine: 1,
            rules: 1,
        },
        ManualClock::new(),
        FixedIds(VecDeque::from([7, 7, 8, 8, 9, 0])),
    )
    .unwrap();
    let mut probe = FakeProbe::default();
    probe.values.insert(root().join("a"), Ok(snapshot(1)));
    probe.values.insert(root().join("b"), Ok(snapshot(2)));
    let a = planner
        .discover(&root().join("a"), &mut probe)
        .unwrap()
        .observation()
        .id();
    assert_eq!(a.value, 7);
    assert_code(
        planner.discover(&root().join("b"), &mut probe),
        ReasonCode::IdentifierCollision,
    );
    let b = planner
        .discover(&root().join("b"), &mut probe)
        .unwrap()
        .observation()
        .id();
    assert_eq!(b.value, 8);
    assert_code(
        planner.prepare(&[a], &[], Duration::from_secs(1)),
        ReasonCode::IdentifierCollision,
    );
    let plan = planner
        .prepare(&[a, b], &[], Duration::from_secs(1))
        .unwrap();
    assert_eq!(plan.id().value, 9);
    assert_code(
        planner.prepare(&[a], &[], Duration::from_secs(1)),
        ReasonCode::IdentifierUnavailable,
    );
    assert_code(
        planner.prepare(&[a], &[], Duration::from_secs(1)),
        ReasonCode::IdentifierUnavailable,
    );
    assert_eq!(planner.state(plan.id()).unwrap(), PlanState::Prepared);
}

#[test]
fn sequential_ids_stop_at_exhaustion_instead_of_wrapping() {
    let mut ids = SequentialIds {
        next: Some(u64::MAX),
    };
    assert_eq!(ids.next_id(), Some(u64::MAX));
    assert_eq!(ids.next_id(), None);
    assert_eq!(ids.next_id(), None);
}

#[test]
fn native_paths_survive_and_display_control_characters_are_escaped() {
    let (mut planner, mut probe, _) = setup();
    let path = root().join("line\n\u{1b}[31m");
    probe.values.insert(path.clone(), Ok(snapshot(1)));
    let finding = planner.discover(&path, &mut probe).unwrap();
    assert_eq!(finding.observation().path(), path);
    assert!(!finding.observation().display_path().contains('\n'));
    assert!(!finding.observation().display_path().contains('\u{1b}'));
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        let path = root().join(std::ffi::OsString::from_vec(vec![b'f', 0xff]));
        probe.values.insert(path.clone(), Ok(snapshot(2)));
        let finding = planner.discover(&path, &mut probe).unwrap();
        let plan = prepare(&mut planner, &[finding.observation().id()]);
        let approval = planner.approve(&plan).unwrap();
        probe.inspected.clear();
        let report = planner
            .validate(&plan, &approval, &mut probe, &Cancellation::default())
            .unwrap();
        assert_eq!(report.ready[0].observation().path(), path);
        assert_eq!(probe.inspected, [path]);
    }
}

#[test]
fn receipt_transition_matrix_is_terminal_and_bound_to_plan_items() {
    let (mut planner, mut probe, _) = setup();
    let id = discover(&mut planner, &mut probe, "file", snapshot(1))
        .observation()
        .id();
    let other = discover(&mut planner, &mut probe, "other", snapshot(2))
        .observation()
        .id();
    let plan = prepare(&mut planner, &[id]);
    assert_code(Receipt::new(&plan, other), ReasonCode::UnknownResource);
    let outcomes = [
        Outcome::Succeeded,
        Outcome::Skipped(ReasonCode::Cancelled),
        Outcome::Failed(ReasonCode::OperationFailed),
        Outcome::Unknown(ReasonCode::OutcomeUnknown),
    ];
    let states = [
        ReceiptState::Planned,
        ReceiptState::Started,
        ReceiptState::Finished(outcomes[0]),
        ReceiptState::Finished(outcomes[1]),
        ReceiptState::Finished(outcomes[2]),
        ReceiptState::Finished(outcomes[3]),
    ];
    for state in states {
        for event in 0..=outcomes.len() {
            let mut receipt = Receipt::new(&plan, id).unwrap();
            if state != ReceiptState::Planned {
                receipt.start().unwrap();
            }
            if let ReceiptState::Finished(outcome) = state {
                receipt.finish(outcome).unwrap();
            }
            assert_eq!(receipt.plan(), plan.id());
            assert_eq!(receipt.resource(), id);
            assert_eq!(receipt.versions(), plan.versions());
            assert_eq!(receipt.action(), Action::MoveToTrash);
            assert_eq!(receipt.recovery(), Recovery::PlatformDependentTrash);
            let allowed = if event == outcomes.len() {
                state == ReceiptState::Planned
            } else {
                state == ReceiptState::Started
                    || (state == ReceiptState::Planned
                        && matches!(outcomes[event], Outcome::Skipped(_)))
            };
            let result = if event == outcomes.len() {
                receipt.start()
            } else {
                receipt.finish(outcomes[event])
            };
            if allowed {
                result.unwrap();
                let expected = if event == outcomes.len() {
                    ReceiptState::Started
                } else {
                    ReceiptState::Finished(outcomes[event])
                };
                assert_eq!(receipt.state(), expected);
            } else {
                assert_code(result, ReasonCode::InvalidTransition);
                assert_eq!(receipt.state(), state);
            }
        }
    }
}
