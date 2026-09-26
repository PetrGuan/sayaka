// SPDX-License-Identifier: MPL-2.0

use super::*;
use crate::app_inventory::RunningObservation;
use crate::app_uninstall;
use crate::clean_policy::{self, ConfigPath, PolicyFileState, PolicyGuardStatus, PolicySnapshot};
use crate::journal::{CleanPolicyContextRecord, CleanPolicyIdentityRecord, CleanPolicyPathRecord};
use crate::purge_preview::{self, ProjectMarker};
use crate::rules;
use sayaka_platform_macos::{
    BundleTrashCandidate, CacheTrashCandidate, NativeFileInfo, NativeLastGuard,
    NativeRuleBindingWitness, NativeTargetMarker, NativeTrashOutcome, NativeWitnessInfo,
    PurgeTrashCandidate, TrashCandidate,
};
use std::collections::HashMap;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, UNIX_EPOCH};

struct MacPlatform {
    candidates: HashMap<PathBuf, TrashCandidate>,
    issues: Vec<SelectionIssue>,
}

impl Probe for MacPlatform {
    fn inspect(&mut self, scope: &Scope, path: &Path) -> Result<Snapshot, ProbeError> {
        if let Some(candidate) = self.candidates.get(path) {
            candidate
                .revalidate()
                .map_err(|error| ProbeError::Other(error.to_string()))?;
        } else {
            match TrashCandidate::capture_diagnostic(scope.root(), path, scope.protected_paths()) {
                Ok(candidate) => {
                    self.candidates.insert(path.to_owned(), candidate);
                }
                Err(failure) => {
                    self.issues.push(SelectionIssue {
                        path: NativePath::from_path(path),
                        message: failure.to_string(),
                        os_code: failure.error.raw_os_error(),
                        native_phase: Some(failure.phase),
                        native_operation: Some(failure.operation),
                    });
                    return Ok(Snapshot {
                        identity: None,
                        kind: ResourceKind::Other,
                        logical_bytes: None,
                        modified_at: None,
                        complete: false,
                        boundary: Boundary::Unknown,
                        protection: Protection::Unknown,
                        trash: Capability::Unsupported,
                        owner: OwnerState::Unknown,
                    });
                }
            }
        }
        let info = self
            .candidates
            .get(path)
            .ok_or_else(|| ProbeError::Other("native candidate was not retained".into()))?
            .info();
        Ok(Snapshot {
            identity: Some(FileIdentity::Unix {
                device: info.device,
                inode: info.inode,
            }),
            kind: ResourceKind::File,
            logical_bytes: Some(info.logical_bytes),
            modified_at: Some(info.modified_at),
            complete: true,
            boundary: Boundary::Verified,
            protection: Protection::Clear,
            trash: Capability::Available,
            owner: OwnerState::NotApplicable,
        })
    }
}

impl Platform for MacPlatform {
    fn effect(
        &mut self,
        path: &Path,
        stop: &mut dyn FnMut() -> bool,
        guard: &mut dyn FnMut() -> GuardDecision,
    ) -> Effect {
        let Some(candidate) = self.candidates.get(path) else {
            return Effect::Refused("native candidate unavailable".into());
        };
        match candidate.move_to_trash_with_last_guard(stop, || match guard() {
            GuardDecision::Proceed => NativeLastGuard::Proceed,
            GuardDecision::Refused(reason) => NativeLastGuard::PolicyRefused(reason),
        }) {
            NativeTrashOutcome::Moved { destination } => Effect::Moved(destination),
            NativeTrashOutcome::Refused(message) => Effect::Refused(message),
            NativeTrashOutcome::Failed(message) => Effect::Failed(message),
            NativeTrashOutcome::Unknown { message, evidence } => Effect::Unknown {
                message,
                evidence: Some(Box::new(journal::RecoveryEvidence {
                    approved: file_evidence(&evidence.approved),
                    returned_destination: evidence
                        .returned_destination
                        .as_deref()
                        .map(NativePath::from_path),
                    held_source: evidence.held_source.as_ref().map(file_evidence),
                    held_source_path: evidence
                        .held_source_path
                        .as_deref()
                        .map(NativePath::from_path),
                    observation_errors: evidence.observation_errors,
                })),
            },
        }
    }
}

fn file_evidence(info: &NativeFileInfo) -> journal::FileEvidence {
    journal::FileEvidence {
        device: info.device,
        inode: info.inode,
        logical_bytes: info.logical_bytes,
        modified: journal::NativeTime::from_system_time(info.modified_at),
    }
}

/// Only this session's engine-owned versioned preview can authorize its retained
/// candidates. An arbitrary M1 Probe or imported JSON cannot reach native effects.
pub struct TrashSession {
    inner: Session<MacPlatform>,
    selected_paths: HashMap<ResourceId, PathBuf>,
}

impl TrashSession {
    pub fn prepare(
        scope: Scope,
        paths: &[PathBuf],
        excluded: &[PathBuf],
        cancellation: &Cancellation,
    ) -> io::Result<Self> {
        if paths.is_empty()
            || paths.len() > journal::MAX_ITEMS
            || excluded.len() > journal::MAX_ITEMS
        {
            return Err(journal::invalid(
                "select between 1 and 32 explicit files, with at most 32 exclusions",
            ));
        }
        if excluded
            .iter()
            .any(|path| !crate::model::valid_absolute_path(path))
        {
            return Err(journal::invalid(
                "exclusions must be absolute native paths without traversal",
            ));
        }
        let mut planner = Planner::new(
            scope,
            Versions {
                engine: 2,
                rules: 1,
            },
        )
        .map_err(model_error)?
        .for_revalidated_trash();
        let mut platform = MacPlatform {
            candidates: HashMap::new(),
            issues: Vec::new(),
        };
        let mut selected = Vec::new();
        let mut excluded_ids = Vec::new();
        let mut selected_paths = HashMap::new();
        for path in paths {
            if cancellation.is_cancelled() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "cancelled during preview",
                ));
            }
            let finding = planner.discover(path, &mut platform).map_err(model_error)?;
            let id = finding.observation().id();
            selected.push(id);
            selected_paths.insert(id, path.clone());
            let mut is_excluded = excluded
                .iter()
                .any(|exclude| path.starts_with(exclude) || exclude.starts_with(path));
            if !is_excluded && let Some(candidate) = platform.candidates.get(path) {
                for exclude in excluded {
                    if cancellation.is_cancelled() {
                        return Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "cancelled during exclusion checks",
                        ));
                    }
                    if candidate.matches_exclusion(exclude).map_err(|error| {
                        io::Error::new(
                            error.kind(),
                            format!("cannot verify exclusion {:?}: {error}", exclude.as_os_str()),
                        )
                    })? {
                        is_excluded = true;
                        break;
                    }
                }
            }
            if is_excluded {
                excluded_ids.push(id);
            }
        }
        let preview = planner
            .prepare(&selected, &excluded_ids, Duration::from_secs(120))
            .map_err(model_error)?;
        Ok(Self {
            inner: Session {
                planner,
                platform,
                preview,
            },
            selected_paths,
        })
    }

    pub fn prepare_rule_selection(
        scope: Scope,
        rule_id: &str,
        paths: &[PathBuf],
        excluded: &[PathBuf],
        cancellation: &Cancellation,
    ) -> io::Result<Self> {
        let metadata = rules::binding_metadata(rule_id)
            .ok_or_else(|| journal::invalid("unsupported rule for native trash"))?;
        if metadata.rule_id != rule_id {
            return Err(journal::invalid("unsupported rule for native trash"));
        }
        if paths.is_empty()
            || paths.len() > journal::MAX_ITEMS
            || excluded.len() > journal::MAX_ITEMS
        {
            return Err(journal::invalid(
                "select between 1 and 32 explicit files, with at most 32 exclusions",
            ));
        }
        if excluded
            .iter()
            .any(|path| !crate::model::valid_absolute_path(path))
        {
            return Err(journal::invalid(
                "exclusions must be absolute native paths without traversal",
            ));
        }
        let mut planner = Planner::new(
            scope.clone(),
            Versions {
                engine: 2,
                rules: 2,
            },
        )
        .map_err(model_error)?
        .for_revalidated_trash();
        let mut platform = MacPlatform {
            candidates: HashMap::new(),
            issues: Vec::new(),
        };
        let mut selected = Vec::new();
        let mut excluded_ids = Vec::new();
        let mut selected_paths = HashMap::new();
        for path in paths {
            if cancellation.is_cancelled() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "cancelled during preview",
                ));
            }
            let selection =
                rules::explicit_selection_for_rule_target(rule_id, path).ok_or_else(|| {
                    journal::invalid("selected path is not a supported explicit rule target")
                })?;
            let marker = match selection.marker {
                rules::RuleTargetMarker::None => None,
                rules::RuleTargetMarker::Prefix4(bytes) => Some(NativeTargetMarker::Prefix4(bytes)),
            };
            let candidate = TrashCandidate::capture_with_source_and_marker(
                scope.root(),
                &selection.target_path,
                &selection.source_path,
                marker,
                scope.protected_paths(),
            )?;
            platform.candidates.insert(path.to_owned(), candidate);
            let finding = planner.discover(path, &mut platform).map_err(model_error)?;
            let id = finding.observation().id();
            selected.push(id);
            selected_paths.insert(id, path.clone());
            let mut is_excluded = excluded
                .iter()
                .any(|exclude| path.starts_with(exclude) || exclude.starts_with(path));
            if !is_excluded && let Some(candidate) = platform.candidates.get(path) {
                for exclude in excluded {
                    if cancellation.is_cancelled() {
                        return Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "cancelled during exclusion checks",
                        ));
                    }
                    if candidate.matches_exclusion(exclude).map_err(|error| {
                        io::Error::new(
                            error.kind(),
                            format!("cannot verify exclusion {:?}: {error}", exclude.as_os_str()),
                        )
                    })? {
                        is_excluded = true;
                        break;
                    }
                }
            }
            if is_excluded {
                excluded_ids.push(id);
            }
        }
        let preview = planner
            .prepare(&selected, &excluded_ids, Duration::from_secs(120))
            .map_err(model_error)?;
        let mut bindings = HashMap::with_capacity(preview.items().len());
        for item in preview.items() {
            let candidate = platform
                .candidates
                .get(item.observation().path())
                .ok_or_else(|| journal::invalid("rule-bound candidate unavailable"))?;
            let witness = candidate
                .rule_binding_witness()
                .ok_or_else(|| journal::invalid("missing rule-bound witness"))?;
            bindings.insert(
                item.resource(),
                Self::to_rule_binding(metadata, &scope, excluded, witness)?,
            );
        }
        let preview = planner
            .seal_rule_bindings_for_prepared(preview.id(), &bindings)
            .map_err(model_error)?;
        Ok(Self {
            inner: Session {
                planner,
                platform,
                preview,
            },
            selected_paths,
        })
    }

    pub fn preview(&self) -> &Plan {
        &self.inner.preview
    }

    /// A Finder metadata preview is only approvable if every native candidate
    /// captured for this plan still has the scan-observed file identity.
    pub fn matches_observed_identities(&self, expected: &[(PathBuf, FileIdentity)]) -> bool {
        expected.iter().all(|(path, identity)| {
            self.inner
                .platform
                .candidates
                .get(path)
                .is_some_and(|candidate| {
                    let info = candidate.info();
                    *identity
                        == FileIdentity::Unix {
                            device: info.device,
                            inode: info.inode,
                        }
                })
        })
    }

    fn to_rule_binding(
        metadata: rules::RuleBindingMetadata,
        scope: &Scope,
        excluded: &[PathBuf],
        witness: &NativeRuleBindingWitness,
    ) -> io::Result<RuleBinding> {
        Ok(RuleBinding {
            schema_version: 1,
            rule_id: metadata.rule_id.to_owned(),
            rule_version: metadata.rule_version,
            ruleset_schema_version: metadata.ruleset_schema_version,
            ruleset_revision: metadata.ruleset_revision,
            semantics: metadata.semantics.to_owned(),
            semantics_digest: metadata.semantics_digest.to_owned(),
            selected_root: scope.root().to_path_buf(),
            exclusions: excluded.to_vec(),
            target: Self::to_witness(&witness.target)?,
            source: Self::to_witness(&witness.source)?,
            root: Self::to_witness(&witness.root)?,
            target_ancestors: witness
                .target_ancestors
                .iter()
                .map(Self::to_witness)
                .collect::<io::Result<Vec<_>>>()?,
            source_ancestors: witness
                .source_ancestors
                .iter()
                .map(Self::to_witness)
                .collect::<io::Result<Vec<_>>>()?,
            warnings: vec![
                "Marker/source evidence is bounded identity metadata only; provenance and rebuild success are not guaranteed.".into(),
                "A file or ancestor replaced after the last check can still move a different object.".into(),
                "Trash does not guarantee restoration and does not measure freed space.".into(),
            ],
        })
    }

    fn to_witness(info: &NativeWitnessInfo) -> io::Result<RuleWitness> {
        let modified_at = Self::time_from_parts(
            info.modified_unix_seconds,
            info.modified_nanoseconds,
            "modified",
        )?;
        let changed_at = Self::time_from_parts(
            info.changed_unix_seconds,
            info.changed_nanoseconds,
            "changed",
        )?;
        let created_at = Self::time_from_parts(
            info.created_unix_seconds,
            info.created_nanoseconds,
            "created",
        )?;
        Ok(RuleWitness {
            path: info.path.clone(),
            identity: FileIdentity::Unix {
                device: info.device,
                inode: info.inode,
            },
            kind: match info.kind {
                "file" => ResourceKind::File,
                "directory" => ResourceKind::Directory,
                "link" => ResourceKind::Link,
                _ => ResourceKind::Other,
            },
            logical_bytes: info.logical_bytes,
            modified_at,
            changed_at,
            created_at,
            uid: info.uid,
            gid: info.gid,
            mode: info.mode,
            nlink: info.nlink,
            flags: info.flags,
        })
    }

    fn time_from_parts(seconds: i64, nanos: i64, label: &str) -> io::Result<std::time::SystemTime> {
        if !(0..1_000_000_000).contains(&nanos) {
            return Err(io::Error::other(format!(
                "invalid witness {label} nanoseconds"
            )));
        }
        let duration =
            Duration::from_secs(seconds.max(0) as u64) + Duration::from_nanos(nanos as u64);
        UNIX_EPOCH
            .checked_add(duration)
            .ok_or_else(|| io::Error::other(format!("invalid witness {label} time")))
    }
    pub fn issues(&self) -> &[SelectionIssue] {
        &self.inner.platform.issues
    }
    pub fn refusals(&self) -> Vec<SelectionRefusal> {
        self.inner
            .preview
            .rejected()
            .iter()
            .map(|item| SelectionRefusal {
                path: NativePath::from_path(&self.selected_paths[&item.resource]),
                reason: item.code.as_str().into(),
            })
            .collect()
    }
    pub fn approve(&mut self, preview: &Plan) -> Result<Approval, Error> {
        self.inner.planner.approve(preview)
    }
    pub fn execute(
        &mut self,
        preview: &Plan,
        approval: &Approval,
        cancellation: &Cancellation,
        store: &Store,
    ) -> io::Result<ExecutionReport> {
        self.inner.execute(preview, approval, cancellation, store)
    }

    pub fn execute_with_exclusions(
        &mut self,
        preview: &Plan,
        approval: &Approval,
        cancellation: &Cancellation,
        store: &Store,
        policy: Option<(&ConfigPath, &Path, &PolicySnapshot)>,
    ) -> io::Result<ExecutionReport> {
        let mut guard = move |_: GuardPoint, _: &Path| -> io::Result<GuardDecision> {
            if let Some((config, root, snapshot)) = policy {
                match clean_policy::guard_snapshot(config, root, snapshot)? {
                    PolicyGuardStatus::Unchanged => {}
                    PolicyGuardStatus::Refused(reason) => {
                        return Ok(GuardDecision::Refused(reason));
                    }
                }
            }
            Ok(GuardDecision::Proceed)
        };
        self.inner.execute_with_clean_policy(
            preview,
            approval,
            cancellation,
            store,
            None,
            Some(&mut guard),
        )
    }

    pub(crate) fn execute_with_clean_policy(
        &mut self,
        preview: &Plan,
        approval: &Approval,
        cancellation: &Cancellation,
        store: &Store,
        clean_policy: CleanPolicyContextRecord,
        guard: &mut dyn FnMut(GuardPoint, &Path) -> io::Result<GuardDecision>,
    ) -> io::Result<ExecutionReport> {
        self.inner.execute_with_clean_policy(
            preview,
            approval,
            cancellation,
            store,
            Some(clean_policy),
            Some(guard),
        )
    }
}

/// Single sealed `.app` bundle Trash session (T9); the plan runs under
/// ExecutionContract::RevalidatedBundleTrashV1. See docs/UNINSTALL_EXECUTION.md.
pub struct BundleUninstallSession {
    inner: Session<BundlePlatform>,
    bundle: PathBuf,
}

struct BundlePlatform {
    candidates: HashMap<PathBuf, BundleTrashCandidate>,
    issues: Vec<SelectionIssue>,
}

impl BundlePlatform {
    /// The planner fails closed on owner state: anything but a proven
    /// absence of running bundle executables refuses the item.
    fn owner_state(bundle: &Path) -> OwnerState {
        match app_uninstall::bundle_running(bundle) {
            RunningObservation::Running(_) => OwnerState::Running,
            RunningObservation::NotRunning => OwnerState::Stopped,
            RunningObservation::NotAttributable(_) | RunningObservation::Unknown => {
                OwnerState::Unknown
            }
            RunningObservation::NotChecked => OwnerState::Unknown,
        }
    }
}

impl Probe for BundlePlatform {
    fn inspect(&mut self, scope: &Scope, path: &Path) -> Result<Snapshot, ProbeError> {
        if let Some(candidate) = self.candidates.get(path) {
            candidate
                .revalidate()
                .map_err(|error| ProbeError::Other(error.to_string()))?;
        } else {
            match BundleTrashCandidate::capture(scope.root(), path, scope.protected_paths()) {
                Ok(candidate) => {
                    self.candidates.insert(path.to_owned(), candidate);
                }
                Err(error) => {
                    self.issues.push(SelectionIssue {
                        path: NativePath::from_path(path),
                        message: error.to_string(),
                        os_code: error.raw_os_error(),
                        native_phase: None,
                        native_operation: None,
                    });
                    return Ok(Snapshot {
                        identity: None,
                        kind: ResourceKind::Other,
                        logical_bytes: None,
                        modified_at: None,
                        complete: false,
                        boundary: Boundary::Unknown,
                        protection: Protection::Unknown,
                        trash: Capability::Unsupported,
                        owner: OwnerState::Unknown,
                    });
                }
            }
        }
        let info = self
            .candidates
            .get(path)
            .ok_or_else(|| ProbeError::Other("native candidate was not retained".into()))?
            .info();
        Ok(Snapshot {
            identity: Some(FileIdentity::Unix {
                device: info.device,
                inode: info.inode,
            }),
            kind: ResourceKind::Directory,
            // The directory's own inode bytes, not a subtree total.
            logical_bytes: Some(info.logical_bytes),
            modified_at: Some(info.modified_at),
            complete: true,
            boundary: Boundary::Verified,
            protection: Protection::Clear,
            trash: Capability::Available,
            owner: Self::owner_state(path),
        })
    }
}

impl Platform for BundlePlatform {
    fn effect(
        &mut self,
        path: &Path,
        stop: &mut dyn FnMut() -> bool,
        guard: &mut dyn FnMut() -> GuardDecision,
    ) -> Effect {
        let Some(candidate) = self.candidates.get(path) else {
            return Effect::Refused("native bundle candidate unavailable".into());
        };
        match candidate.move_to_trash_with_last_guard(stop, || match guard() {
            GuardDecision::Proceed => NativeLastGuard::Proceed,
            GuardDecision::Refused(reason) => NativeLastGuard::PolicyRefused(reason),
        }) {
            NativeTrashOutcome::Moved { destination } => Effect::Moved(destination),
            NativeTrashOutcome::Refused(message) => Effect::Refused(message),
            NativeTrashOutcome::Failed(message) => Effect::Failed(message),
            NativeTrashOutcome::Unknown { message, evidence } => Effect::Unknown {
                message,
                evidence: Some(Box::new(journal::RecoveryEvidence {
                    approved: file_evidence(&evidence.approved),
                    returned_destination: evidence
                        .returned_destination
                        .as_deref()
                        .map(NativePath::from_path),
                    held_source: evidence.held_source.as_ref().map(file_evidence),
                    held_source_path: evidence
                        .held_source_path
                        .as_deref()
                        .map(NativePath::from_path),
                    observation_errors: evidence.observation_errors,
                })),
            },
        }
    }
}

impl BundleUninstallSession {
    /// Prepares a sealed plan for exactly one explicit `.app` bundle. The
    /// scope must be the bundle's parent directory; exclusions are the
    /// preview contract's refusal surface, not plan exclusions.
    pub fn prepare(scope: Scope, bundle: &Path, cancellation: &Cancellation) -> io::Result<Self> {
        let mut planner = Planner::new(
            scope,
            Versions {
                engine: 2,
                rules: 1,
            },
        )
        .map_err(model_error)?
        .for_revalidated_bundle_trash();
        let mut platform = BundlePlatform {
            candidates: HashMap::new(),
            issues: Vec::new(),
        };
        if cancellation.is_cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "cancelled during preview",
            ));
        }
        let finding = planner
            .discover(bundle, &mut platform)
            .map_err(model_error)?;
        let id = finding.observation().id();
        let preview = planner
            .prepare(&[id], &[], Duration::from_secs(120))
            .map_err(model_error)?;
        Ok(Self {
            inner: Session {
                planner,
                platform,
                preview,
            },
            bundle: bundle.to_path_buf(),
        })
    }

    pub fn preview(&self) -> &Plan {
        &self.inner.preview
    }

    pub fn issues(&self) -> &[SelectionIssue] {
        &self.inner.platform.issues
    }

    pub fn refusals(&self) -> Vec<SelectionRefusal> {
        self.inner
            .preview
            .rejected()
            .iter()
            .map(|item| SelectionRefusal {
                path: NativePath::from_path(&self.bundle),
                reason: item.code.as_str().into(),
            })
            .collect()
    }

    /// Approval re-observes the running state per the execution contract;
    /// anything but a proven clear state refuses approval.
    pub fn approve(&mut self, preview: &Plan) -> Result<Approval, Error> {
        match app_uninstall::bundle_running(&self.bundle) {
            RunningObservation::NotRunning => {}
            RunningObservation::Running(_) => return Err(Error::new(ReasonCode::OwnerRunning)),
            _ => return Err(Error::new(ReasonCode::OwnerUnknown)),
        }
        self.inner.planner.approve(preview)
    }

    pub fn execute(
        &mut self,
        preview: &Plan,
        approval: &Approval,
        cancellation: &Cancellation,
        store: &Store,
    ) -> io::Result<ExecutionReport> {
        let bundle = self.bundle.clone();
        let mut guard = move |point: GuardPoint, _: &Path| -> io::Result<GuardDecision> {
            // Last native guard: re-observe running immediately before the
            // sole Foundation call; fail closed on any unclear state.
            if matches!(point, GuardPoint::LastNative) {
                return Ok(match app_uninstall::bundle_running(&bundle) {
                    RunningObservation::NotRunning => GuardDecision::Proceed,
                    RunningObservation::Running(pids) => GuardDecision::Refused(format!(
                        "bundle executables are running (pids: {pids:?}); refused, never signaled"
                    )),
                    other => GuardDecision::Refused(format!(
                        "running state is not proven clear ({}); refused",
                        other.as_str()
                    )),
                });
            }
            Ok(GuardDecision::Proceed)
        };
        self.inner.execute_with_clean_policy(
            preview,
            approval,
            cancellation,
            store,
            None,
            Some(&mut guard),
        )
    }
}

/// Explicit Trash session for sealed marker-bound project artifacts (T8
/// purge). Every item moves as one container under its own candidate; the
/// marker files are revalidation evidence and are never targets.
pub struct PurgeSession {
    inner: Session<PurgePlatform>,
    selections: Vec<PurgeSelection>,
    discovered: Vec<(ResourceId, PathBuf)>,
}

pub struct CacheSession {
    inner: Session<CachePlatform>,
    selections: Vec<CacheSelection>,
    discovered: Vec<(ResourceId, PathBuf)>,
}

struct CachePlatform {
    candidates: HashMap<PathBuf, CacheTrashCandidate>,
    issues: Vec<SelectionIssue>,
}

impl Probe for CachePlatform {
    fn inspect(&mut self, _scope: &Scope, path: &Path) -> Result<Snapshot, ProbeError> {
        let candidate = self
            .candidates
            .get(path)
            .ok_or_else(|| ProbeError::Other("native cache candidate was not retained".into()))?;
        candidate
            .revalidate()
            .map_err(|error| ProbeError::Other(error.to_string()))?;
        let info = candidate.info();
        Ok(Snapshot {
            identity: Some(FileIdentity::Unix {
                device: info.device,
                inode: info.inode,
            }),
            kind: ResourceKind::Directory,
            logical_bytes: Some(info.logical_bytes),
            modified_at: Some(info.modified_at),
            complete: true,
            boundary: Boundary::Verified,
            protection: Protection::Clear,
            trash: Capability::Available,
            owner: OwnerState::NotApplicable,
        })
    }
}

impl Platform for CachePlatform {
    fn effect(
        &mut self,
        path: &Path,
        stop: &mut dyn FnMut() -> bool,
        guard: &mut dyn FnMut() -> GuardDecision,
    ) -> Effect {
        let Some(candidate) = self.candidates.get(path) else {
            return Effect::Refused("native cache candidate unavailable".into());
        };
        match candidate.move_to_trash_with_last_guard(stop, || match guard() {
            GuardDecision::Proceed => NativeLastGuard::Proceed,
            GuardDecision::Refused(reason) => NativeLastGuard::PolicyRefused(reason),
        }) {
            NativeTrashOutcome::Moved { destination } => Effect::Moved(destination),
            NativeTrashOutcome::Refused(message) => Effect::Refused(message),
            NativeTrashOutcome::Failed(message) => Effect::Failed(message),
            NativeTrashOutcome::Unknown { message, evidence } => Effect::Unknown {
                message,
                evidence: Some(Box::new(journal::RecoveryEvidence {
                    approved: file_evidence(&evidence.approved),
                    returned_destination: evidence
                        .returned_destination
                        .as_deref()
                        .map(NativePath::from_path),
                    held_source: evidence.held_source.as_ref().map(file_evidence),
                    held_source_path: evidence
                        .held_source_path
                        .as_deref()
                        .map(NativePath::from_path),
                    observation_errors: evidence.observation_errors,
                })),
            },
        }
    }
}

impl CacheSession {
    pub fn prepare(selections: &[CacheSelection], cancellation: &Cancellation) -> io::Result<Self> {
        if selections.is_empty() || selections.len() > journal::MAX_ITEMS {
            return Err(journal::invalid(
                "select between 1 and 32 explicit cache directories",
            ));
        }
        for selection in selections {
            if !crate::model::valid_absolute_path(&selection.path) {
                return Err(journal::invalid(
                    "cache selections must be absolute native paths without traversal",
                ));
            }
            if !crate::model::valid_absolute_path(&selection.scope_root)
                || !(selection.path == selection.scope_root
                    || selection.path.starts_with(&selection.scope_root))
            {
                return Err(journal::invalid(
                    "cache selections must retain a preview root at or above the cache path",
                ));
            }
            purge_preview::revalidate_developer_cache_selection(selection)
                .map_err(|error| journal::invalid(&error))?;
        }
        let planner_scope_root = common_ancestor(
            &selections
                .iter()
                .filter_map(|selection| selection.path.parent().map(Path::to_path_buf))
                .collect::<Vec<_>>(),
        )
        .ok_or_else(|| journal::invalid("cache selections share no common ancestor"))?;
        let mut planner = Planner::new(
            Scope::new(planner_scope_root, vec![]).map_err(model_error)?,
            Versions {
                engine: 2,
                rules: 1,
            },
        )
        .map_err(model_error)?
        .for_revalidated_cache_trash();
        let mut platform = CachePlatform {
            candidates: HashMap::new(),
            issues: Vec::new(),
        };
        let mut ids = Vec::with_capacity(selections.len());
        let mut discovered = Vec::with_capacity(selections.len());
        for selection in selections {
            if cancellation.is_cancelled() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "cancelled during preview",
                ));
            }
            let candidate =
                CacheTrashCandidate::capture(&selection.scope_root, &selection.path, &[])?;
            let expected = match selection.expected_identity {
                FileIdentity::Unix { device, inode } => (device, inode),
                FileIdentity::Windows { .. } => {
                    return Err(journal::invalid(
                        "developer cache preview identity is not Unix",
                    ));
                }
            };
            let info = candidate.info();
            if (info.device, info.inode) != expected {
                return Err(journal::invalid(
                    "developer cache identity changed since preview",
                ));
            }
            platform
                .candidates
                .insert(selection.path.clone(), candidate);
            let finding = planner
                .discover(&selection.path, &mut platform)
                .map_err(model_error)?;
            let id = finding.observation().id();
            ids.push(id);
            discovered.push((id, selection.path.clone()));
        }
        let preview = planner
            .prepare(&ids, &[], Duration::from_secs(120))
            .map_err(model_error)?;
        Ok(Self {
            inner: Session {
                planner,
                platform,
                preview,
            },
            selections: selections.to_vec(),
            discovered,
        })
    }

    pub fn preview(&self) -> &Plan {
        &self.inner.preview
    }

    pub fn issues(&self) -> &[SelectionIssue] {
        &self.inner.platform.issues
    }

    pub fn refusals(&self) -> Vec<SelectionRefusal> {
        self.inner
            .preview
            .rejected()
            .iter()
            .map(|item| {
                let path = self
                    .discovered
                    .iter()
                    .find(|(id, _)| *id == item.resource)
                    .map(|(_, path)| NativePath::from_path(path));
                SelectionRefusal {
                    path: path.unwrap_or_else(|| NativePath::from_path(Path::new("(unknown)"))),
                    reason: item.code.as_str().into(),
                }
            })
            .collect()
    }

    pub fn approve(&mut self, preview: &Plan) -> Result<Approval, Error> {
        for selection in &self.selections {
            purge_preview::revalidate_developer_cache_selection(selection)
                .map_err(|_| Error::new(ReasonCode::ResourceChanged))?;
            let candidate = self
                .inner
                .platform
                .candidates
                .get(&selection.path)
                .ok_or(Error::new(ReasonCode::ProbeFailed))?;
            candidate
                .revalidate()
                .map_err(|_| Error::new(ReasonCode::ResourceChanged))?;
        }
        self.inner.planner.approve(preview)
    }

    pub fn execute(
        &mut self,
        preview: &Plan,
        approval: &Approval,
        cancellation: &Cancellation,
        store: &Store,
    ) -> io::Result<ExecutionReport> {
        self.execute_with_exclusions(preview, approval, cancellation, store, None)
    }

    pub fn execute_with_exclusions(
        &mut self,
        preview: &Plan,
        approval: &Approval,
        cancellation: &Cancellation,
        store: &Store,
        policy: Option<(&ConfigPath, &Path, &PolicySnapshot)>,
    ) -> io::Result<ExecutionReport> {
        let selections = self.selections.clone();
        let mut guard = move |point: GuardPoint, path: &Path| -> io::Result<GuardDecision> {
            if let Some((config, root, snapshot)) = policy {
                match clean_policy::guard_snapshot(config, root, snapshot)? {
                    PolicyGuardStatus::Unchanged => {}
                    PolicyGuardStatus::Refused(reason) => {
                        return Ok(GuardDecision::Refused(reason));
                    }
                }
            }
            if matches!(point, GuardPoint::LastNative)
                && let Some(selection) = selections.iter().find(|selection| selection.path == path)
                && let Err(error) = purge_preview::revalidate_developer_cache_selection(selection)
            {
                return Ok(GuardDecision::Refused(error));
            }
            Ok(GuardDecision::Proceed)
        };
        self.inner.execute_with_clean_policy(
            preview,
            approval,
            cancellation,
            store,
            None,
            Some(&mut guard),
        )
    }
}

struct PurgePlatform {
    markers: HashMap<PathBuf, Vec<PathBuf>>,
    candidates: HashMap<PathBuf, PurgeTrashCandidate>,
    issues: Vec<SelectionIssue>,
}

impl Probe for PurgePlatform {
    fn inspect(&mut self, scope: &Scope, path: &Path) -> Result<Snapshot, ProbeError> {
        if let Some(candidate) = self.candidates.get(path) {
            candidate
                .revalidate()
                .map_err(|error| ProbeError::Other(error.to_string()))?;
        } else {
            let markers = self.markers.get(path).cloned().unwrap_or_default();
            match PurgeTrashCandidate::capture(
                scope.root(),
                path,
                &markers,
                scope.protected_paths(),
            ) {
                Ok(candidate) => {
                    self.candidates.insert(path.to_owned(), candidate);
                }
                Err(error) => {
                    self.issues.push(SelectionIssue {
                        path: NativePath::from_path(path),
                        message: error.to_string(),
                        os_code: error.raw_os_error(),
                        native_phase: None,
                        native_operation: None,
                    });
                    return Ok(Snapshot {
                        identity: None,
                        kind: ResourceKind::Other,
                        logical_bytes: None,
                        modified_at: None,
                        complete: false,
                        boundary: Boundary::Unknown,
                        protection: Protection::Unknown,
                        trash: Capability::Unsupported,
                        owner: OwnerState::Unknown,
                    });
                }
            }
        }
        let info = self
            .candidates
            .get(path)
            .ok_or_else(|| ProbeError::Other("native candidate was not retained".into()))?
            .info();
        Ok(Snapshot {
            identity: Some(FileIdentity::Unix {
                device: info.device,
                inode: info.inode,
            }),
            kind: ResourceKind::Directory,
            // The directory's own inode bytes, not a subtree total.
            logical_bytes: Some(info.logical_bytes),
            modified_at: Some(info.modified_at),
            complete: true,
            boundary: Boundary::Verified,
            protection: Protection::Clear,
            trash: Capability::Available,
            // An artifact directory has no running-owner concept; the
            // disclosed running-build limitation lives in the contract.
            owner: OwnerState::NotApplicable,
        })
    }
}

impl Platform for PurgePlatform {
    fn effect(
        &mut self,
        path: &Path,
        stop: &mut dyn FnMut() -> bool,
        guard: &mut dyn FnMut() -> GuardDecision,
    ) -> Effect {
        let Some(candidate) = self.candidates.get(path) else {
            return Effect::Refused("native purge candidate unavailable".into());
        };
        match candidate.move_to_trash_with_last_guard(stop, || match guard() {
            GuardDecision::Proceed => NativeLastGuard::Proceed,
            GuardDecision::Refused(reason) => NativeLastGuard::PolicyRefused(reason),
        }) {
            NativeTrashOutcome::Moved { destination } => Effect::Moved(destination),
            NativeTrashOutcome::Refused(message) => Effect::Refused(message),
            NativeTrashOutcome::Failed(message) => Effect::Failed(message),
            NativeTrashOutcome::Unknown { message, evidence } => Effect::Unknown {
                message,
                evidence: Some(Box::new(journal::RecoveryEvidence {
                    approved: file_evidence(&evidence.approved),
                    returned_destination: evidence
                        .returned_destination
                        .as_deref()
                        .map(NativePath::from_path),
                    held_source: evidence.held_source.as_ref().map(file_evidence),
                    held_source_path: evidence
                        .held_source_path
                        .as_deref()
                        .map(NativePath::from_path),
                    observation_errors: evidence.observation_errors,
                })),
            },
        }
    }
}

impl PurgeSession {
    /// Prepares a sealed multi-item plan for the explicitly selected
    /// artifacts. The scope is the selections' deepest common ancestor; the
    /// per-item candidates carry the full ancestry protection chain.
    pub fn prepare(selections: &[PurgeSelection], cancellation: &Cancellation) -> io::Result<Self> {
        if selections.is_empty() || selections.len() > journal::MAX_ITEMS {
            return Err(journal::invalid(
                "select between 1 and 32 explicit artifact directories",
            ));
        }
        for selection in selections {
            if !crate::model::valid_absolute_path(&selection.artifact)
                || !crate::model::valid_absolute_path(&selection.project_root)
            {
                return Err(journal::invalid(
                    "artifacts and project roots must be absolute native paths without traversal",
                ));
            }
            if selection.artifact.parent() != Some(selection.project_root.as_path()) {
                return Err(journal::invalid(
                    "an artifact must be a direct child of its project root",
                ));
            }
            if selection.markers.is_empty() || selection.markers.len() > 4 {
                return Err(journal::invalid(
                    "an artifact carries between 1 and 4 binding markers",
                ));
            }
            for marker in &selection.markers {
                if !crate::model::valid_absolute_path(marker)
                    || marker.parent() != Some(selection.project_root.as_path())
                {
                    return Err(journal::invalid(
                        "markers must be files directly at the project root",
                    ));
                }
            }
        }
        // Scope over the project roots: every artifact is a strict child of
        // its project root, so even a single-item selection keeps the
        // target strictly beneath the scope (the native admission rule).
        let scope_root = common_ancestor(
            &selections
                .iter()
                .map(|selection| selection.project_root.clone())
                .collect::<Vec<_>>(),
        )
        .ok_or_else(|| journal::invalid("selections share no common ancestor"))?;
        let mut planner = Planner::new(
            Scope::new(scope_root, vec![]).map_err(model_error)?,
            Versions {
                engine: 2,
                rules: 1,
            },
        )
        .map_err(model_error)?
        .for_revalidated_purge_trash();
        let mut platform = PurgePlatform {
            markers: selections
                .iter()
                .map(|selection| (selection.artifact.clone(), selection.markers.clone()))
                .collect(),
            candidates: HashMap::new(),
            issues: Vec::new(),
        };
        if cancellation.is_cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "cancelled during preview",
            ));
        }
        let mut ids = Vec::with_capacity(selections.len());
        let mut discovered = Vec::with_capacity(selections.len());
        for selection in selections {
            let finding = planner
                .discover(&selection.artifact, &mut platform)
                .map_err(model_error)?;
            let id = finding.observation().id();
            ids.push(id);
            discovered.push((id, selection.artifact.clone()));
        }
        let preview = planner
            .prepare(&ids, &[], Duration::from_secs(120))
            .map_err(model_error)?;
        Ok(Self {
            inner: Session {
                planner,
                platform,
                preview,
            },
            selections: selections.to_vec(),
            discovered,
        })
    }

    pub fn preview(&self) -> &Plan {
        &self.inner.preview
    }

    pub fn issues(&self) -> &[SelectionIssue] {
        &self.inner.platform.issues
    }

    pub fn refusals(&self) -> Vec<SelectionRefusal> {
        self.inner
            .preview
            .rejected()
            .iter()
            .map(|item| {
                let path = self
                    .discovered
                    .iter()
                    .find(|(id, _)| *id == item.resource)
                    .map(|(_, path)| NativePath::from_path(path));
                SelectionRefusal {
                    path: path.unwrap_or_else(|| NativePath::from_path(Path::new("(unknown)"))),
                    reason: item.code.as_str().into(),
                }
            })
            .collect()
    }

    /// Approval re-validates every candidate (identity, ancestry, markers)
    /// and re-evaluates the nesting exclusion against the live filesystem;
    /// any change refuses approval, never substitutes the new state.
    pub fn approve(&mut self, preview: &Plan) -> Result<Approval, Error> {
        for selection in &self.selections {
            if purge_nesting_observed(&selection.artifact) {
                return Err(Error::new(ReasonCode::ResourceChanged));
            }
            let candidate = self
                .inner
                .platform
                .candidates
                .get(&selection.artifact)
                .ok_or(Error::new(ReasonCode::ProbeFailed))?;
            candidate
                .revalidate()
                .map_err(|_| Error::new(ReasonCode::ResourceChanged))?;
        }
        self.inner.planner.approve(preview)
    }

    pub fn execute(
        &mut self,
        preview: &Plan,
        approval: &Approval,
        cancellation: &Cancellation,
        store: &Store,
    ) -> io::Result<ExecutionReport> {
        self.execute_with_exclusions(preview, approval, cancellation, store, None)
    }

    pub fn execute_with_exclusions(
        &mut self,
        preview: &Plan,
        approval: &Approval,
        cancellation: &Cancellation,
        store: &Store,
        policy: Option<(&ConfigPath, &Path, &PolicySnapshot)>,
    ) -> io::Result<ExecutionReport> {
        let mut guard = move |point: GuardPoint, path: &Path| -> io::Result<GuardDecision> {
            if let Some((config, root, snapshot)) = policy {
                match clean_policy::guard_snapshot(config, root, snapshot)? {
                    PolicyGuardStatus::Unchanged => {}
                    PolicyGuardStatus::Refused(reason) => {
                        return Ok(GuardDecision::Refused(reason));
                    }
                }
            }
            // Last native guard per item: re-evaluate nesting immediately
            // before its sole Foundation call. Identity, marker and
            // ancestry revalidation run inside the native candidate itself.
            if matches!(point, GuardPoint::LastNative) && purge_nesting_observed(path) {
                return Ok(GuardDecision::Refused(
                    "a marker-bound ancestor artifact appeared; the selection nests and is refused"
                        .into(),
                ));
            }
            Ok(GuardDecision::Proceed)
        };
        self.inner.execute_with_clean_policy(
            preview,
            approval,
            cancellation,
            store,
            None,
            Some(&mut guard),
        )
    }
}

/// Re-evaluates the preview's nesting exclusion against the live
/// filesystem: if any strict ancestor of the artifact is itself a
/// marker-bound artifact directory, the selection nests inside another
/// project's artifact and must not move. Fail-closed on observation
/// errors; bounded by the ancestor handle budget.
fn purge_nesting_observed(artifact: &Path) -> bool {
    for ancestor in artifact.ancestors().skip(1).take(64) {
        let Some(name) = ancestor.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(parent) = ancestor.parent() else {
            continue;
        };
        for marker in ProjectMarker::ALL {
            if !marker.artifacts().contains(&name) {
                continue;
            }
            match std::fs::symlink_metadata(parent.join(marker.file_name())) {
                Ok(metadata) if metadata.file_type().is_file() => return true,
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                // An observation error is not proof of absence; fail closed.
                Err(_) => return true,
            }
        }
    }
    false
}

/// Deepest common ancestor of the given absolute paths.
fn common_ancestor(paths: &[PathBuf]) -> Option<PathBuf> {
    let mut iterator = paths.iter();
    let mut common = iterator.next()?.clone();
    for path in iterator {
        while !path.starts_with(&common) {
            if !common.pop() {
                return None;
            }
        }
    }
    Some(common)
}

pub struct CleanSession {
    root: PathBuf,
    config: ConfigPath,
    policy_snapshot: PolicySnapshot,
    preview: Plan,
    inner: TrashSession,
    clean_policy_context: CleanPolicyContextRecord,
}

/// Binds explicit installer selections to their inspected and native identities.
/// Format recognition is a prerequisite, not a disposability or trust assertion.
pub struct InstallerSession {
    inner: TrashSession,
    selected_count: usize,
}

impl InstallerSession {
    pub fn prepare(
        discovered: &crate::installer_preview::InstallerPreview,
        paths: &[PathBuf],
        cancellation: &Cancellation,
    ) -> io::Result<Self> {
        let scope = discovered.selection_scope()?;
        if paths.is_empty() || paths.len() > journal::MAX_ITEMS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "select between 1 and 32 installer files",
            ));
        }
        let mut selected = HashMap::new();
        for path in paths {
            if !crate::model::valid_absolute_path(path) || selected.contains_key(path) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "installer selections must be unique absolute paths without traversal",
                ));
            }
            let candidate = discovered
                .candidates
                .iter()
                .find(|candidate| candidate.path == *path && candidate.selectable())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, format!(
                        "selected path is not a recognized current-user installer candidate: {:?}",
                        path.as_os_str(),
                    ))
                })?;
            selected.insert(path.clone(), candidate);
        }
        let inner = TrashSession::prepare(scope, paths, &discovered.excludes, cancellation)?;
        for item in inner.preview().items() {
            let path = item.observation().path();
            let retained = inner
                .inner
                .platform
                .candidates
                .get(path)
                .ok_or_else(|| journal::invalid("installer native candidate missing"))?;
            selected
                .get(path)
                .ok_or_else(|| journal::invalid("installer selection missing"))?
                .verify_admission(&discovered.root, &retained.admission_witness()?)?;
        }
        Ok(Self {
            inner,
            selected_count: paths.len(),
        })
    }

    pub fn preview(&self) -> &Plan {
        self.inner.preview()
    }

    pub fn issues(&self) -> &[SelectionIssue] {
        self.inner.issues()
    }

    pub fn refusals(&self) -> Vec<SelectionRefusal> {
        self.inner.refusals()
    }

    pub fn ready(&self) -> bool {
        self.preview().items().len() == self.selected_count
            && self.preview().rejected().is_empty()
            && self.issues().is_empty()
    }

    pub fn approve(&mut self) -> io::Result<Approval> {
        if !self.ready() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "installer batch contains refusals; no files can be approved",
            ));
        }
        for candidate in self.inner.inner.platform.candidates.values() {
            candidate.revalidate()?;
        }
        self.inner
            .approve(&self.inner.preview().clone())
            .map_err(model_error)
    }

    pub fn execute(
        &mut self,
        approval: &Approval,
        cancellation: &Cancellation,
        store: &Store,
    ) -> io::Result<ExecutionReport> {
        if !self.ready() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "installer batch was refused",
            ));
        }
        self.inner
            .execute(&self.inner.preview().clone(), approval, cancellation, store)
    }
}

impl CleanSession {
    pub fn prepare_rule_selection(
        scope: Scope,
        rule_id: &str,
        candidates: &[rules::RuleCandidate],
        selected_paths: &[PathBuf],
        config: ConfigPath,
        policy_snapshot: PolicySnapshot,
        cancellation: &Cancellation,
    ) -> io::Result<Self> {
        if selected_paths.is_empty() || selected_paths.len() > journal::MAX_ITEMS {
            return Err(journal::invalid(
                "select between 1 and 32 explicit files for clean execution",
            ));
        }
        let mut discovered = HashMap::new();
        for candidate in candidates {
            if let FileIdentity::Unix { device, inode } = candidate.target_identity {
                discovered.insert(
                    candidate.target_path.clone(),
                    (candidate.rule_id, device, inode),
                );
            }
        }
        for selected in selected_paths {
            if !discovered.contains_key(selected) {
                return Err(journal::invalid(
                    "selected path is not a current clean discovery candidate",
                ));
            }
        }
        let root = scope.root().to_path_buf();
        let inner = TrashSession::prepare_rule_selection(
            scope,
            rule_id,
            selected_paths,
            &policy_snapshot.effective_exclusions,
            cancellation,
        )?;
        let preview = inner.preview().clone();
        for item in preview.items() {
            let Some((expected_rule, expected_device, expected_inode)) =
                discovered.get(item.observation().path())
            else {
                return Err(journal::invalid(
                    "selected candidate is missing from discovery set",
                ));
            };
            if item
                .rule_binding()
                .is_none_or(|binding| binding.rule_id() != *expected_rule)
            {
                return Err(journal::invalid(
                    "selected candidate rule binding changed; rerun clean preview",
                ));
            }
            let Some(FileIdentity::Unix { device, inode }) = item.observation().snapshot().identity
            else {
                return Err(journal::invalid(
                    "selected native candidate lacks Unix identity",
                ));
            };
            if device != *expected_device || inode != *expected_inode {
                return Err(journal::invalid(
                    "selected candidate changed after discovery; rerun clean preview",
                ));
            }
        }
        let clean_policy_context = clean_policy_context_record(&root, &policy_snapshot)?;
        Ok(Self {
            root,
            config,
            policy_snapshot,
            preview,
            inner,
            clean_policy_context,
        })
    }

    pub fn preview(&self) -> &Plan {
        &self.preview
    }

    pub fn approve(&mut self) -> io::Result<Approval> {
        match clean_policy::guard_snapshot(&self.config, &self.root, &self.policy_snapshot)? {
            PolicyGuardStatus::Unchanged => self
                .inner
                .approve(&self.preview)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error)),
            PolicyGuardStatus::Refused(reason) => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{reason}; no_native_call"),
            )),
        }
    }

    pub fn execute(
        &mut self,
        approval: &Approval,
        cancellation: &Cancellation,
        store: &Store,
    ) -> io::Result<ExecutionReport> {
        let config = self.config.clone();
        let root = self.root.clone();
        let expected = self.policy_snapshot.clone();
        let mut guard = move |point: GuardPoint, _path: &Path| -> io::Result<GuardDecision> {
            match clean_policy::guard_snapshot(&config, &root, &expected)? {
                PolicyGuardStatus::Unchanged => Ok(GuardDecision::Proceed),
                PolicyGuardStatus::Refused(reason) => {
                    let marker = match point {
                        GuardPoint::AfterStarted => "policy_refused_after_started",
                        GuardPoint::LastNative => "policy_refused_last_native_guard",
                    };
                    Ok(GuardDecision::Refused(format!("{marker}:{reason}")))
                }
            }
        };
        self.inner.execute_with_clean_policy(
            &self.preview,
            approval,
            cancellation,
            store,
            self.clean_policy_context.clone(),
            &mut guard,
        )
    }
}

fn clean_policy_context_record(
    root: &Path,
    snapshot: &PolicySnapshot,
) -> io::Result<CleanPolicyContextRecord> {
    let root_meta = fs::symlink_metadata(root)?;
    let root_path = display_path_record(root);
    let file_state = match &snapshot.file_state {
        PolicyFileState::Absent {
            expected_path,
            nearest_existing_parent,
            nearest_existing_parent_identity,
        } => serde_json::json!({
            "state": "absent",
            "expected_path": display_path_record(expected_path),
            "nearest_existing_parent": nearest_existing_parent.as_ref().map(|path| display_path_record(path)),
            "nearest_existing_parent_identity": nearest_existing_parent_identity.as_ref().map(|id| serde_json::json!({"device": id.device, "inode": id.inode})),
        }),
        PolicyFileState::Present {
            path,
            identity,
            length,
            modified_unix_ms,
            sha256,
        } => serde_json::json!({
            "state": "present",
            "path": display_path_record(path),
            "identity": {"device": identity.device, "inode": identity.inode},
            "length": length,
            "modified_unix_ms": modified_unix_ms,
            "sha256": sha256,
        }),
    };
    Ok(CleanPolicyContextRecord {
        schema_version: 1,
        kind: "sayaka_clean_policy_context".into(),
        root_path,
        root_identity: CleanPolicyIdentityRecord {
            device: root_meta.dev(),
            inode: root_meta.ino(),
        },
        file_state,
        effective_exclusions: snapshot
            .effective_exclusions
            .iter()
            .map(|path| display_path_record(path))
            .collect(),
    })
}

fn display_path_record(path: &Path) -> CleanPolicyPathRecord {
    let wire = NativePath::from_path(path);
    CleanPolicyPathRecord {
        encoding: wire.encoding,
        bytes_hex: encode_hex(&wire.bytes),
        display: wire.display,
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut text, "{byte:02x}");
    }
    text
}
