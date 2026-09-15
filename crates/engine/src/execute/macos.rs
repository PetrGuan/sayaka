// SPDX-License-Identifier: MPL-2.0

use super::*;
use crate::clean_policy::{self, ConfigPath, PolicyFileState, PolicyGuardStatus, PolicySnapshot};
use crate::journal::{CleanPolicyContextRecord, CleanPolicyIdentityRecord, CleanPolicyPathRecord};
use crate::rules;
use sayaka_platform_macos::{
    NativeFileInfo, NativeLastGuard, NativeRuleBindingWitness, NativeTargetMarker,
    NativeTrashOutcome, NativeWitnessInfo, TrashCandidate,
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
            match TrashCandidate::capture(scope.root(), path, scope.protected_paths()) {
                Ok(candidate) => {
                    self.candidates.insert(path.to_owned(), candidate);
                }
                Err(error) => {
                    self.issues.push(SelectionIssue {
                        path: NativePath::from_path(path),
                        message: error.to_string(),
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
