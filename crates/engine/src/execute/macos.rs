// SPDX-License-Identifier: MPL-2.0

use super::*;
use crate::rules;
use sayaka_platform_macos::{
    NativeFileInfo, NativeRuleBindingWitness, NativeTrashOutcome, NativeWitnessInfo, TrashCandidate,
};
use std::collections::HashMap;
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
    fn effect(&mut self, path: &Path, stop: &mut dyn FnMut() -> bool) -> Effect {
        let Some(candidate) = self.candidates.get(path) else {
            return Effect::Refused("native candidate unavailable".into());
        };
        match candidate.move_to_trash(stop) {
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
        if rule_id != rules::CPYTHON_SOURCE_BACKED_PYC_RULE_ID {
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
            let selection = rules::explicit_selection_for_target(path).ok_or_else(|| {
                journal::invalid("selected path is not a CPython __pycache__ .pyc")
            })?;
            let candidate = TrashCandidate::capture_with_source(
                scope.root(),
                &selection.target_path,
                &selection.source_path,
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
                Self::to_rule_binding(rule_id, &scope, excluded, witness)?,
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
        rule_id: &str,
        scope: &Scope,
        excluded: &[PathBuf],
        witness: &NativeRuleBindingWitness,
    ) -> io::Result<RuleBinding> {
        Ok(RuleBinding {
            schema_version: 1,
            rule_id: rule_id.to_owned(),
            rule_version: rules::CPYTHON_SOURCE_BACKED_PYC_RULE_VERSION,
            ruleset_schema_version: rules::RULESET_SCHEMA_VERSION,
            ruleset_revision: rules::BUILTIN_RULESET_REVISION,
            semantics: rules::CPYTHON_SOURCE_BACKED_PYC_TRASH_SEMANTICS.to_owned(),
            semantics_digest: rules::CPYTHON_SOURCE_BACKED_PYC_TRASH_SEMANTICS_DIGEST.to_owned(),
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
                "Metadata-only rule checks do not validate .pyc contents or Python interpreter availability.".into(),
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
}
