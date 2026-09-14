// SPDX-License-Identifier: MPL-2.0

//! Explicit native Trash sessions. The versioned contract discloses the residual
//! check/use race; an M1 preflight report cannot be supplied as a mutation permit.

#[cfg(any(target_os = "macos", test))]
use crate::journal::{self, ItemRecord};
use crate::journal::{ItemState, NativePath, Record, Store};
use crate::model::*;
#[cfg(any(target_os = "macos", test))]
use crate::{Clock, IdSource, Planner, SequentialIds, SystemClock};
use serde::Serialize;
use std::io;
#[cfg(any(target_os = "macos", test))]
use std::path::Path;
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize)]
pub struct SelectionIssue {
    pub path: NativePath,
    pub message: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct SelectionRefusal {
    pub path: NativePath,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct ExecutionReport {
    pub record: Record,
    pub journal_error: Option<String>,
}

impl ExecutionReport {
    pub fn exit_code(&self) -> u8 {
        if self.journal_error.is_some()
            || self
                .record
                .items
                .iter()
                .any(|item| item.state == ItemState::Unknown)
        {
            1
        } else if self
            .record
            .items
            .iter()
            .all(|item| item.state == ItemState::Succeeded)
        {
            0
        } else if self
            .record
            .items
            .iter()
            .any(|item| item.reason.as_deref() == Some("cancelled"))
        {
            130
        } else {
            3
        }
    }
}

#[cfg(any(target_os = "macos", test))]
pub(crate) enum Effect {
    Moved(PathBuf),
    Refused(String),
    Failed(String),
    Unknown {
        message: String,
        evidence: Option<Box<journal::RecoveryEvidence>>,
    },
}

#[cfg(any(target_os = "macos", test))]
pub(crate) enum GuardDecision {
    Proceed,
    Refused(String),
}

#[cfg(any(target_os = "macos", test))]
pub(crate) enum GuardPoint {
    AfterStarted,
    LastNative,
}

#[cfg(any(target_os = "macos", test))]
type GuardHook<'a> = Option<&'a mut dyn FnMut(GuardPoint, &Path) -> io::Result<GuardDecision>>;

#[cfg(any(target_os = "macos", test))]
trait Platform: Probe {
    fn effect(
        &mut self,
        path: &Path,
        stop: &mut dyn FnMut() -> bool,
        guard: &mut dyn FnMut() -> GuardDecision,
    ) -> Effect;

    fn journal_path(&self, path: &Path) -> NativePath {
        NativePath::from_path(path)
    }
}

#[cfg(any(target_os = "macos", test))]
trait Journal {
    fn new_id(&self) -> io::Result<String>;
    fn publish(&self, record: &Record, initial: bool) -> io::Result<journal::Publication>;
}

#[cfg(target_os = "macos")]
impl Journal for Store {
    fn new_id(&self) -> io::Result<String> {
        self.new_id()
    }
    fn publish(&self, record: &Record, initial: bool) -> io::Result<journal::Publication> {
        self.publish(record, initial)
    }
}

#[cfg(any(target_os = "macos", test))]
struct Session<P, C = SystemClock, I = SequentialIds> {
    planner: Planner<C, I>,
    platform: P,
    preview: Plan,
}

#[cfg(any(target_os = "macos", test))]
impl<P: Platform, C: Clock, I: IdSource> Session<P, C, I> {
    fn execute(
        &mut self,
        preview: &Plan,
        approval: &Approval,
        cancellation: &Cancellation,
        journal: &impl Journal,
    ) -> io::Result<ExecutionReport> {
        self.execute_with_clean_policy(preview, approval, cancellation, journal, None, None)
    }

    fn execute_with_clean_policy(
        &mut self,
        preview: &Plan,
        approval: &Approval,
        cancellation: &Cancellation,
        journal: &impl Journal,
        clean_policy: Option<journal::CleanPolicyContextRecord>,
        mut guard: GuardHook<'_>,
    ) -> io::Result<ExecutionReport> {
        if preview.execution_contract() != ExecutionContract::RevalidatedTrashV1 {
            return Err(journal::invalid(
                "model-only approval cannot authorize native execution",
            ));
        }

        #[cfg(any(target_os = "macos", test))]
        fn item_rule_binding(binding: &RuleBinding) -> journal::RuleBindingRecord {
            journal::RuleBindingRecord {
                schema_version: binding.schema_version(),
                rule_id: binding.rule_id().to_owned(),
                rule_version: binding.rule_version(),
                ruleset_schema_version: binding.ruleset_schema_version(),
                ruleset_revision: binding.ruleset_revision(),
                semantics: binding.semantics().to_owned(),
                semantics_digest: binding.semantics_digest().to_owned(),
                selected_root: NativePath::from_path(binding.selected_root()),
                exclusions: binding
                    .exclusions()
                    .iter()
                    .map(|path| NativePath::from_path(path))
                    .collect(),
                target: item_witness(binding.target()),
                source: item_witness(binding.source()),
                root: item_witness(binding.root()),
                target_ancestors: binding
                    .target_ancestors()
                    .iter()
                    .map(item_witness)
                    .collect(),
                source_ancestors: binding
                    .source_ancestors()
                    .iter()
                    .map(item_witness)
                    .collect(),
                warnings: binding.warnings().to_vec(),
            }
        }

        #[cfg(any(target_os = "macos", test))]
        fn item_witness(witness: &RuleWitness) -> journal::RuleWitnessRecord {
            journal::RuleWitnessRecord {
                path: NativePath::from_path(&witness.path),
                device: match witness.identity {
                    FileIdentity::Unix { device, .. } => device,
                    FileIdentity::Windows { .. } => 0,
                },
                inode: match witness.identity {
                    FileIdentity::Unix { inode, .. } => inode,
                    FileIdentity::Windows { .. } => 0,
                },
                kind: match witness.kind {
                    ResourceKind::File => "file",
                    ResourceKind::Directory => "directory",
                    ResourceKind::Link => "link",
                    ResourceKind::Other => "other",
                }
                .into(),
                logical_bytes: witness.logical_bytes,
                modified: journal::NativeTime::from_system_time(witness.modified_at),
                changed: journal::NativeTime::from_system_time(witness.changed_at),
                created: journal::NativeTime::from_system_time(witness.created_at),
                uid: witness.uid,
                gid: witness.gid,
                mode: witness.mode,
                nlink: witness.nlink,
                flags: witness.flags,
            }
        }
        let validated = self
            .planner
            .validate(preview, approval, &mut self.platform, cancellation)
            .map_err(model_error)?;
        let now = journal::now_ms()?;
        let items = preview
            .items()
            .iter()
            .map(|item| {
                let snapshot = item.observation().snapshot();
                let Some(FileIdentity::Unix { device, inode }) = snapshot.identity else {
                    return Err(journal::invalid("native plan lacks Unix identity"));
                };
                let logical_bytes = snapshot
                    .logical_bytes
                    .ok_or_else(|| journal::invalid("native size is unknown"))?;
                Ok(ItemRecord {
                    path: self.platform.journal_path(item.observation().path()),
                    device,
                    inode,
                    logical_bytes,
                    state: ItemState::Planned,
                    reason: None,
                    destination: None,
                    rule_binding: item.rule_binding().map(item_rule_binding),
                    recovery_evidence: None,
                    updated_unix_ms: now,
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        let clean_profile = clean_policy.is_some();
        let schema_version = if clean_profile {
            3
        } else if preview.schema_version() == 3 {
            journal::SCHEMA_VERSION
        } else {
            1
        };
        let mut report = ExecutionReport {
            record: Record {
                schema_version,
                plan_schema_version: preview.schema_version(),
                engine_version: preview.versions().engine,
                rules_version: preview.versions().rules,
                operation_id: journal.new_id()?,
                contract: preview.execution_contract().as_str().into(),
                scope: self.platform.journal_path(preview.scope()),
                clean_policy,
                created_unix_ms: now,
                items,
            },
            journal_error: None,
        };
        journal.publish(&report.record, true)?.require_clean()?;
        let mut stopped = false;
        for (index, item) in preview.items().iter().enumerate() {
            let skipped = validated
                .skipped
                .iter()
                .find(|skip| skip.resource == item.resource());
            let reason = self
                .planner
                .stop_reason(preview, cancellation)
                .map(|code| code.as_str().to_owned())
                .or_else(|| {
                    skipped.map(|skip| {
                        let mut message = skip.code.as_str().to_owned();
                        if let Some(error) = &skip.probe_error {
                            message.push_str(&format!(": {error}"));
                        }
                        message
                    })
                })
                .or_else(|| stopped.then(|| "stopped_after_ambiguous_outcome".to_owned()));
            if let Some(reason) = reason {
                report.record.items[index].state = ItemState::Skipped;
                report.record.items[index].reason = Some(reason);
            } else {
                report.record.items[index].state = ItemState::Started;
                report.record.items[index].updated_unix_ms = journal::now_ms()?;
                if let Err(error) = journal
                    .publish(&report.record, false)
                    .and_then(journal::Publication::require_clean)
                {
                    // Publication may have reached disk even if sync failed,
                    // but no native call for this item has been made.
                    report.record.items[index].state = ItemState::Skipped;
                    report.record.items[index].reason =
                        Some("intent_publication_incomplete; no_native_call".into());
                    stop_for_journal_error(&mut report, index, error);
                    return Ok(report);
                }
                let mut skip_native_call = false;
                if let Some(check) = guard.as_deref_mut() {
                    match resolve_guard_decision(
                        check(GuardPoint::AfterStarted, item.observation().path()),
                        GuardPoint::AfterStarted,
                    ) {
                        GuardDecision::Proceed => {}
                        GuardDecision::Refused(reason) => {
                            report.record.items[index].state = ItemState::Skipped;
                            report.record.items[index].reason =
                                Some(format!("{reason}; no_native_call"));
                            report.record.items[index].destination = None;
                            stopped = true;
                            skip_native_call = true;
                        }
                    }
                }
                if !skip_native_call {
                    let mut final_stop = None;
                    let planner = &mut self.planner;
                    let mut guard_result = GuardDecision::Proceed;
                    let effect = self.platform.effect(
                        item.observation().path(),
                        &mut || {
                            final_stop = planner.stop_reason(preview, cancellation);
                            final_stop.is_some()
                        },
                        &mut || {
                            if let Some(check) = guard.as_deref_mut() {
                                guard_result = resolve_guard_decision(
                                    check(GuardPoint::LastNative, item.observation().path()),
                                    GuardPoint::LastNative,
                                );
                            }
                            match &guard_result {
                                GuardDecision::Proceed => GuardDecision::Proceed,
                                GuardDecision::Refused(reason) => {
                                    GuardDecision::Refused(reason.clone())
                                }
                            }
                        },
                    );
                    let row = &mut report.record.items[index];
                    match effect {
                        Effect::Moved(destination) => {
                            row.state = ItemState::Succeeded;
                            row.destination = Some(self.platform.journal_path(&destination));
                        }
                        Effect::Refused(message) => {
                            row.state = ItemState::Skipped;
                            row.reason = Some(
                                final_stop
                                    .map(|code| code.as_str().to_owned())
                                    .unwrap_or(message),
                            );
                            if matches!(guard_result, GuardDecision::Refused(_)) {
                                stopped = true;
                            }
                        }
                        Effect::Failed(message) => {
                            row.state = ItemState::Failed;
                            row.reason = Some(message);
                        }
                        Effect::Unknown { message, evidence } => {
                            row.state = ItemState::Unknown;
                            row.reason = Some(message);
                            row.recovery_evidence = evidence.map(|evidence| *evidence);
                            stopped = true;
                        }
                    }
                }
            }
            match journal::now_ms() {
                Ok(now) => report.record.items[index].updated_unix_ms = now,
                Err(error) => {
                    if matches!(
                        report.record.items[index].state,
                        ItemState::Succeeded | ItemState::Failed
                    ) {
                        report.record.items[index].state = ItemState::Unknown;
                    }
                    report.record.items[index].reason =
                        Some(format!("outcome timestamp unavailable: {error}"));
                    stop_for_journal_error(&mut report, index, error);
                    return Ok(report);
                }
            }
            match journal.publish(&report.record, false) {
                Err(error) => {
                    if !matches!(report.record.items[index].state, ItemState::Skipped) {
                        report.record.items[index].state = ItemState::Unknown;
                        report.record.items[index].reason =
                            Some("native_outcome_not_confirmed_durable".into());
                    }
                    stop_for_journal_error(&mut report, index, error);
                    return Ok(report);
                }
                Ok(publication) => {
                    if let Some(error) = publication.cleanup_error {
                        stop_for_journal_error(&mut report, index, error);
                        return Ok(report);
                    }
                }
            }
        }
        Ok(report)
    }
}

#[cfg(any(target_os = "macos", test))]
fn stop_for_journal_error(report: &mut ExecutionReport, index: usize, error: io::Error) {
    report.journal_error = Some(error.to_string());
    for item in &mut report.record.items[index + 1..] {
        item.state = ItemState::Skipped;
        item.reason = Some("stopped_after_journal_failure".into());
    }
}

#[cfg(any(target_os = "macos", test))]
fn model_error(error: Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error)
}

#[cfg(any(target_os = "macos", test))]
fn resolve_guard_decision(result: io::Result<GuardDecision>, point: GuardPoint) -> GuardDecision {
    match result {
        Ok(decision) => decision,
        Err(error) => {
            GuardDecision::Refused(format!("policy_guard_error_{}: {error}", point.label()))
        }
    }
}

#[cfg(any(target_os = "macos", test))]
impl GuardPoint {
    fn label(&self) -> &'static str {
        match self {
            Self::AfterStarted => "after_started",
            Self::LastNative => "last_native",
        }
    }
}

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{CleanSession, TrashSession};

#[cfg(not(target_os = "macos"))]
pub struct TrashSession {
    _unavailable: (),
}

#[cfg(not(target_os = "macos"))]
pub struct CleanSession {
    _unavailable: (),
}

#[cfg(not(target_os = "macos"))]
impl TrashSession {
    pub fn prepare(_: Scope, _: &[PathBuf], _: &[PathBuf], _: &Cancellation) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native Trash is macOS-only",
        ))
    }

    pub fn prepare_rule_selection(
        _: Scope,
        _: &str,
        _: &[PathBuf],
        _: &[PathBuf],
        _: &Cancellation,
    ) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native Trash is macOS-only",
        ))
    }
    pub fn preview(&self) -> &Plan {
        unreachable!("session cannot be created on this platform")
    }
    pub fn issues(&self) -> &[SelectionIssue] {
        &[]
    }
    pub fn refusals(&self) -> Vec<SelectionRefusal> {
        Vec::new()
    }
    pub fn approve(&mut self, _: &Plan) -> Result<Approval, Error> {
        Err(Error::new(ReasonCode::UnsupportedCapability))
    }
    pub fn execute(
        &mut self,
        _: &Plan,
        _: &Approval,
        _: &Cancellation,
        _: &Store,
    ) -> io::Result<ExecutionReport> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native Trash is macOS-only",
        ))
    }
}

#[cfg(not(target_os = "macos"))]
impl CleanSession {
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_rule_selection(
        _: Scope,
        _: &str,
        _: &[crate::rules::RuleCandidate],
        _: &[PathBuf],
        _: crate::clean_policy::ConfigPath,
        _: crate::clean_policy::PolicySnapshot,
        _: &Cancellation,
    ) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native Trash is macOS-only",
        ))
    }
    pub fn preview(&self) -> &Plan {
        unreachable!("session cannot be created on this platform")
    }
    pub fn approve(&mut self) -> io::Result<Approval> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native Trash is macOS-only",
        ))
    }
    pub fn execute(
        &mut self,
        _: &Approval,
        _: &Cancellation,
        _: &Store,
    ) -> io::Result<ExecutionReport> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native Trash is macOS-only",
        ))
    }
}

#[cfg(test)]
mod tests;
