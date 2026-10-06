// SPDX-License-Identifier: MPL-2.0

//! One simulator session for slice 1a of `docs/SIMULATOR_CLEANUP.md`: a sealed
//! preview, an approval bound to its digest and typed phrase, and journaled
//! batch execution with revalidation before and a re-list after every call.
//!
//! The host (process launch, process table, file metadata) is injected so the
//! session logic is exercised without `simctl`; [`MacHost`] is the production
//! host over `sayaka-platform-macos`.

use super::*;
use crate::execute::ExecutionReport;
use crate::journal::{
    self, ItemRecord, ItemState, NativePath, Record, Store, ToolDeviceRecord, ToolOperationRecord,
};
use crate::model::Cancellation;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Instant;

pub const MIN_MACOS_MAJOR: u32 = 26;
pub const MIN_XCODE_MAJOR: u32 = 26;
const MAX_REASON_BYTES: usize = 512;
const MAX_VERSION_FILE_BYTES: u64 = 64 * 1024;

/// Whole-request errors surfaced to hosts with their contract codes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum SessionError {
    ToolUnavailable {
        message: String,
    },
    UnsupportedToolVersion {
        macos: Option<String>,
        xcode: Option<String>,
    },
    ToolChanged,
    /// Xcode, Simulator, a test run or another `simctl` user is running, or
    /// the process table could not be read (`executables` is then empty).
    DeveloperActivity {
        executables: Vec<String>,
    },
    Busy,
    Expired,
    InvalidRequest {
        message: String,
        refusal: Option<RequestRefusal>,
    },
    ParseFailed {
        message: String,
    },
    OutputCapExceeded,
    Timeout,
    JournalUnavailable {
        message: String,
    },
    Cancelled,
    /// The session already executed; a fresh preview is required.
    Consumed,
}

impl SessionError {
    pub fn code(&self) -> &'static str {
        match self {
            SessionError::ToolUnavailable { .. } => "tool_unavailable",
            SessionError::UnsupportedToolVersion { .. } => "unsupported_tool_version",
            SessionError::ToolChanged => "tool_changed",
            SessionError::DeveloperActivity { .. } => "developer_activity",
            SessionError::Busy => "busy",
            SessionError::Expired => "expired",
            SessionError::InvalidRequest { .. } => "invalid_request",
            SessionError::ParseFailed { .. } => "parse_failed",
            SessionError::OutputCapExceeded => "output_cap_exceeded",
            SessionError::Timeout => "timeout",
            SessionError::JournalUnavailable { .. } => "journal_unavailable",
            SessionError::Cancelled => "cancelled",
            SessionError::Consumed => "consumed",
        }
    }
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::ToolUnavailable { message }
            | SessionError::ParseFailed { message }
            | SessionError::JournalUnavailable { message }
            | SessionError::InvalidRequest { message, .. } => {
                write!(f, "{}: {message}", self.code())
            }
            SessionError::DeveloperActivity { executables } if executables.is_empty() => {
                write!(f, "developer_activity: the process table could not be read")
            }
            SessionError::DeveloperActivity { executables } => {
                write!(f, "developer_activity: {}", executables.join(", "))
            }
            SessionError::UnsupportedToolVersion { macos, xcode } => write!(
                f,
                "unsupported_tool_version: macOS {} and Xcode {} (need {MIN_MACOS_MAJOR}+ and {MIN_XCODE_MAJOR}+)",
                macos.as_deref().unwrap_or("unknown"),
                xcode.as_deref().unwrap_or("unknown")
            ),
            SessionError::Busy => {
                f.write_str("busy: another Sayaka operation holds the journal lock")
            }
            SessionError::Expired => {
                f.write_str("expired: the preview is older than 120 seconds; preview again")
            }
            other => f.write_str(other.code()),
        }
    }
}

impl std::error::Error for SessionError {}

/// How a host-level tool call failed before producing an exit status.
#[derive(Debug)]
pub enum ToolFailure {
    Unavailable(String),
    Timeout,
    OutputCap,
    Io(String),
}

impl ToolFailure {
    fn into_error(self) -> SessionError {
        match self {
            ToolFailure::Unavailable(message) | ToolFailure::Io(message) => {
                SessionError::ToolUnavailable { message }
            }
            ToolFailure::Timeout => SessionError::Timeout,
            ToolFailure::OutputCap => SessionError::OutputCapExceeded,
        }
    }

    fn reason(&self) -> String {
        match self {
            ToolFailure::Unavailable(message) => format!("tool_unavailable: {message}"),
            ToolFailure::Timeout => "timeout".into(),
            ToolFailure::OutputCap => "output_cap_exceeded".into(),
            ToolFailure::Io(message) => format!("tool_io_error: {message}"),
        }
    }
}

#[derive(Debug)]
pub struct ToolResult {
    pub success: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ToolIdentity {
    /// Path, real path, device/inode, size and modification time of `simctl`.
    pub fingerprint: String,
    #[serde(skip)]
    pub real_path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ToolVersions {
    pub macos: Option<String>,
    pub xcode: Option<String>,
}

/// Everything the session needs from the machine. Every call is read-only
/// except `run` with `execute == true`.
pub trait Host {
    fn tool_identity(&self) -> Result<ToolIdentity, ToolFailure>;
    fn tool_versions(&self, tool: &ToolIdentity) -> ToolVersions;
    /// Runs one fixed vector after `xcrun`; `execute` selects the long timeout.
    fn run(&self, args: &[String], execute: bool) -> Result<ToolResult, ToolFailure>;
    fn developer_activity(&self) -> io::Result<Vec<String>>;
    fn data_modified_unix_ns(&self, data_path: &Path) -> Option<i128>;
    fn data_identity(&self, data_path: &Path) -> Option<(u64, u64)>;
    fn now(&self) -> Instant;
}

/// Sealed, effect-free preview of one operation kind.
#[derive(Clone, Debug, Serialize)]
pub struct Preview {
    pub schema_version: u32,
    pub effect_class: &'static str,
    pub operation: Operation,
    pub tool: ToolIdentity,
    pub versions: ToolVersions,
    pub candidates: Vec<Candidate>,
    pub plan_digest: String,
    /// Reported at preview so hosts can ask the user to quit them first;
    /// execution refuses while any remain.
    pub developer_activity: Vec<String>,
    pub residual_race_disclosed: bool,
}

#[derive(Clone, Debug)]
pub struct ExecuteRequest {
    pub plan_digest: String,
    pub items: Vec<String>,
    pub approval_token: String,
}

pub struct SimulatorSession<H> {
    host: H,
    preview: Preview,
    created: Instant,
    consumed: bool,
}

fn version_major(version: Option<&str>) -> Option<u32> {
    let version = version?;
    let digits = version.bytes().take_while(u8::is_ascii_digit).count();
    version[..digits].parse().ok()
}

fn bounded_reason(text: &str) -> String {
    let line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if line.len() <= MAX_REASON_BYTES {
        return line;
    }
    let mut end = MAX_REASON_BYTES;
    while !line.is_char_boundary(end) {
        end -= 1;
    }
    line[..end].to_owned()
}

type Listing = (Vec<Device>, Vec<(String, String)>);

fn list<H: Host>(host: &H) -> Result<Listing, SessionError> {
    let read = |args: [&str; 4]| -> Result<Vec<u8>, SessionError> {
        let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
        let output = host.run(&args, false).map_err(ToolFailure::into_error)?;
        if !output.success {
            return Err(SessionError::ToolUnavailable {
                message: bounded_reason(&String::from_utf8_lossy(&output.stderr)),
            });
        }
        Ok(output.stdout)
    };
    let parse_error = |error: ParseError| match error {
        ParseError::TooLarge => SessionError::OutputCapExceeded,
        other => SessionError::ParseFailed {
            message: other.to_string(),
        },
    };
    let devices =
        parse_devices(&read(["simctl", "list", "devices", "-j"])?).map_err(parse_error)?;
    let pairs = parse_pairs(&read(["simctl", "list", "pairs", "-j"])?).map_err(parse_error)?;
    Ok((devices, pairs))
}

/// Orders a validated selection into batches of at most [`MAX_BATCH`],
/// keeping both members of a pair in the same call.
fn pair_batches(candidates: &[Candidate], selected: &[String]) -> Vec<Vec<String>> {
    let mut units: Vec<Vec<String>> = Vec::new();
    let mut placed = BTreeSet::new();
    for udid in selected {
        if !placed.insert(udid.clone()) {
            continue;
        }
        let mut unit = vec![udid.clone()];
        if let Some(partner) = candidates
            .iter()
            .find(|c| &c.device.udid == udid)
            .and_then(|c| c.paired_with.clone())
            && placed.insert(partner.clone())
        {
            unit.push(partner);
        }
        units.push(unit);
    }
    let mut batches: Vec<Vec<String>> = Vec::new();
    for unit in units {
        match batches.last_mut() {
            Some(batch) if batch.len() + unit.len() <= MAX_BATCH => batch.extend(unit),
            _ => batches.push(unit),
        }
    }
    batches
}

impl<H: Host> SimulatorSession<H> {
    /// Lists devices and pairs, checks the tool and its versions, and seals
    /// the candidates for one operation kind. No effects.
    pub fn prepare(
        host: H,
        operation: Operation,
        cancellation: &Cancellation,
    ) -> Result<Self, SessionError> {
        let created = host.now();
        let tool = host.tool_identity().map_err(ToolFailure::into_error)?;
        let versions = host.tool_versions(&tool);
        if version_major(versions.macos.as_deref()).is_none_or(|major| major < MIN_MACOS_MAJOR)
            || version_major(versions.xcode.as_deref()).is_none_or(|major| major < MIN_XCODE_MAJOR)
        {
            return Err(SessionError::UnsupportedToolVersion {
                macos: versions.macos,
                xcode: versions.xcode,
            });
        }
        if cancellation.is_cancelled() {
            return Err(SessionError::Cancelled);
        }
        let (devices, pairs) = list(&host)?;
        if cancellation.is_cancelled() {
            return Err(SessionError::Cancelled);
        }
        if host.tool_identity().map_err(ToolFailure::into_error)? != tool {
            return Err(SessionError::ToolChanged);
        }
        let developer_activity =
            host.developer_activity()
                .map_err(|_| SessionError::DeveloperActivity {
                    executables: Vec::new(),
                })?;
        let candidates = candidates(&devices, &pairs, operation);
        let plan_digest = plan_digest(operation, &tool.fingerprint, &candidates);
        Ok(Self {
            host,
            preview: Preview {
                schema_version: PREVIEW_SCHEMA_VERSION,
                effect_class: EFFECT_CLASS,
                operation,
                tool,
                versions,
                candidates,
                plan_digest,
                developer_activity,
                residual_race_disclosed: true,
            },
            created,
            consumed: false,
        })
    }

    pub fn preview(&self) -> &Preview {
        &self.preview
    }

    pub fn expired(&self) -> bool {
        self.host.now().saturating_duration_since(self.created) >= PREVIEW_TTL
    }

    /// The exact typed phrase for a selection of `count` devices.
    pub fn approval_phrase(&self, count: usize) -> String {
        self.preview.operation.approval_phrase(count)
    }

    /// Checks the approval without consuming the session.
    pub fn check_approval(&self, request: &ExecuteRequest) -> Result<(), SessionError> {
        if self.consumed {
            return Err(SessionError::Consumed);
        }
        if self.expired() {
            return Err(SessionError::Expired);
        }
        let invalid = |message: &str, refusal| SessionError::InvalidRequest {
            message: message.into(),
            refusal,
        };
        if request.plan_digest != self.preview.plan_digest {
            return Err(invalid("plan digest does not match this preview", None));
        }
        validate_request(&self.preview.candidates, &request.items)
            .map_err(|refusal| invalid("selection refused", Some(refusal)))?;
        if request.approval_token != self.approval_phrase(request.items.len()) {
            return Err(invalid("approval phrase does not match", None));
        }
        Ok(())
    }

    /// Executes the approved selection exactly once. Whole-request refusals
    /// return an error before any journal write or tool call; afterwards
    /// every outcome is in the returned record.
    /// Refuses a journal directory inside any previewed device, then opens
    /// the journal under its exclusive lock (`busy` when held) and executes.
    pub fn execute(
        &mut self,
        request: &ExecuteRequest,
        cancellation: &Cancellation,
        state_dir: &Path,
    ) -> Result<ExecutionReport, SessionError> {
        self.check_approval(request)?;
        self.check_state_dir(state_dir)?;
        let journal = open_journal(state_dir)?;
        self.execute_with(request, cancellation, &journal)
    }

    pub(crate) fn execute_with(
        &mut self,
        request: &ExecuteRequest,
        cancellation: &Cancellation,
        journal: &impl ToolJournal,
    ) -> Result<ExecutionReport, SessionError> {
        self.check_approval(request)?;
        if cancellation.is_cancelled() {
            self.consumed = true;
            return Err(SessionError::Cancelled);
        }
        let activity =
            self.host
                .developer_activity()
                .map_err(|_| SessionError::DeveloperActivity {
                    executables: Vec::new(),
                })?;
        if !activity.is_empty() {
            return Err(SessionError::DeveloperActivity {
                executables: activity,
            });
        }
        if self.host.tool_identity().map_err(ToolFailure::into_error)? != self.preview.tool {
            self.consumed = true;
            return Err(SessionError::ToolChanged);
        }
        // From here on the approval is spent, whatever happens. Refusals above
        // (developer activity) leave the preview usable until it expires.
        self.consumed = true;

        let operation = self.preview.operation;
        let batches = pair_batches(&self.preview.candidates, &request.items);
        let ordered: Vec<&Candidate> = batches
            .iter()
            .flatten()
            .map(|udid| {
                self.preview
                    .candidates
                    .iter()
                    .find(|c| &c.device.udid == udid)
                    .expect("validated selection is previewed")
            })
            .collect();
        let journal_error = |error: io::Error| SessionError::JournalUnavailable {
            message: error.to_string(),
        };
        let now = journal::now_ms().map_err(journal_error)?;
        let items = ordered
            .iter()
            .map(|candidate| {
                let path = Path::new(&candidate.device.data_path);
                let (device, inode) = self.host.data_identity(path).unwrap_or((0, 0));
                ItemRecord {
                    path: NativePath::from_path(path),
                    device,
                    inode,
                    logical_bytes: candidate.device.data_path_size.unwrap_or(0),
                    state: ItemState::Planned,
                    reason: None,
                    destination: None,
                    rule_binding: None,
                    recovery_evidence: None,
                    updated_unix_ms: now,
                }
            })
            .collect();
        let scope = ordered
            .first()
            .and_then(|c| Path::new(&c.device.data_path).parent()?.parent())
            .filter(|path| path.is_absolute())
            .unwrap_or(Path::new("/"));
        let mut report = ExecutionReport {
            record: Record {
                schema_version: journal::TOOL_SCHEMA_VERSION,
                plan_schema_version: journal::TOOL_PLAN_SCHEMA_VERSION,
                engine_version: journal::TOOL_ENGINE_VERSION,
                rules_version: journal::TOOL_RULES_VERSION,
                operation_id: journal.new_id().map_err(journal_error)?,
                contract: journal::TOOL_CONTRACT.into(),
                scope: NativePath::from_path(scope),
                clean_policy: None,
                tool_operation: Some(ToolOperationRecord {
                    schema_version: 1,
                    operation: operation.verb().into(),
                    tool_evidence: self.preview.tool.fingerprint.clone(),
                    plan_digest: self.preview.plan_digest.clone(),
                    devices: ordered
                        .iter()
                        .map(|c| ToolDeviceRecord {
                            udid: c.device.udid.clone(),
                            name: c.device.name.clone(),
                            runtime_identifier: c.device.runtime_identifier.clone(),
                            paired_with: c.paired_with.clone(),
                        })
                        .collect(),
                }),
                delegation: None,
                created_unix_ms: now,
                items,
            },
            journal_error: None,
        };
        // Durable intent first: if it cannot be written, nothing runs.
        journal
            .publish(&report.record, true)
            .and_then(journal::Publication::require_clean)
            .map_err(journal_error)?;

        let mut offset = 0;
        let mut stop: Option<String> = None;
        for batch in &batches {
            let range = offset..offset + batch.len();
            offset += batch.len();
            if stop.is_none() && cancellation.is_cancelled() {
                stop = Some("cancelled".into());
            }
            if let Some(reason) = &stop {
                set_range(&mut report.record, range, ItemState::Skipped, reason);
                continue;
            }
            let before = match self.revalidate_batch(&ordered[range.clone()]) {
                Ok(before) => before,
                Err(BatchRefusal::Batch(reason)) => {
                    set_range(&mut report.record, range, ItemState::Skipped, &reason);
                    continue;
                }
                Err(BatchRefusal::Stop(reason)) => {
                    set_range(&mut report.record, range, ItemState::Skipped, &reason);
                    stop = Some(reason);
                    continue;
                }
            };
            set_range(&mut report.record, range.clone(), ItemState::Started, "");
            if let Err(error) = journal
                .publish(&report.record, false)
                .and_then(journal::Publication::require_clean)
            {
                set_range(
                    &mut report.record,
                    range.clone(),
                    ItemState::Skipped,
                    "intent_publication_incomplete; no_tool_call",
                );
                return Ok(stop_for_journal_error(report, range.end, error));
            }
            let args = argument_vector(operation, batch).expect("validated canonical batch");
            let (end, call_reason) = match self.host.run(&args, true) {
                Ok(output) => {
                    let stderr = bounded_reason(&String::from_utf8_lossy(&output.stderr));
                    (
                        CallEnd::Exited {
                            success: output.success,
                        },
                        (!stderr.is_empty()).then_some(stderr),
                    )
                }
                Err(failure) => (CallEnd::Indeterminate, Some(failure.reason())),
            };
            let after = list(&self.host);
            let mut ambiguous = false;
            for (index, candidate) in range.clone().zip(&ordered[range.clone()]) {
                let row = &mut report.record.items[index];
                row.updated_unix_ms = journal::now_ms().unwrap_or(row.updated_unix_ms);
                let (outcome, reason) = match &after {
                    Err(error) => (
                        Outcome::Unknown,
                        Some(format!("post_check_failed: {error}")),
                    ),
                    Ok((devices, _)) => {
                        let current = devices.iter().find(|d| d.udid == candidate.device.udid);
                        let data_after = DataObservation {
                            size: current.and_then(|d| d.data_path_size),
                            modified_unix_ns: current.and_then(|d| {
                                self.host.data_modified_unix_ns(Path::new(&d.data_path))
                            }),
                        };
                        let outcome = classify(
                            operation,
                            end,
                            current,
                            before[index - range.start],
                            data_after,
                        );
                        let failure = || {
                            call_reason
                                .clone()
                                .unwrap_or_else(|| "tool_reported_failure".into())
                        };
                        let reason = match (outcome, operation, end) {
                            (Outcome::Succeeded, ..) => None,
                            (
                                Outcome::Unknown,
                                Operation::Erase,
                                CallEnd::Exited { success: true },
                            ) if current.is_some_and(|d| d.state == "Shutdown") => {
                                // Expected for an already-empty device; not ambiguous.
                                Some("exited_without_observable_change".to_owned())
                            }
                            (
                                Outcome::Unknown,
                                Operation::Erase,
                                CallEnd::Exited { success: true },
                            ) => {
                                ambiguous = true;
                                Some("erase_post_check_mismatch".to_owned())
                            }
                            (
                                Outcome::Unknown,
                                Operation::Delete,
                                CallEnd::Exited { success: true },
                            ) => {
                                ambiguous = true;
                                Some("still_listed_after_success_exit".to_owned())
                            }
                            (Outcome::Unknown, _, CallEnd::Exited { success: false }) => {
                                ambiguous = true;
                                let observed =
                                    before[index - range.start] != DataObservation::default();
                                Some(format!(
                                    "{}: {}",
                                    if observed {
                                        "failed_after_data_changed"
                                    } else {
                                        "failed_without_pre_observation"
                                    },
                                    failure()
                                ))
                            }
                            _ => Some(failure()),
                        };
                        (outcome, reason)
                    }
                };
                row.state = match outcome {
                    Outcome::Succeeded => ItemState::Succeeded,
                    Outcome::Failed => ItemState::Failed,
                    Outcome::Refused => ItemState::Skipped,
                    Outcome::Unknown => ItemState::Unknown,
                };
                row.reason = reason.map(|reason| bounded_reason(&reason));
            }
            if ambiguous || after.is_err() || end == CallEnd::Indeterminate {
                // CoreSimulatorService may still be working; never continue
                // past an ambiguous call.
                stop = Some("stopped_after_ambiguous_outcome".into());
            }
            if let Err(error) = journal
                .publish(&report.record, false)
                .and_then(journal::Publication::require_clean)
            {
                return Ok(stop_for_journal_error(report, range.end, error));
            }
        }
        if let Err(error) = journal
            .publish(&report.record, false)
            .and_then(journal::Publication::require_clean)
        {
            report.journal_error = Some(error.to_string());
        }
        Ok(report)
    }

    /// Re-runs the whole-request and per-candidate checks for one batch and
    /// returns each device's pre-call data observation.
    fn revalidate_batch(&self, batch: &[&Candidate]) -> Result<Vec<DataObservation>, BatchRefusal> {
        match self.host.developer_activity() {
            Ok(found) if found.is_empty() => {}
            Ok(_) => return Err(BatchRefusal::Stop("developer_activity".into())),
            Err(_) => return Err(BatchRefusal::Stop("developer_activity_unreadable".into())),
        }
        match self.host.tool_identity() {
            Ok(tool) if tool == self.preview.tool => {}
            Ok(_) => return Err(BatchRefusal::Stop("tool_changed".into())),
            Err(failure) => return Err(BatchRefusal::Stop(failure.reason())),
        }
        let (devices, pairs) = list(&self.host)
            .map_err(|error| BatchRefusal::Stop(format!("revalidation_failed: {error}")))?;
        let mut before = Vec::with_capacity(batch.len());
        for candidate in batch {
            if let Err(mismatch) = revalidate(candidate, &devices, &pairs) {
                let code = serde_json::to_value(&mismatch)
                    .ok()
                    .and_then(|value| value["code"].as_str().map(str::to_owned))
                    .unwrap_or_else(|| "mismatch".into());
                return Err(BatchRefusal::Batch(format!(
                    "revalidation_mismatch: {code} ({}); no_tool_call",
                    candidate.device.udid
                )));
            }
            let current = devices
                .iter()
                .find(|d| d.udid == candidate.device.udid)
                .expect("revalidated device is present");
            before.push(DataObservation {
                size: current.data_path_size,
                modified_unix_ns: self
                    .host
                    .data_modified_unix_ns(Path::new(&current.data_path)),
            });
        }
        Ok(before)
    }
}

enum BatchRefusal {
    /// Refuses this batch only; later batches are still checked.
    Batch(String),
    /// Refuses this and every later batch.
    Stop(String),
}

fn set_range(record: &mut Record, range: std::ops::Range<usize>, state: ItemState, reason: &str) {
    let now = journal::now_ms().ok();
    for row in &mut record.items[range] {
        row.state = state.clone();
        row.reason = (!reason.is_empty()).then(|| bounded_reason(reason));
        if let Some(now) = now {
            row.updated_unix_ms = now;
        }
    }
}

fn stop_for_journal_error(
    mut report: ExecutionReport,
    from: usize,
    error: io::Error,
) -> ExecutionReport {
    let len = report.record.items.len();
    for row in &mut report.record.items[from..len] {
        if row.state == ItemState::Planned {
            row.state = ItemState::Skipped;
            row.reason = Some("journal_unavailable; no_tool_call".into());
        }
    }
    report.journal_error = Some(error.to_string());
    report
}

/// Journal operations the session needs; [`Store`] in production.
pub(crate) trait ToolJournal {
    fn new_id(&self) -> io::Result<String>;
    fn publish(&self, record: &Record, initial: bool) -> io::Result<journal::Publication>;
}

impl ToolJournal for Store {
    fn new_id(&self) -> io::Result<String> {
        Store::new_id(self)
    }
    fn publish(&self, record: &Record, initial: bool) -> io::Result<journal::Publication> {
        Store::publish(self, record, initial)
    }
}

/// Opens the journal under its exclusive lock; a held lock means another
/// execution is running and is reported as `busy`.
fn open_journal(state_dir: &Path) -> Result<Store, SessionError> {
    journal::validate_state_directory_path(state_dir).map_err(|error| {
        SessionError::JournalUnavailable {
            message: error.to_string(),
        }
    })?;
    Store::open(state_dir, true).map_err(|error| match error.kind() {
        io::ErrorKind::WouldBlock => SessionError::Busy,
        _ => SessionError::JournalUnavailable {
            message: error.to_string(),
        },
    })
}

fn identity(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::metadata(path).ok()?;
    Some((metadata.dev(), metadata.ino()))
}

/// Resolves links where the path (or its parent) exists, so a state
/// directory reached through a symlink is compared by its real location.
fn resolved(path: &Path) -> PathBuf {
    if let Ok(real) = std::fs::canonicalize(path) {
        return real;
    }
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => std::fs::canonicalize(parent)
            .map(|parent| parent.join(name))
            .unwrap_or_else(|_| path.to_path_buf()),
        _ => path.to_path_buf(),
    }
}

impl<H: Host> SimulatorSession<H> {
    /// Refuses a journal directory inside any previewed device: an erase or
    /// delete would otherwise remove the journal after its intent.
    pub fn check_state_dir(&self, state_dir: &Path) -> Result<(), SessionError> {
        let real = resolved(state_dir);
        // Identities of every existing ancestor, so aliases such as APFS
        // firmlinks (`/System/Volumes/Data/Users/…`) are matched too.
        let ancestors: BTreeSet<(u64, u64)> = state_dir.ancestors().filter_map(identity).collect();
        let home = std::env::home_dir();
        for candidate in &self.preview.candidates {
            let mut owned: Vec<PathBuf> = Path::new(&candidate.device.data_path)
                .parent()
                .map(Path::to_path_buf)
                .into_iter()
                .collect();
            // `simctl delete` also removes the device's log directory.
            if let Some(home) = &home {
                owned.push(
                    home.join("Library/Logs/CoreSimulator")
                        .join(&candidate.device.udid),
                );
            }
            for directory in owned {
                if state_dir.starts_with(&directory)
                    || real.starts_with(resolved(&directory))
                    || identity(&directory).is_some_and(|id| ancestors.contains(&id))
                {
                    return Err(SessionError::InvalidRequest {
                        message: "the journal directory lies inside a simulator device".into(),
                        refusal: None,
                    });
                }
            }
        }
        Ok(())
    }
}

/// Reads one top-level string value from a small XML property list.
fn plist_string(bytes: &[u8], wanted: &str) -> Option<String> {
    use quick_xml::Reader;
    use quick_xml::events::Event;
    let mut reader = Reader::from_reader(bytes);
    let mut buffer = Vec::new();
    let mut depth = 0usize;
    let (mut in_key, mut want_value, mut capture) = (false, false, false);
    loop {
        match reader.read_event_into(&mut buffer).ok()? {
            Event::Start(start) => {
                depth += 1;
                if depth > 8 {
                    return None;
                }
                if depth == 3 {
                    if start.name().as_ref() == b"key" {
                        in_key = true;
                        want_value = false;
                    } else if want_value {
                        if start.name().as_ref() != b"string" {
                            return None;
                        }
                        capture = true;
                    }
                }
            }
            Event::Empty(_) if depth == 2 && want_value => return None,
            Event::End(_) => {
                if depth == 3 {
                    if in_key {
                        in_key = false;
                    } else if capture {
                        return None;
                    } else {
                        want_value = false;
                    }
                }
                depth = depth.checked_sub(1)?;
            }
            Event::Text(text) if depth == 3 => {
                let text = std::str::from_utf8(text.as_ref()).ok()?;
                if in_key {
                    want_value = text == wanted;
                } else if capture {
                    return Some(text.to_owned());
                }
            }
            Event::Eof => return None,
            _ => {}
        }
        buffer.clear();
    }
}

fn read_small(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(MAX_VERSION_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() as u64 <= MAX_VERSION_FILE_BYTES).then_some(bytes)
}

/// `<Xcode>.app/Contents/version.plist` for a `simctl` inside
/// `<Xcode>.app/Contents/Developer`.
fn xcode_version_plist(simctl: &Path) -> Option<PathBuf> {
    let developer = simctl
        .ancestors()
        .find(|path| path.file_name() == Some(std::ffi::OsStr::new("Developer")))?;
    let contents = developer.parent()?;
    (contents.file_name() == Some(std::ffi::OsStr::new("Contents")))
        .then(|| contents.join("version.plist"))
}

/// Serializes this process's `xcrun` calls with developer-activity scans, so a
/// scan never sees another session's own `simctl` child.
#[cfg(target_os = "macos")]
static TOOL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(target_os = "macos")]
fn tool_lock() -> std::sync::MutexGuard<'static, ()> {
    TOOL_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Production host: the signed `xcrun` runner and native metadata.
#[cfg(target_os = "macos")]
pub struct MacHost {
    runner: sayaka_platform_macos::devtools::XcrunRunner,
}

#[cfg(target_os = "macos")]
impl MacHost {
    pub fn new() -> Result<Self, SessionError> {
        sayaka_platform_macos::devtools::XcrunRunner::new()
            .map(|runner| Self { runner })
            .map_err(|error| SessionError::ToolUnavailable {
                message: error.to_string(),
            })
    }
}

#[cfg(target_os = "macos")]
fn tool_failure(error: sayaka_platform_macos::devtools::ToolError) -> ToolFailure {
    use sayaka_platform_macos::devtools::ToolError;
    match error {
        ToolError::Unavailable(message) => ToolFailure::Unavailable(message),
        ToolError::Spawn(error) => ToolFailure::Unavailable(error.to_string()),
        ToolError::Timeout => ToolFailure::Timeout,
        ToolError::OutputCap => ToolFailure::OutputCap,
        ToolError::Io(error) => ToolFailure::Io(error.to_string()),
    }
}

#[cfg(target_os = "macos")]
impl Host for MacHost {
    fn tool_identity(&self) -> Result<ToolIdentity, ToolFailure> {
        let _serialized = tool_lock();
        let evidence =
            sayaka_platform_macos::devtools::tool_evidence(&self.runner).map_err(tool_failure)?;
        Ok(ToolIdentity {
            fingerprint: evidence.fingerprint(),
            real_path: evidence.real_path,
        })
    }

    fn tool_versions(&self, tool: &ToolIdentity) -> ToolVersions {
        let macos = read_small(Path::new(
            "/System/Library/CoreServices/SystemVersion.plist",
        ))
        .and_then(|bytes| plist_string(&bytes, "ProductVersion"));
        let xcode = xcode_version_plist(&tool.real_path)
            .and_then(|path| read_small(&path))
            .and_then(|bytes| plist_string(&bytes, "CFBundleShortVersionString"));
        ToolVersions { macos, xcode }
    }

    fn run(&self, args: &[String], execute: bool) -> Result<ToolResult, ToolFailure> {
        use sayaka_platform_macos::devtools::{EXECUTE_TIMEOUT, LIST_TIMEOUT, ToolRunner};
        let timeout = if execute {
            EXECUTE_TIMEOUT
        } else {
            LIST_TIMEOUT
        };
        let _serialized = tool_lock();
        self.runner
            .run(args, timeout)
            .map(|output| ToolResult {
                success: output.success,
                stdout: output.stdout,
                stderr: output.stderr,
            })
            .map_err(tool_failure)
    }

    fn developer_activity(&self) -> io::Result<Vec<String>> {
        // Holding the tool lock guarantees no `xcrun` child of this process
        // is alive, so none needs excluding.
        let _serialized = tool_lock();
        Ok(sayaka_platform_macos::devtools::developer_activity(None)?
            .into_iter()
            .map(|path| path.display().to_string())
            .collect())
    }

    fn data_modified_unix_ns(&self, data_path: &Path) -> Option<i128> {
        sayaka_platform_macos::devtools::modified_unix_ns(data_path)
    }

    fn data_identity(&self, data_path: &Path) -> Option<(u64, u64)> {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::symlink_metadata(data_path).ok()?;
        Some((metadata.dev(), metadata.ino()))
    }

    fn now(&self) -> Instant {
        Instant::now()
    }
}

#[cfg(test)]
mod tests;
