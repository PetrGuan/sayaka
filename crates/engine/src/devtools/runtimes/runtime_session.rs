// SPDX-License-Identifier: MPL-2.0
use super::*;
use crate::{
    devtools::session::{
        ExecuteRequest, Host, SessionError, ToolIdentity, ToolJournal, ToolVersions, open_journal,
        pair_batches,
    },
    journal::{self, ItemState, NativePath, Record},
    model::Cancellation,
    runtime_journal::{Context, Item, Target},
};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
#[derive(Clone, Debug, Serialize)]
pub struct RuntimePreview {
    pub candidates: Vec<RuntimeCandidate>,
    pub tool: ToolIdentity,
    pub versions: ToolVersions,
    pub developer_activity: Vec<String>,
    pub plan_digest: String,
    pub observed_unix_ms: u64,
}
#[derive(Serialize)]
pub struct RuntimeReport {
    pub record: Record,
    pub journal_error: Option<String>,
}
#[derive(Clone)]
struct Listing {
    images: Vec<Runtime>,
    devices: Vec<Device>,
    pairs: Vec<(String, String)>,
    types: BTreeMap<String, String>,
    matches: Vec<SdkMatch>,
}
pub struct RuntimeSession<H> {
    host: H,
    preview: RuntimePreview,
    listing: Listing,
    created: Instant,
    consumed: bool,
    #[cfg(debug_assertions)]
    disposable: Option<(String, BTreeSet<String>)>,
}
fn invalid(s: &str) -> SessionError {
    SessionError::InvalidRequest {
        message: s.into(),
        refusal: None,
    }
}
fn parse(e: ParseError) -> SessionError {
    SessionError::ParseFailed {
        message: e.to_string(),
    }
}
fn journal_error(e: std::io::Error) -> SessionError {
    SessionError::JournalUnavailable {
        message: e.to_string(),
    }
}
fn check(cancel: &Cancellation, start: Instant, now: Instant) -> Result<(), SessionError> {
    if cancel.is_cancelled() {
        Err(SessionError::Cancelled)
    } else if now.saturating_duration_since(start) >= Duration::from_secs(160) {
        Err(SessionError::Timeout)
    } else {
        Ok(())
    }
}
fn read<H: Host>(
    host: &H,
    args: &[&str],
    cancel: &Cancellation,
    start: Instant,
) -> Result<Vec<u8>, SessionError> {
    check(cancel, start, host.now())?;
    let output = host
        .run(
            &args.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            false,
        )
        .map_err(|e| e.into_error())?;
    check(cancel, start, host.now())?;
    if !output.success {
        return Err(SessionError::ToolUnavailable {
            message: "read-only simctl command failed".into(),
        });
    }
    if output.stdout.len() > MAX_LIST_BYTES {
        return Err(SessionError::OutputCapExceeded);
    }
    Ok(output.stdout)
}
fn checked_devices(raw: &[u8]) -> Result<Vec<Device>, SessionError> {
    json(raw).map_err(parse)?;
    let mut devices = parse_devices(raw).map_err(parse)?;
    devices.sort_by(|a, b| a.udid.cmp(&b.udid));
    for d in &devices {
        if !valid_path(&d.data_path)
            || [
                &d.name,
                &d.runtime_identifier,
                &d.device_type_identifier,
                &d.state,
            ]
            .iter()
            .any(|s| s.len() > 4096 || s.contains('\0'))
        {
            return Err(invalid("invalid device fields"));
        }
    }
    Ok(devices)
}

fn listing<H: Host>(
    host: &H,
    cancel: &Cancellation,
    start: Instant,
) -> Result<Listing, SessionError> {
    let images = parse_runtimes(&read(
        host,
        &["simctl", "runtime", "list", "-j"],
        cancel,
        start,
    )?)
    .map_err(parse)?;
    let matches = parse_matches(&read(
        host,
        &["simctl", "runtime", "match", "list", "-j"],
        cancel,
        start,
    )?)
    .map_err(parse)?;
    let raw = read(host, &["simctl", "list", "devices", "-j"], cancel, start)?;
    let devices = checked_devices(&raw)?;
    let raw = read(host, &["simctl", "list", "pairs", "-j"], cancel, start)?;
    json(&raw).map_err(parse)?;
    let mut pairs = parse_pairs(&raw).map_err(parse)?;
    if pairs.len() > 512 {
        return Err(SessionError::OutputCapExceeded);
    }
    pairs.sort();
    let types = parse_types(&read(
        host,
        &["simctl", "list", "devicetypes", "-j"],
        cancel,
        start,
    )?)
    .map_err(parse)?;
    Ok(Listing {
        images,
        devices,
        pairs,
        types,
        matches,
    })
}
impl<H: Host> RuntimeSession<H> {
    pub fn prepare(host: H, cancel: &Cancellation) -> Result<Self, SessionError> {
        let start = host.now();
        check(cancel, start, host.now())?;
        let tool = host.tool_identity().map_err(|e| e.into_error())?;
        let versions = host.tool_versions(&tool);
        if !versions.macos.as_deref().is_some_and(|s| {
            s.split('.')
                .next()
                .and_then(|s| s.parse::<u32>().ok())
                .is_some_and(|v| v >= 26)
        }) || !versions.xcode.as_deref().is_some_and(|s| {
            s.split('.')
                .next()
                .and_then(|s| s.parse::<u32>().ok())
                .is_some_and(|v| v >= 26)
        }) {
            return Err(SessionError::UnsupportedToolVersion {
                macos: versions.macos,
                xcode: versions.xcode,
            });
        }
        let l = listing(&host, cancel, start)?;
        if host.tool_identity().map_err(|e| e.into_error())? != tool {
            return Err(SessionError::ToolChanged);
        }
        let activity = host
            .developer_activity()
            .map_err(|_| SessionError::DeveloperActivity {
                executables: vec![],
            })?;
        let now = journal::now_ms().map_err(journal_error)?;
        let candidates = assess(
            &l.images,
            &l.devices,
            &l.pairs,
            &l.types,
            &l.matches,
            versions.xcode.as_deref(),
            now / 1000,
        );
        let seal = serde_json::to_vec(&(&tool, &versions, &candidates, &l.matches, &l.types, now))
            .map_err(|_| invalid("serialization"))?;
        if seal.len() > MAX_REPORT {
            return Err(SessionError::OutputCapExceeded);
        }
        let plan_digest = format!("{:x}", Sha256::digest(&seal));
        check(cancel, start, host.now())?;
        let created = host.now();
        Ok(Self {
            host,
            preview: RuntimePreview {
                candidates,
                tool,
                versions,
                developer_activity: activity,
                plan_digest,
                observed_unix_ms: now,
            },
            listing: l,
            created,
            consumed: false,
            #[cfg(debug_assertions)]
            disposable: None,
        })
    }
    /// Development-only evidence collection. Caller must explicitly supply owned,
    /// disposable identities. Not exported by release bindings; bypasses only evidence.
    #[cfg(debug_assertions)]
    pub fn prepare_disposable(
        host: H,
        cancel: &Cancellation,
        image: &str,
        devices: &[String],
    ) -> Result<Self, SessionError> {
        let mut s = Self::prepare(host, cancel)?;
        if canonical_udid(image).as_deref() != Some(image)
            || devices.len() > 32
            || devices.iter().collect::<BTreeSet<_>>().len() != devices.len()
        {
            return Err(invalid("invalid disposable identities"));
        }
        let c = s
            .preview
            .candidates
            .iter_mut()
            .find(|c| c.runtime.identifier == image)
            .ok_or_else(|| invalid("disposable image not observed"))?;
        let ids: BTreeSet<_> = devices.iter().cloned().collect();
        if c.dependents
            .iter()
            .map(|d| d.device.udid.clone())
            .collect::<BTreeSet<_>>()
            != ids
        {
            return Err(invalid("disposable device set differs"));
        }
        c.refusals.retain(|r| r != "native_evidence_missing");
        s.disposable = Some((image.into(), ids));
        s.preview.plan_digest = format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&(&s.preview, &s.disposable)).map_err(|_| invalid("seal"))?
            )
        );
        Ok(s)
    }
    pub fn preview(&self) -> &RuntimePreview {
        &self.preview
    }
    fn selected(&self, r: &ExecuteRequest) -> Result<Vec<&RuntimeCandidate>, SessionError> {
        if self.consumed {
            return Err(SessionError::Consumed);
        }
        if self.host.now().saturating_duration_since(self.created) >= PREVIEW_TTL {
            return Err(SessionError::Expired);
        }
        if r.plan_digest != self.preview.plan_digest
            || r.items.is_empty()
            || r.items.len() > 32
            || r.items.iter().collect::<BTreeSet<_>>().len() != r.items.len()
        {
            return Err(invalid("invalid runtime selection"));
        }
        let mut selected = Vec::new();
        for id in &r.items {
            let c = self
                .preview
                .candidates
                .iter()
                .find(|c| &c.runtime.identifier == id)
                .ok_or_else(|| invalid("runtime not previewed"))?;
            if !c.eligible() {
                return Err(invalid("runtime is protected"));
            }
            selected.push(c)
        }
        selected.sort_by(|a, b| a.runtime.identifier.cmp(&b.runtime.identifier));
        if selected.iter().map(|c| c.dependents.len()).sum::<usize>() > 32 {
            return Err(invalid("too many dependent devices"));
        }
        Ok(selected)
    }
    pub fn check_approval(&self, r: &ExecuteRequest) -> Result<(), SessionError> {
        let s = self.selected(r)?;
        let n = s.iter().map(|c| c.dependents.len()).sum::<usize>();
        if r.approval_token != format!("delete {} runtimes and {n} simulators", s.len()) {
            return Err(invalid("approval phrase mismatch"));
        }
        Ok(())
    }
    pub fn check_state_dir(&self, path: &Path) -> Result<(), SessionError> {
        journal::validate_state_directory_path(path).map_err(journal_error)?;
        // Resolve an existing parent, not an unchecked lexical fallback.
        let real = if path.exists() {
            std::fs::canonicalize(path)
        } else {
            path.parent()
                .ok_or_else(|| invalid("journal parent"))?
                .canonicalize()
                .map(|p| p.join(path.file_name().unwrap()))
        }
        .map_err(journal_error)?;
        let mut roots = vec![
            PathBuf::from("/Library/Developer/CoreSimulator"),
            PathBuf::from("/System/Library/AssetsV2"),
        ];
        let home = std::env::home_dir().ok_or_else(|| invalid("home unavailable"))?;
        roots.push(home.join("Library/Logs/CoreSimulator"));
        for d in &self.listing.devices {
            roots.push(
                Path::new(&d.data_path)
                    .parent()
                    .ok_or_else(|| invalid("device parent"))?
                    .to_path_buf(),
            );
        }
        for i in &self.listing.images {
            roots.push(PathBuf::from(&i.path));
        }
        for root in roots {
            if path.starts_with(&root) || real.starts_with(&root) {
                return Err(invalid("journal overlaps runtime-managed data"));
            }
            if root.exists() {
                let resolved = root.canonicalize().map_err(journal_error)?;
                if real.starts_with(resolved) {
                    return Err(invalid("journal alias overlaps managed data"));
                }
                use std::os::unix::fs::MetadataExt;
                let m = std::fs::metadata(&root).map_err(journal_error)?;
                for a in real.ancestors() {
                    if let Ok(n) = std::fs::metadata(a) {
                        if m.dev() == n.dev() && m.ino() == n.ino() {
                            return Err(invalid("journal identity overlaps managed data"));
                        }
                    }
                }
            }
        }
        Ok(())
    }
    fn fresh(&self, cancel: &Cancellation) -> Result<Listing, SessionError> {
        let start = self.host.now();
        let activity =
            self.host
                .developer_activity()
                .map_err(|_| SessionError::DeveloperActivity {
                    executables: vec![],
                })?;
        if !activity.is_empty() {
            return Err(SessionError::DeveloperActivity {
                executables: activity,
            });
        }
        if self.host.tool_identity().map_err(|e| e.into_error())? != self.preview.tool {
            return Err(SessionError::ToolChanged);
        }
        let l = listing(&self.host, cancel, start)?;
        if self.host.tool_identity().map_err(|e| e.into_error())? != self.preview.tool {
            return Err(SessionError::ToolChanged);
        }
        let activity =
            self.host
                .developer_activity()
                .map_err(|_| SessionError::DeveloperActivity {
                    executables: vec![],
                })?;
        if !activity.is_empty() {
            return Err(SessionError::DeveloperActivity {
                executables: activity,
            });
        }
        Ok(l)
    }
    fn validate(
        &self,
        l: &Listing,
        c: &RuntimeCandidate,
        removed: &BTreeSet<String>,
    ) -> Result<(), SessionError> {
        let current = l
            .images
            .iter()
            .find(|i| i.identifier == c.runtime.identifier)
            .ok_or_else(|| invalid("runtime disappeared"))?;
        // Optional size/activity changes are not identity changes, but cannot relax admission.
        let mut identity = current.clone();
        identity.size_bytes = c.runtime.size_bytes;
        identity.last_used_at = c.runtime.last_used_at.clone();
        identity.issues = c.runtime.issues.clone();
        if identity != c.runtime
            || l.matches != self.listing.matches
            || l.types != self.listing.types
        {
            return Err(invalid("runtime or SDK/type evidence changed"));
        }
        let expected: Vec<_> = c
            .dependents
            .iter()
            .filter(|d| !removed.contains(&d.device.udid))
            .cloned()
            .collect();
        let now = journal::now_ms().map_err(journal_error)? / 1000;
        let mut assessed = assess(
            &l.images,
            &l.devices,
            &l.pairs,
            &l.types,
            &l.matches,
            self.preview.versions.xcode.as_deref(),
            now,
        );
        #[cfg(debug_assertions)]
        if let Some((id, ids)) = &self.disposable {
            if id == &c.runtime.identifier
                && c.dependents
                    .iter()
                    .map(|d| d.device.udid.clone())
                    .collect::<BTreeSet<_>>()
                    == *ids
            {
                if let Some(a) = assessed.iter_mut().find(|a| &a.runtime.identifier == id) {
                    a.refusals.retain(|r| r != "native_evidence_missing");
                }
            }
        }
        let actual = assessed
            .iter()
            .find(|a| a.runtime.identifier == c.runtime.identifier)
            .ok_or_else(|| invalid("runtime missing"))?;
        if !actual.eligible() || actual.dependents.len() != expected.len() {
            return Err(invalid("runtime or dependents protected/changed"));
        }
        for (a, e) in actual.dependents.iter().zip(expected.iter()) {
            if a.device.udid != e.device.udid
                || a.device.name != e.device.name
                || a.device.runtime_identifier != e.device.runtime_identifier
                || a.device.device_type_identifier != e.device.device_type_identifier
                || a.device.data_path != e.device.data_path
                || a.device.is_available != e.device.is_available
                || a.device.state != e.device.state
                || a.paired_with != e.paired_with
                || a.refusals != e.refusals
            {
                return Err(invalid("dependent identity changed"));
            }
        }
        if removed
            .iter()
            .any(|id| l.devices.iter().any(|d| &d.udid == id))
        {
            return Err(invalid("removed device reappeared"));
        }
        Ok(())
    }
    fn dry_run(&self, c: &RuntimeCandidate, cancel: &Cancellation) -> Result<(), SessionError> {
        read(
            &self.host,
            &[
                "simctl",
                "runtime",
                "delete",
                &c.runtime.identifier,
                "--dry-run",
            ],
            cancel,
            self.host.now(),
        )
        .map(|_| ())
    }
    pub fn execute(
        &mut self,
        r: &ExecuteRequest,
        cancel: &Cancellation,
        path: &Path,
    ) -> Result<RuntimeReport, SessionError> {
        self.check_approval(r)?;
        self.check_state_dir(path)?;
        let store = open_journal(path)?;
        self.execute_with(r, cancel, &store)
    }
    fn execute_with(
        &mut self,
        r: &ExecuteRequest,
        cancel: &Cancellation,
        store: &impl ToolJournal,
    ) -> Result<RuntimeReport, SessionError> {
        self.check_approval(r)?;
        let selected: Vec<_> = self.selected(r)?.into_iter().cloned().collect();
        let l = self.fresh(cancel)?;
        let mut removed = BTreeSet::new();
        for c in &selected {
            self.validate(&l, c, &removed)?;
            self.dry_run(c, cancel)?
        }
        self.check_approval(r)?;
        self.consumed = true;
        let now = journal::now_ms().map_err(journal_error)?;
        let mut items = Vec::new();
        let mut calls = Vec::new();
        for c in &selected {
            let ids = c
                .dependents
                .iter()
                .map(|d| d.device.udid.clone())
                .collect::<Vec<_>>();
            for batch in pair_batches(&c.dependents, &ids) {
                let start = items.len();
                for id in &batch {
                    let d = c.dependents.iter().find(|d| &d.device.udid == id).unwrap();
                    items.push(Item {
                        target: Target::Device {
                            udid: id.clone(),
                            name: d.device.name.clone(),
                            runtime_identifier: d.device.runtime_identifier.clone(),
                            paired_with: d.paired_with.clone(),
                        },
                        logical_bytes: d.device.data_path_size,
                        state: ItemState::Planned,
                        reason: None,
                        updated_unix_ms: now,
                    });
                }
                calls.push((
                    c.clone(),
                    start..items.len(),
                    argument_vector(Operation::Delete, &batch).unwrap(),
                    false,
                ));
            }
            let start = items.len();
            items.push(Item {
                target: Target::Runtime {
                    image: c.runtime.clone(),
                    dependent_udids: ids,
                },
                logical_bytes: c.runtime.size_bytes,
                state: ItemState::Planned,
                reason: None,
                updated_unix_ms: now,
            });
            calls.push((
                c.clone(),
                start..items.len(),
                vec![
                    "simctl".into(),
                    "runtime".into(),
                    "delete".into(),
                    c.runtime.identifier.clone(),
                ],
                true,
            ));
        }
        let mut report = RuntimeReport {
            record: Record {
                schema_version: 11,
                plan_schema_version: 11,
                engine_version: 2,
                rules_version: 1,
                operation_id: store.new_id().map_err(journal_error)?,
                contract: EFFECT_CLASS.into(),
                scope: NativePath::from_path(Path::new("/")),
                clean_policy: None,
                tool_operation: None,
                related_context: None,
                orphan_context: None,
                delegation: None,
                empty_trash_context: None,
                runtime_context: Some(Context {
                    schema_version: 1,
                    operation: "runtime_delete".into(),
                    tool_evidence: self.preview.tool.fingerprint.clone(),
                    plan_digest: r.plan_digest.clone(),
                    items,
                }),
                created_unix_ms: now,
                items: vec![],
            },
            journal_error: None,
        };
        store
            .publish(&report.record, true)
            .and_then(journal::Publication::require_clean)
            .map_err(journal_error)?;
        let mut stop = None;
        for (c, range, args, is_runtime) in calls {
            if stop.is_none() {
                let pre = (|| {
                    let l = self.fresh(cancel)?;
                    self.validate(&l, &c, &removed)?;
                    if is_runtime {
                        if l.devices
                            .iter()
                            .any(|d| d.runtime_identifier == c.runtime.runtime_identifier)
                        {
                            return Err(invalid("new runtime dependents"));
                        }
                        self.dry_run(&c, cancel)?;
                        let l = self.fresh(cancel)?;
                        self.validate(&l, &c, &removed)?;
                    }
                    if cancel.is_cancelled() {
                        return Err(SessionError::Cancelled);
                    }
                    Ok(())
                })();
                if let Err(e) = pre {
                    stop = Some(e.code().to_string())
                }
            }
            if let Some(reason) = &stop {
                set(&mut report, range, ItemState::Skipped, reason);
                continue;
            }
            set(&mut report, range.clone(), ItemState::Started, "");
            if let Err(e) = store
                .publish(&report.record, false)
                .and_then(journal::Publication::require_clean)
            {
                set(
                    &mut report,
                    range,
                    ItemState::Skipped,
                    "journal_failed_before_call",
                );
                report.journal_error = Some(e.to_string());
                stop = Some("journal_unavailable".into());
                continue;
            }
            let call = self.host.run(&args, true);
            let settled = (is_runtime && call.as_ref().is_ok_and(|output| output.success))
                .then(|| self.settle_runtime(&c.runtime, cancel));
            // Do not add another observation after settlement has latched uncertainty.
            let after = if settled.is_none() {
                listing(&self.host, &Cancellation::default(), self.host.now())
            } else {
                Err(SessionError::Cancelled)
            };
            for index in range {
                let item = &mut report.record.runtime_context.as_mut().unwrap().items[index];
                let (state, reason) = if let Some(result) = &settled {
                    result.clone()
                } else {
                    match (&call, &after) {
                        (Err(e), _) => (ItemState::Unknown, e.reason()),
                        (_, Err(e)) => (
                            ItemState::Unknown,
                            format!("post_check_failed: {}", e.code()),
                        ),
                        (Ok(output), Ok(l)) => {
                            let absent = match &item.target {
                                Target::Device { udid, .. } => {
                                    !l.devices.iter().any(|d| &d.udid == udid)
                                }
                                Target::Runtime { image, .. } => {
                                    !l.images.iter().any(|r| r.identifier == image.identifier)
                                        && !l.devices.iter().any(|d| {
                                            d.runtime_identifier == image.runtime_identifier
                                        })
                                }
                            };
                            if absent {
                                (
                                    ItemState::Succeeded,
                                    if output.success {
                                        ""
                                    } else {
                                        "removed_after_nonzero_exit"
                                    }
                                    .into(),
                                )
                            } else if !output.success {
                                let unchanged = match &item.target {
                                    Target::Runtime { image, .. } => {
                                        l.images.iter().any(|r| r == image)
                                    }
                                    Target::Device { udid, .. } => c
                                        .dependents
                                        .iter()
                                        .find(|d| &d.device.udid == udid)
                                        .is_some_and(|before| {
                                            l.devices.iter().any(|d| d == &before.device)
                                        }),
                                };
                                (
                                    if unchanged {
                                        ItemState::Failed
                                    } else {
                                        ItemState::Unknown
                                    },
                                    "tool_reported_failure".into(),
                                )
                            } else {
                                (ItemState::Unknown, "post_check_mismatch".into())
                            }
                        }
                    }
                };
                item.state = state.clone();
                item.reason = (!reason.is_empty()).then(|| reason.chars().take(128).collect());
                item.updated_unix_ms = journal::now_ms().unwrap_or(now);
                if state == ItemState::Succeeded {
                    if let Target::Device { udid, .. } = &item.target {
                        removed.insert(udid.clone());
                    }
                } else {
                    stop = Some("stopped_after_failed_or_unknown_outcome".into())
                }
            }
            // A nonzero device call still stops even when all absences were observed.
            if call.as_ref().is_ok_and(|o| !o.success) {
                stop = Some("stopped_after_tool_failure".into())
            }
            if let Err(e) = store
                .publish(&report.record, false)
                .and_then(journal::Publication::require_clean)
            {
                report.journal_error = Some(e.to_string());
                stop = Some("journal_unavailable".into())
            }
        }
        if let Err(e) = store
            .publish(&report.record, false)
            .and_then(journal::Publication::require_clean)
        {
            report.journal_error = Some(e.to_string())
        }
        Ok(report)
    }
}
// A zero-exit runtime deletion may return while CoreSimulator still says Deleting.
// This is one post-check, not an effect retry or reconciliation of old history.
const SETTLE_WINDOW: Duration = Duration::from_secs(30);
const SETTLE_INTERVAL: Duration = Duration::from_millis(250);
const MAX_SETTLE_OBSERVATIONS: usize = 120;

fn settlement_identity(current: &Runtime, original: &Runtime) -> bool {
    current.identifier == original.identifier
        && current.runtime_identifier == original.runtime_identifier
        && current.version == original.version
        && current.build == original.build
        && current.kind == original.kind
        && current.path == original.path
        && current.deletable == original.deletable
}

impl<H: Host> RuntimeSession<H> {
    fn settle_runtime(&self, image: &Runtime, cancel: &Cancellation) -> (ItemState, String) {
        let start = self.host.now();
        let mut attempts = 0;
        let mut last = "not_observed";
        let mut registration_absent = false;
        let unknown = |cause: &str, attempts: usize| {
            (
                ItemState::Unknown,
                format!("runtime_post_check:{cause};observations={attempts}"),
            )
        };
        loop {
            if cancel.is_cancelled() {
                return unknown("cancelled", attempts);
            }
            if self.host.now().saturating_duration_since(start) >= SETTLE_WINDOW
                || attempts >= MAX_SETTLE_OBSERVATIONS
            {
                return unknown(&format!("deadline_{last}"), attempts);
            }
            // Existing identity/activity observations can have an in-flight overrun;
            // no outcome is accepted after the monotonic settlement window expires.
            match self.host.tool_identity() {
                Ok(tool) if tool == self.preview.tool => (),
                _ => return unknown("tool_changed_or_unavailable", attempts),
            }
            match self.host.developer_activity() {
                Ok(activity) if activity.is_empty() => (),
                _ => return unknown("activity_changed_or_unavailable", attempts),
            }
            let read = |args: &[&str]| -> Result<Vec<u8>, &'static str> {
                if cancel.is_cancelled() {
                    return Err("cancelled");
                }
                let remaining = SETTLE_WINDOW
                    .checked_sub(self.host.now().saturating_duration_since(start))
                    .filter(|v| !v.is_zero())
                    .ok_or("deadline")?;
                let output = self
                    .host
                    .run_read_with_timeout(
                        &args.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                        remaining,
                    )
                    .map_err(|_| "read_failed")?;
                if cancel.is_cancelled() {
                    return Err("cancelled");
                }
                if self.host.now().saturating_duration_since(start) >= SETTLE_WINDOW {
                    return Err("deadline");
                }
                if !output.success || output.stdout.len() > MAX_LIST_BYTES {
                    return Err("read_failed_or_capped");
                }
                Ok(output.stdout)
            };
            attempts += 1;
            let observed = (|| {
                let images = parse_runtimes(&read(&["simctl", "runtime", "list", "-j"])?)
                    .map_err(|_| "invalid_images")?;
                let raw = read(&["simctl", "list", "devices", "-j"])?;
                let devices = checked_devices(&raw).map_err(|_| "invalid_devices")?;
                Ok::<_, &str>((images, devices))
            })();
            let (images, devices) = match observed {
                Ok(value) => value,
                Err(cause) => return unknown(cause, attempts),
            };
            if images.iter().any(|r| {
                r.runtime_identifier == image.runtime_identifier && r.identifier != image.identifier
            }) {
                return unknown("ambiguous_images", attempts);
            }
            if devices
                .iter()
                .any(|d| d.runtime_identifier == image.runtime_identifier)
            {
                return unknown("dependent_observed", attempts);
            }
            let current = images.iter().find(|r| r.identifier == image.identifier);
            if let Some(current) = current {
                if registration_absent {
                    return unknown("runtime_reappeared", attempts);
                }
                if !settlement_identity(current, image) {
                    return unknown("identity_changed", attempts);
                }
                last = match current.state.as_str() {
                    "Ready" => "ready",
                    "Deleting" => "deleting",
                    _ => return unknown("unexpected_state", attempts),
                };
            }
            match self.host.tool_identity() {
                Ok(tool) if tool == self.preview.tool => (),
                _ => return unknown("tool_changed_or_unavailable", attempts),
            }
            match self.host.developer_activity() {
                Ok(activity) if activity.is_empty() => (),
                _ => return unknown("activity_changed_or_unavailable", attempts),
            }
            if cancel.is_cancelled() {
                return unknown("cancelled", attempts);
            }
            if self.host.now().saturating_duration_since(start) >= SETTLE_WINDOW {
                return unknown("deadline", attempts);
            }
            if current.is_none() {
                registration_absent = true;
                match self.host.runtime_path_present(Path::new(&image.path)) {
                    Ok(false) => {
                        if cancel.is_cancelled() {
                            return unknown("cancelled", attempts);
                        }
                        if self.host.now().saturating_duration_since(start) >= SETTLE_WINDOW {
                            return unknown("deadline", attempts);
                        }
                        return (
                            ItemState::Succeeded,
                            format!("runtime_and_path_absence_confirmed;observations={attempts}"),
                        );
                    }
                    Ok(true) => last = "asset_path_present",
                    Err(_) => return unknown("asset_path_unavailable", attempts),
                }
            }
            let remaining =
                SETTLE_WINDOW.saturating_sub(self.host.now().saturating_duration_since(start));
            self.host
                .wait_for_runtime_post_check(SETTLE_INTERVAL.min(remaining));
        }
    }
}

fn set(r: &mut RuntimeReport, range: std::ops::Range<usize>, state: ItemState, reason: &str) {
    for i in &mut r.record.runtime_context.as_mut().unwrap().items[range] {
        i.state = state.clone();
        i.reason = (!reason.is_empty()).then(|| reason.into());
        i.updated_unix_ms = journal::now_ms().unwrap_or(i.updated_unix_ms)
    }
}

#[cfg(test)]
mod tests;
