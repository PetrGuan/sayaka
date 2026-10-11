// SPDX-License-Identifier: MPL-2.0
//! Single-use observation/delegation sessions. This module never sends an event.
use crate::{
    empty_trash_journal::{
        self as wire, Aggregate, Context, FinderOutcome, KnownItem, Observation, OperationState,
        SourceRef, SourceRoot, SourceStatus,
    },
    journal::{
        self, EvidenceBudget, EvidenceStamp, ItemRecord, ItemState, NativePath, Record, Store,
    },
};
use sayaka_platform_macos::empty_trash::{Root, Stamp};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    io,
    path::PathBuf,
    time::{Duration, Instant},
};
const TTL: Duration = Duration::from_secs(120);
const OBSERVE: Duration = Duration::from_secs(2);
fn error(s: &str) -> io::Error {
    journal::invalid(s)
}
fn check(d: Instant) -> io::Result<()> {
    if Instant::now() >= d {
        Err(error("empty_trash_deadline_expired"))
    } else {
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinderObservation {
    pub count: u64,
    pub warns_before_emptying: bool,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceInput {
    pub path: NativePath,
    pub schemas: Vec<u32>,
}
#[derive(Clone, Debug, Serialize)]
pub struct PreviewItem {
    pub item: ItemRecord,
    pub evidence: KnownItem,
}
#[derive(Clone, Debug, Serialize)]
pub struct Preview {
    pub kind: &'static str,
    pub schema_version: u32,
    pub contract: &'static str,
    pub effect_scope: &'static str,
    pub effects_performed: bool,
    pub can_begin: bool,
    pub plan_digest: String,
    pub approved_unix_ms: u64,
    pub deadline_unix_ms: u64,
    pub trash_root: Option<NativePath>,
    pub trash_device: Option<u64>,
    pub trash_inode: Option<u64>,
    pub finder: Option<FinderObservation>,
    pub known_subset_complete: bool,
    pub coverage_reasons: Vec<String>,
    pub refusals: Vec<String>,
    pub source_roots: Vec<SourceRoot>,
    pub items: Vec<PreviewItem>,
    pub omitted_count: Option<u64>,
    pub omitted_lower_bound: u64,
    pub unknown_size_count: u64,
    pub unaccounted_logical_bytes: Option<u64>,
    pub reclaimed_bytes: Option<u64>,
}
struct Origin {
    root: usize,
    id: String,
    digest: String,
    stamp: EvidenceStamp,
}
struct Retained {
    path: PathBuf,
    stamp: Stamp,
    item: ItemRecord,
    known: KnownItem,
}
struct Active {
    history: Store,
    guard: Store,
    record: Record,
}
pub struct EmptyTrashSession {
    preview: Preview,
    deadline: Instant,
    root: Option<Root>,
    base: Option<Root>,
    items: Vec<Retained>,
    origins: Vec<Origin>,
    begun: bool,
    finished: bool,
    permit_claimed: bool,
    active: Option<Active>,
    result: Option<Record>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Permit {
    pub operation_id: String,
    pub plan_digest: String,
    pub dispatch_timeout_seconds: u32,
    pub remaining_milliseconds: u64,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinishInput {
    pub outcome: FinderOutcome,
    #[serde(deserialize_with = "wire::required_option")]
    pub error_code: Option<i32>,
    #[serde(deserialize_with = "wire::required_option")]
    pub message: Option<String>,
    #[serde(deserialize_with = "wire::required_option")]
    pub finder_after_count: Option<u64>,
}
impl EmptyTrashSession {
    pub fn preview(&self) -> &Preview {
        &self.preview
    }
    pub fn result(&self) -> Option<&Record> {
        self.result.as_ref()
    }
    pub fn prepare(
        sources: Vec<SourceInput>,
        finder: Option<FinderObservation>,
    ) -> io::Result<Self> {
        let start = Instant::now();
        let deadline = start + TTL;
        let observation = start + OBSERVE;
        let created = journal::now_ms()?;
        if sources.len() > 8 {
            return Err(error("too_many_source_roots"));
        }
        let mut seen = HashSet::new();
        for s in &sources {
            let p = wire::path(&s.path)?;
            if !seen.insert(p)
                || s.schemas.is_empty()
                || s.schemas.len() > 8
                || s.schemas.iter().any(|n| !matches!(n,1..=5|7..=9))
                || s.schemas.iter().collect::<HashSet<_>>().len() != s.schemas.len()
            {
                return Err(error("invalid_source_roots"));
            }
        }
        let mut p = Preview {
            kind: "sayaka_empty_trash_preview",
            schema_version: 1,
            contract: wire::CONTRACT,
            effect_scope: wire::EFFECT_SCOPE,
            effects_performed: false,
            can_begin: false,
            plan_digest: String::new(),
            approved_unix_ms: created,
            deadline_unix_ms: created
                .checked_add(120000)
                .ok_or_else(|| error("timestamp_overflow"))?,
            trash_root: None,
            trash_device: None,
            trash_inode: None,
            finder,
            known_subset_complete: true,
            coverage_reasons: vec![],
            refusals: vec![],
            source_roots: vec![],
            items: vec![],
            omitted_count: Some(0),
            omitted_lower_bound: 0,
            unknown_size_count: 0,
            unaccounted_logical_bytes: None,
            reclaimed_bytes: None,
        };
        let root = match Root::capture(observation) {
            Ok(r) => {
                p.trash_root = Some(NativePath::from_path(r.path()));
                let (d, i) = r.identity();
                p.trash_device = Some(d);
                p.trash_inode = Some(i);
                Some(r)
            }
            Err(_) => {
                p.refusals.push("trash_root_unavailable".into());
                None
            }
        };
        let base = match Root::state_base(observation) {
            Ok(r) => Some(r),
            Err(_) => {
                p.refusals.push("canonical_state_base_unavailable".into());
                None
            }
        };
        let mut budget = EvidenceBudget {
            entries: 0,
            records: 0,
            bytes: 0,
            deadline: observation,
        };
        let mut items = BTreeMap::<PathBuf, Retained>::new();
        let mut conflicts = HashSet::new();
        let mut origins = Vec::new();
        for (index, input) in sources.into_iter().enumerate() {
            let path = wire::path(&input.path)?;
            let mut source = SourceRoot {
                path: input.path,
                schemas: input.schemas,
                status: SourceStatus::Incomplete,
                device: None,
                inode: None,
            };
            let read = (|| {
                budget.check()?;
                let store = Store::open(&path, false)?;
                let (d, i) = store.identity()?;
                source.device = Some(d);
                source.inode = Some(i);
                let records = store.source_records(&mut budget)?;
                Ok::<_, io::Error>(records)
            })();
            match read {
                Err(e) => {
                    if e.kind() == io::ErrorKind::NotFound
                        && std::fs::symlink_metadata(&path)
                            .is_err_and(|e| e.kind() == io::ErrorKind::NotFound)
                    {
                        source.status = SourceStatus::Absent
                    } else {
                        incomplete(&mut p, "source_unavailable_busy_corrupt_or_budget");
                    }
                }
                Ok(records) => {
                    source.status = SourceStatus::Read;
                    for evidence in records {
                        let record = evidence.record;
                        if !source.schemas.contains(&record.schema_version)
                            || record.schema_version == 10
                            || record
                                .items
                                .iter()
                                .any(|i| matches!(i.state, ItemState::Started | ItemState::Planned))
                        {
                            source.status = SourceStatus::Incomplete;
                            incomplete(&mut p, "unsupported_or_interrupted_source");
                            continue;
                        }
                        let mut retained_record = false;
                        for (row, item) in record.items.iter().enumerate() {
                            if item.state != ItemState::Succeeded {
                                continue;
                            }
                            let Some(destination) = &item.destination else {
                                continue;
                            };
                            let Ok(path) = wire::path(destination) else {
                                incomplete(&mut p, "invalid_destination");
                                continue;
                            };
                            let Some(root) = &root else {
                                incomplete(&mut p, "trash_root_unavailable");
                                continue;
                            };
                            if path.parent() != Some(root.path()) {
                                p.omitted_lower_bound += 1;
                                continue;
                            }
                            let stamp = match root.observe(&path, observation) {
                                Ok(Some(s)) if s.device == item.device && s.inode == item.inode => {
                                    s
                                }
                                Ok(_) => {
                                    p.omitted_lower_bound += 1;
                                    continue;
                                }
                                Err(_) => {
                                    p.omitted_lower_bound += 1;
                                    incomplete(&mut p, "destination_observation_unavailable");
                                    continue;
                                }
                            };
                            let measured = if let Some(c) = &record.orphan_context {
                                c.selected[row].measured_logical_bytes
                            } else {
                                Some(item.logical_bytes)
                            };
                            let reference = SourceRef {
                                root_index: index,
                                operation_id: record.operation_id.clone(),
                                item_index: row,
                                record_digest: evidence.digest.clone(),
                            };
                            if conflicts.contains(&path) {
                                p.omitted_lower_bound += 1;
                                continue;
                            }
                            if let Some(old) = items.get_mut(&path) {
                                if old.stamp != stamp
                                    || old.item.logical_bytes != item.logical_bytes
                                    || old.known.historical_logical_bytes != measured
                                    || old.known.source_refs.len() >= wire::MAX_REFS
                                {
                                    items.remove(&path);
                                    conflicts.insert(path);
                                    p.omitted_lower_bound += 1;
                                    incomplete(&mut p, "conflicting_or_excess_provenance");
                                } else {
                                    old.known.source_refs.push(reference);
                                    retained_record = true;
                                }
                                continue;
                            }
                            if items.len() >= wire::MAX_ITEMS {
                                p.omitted_lower_bound += 1;
                                incomplete(&mut p, "known_item_limit");
                                continue;
                            }
                            items.insert(
                                path.clone(),
                                Retained {
                                    path,
                                    stamp,
                                    item: ItemRecord {
                                        path: destination.clone(),
                                        device: item.device,
                                        inode: item.inode,
                                        logical_bytes: item.logical_bytes,
                                        state: ItemState::Started,
                                        reason: None,
                                        destination: None,
                                        rule_binding: None,
                                        recovery_evidence: None,
                                        updated_unix_ms: created,
                                    },
                                    known: KnownItem {
                                        source_refs: vec![reference],
                                        historical_logical_bytes: measured,
                                        observation: Observation::Started,
                                    },
                                },
                            );
                            retained_record = true;
                        }
                        if retained_record {
                            origins.push(Origin {
                                root: index,
                                id: record.operation_id,
                                digest: evidence.digest,
                                stamp: evidence.stamp,
                            })
                        }
                    }
                }
            }
            p.source_roots.push(source);
        }
        let items: Vec<_> = items.into_values().collect();
        let refs: HashSet<_> = items
            .iter()
            .flat_map(|i| {
                i.known
                    .source_refs
                    .iter()
                    .map(|r| (r.root_index, r.operation_id.clone()))
            })
            .collect();
        origins.retain(|o| refs.contains(&(o.root, o.id.clone())));
        p.items = items
            .iter()
            .map(|i| PreviewItem {
                item: i.item.clone(),
                evidence: i.known.clone(),
            })
            .collect();
        p.unknown_size_count = items
            .iter()
            .filter(|i| i.known.historical_logical_bytes.is_none())
            .count() as u64;
        if budget.check().is_err() {
            incomplete(&mut p, "observation_deadline");
        }
        p.omitted_count = if p.known_subset_complete {
            Some(p.omitted_lower_bound)
        } else {
            None
        };
        match finder {
            None => p
                .refusals
                .push("finder_observations_unavailable_read_only".into()),
            Some(f) if f.count == 0 => p.refusals.push("finder_reports_empty".into()),
            Some(f) if f.count < items.len() as u64 => p
                .refusals
                .push("finder_count_less_than_known_subset".into()),
            _ => {}
        }
        if let Some(b) = &base {
            if barrier(b, false, &mut budget).is_err() {
                p.refusals
                    .push("maintenance_barrier_unavailable_or_unresolved".into());
            }
        }
        if budget.check().is_err() {
            incomplete(&mut p, "observation_deadline");
        }
        p.omitted_count = if p.known_subset_complete {
            Some(p.omitted_lower_bound)
        } else {
            None
        };
        if check(deadline).is_err() {
            p.refusals.push("preview_expired".into())
        }
        p.can_begin = p.refusals.is_empty();
        p.plan_digest = format!("{:x}", Sha256::digest(serde_json::to_vec(&p)?));
        let mut session = Self {
            preview: p,
            deadline,
            root,
            base,
            items,
            origins,
            begun: false,
            finished: false,
            permit_claimed: false,
            active: None,
            result: None,
        };
        if session.preview.can_begin {
            let record = session.intent("0".into())?;
            let size = serde_json::to_vec(&record)?.len(); // Reserve bounded worst-case context/message and per-item observation strings.
            if size
                .checked_add(2048 + session.items.len() * 128)
                .is_none_or(|n| n > journal::MAX_RECORD_BYTES as usize)
            {
                session.preview.can_begin = false;
                session
                    .preview
                    .refusals
                    .push("complete_intent_exceeds_record_limit".into());
            }
        }
        Ok(session)
    }
    fn intent(&self, id: String) -> io::Result<Record> {
        let p = &self.preview;
        let finder = p
            .finder
            .ok_or_else(|| error("missing_finder_observation"))?;
        let context = Context {
            schema_version: 1,
            performer: "finder".into(),
            effect_scope: wire::EFFECT_SCOPE.into(),
            trash_root: p
                .trash_root
                .clone()
                .ok_or_else(|| error("missing_trash_root"))?,
            trash_device: p.trash_device.ok_or_else(|| error("missing_trash_root"))?,
            trash_inode: p.trash_inode.ok_or_else(|| error("missing_trash_root"))?,
            plan_digest: p.plan_digest.clone(),
            approved_unix_ms: p.approved_unix_ms,
            deadline_unix_ms: p.deadline_unix_ms,
            operation_state: OperationState::Started,
            aggregate_outcome: None,
            finder_preview_count: finder.count,
            finder_before_count: finder.count,
            finder_after_count: None,
            warns_before_emptying: finder.warns_before_emptying,
            finder_outcome: None,
            finder_error_code: None,
            finder_message: None,
            dispatch_timeout_seconds: 600,
            dispatch_may_continue: true,
            known_subset_complete: p.known_subset_complete,
            coverage_reasons: p.coverage_reasons.clone(),
            omitted_count: p.omitted_count,
            omitted_lower_bound: p.omitted_lower_bound,
            unknown_size_count: p.unknown_size_count,
            source_roots: p.source_roots.clone(),
            known_items: self.items.iter().map(|i| i.known.clone()).collect(),
            unaccounted_logical_bytes: None,
            reclaimed_bytes: None,
        };
        let r = Record {
            schema_version: 10,
            plan_schema_version: 10,
            engine_version: 1,
            rules_version: 1,
            operation_id: id,
            contract: wire::CONTRACT.into(),
            scope: context.trash_root.clone(),
            clean_policy: None,
            tool_operation: None,
            related_context: None,
            orphan_context: None,
            delegation: None,
            empty_trash_context: Some(context),
            created_unix_ms: p.approved_unix_ms,
            items: self.items.iter().map(|i| i.item.clone()).collect(),
        };
        r.validate()?;
        Ok(r)
    }
    /// Consumed even on refusal: a changed preview must be recaptured and reconfirmed.
    pub fn begin(
        &mut self,
        digest: &str,
        phrase: &str,
        finder: FinderObservation,
    ) -> io::Result<Permit> {
        if self.begun {
            return Err(error("preview_already_consumed"));
        }
        self.begun = true;
        if !self.preview.can_begin
            || digest != self.preview.plan_digest
            || phrase != "empty trash"
            || Some(finder) != self.preview.finder
        {
            return Err(error("approval_or_finder_observation_mismatch"));
        }
        check(self.deadline)?;
        let d = Instant::now() + OBSERVE;
        let root = self.root.as_ref().ok_or_else(|| error("missing_root"))?;
        let base = self.base.as_ref().ok_or_else(|| error("missing_base"))?;
        root.revalidate(d)?;
        base.revalidate(d)?;
        let mut b = EvidenceBudget {
            entries: 0,
            records: 0,
            bytes: 0,
            deadline: d,
        };
        for (index, source) in self.preview.source_roots.iter().enumerate() {
            let relevant: Vec<_> = self.origins.iter().filter(|o| o.root == index).collect();
            if relevant.is_empty() {
                continue;
            }
            let store = Store::open(&wire::path(&source.path)?, false)?;
            if Some(store.identity()?.0) != source.device
                || Some(store.identity()?.1) != source.inode
            {
                return Err(error("source_root_changed"));
            }
            for o in relevant {
                let current = store.source_record(&o.id, &mut b)?;
                if current.digest != o.digest || current.stamp != o.stamp {
                    return Err(error("source_record_changed"));
                }
            }
        }
        for i in &self.items {
            if root.observe(&i.path, d)?.as_ref() != Some(&i.stamp) {
                return Err(error("known_item_changed"));
            }
        }
        let (history, guard) = barrier(base, true, &mut b)?;
        let history = history.ok_or_else(|| error("missing_history_store"))?;
        let guard = guard.ok_or_else(|| error("missing_guard_store"))?;
        let id = history.empty_trash_id()?;
        let record = self.intent(id.clone())?;
        base.revalidate(d)?;
        root.revalidate(d)?;
        check(self.deadline)?;
        // Both stores must be durable, with publication markers removed, before permit.
        guard.publish(&record, true)?.require_clean()?;
        history.publish(&record, true)?.require_clean()?;
        base.revalidate(d)?;
        root.revalidate(d)?;
        check(self.deadline)?;
        let permit = Permit {
            operation_id: id,
            plan_digest: digest.into(),
            dispatch_timeout_seconds: 600,
            remaining_milliseconds: self
                .deadline
                .saturating_duration_since(Instant::now())
                .as_millis() as u64,
        };
        self.active = Some(Active {
            history,
            guard,
            record,
        });
        Ok(permit)
    }
    /// Host calls immediately before its one event. An expired or cancelled permit
    /// can only be finished as not_dispatched. The host also rechecks its license.
    pub fn claim_dispatch(&mut self) -> io::Result<u64> {
        if self.active.is_none() || self.finished || self.permit_claimed {
            return Err(error("permit_not_available"));
        }
        check(self.deadline)?;
        self.permit_claimed = true;
        Ok(self
            .deadline
            .saturating_duration_since(Instant::now())
            .as_millis() as u64)
    }
    pub fn finish(&mut self, input: FinishInput) -> io::Result<&Record> {
        if self.finished || self.active.is_none() {
            return Err(error("finish_not_available"));
        }
        if input.outcome != FinderOutcome::NotDispatched && !self.permit_claimed {
            return Err(error("dispatch_permit_not_claimed"));
        }
        self.finished = true;
        let d = Instant::now() + OBSERVE;
        let mut active = self
            .active
            .take()
            .ok_or_else(|| error("missing_active_operation"))?;
        let c = active
            .record
            .empty_trash_context
            .as_mut()
            .ok_or_else(|| error("missing_context"))?;
        let now = journal::now_ms()?.max(active.record.created_unix_ms);
        let root = self.root.as_ref().ok_or_else(|| error("missing_root"))?;
        for ((retained, item), known) in self
            .items
            .iter()
            .zip(&mut active.record.items)
            .zip(&mut c.known_items)
        {
            let observation = if input.outcome == FinderOutcome::NotDispatched {
                Observation::NotDispatched
            } else {
                match root.observe(&retained.path, d) {
                    Ok(None) => Observation::Absent,
                    Ok(Some(s)) if s == retained.stamp => Observation::Present,
                    _ => Observation::Unknown,
                }
            };
            known.observation = observation;
            let (state, reason) = match observation {
                Observation::Absent => (ItemState::Succeeded, "absent_after_delegation"),
                Observation::Present => (ItemState::Failed, "still_present"),
                Observation::NotDispatched => (ItemState::Skipped, "not_dispatched"),
                _ => (ItemState::Unknown, "observation_unknown"),
            };
            item.state = state;
            item.reason = Some(reason.into());
            item.updated_unix_ms = now;
        }
        let stable = root.revalidate(d).is_ok();
        if !stable && input.outcome != FinderOutcome::NotDispatched {
            for (k, i) in c.known_items.iter_mut().zip(&mut active.record.items) {
                k.observation = Observation::Unknown;
                i.state = ItemState::Unknown;
                i.reason = Some("observation_unknown".into());
            }
        }
        c.operation_state = OperationState::Finished;
        c.finder_outcome = Some(input.outcome);
        c.finder_error_code = input.error_code;
        c.finder_message = input.message.map(|s| sanitize(&s));
        c.finder_after_count = input.finder_after_count;
        c.dispatch_may_continue = matches!(
            input.outcome,
            FinderOutcome::TimedOut | FinderOutcome::TransportUnknown
        );
        c.aggregate_outcome = Some(wire::aggregate(
            input.outcome,
            c.known_items.iter().map(|i| i.observation),
            input.finder_after_count,
            stable,
        ));
        active.record.validate()?;
        let unresolved = c_unresolved(&active.record);
        // A failed publish leaves the external guard. Never expose a proposed result.
        self.base
            .as_ref()
            .ok_or_else(|| error("missing_base"))?
            .revalidate(Instant::now() + OBSERVE)?;
        active
            .history
            .publish(&active.record, false)?
            .require_clean()?;
        if !unresolved {
            active
                .guard
                .clear_empty_trash_guard(&active.record.operation_id)?;
        }
        self.result = Some(active.record);
        Ok(self.result.as_ref().expect("just assigned"))
    }
}
fn sanitize(s: &str) -> String {
    let mut v = String::new();
    for c in s.chars().filter(|c| !c.is_control()) {
        if v.len() + c.len_utf8() > 512 {
            break;
        }
        v.push(c)
    }
    v
}
fn incomplete(p: &mut Preview, reason: &str) {
    p.known_subset_complete = false;
    if !p.coverage_reasons.iter().any(|r| r == reason) && p.coverage_reasons.len() < 32 {
        p.coverage_reasons.push(reason.into());
    }
}
fn c_unresolved(r: &Record) -> bool {
    r.empty_trash_context.as_ref().is_none_or(|c| {
        c.operation_state == OperationState::Started
            || c.dispatch_may_continue
            || c.aggregate_outcome == Some(Aggregate::Unknown)
    })
}
fn barrier(
    base: &Root,
    create: bool,
    budget: &mut EvidenceBudget,
) -> io::Result<(Option<Store>, Option<Store>)> {
    let open = |name: &str| -> io::Result<Option<Store>> {
        let path = base.path().join(name);
        match Store::open(&path, create) {
            Ok(s) => Ok(Some(s)),
            Err(e)
                if !create
                    && e.kind() == io::ErrorKind::NotFound
                    && std::fs::symlink_metadata(&path)
                        .is_err_and(|e| e.kind() == io::ErrorKind::NotFound) =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    };
    budget.check()?;
    let guard = open("EmptyTrashState")?;
    let history = open("MaintenanceJournal")?;
    if let Some(g) = &guard {
        let r = g.source_records(budget)?;
        if !r.is_empty() {
            return Err(error("unresolved_empty_trash_guard"));
        }
    }
    if let Some(h) = &history {
        let r = h.source_records(budget)?;
        if r.len() >= journal::MAX_RECORDS
            || r.iter()
                .any(|e| e.record.schema_version != 10 || c_unresolved(&e.record))
        {
            return Err(error("unresolved_or_inconsistent_maintenance_history"));
        }
    }
    budget.check()?;
    Ok((history, guard))
}
