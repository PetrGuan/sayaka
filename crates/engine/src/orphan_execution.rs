// SPDX-License-Identifier: MPL-2.0
//! Retained orphan plans; serialized evidence and history never confer authority.
use crate::{
    app_observation::{self as observation, Bundle, Root},
    app_uninstall,
    clean_policy::{self, ConfigPath, GlobalPolicySnapshot},
    execute::ExecutionReport,
    journal::{self, ItemState, NativePath, Record, Store},
    model::Cancellation,
    orphan_journal::{self as wire, Binding},
    related_uninstall::{self as shared, absent_without_links},
};
use sayaka_platform_macos::{
    self as platform, NativeLastGuard, OrphanTrashCandidate, orphans,
    related::{self, PathWitness, Rule},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    io,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime},
};
pub const ORPHAN_NATIVE_ACCEPTANCE_RECORDED: bool = false;
pub const CONTRACT: &str = "revalidated_orphan_trash_v1";
const TTL: Duration = Duration::from_secs(120);
const AGE: Duration = Duration::from_secs(30 * 24 * 60 * 60);
fn error(s: impl ToString) -> io::Error {
    io::Error::other(s.to_string())
}
fn hash(v: impl AsRef<[u8]>) -> String {
    Sha256::digest(v)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn native(p: &NativePath) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;
    PathBuf::from(std::ffi::OsStr::from_bytes(&p.bytes))
}
fn disjoint(a: &Path, b: &Path) -> io::Result<()> {
    crate::purge_preview::bundle_owned::ensure_disjoint(a, b).map_err(error)
}
#[derive(Clone, Debug, Serialize)]
pub struct CandidatePreview {
    #[serde(flatten)]
    pub binding: Binding,
    pub ownership_basis: &'static str,
    pub execution_supported: bool,
    pub default_selected: bool,
    pub refusals: Vec<String>,
    pub latest_mtime_unix_ms: Option<u64>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Preview {
    pub kind: &'static str,
    pub schema_version: u32,
    pub complete: bool,
    pub effects_performed: bool,
    pub home: NativePath,
    pub plan_digest: String,
    pub expires_unix_ms: u64,
    pub coverage: &'static str,
    pub copy_roots: Vec<wire::RootRecord>,
    pub spotlight: Vec<wire::SpotlightRecord>,
    pub issues: Vec<String>,
    pub warning: &'static str,
    pub candidates: Vec<CandidatePreview>,
}
struct Candidate {
    rule: Rule,
    path: PathBuf,
    native: Option<OrphanTrashCandidate>,
}
pub struct OrphanSession {
    preview: Preview,
    captured: Instant,
    created: u64,
    home: PathBuf,
    library: PathWitness,
    roots: Vec<Root>,
    trash: PathWitness,
    bundles: Vec<Bundle>,
    candidates: Vec<Candidate>,
    config: ConfigPath,
    policy: GlobalPolicySnapshot,
    cancellation: Cancellation,
    last_wall: std::cell::Cell<u64>,
    wall_deadline: std::cell::Cell<Option<u64>>,
    launch_snapshot: LaunchSnapshot,
    entries_remaining: std::cell::Cell<usize>,
    moved_targets: std::cell::RefCell<Vec<PathWitness>>,
}
impl OrphanSession {
    pub fn prepare(
        extra: &[PathBuf],
        policy_dir: &Path,
        cancellation: Cancellation,
    ) -> io::Result<Self> {
        let captured = Instant::now();
        let deadline = captured + Duration::from_secs(30);
        let created = journal::now_ms()?;
        let home = platform::effective_account_home()?;
        let library = orphans::exact(&home.join("Library"))?;
        let roots = observation::roots(&home, extra)?;
        let trash = orphans::verified_trash()?;
        let config = clean_policy::resolve_config_path(Some(policy_dir))?;
        let policy = clean_policy::snapshot_all(&config)?;
        let launch_snapshot = LaunchSnapshot::capture(&home, deadline)?;
        let mut session = Self {
            preview: Preview {
                kind: "sayaka.orphan_preview",
                schema_version: 2,
                complete: false,
                effects_performed: false,
                home: NativePath::from_path(&home),
                plan_digest: String::new(),
                expires_unix_ms: created
                    .checked_add(120_000)
                    .ok_or_else(|| error("clock_overflow"))?,
                coverage: "registered_and_selected_roots",
                copy_roots: roots.iter().map(root_record).collect(),
                spotlight: Vec::new(),
                issues: Vec::new(),
                warning: "No installed copy observed within bounded coverage is not proof of ownership. Unregistered apps or writers may be missed. Names and mtime do not prove data is dispensable. A path may be replaced after the last check; directory members are not frozen. Trash does not guarantee restoration or free space.",
                candidates: Vec::new(),
            },
            captured,
            created,
            home,
            library,
            roots,
            trash,
            bundles: Vec::new(),
            candidates: Vec::new(),
            config,
            policy,
            cancellation,
            last_wall: std::cell::Cell::new(created),
            wall_deadline: std::cell::Cell::new(None),
            launch_snapshot,
            entries_remaining: std::cell::Cell::new(10_000),
            moved_targets: std::cell::RefCell::new(Vec::new()),
        };
        session.bundles = session.trash_bundles(deadline)?;
        let mut locations = BTreeSet::new();
        let mut discovered = 0;
        for rule in Rule::ALL.into_iter().filter(|r| *r != Rule::Containers) {
            let (parent, suffix) = rule.location();
            let directory = session.home.join("Library").join(parent);
            if absent_without_links(&directory)? {
                continue;
            }
            let witness = orphans::exact(&directory)?;
            for e in std::fs::read_dir(&directory)? {
                discovered += 1;
                observation::consume(&session.entries_remaining)?;
                session.budget(deadline)?;
                if discovered > 10_000 || locations.len() >= 256 {
                    return Err(error("discovery_incomplete"));
                }
                let e = e?;
                let name = e.file_name();
                let Some(name) = name.to_str() else { continue };
                let Some(id) = name
                    .strip_suffix(suffix)
                    .filter(|s| related::valid_bundle_id(s))
                else {
                    continue;
                };
                // Separate HTTP file and directory shapes, never suffix reinterpretation.
                if rule == Rule::HttpStorages && name.ends_with(".binarycookies") {
                    continue;
                }
                if !locations.insert((e.path(), rule.key().to_owned())) {
                    continue;
                }
                let matches: Vec<_> = session.bundles.iter().filter(|b| b.id == id).collect();
                if matches.len() > 8 {
                    return Err(error("trash_evidence_truncated"));
                }
                let tier = if matches.is_empty() {
                    "name_only"
                } else {
                    "trashed_bundle"
                };
                let mut refusals = Vec::new();
                if !ORPHAN_NATIVE_ACCEPTANCE_RECORDED {
                    refusals.push("native_acceptance_pending".into());
                }
                if !shared::rule_evidenced(rule) {
                    refusals.push("rule_evidence_unavailable".into());
                }
                if shared::DENIED.iter().any(|p| id.starts_with(p))
                    || app_uninstall::vendor_uninstaller_for_id(id).is_some()
                {
                    refusals.push("protected_owner".into());
                }
                let sensitive = shared::SENSITIVE.iter().any(|p| id.starts_with(p));
                if tier == "name_only" && (rule != Rule::Caches || sensitive) {
                    refusals.push("name_only_read_only".into());
                }
                let candidate =
                    OrphanTrashCandidate::capture(rule, id, &session.policy.effective_exclusions)
                        .map_err(|e| {
                            refusals.push(format!("admission_refused: {e}"));
                            e
                        })
                        .ok();
                let path = e.path();
                if let Err(e) = session.policy_guard(&path, None) {
                    refusals.push(e.to_string());
                }
                let latest = if tier == "name_only" && rule == Rule::Caches {
                    match orphans::latest_mtime(&path) {
                        Ok(t) => {
                            if !old_enough(t, SystemTime::now()) {
                                refusals.push("recently_modified".into());
                            }
                            Some(t)
                        }
                        Err(e) => {
                            refusals.push(format!("inactivity_unknown: {e}"));
                            None
                        }
                    }
                } else {
                    None
                };
                let measured = if rule.is_file() {
                    candidate.as_ref().map(|n| n.info().logical_bytes)
                } else {
                    shared::measure_size(&path, Instant::now()).ok()
                };
                let item_id = hash(format!(
                    "{captured:?}:{created}:{:?}:{}",
                    candidate
                        .as_ref()
                        .map(|c| (c.info().device, c.info().inode)),
                    path.display()
                ));
                let mut consequence = shared::consequence(rule).to_owned();
                if sensitive {
                    consequence.push_str(" Sensitive app: local vault/authentication data may be lost. Verify your recovery method.");
                }
                let binding = Binding {
                    item_id,
                    bundle_id: id.to_owned(),
                    tier: tier.into(),
                    rule_id: shared::rule_id(rule),
                    rule_version: 1,
                    path: NativePath::from_path(&path),
                    kind: if rule.is_file() { "file" } else { "directory" }.into(),
                    consequence,
                    measured_logical_bytes: measured,
                    trashed_bundles: if matches.is_empty() {
                        None
                    } else {
                        Some(
                            matches
                                .iter()
                                .map(|b| trash_record(b, &session.trash))
                                .collect(),
                        )
                    },
                };
                session.preview.candidates.push(CandidatePreview {
                    binding,
                    ownership_basis: "bundle_id_convention",
                    execution_supported: false,
                    default_selected: false,
                    refusals,
                    latest_mtime_unix_ms: latest
                        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                        .and_then(|d| d.as_millis().try_into().ok()),
                });
                session.candidates.push(Candidate {
                    rule,
                    path,
                    native: candidate,
                });
            }
            witness.revalidate()?;
        }
        let inventory =
            observation::inventory(&session.roots, deadline, &session.entries_remaining)?;
        let mut groups = BTreeMap::<String, Vec<usize>>::new();
        for (i, row) in session.preview.candidates.iter().enumerate() {
            groups
                .entry(row.binding.bundle_id.clone())
                .or_default()
                .push(i);
        }
        let mut summaries = BTreeMap::new();
        for indices in groups.values() {
            match session.observe_with_inventory(indices, deadline, None, Some(&inventory)) {
                Ok(rows) => {
                    for row in rows {
                        summaries.insert(row.bundle_id.clone(), row);
                    }
                }
                Err(e) => {
                    for &i in indices {
                        session.preview.candidates[i].refusals.push(e.to_string());
                    }
                }
            }
        }
        session.preview.spotlight = summaries.into_values().collect();
        if let Err(e) = session.budget(deadline) {
            session.preview.issues.push(e.to_string());
        }
        if session.entries_remaining.get() == 0 {
            session
                .preview
                .issues
                .push("discovery_entry_budget_exhausted".into());
        }
        session.preview.complete = session.preview.issues.is_empty();
        for row in &mut session.preview.candidates {
            if !session.preview.complete {
                row.refusals.push("preview_incomplete".into());
            }
            row.execution_supported = row.refusals.is_empty();
            row.default_selected = row.execution_supported
                && row.binding.tier == "trashed_bundle"
                && !shared::SENSITIVE
                    .iter()
                    .any(|p| row.binding.bundle_id.starts_with(p))
                && matches!(
                    row.binding.rule_id.as_str(),
                    "org.apple.library.caches.bundle_id_convention.v1"
                        | "org.apple.library.logs.bundle_id_convention.v1"
                        | "org.apple.library.saved_state.bundle_id_convention.v1"
                );
        }
        session.preview.plan_digest = hash(format!(
            "{}:{:?}:{:?}",
            serde_json::to_string(&session.preview)?,
            session.library.identity(),
            session.policy
        ));
        Ok(session)
    }
    pub fn preview(&self) -> &Preview {
        &self.preview
    }
    pub fn default_state_directory(&self) -> PathBuf {
        self.home
            .join("Library/Application Support/SayakaLeftoversJournal")
    }
    fn budget(&self, deadline: Instant) -> io::Result<()> {
        if self.cancellation.is_cancelled() {
            return Err(error("cancelled"));
        }
        if Instant::now() >= deadline {
            return Err(error("observation_timeout"));
        }
        let now = journal::now_ms()?;
        if now < self.last_wall.get() {
            return Err(error("clock_rollback"));
        }
        if self.wall_deadline.get().is_some_and(|d| now >= d) {
            return Err(error("approval_expired"));
        }
        self.last_wall.set(now);
        Ok(())
    }
    fn policy_guard(&self, path: &Path, state: Option<&Path>) -> io::Result<()> {
        clean_policy::guard_all(&self.config, &self.policy)?;
        disjoint(path, &self.config.directory)?;
        for p in &self.policy.effective_exclusions {
            disjoint(path, p)?;
        }
        for p in self.history_roots() {
            disjoint(path, &p)?;
        }
        if let Some(state) = state {
            disjoint(path, state)?;
        }
        Ok(())
    }
    fn history_roots(&self) -> Vec<PathBuf> {
        let base = self.home.join("Library/Application Support");
        vec![
            base.join("Sayaka"),
            base.join("SayakaCleaner/UninstallJournal"),
            base.join("SayakaCleaner Direct/UninstallJournal"),
        ]
    }
    fn trash_bundles(&self, deadline: Instant) -> io::Result<Vec<Bundle>> {
        self.trash.revalidate()?;
        let mut paths = BTreeSet::new();
        let mut count = 0;
        for e in std::fs::read_dir(self.trash.path())? {
            count += 1;
            observation::consume(&self.entries_remaining)?;
            self.budget(deadline)?;
            if count > 10_000 {
                return Err(error("trash_inventory_incomplete"));
            }
            let p = e?.path();
            if let Some(moved) = self.moved_targets.borrow().iter().find(|w| w.path() == p) {
                moved.revalidate()?;
                continue;
            }
            if p.extension().is_some_and(|e| e == "app") {
                paths.insert(p);
            }
        }
        for root in self.history_roots() {
            if absent_without_links(&root)? {
                continue;
            }
            let records = Store::open(&root, false)?.records()?;
            if !records.uncommitted_snapshots.is_empty() {
                return Err(error("history_locator_incomplete"));
            }
            for record in records.records {
                self.budget(deadline)?;
                if !matches!(record.schema_version, 4 | 8) {
                    continue;
                }
                for item in record.items {
                    if let Some(dest) = item.destination {
                        count += 1;
                        observation::consume(&self.entries_remaining)?;
                        if count > 10_000 {
                            return Err(error("trash_locator_limit"));
                        }
                        let p = native(&dest);
                        if p.starts_with(self.trash.path())
                            && p.extension().is_some_and(|e| e == "app")
                            && !absent_without_links(&p)?
                        {
                            paths.insert(p);
                        }
                    }
                }
            }
        }
        let mut bundles = Vec::new();
        for path in paths {
            self.budget(deadline)?;
            orphans::in_trash(&self.trash, &path)?;
            bundles.push(Bundle::capture(&path)?);
        }
        self.trash.revalidate()?;
        Ok(bundles)
    }
    fn observe(
        &self,
        selected: &[usize],
        deadline: Instant,
        state: Option<&Path>,
    ) -> io::Result<Vec<wire::SpotlightRecord>> {
        self.entries_remaining.set(10_000);
        self.observe_with_inventory(selected, deadline, state, None)
    }
    fn observe_with_inventory(
        &self,
        selected: &[usize],
        deadline: Instant,
        state: Option<&Path>,
        cached: Option<&[Bundle]>,
    ) -> io::Result<Vec<wire::SpotlightRecord>> {
        self.budget(deadline)?;
        self.library.revalidate()?;
        self.trash.revalidate()?;
        if cached.is_none() {
            let fresh = self.trash_bundles(deadline)?;
            let signature = |b: &Bundle| {
                (
                    b.path.clone(),
                    b.id.clone(),
                    b.bundle.identity(),
                    b.manifest.identity(),
                    b.digest,
                )
            };
            if fresh.iter().map(signature).collect::<Vec<_>>()
                != self.bundles.iter().map(signature).collect::<Vec<_>>()
            {
                return Err(error("resource_changed: trash evidence"));
            }
        }
        for b in &self.bundles {
            b.revalidate()?;
        }
        let owned;
        let inventory = if let Some(cached) = cached {
            cached
        } else {
            owned = observation::inventory(&self.roots, deadline, &self.entries_remaining)?;
            &owned
        };
        let mut queries = BTreeMap::<String, bool>::new();
        for &i in selected {
            let row = &self.preview.candidates[i];
            let id = &row.binding.bundle_id;
            queries.insert(id.clone(), true);
            for (offset, _) in id.match_indices('.') {
                queries.entry(id[..offset].to_owned()).or_insert(false);
            }
            if inventory
                .iter()
                .any(|b| id.starts_with(&format!("{}.", b.id)))
            {
                return Err(error("installed_family_member"));
            }
        }
        let mut summary = Vec::new();
        for (id, direct) in queries {
            let copies = observation::copies(&id, inventory, deadline, &self.entries_remaining)?;
            for p in &copies.paths {
                let matching = self.bundles.iter().find(|b| b.path == *p && b.id == id);
                if let Some(b) = matching {
                    orphans::in_trash(&self.trash, p)?;
                    b.revalidate()?;
                } else {
                    return Err(error(if direct {
                        "installed_copy_present"
                    } else {
                        "installed_family_member"
                    }));
                }
            }
            summary.push(wire::SpotlightRecord {
                bundle_id: id,
                scope: "local_computer".into(),
                status: "complete".into(),
                result_count: copies.spotlight.len(),
                verified_trash_count: copies.spotlight.len(),
                stale_registrations: copies
                    .stale
                    .iter()
                    .map(|p| NativePath::from_path(p))
                    .collect(),
            });
        }
        let processes = related::executable_paths()?;
        for &i in selected {
            let row = &self.preview.candidates[i];
            let c = &self.candidates[i];
            self.policy_guard(&c.path, state)?;
            c.native
                .as_ref()
                .ok_or_else(|| error("native_candidate_missing"))?
                .revalidate()?;
            if related::bundle_id_running(&row.binding.bundle_id)? {
                return Err(error("running"));
            }
            let physical = observation::live_path(&orphans::exact(&c.path)?.physical_path()?);
            for executable in &processes {
                let executable = observation::live_path(executable);
                if executable.starts_with(&c.path) || executable.starts_with(&physical) {
                    return Err(error("running"));
                }
                for b in self
                    .bundles
                    .iter()
                    .filter(|b| b.id == row.binding.bundle_id)
                {
                    if executable.starts_with(&b.path)
                        || executable
                            .starts_with(observation::live_path(&b.bundle.physical_path()?))
                    {
                        return Err(error("running"));
                    }
                }
            }
            self.launch_agents(&row.binding.bundle_id, &c.path, deadline)?;
            if row.binding.tier == "name_only"
                && c.rule == Rule::Caches
                && !old_enough(orphans::latest_mtime(&c.path)?, SystemTime::now())
            {
                return Err(error("recently_modified"));
            }
        }
        self.budget(deadline)?;
        Ok(summary)
    }
    fn launch_agents(&self, id: &str, candidate: &Path, deadline: Instant) -> io::Result<()> {
        self.budget(deadline)?;
        self.launch_snapshot.revalidate(&self.home, deadline)?;
        let physical = shared::physical_location(candidate)?;
        for entry in &self.launch_snapshot.entries {
            for (field, program) in &entry.fields {
                if field == id || field.starts_with(&format!("{id}.")) {
                    return Err(error("launch_agent_reference"));
                }
                if *program {
                    let path = Path::new(field);
                    if !path.is_absolute() {
                        return Err(error("launch_agent_path_unknown"));
                    }
                    if path.starts_with(candidate)
                        || shared::physical_location(path)?.starts_with(&physical)
                    {
                        return Err(error("launch_agent_reference"));
                    }
                }
            }
        }
        self.budget(deadline)
    }

    pub fn begin(
        self,
        ids: &[String],
        digest: &str,
        token: &str,
        state: &Path,
    ) -> io::Result<OrphanOperation> {
        if !ORPHAN_NATIVE_ACCEPTANCE_RECORDED {
            return Err(error("native_acceptance_pending"));
        }
        if ids.is_empty()
            || ids.len() > 32
            || digest != self.preview.plan_digest
            || token != format!("trash {} leftovers", ids.len())
            || !self.preview.complete
        {
            return Err(error("invalid_approval"));
        }
        let now = journal::now_ms()?;
        if self.captured.elapsed() >= TTL
            || now < self.created
            || now >= self.preview.expires_unix_ms
        {
            return Err(error("approval_expired"));
        }
        let mut unique = HashSet::new();
        let mut selected: Vec<usize> = Vec::new();
        for id in ids {
            if !unique.insert(id) {
                return Err(error("duplicate_item_id"));
            }
            let i = self
                .preview
                .candidates
                .iter()
                .position(|c| c.binding.item_id == *id && c.execution_supported)
                .ok_or_else(|| error("invalid_item_id"))?;
            for &other in &selected {
                disjoint(&self.candidates[i].path, &self.candidates[other].path)?;
            }
            selected.push(i);
        }
        let deadline = Instant::now() + TTL;
        self.wall_deadline.set(Some(
            now.checked_add(120_000)
                .ok_or_else(|| error("clock_overflow"))?,
        ));
        let spotlight = self.observe(
            &selected,
            deadline.min(Instant::now() + Duration::from_secs(30)),
            Some(state),
        )?;
        if self.captured.elapsed() >= TTL || journal::now_ms()? >= self.preview.expires_unix_ms {
            return Err(error("approval_expired"));
        }
        // A Store root cannot contain another contract's Store: its reader
        // intentionally rejects unknown entries. Validate before mkdir/lock.
        for root in self.history_roots() {
            disjoint(state, &root)?;
        }
        self.budget(deadline)?;
        let store = Store::open(state, true)?;
        let history = store.records()?;
        if !history.uncommitted_snapshots.is_empty()
            || history.records.iter().any(|r| r.schema_version != 9)
        {
            return Err(error("leftovers_history_requires_schema_9"));
        }
        let state_witness = orphans::exact(state)?;
        for &i in &selected {
            self.policy_guard(&self.candidates[i].path, Some(state))?;
        }
        let record = Record {
            schema_version: 9,
            plan_schema_version: 9,
            engine_version: 1,
            rules_version: 1,
            operation_id: store.new_id()?,
            contract: CONTRACT.into(),
            scope: NativePath::from_path(&self.home.join("Library")),
            created_unix_ms: now,
            clean_policy: None,
            tool_operation: None,
            related_context: None,
            delegation: None,
            orphan_context: Some(wire::Context {
                schema_version: 1,
                home: NativePath::from_path(&self.home),
                library_device: self.library.identity().0,
                library_inode: self.library.identity().1,
                copy_roots: self.preview.copy_roots.clone(),
                coverage: self.preview.coverage.into(),
                spotlight,
                policy_digest: hash(format!("{:?}", self.policy)),
                plan_digest: digest.into(),
                approved_unix_ms: now,
                deadline_unix_ms: now
                    .checked_add(120_000)
                    .ok_or_else(|| error("clock_overflow"))?,
                selected: selected
                    .iter()
                    .map(|&i| self.preview.candidates[i].binding.clone())
                    .collect(),
            }),
            items: selected
                .iter()
                .map(|&i| {
                    shared::item(
                        &self.candidates[i].path,
                        self.candidates[i].native.as_ref().unwrap().info(),
                        now,
                    )
                })
                .collect(),
        };
        store.publish(&record, true)?.require_clean()?;
        Ok(OrphanOperation {
            session: self,
            selected,
            store,
            state_witness,
            deadline,
            report: ExecutionReport {
                record,
                journal_error: None,
            },
        })
    }
}
pub struct OrphanOperation {
    session: OrphanSession,
    selected: Vec<usize>,
    store: Store,
    state_witness: PathWitness,
    deadline: Instant,
    report: ExecutionReport,
}
impl OrphanOperation {
    pub fn execute(mut self) -> ExecutionReport {
        let mut latch: Option<String> = None;
        for (position, &index) in self.selected.iter().enumerate() {
            let remaining = &self.selected[position..];
            let check = || {
                self.state_witness.revalidate()?;
                self.session.observe(
                    remaining,
                    self.deadline.min(Instant::now() + Duration::from_secs(30)),
                    Some(self.state_witness.path()),
                )?;
                Ok::<(), io::Error>(())
            };
            if latch.is_none() {
                if let Err(e) = check() {
                    latch = Some(e.to_string());
                }
            }
            if let Some(reason) = &latch {
                shared::skip(&mut self.report.record.items[position], reason);
                if shared::publish(&self.store, &mut self.report).is_err() {
                    break;
                }
                continue;
            }
            self.report.record.items[position].state = ItemState::Started;
            self.report.record.items[position].reason = Some("native_call_started".into());
            if shared::publish(&self.store, &mut self.report).is_err() {
                break;
            }
            let candidate = self.session.candidates[index].native.as_ref().unwrap();
            let outcome = candidate.move_to_trash_with_last_guard(
                || self.session.cancellation.is_cancelled(),
                || match check() {
                    Ok(()) => NativeLastGuard::Proceed,
                    Err(e) => {
                        latch = Some(e.to_string());
                        NativeLastGuard::PolicyRefused(e.to_string())
                    }
                },
            );
            // The native outcome has verified the destination identity. Keep
            // that identity so a moved cache named *.app is not reinterpreted
            // as newly discovered application evidence on the next item.
            if let platform::NativeTrashOutcome::Moved { destination } = &outcome {
                match orphans::exact(destination) {
                    Ok(witness)
                        if witness.identity()
                            == (candidate.info().device, candidate.info().inode) =>
                    {
                        self.session.moved_targets.borrow_mut().push(witness);
                    }
                    _ => latch = Some("resource_changed: moved target".into()),
                }
            }
            shared::apply(&mut self.report.record.items[position], outcome);
            if shared::publish(&self.store, &mut self.report).is_err() {
                break;
            }
        }
        for item in &mut self.report.record.items {
            if item.state == ItemState::Planned {
                shared::skip(item, "journal_unavailable");
            }
            if item.state == ItemState::Started {
                item.state = ItemState::Unknown;
                item.reason = Some("journal_publication_uncertain".into());
            }
        }
        self.report
    }
}
struct LaunchEntry {
    witness: PathWitness,
    digest: String,
    fields: Vec<(String, bool)>,
}
struct LaunchSnapshot {
    root: Root,
    entries: Vec<LaunchEntry>,
}
impl LaunchSnapshot {
    fn capture(home: &Path, deadline: Instant) -> io::Result<Self> {
        let limit = deadline.min(Instant::now() + Duration::from_secs(2));
        let root = Root::capture(home.join("Library/LaunchAgents"), true)?;
        let mut entries = Vec::new();
        let mut bytes_read = 0usize;
        if !root.absent {
            let mut paths = Vec::new();
            for (n, entry) in std::fs::read_dir(&root.path)?.enumerate() {
                if n >= 1024 || Instant::now() >= limit {
                    return Err(error("launch_agent_unknown"));
                }
                let path = entry?.path();
                if path.extension().is_some_and(|e| e == "plist") {
                    paths.push(path);
                }
            }
            paths.sort();
            for path in paths {
                if Instant::now() >= limit {
                    return Err(error("launch_agent_unknown"));
                }
                let witness = orphans::exact(&path)?;
                let (fields, bytes) = orphans::launch_agent_document(&path)?;
                bytes_read = bytes_read
                    .checked_add(bytes.len())
                    .ok_or_else(|| error("launch_agent_limit"))?;
                if bytes_read > 16 * 1024 * 1024 {
                    return Err(error("launch_agent_limit"));
                }
                witness.revalidate()?;
                entries.push(LaunchEntry {
                    witness,
                    digest: hash(bytes),
                    fields,
                });
            }
        }
        root.revalidate()?;
        if Instant::now() >= limit {
            return Err(error("launch_agent_unknown"));
        }
        Ok(Self { root, entries })
    }
    fn revalidate(&self, home: &Path, deadline: Instant) -> io::Result<()> {
        self.root.revalidate()?;
        for entry in &self.entries {
            entry.witness.revalidate()?;
        }
        let fresh = Self::capture(home, deadline)?;
        if fresh.root.absent != self.root.absent
            || fresh.root.witness.identity() != self.root.witness.identity()
            || fresh.entries.len() != self.entries.len()
            || fresh.entries.iter().zip(&self.entries).any(|(a, b)| {
                a.witness.path() != b.witness.path()
                    || a.witness.identity() != b.witness.identity()
                    || a.digest != b.digest
            })
        {
            return Err(error("resource_changed: LaunchAgents"));
        }
        self.root.revalidate()?;
        for entry in &self.entries {
            entry.witness.revalidate()?;
        }
        Ok(())
    }
}

fn root_record(root: &Root) -> wire::RootRecord {
    wire::RootRecord {
        path: NativePath::from_path(&root.path),
        state: if root.absent { "absent" } else { "present" }.into(),
        device: root.witness.identity().0,
        inode: root.witness.identity().1,
    }
}
fn trash_record(bundle: &Bundle, root: &PathWitness) -> wire::TrashedBundle {
    wire::TrashedBundle {
        path: NativePath::from_path(&bundle.path),
        device: bundle.bundle.identity().0,
        inode: bundle.bundle.identity().1,
        manifest_device: bundle.manifest.identity().0,
        manifest_inode: bundle.manifest.identity().1,
        manifest_digest: bundle.digest.iter().map(|b| format!("{b:02x}")).collect(),
        trash_root: NativePath::from_path(root.path()),
        trash_device: root.identity().0,
        trash_inode: root.identity().1,
    }
}
fn old_enough(modified: SystemTime, now: SystemTime) -> bool {
    now.duration_since(modified).is_ok_and(|d| d >= AGE)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inactivity_boundaries_fail_closed() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100 * 86400);
        assert!(old_enough(now - AGE, now));
        assert!(!old_enough(now - AGE + Duration::from_secs(1), now));
        assert!(!old_enough(now + Duration::from_secs(1), now));
    }
    #[test]
    fn gate_cannot_be_supplied_by_caller() {
        assert!(!ORPHAN_NATIVE_ACCEPTANCE_RECORDED);
    }
}
