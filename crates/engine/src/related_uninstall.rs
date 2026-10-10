// SPDX-License-Identifier: MPL-2.0

//! Same-session bundle-first related-data coordinator. Serialized previews and
//! journals are audit data, never authority to manufacture a native candidate.
use crate::app_inventory::{StringState, read_bundle_identifier_with_digest};
use crate::app_uninstall::{self, UninstallPreview};
use crate::clean_policy::{self, ConfigPath, GlobalPolicySnapshot};
use crate::execute::ExecutionReport;
use crate::journal::{
    self, ItemRecord, ItemState, NativePath, Publication, Record, RelatedContext,
    RelatedItemBinding, Store,
};
use crate::model::{Cancellation, ExecutionContract};
use platform::related::{self, PathWitness, Rule};
use sayaka_platform_macos::{
    self as platform, AdminBundleEvidence, BundleTrashCandidate, NativeFileInfo, NativeLastGuard,
    NativeTrashOutcome, RelatedTrashCandidate,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const TTL: Duration = Duration::from_secs(120);
const BUDGET: Duration = Duration::from_secs(5);
/// Release gate: change only in an independently reviewed PR attaching the
/// owner-run native acceptance evidence required by the approved contract.
/// Not configurable by callers, environment, an approval token or imported JSON.
pub const NATIVE_ACCEPTANCE_RECORDED: bool = false;
const COVERAGE: &str = "registered_and_selected_roots";
const DENIED: &[&str] = &[
    "com.apple.",
    "group.",
    "com.crowdstrike.",
    "com.sentinelone.",
    "com.sentinel-labs.",
    "com.eset.",
    "com.jamf.",
    "com.jamfsoftware.",
    "com.paloaltonetworks.",
    "com.cisco.anyconnect",
    "com.cisco.secureclient",
];
const SENSITIVE: &[&str] = &[
    "com.1password.",
    "com.agilebits.",
    "com.lastpass.",
    "com.dashlane.",
    "com.bitwarden.",
    "com.keepassx.",
    "org.keepassx.",
    "org.keepassxc.",
    "com.authy.",
    "com.yubico.",
];

fn error(reason: impl Into<String>) -> io::Error {
    io::Error::other(reason.into())
}
fn digest(bytes: impl AsRef<[u8]>) -> String {
    Sha256::digest(bytes.as_ref())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn overlap(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}
fn rule_id(rule: Rule) -> String {
    format!("org.apple.library.{}.bundle_id_convention.v1", rule.key())
}
fn rule_evidenced(rule: Rule) -> bool {
    // Exact Apple-published paths. Other proposed rows stay read-only pending
    // their exact-leaf evidence/OS acceptance; no widening by basename alone.
    matches!(
        rule,
        Rule::Caches | Rule::ApplicationSupport | Rule::Preferences
    )
}
fn consequence(rule: Rule) -> &'static str {
    match rule {
        Rule::Caches => "Cached data may need to be downloaded or rebuilt.",
        Rule::Logs => "Diagnostic history will be lost and cannot be regenerated.",
        Rule::SavedState => "Window restoration and unsaved resume context may be lost.",
        Rule::HttpStorages | Rule::HttpCookies | Rule::Cookies => {
            "Cookies and login sessions may be lost; you may need to sign in again."
        }
        Rule::WebKit => "Persistent website data, offline content and login sessions may be lost.",
        Rule::Preferences => {
            "Settings may reset. System services may recreate the preferences file."
        }
        Rule::ApplicationSupport => {
            "App data may include the only copy of documents, profiles or databases."
        }
        Rule::Containers => {
            "All sandbox app data, including documents and settings, may be lost. macOS may require permission."
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct CandidatePreview {
    pub item_id: String,
    pub path: NativePath,
    pub rule_id: String,
    pub rule_version: u32,
    pub kind: &'static str,
    pub role: &'static str,
    pub ownership_basis: &'static str,
    pub consequence: String,
    pub logical_bytes: Option<u64>,
    pub size_complete: bool,
    pub execution_supported: bool,
    pub default_selected: bool,
    pub refusals: Vec<String>,
    pub device: Option<u64>,
    pub inode: Option<u64>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Preview {
    pub kind: &'static str,
    pub schema_version: u32,
    pub complete: bool,
    pub effects_performed: bool,
    pub bundle_path: NativePath,
    pub bundle_id: String,
    pub plan_digest: String,
    pub expires_unix_ms: u64,
    pub coverage: &'static str,
    pub app_roots: Vec<NativePath>,
    pub issues: Vec<String>,
    pub copy_issues: Vec<String>,
    pub warning: &'static str,
    pub candidates: Vec<CandidatePreview>,
}
struct Candidate {
    rule: Rule,
    path: PathBuf,
    native: Option<RelatedTrashCandidate>,
}
struct Root {
    path: PathBuf,
    witness: Option<PathWitness>,
}

/// No public constructor for approved effects or detached related execution.
pub struct RelatedUninstallSession {
    preview: Preview,
    captured: Instant,
    bundle: PathBuf,
    bundle_witness: PathWitness,
    manifest_witness: PathWitness,
    manifest_digest: String,
    home: PathBuf,
    library: PathWitness,
    roots: Vec<Root>,
    candidates: Vec<Candidate>,
    config: ConfigPath,
    policy: GlobalPolicySnapshot,
    ordinary: Option<BundleTrashCandidate>,
    admin: Option<AdminBundleEvidence>,
    cancellation: Cancellation,
    copy_issues: std::cell::RefCell<Vec<String>>,
}

impl RelatedUninstallSession {
    pub fn prepare(
        retained: &UninstallPreview,
        extra_roots: &[PathBuf],
        policy_dir: &Path,
        cancellation: Cancellation,
    ) -> io::Result<Self> {
        let captured = Instant::now();
        if extra_roots.len() > 8 {
            return Err(error("too_many_app_roots"));
        }
        let bundle = retained.bundle_path.clone();
        let bundle_witness = PathWitness::capture(&bundle)?;
        let expected = retained
            .identity
            .as_ref()
            .ok_or_else(|| error("bundle_identity_missing"))?;
        if bundle_witness.identity() != (expected.device, expected.inode) {
            return Err(error("resource_changed"));
        }
        let manifest_witness = PathWitness::capture(&bundle.join("Contents/Info.plist"))?;
        let (id, manifest_hash, device, inode) =
            read_bundle_identifier_with_digest(&bundle).map_err(error)?;
        let id = id
            .value
            .filter(|_| id.state == StringState::Present)
            .filter(|id| related::valid_bundle_id(id))
            .ok_or_else(|| error("invalid_bundle_id"))?;
        if manifest_witness.identity() != (device, inode) {
            return Err(error("resource_changed"));
        }
        let home = platform::effective_account_home()?;
        let library = PathWitness::capture(&home.join("Library"))?;
        let config = clean_policy::resolve_config_path(Some(policy_dir))?;
        let policy = clean_policy::snapshot_all(&config)?;
        let fresh = app_uninstall::preview_bundle_uninstall(&bundle);
        let mut issues = Vec::new();
        if fresh.refusals.iter().any(|r| {
            !matches!(
                r.code,
                app_uninstall::UninstallRefusalCode::TrashPlanUnavailable
            )
        }) {
            issues.push("bundle_ineligible".into());
        }
        if DENIED.iter().any(|prefix| id.starts_with(prefix)) || fresh.vendor_uninstaller.is_some()
        {
            issues.push("owner_protected".into());
        }
        let ordinary = BundleTrashCandidate::capture(
            bundle
                .parent()
                .ok_or_else(|| error("bundle_parent_missing"))?,
            &bundle,
            &[],
        )
        .ok();
        let admin = if ordinary.is_none() {
            crate::admin_uninstall::admin_evidence(&fresh)
        } else {
            None
        };
        if ordinary.is_none() && admin.is_none() {
            issues.push("bundle_ineligible".into());
        }
        let mut paths = vec![
            PathBuf::from("/Applications"),
            home.join("Applications"),
            bundle
                .parent()
                .ok_or_else(|| error("bundle_parent_missing"))?
                .to_owned(),
        ];
        paths.extend_from_slice(extra_roots);
        paths.sort();
        paths.dedup();
        if paths.len() > 11 {
            return Err(error("too_many_app_roots"));
        }
        let mut roots = Vec::new();
        for path in paths {
            let witness = match PathWitness::capture(&path) {
                Ok(w) if w.is_directory() => Some(w),
                Err(e)
                    if e.kind() == io::ErrorKind::NotFound
                        && path == home.join("Applications")
                        && absent_without_links(&path)? =>
                {
                    None
                }
                _ => {
                    issues.push("copies_unknown".into());
                    None
                }
            };
            roots.push(Root { path, witness });
        }
        let mut session = Self {
            preview: Preview {
                kind: "sayaka.app_uninstall_related_preview",
                schema_version: 2,
                complete: false,
                effects_performed: false,
                bundle_path: NativePath::from_path(&bundle),
                bundle_id: id,
                plan_digest: String::new(),
                expires_unix_ms: journal::now_ms()?
                    .checked_add(120_000)
                    .ok_or_else(|| error("clock_overflow"))?,
                coverage: COVERAGE,
                app_roots: roots
                    .iter()
                    .map(|r| NativePath::from_path(&r.path))
                    .collect(),
                issues,
                copy_issues: Vec::new(),
                warning: ExecutionContract::RevalidatedRelatedTrashV1.warning(),
                candidates: Vec::new(),
            },
            captured,
            bundle,
            bundle_witness,
            manifest_witness,
            manifest_digest: digest(manifest_hash),
            home,
            library,
            roots,
            candidates: Vec::new(),
            config,
            policy,
            ordinary,
            admin,
            cancellation,
            copy_issues: std::cell::RefCell::new(Vec::new()),
        };
        if let Err(e) = session.shared_guard(None, None) {
            session.preview.issues.push(e.to_string());
        }
        let sensitive = SENSITIVE
            .iter()
            .any(|p| session.preview.bundle_id.starts_with(p));
        let measurement_start = Instant::now();
        for rule in Rule::ALL {
            let path = rule.path(&session.home, &session.preview.bundle_id)?;
            if absent_without_links(&path).unwrap_or(false) {
                continue;
            }
            let mut refusals = Vec::new();
            if !NATIVE_ACCEPTANCE_RECORDED {
                refusals.push("native_acceptance_pending".into());
            }
            if !rule_evidenced(rule) {
                refusals.push("rule_evidence_unavailable".into());
            }
            if physically_protected(&path, &session.policy.effective_exclusions).unwrap_or(true)
                || physical_overlap(&session.config.directory, &path).unwrap_or(true)
            {
                refusals.push("protected_by_user".into());
            }
            let native = match RelatedTrashCandidate::capture(rule, &session.preview.bundle_id, &[])
            {
                Ok(native) => Some(native),
                Err(e) => {
                    refusals.push(format!("admission_refused: {e}"));
                    session
                        .preview
                        .issues
                        .push("candidate_admission_incomplete".into());
                    None
                }
            };
            let info = native.as_ref().map(|n| n.info());
            let logical_bytes = if rule.is_file() {
                info.map(|i| i.logical_bytes)
            } else {
                measure_size(&path, measurement_start).ok()
            };
            let item_id = digest(format!(
                "{:?}:{:?}:{}:{}",
                session.captured,
                session.bundle_witness.identity(),
                rule.key(),
                path.display()
            ));
            let mut consequence = consequence(rule).to_owned();
            if sensitive {
                consequence.push_str(" Sensitive app: local vault or authentication data may be lost. Verify your recovery method first.");
            }
            session.preview.candidates.push(CandidatePreview {
                item_id,
                path: NativePath::from_path(&path),
                rule_id: rule_id(rule),
                rule_version: 1,
                kind: if rule.is_file() { "file" } else { "directory" },
                role: rule.key(),
                ownership_basis: "bundle_id_convention",
                consequence,
                logical_bytes,
                size_complete: logical_bytes.is_some(),
                execution_supported: false,
                default_selected: false,
                refusals,
                device: info.map(|i| i.device),
                inode: info.map(|i| i.inode),
            });
            session.candidates.push(Candidate { rule, path, native });
        }
        if let Err(e) = session.shared_guard(None, None) {
            session.preview.issues.push(e.to_string());
        }
        if captured.elapsed() > BUDGET {
            session.preview.issues.push("preview_timeout".into());
        }
        session.preview.copy_issues = session.copy_issues.borrow().clone();
        session.preview.issues.sort();
        session.preview.issues.dedup();
        session.preview.complete = session.preview.issues.is_empty();
        for (row, candidate) in session
            .preview
            .candidates
            .iter_mut()
            .zip(&session.candidates)
        {
            if !session.preview.complete {
                row.refusals.push("preview_incomplete".into());
            }
            row.execution_supported = row.refusals.is_empty();
            row.default_selected = row.execution_supported
                && !sensitive
                && matches!(candidate.rule, Rule::Caches | Rule::Logs | Rule::SavedState);
        }
        // Digest includes all serialized evidence plus private identity/policy seals.
        let root_ids: Vec<_> = session
            .roots
            .iter()
            .map(|r| r.witness.as_ref().map(PathWitness::identity))
            .collect();
        session.preview.plan_digest = digest(format!(
            "{}:{:?}:{:?}:{}:{:?}",
            serde_json::to_string(&session.preview)?,
            session.bundle_witness.identity(),
            root_ids,
            session.manifest_digest,
            session.policy
        ));
        Ok(session)
    }
    pub fn preview(&self) -> &Preview {
        &self.preview
    }
    pub fn admin_required(&self) -> bool {
        self.ordinary.is_none() && self.admin.is_some()
    }
    pub fn expected_token(&self, n: usize) -> io::Result<String> {
        Ok(format!(
            "uninstall {} and trash {n} related items",
            self.bundle
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| error("bundle_name_encoding"))?
        ))
    }
    fn check_bundle(&self) -> io::Result<()> {
        self.bundle_witness.revalidate()?;
        self.manifest_witness.revalidate()?;
        let (id, hash, _, _) = read_bundle_identifier_with_digest(&self.bundle).map_err(error)?;
        if id.value.as_deref() != Some(&self.preview.bundle_id)
            || digest(hash) != self.manifest_digest
        {
            return Err(error("resource_changed"));
        }
        if !app_uninstall::preview_bundle_uninstall(&self.bundle)
            .refusals
            .is_empty()
        {
            return Err(error("bundle_ineligible"));
        }
        Ok(())
    }
    fn shared_guard(&self, moved: Option<&Path>, deadline: Option<Instant>) -> io::Result<()> {
        let start = Instant::now();
        if self.cancellation.is_cancelled() {
            return Err(error("cancelled"));
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return Err(error("approval_expired"));
        }
        self.library.revalidate()?;
        if let Some(destination) = moved {
            let witness = PathWitness::capture(destination)?;
            if witness.identity() != self.bundle_witness.identity()
                || !absent_without_links(&self.bundle)?
            {
                return Err(error("resource_changed"));
            }
            let manifest = PathWitness::capture(&destination.join("Contents/Info.plist"))?;
            if manifest.identity() != self.manifest_witness.identity() {
                return Err(error("resource_changed"));
            }
            let (id, hash, _, _) =
                read_bundle_identifier_with_digest(destination).map_err(error)?;
            if id.value.as_deref() != Some(&self.preview.bundle_id)
                || digest(hash) != self.manifest_digest
            {
                return Err(error("resource_changed"));
            }
            witness.revalidate()?;
            manifest.revalidate()?;
        }
        clean_policy::guard_all(&self.config, &self.policy)?;
        self.observe_copies(moved, start)?;
        let paths =
            related::executable_paths().map_err(|e| error(format!("running_unknown: {e}")))?;
        if related::bundle_id_running(&self.preview.bundle_id)?
            || paths.iter().any(|p| {
                p.starts_with(&self.bundle)
                    || moved.is_some_and(|m| p.starts_with(m))
                    || self.candidates.iter().any(|c| p.starts_with(&c.path))
            })
        {
            return Err(error("running"));
        }
        if start.elapsed() > BUDGET {
            return Err(error("observation_timeout"));
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return Err(error("approval_expired"));
        }
        Ok(())
    }
    fn observe_copies(&self, moved: Option<&Path>, start: Instant) -> io::Result<()> {
        let mut seen = HashSet::new();
        let mut entries = 0usize;
        let mut apps = 0usize;
        for root in &self.roots {
            match &root.witness {
                Some(w) => w.revalidate()?,
                None if root.path == self.home.join("Applications")
                    && absent_without_links(&root.path)? =>
                {
                    continue;
                }
                None => return Err(error("copies_unknown")),
            }
            let mut stack = vec![(root.path.clone(), 0)];
            while let Some((dir, depth)) = stack.pop() {
                if depth > 32
                    || entries > 100_000
                    || apps > 4096
                    || start.elapsed() > BUDGET
                    || self.cancellation.is_cancelled()
                {
                    return Err(error("copies_unknown"));
                }
                let witness = PathWitness::capture(&dir).map_err(|_| error("copies_unknown"))?;
                if !witness.is_directory() {
                    return Err(error("copies_unknown"));
                }
                if dir.extension().is_some_and(|e| e == "app") {
                    apps += 1;
                    self.inspect_copy(&dir, moved, &mut seen)?;
                    continue;
                }
                for entry in std::fs::read_dir(&dir).map_err(|_| error("copies_unknown"))? {
                    entries += 1;
                    let entry = entry.map_err(|_| error("copies_unknown"))?;
                    let ty = entry.file_type().map_err(|_| error("copies_unknown"))?;
                    if ty.is_symlink() {
                        return Err(error("copies_unknown"));
                    }
                    if ty.is_dir() {
                        let path = entry.path();
                        if path.extension().is_some_and(|e| e == "app")
                            || !platform::is_package(&path).map_err(|_| error("copies_unknown"))?
                        {
                            stack.push((path, depth + 1));
                        }
                    }
                    if entries > 100_000 || start.elapsed() > BUDGET {
                        return Err(error("copies_unknown"));
                    }
                }
                witness.revalidate()?;
            }
        }
        for path in related::registered_applications(&self.preview.bundle_id)
            .map_err(|e| error(format!("copies_unknown: {e}")))?
        {
            if absent_without_links(&path)? {
                let message = format!(
                    "stale_registration: {}",
                    NativePath::from_path(&path).display
                );
                let mut issues = self.copy_issues.borrow_mut();
                if !issues.contains(&message) {
                    if issues.len() >= 256 {
                        return Err(error("copy_issues_truncated"));
                    }
                    issues.push(message);
                }
                continue;
            }
            self.inspect_copy(&path, moved, &mut seen)?;
        }
        if start.elapsed() > BUDGET {
            return Err(error("copies_unknown"));
        }
        Ok(())
    }
    fn inspect_copy(
        &self,
        path: &Path,
        moved: Option<&Path>,
        seen: &mut HashSet<(u64, u64)>,
    ) -> io::Result<()> {
        let witness = PathWitness::capture(path).map_err(|_| error("copies_unknown"))?;
        if !witness.is_directory() {
            return Err(error("copies_unknown"));
        }
        let (id, _, _, _) =
            read_bundle_identifier_with_digest(path).map_err(|_| error("copies_unknown"))?;
        if id.state != StringState::Present {
            return Err(error("copies_unknown"));
        }
        witness.revalidate()?;
        if id.value.as_deref() != Some(&self.preview.bundle_id) {
            return Ok(());
        }
        let identity = witness.identity();
        if !seen.insert(identity) {
            return Ok(());
        }
        if identity == self.bundle_witness.identity() {
            if moved.is_none() && path == self.bundle {
                return Ok(());
            }
            if moved == Some(path) {
                return Ok(());
            }
        }
        // Only the verified moved target is ignored. Other registered Trash
        // entries conservatively refuse until their containment is proven.
        Err(error("other_copy_present"))
    }
    /// Consume a same-preview subset, then publish both intents before effects.
    pub fn begin(
        self,
        ids: &[String],
        expected_digest: &str,
        token: &str,
        state_dir: &Path,
    ) -> io::Result<RelatedOperation> {
        if !NATIVE_ACCEPTANCE_RECORDED {
            return Err(error("native_acceptance_pending"));
        }
        if self.captured.elapsed() >= TTL || !self.preview.complete {
            return Err(error("preview_incomplete_or_expired"));
        }
        if ids.is_empty()
            || ids.len() > 32
            || self.preview.plan_digest != expected_digest
            || token != self.expected_token(ids.len())?
        {
            return Err(error("invalid_related_approval"));
        }
        let mut unique = HashSet::new();
        let mut selected = Vec::new();
        for id in ids {
            let i = self
                .preview
                .candidates
                .iter()
                .position(|c| &c.item_id == id && c.execution_supported)
                .ok_or_else(|| error("invalid_related_selection"))?;
            if !unique.insert(id) {
                return Err(error("duplicate_related_selection"));
            }
            selected.push(i);
        }
        selected.sort_unstable();
        let deadline = Instant::now() + TTL;
        self.check_bundle()?;
        self.shared_guard(None, Some(deadline))?;
        for &i in &selected {
            let target = &self.candidates[i];
            if physical_overlap(&target.path, state_dir)?
                || physical_overlap(&target.path, &self.config.directory)?
                || physically_protected(&target.path, &self.policy.effective_exclusions)?
            {
                return Err(error("protected_by_user"));
            }
            target
                .native
                .as_ref()
                .ok_or_else(|| error("native_candidate_missing"))?
                .revalidate()?;
        }
        // Last acceptance check: observation work must not extend preview validity.
        if self.captured.elapsed() >= TTL {
            return Err(error("approval_expired"));
        }
        let store = Store::open(state_dir, true)?;
        // Reserve the two-record capacity while holding the exclusive Store lock.
        if store.records()?.records.len() > journal::MAX_RECORDS - 2 {
            return Err(error("journal capacity requires two free records"));
        }
        let state_witness = PathWitness::capture(state_dir)?;
        for &i in &selected {
            if physical_overlap(state_dir, &self.candidates[i].path)? {
                return Err(error("protected_by_user"));
            }
        }
        let now = journal::now_ms()?;
        let parent_id = store.new_id()?;
        let child_id = store.new_id()?;
        let bundle_info = if let Some(n) = &self.ordinary {
            n.info().clone()
        } else {
            let a = self
                .admin
                .as_ref()
                .ok_or_else(|| error("bundle_ineligible"))?;
            NativeFileInfo {
                device: a.device,
                inode: a.inode,
                logical_bytes: a.logical_bytes,
                modified_at: std::time::SystemTime::UNIX_EPOCH,
            }
        };
        let parent = Record {
            schema_version: if self.admin_required() { 7 } else { 4 },
            plan_schema_version: if self.admin_required() { 7 } else { 4 },
            engine_version: 2,
            rules_version: 1,
            operation_id: parent_id.clone(),
            contract: if self.admin_required() {
                "system_delegated_trash_v1"
            } else {
                "revalidated_bundle_trash_v1"
            }
            .into(),
            scope: NativePath::from_path(
                self.bundle
                    .parent()
                    .ok_or_else(|| error("bundle_parent_missing"))?,
            ),
            clean_policy: None,
            tool_operation: None,
            related_context: None,
            delegation: self.admin.as_ref().map(|a| journal::DelegationRecord {
                schema_version: 1,
                performer: journal::DELEGATED_PERFORMER.into(),
                plan_digest: self.preview.plan_digest.clone(),
                manifest_device: a.manifest_device,
                manifest_inode: a.manifest_inode,
            }),
            created_unix_ms: now,
            items: vec![item(&self.bundle, &bundle_info, now)],
        };
        let child = Record {
            schema_version: 8,
            plan_schema_version: 8,
            engine_version: 2,
            rules_version: 1,
            operation_id: child_id,
            contract: ExecutionContract::RevalidatedRelatedTrashV1.as_str().into(),
            scope: NativePath::from_path(&self.home.join("Library")),
            clean_policy: None,
            tool_operation: None,
            delegation: None,
            related_context: Some(RelatedContext {
                schema_version: 1,
                parent_operation_id: parent_id,
                bundle_path: NativePath::from_path(&self.bundle),
                bundle_id: self.preview.bundle_id.clone(),
                bundle_device: bundle_info.device,
                bundle_inode: bundle_info.inode,
                manifest_device: self.manifest_witness.identity().0,
                manifest_inode: self.manifest_witness.identity().1,
                manifest_digest: self.manifest_digest.clone(),
                plan_digest: self.preview.plan_digest.clone(),
                policy_digest: digest(format!("{:?}", self.policy)),
                home: NativePath::from_path(&self.home),
                library_device: self.library.identity().0,
                library_inode: self.library.identity().1,
                copy_roots: self.preview.app_roots.clone(),
                coverage: COVERAGE.into(),
                approved_unix_ms: now,
                deadline_unix_ms: now
                    .checked_add(120_000)
                    .ok_or_else(|| error("clock_overflow"))?,
                selected: selected
                    .iter()
                    .map(|&i| {
                        let row = &self.preview.candidates[i];
                        RelatedItemBinding {
                            item_id: row.item_id.clone(),
                            rule_id: row.rule_id.clone(),
                            rule_version: 1,
                            path: row.path.clone(),
                            kind: row.kind.into(),
                            consequence: row.consequence.clone(),
                        }
                    })
                    .collect(),
            }),
            created_unix_ms: now,
            items: selected
                .iter()
                .map(|&i| {
                    let c = &self.candidates[i];
                    item(
                        &c.path,
                        c.native.as_ref().expect("approved candidate").info(),
                        now,
                    )
                })
                .collect(),
        };
        store.publish(&parent, true)?.require_clean()?;
        store.publish(&child, true)?.require_clean()?;
        Ok(RelatedOperation {
            session: self,
            store,
            state_witness,
            selected,
            deadline,
            parent: ExecutionReport {
                record: parent,
                journal_error: None,
            },
            related: ExecutionReport {
                record: child,
                journal_error: None,
            },
            delegated_started: false,
        })
    }
}

pub struct RelatedOperation {
    session: RelatedUninstallSession,
    store: Store,
    state_witness: PathWitness,
    selected: Vec<usize>,
    deadline: Instant,
    parent: ExecutionReport,
    related: ExecutionReport,
    delegated_started: bool,
}
#[derive(Debug, Serialize)]
pub struct RelatedResult {
    pub bundle: ExecutionReport,
    pub related: ExecutionReport,
}
impl RelatedResult {
    pub fn exit_code(&self) -> u8 {
        let a = self.bundle.exit_code();
        let b = self.related.exit_code();
        if a != 0 { a } else { b }
    }
}
impl RelatedOperation {
    pub fn admin_required(&self) -> bool {
        self.session.admin_required()
    }
    pub fn bundle_path(&self) -> &Path {
        &self.session.bundle
    }
    fn parent_start(&mut self) -> io::Result<()> {
        self.state_witness.revalidate()?;
        self.session.check_bundle()?;
        self.session.shared_guard(None, Some(self.deadline))?;
        if let Some(candidate) = &self.session.ordinary {
            candidate.revalidate()?;
        }
        if let Some(expected) = &self.session.admin {
            let fresh = AdminBundleEvidence::capture(&self.session.bundle)?;
            if (
                fresh.device,
                fresh.inode,
                fresh.manifest_device,
                fresh.manifest_inode,
            ) != (
                expected.device,
                expected.inode,
                expected.manifest_device,
                expected.manifest_inode,
            ) {
                return Err(error("resource_changed"));
            }
        }
        self.parent.record.items[0].state = ItemState::Started;
        self.parent.record.items[0].reason = Some("native_call_started".into());
        publish(&self.store, &mut self.parent)?;
        Ok(())
    }
    pub fn execute(mut self) -> RelatedResult {
        if self.admin_required() {
            skip(&mut self.parent.record.items[0], "administrator_required");
        } else if let Err(e) = self.parent_start() {
            skip(&mut self.parent.record.items[0], &e.to_string());
        } else {
            let candidate = self.session.ordinary.as_ref().expect("ordinary candidate");
            let outcome = candidate.move_to_trash_with_last_guard(
                || self.session.cancellation.is_cancelled(),
                || match self
                    .state_witness
                    .revalidate()
                    .and_then(|_| self.session.check_bundle())
                    .and_then(|_| self.session.shared_guard(None, Some(self.deadline)))
                {
                    Ok(()) => NativeLastGuard::Proceed,
                    Err(e) => NativeLastGuard::PolicyRefused(e.to_string()),
                },
            );
            apply(&mut self.parent.record.items[0], outcome);
        }
        let _ = publish(&self.store, &mut self.parent);
        self.finish_related()
    }
    /// Only call Finder after this returns success; no Boolean success input.
    pub fn admin_begin(&mut self) -> io::Result<()> {
        if !self.admin_required() || self.delegated_started {
            return Err(error("invalid_admin_state"));
        }
        self.parent_start()?;
        self.delegated_started = true;
        Ok(())
    }
    pub fn admin_finish(mut self, status: crate::admin_uninstall::DelegateStatus) -> RelatedResult {
        if !self.delegated_started {
            skip(&mut self.parent.record.items[0], "admin_not_started");
        } else if let Some(evidence) = &self.session.admin {
            let mut present = evidence.is_present_at(&self.session.bundle).ok();
            for _ in 0..10 {
                if present != Some(true)
                    || status != crate::admin_uninstall::DelegateStatus::Reported
                {
                    break;
                }
                std::thread::sleep(Duration::from_millis(300));
                present = evidence.is_present_at(&self.session.bundle).ok();
            }
            let dest = if present == Some(false) {
                evidence.find_in_user_trash().ok().flatten()
            } else {
                None
            };
            let (state, reason) = crate::admin_uninstall::classify(present, dest.is_some(), status);
            let item = &mut self.parent.record.items[0];
            item.state = state.clone();
            item.reason = Some(reason.into());
            item.destination = if state == ItemState::Succeeded {
                dest.as_deref().map(NativePath::from_path)
            } else {
                None
            };
        }
        let _ = publish(&self.store, &mut self.parent);
        self.finish_related()
    }
    fn finish_related(mut self) -> RelatedResult {
        let moved = self.parent.record.items[0]
            .destination
            .as_ref()
            .map(|p| native_path(p));
        let mut authority = SharedAuthority::default();
        for (position, &index) in self.selected.iter().enumerate() {
            if self.related.journal_error.is_some() {
                break;
            }
            let reason = if self.parent.journal_error.is_some()
                || self.parent.record.items[0].state != ItemState::Succeeded
            {
                Some("bundle_not_removed".to_owned())
            } else if self.session.cancellation.is_cancelled() {
                Some("cancelled".into())
            } else if Instant::now() >= self.deadline {
                Some("approval_expired".into())
            } else {
                authority
                    .check(|| {
                        self.state_witness.revalidate().and_then(|_| {
                            self.session
                                .shared_guard(moved.as_deref(), Some(self.deadline))
                        })
                    })
                    .err()
                    .map(|e| e.to_string())
            };
            if let Some(reason) = reason {
                skip(&mut self.related.record.items[position], &reason);
                let _ = publish(&self.store, &mut self.related);
                continue;
            }
            let candidate = self.session.candidates[index]
                .native
                .as_ref()
                .expect("approved candidate");
            if let Err(e) = candidate.revalidate() {
                skip(
                    &mut self.related.record.items[position],
                    &format!("resource_changed: {e}"),
                );
                let _ = publish(&self.store, &mut self.related);
                continue;
            }
            self.related.record.items[position].state = ItemState::Started;
            self.related.record.items[position].reason = Some("native_call_started".into());
            if publish(&self.store, &mut self.related).is_err() {
                break;
            }
            let outcome = candidate.move_to_trash_with_last_guard(
                || self.session.cancellation.is_cancelled(),
                || match authority.check(|| {
                    self.state_witness.revalidate().and_then(|_| {
                        self.session
                            .shared_guard(moved.as_deref(), Some(self.deadline))
                    })
                }) {
                    Ok(()) => NativeLastGuard::Proceed,
                    Err(e) => NativeLastGuard::PolicyRefused(e.to_string()),
                },
            );
            apply(&mut self.related.record.items[position], outcome);
            if publish(&self.store, &mut self.related).is_err() {
                break;
            }
        }
        for item in &mut self.related.record.items {
            if item.state == ItemState::Planned {
                skip(item, "journal_unavailable");
            } else if item.state == ItemState::Started {
                item.state = ItemState::Unknown;
                item.reason = Some("journal_publication_uncertain".into());
            }
        }
        RelatedResult {
            bundle: self.parent,
            related: self.related,
        }
    }
}
fn native_path(p: &NativePath) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;
    PathBuf::from(std::ffi::OsStr::from_bytes(&p.bytes))
}
fn item(path: &Path, info: &NativeFileInfo, now: u64) -> ItemRecord {
    ItemRecord {
        path: NativePath::from_path(path),
        device: info.device,
        inode: info.inode,
        logical_bytes: info.logical_bytes,
        state: ItemState::Planned,
        reason: None,
        destination: None,
        rule_binding: None,
        recovery_evidence: None,
        updated_unix_ms: now,
    }
}
fn skip(item: &mut ItemRecord, reason: &str) {
    item.state = ItemState::Skipped;
    item.reason = Some(reason.into());
}
fn publish(store: &Store, report: &mut ExecutionReport) -> io::Result<()> {
    let now = journal::now_ms().map_err(|e| {
        report.journal_error = Some(e.to_string());
        e
    })?;
    for item in &mut report.record.items {
        item.updated_unix_ms = now;
    }
    store
        .publish(&report.record, false)
        .and_then(Publication::require_clean)
        .map_err(|e| {
            report.journal_error = Some(e.to_string());
            e
        })
}
fn apply(item: &mut ItemRecord, outcome: NativeTrashOutcome) {
    match outcome {
        NativeTrashOutcome::Moved { destination } => {
            item.state = ItemState::Succeeded;
            item.reason = Some("moved_to_trash".into());
            item.destination = Some(NativePath::from_path(&destination));
        }
        NativeTrashOutcome::Refused(reason) => skip(item, &reason),
        NativeTrashOutcome::Failed(reason) => {
            item.state = ItemState::Failed;
            item.reason = Some(reason);
        }
        NativeTrashOutcome::Unknown { message, evidence } => {
            item.state = ItemState::Unknown;
            item.reason = Some(message);
            item.recovery_evidence = Some(journal::RecoveryEvidence {
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
            });
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
fn absent_without_links(path: &Path) -> io::Result<bool> {
    for component in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        match std::fs::symlink_metadata(component) {
            Ok(m) if m.file_type().is_symlink() => return Err(error("symlink_path")),
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(true),
            Err(e) => return Err(e),
        }
    }
    Ok(false)
}
fn measure_size(path: &Path, start: Instant) -> io::Result<u64> {
    let policy = platform::ReadOnlyPolicy::enter()?;
    let result = (|| {
        let mut total = 0u64;
        let mut count = 0usize;
        let mut stack = vec![path.to_owned()];
        while let Some(path) = stack.pop() {
            if start.elapsed() > Duration::from_secs(2) || count >= 100_000 {
                return Err(error("size_unknown"));
            }
            count += 1;
            let witness = PathWitness::capture(&path)?;
            if witness.is_directory() {
                for entry in std::fs::read_dir(&path)? {
                    stack.push(entry?.path());
                }
            } else {
                total = total
                    .checked_add(std::fs::symlink_metadata(&path)?.len())
                    .ok_or_else(|| error("size_overflow"))?;
            }
            witness.revalidate()?;
        }
        Ok(total)
    })();
    let restored = policy.restore();
    let total = result?;
    restored?;
    Ok(total)
}

#[derive(Default)]
struct SharedAuthority {
    refusal: Option<String>,
}
impl SharedAuthority {
    fn check(&mut self, observe: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
        if let Some(reason) = &self.refusal {
            return Err(error(reason.clone()));
        }
        if let Err(e) = observe() {
            self.refusal = Some(e.to_string());
            return Err(e);
        }
        Ok(())
    }
}
pub(crate) fn physical_location(path: &Path) -> io::Result<PathBuf> {
    if !path.is_absolute()
        || path.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(error("invalid_path"));
    }
    let mut existing = path.to_owned();
    let mut suffix = Vec::new();
    while absent_without_links(&existing)? {
        suffix.push(
            existing
                .file_name()
                .ok_or_else(|| error("invalid_path"))?
                .to_owned(),
        );
        existing = existing
            .parent()
            .ok_or_else(|| error("invalid_path"))?
            .to_owned();
    }
    let witness = PathWitness::capture(&existing)?;
    let mut physical = witness.physical_path()?;
    for component in suffix.into_iter().rev() {
        physical.push(component);
    }
    Ok(physical)
}
fn physical_overlap(a: &Path, b: &Path) -> io::Result<bool> {
    Ok(overlap(&physical_location(a)?, &physical_location(b)?))
}
fn physically_protected(target: &Path, excluded: &[PathBuf]) -> io::Result<bool> {
    for path in excluded {
        if physical_overlap(target, path)? {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_refusal_never_reobserves_or_resumes() {
        let mut authority = SharedAuthority::default();
        assert!(authority.check(|| Ok(())).is_ok());
        assert!(authority.check(|| Err(error("running"))).is_err());
        assert_eq!(
            authority
                .check(|| panic!("must not wait and retry a shared refusal"))
                .unwrap_err()
                .to_string(),
            "running"
        );
    }
    #[test]
    fn unrelated_names_and_sensitive_data_cannot_gain_defaults() {
        for rule in Rule::ALL {
            assert!(rule.path(Path::new("/fixture"), "../outside").is_err());
            assert!(rule.path(Path::new("/fixture"), "com/example").is_err());
        }
        assert!(!rule_evidenced(Rule::HttpStorages));
        assert!(!rule_evidenced(Rule::Containers));
        assert!(consequence(Rule::ApplicationSupport).contains("only copy"));
        assert!(DENIED.iter().any(|p| "com.apple.dt.Xcode".starts_with(p)));
        assert!(
            SENSITIVE
                .iter()
                .any(|p| "com.agilebits.onepassword7".starts_with(p))
        );
    }
    #[test]
    fn nofollow_witness_refuses_replacement_and_links() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        // Resolve only the fixture's parent; macOS /tmp can itself be an alias.
        let root = std::fs::canonicalize(temp.path()).unwrap();
        let path = root.join("original");
        std::fs::write(&path, b"fixture").unwrap();
        let witness = PathWitness::capture(&path).unwrap();
        std::fs::rename(&path, root.join("retained")).unwrap();
        std::fs::write(&path, b"replacement").unwrap();
        assert!(witness.revalidate().is_err());
        let alias = root.join("alias");
        symlink(&path, &alias).unwrap();
        assert!(PathWitness::capture(&alias).is_err());
    }
    #[test]
    fn component_overlap_does_not_confuse_sibling_names() {
        assert!(overlap(
            Path::new("/Library/id"),
            Path::new("/Library/id/journal")
        ));
        assert!(!overlap(
            Path::new("/Library/id"),
            Path::new("/Library/id-other")
        ));
    }
}
