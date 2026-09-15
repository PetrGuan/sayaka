// SPDX-License-Identifier: MPL-2.0

//! Read-only installer discovery for explicit scan roots.

use crate::model::{Cancellation, FileIdentity, ResourceKind, overlaps, valid_absolute_path};
use crate::scan::{ScanEntry, ScanIssue, ScanReport, ScanStatus};
use flate2::{Decompress, FlushDecompress, Status};
use quick_xml::Reader;
use quick_xml::events::Event;
use std::collections::{HashMap, HashSet};
#[cfg(target_os = "macos")]
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

pub const INSTALLER_PREVIEW_SCHEMA_VERSION: u32 = 1;
pub const INSTALLER_KIND: &str = "installer_preview";
pub const INSTALLER_TOTAL_BUDGET: Duration = Duration::from_secs(30);
const MIB: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallerStatus {
    Complete,
    Partial,
    Cancelled,
    Failed,
}

impl InstallerStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
        }
    }

    pub const fn exit_code(self) -> u8 {
        match self {
            Self::Complete => 0,
            Self::Partial => 3,
            Self::Cancelled => 130,
            Self::Failed => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstallerPreviewLimits {
    pub max_candidates: usize,
    pub max_dmg_footer_bytes: u64,
    pub max_pkg_toc_compressed: u64,
    pub max_pkg_toc_uncompressed: u64,
    pub max_pkg_xml_depth: usize,
    pub max_pkg_xml_nodes: usize,
    pub max_retained_name_bytes: usize,
    pub max_candidate_io_bytes: u64,
    pub max_expanded_bytes: u64,
}

impl Default for InstallerPreviewLimits {
    fn default() -> Self {
        Self {
            max_candidates: 512,
            max_dmg_footer_bytes: 512,
            max_pkg_toc_compressed: 4 * MIB,
            max_pkg_toc_uncompressed: 16 * MIB,
            max_pkg_xml_depth: 32,
            max_pkg_xml_nodes: 50_000,
            max_retained_name_bytes: 1024 * 1024,
            max_candidate_io_bytes: 64 * MIB,
            max_expanded_bytes: 128 * MIB,
        }
    }
}

impl InstallerPreviewLimits {
    pub fn validate(self) -> Result<(), String> {
        let defaults = Self::default();
        let valid = self.max_candidates > 0
            && self.max_candidates <= defaults.max_candidates
            && self.max_dmg_footer_bytes == defaults.max_dmg_footer_bytes
            && self.max_pkg_toc_compressed > 0
            && self.max_pkg_toc_compressed <= defaults.max_pkg_toc_compressed
            && self.max_pkg_toc_uncompressed > 0
            && self.max_pkg_toc_uncompressed <= defaults.max_pkg_toc_uncompressed
            && self.max_pkg_xml_depth > 0
            && self.max_pkg_xml_depth <= defaults.max_pkg_xml_depth
            && self.max_pkg_xml_nodes > 0
            && self.max_pkg_xml_nodes <= defaults.max_pkg_xml_nodes
            && self.max_retained_name_bytes > 0
            && self.max_retained_name_bytes <= defaults.max_retained_name_bytes
            && self.max_candidate_io_bytes > 0
            && self.max_candidate_io_bytes <= defaults.max_candidate_io_bytes
            && self.max_expanded_bytes > 0
            && self.max_expanded_bytes <= defaults.max_expanded_bytes;
        if valid {
            Ok(())
        } else {
            Err("invalid installer preview limits".into())
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct InstallerPreviewOptions {
    pub filter: String,
    pub excludes: Vec<PathBuf>,
    pub limits: InstallerPreviewLimits,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerScope {
    CurrentUser,
    OtherUser,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateNameKind {
    Dmg,
    Pkg,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormatFamily {
    UdifDmg,
    FlatPkgXar,
    Xar,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormatStatus {
    Recognized,
    Unsupported,
    Corrupt,
    Changed,
    PermissionDenied,
    Partial,
    Cancelled,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateFormat {
    pub family: FormatFamily,
    pub status: FormatStatus,
    pub detection_level: &'static str,
    pub evidence: Vec<&'static str>,
    pub limitations: Vec<&'static str>,
}

#[derive(Clone, Debug)]
pub struct InstallerCandidate {
    pub path: PathBuf,
    pub identity: FileIdentity,
    pub owner_scope: OwnerScope,
    pub logical_bytes: Option<u64>,
    pub allocated_bytes: Option<u64>,
    pub counted: bool,
    pub name_kind: CandidateNameKind,
    pub format: CandidateFormat,
    #[cfg(target_os = "macos")]
    inspection: Option<InspectionWitness>,
}

impl InstallerCandidate {
    /// Only a selection candidate, never permission to perform a native effect.
    pub fn selectable(&self) -> bool {
        #[cfg(target_os = "macos")]
        {
            self.inspection.as_ref().is_some_and(|witness| {
                self.path == witness.path
                    && self.identity == witness.target.identity
                    && self.logical_bytes == Some(witness.target.size)
                    && self.owner_scope == OwnerScope::CurrentUser
                    && witness.owner_scope == OwnerScope::CurrentUser
                    && witness.target.links == 1
                    && self.name_kind == witness.name_kind
                    && self.format == witness.format
                    && self.format.status == FormatStatus::Recognized
                    && matches!(
                        (self.name_kind, self.format.family),
                        (CandidateNameKind::Dmg, FormatFamily::UdifDmg)
                            | (CandidateNameKind::Pkg, FormatFamily::FlatPkgXar)
                    )
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            false
        }
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn verify_admission(
        &self,
        root: &Path,
        admission: &sayaka_platform_macos::NativeAdmissionWitness,
    ) -> std::io::Result<()> {
        let witness = self
            .inspection
            .as_ref()
            .filter(|_| self.selectable())
            .ok_or_else(|| {
                crate::journal::invalid("installer has no eligible inspection witness")
            })?;
        let mut current = root.to_path_buf();
        let ancestors_match = witness.ancestors.len() == admission.target_ancestors.len()
            && witness
                .ancestors
                .iter()
                .zip(&admission.target_ancestors)
                .all(|(before, after)| {
                    current.push(&before.name);
                    after.path == current && before.baseline.matches_native(after)
                });
        if witness.root_path != root
            || admission.root.path != root
            || admission.target.path != self.path
            || !witness.root.matches_native(&admission.root)
            || !witness.target.matches_native(&admission.target)
            || !ancestors_match
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "installer or ancestry changed after inspection; rerun preview",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallerIssueCode {
    InvalidInput,
    CandidateLimit,
    NameBytesLimit,
    IoBudgetExceeded,
    ExpandedBudgetExceeded,
    DurationLimit,
    Cancelled,
    Changed,
    PermissionDenied,
    NotFound,
    PolicyFailure,
    UnsupportedPlatform,
    Corrupt,
    Unsupported,
    ParseLimit,
    Internal,
}

impl InstallerIssueCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::CandidateLimit => "candidate_limit",
            Self::NameBytesLimit => "name_bytes_limit",
            Self::IoBudgetExceeded => "candidate_io_limit",
            Self::ExpandedBudgetExceeded => "expanded_data_limit",
            Self::DurationLimit => "duration_limit",
            Self::Cancelled => "cancelled",
            Self::Changed => "changed_entry",
            Self::PermissionDenied => "permission_denied",
            Self::NotFound => "not_found",
            Self::PolicyFailure => "policy_failure",
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::Corrupt => "corrupt_or_truncated",
            Self::Unsupported => "unsupported_or_unknown",
            Self::ParseLimit => "parse_limit",
            Self::Internal => "internal_error",
        }
    }
}

#[derive(Clone, Debug)]
pub struct InstallerIssue {
    pub path: Option<PathBuf>,
    pub code: InstallerIssueCode,
    pub message: String,
    pub os_code: Option<i32>,
}

#[derive(Clone, Debug, Default)]
pub struct InstallerCounts {
    pub scan_entries: usize,
    pub named_candidates: usize,
    pub inspected_candidates: usize,
    pub recognized: usize,
    pub unsupported: usize,
    pub corrupt: usize,
    pub changed: usize,
    pub permission_denied: usize,
    pub aliases: usize,
    pub scan_issues: usize,
    pub probe_issues: usize,
}

#[derive(Clone, Debug, Default)]
pub struct InstallerBytes {
    pub matched_logical_bytes: u64,
    pub matched_logical_unknown_files: u64,
    pub matched_allocated_bytes: u64,
    pub matched_allocated_unknown_files: u64,
}

#[derive(Clone, Debug, Default)]
pub struct InstallerMetrics {
    pub elapsed_ms: u64,
    pub probe_elapsed_ms: u64,
    pub candidate_io_bytes: u64,
    pub expanded_bytes: u64,
    pub retained_name_bytes: usize,
}

#[derive(Clone, Debug)]
pub struct InstallerPreview {
    pub schema_version: u32,
    pub kind: &'static str,
    pub platform: &'static str,
    pub status: InstallerStatus,
    pub complete: bool,
    pub effects_performed: bool,
    pub root: PathBuf,
    pub filter: String,
    pub excludes: Vec<PathBuf>,
    pub scan_task_id: String,
    pub counts: InstallerCounts,
    pub bytes: InstallerBytes,
    pub candidates: Vec<InstallerCandidate>,
    pub scan_issues: Vec<ScanIssue>,
    pub issues: Vec<InstallerIssue>,
    pub issues_omitted: usize,
    pub metrics: InstallerMetrics,
    selection_context: Option<SelectionContext>,
}

#[derive(Clone, Debug)]
struct SelectionContext {
    root: PathBuf,
    filter: String,
    excludes: Vec<PathBuf>,
}

impl InstallerPreview {
    pub fn selection_ready(&self) -> bool {
        cfg!(target_os = "macos")
            && self.schema_version == INSTALLER_PREVIEW_SCHEMA_VERSION
            && self.kind == INSTALLER_KIND
            && self.platform == "macos"
            && self.complete
            && self.issues_omitted == 0
            && self.status == InstallerStatus::Complete
            && !self.effects_performed
            && self.selection_context.as_ref().is_some_and(|context| {
                self.root == context.root
                    && self.filter == context.filter
                    && self.excludes == context.excludes
            })
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn selection_scope(&self) -> std::io::Result<crate::model::Scope> {
        if !self.selection_ready() || self.excludes.len() > crate::journal::MAX_ITEMS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "installer selection requires a complete unchanged preview and at most 32 exclusions",
            ));
        }
        crate::model::Scope::new(self.root.clone(), self.excludes.clone())
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))
    }
}

#[derive(Default)]
struct ProbeBudget {
    io_bytes: u64,
    expanded_bytes: u64,
}

impl ProbeBudget {
    fn preflight_io(&self, bytes: u64, limits: InstallerPreviewLimits) -> Result<(), PreviewError> {
        let next = self.io_bytes.checked_add(bytes).ok_or_else(|| {
            PreviewError::new(InstallerIssueCode::IoBudgetExceeded, "I/O overflow")
        })?;
        if next > limits.max_candidate_io_bytes {
            return Err(PreviewError::new(
                InstallerIssueCode::IoBudgetExceeded,
                "candidate read budget exceeded",
            ));
        }
        Ok(())
    }

    fn charge_io(
        &mut self,
        bytes: u64,
        limits: InstallerPreviewLimits,
    ) -> Result<(), PreviewError> {
        let next = self.io_bytes.checked_add(bytes).ok_or_else(|| {
            PreviewError::new(InstallerIssueCode::IoBudgetExceeded, "I/O overflow")
        })?;
        if next > limits.max_candidate_io_bytes {
            return Err(PreviewError::new(
                InstallerIssueCode::IoBudgetExceeded,
                "candidate read budget exceeded",
            ));
        }
        self.io_bytes = next;
        Ok(())
    }

    fn add_expanded(
        &mut self,
        bytes: u64,
        limits: InstallerPreviewLimits,
    ) -> Result<(), PreviewError> {
        let next = self.expanded_bytes.checked_add(bytes).ok_or_else(|| {
            PreviewError::new(
                InstallerIssueCode::ExpandedBudgetExceeded,
                "expanded-byte overflow",
            )
        })?;
        if next > limits.max_expanded_bytes {
            return Err(PreviewError::new(
                InstallerIssueCode::ExpandedBudgetExceeded,
                "expanded TOC budget exceeded",
            ));
        }
        self.expanded_bytes = next;
        Ok(())
    }

    fn remaining_expanded(&self, limits: InstallerPreviewLimits) -> u64 {
        limits
            .max_expanded_bytes
            .saturating_sub(self.expanded_bytes)
    }
}

#[derive(Debug)]
struct PreviewError {
    code: InstallerIssueCode,
    message: String,
    os_code: Option<i32>,
}

impl PreviewError {
    fn new(code: InstallerIssueCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            os_code: None,
        }
    }

    fn with_os(mut self, os_code: Option<i32>) -> Self {
        self.os_code = os_code;
        self
    }
}

#[derive(Clone, Copy)]
struct ProbeContext<'a> {
    cancellation: &'a Cancellation,
    deadline: Instant,
    limits: InstallerPreviewLimits,
}

impl ProbeContext<'_> {
    fn check(&self) -> Result<(), PreviewError> {
        if self.cancellation.is_cancelled() {
            return Err(PreviewError::new(
                InstallerIssueCode::Cancelled,
                "installer preview cancelled",
            ));
        }
        if Instant::now() >= self.deadline {
            return Err(PreviewError::new(
                InstallerIssueCode::DurationLimit,
                "installer preview time budget exhausted",
            ));
        }
        Ok(())
    }
}

pub fn preview_installers(
    report: ScanReport,
    options: &InstallerPreviewOptions,
    cancellation: &Cancellation,
    probe_budget: Duration,
) -> InstallerPreview {
    let started = Instant::now();
    let limits = options.limits;
    let root = report
        .roots
        .first()
        .cloned()
        .unwrap_or_else(|| PathBuf::from("/"));
    let mut status = match report.status {
        ScanStatus::Complete => InstallerStatus::Complete,
        ScanStatus::Partial => InstallerStatus::Partial,
        ScanStatus::Cancelled => InstallerStatus::Cancelled,
        ScanStatus::Failed => InstallerStatus::Failed,
    };
    let mut preview = InstallerPreview {
        schema_version: INSTALLER_PREVIEW_SCHEMA_VERSION,
        kind: INSTALLER_KIND,
        platform: if cfg!(target_os = "macos") {
            "macos"
        } else if cfg!(windows) {
            "windows"
        } else {
            "unsupported"
        },
        status,
        complete: matches!(status, InstallerStatus::Complete),
        effects_performed: false,
        root: root.clone(),
        filter: options.filter.clone(),
        excludes: options.excludes.clone(),
        scan_task_id: report.task_id.to_string(),
        counts: InstallerCounts {
            scan_entries: report.entries.len(),
            scan_issues: report.issues.len(),
            ..InstallerCounts::default()
        },
        bytes: InstallerBytes::default(),
        candidates: Vec::new(),
        scan_issues: report.issues.clone(),
        issues: Vec::new(),
        issues_omitted: report.issues_omitted,
        metrics: InstallerMetrics::default(),
        selection_context: None,
    };
    if let Err(message) = limits.validate() {
        preview.status = InstallerStatus::Failed;
        preview.complete = false;
        push_issue(
            &mut preview,
            InstallerIssue {
                path: None,
                code: InstallerIssueCode::InvalidInput,
                message,
                os_code: None,
            },
        );
        preview.metrics.elapsed_ms = elapsed_ms(started.elapsed());
        return preview;
    }
    let deadline = Instant::now() + probe_budget;
    let context = ProbeContext {
        cancellation,
        deadline,
        limits,
    };
    let by_path: HashMap<PathBuf, &ScanEntry> = report
        .entries
        .iter()
        .map(|entry| (entry.path.clone(), entry))
        .collect();
    let root_identities: HashMap<PathBuf, FileIdentity> = report
        .roots
        .iter()
        .filter_map(|path| {
            by_path
                .get(path)
                .filter(|entry| entry.kind == ResourceKind::Directory)
                .map(|entry| (path.clone(), entry.identity))
        })
        .collect();
    let mut retained_name_bytes = 0usize;
    let mut named = Vec::new();
    for entry in &report.entries {
        if entry.kind != ResourceKind::File || entry.dataless {
            continue;
        }
        let Some(kind) = candidate_name_kind(&entry.path) else {
            continue;
        };
        if !options.filter.is_empty() && !matches_filter(&entry.path, &options.filter) {
            continue;
        }
        if excluded(entry, &report.entries, &options.excludes) {
            continue;
        }
        preview.counts.named_candidates += 1;
        let bytes = entry.path.as_os_str().len();
        if retained_name_bytes.saturating_add(bytes) > limits.max_retained_name_bytes {
            preview.status = InstallerStatus::Partial;
            preview.complete = false;
            push_issue(
                &mut preview,
                InstallerIssue {
                    path: Some(entry.path.clone()),
                    code: InstallerIssueCode::NameBytesLimit,
                    message: "candidate name budget exceeded".into(),
                    os_code: None,
                },
            );
            break;
        }
        retained_name_bytes += bytes;
        if named.len() >= limits.max_candidates {
            preview.status = InstallerStatus::Partial;
            preview.complete = false;
            push_issue(
                &mut preview,
                InstallerIssue {
                    path: None,
                    code: InstallerIssueCode::CandidateLimit,
                    message: "candidate limit reached".into(),
                    os_code: None,
                },
            );
            break;
        }
        named.push((entry, kind));
    }
    preview.metrics.retained_name_bytes = retained_name_bytes;
    let mut accounted = HashSet::new();
    let mut probe = ProbeBudget::default();
    for (entry, name_kind) in named {
        let candidate = match inspect_candidate(
            entry,
            name_kind,
            &root_identities,
            &by_path,
            context,
            &mut probe,
        ) {
            Ok(candidate) => candidate,
            Err(error) => {
                preview.status = match error.code {
                    InstallerIssueCode::Cancelled => InstallerStatus::Cancelled,
                    InstallerIssueCode::InvalidInput | InstallerIssueCode::Internal => {
                        InstallerStatus::Failed
                    }
                    _ => InstallerStatus::Partial,
                };
                preview.complete = false;
                push_issue(
                    &mut preview,
                    InstallerIssue {
                        path: Some(entry.path.clone()),
                        code: error.code,
                        message: error.message,
                        os_code: error.os_code,
                    },
                );
                InstallerCandidate {
                    path: entry.path.clone(),
                    identity: entry.identity,
                    owner_scope: OwnerScope::Unknown,
                    logical_bytes: entry.logical_bytes,
                    allocated_bytes: entry.allocated_bytes,
                    counted: entry.counted,
                    name_kind,
                    format: format_unknown_for_error(error.code),
                    #[cfg(target_os = "macos")]
                    inspection: None,
                }
            }
        };
        if accounted.insert(candidate.identity) {
            if let Some(bytes) = candidate.logical_bytes {
                preview.bytes.matched_logical_bytes =
                    preview.bytes.matched_logical_bytes.saturating_add(bytes);
            } else {
                preview.bytes.matched_logical_unknown_files += 1;
            }
            if let Some(bytes) = candidate.allocated_bytes {
                preview.bytes.matched_allocated_bytes =
                    preview.bytes.matched_allocated_bytes.saturating_add(bytes);
            } else {
                preview.bytes.matched_allocated_unknown_files += 1;
            }
        } else {
            preview.counts.aliases += 1;
        }
        preview.counts.inspected_candidates += 1;
        match candidate.format.status {
            FormatStatus::Recognized => preview.counts.recognized += 1,
            FormatStatus::Unsupported | FormatStatus::Unknown => preview.counts.unsupported += 1,
            FormatStatus::Corrupt => preview.counts.corrupt += 1,
            FormatStatus::Changed => preview.counts.changed += 1,
            FormatStatus::PermissionDenied => preview.counts.permission_denied += 1,
            FormatStatus::Partial => preview.counts.probe_issues += 1,
            FormatStatus::Cancelled => preview.counts.probe_issues += 1,
        }
        preview.candidates.push(candidate);
        if matches!(
            preview.status,
            InstallerStatus::Cancelled | InstallerStatus::Failed
        ) {
            break;
        }
    }
    preview.metrics.elapsed_ms = elapsed_ms(started.elapsed());
    preview.metrics.probe_elapsed_ms = preview.metrics.elapsed_ms;
    preview.metrics.candidate_io_bytes = probe.io_bytes;
    preview.metrics.expanded_bytes = probe.expanded_bytes;
    if preview.complete {
        status = InstallerStatus::Complete;
        preview.status = status;
        if preview.issues_omitted == 0 {
            preview.selection_context = Some(SelectionContext {
                root: preview.root.clone(),
                filter: preview.filter.clone(),
                excludes: preview.excludes.clone(),
            });
        }
    }
    preview
}

fn push_issue(preview: &mut InstallerPreview, issue: InstallerIssue) {
    const MAX_ISSUES: usize = 1024;
    if preview.issues.len() < MAX_ISSUES {
        preview.issues.push(issue);
    } else {
        preview.issues_omitted += 1;
    }
}

fn elapsed_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn candidate_name_kind(path: &Path) -> Option<CandidateNameKind> {
    let name = path.file_name()?.to_string_lossy();
    if name.ends_with(".dmg") || name.ends_with(".DMG") {
        Some(CandidateNameKind::Dmg)
    } else if name.ends_with(".pkg") || name.ends_with(".PKG") {
        Some(CandidateNameKind::Pkg)
    } else {
        None
    }
}

fn matches_filter(path: &Path, filter: &str) -> bool {
    let text = path.to_string_lossy().to_ascii_lowercase();
    text.contains(&filter.to_ascii_lowercase())
}

fn excluded(entry: &ScanEntry, entries: &[ScanEntry], excludes: &[PathBuf]) -> bool {
    if excludes.is_empty() {
        return false;
    }
    if excludes.iter().any(|path| overlaps(&entry.path, path)) {
        return true;
    }
    let mut identities = HashSet::new();
    for other in entries {
        if excludes.iter().any(|path| overlaps(&other.path, path)) {
            identities.insert(other.identity);
        }
    }
    identities.contains(&entry.identity)
}

fn format_unknown_for_error(code: InstallerIssueCode) -> CandidateFormat {
    let status = match code {
        InstallerIssueCode::Cancelled => FormatStatus::Cancelled,
        InstallerIssueCode::PermissionDenied => FormatStatus::PermissionDenied,
        InstallerIssueCode::Changed => FormatStatus::Changed,
        InstallerIssueCode::Corrupt => FormatStatus::Corrupt,
        InstallerIssueCode::DurationLimit
        | InstallerIssueCode::IoBudgetExceeded
        | InstallerIssueCode::ExpandedBudgetExceeded
        | InstallerIssueCode::ParseLimit => FormatStatus::Partial,
        InstallerIssueCode::Unsupported | InstallerIssueCode::UnsupportedPlatform => {
            FormatStatus::Unsupported
        }
        _ => FormatStatus::Unknown,
    };
    CandidateFormat {
        family: FormatFamily::Unknown,
        status,
        detection_level: "not_assessed",
        evidence: vec![],
        limitations: vec![
            "not_mounted",
            "not_installed",
            "signature_not_assessed",
            "provenance_not_read",
        ],
    }
}

fn inspect_candidate(
    entry: &ScanEntry,
    name_kind: CandidateNameKind,
    root_identities: &HashMap<PathBuf, FileIdentity>,
    by_path: &HashMap<PathBuf, &ScanEntry>,
    context: ProbeContext<'_>,
    budget: &mut ProbeBudget,
) -> Result<InstallerCandidate, PreviewError> {
    context.check()?;
    let root = explicit_root_for_path(root_identities, &entry.path).ok_or_else(|| {
        PreviewError::new(
            InstallerIssueCode::InvalidInput,
            "candidate has no explicit root membership",
        )
    })?;
    let root_identity = root_identities[root];
    let relative = entry.path.strip_prefix(root).map_err(|_| {
        PreviewError::new(
            InstallerIssueCode::InvalidInput,
            "candidate cannot be relativized to root",
        )
    })?;
    let ancestors = ancestor_identities(root, relative, by_path).ok_or_else(|| {
        PreviewError::new(
            InstallerIssueCode::Changed,
            "ancestor identity is unavailable for candidate",
        )
    })?;
    let mut inspected = InspectedRead::open(entry, root, root_identity, relative, &ancestors)?;
    let owner_scope = inspected.owner_scope;
    let parsed = match name_kind {
        CandidateNameKind::Dmg => parse_dmg(entry, &mut inspected, context, budget),
        CandidateNameKind::Pkg => parse_pkg(entry, &mut inspected, context, budget),
    };
    #[cfg(target_os = "macos")]
    let inspection = parsed.as_ref().ok().map(|format| InspectionWitness {
        path: entry.path.clone(),
        root_path: inspected.root_path.clone(),
        root: inspected.root_baseline,
        ancestors: inspected.dir_chain.clone(),
        target: inspected.baseline,
        owner_scope,
        name_kind,
        format: format.clone(),
    });
    let finalize = inspected.finish();
    match (parsed, finalize) {
        (Ok(format), Ok(())) => Ok(InstallerCandidate {
            path: entry.path.clone(),
            identity: entry.identity,
            owner_scope,
            logical_bytes: entry.logical_bytes,
            allocated_bytes: entry.allocated_bytes,
            counted: entry.counted,
            name_kind,
            format,
            #[cfg(target_os = "macos")]
            inspection,
        }),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(primary), Err(finalize_error)) => Err(PreviewError::new(
            InstallerIssueCode::PolicyFailure,
            format!("{}; {}", primary.message, finalize_error.message),
        )),
    }
}

fn explicit_root_for_path<'a>(
    roots: &'a HashMap<PathBuf, FileIdentity>,
    path: &Path,
) -> Option<&'a Path> {
    roots
        .keys()
        .map(PathBuf::as_path)
        .filter(|root| path.starts_with(root))
        .max_by_key(|root| root.as_os_str().len())
}

fn ancestor_identities(
    root: &Path,
    relative: &Path,
    by_path: &HashMap<PathBuf, &ScanEntry>,
) -> Option<Vec<(PathBuf, FileIdentity)>> {
    let mut current = root.to_path_buf();
    let mut parent = relative.to_path_buf();
    if !parent.pop() {
        return Some(Vec::new());
    }
    let mut result = Vec::new();
    for component in parent.components() {
        let Component::Normal(name) = component else {
            return None;
        };
        current.push(name);
        let entry = by_path.get(&current).copied()?;
        if entry.kind != ResourceKind::Directory {
            return None;
        }
        result.push((PathBuf::from(name), entry.identity));
    }
    Some(result)
}

fn parse_dmg(
    _entry: &ScanEntry,
    inspected: &mut InspectedRead,
    context: ProbeContext<'_>,
    budget: &mut ProbeBudget,
) -> Result<CandidateFormat, PreviewError> {
    context.check()?;
    if inspected.size < context.limits.max_dmg_footer_bytes {
        return Ok(CandidateFormat {
            family: FormatFamily::Unknown,
            status: FormatStatus::Corrupt,
            detection_level: "corrupt_or_truncated",
            evidence: vec!["named_candidate_only"],
            limitations: common_limitations(),
        });
    }
    let offset = inspected
        .size
        .checked_sub(context.limits.max_dmg_footer_bytes)
        .ok_or_else(|| PreviewError::new(InstallerIssueCode::Corrupt, "invalid footer offset"))?;
    let footer =
        inspected.read_exact(offset, context.limits.max_dmg_footer_bytes, budget, context)?;
    match parse_udif_footer(&footer, inspected.size) {
        UdifResult::Recognized => Ok(CandidateFormat {
            family: FormatFamily::UdifDmg,
            status: FormatStatus::Recognized,
            detection_level: "udif_koly_footer",
            evidence: vec!["bounded_footer", "koly_magic", "version_4", "header_512"],
            limitations: common_limitations(),
        }),
        UdifResult::Unsupported => Ok(CandidateFormat {
            family: FormatFamily::UdifDmg,
            status: FormatStatus::Unsupported,
            detection_level: "dmg_unsupported_or_unknown",
            evidence: vec!["bounded_footer", "koly_magic"],
            limitations: common_limitations(),
        }),
        UdifResult::Corrupt => Ok(CandidateFormat {
            family: FormatFamily::UdifDmg,
            status: FormatStatus::Corrupt,
            detection_level: "corrupt_or_truncated",
            evidence: vec!["bounded_footer", "koly_magic"],
            limitations: common_limitations(),
        }),
        UdifResult::NotUdif => Ok(CandidateFormat {
            family: FormatFamily::Unknown,
            status: FormatStatus::Unsupported,
            detection_level: "named_dmg_not_udif",
            evidence: vec!["named_candidate_only"],
            limitations: common_limitations(),
        }),
    }
}

fn parse_pkg(
    _entry: &ScanEntry,
    inspected: &mut InspectedRead,
    context: ProbeContext<'_>,
    budget: &mut ProbeBudget,
) -> Result<CandidateFormat, PreviewError> {
    context.check()?;
    if inspected.size < 28 {
        return Ok(CandidateFormat {
            family: FormatFamily::Xar,
            status: FormatStatus::Corrupt,
            detection_level: "pkg_corrupt_or_truncated",
            evidence: vec!["named_candidate_only"],
            limitations: common_limitations(),
        });
    }
    let header = inspected.read_exact(0, 28, budget, context)?;
    let parsed = match parse_xar_header(&header, inspected.size, context.limits) {
        XarHeaderOutcome::Header(header) => header,
        XarHeaderOutcome::Unsupported => {
            return Ok(CandidateFormat {
                family: FormatFamily::Unknown,
                status: FormatStatus::Unsupported,
                detection_level: "named_candidate_only",
                evidence: vec!["named_candidate_only"],
                limitations: common_limitations(),
            });
        }
        XarHeaderOutcome::Corrupt => {
            return Ok(CandidateFormat {
                family: FormatFamily::Xar,
                status: FormatStatus::Corrupt,
                detection_level: "pkg_corrupt_or_truncated",
                evidence: vec!["bounded_header"],
                limitations: common_limitations(),
            });
        }
        XarHeaderOutcome::OverConfiguredLimit => {
            return Err(PreviewError::new(
                InstallerIssueCode::ParseLimit,
                "xar toc sizes exceed configured inspection limits",
            ));
        }
    };
    let toc = inspected.read_exact(parsed.header_size, parsed.toc_compressed, budget, context)?;
    let inflated = match inflate_toc(&toc, parsed.toc_uncompressed, context, budget)? {
        InflateOutcome::Data(data) => data,
        InflateOutcome::Corrupt => {
            return Ok(CandidateFormat {
                family: FormatFamily::Xar,
                status: FormatStatus::Corrupt,
                detection_level: "pkg_corrupt_or_truncated",
                evidence: vec!["bounded_header", "bounded_toc"],
                limitations: common_limitations(),
            });
        }
    };
    let hints = match parse_toc_hints(&inflated, context)? {
        TocOutcome::Hints(hints) => hints,
        TocOutcome::Corrupt => {
            return Ok(CandidateFormat {
                family: FormatFamily::Xar,
                status: FormatStatus::Corrupt,
                detection_level: "pkg_corrupt_or_truncated",
                evidence: vec!["bounded_header", "bounded_toc", "xml_stream"],
                limitations: common_limitations(),
            });
        }
    };
    if hints.package_info || hints.distribution {
        let mut evidence = vec!["bounded_header", "bounded_toc", "xml_stream"];
        if hints.package_info {
            evidence.push("top_level_package_info");
        }
        if hints.distribution {
            evidence.push("top_level_distribution");
        }
        Ok(CandidateFormat {
            family: FormatFamily::FlatPkgXar,
            status: FormatStatus::Recognized,
            detection_level: "xar_flat_pkg_manifest_hint",
            evidence,
            limitations: common_limitations(),
        })
    } else {
        Ok(CandidateFormat {
            family: FormatFamily::Xar,
            status: FormatStatus::Unsupported,
            detection_level: "xar_archive_not_pkg",
            evidence: vec!["bounded_header", "bounded_toc", "xml_stream"],
            limitations: common_limitations(),
        })
    }
}

fn common_limitations() -> Vec<&'static str> {
    vec![
        "not_mounted",
        "not_installed",
        "signature_not_assessed",
        "provenance_not_read",
    ]
}

enum UdifResult {
    Recognized,
    Unsupported,
    Corrupt,
    NotUdif,
}

fn be_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    Some(u32::from_be_bytes(bytes.get(offset..end)?.try_into().ok()?))
}

fn be_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    Some(u64::from_be_bytes(bytes.get(offset..end)?.try_into().ok()?))
}

fn parse_udif_footer(footer: &[u8], file_size: u64) -> UdifResult {
    if footer.len() != 512 {
        return UdifResult::Corrupt;
    }
    if footer.get(0..4) != Some(b"koly") {
        return UdifResult::NotUdif;
    }
    let Some(version) = be_u32(footer, 4) else {
        return UdifResult::Corrupt;
    };
    let Some(header_size) = be_u32(footer, 8) else {
        return UdifResult::Corrupt;
    };
    if version != 4 || header_size != 512 {
        return UdifResult::Unsupported;
    }
    let Some(footer_start) = file_size.checked_sub(512) else {
        return UdifResult::Corrupt;
    };
    for (off_pos, len_pos) in [(0x18usize, 0x20usize), (0x28, 0x30), (0xd8, 0xe0)] {
        let Some(offset) = be_u64(footer, off_pos) else {
            return UdifResult::Corrupt;
        };
        let Some(length) = be_u64(footer, len_pos) else {
            return UdifResult::Corrupt;
        };
        if length == 0 {
            continue;
        }
        let Some(end) = offset.checked_add(length) else {
            return UdifResult::Corrupt;
        };
        if end > file_size || offset >= file_size || end > footer_start {
            return UdifResult::Corrupt;
        }
    }
    UdifResult::Recognized
}

struct XarHeader {
    header_size: u64,
    toc_compressed: u64,
    toc_uncompressed: u64,
}

enum XarHeaderOutcome {
    Header(XarHeader),
    Unsupported,
    Corrupt,
    OverConfiguredLimit,
}

fn parse_xar_header(
    header: &[u8],
    file_size: u64,
    limits: InstallerPreviewLimits,
) -> XarHeaderOutcome {
    if header.len() < 28 {
        return XarHeaderOutcome::Corrupt;
    }
    let magic = u32::from_be_bytes(header[0..4].try_into().expect("fixed"));
    if magic != 0x7861_7221 {
        return XarHeaderOutcome::Unsupported;
    }
    let header_size = u16::from_be_bytes(header[4..6].try_into().expect("fixed")) as u64;
    let version = u16::from_be_bytes(header[6..8].try_into().expect("fixed"));
    let toc_compressed = u64::from_be_bytes(header[8..16].try_into().expect("fixed"));
    let toc_uncompressed = u64::from_be_bytes(header[16..24].try_into().expect("fixed"));
    let checksum = u32::from_be_bytes(header[24..28].try_into().expect("fixed"));
    if header_size < 28 || header_size > file_size {
        return XarHeaderOutcome::Corrupt;
    }
    if version != 1 {
        return XarHeaderOutcome::Unsupported;
    }
    if !(0..=4).contains(&checksum) {
        return XarHeaderOutcome::Unsupported;
    }
    if toc_compressed == 0 || toc_uncompressed == 0 {
        return XarHeaderOutcome::Corrupt;
    }
    let Some(toc_end) = header_size.checked_add(toc_compressed) else {
        return XarHeaderOutcome::Corrupt;
    };
    if toc_end > file_size {
        return XarHeaderOutcome::Corrupt;
    }
    if toc_compressed > limits.max_pkg_toc_compressed
        || toc_uncompressed > limits.max_pkg_toc_uncompressed
    {
        return XarHeaderOutcome::OverConfiguredLimit;
    }
    XarHeaderOutcome::Header(XarHeader {
        header_size,
        toc_compressed,
        toc_uncompressed,
    })
}

enum InflateOutcome {
    Data(Vec<u8>),
    Corrupt,
}

fn inflate_toc(
    compressed: &[u8],
    uncompressed_limit: u64,
    context: ProbeContext<'_>,
    budget: &mut ProbeBudget,
) -> Result<InflateOutcome, PreviewError> {
    let mut decompressor = Decompress::new(true);
    let initial_capacity = uncompressed_limit
        .min(context.limits.max_expanded_bytes)
        .min(64 * 1024);
    let mut output = Vec::with_capacity(initial_capacity as usize);
    let mut input_offset = 0usize;
    loop {
        context.check()?;
        let remaining_per_file = uncompressed_limit
            .checked_sub(output.len() as u64)
            .ok_or_else(|| {
                PreviewError::new(InstallerIssueCode::Corrupt, "inflated TOC size overflow")
            })?;
        if remaining_per_file == 0 {
            let in_before = decompressor.total_in();
            let out_before = decompressor.total_out();
            let status = decompressor.decompress(
                &compressed[input_offset..],
                &mut [],
                FlushDecompress::None,
            );
            let consumed = usize::try_from(decompressor.total_in().saturating_sub(in_before))
                .map_err(|_| {
                    PreviewError::new(InstallerIssueCode::Corrupt, "inflate consumed overflow")
                })?;
            let produced = usize::try_from(decompressor.total_out().saturating_sub(out_before))
                .map_err(|_| {
                    PreviewError::new(InstallerIssueCode::Corrupt, "inflate produced overflow")
                })?;
            input_offset = input_offset.saturating_add(consumed);
            if produced > 0 {
                return Ok(InflateOutcome::Corrupt);
            }
            match status {
                Ok(Status::StreamEnd) => {
                    if input_offset != compressed.len() {
                        return Ok(InflateOutcome::Corrupt);
                    }
                    return Ok(InflateOutcome::Data(output));
                }
                _ => return Ok(InflateOutcome::Corrupt),
            }
        }
        let remaining_global = budget.remaining_expanded(context.limits);
        if remaining_global == 0 {
            return Err(PreviewError::new(
                InstallerIssueCode::ParseLimit,
                "insufficient expanded-byte budget for TOC decode",
            ));
        }
        let decode_window_u64 = remaining_per_file.min(remaining_global).min(8192);
        let decode_window = usize::try_from(decode_window_u64).map_err(|_| {
            PreviewError::new(InstallerIssueCode::ParseLimit, "invalid decode window")
        })?;
        let mut chunk = [0u8; 8192];
        let in_before = decompressor.total_in();
        let out_before = decompressor.total_out();
        let status = decompressor.decompress(
            &compressed[input_offset..],
            &mut chunk[..decode_window],
            FlushDecompress::None,
        );
        let consumed =
            usize::try_from(decompressor.total_in().saturating_sub(in_before)).map_err(|_| {
                PreviewError::new(InstallerIssueCode::Corrupt, "inflate consumed overflow")
            })?;
        let produced = usize::try_from(decompressor.total_out().saturating_sub(out_before))
            .map_err(|_| {
                PreviewError::new(InstallerIssueCode::Corrupt, "inflate produced overflow")
            })?;
        input_offset = input_offset.saturating_add(consumed);
        if produced > 0 {
            budget.add_expanded(produced as u64, context.limits)?;
            output.extend_from_slice(&chunk[..produced]);
        }
        let status = match status {
            Ok(status) => status,
            Err(_) => return Ok(InflateOutcome::Corrupt),
        };
        if status == Status::StreamEnd {
            break;
        }
        if consumed == 0 && produced == 0 {
            return Ok(InflateOutcome::Corrupt);
        }
    }
    if input_offset != compressed.len() {
        return Ok(InflateOutcome::Corrupt);
    }
    Ok(InflateOutcome::Data(output))
}

#[derive(Default)]
struct TocHints {
    package_info: bool,
    distribution: bool,
}

enum TocOutcome {
    Hints(TocHints),
    Corrupt,
}

enum AttrChargeOutcome {
    Ok,
    Corrupt,
}

fn charge_attributes<'a>(
    attributes: quick_xml::events::attributes::Attributes<'a>,
    retained_name_bytes: &mut usize,
    limits: InstallerPreviewLimits,
) -> Result<AttrChargeOutcome, PreviewError> {
    let mut seen = HashSet::<Vec<u8>>::new();
    for attr in attributes {
        let attr = match attr {
            Ok(attr) => attr,
            Err(_) => return Ok(AttrChargeOutcome::Corrupt),
        };
        let key = attr.key.as_ref();
        if !seen.insert(key.to_vec()) {
            return Ok(AttrChargeOutcome::Corrupt);
        }
        if std::str::from_utf8(key).is_err() || key.contains(&b'&') {
            return Ok(AttrChargeOutcome::Corrupt);
        }
        let raw_value = attr.value.as_ref();
        let decoded_value_len = match decoded_xml_scalar_len(raw_value) {
            Ok(len) => len,
            Err(()) => return Ok(AttrChargeOutcome::Corrupt),
        };
        let charge = key
            .len()
            .checked_add(key.len())
            .and_then(|value| value.checked_add(raw_value.len()))
            .and_then(|value| value.checked_add(decoded_value_len))
            .ok_or_else(|| {
                PreviewError::new(
                    InstallerIssueCode::ParseLimit,
                    "XML attribute budget overflow",
                )
            })?;
        *retained_name_bytes = retained_name_bytes.saturating_add(charge);
        if *retained_name_bytes > limits.max_retained_name_bytes {
            return Err(PreviewError::new(
                InstallerIssueCode::ParseLimit,
                "XML retained-name budget exceeded",
            ));
        }
    }
    Ok(AttrChargeOutcome::Ok)
}

fn decoded_xml_scalar_len(raw: &[u8]) -> Result<usize, ()> {
    let mut index = 0usize;
    let mut total = 0usize;
    while index < raw.len() {
        let next_entity = raw[index..]
            .iter()
            .position(|byte| *byte == b'&')
            .map(|delta| index + delta)
            .unwrap_or(raw.len());
        if next_entity > index {
            let plain = std::str::from_utf8(&raw[index..next_entity]).map_err(|_| ())?;
            total = total.checked_add(plain.len()).ok_or(())?;
            index = next_entity;
            if index == raw.len() {
                break;
            }
        }
        index += 1;
        let semi = raw[index..]
            .iter()
            .position(|byte| *byte == b';')
            .ok_or(())?;
        let entity = &raw[index..index + semi];
        let decoded_len = match entity {
            b"lt" | b"gt" | b"amp" | b"apos" | b"quot" => 1usize,
            _ if entity.starts_with(b"#x") || entity.starts_with(b"#X") => {
                let digits = &entity[2..];
                if digits.is_empty() {
                    return Err(());
                }
                let text = std::str::from_utf8(digits).map_err(|_| ())?;
                let code = u32::from_str_radix(text, 16).map_err(|_| ())?;
                let scalar = char::from_u32(code).ok_or(())?;
                if !is_valid_xml_scalar(scalar) {
                    return Err(());
                }
                scalar.len_utf8()
            }
            _ if entity.starts_with(b"#") => {
                let digits = &entity[1..];
                if digits.is_empty() {
                    return Err(());
                }
                let text = std::str::from_utf8(digits).map_err(|_| ())?;
                let code = text.parse::<u32>().map_err(|_| ())?;
                let scalar = char::from_u32(code).ok_or(())?;
                if !is_valid_xml_scalar(scalar) {
                    return Err(());
                }
                scalar.len_utf8()
            }
            _ => return Err(()),
        };
        total = total.checked_add(decoded_len).ok_or(())?;
        index += semi + 1;
    }
    Ok(total)
}

fn is_valid_xml_scalar(ch: char) -> bool {
    matches!(
        ch as u32,
        0x9 | 0xA | 0xD | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF
    )
}

fn parse_toc_hints(payload: &[u8], context: ProbeContext<'_>) -> Result<TocOutcome, PreviewError> {
    let mut reader = Reader::from_reader(payload);
    reader.config_mut().trim_text(true);
    let mut buffer = Vec::new();
    let mut depth = 0usize;
    let mut nodes = 0usize;
    let mut retained_name_bytes = 0usize;
    let mut element_stack: Vec<Vec<u8>> = Vec::new();
    let mut root_seen = false;
    let mut root_closed = false;
    let mut toc_seen = false;
    let mut top_level_files: Vec<FileFrame> = Vec::new();
    let mut hints = TocHints::default();
    loop {
        context.check()?;
        let event = match reader.read_event_into(&mut buffer) {
            Ok(event) => event,
            Err(_) => return Ok(TocOutcome::Corrupt),
        };
        match event {
            Event::Start(start) => {
                depth += 1;
                nodes += 1;
                if depth > context.limits.max_pkg_xml_depth
                    || nodes > context.limits.max_pkg_xml_nodes
                {
                    return Err(PreviewError::new(
                        InstallerIssueCode::ParseLimit,
                        "XML structural limits exceeded",
                    ));
                }
                let tag = start.name().as_ref().to_vec();
                match charge_attributes(
                    start.attributes(),
                    &mut retained_name_bytes,
                    context.limits,
                )? {
                    AttrChargeOutcome::Ok => {}
                    AttrChargeOutcome::Corrupt => return Ok(TocOutcome::Corrupt),
                }
                retained_name_bytes = retained_name_bytes.saturating_add(tag.len());
                if retained_name_bytes > context.limits.max_retained_name_bytes {
                    return Err(PreviewError::new(
                        InstallerIssueCode::ParseLimit,
                        "XML retained-name budget exceeded",
                    ));
                }
                if root_closed {
                    return Ok(TocOutcome::Corrupt);
                }
                if depth == 1 {
                    if root_seen || tag.as_slice() != b"xar" {
                        return Ok(TocOutcome::Corrupt);
                    }
                    root_seen = true;
                } else {
                    let parent = element_stack.last();
                    if depth == 2 && parent.is_some_and(|name| name.as_slice() == b"xar") {
                        if tag.as_slice() == b"toc" {
                            if toc_seen {
                                return Ok(TocOutcome::Corrupt);
                            }
                            toc_seen = true;
                        }
                    } else if tag.as_slice() == b"toc" && depth != 2 {
                        return Ok(TocOutcome::Corrupt);
                    }
                    if parent.is_some_and(|name| name.as_slice() == b"toc")
                        && tag.as_slice() == b"file"
                    {
                        top_level_files.push(FileFrame::default());
                    } else if parent.is_some_and(|name| name.as_slice() == b"file")
                        && (tag.as_slice() == b"name" || tag.as_slice() == b"type")
                        && element_stack.len() == 3
                        && element_stack[0].as_slice() == b"xar"
                        && element_stack[1].as_slice() == b"toc"
                        && element_stack[2].as_slice() == b"file"
                        && let Some(file) = top_level_files.last_mut()
                    {
                        if tag.as_slice() == b"name" {
                            file.pending_name = true;
                        } else {
                            file.pending_type = true;
                        }
                    }
                }
                element_stack.push(tag);
            }
            Event::Empty(empty) => {
                depth += 1;
                nodes += 1;
                if depth > context.limits.max_pkg_xml_depth
                    || nodes > context.limits.max_pkg_xml_nodes
                {
                    return Err(PreviewError::new(
                        InstallerIssueCode::ParseLimit,
                        "XML structural limits exceeded",
                    ));
                }
                let tag = empty.name().as_ref().to_vec();
                match charge_attributes(
                    empty.attributes(),
                    &mut retained_name_bytes,
                    context.limits,
                )? {
                    AttrChargeOutcome::Ok => {}
                    AttrChargeOutcome::Corrupt => return Ok(TocOutcome::Corrupt),
                }
                retained_name_bytes = retained_name_bytes.saturating_add(tag.len());
                if retained_name_bytes > context.limits.max_retained_name_bytes {
                    return Err(PreviewError::new(
                        InstallerIssueCode::ParseLimit,
                        "XML retained-name budget exceeded",
                    ));
                }
                if root_closed {
                    return Ok(TocOutcome::Corrupt);
                }
                if depth == 1 {
                    if root_seen || tag.as_slice() != b"xar" {
                        return Ok(TocOutcome::Corrupt);
                    }
                    root_seen = true;
                    root_closed = true;
                } else {
                    let parent = element_stack.last();
                    if depth == 2 && parent.is_some_and(|name| name.as_slice() == b"xar") {
                        if tag.as_slice() == b"toc" {
                            if toc_seen {
                                return Ok(TocOutcome::Corrupt);
                            }
                            toc_seen = true;
                        }
                    } else if tag.as_slice() == b"toc" && depth != 2 {
                        return Ok(TocOutcome::Corrupt);
                    }
                    if parent.is_some_and(|name| name.as_slice() == b"toc")
                        && tag.as_slice() == b"file"
                    {
                        top_level_files.push(FileFrame::default());
                        if !finalize_top_level_file(
                            top_level_files.pop().expect("just pushed"),
                            &mut hints,
                        ) {
                            return Ok(TocOutcome::Corrupt);
                        }
                    }
                }
                depth -= 1;
            }
            Event::Text(text) => {
                let raw = text.into_inner();
                let value = match std::str::from_utf8(&raw) {
                    Ok(value) => value,
                    Err(_) => return Ok(TocOutcome::Corrupt),
                };
                if root_closed && !value.trim().is_empty() {
                    return Ok(TocOutcome::Corrupt);
                }
                if element_stack.is_empty() {
                    buffer.clear();
                    continue;
                }
                let tag = element_stack.last().expect("checked");
                if tag.as_slice() != b"name" && tag.as_slice() != b"type" {
                    buffer.clear();
                    continue;
                }
                if raw
                    .iter()
                    .any(|b| matches!(b, 0x00..=0x08 | 0x0b | 0x0c | 0x0e..=0x1f))
                {
                    return Ok(TocOutcome::Corrupt);
                }
                retained_name_bytes = retained_name_bytes.saturating_add(raw.len());
                if retained_name_bytes > context.limits.max_retained_name_bytes {
                    return Err(PreviewError::new(
                        InstallerIssueCode::ParseLimit,
                        "XML retained-name budget exceeded",
                    ));
                }
                let Some(frame) = top_level_files.last_mut() else {
                    buffer.clear();
                    continue;
                };
                if tag.as_slice() == b"name" && frame.pending_name {
                    frame.pending_name = false;
                    if frame.name.replace(value.to_owned()).is_some() {
                        frame.conflict = true;
                    }
                } else if tag.as_slice() == b"type" && frame.pending_type {
                    frame.pending_type = false;
                    if frame.kind.replace(value.to_owned()).is_some() {
                        frame.conflict = true;
                    }
                }
            }
            Event::End(end) => {
                let tag = end.name().as_ref().to_vec();
                let Some(open) = element_stack.pop() else {
                    return Ok(TocOutcome::Corrupt);
                };
                if open != tag {
                    return Ok(TocOutcome::Corrupt);
                }
                if tag.as_slice() == b"file"
                    && element_stack
                        .last()
                        .is_some_and(|name| name.as_slice() == b"toc")
                {
                    let Some(frame) = top_level_files.pop() else {
                        return Ok(TocOutcome::Corrupt);
                    };
                    if !finalize_top_level_file(frame, &mut hints) {
                        return Ok(TocOutcome::Corrupt);
                    }
                }
                if tag.as_slice() == b"xar" {
                    root_closed = true;
                }
                depth = depth.saturating_sub(1);
            }
            Event::DocType(_) | Event::GeneralRef(_) => {
                return Ok(TocOutcome::Corrupt);
            }
            Event::Decl(_) | Event::Comment(_) | Event::PI(_) => {}
            Event::CData(text) => {
                if std::str::from_utf8(text.as_ref()).is_err() {
                    return Ok(TocOutcome::Corrupt);
                }
                if root_closed && !text.as_ref().iter().all(u8::is_ascii_whitespace) {
                    return Ok(TocOutcome::Corrupt);
                }
            }
            Event::Eof => {
                if !root_seen
                    || !root_closed
                    || !toc_seen
                    || depth != 0
                    || !element_stack.is_empty()
                    || !top_level_files.is_empty()
                {
                    return Ok(TocOutcome::Corrupt);
                }
                break;
            }
        }
        buffer.clear();
    }
    if !root_seen || !root_closed || !toc_seen {
        return Ok(TocOutcome::Corrupt);
    }
    Ok(TocOutcome::Hints(hints))
}

#[derive(Default)]
struct FileFrame {
    name: Option<String>,
    kind: Option<String>,
    pending_name: bool,
    pending_type: bool,
    conflict: bool,
}

fn finalize_top_level_file(frame: FileFrame, hints: &mut TocHints) -> bool {
    if frame.conflict
        || frame.pending_name
        || frame.pending_type
        || frame
            .name
            .as_deref()
            .is_some_and(|name| name.contains('/') || name.contains(".."))
    {
        return false;
    }
    if frame.kind.as_deref() != Some("file") {
        return true;
    }
    match frame.name.as_deref() {
        Some("PackageInfo") => {
            if hints.package_info {
                return false;
            }
            hints.package_info = true;
        }
        Some("Distribution") => {
            if hints.distribution {
                return false;
            }
            hints.distribution = true;
        }
        _ => {}
    }
    true
}

#[cfg(target_os = "macos")]
struct InspectedRead {
    policy: Option<sayaka_platform_macos::ReadOnlyPolicy>,
    root_path: PathBuf,
    root_baseline: FileStamp,
    dir_chain: Vec<DirCheckpoint>,
    leaf_name: OsString,
    fd: rustix::fd::OwnedFd,
    baseline: FileStamp,
    size: u64,
    owner_scope: OwnerScope,
}

#[cfg(not(target_os = "macos"))]
struct InspectedRead {
    size: u64,
    owner_scope: OwnerScope,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Debug)]
struct DirCheckpoint {
    name: OsString,
    baseline: FileStamp,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileStamp {
    identity: FileIdentity,
    mode_kind: ResourceKind,
    flags: u32,
    size: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    created: (i64, i64),
    mtime: (i64, i64),
    ctime: (i64, i64),
}

#[cfg(target_os = "macos")]
#[derive(Clone, Debug)]
struct InspectionWitness {
    path: PathBuf,
    root_path: PathBuf,
    root: FileStamp,
    ancestors: Vec<DirCheckpoint>,
    target: FileStamp,
    owner_scope: OwnerScope,
    name_kind: CandidateNameKind,
    format: CandidateFormat,
}

#[cfg(target_os = "macos")]
impl FileStamp {
    fn matches_native(&self, native: &sayaka_platform_macos::NativeWitnessInfo) -> bool {
        self.identity
            == (FileIdentity::Unix {
                device: native.device,
                inode: native.inode,
            })
            && matches!(
                (self.mode_kind, native.kind),
                (ResourceKind::File, "file") | (ResourceKind::Directory, "directory")
            )
            && self.uid == native.uid
            && self.gid == native.gid
            && self.mode == native.mode
            && self.flags == native.flags
            && self.created == (native.created_unix_seconds, native.created_nanoseconds)
            && (self.mode_kind == ResourceKind::Directory
                || (self.size == native.logical_bytes
                    && self.links == native.nlink
                    && self.mtime == (native.modified_unix_seconds, native.modified_nanoseconds)
                    && self.ctime == (native.changed_unix_seconds, native.changed_nanoseconds)))
    }
}

#[cfg(target_os = "macos")]
fn directory_flags() -> rustix::fs::OFlags {
    use rustix::fs::OFlags;
    OFlags::RDONLY
        | OFlags::DIRECTORY
        | OFlags::CLOEXEC
        | OFlags::NONBLOCK
        | OFlags::from_bits_retain(0x2000_0000)
}

#[cfg(target_os = "macos")]
fn file_flags() -> rustix::fs::OFlags {
    use rustix::fs::OFlags;
    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::from_bits_retain(0x2000_0000)
}

#[cfg(target_os = "macos")]
impl InspectedRead {
    fn open(
        entry: &ScanEntry,
        root: &Path,
        root_identity: FileIdentity,
        relative_path: &Path,
        ancestors: &[(PathBuf, FileIdentity)],
    ) -> Result<Self, PreviewError> {
        use rustix::fs::{self, Mode};
        use sayaka_platform_macos::ReadOnlyPolicy;

        let mut policy = Some(ReadOnlyPolicy::enter().map_err(|error| {
            PreviewError::new(
                InstallerIssueCode::PolicyFailure,
                format!("read-only policy setup failed: {error}"),
            )
        })?);
        let opened = (|| {
            if !valid_absolute_path(root) || root.parent().is_none() {
                return Err(PreviewError::new(
                    InstallerIssueCode::InvalidInput,
                    "root must be a non-root absolute path",
                ));
            }
            let root_fd = fs::open(root, directory_flags(), Mode::empty())
                .map_err(|error| map_errno(error, "open root"))?;
            let root_stat = fs::fstat(&root_fd).map_err(|error| map_errno(error, "stat root"))?;
            let root_stamp = stamp_from_stat(&root_stat)?;
            if root_stamp.mode_kind != ResourceKind::Directory
                || root_stamp.identity != root_identity
                || dataless(&root_stat)
            {
                return Err(PreviewError::new(
                    InstallerIssueCode::Changed,
                    "root changed since scan",
                ));
            }
            let mut chain = Vec::with_capacity(ancestors.len());
            let mut current = root_fd;
            for (name, identity) in ancestors {
                if name.components().count() != 1 {
                    return Err(PreviewError::new(
                        InstallerIssueCode::InvalidInput,
                        "invalid ancestor component",
                    ));
                }
                let fd = fs::openat(&current, name, directory_flags(), Mode::empty())
                    .map_err(|error| map_errno(error, "open ancestor"))?;
                let stat = fs::fstat(&fd).map_err(|error| map_errno(error, "stat ancestor"))?;
                let facts = stamp_from_stat(&stat)?;
                if facts.mode_kind != ResourceKind::Directory || facts.identity != *identity {
                    return Err(PreviewError::new(
                        InstallerIssueCode::Changed,
                        "ancestor changed since scan",
                    ));
                }
                if dataless(&stat) {
                    return Err(PreviewError::new(
                        InstallerIssueCode::Changed,
                        "ancestor is dataless",
                    ));
                }
                chain.push(DirCheckpoint {
                    name: name.as_os_str().to_os_string(),
                    baseline: facts,
                });
                current = fd;
            }
            let leaf = relative_path.file_name().ok_or_else(|| {
                PreviewError::new(
                    InstallerIssueCode::InvalidInput,
                    "missing candidate filename",
                )
            })?;
            let fd = fs::openat(&current, leaf, file_flags(), Mode::empty())
                .map_err(|error| map_errno(error, "open file"))?;
            let stat = fs::fstat(&fd).map_err(|error| map_errno(error, "stat file"))?;
            let facts = stamp_from_stat(&stat)?;
            if facts.mode_kind != ResourceKind::File || facts.identity != entry.identity {
                return Err(PreviewError::new(
                    InstallerIssueCode::Changed,
                    "candidate changed since scan",
                ));
            }
            if dataless(&stat) {
                return Err(PreviewError::new(
                    InstallerIssueCode::Changed,
                    "candidate is dataless",
                ));
            }
            if entry.logical_bytes.is_some_and(|size| size != facts.size) {
                return Err(PreviewError::new(
                    InstallerIssueCode::Changed,
                    "candidate size changed since scan",
                ));
            }
            let current_uid = rustix::process::geteuid().as_raw();
            let owner_scope = if facts.uid == current_uid {
                OwnerScope::CurrentUser
            } else {
                OwnerScope::OtherUser
            };
            Ok(Self {
                policy: policy.take(),
                root_path: root.to_path_buf(),
                root_baseline: root_stamp,
                dir_chain: chain,
                leaf_name: leaf.to_os_string(),
                fd,
                baseline: facts,
                size: facts.size,
                owner_scope,
            })
        })();
        match opened {
            Ok(value) => Ok(value),
            Err(primary) => {
                let Some(policy) = policy else {
                    return Err(primary);
                };
                let restored = policy.restore().map_err(|error| {
                    PreviewError::new(
                        InstallerIssueCode::PolicyFailure,
                        format!("read-only policy restore failed: {error}"),
                    )
                });
                match restored {
                    Ok(()) => Err(primary),
                    Err(restore) => Err(PreviewError::new(
                        InstallerIssueCode::PolicyFailure,
                        format!("{}; {}", primary.message, restore.message),
                    )),
                }
            }
        }
    }

    fn finish(mut self) -> Result<(), PreviewError> {
        let validation = self.check_unchanged();
        let restored = self
            .policy
            .take()
            .expect("policy initialized")
            .restore()
            .map_err(|error| {
                PreviewError::new(
                    InstallerIssueCode::PolicyFailure,
                    format!("read-only policy restore failed: {error}"),
                )
            });
        match (validation, restored) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) => Err(error),
            (Ok(()), Err(error)) => Err(error),
            (Err(primary), Err(restore)) => Err(PreviewError::new(
                InstallerIssueCode::PolicyFailure,
                format!("{}; {}", primary.message, restore.message),
            )),
        }
    }

    fn read_exact(
        &mut self,
        offset: u64,
        length: u64,
        budget: &mut ProbeBudget,
        context: ProbeContext<'_>,
    ) -> Result<Vec<u8>, PreviewError> {
        use rustix::io::pread;
        context.check()?;
        let end = offset
            .checked_add(length)
            .ok_or_else(|| PreviewError::new(InstallerIssueCode::Corrupt, "range overflow"))?;
        if end > self.size {
            return Err(PreviewError::new(
                InstallerIssueCode::Corrupt,
                "range exceeds file bounds",
            ));
        }
        budget.preflight_io(length, context.limits)?;
        let len = usize::try_from(length).map_err(|_| {
            PreviewError::new(InstallerIssueCode::Corrupt, "requested range is too large")
        })?;
        let mut output = vec![0u8; len];
        let mut filled = 0usize;
        const READ_CHUNK: usize = 64 * 1024;
        while filled < len {
            context.check()?;
            #[cfg(all(test, target_os = "macos"))]
            observe_read_policy()?;
            let next = filled.saturating_add((len - filled).min(READ_CHUNK));
            let read = pread(
                &self.fd,
                &mut output[filled..next],
                offset
                    .checked_add(u64::try_from(filled).expect("usize fits u64"))
                    .ok_or_else(|| {
                        PreviewError::new(InstallerIssueCode::Corrupt, "offset overflow")
                    })?,
            )
            .map_err(|error| map_errno(error, "pread"))?;
            if read == 0 {
                return Err(PreviewError::new(
                    InstallerIssueCode::Corrupt,
                    "unexpected end of file",
                ));
            }
            budget.charge_io(
                u64::try_from(read).expect("read count always fits into u64"),
                context.limits,
            )?;
            filled = filled.saturating_add(read);
        }
        self.check_unchanged()?;
        Ok(output)
    }

    fn check_unchanged(&self) -> Result<(), PreviewError> {
        use rustix::fs::{self, Mode};
        let root_fd = fs::open(&self.root_path, directory_flags(), Mode::empty())
            .map_err(|error| map_errno(error, "post-read open root"))?;
        let root_stat =
            fs::fstat(&root_fd).map_err(|error| map_errno(error, "post-read root stat"))?;
        let root_current = stamp_from_stat(&root_stat)?;
        if root_current != self.root_baseline
            || root_current.mode_kind != ResourceKind::Directory
            || dataless(&root_stat)
        {
            return Err(PreviewError::new(
                InstallerIssueCode::Changed,
                "root changed during read",
            ));
        }
        let mut current_fd = root_fd;
        for checkpoint in &self.dir_chain {
            let fd = fs::openat(
                &current_fd,
                &checkpoint.name,
                directory_flags(),
                Mode::empty(),
            )
            .map_err(|error| map_errno(error, "post-read open ancestor"))?;
            let stat =
                fs::fstat(&fd).map_err(|error| map_errno(error, "post-read ancestor stat"))?;
            let ancestor_current = stamp_from_stat(&stat)?;
            if ancestor_current != checkpoint.baseline
                || ancestor_current.mode_kind != ResourceKind::Directory
                || dataless(&stat)
            {
                return Err(PreviewError::new(
                    InstallerIssueCode::Changed,
                    "ancestor changed during read",
                ));
            }
            current_fd = fd;
        }
        let stat = fs::fstat(&self.fd).map_err(|error| map_errno(error, "post-read stat"))?;
        let leaf_current = stamp_from_stat(&stat)?;
        if leaf_current != self.baseline
            || leaf_current.mode_kind != ResourceKind::File
            || dataless(&stat)
        {
            return Err(PreviewError::new(
                InstallerIssueCode::Changed,
                "candidate changed during read",
            ));
        }
        let remapped = fs::openat(&current_fd, &self.leaf_name, file_flags(), Mode::empty())
            .map_err(|error| map_errno(error, "reopen candidate"))?;
        let remapped_stat =
            fs::fstat(&remapped).map_err(|error| map_errno(error, "restat candidate"))?;
        let remapped_current = stamp_from_stat(&remapped_stat)?;
        if remapped_current != self.baseline
            || remapped_current.mode_kind != ResourceKind::File
            || dataless(&remapped_stat)
        {
            return Err(PreviewError::new(
                InstallerIssueCode::Changed,
                "candidate path changed during read",
            ));
        }
        Ok(())
    }
}

#[cfg(not(target_os = "macos"))]
impl InspectedRead {
    fn open(
        _entry: &ScanEntry,
        _root: &Path,
        _root_identity: FileIdentity,
        _relative_path: &Path,
        _ancestors: &[(PathBuf, FileIdentity)],
    ) -> Result<Self, PreviewError> {
        Err(PreviewError::new(
            InstallerIssueCode::UnsupportedPlatform,
            "native installer inspection is currently implemented for macOS only",
        ))
    }

    fn read_exact(
        &mut self,
        _offset: u64,
        _length: u64,
        _budget: &mut ProbeBudget,
        _context: ProbeContext<'_>,
    ) -> Result<Vec<u8>, PreviewError> {
        Err(PreviewError::new(
            InstallerIssueCode::UnsupportedPlatform,
            "native installer inspection is currently implemented for macOS only",
        ))
    }

    fn finish(self) -> Result<(), PreviewError> {
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn map_errno(error: rustix::io::Errno, context: &str) -> PreviewError {
    if error == rustix::io::Errno::PERM || error == rustix::io::Errno::ACCESS {
        return PreviewError::new(
            InstallerIssueCode::PermissionDenied,
            format!("{context}: permission denied"),
        )
        .with_os(Some(error.raw_os_error()));
    }
    if error == rustix::io::Errno::NOENT {
        return PreviewError::new(
            InstallerIssueCode::NotFound,
            format!("{context}: not found"),
        )
        .with_os(Some(error.raw_os_error()));
    }
    if error == rustix::io::Errno::LOOP {
        return PreviewError::new(
            InstallerIssueCode::Changed,
            format!("{context}: symlink/refusal with no-follow policy"),
        )
        .with_os(Some(error.raw_os_error()));
    }
    PreviewError::new(InstallerIssueCode::Changed, format!("{context}: {error}"))
        .with_os(Some(error.raw_os_error()))
}

#[cfg(target_os = "macos")]
fn dataless(stat: &rustix::fs::Stat) -> bool {
    stat.st_flags & 0x4000_0000 != 0
}

#[cfg(target_os = "macos")]
fn stamp_from_stat(stat: &rustix::fs::Stat) -> Result<FileStamp, PreviewError> {
    let kind = match stat.st_mode & libc::S_IFMT {
        libc::S_IFREG => ResourceKind::File,
        libc::S_IFDIR => ResourceKind::Directory,
        libc::S_IFLNK => ResourceKind::Link,
        _ => ResourceKind::Other,
    };
    let size = u64::try_from(stat.st_size)
        .map_err(|_| PreviewError::new(InstallerIssueCode::Corrupt, "negative file size"))?;
    Ok(FileStamp {
        identity: FileIdentity::Unix {
            device: u64::from(stat.st_dev.cast_unsigned()),
            inode: stat.st_ino,
        },
        mode_kind: kind,
        flags: stat.st_flags,
        size,
        uid: stat.st_uid,
        gid: stat.st_gid,
        mode: u32::from(stat.st_mode),
        links: u64::from(stat.st_nlink),
        created: (stat.st_birthtime, stat.st_birthtime_nsec),
        mtime: (stat.st_mtime, stat.st_mtime_nsec),
        ctime: (stat.st_ctime, stat.st_ctime_nsec),
    })
}

#[cfg(all(test, target_os = "macos"))]
type ReadPolicyObserver = fn() -> Result<(), PreviewError>;

#[cfg(all(test, target_os = "macos"))]
static READ_POLICY_OBSERVER: std::sync::Mutex<Option<ReadPolicyObserver>> =
    std::sync::Mutex::new(None);

#[cfg(all(test, target_os = "macos"))]
fn set_read_policy_observer(observer: Option<ReadPolicyObserver>) {
    *READ_POLICY_OBSERVER
        .lock()
        .expect("read observer mutex poisoned") = observer;
}

#[cfg(all(test, target_os = "macos"))]
fn observe_read_policy() -> Result<(), PreviewError> {
    let callback = *READ_POLICY_OBSERVER
        .lock()
        .expect("read observer mutex poisoned");
    if let Some(callback) = callback {
        callback()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::ZlibEncoder};
    use std::io::Write;
    #[cfg(target_os = "macos")]
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[cfg(target_os = "macos")]
    mod owned_fixture {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/owned_temp.rs"
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn scanned_installer_replaced_by_fifo_is_refused_without_blocking() {
        use rustix::fs::OFlags;
        // Fail before touching a FIFO if the nonblocking-open invariant regresses.
        assert!(file_flags().contains(OFlags::NONBLOCK));
        let fixture = owned_fixture::OwnedTempDir::new(
            Path::new(env!("CARGO_MANIFEST_DIR")),
            "sayaka-installer-fifo-",
        )
        .unwrap();
        let root = fixture.path();
        let file = root.join("sample.pkg");
        std::fs::write(&file, b"original regular file").unwrap();
        let entry = file_entry(&file);
        let root_identity = unix_identity(root);
        std::fs::rename(&file, root.join("original.pkg")).unwrap();
        let created = std::process::Command::new("/usr/bin/mkfifo")
            .args(["-m", "600"])
            .arg(&file)
            .env_clear()
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert!(
            created.status.success(),
            "{}",
            String::from_utf8_lossy(&created.stderr)
        );
        let started = Instant::now();
        let result = InspectedRead::open(&entry, root, root_identity, Path::new("sample.pkg"), &[]);
        assert!(matches!(
            result,
            Err(PreviewError {
                code: InstallerIssueCode::Changed,
                ..
            })
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(
            std::fs::read(root.join("original.pkg")).unwrap(),
            b"original regular file"
        );
    }

    #[test]
    fn udif_footer_accepts_basic_koly_and_rejects_bad_ranges() {
        let mut footer = [0u8; 512];
        footer[0..4].copy_from_slice(b"koly");
        footer[4..8].copy_from_slice(&4u32.to_be_bytes());
        footer[8..12].copy_from_slice(&512u32.to_be_bytes());
        footer[0xd8..0xe0].copy_from_slice(&128u64.to_be_bytes());
        footer[0xe0..0xe8].copy_from_slice(&64u64.to_be_bytes());
        assert!(matches!(
            parse_udif_footer(&footer, 2048),
            UdifResult::Recognized
        ));
        footer[4..8].copy_from_slice(&3u32.to_be_bytes());
        assert!(matches!(
            parse_udif_footer(&footer, 2048),
            UdifResult::Unsupported
        ));
        footer[4..8].copy_from_slice(&4u32.to_be_bytes());
        footer[0xe0..0xe8].copy_from_slice(&2048u64.to_be_bytes());
        assert!(matches!(
            parse_udif_footer(&footer, 2048),
            UdifResult::Corrupt
        ));
    }

    #[test]
    fn xar_header_rejects_bad_magic_and_bounds() {
        let mut header = [0u8; 28];
        header[0..4].copy_from_slice(&0x7861_7221u32.to_be_bytes());
        header[4..6].copy_from_slice(&28u16.to_be_bytes());
        header[6..8].copy_from_slice(&1u16.to_be_bytes());
        header[8..16].copy_from_slice(&32u64.to_be_bytes());
        header[16..24].copy_from_slice(&128u64.to_be_bytes());
        header[24..28].copy_from_slice(&1u32.to_be_bytes());
        assert!(matches!(
            parse_xar_header(&header, 4096, InstallerPreviewLimits::default()),
            XarHeaderOutcome::Header(_)
        ));
        header[0] = 0;
        assert!(matches!(
            parse_xar_header(&header, 4096, InstallerPreviewLimits::default()),
            XarHeaderOutcome::Unsupported
        ));
    }

    #[test]
    fn xar_header_classifies_bounds_before_configured_caps() {
        let mut header = [0u8; 28];
        header[0..4].copy_from_slice(&0x7861_7221u32.to_be_bytes());
        header[4..6].copy_from_slice(&28u16.to_be_bytes());
        header[6..8].copy_from_slice(&1u16.to_be_bytes());
        header[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
        header[16..24].copy_from_slice(&u64::MAX.to_be_bytes());
        header[24..28].copy_from_slice(&1u32.to_be_bytes());
        assert!(matches!(
            parse_xar_header(&header, 28, InstallerPreviewLimits::default()),
            XarHeaderOutcome::Corrupt
        ));

        let tight_limits = InstallerPreviewLimits {
            max_pkg_toc_compressed: 64,
            max_pkg_toc_uncompressed: 64,
            ..InstallerPreviewLimits::default()
        };
        header[8..16].copy_from_slice(&65u64.to_be_bytes());
        header[16..24].copy_from_slice(&65u64.to_be_bytes());
        assert!(matches!(
            parse_xar_header(&header, 10_000, tight_limits),
            XarHeaderOutcome::OverConfiguredLimit
        ));
    }

    #[test]
    fn xml_hint_parser_accepts_descriptors_and_rejects_doctype() {
        let xml = br#"<?xml version="1.0"?><xar><toc><file><name>PackageInfo</name><type>file</type></file></toc></xar>"#;
        let hints = parse_toc_hints(
            xml,
            ProbeContext {
                cancellation: &Cancellation::default(),
                deadline: Instant::now() + Duration::from_secs(1),
                limits: InstallerPreviewLimits::default(),
            },
        )
        .unwrap();
        match hints {
            TocOutcome::Hints(hints) => assert!(hints.package_info),
            TocOutcome::Corrupt => panic!("expected valid hints"),
        }
        let bad = br#"<!DOCTYPE xar><xar><toc/></xar>"#;
        assert!(matches!(
            parse_toc_hints(
                bad,
                ProbeContext {
                    cancellation: &Cancellation::default(),
                    deadline: Instant::now() + Duration::from_secs(1),
                    limits: InstallerPreviewLimits::default(),
                },
            )
            .unwrap(),
            TocOutcome::Corrupt
        ));
    }

    #[test]
    fn xml_hint_parser_rejects_truncated_and_mismatched_roots() {
        let truncated = br#"<?xml version="1.0"?><xar><toc><file><name>PackageInfo</name><type>file</type></file>"#;
        let mismatched = br#"<?xml version="1.0"?><xar><toc><file></toc></xar>"#;
        let trailing = br#"<?xml version="1.0"?><xar><toc/></xar><xar/>"#;
        for xml in [
            truncated.as_slice(),
            mismatched.as_slice(),
            trailing.as_slice(),
        ] {
            assert!(matches!(
                parse_toc_hints(
                    xml,
                    ProbeContext {
                        cancellation: &Cancellation::default(),
                        deadline: Instant::now() + Duration::from_secs(1),
                        limits: InstallerPreviewLimits::default(),
                    },
                )
                .unwrap(),
                TocOutcome::Corrupt
            ));
        }
    }

    #[test]
    fn xml_hint_parser_ignores_nested_or_non_file_descriptors() {
        let nested = br#"<?xml version="1.0"?><xar><toc><metadata><file><name>PackageInfo</name><type>file</type></file></metadata></toc></xar>"#;
        let directory = br#"<?xml version="1.0"?><xar><toc><file><name>PackageInfo</name><type>directory</type></file></toc></xar>"#;
        for xml in [nested.as_slice(), directory.as_slice()] {
            match parse_toc_hints(
                xml,
                ProbeContext {
                    cancellation: &Cancellation::default(),
                    deadline: Instant::now() + Duration::from_secs(1),
                    limits: InstallerPreviewLimits::default(),
                },
            )
            .unwrap()
            {
                TocOutcome::Hints(hints) => {
                    assert!(!hints.package_info);
                    assert!(!hints.distribution);
                }
                TocOutcome::Corrupt => panic!("expected valid generic xar toc"),
            }
        }
    }

    #[test]
    fn xml_hint_parser_rejects_nested_file_forgery_for_top_level_hint() {
        let nested_forgery = br#"<?xml version="1.0"?><xar><toc><file><file><name>PackageInfo</name><type>file</type></file></file></toc></xar>"#;
        let outer_dir_nested_hint = br#"<?xml version="1.0"?><xar><toc><file><name>Outer</name><type>directory</type><file><name>PackageInfo</name><type>file</type></file></file></toc></xar>"#;
        let outer_missing_nested_hint = br#"<?xml version="1.0"?><xar><toc><file><file><name>Distribution</name><type>file</type></file></file></toc></xar>"#;
        for xml in [
            nested_forgery.as_slice(),
            outer_dir_nested_hint.as_slice(),
            outer_missing_nested_hint.as_slice(),
        ] {
            let cancellation = Cancellation::default();
            match parse_toc_hints(
                xml,
                ProbeContext {
                    cancellation: &cancellation,
                    deadline: Instant::now() + Duration::from_secs(1),
                    limits: InstallerPreviewLimits::default(),
                },
            )
            .unwrap()
            {
                TocOutcome::Hints(hints) => {
                    assert!(!hints.package_info);
                    assert!(!hints.distribution);
                }
                TocOutcome::Corrupt => panic!("expected valid generic xar toc"),
            }
        }
    }

    #[test]
    fn xml_attribute_budget_enforced_for_large_and_accumulated_attributes() {
        let large_attr = "a".repeat(300);
        let xml_over = format!(
            r#"<?xml version="1.0"?><xar><toc><file x="{large_attr}"><name>PackageInfo</name><type>file</type></file></toc></xar>"#
        );
        let cancellation = Cancellation::default();
        let over_result = parse_toc_hints(
            xml_over.as_bytes(),
            ProbeContext {
                cancellation: &cancellation,
                deadline: Instant::now() + Duration::from_secs(1),
                limits: InstallerPreviewLimits {
                    max_retained_name_bytes: 256,
                    ..InstallerPreviewLimits::default()
                },
            },
        );
        assert!(matches!(
            over_result,
            Err(PreviewError {
                code: InstallerIssueCode::ParseLimit,
                ..
            })
        ));

        let exact_attr = "b".repeat(59);
        let xml_exact = format!(
            r#"<?xml version="1.0"?><xar><toc><file z="{exact_attr}"><name>PackageInfo</name><type>file</type></file></toc></xar>"#
        );
        let exact = parse_toc_hints(
            xml_exact.as_bytes(),
            ProbeContext {
                cancellation: &cancellation,
                deadline: Instant::now() + Duration::from_secs(1),
                limits: InstallerPreviewLimits {
                    max_retained_name_bytes: 192,
                    ..InstallerPreviewLimits::default()
                },
            },
        )
        .unwrap();
        match exact {
            TocOutcome::Hints(hints) => assert!(hints.package_info),
            TocOutcome::Corrupt => panic!("expected valid hints at exact attribute budget"),
        }

        let xml_many_small = r#"<?xml version="1.0"?><xar><toc><file a1="1" a2="2" a3="3" a4="4" a5="5"><name>PackageInfo</name><type>file</type></file></toc></xar>"#;
        let many_small = parse_toc_hints(
            xml_many_small.as_bytes(),
            ProbeContext {
                cancellation: &cancellation,
                deadline: Instant::now() + Duration::from_secs(1),
                limits: InstallerPreviewLimits {
                    max_retained_name_bytes: 60,
                    ..InstallerPreviewLimits::default()
                },
            },
        );
        assert!(matches!(
            many_small,
            Err(PreviewError {
                code: InstallerIssueCode::ParseLimit,
                ..
            })
        ));
    }

    #[test]
    fn xml_attribute_duplicates_or_invalid_entities_are_corrupt() {
        let duplicate = br#"<?xml version="1.0"?><xar><toc><file x="1" x="2"><name>PackageInfo</name><type>file</type></file></toc></xar>"#;
        let invalid_entity = br#"<?xml version="1.0"?><xar><toc><file x="&custom;"><name>PackageInfo</name><type>file</type></file></toc></xar>"#;
        let cancellation = Cancellation::default();
        for xml in [duplicate.as_slice(), invalid_entity.as_slice()] {
            assert!(matches!(
                parse_toc_hints(
                    xml,
                    ProbeContext {
                        cancellation: &cancellation,
                        deadline: Instant::now() + Duration::from_secs(1),
                        limits: InstallerPreviewLimits::default(),
                    },
                )
                .unwrap(),
                TocOutcome::Corrupt
            ));
        }
    }

    #[test]
    fn inflate_toc_charges_output_even_when_stream_errors() {
        let source = vec![b'A'; 1024];
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&source).unwrap();
        let mut compressed = encoder.finish().unwrap();
        let last = compressed.len() - 1;
        compressed[last] ^= 0x01;
        let mut budget = ProbeBudget::default();
        let limits = InstallerPreviewLimits::default();
        let cancellation = Cancellation::default();
        let outcome = inflate_toc(
            &compressed,
            4096,
            ProbeContext {
                cancellation: &cancellation,
                deadline: Instant::now() + Duration::from_secs(1),
                limits,
            },
            &mut budget,
        )
        .unwrap();
        assert!(matches!(outcome, InflateOutcome::Corrupt));
        assert!(budget.expanded_bytes > 0);
        assert!(budget.expanded_bytes <= limits.max_expanded_bytes);
    }

    #[test]
    fn inflate_toc_stops_at_remaining_budget_without_overrun() {
        let source = vec![b'B'; 4096];
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&source).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut budget = ProbeBudget::default();
        let limits = InstallerPreviewLimits {
            max_expanded_bytes: 256,
            ..InstallerPreviewLimits::default()
        };
        let cancellation = Cancellation::default();
        let result = inflate_toc(
            &compressed,
            4096,
            ProbeContext {
                cancellation: &cancellation,
                deadline: Instant::now() + Duration::from_secs(1),
                limits,
            },
            &mut budget,
        );
        match result {
            Err(err) => assert_eq!(err.code, InstallerIssueCode::ParseLimit),
            Ok(_) => panic!("expected parse limit"),
        }
        assert_eq!(budget.expanded_bytes, 256);
    }

    #[test]
    fn inflate_toc_succeeds_at_exact_output_limit() {
        let source = vec![b'C'; 512];
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&source).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut budget = ProbeBudget::default();
        let limits = InstallerPreviewLimits {
            max_expanded_bytes: 512,
            ..InstallerPreviewLimits::default()
        };
        let cancellation = Cancellation::default();
        let outcome = inflate_toc(
            &compressed,
            512,
            ProbeContext {
                cancellation: &cancellation,
                deadline: Instant::now() + Duration::from_secs(1),
                limits,
            },
            &mut budget,
        )
        .unwrap();
        match outcome {
            InflateOutcome::Data(data) => assert_eq!(data.len(), 512),
            InflateOutcome::Corrupt => panic!("expected successful inflate"),
        }
        assert_eq!(budget.expanded_bytes, 512);
    }

    #[cfg(target_os = "macos")]
    fn test_root_dir() -> PathBuf {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("installer-preview-unit-{unique}"));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create test root");
        root
    }

    #[cfg(target_os = "macos")]
    fn unix_identity(path: &Path) -> FileIdentity {
        use rustix::fs;
        let stat = fs::stat(path).expect("stat");
        FileIdentity::Unix {
            device: u64::from(stat.st_dev.cast_unsigned()),
            inode: stat.st_ino,
        }
    }

    #[cfg(target_os = "macos")]
    fn file_entry(path: &Path) -> ScanEntry {
        let bytes = std::fs::metadata(path).expect("metadata").len();
        ScanEntry {
            id: 1,
            path: path.to_path_buf(),
            kind: ResourceKind::File,
            identity: unix_identity(path),
            logical_bytes: Some(bytes),
            allocated_bytes: Some(bytes),
            dataless: false,
            counted: true,
            depth: 1,
        }
    }

    #[cfg(target_os = "macos")]
    static POLICY_HIT_COUNT: AtomicUsize = AtomicUsize::new(0);
    #[cfg(target_os = "macos")]
    static OBSERVER_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    #[cfg(target_os = "macos")]
    static TRUNCATE_OBSERVER_CALLS: AtomicUsize = AtomicUsize::new(0);
    #[cfg(target_os = "macos")]
    static TRUNCATE_TARGET: std::sync::OnceLock<std::sync::Mutex<Option<PathBuf>>> =
        std::sync::OnceLock::new();

    #[cfg(target_os = "macos")]
    fn truncate_target_slot() -> &'static std::sync::Mutex<Option<PathBuf>> {
        TRUNCATE_TARGET.get_or_init(|| std::sync::Mutex::new(None))
    }

    #[cfg(target_os = "macos")]
    fn assert_read_policy_active() -> Result<(), PreviewError> {
        let nested = sayaka_platform_macos::ReadOnlyPolicy::enter().map_err(|error| {
            PreviewError::new(
                InstallerIssueCode::PolicyFailure,
                format!("nested read-only policy enter failed during read: {error}"),
            )
        })?;
        nested.restore().map_err(|error| {
            PreviewError::new(
                InstallerIssueCode::PolicyFailure,
                format!("nested read-only policy restore failed during read: {error}"),
            )
        })?;
        POLICY_HIT_COUNT.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn truncate_before_second_read() -> Result<(), PreviewError> {
        let nested = sayaka_platform_macos::ReadOnlyPolicy::enter().map_err(|error| {
            PreviewError::new(
                InstallerIssueCode::PolicyFailure,
                format!("nested read-only policy enter failed during read: {error}"),
            )
        })?;
        nested.restore().map_err(|error| {
            PreviewError::new(
                InstallerIssueCode::PolicyFailure,
                format!("nested read-only policy restore failed during read: {error}"),
            )
        })?;
        let call = TRUNCATE_OBSERVER_CALLS.fetch_add(1, Ordering::Relaxed) + 1;
        if call == 2
            && let Some(path) = truncate_target_slot()
                .lock()
                .expect("truncate target lock")
                .clone()
        {
            std::fs::OpenOptions::new()
                .write(true)
                .open(path)
                .map_err(|error| {
                    PreviewError::new(
                        InstallerIssueCode::Changed,
                        format!("truncate-open failed: {error}"),
                    )
                })?
                .set_len(64 * 1024)
                .map_err(|error| {
                    PreviewError::new(
                        InstallerIssueCode::Changed,
                        format!("truncate-set-len failed: {error}"),
                    )
                })?;
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn inspected_read_keeps_policy_active_during_pread() {
        let _guard = OBSERVER_TEST_LOCK
            .lock()
            .expect("observer test lock poisoned");
        let root = test_root_dir();
        let file = root.join("sample.pkg");
        std::fs::write(&file, vec![0x5a; 32 * 1024]).expect("write");
        let entry = file_entry(&file);
        let root_identity = unix_identity(&root);
        let mut inspected =
            InspectedRead::open(&entry, &root, root_identity, Path::new("sample.pkg"), &[])
                .expect("open inspected");
        POLICY_HIT_COUNT.store(0, Ordering::Relaxed);
        set_read_policy_observer(Some(assert_read_policy_active));
        let mut budget = ProbeBudget::default();
        let result = inspected.read_exact(
            0,
            32 * 1024,
            &mut budget,
            ProbeContext {
                cancellation: &Cancellation::default(),
                deadline: Instant::now() + Duration::from_secs(5),
                limits: InstallerPreviewLimits::default(),
            },
        );
        set_read_policy_observer(None);
        assert!(result.is_ok(), "read failed: {result:?}");
        assert!(POLICY_HIT_COUNT.load(Ordering::Relaxed) > 0);
        inspected.finish().expect("finish");
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn inspected_read_detects_root_replacement_before_finish() {
        let root = test_root_dir();
        let file = root.join("sample.pkg");
        std::fs::write(&file, vec![0x44; 4096]).expect("write");
        let entry = file_entry(&file);
        let root_identity = unix_identity(&root);
        let mut inspected =
            InspectedRead::open(&entry, &root, root_identity, Path::new("sample.pkg"), &[])
                .expect("open inspected");
        let moved = root.with_file_name(format!(
            "{}-moved",
            root.file_name().and_then(|v| v.to_str()).unwrap_or("root")
        ));
        let _ = std::fs::remove_dir_all(&moved);
        std::fs::rename(&root, &moved).expect("rename root");
        std::fs::create_dir_all(&root).expect("create replacement root");
        std::fs::write(root.join("sample.pkg"), vec![0x44; 4096]).expect("write replacement");
        let mut budget = ProbeBudget::default();
        let read = inspected.read_exact(
            0,
            512,
            &mut budget,
            ProbeContext {
                cancellation: &Cancellation::default(),
                deadline: Instant::now() + Duration::from_secs(5),
                limits: InstallerPreviewLimits::default(),
            },
        );
        assert!(matches!(
            read,
            Err(PreviewError {
                code: InstallerIssueCode::Changed,
                ..
            })
        ));
        let _ = inspected.finish();
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&moved);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn inspected_read_detects_ancestor_swap_even_if_leaf_inode_matches() {
        let root = test_root_dir();
        let dir = root.join("a");
        std::fs::create_dir_all(&dir).expect("create ancestor");
        let file = dir.join("sample.pkg");
        std::fs::write(&file, vec![0x66; 4096]).expect("write file");
        let entry = file_entry(&file);
        let root_identity = unix_identity(&root);
        let ancestors = vec![(PathBuf::from("a"), unix_identity(&dir))];
        let mut inspected = InspectedRead::open(
            &entry,
            &root,
            root_identity,
            Path::new("a/sample.pkg"),
            &ancestors,
        )
        .expect("open inspected");

        let old_dir = root.join("a-old");
        let _ = std::fs::remove_dir_all(&old_dir);
        std::fs::rename(&dir, &old_dir).expect("move ancestor");
        std::fs::create_dir_all(&dir).expect("create replacement ancestor");
        std::fs::hard_link(old_dir.join("sample.pkg"), dir.join("sample.pkg"))
            .expect("hardlink same leaf inode");

        let mut budget = ProbeBudget::default();
        let read = inspected.read_exact(
            0,
            512,
            &mut budget,
            ProbeContext {
                cancellation: &Cancellation::default(),
                deadline: Instant::now() + Duration::from_secs(5),
                limits: InstallerPreviewLimits::default(),
            },
        );
        assert!(matches!(
            read,
            Err(PreviewError {
                code: InstallerIssueCode::Changed,
                ..
            })
        ));
        let _ = inspected.finish();
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&old_dir);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn read_exact_budget_preflight_denial_does_not_charge_or_read() {
        let _guard = OBSERVER_TEST_LOCK
            .lock()
            .expect("observer test lock poisoned");
        let root = test_root_dir();
        let file = root.join("sample.dmg");
        std::fs::write(&file, vec![0x11; 512]).expect("write");
        let entry = file_entry(&file);
        let root_identity = unix_identity(&root);
        let mut inspected =
            InspectedRead::open(&entry, &root, root_identity, Path::new("sample.dmg"), &[])
                .expect("open inspected");
        POLICY_HIT_COUNT.store(0, Ordering::Relaxed);
        set_read_policy_observer(Some(assert_read_policy_active));
        let mut budget = ProbeBudget::default();
        let result = inspected.read_exact(
            0,
            512,
            &mut budget,
            ProbeContext {
                cancellation: &Cancellation::default(),
                deadline: Instant::now() + Duration::from_secs(5),
                limits: InstallerPreviewLimits {
                    max_candidate_io_bytes: 511,
                    ..InstallerPreviewLimits::default()
                },
            },
        );
        set_read_policy_observer(None);
        assert!(matches!(
            result,
            Err(PreviewError {
                code: InstallerIssueCode::IoBudgetExceeded,
                ..
            })
        ));
        assert_eq!(budget.io_bytes, 0);
        assert_eq!(POLICY_HIT_COUNT.load(Ordering::Relaxed), 0);
        let _ = inspected.finish();
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn read_exact_charges_only_actual_bytes_before_eof_error() {
        let _guard = OBSERVER_TEST_LOCK
            .lock()
            .expect("observer test lock poisoned");
        let root = test_root_dir();
        let file = root.join("sample.pkg");
        let requested = 256 * 1024u64;
        std::fs::write(&file, vec![0x22; requested as usize]).expect("write");
        let entry = file_entry(&file);
        let root_identity = unix_identity(&root);
        let mut inspected =
            InspectedRead::open(&entry, &root, root_identity, Path::new("sample.pkg"), &[])
                .expect("open inspected");
        TRUNCATE_OBSERVER_CALLS.store(0, Ordering::Relaxed);
        *truncate_target_slot().lock().expect("truncate target lock") = Some(file.clone());
        set_read_policy_observer(Some(truncate_before_second_read));
        let mut budget = ProbeBudget::default();
        let result = inspected.read_exact(
            0,
            requested,
            &mut budget,
            ProbeContext {
                cancellation: &Cancellation::default(),
                deadline: Instant::now() + Duration::from_secs(5),
                limits: InstallerPreviewLimits::default(),
            },
        );
        set_read_policy_observer(None);
        *truncate_target_slot().lock().expect("truncate target lock") = None;
        assert!(result.is_err());
        assert!(budget.io_bytes > 0);
        assert!(budget.io_bytes < requested);
        assert!(budget.io_bytes <= InstallerPreviewLimits::default().max_candidate_io_bytes);
        let _ = inspected.finish();
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn read_exact_at_io_budget_limit_succeeds_and_charges_exactly() {
        let root = test_root_dir();
        let file = root.join("sample.pkg");
        std::fs::write(&file, vec![0x33; 1024]).expect("write");
        let entry = file_entry(&file);
        let root_identity = unix_identity(&root);
        let mut inspected =
            InspectedRead::open(&entry, &root, root_identity, Path::new("sample.pkg"), &[])
                .expect("open inspected");
        let mut budget = ProbeBudget::default();
        let result = inspected.read_exact(
            0,
            1024,
            &mut budget,
            ProbeContext {
                cancellation: &Cancellation::default(),
                deadline: Instant::now() + Duration::from_secs(5),
                limits: InstallerPreviewLimits {
                    max_candidate_io_bytes: 1024,
                    ..InstallerPreviewLimits::default()
                },
            },
        );
        assert!(result.is_ok(), "exact-limit read should succeed");
        assert_eq!(budget.io_bytes, 1024);
        inspected.finish().expect("finish");
        let _ = std::fs::remove_dir_all(root);
    }
}
