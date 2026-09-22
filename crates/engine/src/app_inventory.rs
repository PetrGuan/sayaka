// SPDX-License-Identifier: MPL-2.0

//! Read-only macOS application inventory for explicit roots.

use crate::model::{Cancellation, FileIdentity, ResourceKind, overlaps, valid_absolute_path};
use crate::scan::{ScanEntry, ScanIssue, ScanReport, ScanStatus};
use quick_xml::Reader;
use quick_xml::events::Event;
use std::collections::{HashMap, HashSet};
#[cfg(target_os = "macos")]
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

pub const APP_INVENTORY_KIND: &str = "app_inventory";
pub const APP_INVENTORY_SCHEMA_VERSION: u32 = 1;
pub const APP_INVENTORY_TOTAL_BUDGET: Duration = Duration::from_secs(30);
const MIB: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppInventoryStatus {
    Complete,
    Partial,
    Cancelled,
    Failed,
}

impl AppInventoryStatus {
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
pub struct AppInventoryLimits {
    pub max_candidates: usize,
    pub max_info_plist_bytes: u64,
    pub max_total_plist_io_bytes: u64,
    pub max_plist_objects: usize,
    pub max_plist_refs_visited: usize,
    pub max_plist_depth: usize,
    pub max_xml_nodes: usize,
    pub max_xml_depth: usize,
    pub max_string_bytes: usize,
    pub max_retained_string_bytes: usize,
    pub max_total_retained_metadata_string_bytes: usize,
    pub max_issues: usize,
}

impl Default for AppInventoryLimits {
    fn default() -> Self {
        Self {
            max_candidates: 4096,
            max_info_plist_bytes: MIB,
            max_total_plist_io_bytes: 64 * MIB,
            max_plist_objects: 16_384,
            max_plist_refs_visited: 32_768,
            max_plist_depth: 8,
            max_xml_nodes: 20_000,
            max_xml_depth: 16,
            max_string_bytes: 4096,
            max_retained_string_bytes: 64 * 1024,
            max_total_retained_metadata_string_bytes: 16 * 1024 * 1024,
            max_issues: 1024,
        }
    }
}

impl AppInventoryLimits {
    pub fn validate(self) -> Result<(), String> {
        let d = Self::default();
        let valid = self.max_candidates > 0
            && self.max_candidates <= d.max_candidates
            && self.max_info_plist_bytes > 0
            && self.max_info_plist_bytes <= d.max_info_plist_bytes
            && self.max_total_plist_io_bytes > 0
            && self.max_total_plist_io_bytes <= d.max_total_plist_io_bytes
            && self.max_plist_objects > 0
            && self.max_plist_objects <= d.max_plist_objects
            && self.max_plist_refs_visited > 0
            && self.max_plist_refs_visited <= d.max_plist_refs_visited
            && self.max_plist_depth > 0
            && self.max_plist_depth <= d.max_plist_depth
            && self.max_xml_nodes > 0
            && self.max_xml_nodes <= d.max_xml_nodes
            && self.max_xml_depth > 0
            && self.max_xml_depth <= d.max_xml_depth
            && self.max_string_bytes > 0
            && self.max_string_bytes <= d.max_string_bytes
            && self.max_retained_string_bytes > 0
            && self.max_retained_string_bytes <= d.max_retained_string_bytes
            && self.max_total_retained_metadata_string_bytes > 0
            && self.max_total_retained_metadata_string_bytes
                <= d.max_total_retained_metadata_string_bytes
            && self.max_issues > 0
            && self.max_issues <= d.max_issues;
        if valid {
            Ok(())
        } else {
            Err("invalid app inventory limits".into())
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct AppInventoryOptions {
    pub filter: String,
    pub excludes: Vec<PathBuf>,
    pub limits: AppInventoryLimits,
    pub metadata_read_mode: AppInventoryMetadataReadMode,
    /// Opt-in read-only running-process attribution by exact executable path.
    pub running_attribution: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum AppInventoryMetadataReadMode {
    #[default]
    Baseline,
    AppRelated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppIssueCode {
    InvalidInput,
    CandidateLimit,
    DurationLimit,
    Cancelled,
    UnsupportedPlatform,
    PolicyFailure,
    PermissionDenied,
    NotFound,
    LinkSkipped,
    CloudOrDataless,
    Changed,
    PlistIoLimit,
    PlistSizeLimit,
    UnsupportedPlistFormat,
    MalformedPlist,
    PlistParseLimit,
    InvalidExecutablePath,
    Internal,
}

impl AppIssueCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::CandidateLimit => "candidate_limit",
            Self::DurationLimit => "duration_limit",
            Self::Cancelled => "cancelled",
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::PolicyFailure => "policy_failure",
            Self::PermissionDenied => "permission_denied",
            Self::NotFound => "not_found",
            Self::LinkSkipped => "link_skipped",
            Self::CloudOrDataless => "cloud_or_dataless",
            Self::Changed => "changed_entry",
            Self::PlistIoLimit => "plist_io_limit",
            Self::PlistSizeLimit => "plist_size_limit",
            Self::UnsupportedPlistFormat => "unsupported_plist_format",
            Self::MalformedPlist => "malformed_plist",
            Self::PlistParseLimit => "plist_parse_limit",
            Self::InvalidExecutablePath => "invalid_executable_path",
            Self::Internal => "internal_error",
        }
    }
}

#[derive(Clone, Debug)]
pub struct AppIssue {
    pub path: Option<PathBuf>,
    pub code: AppIssueCode,
    pub message: String,
    pub os_code: Option<i32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StringState {
    Present,
    Missing,
    NotString,
    Duplicate,
    TooLong,
}

impl StringState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Missing => "missing",
            Self::NotString => "not_string",
            Self::Duplicate => "duplicate",
            Self::TooLong => "too_long",
        }
    }
}

#[derive(Clone, Debug)]
pub struct StringField {
    pub state: StringState,
    pub value: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppKind {
    App,
    NonApp,
    Unknown,
}

impl AppKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::App => "app",
            Self::NonApp => "non_app",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameSource {
    BundleDisplayName,
    BundleNameFallback,
    BundleFilenameFallback,
}

impl NameSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BundleDisplayName => "cf_bundle_display_name",
            Self::BundleNameFallback => "cf_bundle_name_fallback",
            Self::BundleFilenameFallback => "bundle_filename_fallback",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlistFormat {
    Xml,
    Binary,
    Unsupported,
}

impl PlistFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Xml => "xml",
            Self::Binary => "binary",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathStatus {
    PresentFile,
    PresentNonFile,
    Missing,
    NotFollowedSymlink,
    InvalidDeclaredPath,
    NotChecked,
}

impl PathStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PresentFile => "present_file",
            Self::PresentNonFile => "present_non_file",
            Self::Missing => "missing",
            Self::NotFollowedSymlink => "not_followed_symlink",
            Self::InvalidDeclaredPath => "invalid_declared_path",
            Self::NotChecked => "not_checked",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ExecutableMetadata {
    pub state: StringState,
    pub declared_value: Option<String>,
    pub path_status: PathStatus,
}

/// Read-only observation of whether an app's declared executable is running.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunningObservation {
    /// Attribution was not requested.
    NotChecked,
    /// No trustworthy executable path exists (missing, non-file, link, or
    /// unresolvable); absence of a match is never reported instead.
    NotAttributable(&'static str),
    NotRunning,
    Running(Vec<u32>),
    /// Enumeration failed or was incomplete; not evidence of absence.
    Unknown,
}

impl RunningObservation {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotChecked => "not_checked",
            Self::NotAttributable(_) => "not_attributable",
            Self::NotRunning => "not_running",
            Self::Running(_) => "running",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug)]
pub struct AppRecord {
    pub bundle_path: PathBuf,
    pub observed_roots: Vec<PathBuf>,
    pub bundle_identity: FileIdentity,
    pub app_kind: AppKind,
    pub parser_format: PlistFormat,
    pub display_name: String,
    pub display_name_source: NameSource,
    pub localized: bool,
    pub bundle_id: StringField,
    pub short_version: StringField,
    pub build_version: StringField,
    pub package_type: StringField,
    pub declared_product_dir_name: StringField,
    pub executable: ExecutableMetadata,
    pub running: RunningObservation,
}

#[derive(Clone, Debug, Default)]
pub struct AppInventoryCounts {
    pub scan_entries: usize,
    pub scan_issues: usize,
    pub named_candidates: usize,
    pub inspected_candidates: usize,
    pub recognized_apps: usize,
    pub unknown: usize,
    pub non_app: usize,
    pub duplicate_identities: usize,
    pub metadata_issues: usize,
}

#[derive(Clone, Debug, Default)]
pub struct AppInventoryMetrics {
    pub elapsed_ms: u64,
    pub probe_elapsed_ms: u64,
    pub plist_read_bytes: u64,
    pub retained_metadata_string_bytes: usize,
}

#[derive(Clone, Debug)]
pub struct AppInventory {
    pub schema_version: u32,
    pub kind: &'static str,
    pub platform: &'static str,
    pub status: AppInventoryStatus,
    pub complete: bool,
    pub effects_performed: bool,
    pub roots: Vec<PathBuf>,
    pub filter: String,
    pub excludes: Vec<PathBuf>,
    pub scan_task_id: String,
    pub counts: AppInventoryCounts,
    pub apps: Vec<AppRecord>,
    pub scan_issues: Vec<ScanIssue>,
    pub issues: Vec<AppIssue>,
    pub issues_omitted: usize,
    pub metrics: AppInventoryMetrics,
}

#[derive(Default)]
struct ProbeBudget {
    io_bytes: u64,
    retained_bytes: usize,
    visited_refs: usize,
}

impl ProbeBudget {
    fn preflight_io(&self, bytes: u64, limits: AppInventoryLimits) -> Result<(), AppError> {
        let next = self
            .io_bytes
            .checked_add(bytes)
            .ok_or_else(|| AppError::new(AppIssueCode::PlistIoLimit, "I/O overflow"))?;
        if next > limits.max_total_plist_io_bytes {
            return Err(AppError::new(
                AppIssueCode::PlistIoLimit,
                "total Info.plist read budget exceeded",
            ));
        }
        Ok(())
    }

    fn charge_io(&mut self, bytes: u64, limits: AppInventoryLimits) -> Result<(), AppError> {
        let next = self
            .io_bytes
            .checked_add(bytes)
            .ok_or_else(|| AppError::new(AppIssueCode::PlistIoLimit, "I/O overflow"))?;
        if next > limits.max_total_plist_io_bytes {
            return Err(AppError::new(
                AppIssueCode::PlistIoLimit,
                "total Info.plist read budget exceeded",
            ));
        }
        self.io_bytes = next;
        Ok(())
    }

    fn charge_retained(
        &mut self,
        bytes: usize,
        limits: AppInventoryLimits,
    ) -> Result<(), AppError> {
        let next = self.retained_bytes.checked_add(bytes).ok_or_else(|| {
            AppError::new(AppIssueCode::PlistParseLimit, "retained-string overflow")
        })?;
        if next > limits.max_total_retained_metadata_string_bytes {
            return Err(AppError::new(
                AppIssueCode::PlistParseLimit,
                "total retained metadata string budget exceeded",
            ));
        }
        self.retained_bytes = next;
        Ok(())
    }

    fn visit_ref(&mut self, limits: AppInventoryLimits) -> Result<(), AppError> {
        let next = self
            .visited_refs
            .checked_add(1)
            .ok_or_else(|| AppError::new(AppIssueCode::PlistParseLimit, "reference overflow"))?;
        if next > limits.max_plist_refs_visited {
            return Err(AppError::new(
                AppIssueCode::PlistParseLimit,
                "plist visited-reference limit exceeded",
            ));
        }
        self.visited_refs = next;
        Ok(())
    }
}

#[derive(Debug)]
struct AppError {
    code: AppIssueCode,
    message: String,
    os_code: Option<i32>,
}

impl AppError {
    fn new(code: AppIssueCode, message: impl Into<String>) -> Self {
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
    limits: AppInventoryLimits,
    metadata_read_mode: AppInventoryMetadataReadMode,
    now: fn() -> Instant,
}

impl ProbeContext<'_> {
    fn check(&self) -> Result<(), AppError> {
        if self.cancellation.is_cancelled() {
            return Err(AppError::new(
                AppIssueCode::Cancelled,
                "app inventory cancelled",
            ));
        }
        if (self.now)() >= self.deadline {
            return Err(AppError::new(
                AppIssueCode::DurationLimit,
                "app inventory time budget exhausted",
            ));
        }
        Ok(())
    }
}

fn wall_clock_now() -> Instant {
    Instant::now()
}

pub fn inventory_apps(
    report: ScanReport,
    options: &AppInventoryOptions,
    cancellation: &Cancellation,
    probe_budget: Duration,
) -> AppInventory {
    inventory_apps_with_now(report, options, cancellation, probe_budget, wall_clock_now)
}

fn inventory_apps_with_now(
    report: ScanReport,
    options: &AppInventoryOptions,
    cancellation: &Cancellation,
    probe_budget: Duration,
    now: fn() -> Instant,
) -> AppInventory {
    let started = Instant::now();
    let limits = options.limits;
    let mut status = match report.status {
        ScanStatus::Complete => AppInventoryStatus::Complete,
        ScanStatus::Partial => AppInventoryStatus::Partial,
        ScanStatus::Cancelled => AppInventoryStatus::Cancelled,
        ScanStatus::Failed => AppInventoryStatus::Failed,
    };
    let mut inventory = AppInventory {
        schema_version: APP_INVENTORY_SCHEMA_VERSION,
        kind: APP_INVENTORY_KIND,
        platform: if cfg!(target_os = "macos") {
            "macos"
        } else {
            "unsupported"
        },
        status,
        complete: matches!(status, AppInventoryStatus::Complete),
        effects_performed: false,
        roots: report.roots.clone(),
        filter: options.filter.clone(),
        excludes: options.excludes.clone(),
        scan_task_id: report.task_id.to_string(),
        counts: AppInventoryCounts {
            scan_entries: report.entries.len(),
            scan_issues: report.issues.len(),
            ..AppInventoryCounts::default()
        },
        apps: Vec::new(),
        scan_issues: report.issues.clone(),
        issues: Vec::new(),
        issues_omitted: report.issues_omitted,
        metrics: AppInventoryMetrics::default(),
    };
    if let Err(message) = limits.validate() {
        inventory.status = AppInventoryStatus::Failed;
        inventory.complete = false;
        push_issue(
            &mut inventory,
            AppIssue {
                path: None,
                code: AppIssueCode::InvalidInput,
                message,
                os_code: None,
            },
            limits,
        );
        inventory.metrics.elapsed_ms = elapsed_ms(started.elapsed());
        return inventory;
    }
    if !cfg!(target_os = "macos") {
        inventory.status = AppInventoryStatus::Failed;
        inventory.complete = false;
        push_issue(
            &mut inventory,
            AppIssue {
                path: None,
                code: AppIssueCode::UnsupportedPlatform,
                message: "native macOS app inspection is unavailable on this platform".into(),
                os_code: None,
            },
            limits,
        );
        inventory.metrics.elapsed_ms = elapsed_ms(started.elapsed());
        return inventory;
    }

    let deadline = Instant::now() + probe_budget;
    let context = ProbeContext {
        cancellation,
        deadline,
        limits,
        metadata_read_mode: options.metadata_read_mode,
        now,
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

    let exclusions = match ExclusionMatcher::build(&report.entries, &options.excludes, context) {
        Ok(value) => value,
        Err(error) => {
            inventory.status = match error.code {
                AppIssueCode::Cancelled => AppInventoryStatus::Cancelled,
                AppIssueCode::InvalidInput
                | AppIssueCode::Internal
                | AppIssueCode::UnsupportedPlatform => AppInventoryStatus::Failed,
                _ => AppInventoryStatus::Partial,
            };
            inventory.complete = false;
            push_issue(
                &mut inventory,
                AppIssue {
                    path: None,
                    code: error.code,
                    message: error.message,
                    os_code: error.os_code,
                },
                limits,
            );
            inventory.metrics.elapsed_ms = elapsed_ms(started.elapsed());
            return inventory;
        }
    };

    let mut named = Vec::new();
    for entry in &report.entries {
        if entry.kind != ResourceKind::Directory {
            continue;
        }
        if !is_app_candidate(&entry.path) {
            continue;
        }
        if !options.filter.is_empty() && !matches_filter(&entry.path, &options.filter) {
            continue;
        }
        if exclusions.contains(entry) {
            continue;
        }
        inventory.counts.named_candidates += 1;
        if named.len() >= limits.max_candidates {
            inventory.status = AppInventoryStatus::Partial;
            inventory.complete = false;
            push_issue(
                &mut inventory,
                AppIssue {
                    path: None,
                    code: AppIssueCode::CandidateLimit,
                    message: "app candidate limit reached".into(),
                    os_code: None,
                },
                limits,
            );
            break;
        }
        named.push(entry);
    }

    let mut dedup: HashMap<FileIdentity, usize> = HashMap::new();
    let mut budget = ProbeBudget::default();
    for entry in named {
        if let Some(&existing) = dedup.get(&entry.identity) {
            inventory.counts.duplicate_identities += 1;
            for root in roots_for_path(&root_identities, &entry.path) {
                if !inventory.apps[existing]
                    .observed_roots
                    .iter()
                    .any(|value| value == &root)
                {
                    inventory.apps[existing].observed_roots.push(root);
                }
            }
            continue;
        }
        let inspected = inspect_bundle(entry, &root_identities, &by_path, context, &mut budget);
        match inspected {
            Ok(mut app) => {
                inventory.counts.inspected_candidates += 1;
                match app.app_kind {
                    AppKind::App => inventory.counts.recognized_apps += 1,
                    AppKind::NonApp => inventory.counts.non_app += 1,
                    AppKind::Unknown => inventory.counts.unknown += 1,
                }
                app.observed_roots = roots_for_path(&root_identities, &entry.path);
                dedup.insert(entry.identity, inventory.apps.len());
                inventory.apps.push(app);
            }
            Err(error) => {
                inventory.status = match error.code {
                    AppIssueCode::Cancelled => AppInventoryStatus::Cancelled,
                    AppIssueCode::InvalidInput
                    | AppIssueCode::Internal
                    | AppIssueCode::UnsupportedPlatform => AppInventoryStatus::Failed,
                    _ => AppInventoryStatus::Partial,
                };
                inventory.complete = false;
                inventory.counts.metadata_issues += 1;
                let mut unknown = unknown_record(entry.path.clone(), entry.identity);
                unknown.observed_roots = roots_for_path(&root_identities, &entry.path);
                dedup.insert(entry.identity, inventory.apps.len());
                inventory.apps.push(unknown);
                inventory.counts.unknown += 1;
                push_issue(
                    &mut inventory,
                    AppIssue {
                        path: Some(entry.path.clone()),
                        code: error.code,
                        message: error.message,
                        os_code: error.os_code,
                    },
                    limits,
                );
                inventory.counts.inspected_candidates += 1;
                if matches!(
                    inventory.status,
                    AppInventoryStatus::Cancelled | AppInventoryStatus::Failed
                ) {
                    break;
                }
            }
        }
    }

    inventory.metrics.elapsed_ms = elapsed_ms(started.elapsed());
    inventory.metrics.probe_elapsed_ms = inventory.metrics.elapsed_ms;
    inventory.metrics.plist_read_bytes = budget.io_bytes;
    inventory.metrics.retained_metadata_string_bytes = budget.retained_bytes;
    if inventory.complete {
        status = AppInventoryStatus::Complete;
        inventory.status = status;
    }
    if options.running_attribution {
        attribute_running_state(&mut inventory.apps);
    }
    inventory
}

/// Enumerates visible running processes as canonical executable path -> PIDs.
/// Errors (including truncated enumeration) are never evidence of absence.
pub fn running_process_paths() -> std::io::Result<std::collections::HashMap<PathBuf, Vec<u32>>> {
    let mut by_path: std::collections::HashMap<PathBuf, Vec<u32>> =
        std::collections::HashMap::new();
    for (pid, path) in native_running_paths()? {
        by_path.entry(path).or_default().push(pid);
    }
    Ok(by_path)
}

/// Single-file parse budget for `read_bundle_identifier`.
const SINGLE_PLIST_SECONDS: u64 = 5;

/// Honest outcome of the single-bundle identifier observation.
#[derive(Clone, Debug)]
pub enum BundleIdentifierRead {
    /// The plist was read and parsed; the field carries the parser's own
    /// verdict (present, missing, not_string, duplicate, too_long).
    Parsed(StringField),
    /// The plist could not be inspected, read or parsed; no identifier is
    /// invented from partial evidence.
    Unreadable(&'static str),
}

/// Reads only `CFBundleIdentifier` from one explicit bundle directory,
/// reusing the inventory plist parser under a single-file budget.
/// Read-only; used by the T9 copy-evidence slice to name the previewed
/// bundle without a full inventory of its parent.
pub fn read_bundle_identifier(bundle: &Path) -> BundleIdentifierRead {
    let plist = bundle.join("Contents").join("Info.plist");
    let limits = AppInventoryLimits::default();
    let metadata = match std::fs::symlink_metadata(&plist) {
        Ok(metadata) if metadata.is_file() => metadata,
        Ok(_) => return BundleIdentifierRead::Unreadable("Info.plist is not a regular file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return BundleIdentifierRead::Unreadable("Info.plist is missing");
        }
        Err(_) => return BundleIdentifierRead::Unreadable("Info.plist cannot be inspected"),
    };
    if metadata.len() > limits.max_info_plist_bytes {
        return BundleIdentifierRead::Unreadable("Info.plist exceeds the single-file budget");
    }
    let bytes = match std::fs::read(&plist) {
        Ok(bytes) => bytes,
        Err(_) => return BundleIdentifierRead::Unreadable("Info.plist cannot be read"),
    };
    let cancellation = Cancellation::default();
    let context = ProbeContext {
        cancellation: &cancellation,
        deadline: wall_clock_now() + Duration::from_secs(SINGLE_PLIST_SECONDS),
        limits,
        metadata_read_mode: AppInventoryMetadataReadMode::Baseline,
        now: wall_clock_now,
    };
    let mut budget = ProbeBudget::default();
    match parse_info_plist(&bytes, context, &mut budget) {
        Ok(parsed) => BundleIdentifierRead::Parsed(parsed.bundle_id),
        Err(_) => BundleIdentifierRead::Unreadable("Info.plist cannot be parsed"),
    }
}

/// Resolves the declared executable of each record to a canonical path and
/// matches it against the visible running processes exactly once. A failed
/// or incomplete enumeration marks every record Unknown rather than
/// reporting "not running" from incomplete evidence.
fn attribute_running_state(apps: &mut [AppRecord]) {
    let running = match running_process_paths() {
        Ok(paths) => paths,
        Err(_) => {
            for app in apps.iter_mut() {
                app.running = RunningObservation::Unknown;
            }
            return;
        }
    };
    for app in apps.iter_mut() {
        app.running = running_observation(&app.bundle_path, &app.executable, &running);
    }
}

/// Pure attribution rule, separated for fixtures: only a declared, valid,
/// present regular-file executable whose path canonically resolves can be
/// matched; everything else is explicitly not attributable.
fn running_observation(
    bundle_path: &Path,
    executable: &ExecutableMetadata,
    running: &std::collections::HashMap<PathBuf, Vec<u32>>,
) -> RunningObservation {
    if executable.state != StringState::Present {
        return RunningObservation::NotAttributable("no valid declared executable");
    }
    if executable.path_status != PathStatus::PresentFile {
        return RunningObservation::NotAttributable("executable is not a present regular file");
    }
    let Some(name) = executable.declared_value.as_deref() else {
        return RunningObservation::NotAttributable("no declared executable value");
    };
    let candidate = bundle_path.join("Contents").join("MacOS").join(name);
    let Ok(resolved) = std::fs::canonicalize(&candidate) else {
        return RunningObservation::NotAttributable("executable path cannot be resolved");
    };
    match running.get(&resolved) {
        Some(pids) if !pids.is_empty() => RunningObservation::Running(pids.clone()),
        _ => RunningObservation::NotRunning,
    }
}

#[cfg(target_os = "macos")]
fn native_running_paths() -> std::io::Result<Vec<(u32, PathBuf)>> {
    sayaka_platform_macos::status::running_executable_paths(65_536)
}

#[cfg(not(target_os = "macos"))]
fn native_running_paths() -> std::io::Result<Vec<(u32, PathBuf)>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "running attribution currently requires macOS",
    ))
}

fn push_issue(inventory: &mut AppInventory, issue: AppIssue, limits: AppInventoryLimits) {
    if inventory.issues.len() < limits.max_issues {
        inventory.issues.push(issue);
    } else {
        inventory.issues_omitted += 1;
    }
}

fn elapsed_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn is_app_candidate(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with(".app"))
}

fn matches_filter(path: &Path, filter: &str) -> bool {
    path.to_string_lossy()
        .to_ascii_lowercase()
        .contains(&filter.to_ascii_lowercase())
}

struct ExclusionMatcher<'a> {
    excludes: &'a [PathBuf],
    excluded_identities: HashSet<FileIdentity>,
}

impl<'a> ExclusionMatcher<'a> {
    fn build(
        entries: &[ScanEntry],
        excludes: &'a [PathBuf],
        context: ProbeContext<'_>,
    ) -> Result<Self, AppError> {
        if excludes.is_empty() {
            return Ok(Self {
                excludes,
                excluded_identities: HashSet::new(),
            });
        }
        let excluded_identities = collect_excluded_identities(entries, excludes, context, || {})?;
        Ok(Self {
            excludes,
            excluded_identities,
        })
    }

    fn contains(&self, entry: &ScanEntry) -> bool {
        self.excludes.iter().any(|path| overlaps(&entry.path, path))
            || self.excluded_identities.contains(&entry.identity)
    }
}

fn collect_excluded_identities(
    entries: &[ScanEntry],
    excludes: &[PathBuf],
    context: ProbeContext<'_>,
    mut on_entry: impl FnMut(),
) -> Result<HashSet<FileIdentity>, AppError> {
    let mut identities = HashSet::new();
    for (index, other) in entries.iter().enumerate() {
        if index % 256 == 0 {
            context.check()?;
        }
        on_entry();
        if excludes.iter().any(|path| overlaps(&other.path, path)) {
            identities.insert(other.identity);
        }
    }
    Ok(identities)
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

fn roots_for_path(roots: &HashMap<PathBuf, FileIdentity>, path: &Path) -> Vec<PathBuf> {
    let mut values = roots
        .keys()
        .filter(|root| path.starts_with(root.as_path()))
        .cloned()
        .collect::<Vec<_>>();
    values.sort_by_key(|root| root.as_os_str().len());
    values
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

fn inspect_bundle(
    entry: &ScanEntry,
    root_identities: &HashMap<PathBuf, FileIdentity>,
    by_path: &HashMap<PathBuf, &ScanEntry>,
    context: ProbeContext<'_>,
    budget: &mut ProbeBudget,
) -> Result<AppRecord, AppError> {
    context.check()?;
    let root = explicit_root_for_path(root_identities, &entry.path).ok_or_else(|| {
        AppError::new(
            AppIssueCode::InvalidInput,
            "app candidate has no explicit root membership",
        )
    })?;
    let root_identity = root_identities[root];
    let relative = entry.path.strip_prefix(root).map_err(|_| {
        AppError::new(
            AppIssueCode::InvalidInput,
            "app candidate cannot be relativized to root",
        )
    })?;
    let ancestors = ancestor_identities(root, relative, by_path)
        .ok_or_else(|| AppError::new(AppIssueCode::Changed, "ancestor identity unavailable"))?;

    let mut inspected = InspectedBundle::open(entry, root, root_identity, relative, &ancestors)?;
    let plist = inspected.read_info_plist(context, budget)?;
    let parsed = parse_info_plist(&plist, context, budget)?;

    let display_name = if parsed.display_name.state == StringState::Present {
        (
            parsed.display_name.value.clone().unwrap_or_default(),
            NameSource::BundleDisplayName,
        )
    } else if parsed.bundle_name.state == StringState::Present {
        (
            parsed.bundle_name.value.clone().unwrap_or_default(),
            NameSource::BundleNameFallback,
        )
    } else {
        (
            entry
                .path
                .file_stem()
                .and_then(|v| v.to_str())
                .unwrap_or("(unknown)")
                .to_owned(),
            NameSource::BundleFilenameFallback,
        )
    };

    let app_kind = match (&parsed.package_type.state, &parsed.package_type.value) {
        (StringState::Present, Some(value)) if value == "APPL" => AppKind::App,
        (StringState::Present, Some(_)) => AppKind::NonApp,
        (StringState::Missing, _) => AppKind::Unknown,
        _ => AppKind::Unknown,
    };

    let mut executable = ExecutableMetadata {
        state: parsed.executable.state,
        declared_value: parsed.executable.value.clone(),
        path_status: PathStatus::NotChecked,
    };
    if parsed.executable.state == StringState::Present
        && let Some(name) = parsed.executable.value.as_deref()
    {
        if !valid_single_component_executable(name) {
            executable.path_status = PathStatus::InvalidDeclaredPath;
        } else {
            executable.path_status = match inspected.stat_executable(name) {
                Ok(status) => status,
                Err(error) => {
                    let finish = inspected.finish();
                    return match finish {
                        Ok(()) => Err(error),
                        Err(validate) => Err(validate),
                    };
                }
            };
        }
    }

    inspected.finish()?;

    Ok(AppRecord {
        bundle_path: entry.path.clone(),
        observed_roots: Vec::new(),
        bundle_identity: entry.identity,
        app_kind,
        parser_format: parsed.format,
        display_name: display_name.0,
        display_name_source: display_name.1,
        localized: false,
        bundle_id: parsed.bundle_id,
        short_version: parsed.short_version,
        build_version: parsed.build_version,
        package_type: parsed.package_type,
        declared_product_dir_name: parsed.cr_product_dir_name,
        executable,
        running: RunningObservation::NotChecked,
    })
}

fn valid_single_component_executable(value: &str) -> bool {
    !value.is_empty()
        && !value.contains('/')
        && value != "."
        && value != ".."
        && !value.contains('\0')
}

fn unknown_record(path: PathBuf, identity: FileIdentity) -> AppRecord {
    let missing = StringField {
        state: StringState::Missing,
        value: None,
    };
    AppRecord {
        bundle_path: path.clone(),
        observed_roots: Vec::new(),
        bundle_identity: identity,
        app_kind: AppKind::Unknown,
        parser_format: PlistFormat::Unsupported,
        display_name: path
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("(unknown)")
            .to_owned(),
        display_name_source: NameSource::BundleFilenameFallback,
        localized: false,
        bundle_id: missing.clone(),
        short_version: missing.clone(),
        build_version: missing.clone(),
        package_type: missing.clone(),
        declared_product_dir_name: missing.clone(),
        executable: ExecutableMetadata {
            state: StringState::Missing,
            declared_value: None,
            path_status: PathStatus::NotChecked,
        },
        running: RunningObservation::NotChecked,
    }
}

struct ParsedPlist {
    format: PlistFormat,
    display_name: StringField,
    bundle_name: StringField,
    bundle_id: StringField,
    short_version: StringField,
    build_version: StringField,
    package_type: StringField,
    cr_product_dir_name: StringField,
    executable: StringField,
}

fn missing_fields(format: PlistFormat) -> ParsedPlist {
    let missing = StringField {
        state: StringState::Missing,
        value: None,
    };
    ParsedPlist {
        format,
        display_name: missing.clone(),
        bundle_name: missing.clone(),
        bundle_id: missing.clone(),
        short_version: missing.clone(),
        build_version: missing.clone(),
        package_type: missing.clone(),
        cr_product_dir_name: missing.clone(),
        executable: missing,
    }
}

fn parse_info_plist(
    bytes: &[u8],
    context: ProbeContext<'_>,
    budget: &mut ProbeBudget,
) -> Result<ParsedPlist, AppError> {
    if bytes.starts_with(b"bplist00") {
        parse_binary_plist(bytes, context, budget)
    } else {
        let prefix = bytes
            .iter()
            .skip_while(|b| b.is_ascii_whitespace())
            .copied()
            .collect::<Vec<_>>();
        if prefix.starts_with(b"<?xml")
            || prefix.starts_with(b"<plist")
            || prefix.starts_with(b"<!DOCTYPE")
        {
            parse_xml_plist(bytes, context, budget)
        } else {
            Err(AppError::new(
                AppIssueCode::UnsupportedPlistFormat,
                "unsupported plist format",
            ))
        }
    }
}

fn parse_xml_plist(
    bytes: &[u8],
    context: ProbeContext<'_>,
    budget: &mut ProbeBudget,
) -> Result<ParsedPlist, AppError> {
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut depth = 0usize;
    let mut nodes = 0usize;
    let mut root_seen = false;
    let mut root_closed = false;
    let mut in_root_dict = false;
    let mut root_dict_closed = false;
    let mut value_depth = 0usize;
    let mut pending_value_name: Option<Vec<u8>> = None;
    let mut pending_key: Option<String> = None;
    let mut key_next_is_value = false;
    let mut selected: HashMap<&'static str, StringField> = HashMap::new();
    let mut key_buffer = String::new();
    let mut string_buffer = String::new();
    let mut in_key = false;
    let mut in_string = false;

    loop {
        context.check()?;
        let event = reader
            .read_event_into(&mut buffer)
            .map_err(|_| AppError::new(AppIssueCode::MalformedPlist, "malformed XML plist"))?;
        match event {
            Event::Start(start) => {
                depth += 1;
                nodes += 1;
                if depth > context.limits.max_xml_depth || nodes > context.limits.max_xml_nodes {
                    return Err(AppError::new(
                        AppIssueCode::PlistParseLimit,
                        "XML plist structural limits exceeded",
                    ));
                }
                let name = start.name().as_ref().to_vec();
                if root_closed {
                    return Err(AppError::new(
                        AppIssueCode::MalformedPlist,
                        "content appears after plist root",
                    ));
                }
                if depth == 1 && name.as_slice() != b"plist" {
                    return Err(AppError::new(
                        AppIssueCode::MalformedPlist,
                        "XML root is not plist",
                    ));
                }
                if depth == 1 {
                    if root_seen {
                        return Err(AppError::new(
                            AppIssueCode::MalformedPlist,
                            "multiple plist roots are not allowed",
                        ));
                    }
                    root_seen = true;
                } else if depth == 2 {
                    if root_dict_closed {
                        return Err(AppError::new(
                            AppIssueCode::MalformedPlist,
                            "multiple root dictionaries are not allowed",
                        ));
                    }
                    if name.as_slice() != b"dict" {
                        return Err(AppError::new(
                            AppIssueCode::MalformedPlist,
                            "plist root must contain one dict",
                        ));
                    }
                    in_root_dict = true;
                } else if in_root_dict {
                    if value_depth > 0 {
                        value_depth = value_depth.saturating_add(1);
                        buffer.clear();
                        continue;
                    }
                    if name.as_slice() == b"key" {
                        in_key = true;
                        key_buffer.clear();
                    } else if key_next_is_value && name.as_slice() == b"string" {
                        in_string = true;
                        string_buffer.clear();
                        pending_value_name = Some(name.clone());
                        value_depth = 1;
                    } else if key_next_is_value {
                        mark_selected_xml_not_string(
                            &mut selected,
                            pending_key.as_deref(),
                            context.metadata_read_mode,
                        )?;
                        pending_key = None;
                        key_next_is_value = false;
                        pending_value_name = Some(name.clone());
                        value_depth = 1;
                    }
                    if key_next_is_value && !in_string {
                        key_next_is_value = false;
                    }
                }
            }
            Event::Empty(empty) => {
                depth += 1;
                nodes += 1;
                if depth > context.limits.max_xml_depth || nodes > context.limits.max_xml_nodes {
                    return Err(AppError::new(
                        AppIssueCode::PlistParseLimit,
                        "XML plist structural limits exceeded",
                    ));
                }
                let name = empty.name().as_ref().to_vec();
                if depth == 1 {
                    if name.as_slice() != b"plist" {
                        return Err(AppError::new(
                            AppIssueCode::MalformedPlist,
                            "XML root is not plist",
                        ));
                    }
                    if root_seen {
                        return Err(AppError::new(
                            AppIssueCode::MalformedPlist,
                            "multiple plist roots are not allowed",
                        ));
                    }
                    root_seen = true;
                    root_closed = true;
                } else if depth == 2 {
                    if name.as_slice() != b"dict" {
                        return Err(AppError::new(
                            AppIssueCode::MalformedPlist,
                            "plist root must contain one dict",
                        ));
                    }
                    in_root_dict = true;
                    root_dict_closed = true;
                } else if in_root_dict
                    && value_depth == 0
                    && key_next_is_value
                    && !in_string
                    && !in_key
                {
                    mark_selected_xml_not_string(
                        &mut selected,
                        pending_key.as_deref(),
                        context.metadata_read_mode,
                    )?;
                    pending_key = None;
                    key_next_is_value = false;
                }
                depth = depth.saturating_sub(1);
            }
            Event::Text(text) => {
                if !in_root_dict || (!in_key && value_depth == 0) {
                    buffer.clear();
                    continue;
                }
                if in_key {
                    let key = decode_xml_text(text.as_ref())?;
                    charge_xml_text_budget(&key_buffer, &key, context.limits)?;
                    key_buffer.push_str(&key);
                } else if in_string && key_next_is_value {
                    let value = decode_xml_text(text.as_ref())?;
                    charge_xml_text_budget(&string_buffer, &value, context.limits)?;
                    string_buffer.push_str(&value);
                }
            }
            Event::CData(cdata) => {
                if !in_root_dict || (!in_key && value_depth == 0) {
                    buffer.clear();
                    continue;
                }
                let value = std::str::from_utf8(cdata.as_ref()).map_err(|_| {
                    AppError::new(AppIssueCode::MalformedPlist, "invalid CDATA UTF-8")
                })?;
                if in_key {
                    charge_xml_text_budget(&key_buffer, value, context.limits)?;
                    key_buffer.push_str(value);
                } else if in_string && key_next_is_value {
                    charge_xml_text_budget(&string_buffer, value, context.limits)?;
                    string_buffer.push_str(value);
                }
            }
            Event::GeneralRef(value) => {
                let name = value.as_ref();
                let decoded = decode_xml_general_ref(name)?;
                if in_key {
                    charge_xml_text_budget(&key_buffer, &decoded, context.limits)?;
                    key_buffer.push_str(&decoded);
                } else if in_string && key_next_is_value {
                    charge_xml_text_budget(&string_buffer, &decoded, context.limits)?;
                    string_buffer.push_str(&decoded);
                }
            }
            Event::End(end) => {
                let name = end.name().as_ref().to_vec();
                if in_root_dict {
                    if value_depth == 0 && name.as_slice() == b"key" {
                        in_key = false;
                        pending_key = Some(std::mem::take(&mut key_buffer));
                        key_next_is_value = true;
                    } else if in_string && name.as_slice() == b"string" {
                        in_string = false;
                        if key_next_is_value
                            && pending_value_name
                                .as_deref()
                                .is_some_and(|value| value == b"string")
                        {
                            if let Some(key) = pending_key.take() {
                                set_selected_xml_field(
                                    &mut selected,
                                    &key,
                                    &string_buffer,
                                    context.metadata_read_mode,
                                    context.limits,
                                    budget,
                                )?;
                            }
                            key_next_is_value = false;
                        }
                        string_buffer.clear();
                    }
                    if value_depth > 0 {
                        value_depth = value_depth.saturating_sub(1);
                        if value_depth == 0 {
                            pending_value_name = None;
                            if !in_string {
                                pending_key = None;
                            }
                        }
                    }
                }
                if depth == 2 && name.as_slice() == b"dict" {
                    root_dict_closed = true;
                }
                if depth == 1 && name.as_slice() == b"plist" {
                    root_closed = true;
                }
                depth = depth.saturating_sub(1);
            }
            Event::DocType(value) => {
                let text = std::str::from_utf8(value.as_ref())
                    .map_err(|_| {
                        AppError::new(AppIssueCode::MalformedPlist, "invalid XML doctype")
                    })?
                    .trim();
                let allowed = text
                    == "plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"";
                if !allowed || text.contains('[') {
                    return Err(AppError::new(
                        AppIssueCode::MalformedPlist,
                        "unsupported XML doctype",
                    ));
                }
            }
            Event::Decl(_) | Event::Comment(_) | Event::PI(_) => {}
            Event::Eof => break,
        }
        buffer.clear();
    }

    if !root_seen
        || !in_root_dict
        || !root_dict_closed
        || !root_closed
        || depth != 0
        || value_depth != 0
        || key_next_is_value
    {
        return Err(AppError::new(
            AppIssueCode::MalformedPlist,
            "incomplete plist XML structure",
        ));
    }

    Ok(parsed_from_selected(PlistFormat::Xml, selected))
}

fn decode_xml_text(raw: &[u8]) -> Result<String, AppError> {
    let text = std::str::from_utf8(raw)
        .map_err(|_| AppError::new(AppIssueCode::MalformedPlist, "invalid UTF-8 text"))?;
    let mut output = String::new();
    let mut rest = text;
    while let Some(pos) = rest.find('&') {
        output.push_str(&rest[..pos]);
        let suffix = &rest[pos + 1..];
        let semi = suffix.find(';').ok_or_else(|| {
            AppError::new(AppIssueCode::MalformedPlist, "unterminated XML entity")
        })?;
        let entity = &suffix[..semi];
        let ch = decode_xml_entity(entity)?;
        output.push(ch);
        rest = &suffix[semi + 1..];
    }
    output.push_str(rest);
    Ok(output)
}

fn decode_xml_general_ref(raw: &[u8]) -> Result<String, AppError> {
    let entity = std::str::from_utf8(raw)
        .map_err(|_| AppError::new(AppIssueCode::MalformedPlist, "unsupported XML entity"))?;
    Ok(decode_xml_entity(entity)?.to_string())
}

fn decode_xml_entity(entity: &str) -> Result<char, AppError> {
    match entity {
        "lt" => Ok('<'),
        "gt" => Ok('>'),
        "amp" => Ok('&'),
        "apos" => Ok('\''),
        "quot" => Ok('"'),
        _ if entity.starts_with("#x") || entity.starts_with("#X") => {
            let code = u32::from_str_radix(&entity[2..], 16).map_err(|_| {
                AppError::new(AppIssueCode::MalformedPlist, "invalid XML character entity")
            })?;
            char::from_u32(code)
                .filter(|ch| is_valid_xml_scalar(*ch))
                .ok_or_else(|| AppError::new(AppIssueCode::MalformedPlist, "invalid XML scalar"))
        }
        _ if entity.starts_with('#') => {
            let code = entity[1..].parse::<u32>().map_err(|_| {
                AppError::new(AppIssueCode::MalformedPlist, "invalid XML character entity")
            })?;
            char::from_u32(code)
                .filter(|ch| is_valid_xml_scalar(*ch))
                .ok_or_else(|| AppError::new(AppIssueCode::MalformedPlist, "invalid XML scalar"))
        }
        _ => Err(AppError::new(
            AppIssueCode::MalformedPlist,
            "unsupported XML entity",
        )),
    }
}

fn is_valid_xml_scalar(ch: char) -> bool {
    matches!(
        ch as u32,
        0x9 | 0xA | 0xD | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF
    )
}

fn charge_xml_text_budget(
    existing: &str,
    segment: &str,
    limits: AppInventoryLimits,
) -> Result<(), AppError> {
    let total = existing
        .len()
        .checked_add(segment.len())
        .ok_or_else(|| AppError::new(AppIssueCode::PlistParseLimit, "XML text length overflow"))?;
    if total > limits.max_string_bytes {
        return Err(AppError::new(
            AppIssueCode::PlistParseLimit,
            "XML selected string exceeds per-field budget",
        ));
    }
    Ok(())
}

fn mark_selected_xml_not_string(
    selected: &mut HashMap<&'static str, StringField>,
    key: Option<&str>,
    read_mode: AppInventoryMetadataReadMode,
) -> Result<(), AppError> {
    let Some(key) = key else {
        return Ok(());
    };
    let Some(name) = selected_key_index(key, read_mode) else {
        return Ok(());
    };
    if selected.contains_key(name) {
        return Err(AppError::new(
            AppIssueCode::MalformedPlist,
            "duplicate selected key in plist dictionary",
        ));
    }
    selected.insert(
        name,
        StringField {
            state: StringState::NotString,
            value: None,
        },
    );
    Ok(())
}

fn set_selected_xml_field(
    selected: &mut HashMap<&'static str, StringField>,
    key: &str,
    value: &str,
    read_mode: AppInventoryMetadataReadMode,
    limits: AppInventoryLimits,
    budget: &mut ProbeBudget,
) -> Result<(), AppError> {
    let target = selected_key_index(key, read_mode);
    let Some(name) = target else {
        return Ok(());
    };
    if selected.contains_key(name) {
        return Err(AppError::new(
            AppIssueCode::MalformedPlist,
            "duplicate selected key in plist dictionary",
        ));
    }
    if value.len() > limits.max_string_bytes {
        selected.insert(
            name,
            StringField {
                state: StringState::TooLong,
                value: None,
            },
        );
        return Ok(());
    }
    budget.charge_retained(value.len(), limits)?;
    selected.insert(
        name,
        StringField {
            state: StringState::Present,
            value: Some(value.to_owned()),
        },
    );
    Ok(())
}

fn selected_key_index(key: &str, read_mode: AppInventoryMetadataReadMode) -> Option<&'static str> {
    match key {
        "CFBundleDisplayName" => Some("CFBundleDisplayName"),
        "CFBundleName" => Some("CFBundleName"),
        "CFBundleIdentifier" => Some("CFBundleIdentifier"),
        "CFBundleShortVersionString" => Some("CFBundleShortVersionString"),
        "CFBundleVersion" => Some("CFBundleVersion"),
        "CFBundlePackageType" => Some("CFBundlePackageType"),
        "CrProductDirName" if read_mode == AppInventoryMetadataReadMode::AppRelated => {
            Some("CrProductDirName")
        }
        "CFBundleExecutable" => Some("CFBundleExecutable"),
        _ => None,
    }
}

fn parsed_from_selected(
    format: PlistFormat,
    selected: HashMap<&'static str, StringField>,
) -> ParsedPlist {
    let mut parsed = missing_fields(format);
    parsed.display_name = selected
        .get("CFBundleDisplayName")
        .cloned()
        .unwrap_or(parsed.display_name);
    parsed.bundle_name = selected
        .get("CFBundleName")
        .cloned()
        .unwrap_or(parsed.bundle_name);
    parsed.bundle_id = selected
        .get("CFBundleIdentifier")
        .cloned()
        .unwrap_or(parsed.bundle_id);
    parsed.short_version = selected
        .get("CFBundleShortVersionString")
        .cloned()
        .unwrap_or(parsed.short_version);
    parsed.build_version = selected
        .get("CFBundleVersion")
        .cloned()
        .unwrap_or(parsed.build_version);
    parsed.package_type = selected
        .get("CFBundlePackageType")
        .cloned()
        .unwrap_or(parsed.package_type);
    parsed.cr_product_dir_name = selected
        .get("CrProductDirName")
        .cloned()
        .unwrap_or(parsed.cr_product_dir_name);
    parsed.executable = selected
        .get("CFBundleExecutable")
        .cloned()
        .unwrap_or(parsed.executable);
    parsed
}

fn parse_binary_plist(
    bytes: &[u8],
    context: ProbeContext<'_>,
    budget: &mut ProbeBudget,
) -> Result<ParsedPlist, AppError> {
    if bytes.len() < 40 {
        return Err(AppError::new(
            AppIssueCode::MalformedPlist,
            "binary plist too short",
        ));
    }
    if !bytes.starts_with(b"bplist00") {
        return Err(AppError::new(
            AppIssueCode::UnsupportedPlistFormat,
            "unsupported binary plist magic",
        ));
    }
    let trailer = &bytes[bytes.len() - 32..];
    let offset_size = trailer[6] as usize;
    let object_ref_size = trailer[7] as usize;
    if offset_size == 0 || object_ref_size == 0 || offset_size > 8 || object_ref_size > 8 {
        return Err(AppError::new(
            AppIssueCode::MalformedPlist,
            "invalid binary plist trailer",
        ));
    }
    let object_count = be_u64(trailer, 8)? as usize;
    let top_object = be_u64(trailer, 16)? as usize;
    let offset_table_start = be_u64(trailer, 24)? as usize;
    if object_count == 0 || object_count > context.limits.max_plist_objects {
        return Err(AppError::new(
            AppIssueCode::PlistParseLimit,
            "binary plist object limit exceeded",
        ));
    }
    if top_object >= object_count {
        return Err(AppError::new(
            AppIssueCode::MalformedPlist,
            "invalid top object index",
        ));
    }
    let table_bytes = object_count
        .checked_mul(offset_size)
        .ok_or_else(|| AppError::new(AppIssueCode::MalformedPlist, "offset table overflow"))?;
    let table_end = offset_table_start
        .checked_add(table_bytes)
        .ok_or_else(|| AppError::new(AppIssueCode::MalformedPlist, "offset table overflow"))?;
    if table_end > bytes.len() - 32 {
        return Err(AppError::new(
            AppIssueCode::MalformedPlist,
            "offset table outside binary plist bounds",
        ));
    }

    let mut offsets = Vec::with_capacity(object_count);
    for i in 0..object_count {
        context.check()?;
        let at = offset_table_start + i * offset_size;
        let value = read_be_uint(bytes, at, offset_size)? as usize;
        if value >= offset_table_start {
            return Err(AppError::new(
                AppIssueCode::MalformedPlist,
                "object offset points into offset table or trailer",
            ));
        }
        offsets.push(value);
    }

    let mut selected: HashMap<&'static str, StringField> = HashMap::new();
    decode_top_dict(
        bytes,
        &offsets,
        top_object,
        object_ref_size,
        context,
        budget,
        &mut selected,
    )?;

    Ok(parsed_from_selected(PlistFormat::Binary, selected))
}

fn be_u64(bytes: &[u8], offset: usize) -> Result<u64, AppError> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| AppError::new(AppIssueCode::MalformedPlist, "offset overflow"))?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| AppError::new(AppIssueCode::MalformedPlist, "out of bounds read"))?;
    Ok(u64::from_be_bytes(slice.try_into().expect("fixed")))
}

fn read_be_uint(bytes: &[u8], offset: usize, size: usize) -> Result<u64, AppError> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| AppError::new(AppIssueCode::MalformedPlist, "offset overflow"))?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| AppError::new(AppIssueCode::MalformedPlist, "out of bounds read"))?;
    let mut output = 0u64;
    for byte in slice {
        output = output
            .checked_shl(8)
            .ok_or_else(|| AppError::new(AppIssueCode::MalformedPlist, "integer overflow"))?;
        output |= u64::from(*byte);
    }
    Ok(output)
}

fn decode_length(
    bytes: &[u8],
    offsets: &[usize],
    object: usize,
    low_nibble: u8,
    context: ProbeContext<'_>,
    budget: &mut ProbeBudget,
) -> Result<(usize, usize), AppError> {
    let start = offsets[object];
    if low_nibble < 0x0f {
        return Ok((usize::from(low_nibble), 1));
    }
    let marker = *bytes
        .get(start + 1)
        .ok_or_else(|| AppError::new(AppIssueCode::MalformedPlist, "missing length marker"))?;
    let ty = marker >> 4;
    if ty != 0x1 {
        return Err(AppError::new(
            AppIssueCode::MalformedPlist,
            "extended length marker is not integer",
        ));
    }
    let size_pow = usize::from(marker & 0x0f);
    if size_pow > 3 {
        return Err(AppError::new(
            AppIssueCode::MalformedPlist,
            "extended length integer too large",
        ));
    }
    let size = 1usize << size_pow;
    let value = read_be_uint(bytes, start + 2, size)?;
    let len = usize::try_from(value)
        .map_err(|_| AppError::new(AppIssueCode::PlistParseLimit, "plist length is too large"))?;
    budget.visit_ref(context.limits)?;
    Ok((len, 2 + size))
}

fn decode_string(
    bytes: &[u8],
    offsets: &[usize],
    object: usize,
    context: ProbeContext<'_>,
    budget: &mut ProbeBudget,
) -> Result<Option<String>, AppError> {
    context.check()?;
    budget.visit_ref(context.limits)?;
    let start = offsets[object];
    let marker = *bytes.get(start).ok_or_else(|| {
        AppError::new(AppIssueCode::MalformedPlist, "object marker out of bounds")
    })?;
    let ty = marker >> 4;
    let low = marker & 0x0f;
    match ty {
        0x5 => {
            let (len, header) = decode_length(bytes, offsets, object, low, context, budget)?;
            if len > context.limits.max_string_bytes {
                return Ok(None);
            }
            let from = start + header;
            let to = from
                .checked_add(len)
                .ok_or_else(|| AppError::new(AppIssueCode::MalformedPlist, "string overflow"))?;
            let raw = bytes.get(from..to).ok_or_else(|| {
                AppError::new(AppIssueCode::MalformedPlist, "string out of bounds")
            })?;
            let value = std::str::from_utf8(raw)
                .map_err(|_| {
                    AppError::new(AppIssueCode::MalformedPlist, "invalid ASCII plist string")
                })?
                .to_owned();
            budget.charge_retained(value.len(), context.limits)?;
            Ok(Some(value))
        }
        0x6 => {
            let (len, header) = decode_length(bytes, offsets, object, low, context, budget)?;
            if len > context.limits.max_string_bytes {
                return Ok(None);
            }
            let byte_len = len.checked_mul(2).ok_or_else(|| {
                AppError::new(AppIssueCode::MalformedPlist, "UTF-16 length overflow")
            })?;
            let from = start + header;
            let to = from
                .checked_add(byte_len)
                .ok_or_else(|| AppError::new(AppIssueCode::MalformedPlist, "UTF-16 overflow"))?;
            let raw = bytes.get(from..to).ok_or_else(|| {
                AppError::new(AppIssueCode::MalformedPlist, "UTF-16 out of bounds")
            })?;
            let mut units = Vec::with_capacity(len);
            for chunk in raw.chunks_exact(2) {
                units.push(u16::from_be_bytes([chunk[0], chunk[1]]));
            }
            let value = String::from_utf16(&units).map_err(|_| {
                AppError::new(AppIssueCode::MalformedPlist, "invalid UTF-16 plist string")
            })?;
            budget.charge_retained(value.len(), context.limits)?;
            Ok(Some(value))
        }
        0x7 => Err(AppError::new(
            AppIssueCode::UnsupportedPlistFormat,
            "binary plist UTF-8 string marker is unsupported in this slice",
        )),
        _ => Ok(None),
    }
}

fn decode_top_dict(
    bytes: &[u8],
    offsets: &[usize],
    object: usize,
    object_ref_size: usize,
    context: ProbeContext<'_>,
    budget: &mut ProbeBudget,
    selected: &mut HashMap<&'static str, StringField>,
) -> Result<(), AppError> {
    budget.visit_ref(context.limits)?;
    let start = offsets[object];
    let marker = *bytes
        .get(start)
        .ok_or_else(|| AppError::new(AppIssueCode::MalformedPlist, "top object out of bounds"))?;
    if marker >> 4 != 0xD {
        return Err(AppError::new(
            AppIssueCode::MalformedPlist,
            "top object is not a dictionary",
        ));
    }
    let (count, header) = decode_length(bytes, offsets, object, marker & 0x0f, context, budget)?;
    let keys_start = start + header;
    let refs_len = count
        .checked_mul(object_ref_size)
        .ok_or_else(|| AppError::new(AppIssueCode::MalformedPlist, "dictionary refs overflow"))?;
    let values_start = keys_start
        .checked_add(refs_len)
        .ok_or_else(|| AppError::new(AppIssueCode::MalformedPlist, "dictionary refs overflow"))?;
    let values_end = values_start
        .checked_add(refs_len)
        .ok_or_else(|| AppError::new(AppIssueCode::MalformedPlist, "dictionary refs overflow"))?;
    if values_end > bytes.len() {
        return Err(AppError::new(
            AppIssueCode::MalformedPlist,
            "dictionary references out of bounds",
        ));
    }

    for idx in 0..count {
        context.check()?;
        if idx > context.limits.max_plist_refs_visited {
            return Err(AppError::new(
                AppIssueCode::PlistParseLimit,
                "plist key iteration limit exceeded",
            ));
        }
        let key_ref =
            read_be_uint(bytes, keys_start + idx * object_ref_size, object_ref_size)? as usize;
        let value_ref =
            read_be_uint(bytes, values_start + idx * object_ref_size, object_ref_size)? as usize;
        if key_ref >= offsets.len() || value_ref >= offsets.len() {
            return Err(AppError::new(
                AppIssueCode::MalformedPlist,
                "dictionary object reference out of bounds",
            ));
        }
        let Some(key) = decode_string(bytes, offsets, key_ref, context, budget)? else {
            continue;
        };
        let Some(slot) = selected_key_index(&key, context.metadata_read_mode) else {
            continue;
        };
        if selected.contains_key(slot) {
            return Err(AppError::new(
                AppIssueCode::MalformedPlist,
                "duplicate selected key in plist dictionary",
            ));
        }
        let value = decode_string(bytes, offsets, value_ref, context, budget)?;
        match value {
            Some(value) => {
                if value.len() > context.limits.max_string_bytes {
                    selected.insert(
                        slot,
                        StringField {
                            state: StringState::TooLong,
                            value: None,
                        },
                    );
                } else {
                    selected.insert(
                        slot,
                        StringField {
                            state: StringState::Present,
                            value: Some(value),
                        },
                    );
                }
            }
            None => {
                selected.insert(
                    slot,
                    StringField {
                        state: StringState::NotString,
                        value: None,
                    },
                );
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
struct InspectedBundle {
    policy: Option<sayaka_platform_macos::ReadOnlyPolicy>,
    root_path: PathBuf,
    root_baseline: FileStamp,
    dir_chain: Vec<DirCheckpoint>,
    bundle_name: Option<OsString>,
    contents_name: OsString,
    macos_name: OsString,
    info_name: OsString,
    bundle_fd: rustix::fd::OwnedFd,
    contents_fd: rustix::fd::OwnedFd,
    info_fd: rustix::fd::OwnedFd,
    macos_fd: Option<rustix::fd::OwnedFd>,
    bundle_baseline: FileStamp,
    contents_baseline: FileStamp,
    info_baseline: FileStamp,
    macos_baseline: Option<FileStamp>,
    executable_observation: Option<ExecutableObservation>,
}

#[cfg(not(target_os = "macos"))]
struct InspectedBundle;

#[cfg(target_os = "macos")]
#[derive(Clone)]
enum ExecutableObservation {
    Missing(OsString),
    Present { name: OsString, stamp: FileStamp },
}

#[cfg(target_os = "macos")]
#[derive(Clone)]
struct DirCheckpoint {
    name: OsString,
    baseline: FileStamp,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    identity: FileIdentity,
    kind: ResourceKind,
    flags: u32,
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
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
    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::from_bits_retain(0x2000_0000)
}

#[cfg(target_os = "macos")]
fn map_errno(error: rustix::io::Errno, context: &str) -> AppError {
    let io = std::io::Error::from_raw_os_error(error.raw_os_error());
    let code = if error == rustix::io::Errno::LOOP {
        AppIssueCode::LinkSkipped
    } else if io.kind() == std::io::ErrorKind::PermissionDenied {
        AppIssueCode::PermissionDenied
    } else if io.kind() == std::io::ErrorKind::NotFound {
        AppIssueCode::NotFound
    } else {
        AppIssueCode::Internal
    };
    AppError::new(code, format!("{context}: {io}")).with_os(io.raw_os_error())
}

#[cfg(target_os = "macos")]
fn stamp_from_stat(stat: &rustix::fs::Stat) -> Result<FileStamp, AppError> {
    let kind = match stat.st_mode & libc::S_IFMT {
        libc::S_IFREG => ResourceKind::File,
        libc::S_IFDIR => ResourceKind::Directory,
        libc::S_IFLNK => ResourceKind::Link,
        _ => ResourceKind::Other,
    };
    Ok(FileStamp {
        identity: FileIdentity::Unix {
            device: u64::from(stat.st_dev.cast_unsigned()),
            inode: stat.st_ino,
        },
        kind,
        flags: stat.st_flags,
        size: u64::try_from(stat.st_size)
            .map_err(|_| AppError::new(AppIssueCode::Internal, "negative stat size"))?,
        mtime: (stat.st_mtime, stat.st_mtime_nsec),
        ctime: (stat.st_ctime, stat.st_ctime_nsec),
    })
}

#[cfg(target_os = "macos")]
fn dataless(stat: &rustix::fs::Stat) -> bool {
    stat.st_flags & 0x4000_0000 != 0
}

#[cfg(target_os = "macos")]
impl InspectedBundle {
    fn open(
        entry: &ScanEntry,
        root: &Path,
        root_identity: FileIdentity,
        relative: &Path,
        ancestors: &[(PathBuf, FileIdentity)],
    ) -> Result<Self, AppError> {
        use rustix::fs::{self, Mode};
        use sayaka_platform_macos::ReadOnlyPolicy;

        let mut policy = Some(ReadOnlyPolicy::enter().map_err(|error| {
            AppError::new(
                AppIssueCode::PolicyFailure,
                format!("read-only policy setup failed: {error}"),
            )
        })?);
        let opened = (|| {
            if !valid_absolute_path(root) || root.parent().is_none() {
                return Err(AppError::new(
                    AppIssueCode::InvalidInput,
                    "root must be a non-root absolute path",
                ));
            }
            let root_fd = fs::open(root, directory_flags(), Mode::empty())
                .map_err(|error| map_errno(error, "open root"))?;
            let root_stat = fs::fstat(&root_fd).map_err(|error| map_errno(error, "stat root"))?;
            let root_stamp = stamp_from_stat(&root_stat)?;
            if root_stamp.kind != ResourceKind::Directory
                || root_stamp.identity != root_identity
                || dataless(&root_stat)
            {
                return Err(AppError::new(
                    AppIssueCode::Changed,
                    "root changed since scan",
                ));
            }

            let mut current = root_fd;
            let mut chain = Vec::with_capacity(ancestors.len());
            for (name, identity) in ancestors {
                if name.components().count() != 1 {
                    return Err(AppError::new(
                        AppIssueCode::InvalidInput,
                        "invalid ancestor component",
                    ));
                }
                let fd = fs::openat(&current, name, directory_flags(), Mode::empty())
                    .map_err(|error| map_errno(error, "open ancestor"))?;
                let stat = fs::fstat(&fd).map_err(|error| map_errno(error, "stat ancestor"))?;
                let stamp = stamp_from_stat(&stat)?;
                if stamp.kind != ResourceKind::Directory
                    || stamp.identity != *identity
                    || dataless(&stat)
                {
                    return Err(AppError::new(
                        AppIssueCode::Changed,
                        "ancestor changed since scan",
                    ));
                }
                chain.push(DirCheckpoint {
                    name: name.as_os_str().to_os_string(),
                    baseline: stamp,
                });
                current = fd;
            }

            let direct_root_bundle = relative.as_os_str().is_empty();
            let bundle_name = if direct_root_bundle {
                None
            } else {
                Some(
                    relative
                        .file_name()
                        .ok_or_else(|| {
                            AppError::new(AppIssueCode::InvalidInput, "missing app bundle filename")
                        })?
                        .to_os_string(),
                )
            };
            let bundle_fd = if let Some(name) = &bundle_name {
                fs::openat(&current, name, directory_flags(), Mode::empty())
                    .map_err(|error| map_errno(error, "open app bundle"))?
            } else {
                current
            };
            let bundle_stat =
                fs::fstat(&bundle_fd).map_err(|error| map_errno(error, "stat app bundle"))?;
            let bundle_stamp = stamp_from_stat(&bundle_stat)?;
            if bundle_stamp.kind != ResourceKind::Directory
                || bundle_stamp.identity != entry.identity
            {
                return Err(AppError::new(
                    AppIssueCode::Changed,
                    "app bundle changed since scan",
                ));
            }
            if dataless(&bundle_stat) {
                return Err(AppError::new(
                    AppIssueCode::CloudOrDataless,
                    "app bundle is dataless",
                ));
            }

            let contents_name = OsString::from("Contents");
            let contents_fd =
                fs::openat(&bundle_fd, &contents_name, directory_flags(), Mode::empty())
                    .map_err(|error| map_errno(error, "open Contents"))?;
            let contents_stat =
                fs::fstat(&contents_fd).map_err(|error| map_errno(error, "stat Contents"))?;
            let contents_stamp = stamp_from_stat(&contents_stat)?;
            if contents_stamp.kind != ResourceKind::Directory || dataless(&contents_stat) {
                return Err(AppError::new(
                    AppIssueCode::Changed,
                    "Contents changed or unavailable",
                ));
            }

            let info_name = OsString::from("Info.plist");
            let info_fd = fs::openat(&contents_fd, &info_name, file_flags(), Mode::empty())
                .map_err(|error| map_errno(error, "open Contents/Info.plist"))?;
            let info_stat =
                fs::fstat(&info_fd).map_err(|error| map_errno(error, "stat Info.plist"))?;
            let info_stamp = stamp_from_stat(&info_stat)?;
            if info_stamp.kind != ResourceKind::File || dataless(&info_stat) {
                return Err(AppError::new(
                    AppIssueCode::Changed,
                    "Info.plist changed or unavailable",
                ));
            }

            Ok(Self {
                policy: policy.take(),
                root_path: root.to_path_buf(),
                root_baseline: root_stamp,
                dir_chain: chain,
                bundle_name,
                contents_name,
                macos_name: OsString::from("MacOS"),
                info_name,
                bundle_fd,
                contents_fd,
                info_fd,
                macos_fd: None,
                bundle_baseline: bundle_stamp,
                contents_baseline: contents_stamp,
                info_baseline: info_stamp,
                macos_baseline: None,
                executable_observation: None,
            })
        })();

        match opened {
            Ok(value) => Ok(value),
            Err(primary) => {
                let Some(policy) = policy else {
                    return Err(primary);
                };
                let restored = policy.restore().map_err(|error| {
                    AppError::new(
                        AppIssueCode::PolicyFailure,
                        format!("read-only policy restore failed: {error}"),
                    )
                });
                match restored {
                    Ok(()) => Err(primary),
                    Err(restore) => Err(AppError::new(
                        AppIssueCode::PolicyFailure,
                        format!("{}; {}", primary.message, restore.message),
                    )),
                }
            }
        }
    }

    fn read_info_plist(
        &mut self,
        context: ProbeContext<'_>,
        budget: &mut ProbeBudget,
    ) -> Result<Vec<u8>, AppError> {
        use rustix::io::pread;
        context.check()?;
        if self.info_baseline.size > context.limits.max_info_plist_bytes {
            return Err(AppError::new(
                AppIssueCode::PlistSizeLimit,
                "Info.plist exceeds per-file size limit",
            ));
        }
        budget.preflight_io(self.info_baseline.size, context.limits)?;
        let len = usize::try_from(self.info_baseline.size)
            .map_err(|_| AppError::new(AppIssueCode::PlistParseLimit, "Info.plist too large"))?;
        let mut output = vec![0u8; len];
        let mut filled = 0usize;
        const CHUNK: usize = 64 * 1024;
        while filled < len {
            context.check()?;
            let next = filled + (len - filled).min(CHUNK);
            let read = pread(
                &self.info_fd,
                &mut output[filled..next],
                u64::try_from(filled)
                    .map_err(|_| AppError::new(AppIssueCode::PlistParseLimit, "offset overflow"))?,
            )
            .map_err(|error| map_errno(error, "read Info.plist"))?;
            if read == 0 {
                return Err(AppError::new(
                    AppIssueCode::MalformedPlist,
                    "unexpected end of Info.plist",
                ));
            }
            budget.charge_io(
                u64::try_from(read)
                    .map_err(|_| AppError::new(AppIssueCode::PlistParseLimit, "read overflow"))?,
                context.limits,
            )?;
            filled += read;
        }
        self.check_unchanged()?;
        Ok(output)
    }

    fn stat_executable(&mut self, name: &str) -> Result<PathStatus, AppError> {
        use rustix::fs::{self, AtFlags, Mode};
        let macos_stat = match fs::statat(
            &self.contents_fd,
            &self.macos_name,
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(stat) => stat,
            Err(error) => {
                let mapped = if error == rustix::io::Errno::NOENT {
                    AppError::new(AppIssueCode::NotFound, "Contents/MacOS missing")
                } else {
                    map_errno(error, "stat Contents/MacOS")
                };
                return match mapped.code {
                    AppIssueCode::NotFound => Ok(PathStatus::Missing),
                    AppIssueCode::LinkSkipped => Ok(PathStatus::NotFollowedSymlink),
                    _ => Err(mapped),
                };
            }
        };
        let macos_stamp = stamp_from_stat(&macos_stat)?;
        if macos_stamp.kind == ResourceKind::Link {
            return Ok(PathStatus::NotFollowedSymlink);
        }
        if macos_stamp.kind != ResourceKind::Directory || dataless(&macos_stat) {
            return Ok(PathStatus::PresentNonFile);
        }
        let macos_fd = fs::openat(
            &self.contents_fd,
            &self.macos_name,
            directory_flags(),
            Mode::empty(),
        )
        .map_err(|error| map_errno(error, "open Contents/MacOS"))?;
        let held_macos_stat =
            fs::fstat(&macos_fd).map_err(|error| map_errno(error, "stat Contents/MacOS"))?;
        if stamp_from_stat(&held_macos_stat)? != macos_stamp || dataless(&held_macos_stat) {
            return Err(AppError::new(
                AppIssueCode::Changed,
                "Contents/MacOS changed during inspection",
            ));
        }
        self.macos_baseline = Some(macos_stamp);
        self.macos_fd = Some(macos_fd);
        let stat = match fs::statat(
            self.macos_fd.as_ref().expect("macOS fd present"),
            Path::new(name),
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(stat) => stat,
            Err(error) => {
                let mapped = if error == rustix::io::Errno::NOENT {
                    AppError::new(AppIssueCode::NotFound, "declared executable missing")
                } else {
                    map_errno(error, "stat declared executable")
                };
                return match mapped.code {
                    AppIssueCode::NotFound => {
                        self.executable_observation =
                            Some(ExecutableObservation::Missing(OsString::from(name)));
                        Ok(PathStatus::Missing)
                    }
                    AppIssueCode::LinkSkipped => Ok(PathStatus::NotFollowedSymlink),
                    _ => Err(mapped),
                };
            }
        };
        let stamp = stamp_from_stat(&stat)?;
        let name = OsString::from(name);
        self.executable_observation = Some(ExecutableObservation::Present { name, stamp });
        Ok(match stamp.kind {
            ResourceKind::File => PathStatus::PresentFile,
            ResourceKind::Link => PathStatus::NotFollowedSymlink,
            _ => PathStatus::PresentNonFile,
        })
    }

    fn finish(mut self) -> Result<(), AppError> {
        let validation = self.check_unchanged();
        let restored = self
            .policy
            .take()
            .expect("policy initialized")
            .restore()
            .map_err(|error| {
                AppError::new(
                    AppIssueCode::PolicyFailure,
                    format!("read-only policy restore failed: {error}"),
                )
            });
        match (validation, restored) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) => Err(error),
            (Ok(()), Err(error)) => Err(error),
            (Err(primary), Err(restore)) => Err(AppError::new(
                AppIssueCode::PolicyFailure,
                format!("{}; {}", primary.message, restore.message),
            )),
        }
    }

    fn check_unchanged(&self) -> Result<(), AppError> {
        use rustix::fs::{self, Mode};
        let root_fd = fs::open(&self.root_path, directory_flags(), Mode::empty())
            .map_err(|error| map_errno(error, "reopen root"))?;
        let root_stat = fs::fstat(&root_fd).map_err(|error| map_errno(error, "restat root"))?;
        let root_stamp = stamp_from_stat(&root_stat)?;
        if root_stamp != self.root_baseline || dataless(&root_stat) {
            return Err(AppError::new(
                AppIssueCode::Changed,
                "root changed during inspection",
            ));
        }

        let mut current = root_fd;
        for checkpoint in &self.dir_chain {
            let fd = fs::openat(&current, &checkpoint.name, directory_flags(), Mode::empty())
                .map_err(|error| map_errno(error, "reopen ancestor"))?;
            let stat = fs::fstat(&fd).map_err(|error| map_errno(error, "restat ancestor"))?;
            let stamp = stamp_from_stat(&stat)?;
            if stamp != checkpoint.baseline || dataless(&stat) {
                return Err(AppError::new(
                    AppIssueCode::Changed,
                    "ancestor changed during inspection",
                ));
            }
            current = fd;
        }

        let remapped_bundle = if let Some(bundle_name) = &self.bundle_name {
            fs::openat(&current, bundle_name, directory_flags(), Mode::empty())
                .map_err(|error| map_errno(error, "reopen app bundle"))?
        } else {
            current
        };
        let remapped_bundle_stat =
            fs::fstat(&remapped_bundle).map_err(|error| map_errno(error, "restat app bundle"))?;
        let remapped_bundle_stamp = stamp_from_stat(&remapped_bundle_stat)?;
        if remapped_bundle_stamp != self.bundle_baseline || dataless(&remapped_bundle_stat) {
            return Err(AppError::new(
                AppIssueCode::Changed,
                "app bundle path changed during inspection",
            ));
        }
        let remapped_contents = fs::openat(
            &remapped_bundle,
            &self.contents_name,
            directory_flags(),
            Mode::empty(),
        )
        .map_err(|error| map_errno(error, "reopen Contents"))?;
        let remapped_contents_stat =
            fs::fstat(&remapped_contents).map_err(|error| map_errno(error, "restat Contents"))?;
        let remapped_contents_stamp = stamp_from_stat(&remapped_contents_stat)?;
        if remapped_contents_stamp != self.contents_baseline || dataless(&remapped_contents_stat) {
            return Err(AppError::new(
                AppIssueCode::Changed,
                "Contents path changed during inspection",
            ));
        }

        let info_stat =
            fs::fstat(&self.info_fd).map_err(|error| map_errno(error, "restat Info.plist"))?;
        let info_stamp = stamp_from_stat(&info_stat)?;
        if info_stamp != self.info_baseline || dataless(&info_stat) {
            return Err(AppError::new(
                AppIssueCode::Changed,
                "Info.plist changed during inspection",
            ));
        }

        let remapped_info = fs::openat(
            &remapped_contents,
            &self.info_name,
            file_flags(),
            Mode::empty(),
        )
        .map_err(|error| map_errno(error, "reopen Info.plist"))?;
        let remapped_info_stat =
            fs::fstat(&remapped_info).map_err(|error| map_errno(error, "restat Info.plist"))?;
        let remapped_info_stamp = stamp_from_stat(&remapped_info_stat)?;
        if remapped_info_stamp != self.info_baseline || dataless(&remapped_info_stat) {
            return Err(AppError::new(
                AppIssueCode::Changed,
                "Info.plist path changed during inspection",
            ));
        }
        if let Some(macos_baseline) = self.macos_baseline {
            let held_macos_stat = fs::fstat(self.macos_fd.as_ref().expect("macOS fd present"))
                .map_err(|error| map_errno(error, "restat held Contents/MacOS"))?;
            if stamp_from_stat(&held_macos_stat)? != macos_baseline || dataless(&held_macos_stat) {
                return Err(AppError::new(
                    AppIssueCode::Changed,
                    "held Contents/MacOS changed during inspection",
                ));
            }
            let remapped_macos = fs::openat(
                &remapped_contents,
                &self.macos_name,
                directory_flags(),
                Mode::empty(),
            )
            .map_err(|error| map_errno(error, "reopen Contents/MacOS"))?;
            let remapped_macos_stat = fs::fstat(&remapped_macos)
                .map_err(|error| map_errno(error, "restat Contents/MacOS"))?;
            if stamp_from_stat(&remapped_macos_stat)? != macos_baseline
                || dataless(&remapped_macos_stat)
            {
                return Err(AppError::new(
                    AppIssueCode::Changed,
                    "Contents/MacOS path changed during inspection",
                ));
            }
            if let Some(observation) = &self.executable_observation {
                match observation {
                    ExecutableObservation::Missing(missing) => {
                        match fs::statat(
                            self.macos_fd.as_ref().expect("macOS fd present"),
                            missing,
                            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                        ) {
                            Ok(_) => {
                                return Err(AppError::new(
                                    AppIssueCode::Changed,
                                    "declared executable appeared during inspection",
                                ));
                            }
                            Err(error) if error == rustix::io::Errno::NOENT => {}
                            Err(error) => {
                                return Err(map_errno(error, "restat declared executable"));
                            }
                        }
                        match fs::statat(
                            &remapped_macos,
                            missing,
                            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                        ) {
                            Ok(_) => {
                                return Err(AppError::new(
                                    AppIssueCode::Changed,
                                    "declared executable path changed during inspection",
                                ));
                            }
                            Err(error) if error == rustix::io::Errno::NOENT => {}
                            Err(error) => {
                                return Err(map_errno(error, "restat declared executable path"));
                            }
                        }
                    }
                    ExecutableObservation::Present { name, stamp } => {
                        let held_leaf = fs::statat(
                            self.macos_fd.as_ref().expect("macOS fd present"),
                            name,
                            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                        )
                        .map_err(|error| map_errno(error, "restat declared executable"))?;
                        if stamp_from_stat(&held_leaf)? != *stamp || dataless(&held_leaf) {
                            return Err(AppError::new(
                                AppIssueCode::Changed,
                                "declared executable changed during inspection",
                            ));
                        }
                        let remapped_leaf = fs::statat(
                            &remapped_macos,
                            name,
                            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                        )
                        .map_err(|error| map_errno(error, "restat declared executable path"))?;
                        if stamp_from_stat(&remapped_leaf)? != *stamp || dataless(&remapped_leaf) {
                            return Err(AppError::new(
                                AppIssueCode::Changed,
                                "declared executable path changed during inspection",
                            ));
                        }
                    }
                }
            }
        }

        let bundle_stat =
            fs::fstat(&self.bundle_fd).map_err(|error| map_errno(error, "restat held bundle"))?;
        if stamp_from_stat(&bundle_stat)? != self.bundle_baseline {
            return Err(AppError::new(
                AppIssueCode::Changed,
                "held app bundle changed during inspection",
            ));
        }
        let contents_stat = fs::fstat(&self.contents_fd)
            .map_err(|error| map_errno(error, "restat held Contents"))?;
        if stamp_from_stat(&contents_stat)? != self.contents_baseline {
            return Err(AppError::new(
                AppIssueCode::Changed,
                "held Contents changed during inspection",
            ));
        }
        Ok(())
    }
}

#[cfg(not(target_os = "macos"))]
impl InspectedBundle {
    fn open(
        _entry: &ScanEntry,
        _root: &Path,
        _root_identity: FileIdentity,
        _relative: &Path,
        _ancestors: &[(PathBuf, FileIdentity)],
    ) -> Result<Self, AppError> {
        Err(AppError::new(
            AppIssueCode::UnsupportedPlatform,
            "native macOS app inspection is unavailable on this platform",
        ))
    }

    fn read_info_plist(
        &mut self,
        _context: ProbeContext<'_>,
        _budget: &mut ProbeBudget,
    ) -> Result<Vec<u8>, AppError> {
        Err(AppError::new(
            AppIssueCode::UnsupportedPlatform,
            "native macOS app inspection is unavailable on this platform",
        ))
    }

    fn stat_executable(&mut self, _name: &str) -> Result<PathStatus, AppError> {
        Ok(PathStatus::NotChecked)
    }

    fn finish(self) -> Result<(), AppError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::{ScanEntry, ScanMetrics, ScanReport, ScanStatus, ScanTaskId, ScanTotals};
    use std::fs;
    #[cfg(target_os = "macos")]
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, OnceLock};

    #[cfg(target_os = "macos")]
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn running_observation_matches_only_resolved_present_executables() {
        let root = tempfile::tempdir().expect("tempdir");
        let bundle = root.path().join("Fixture.app");
        let macos = bundle.join("Contents").join("MacOS");
        fs::create_dir_all(&macos).expect("create app tree");
        fs::write(macos.join("Run"), b"inert").expect("write executable");
        let resolved = fs::canonicalize(macos.join("Run")).expect("canonicalize");
        let mut running = std::collections::HashMap::new();
        running.insert(resolved, vec![4242_u32, 4343_u32]);

        let present = ExecutableMetadata {
            state: StringState::Present,
            declared_value: Some("Run".into()),
            path_status: PathStatus::PresentFile,
        };
        assert_eq!(
            running_observation(&bundle, &present, &running),
            RunningObservation::Running(vec![4242, 4343])
        );

        let empty: std::collections::HashMap<PathBuf, Vec<u32>> = std::collections::HashMap::new();
        assert_eq!(
            running_observation(&bundle, &present, &empty),
            RunningObservation::NotRunning
        );

        for (state, declared, status) in [
            (StringState::Missing, None, PathStatus::NotChecked),
            (
                StringState::Present,
                Some("Run".into()),
                PathStatus::Missing,
            ),
            (
                StringState::Present,
                Some("Run".into()),
                PathStatus::NotFollowedSymlink,
            ),
            (StringState::NotString, None, PathStatus::NotChecked),
        ] {
            let metadata = ExecutableMetadata {
                state,
                declared_value: declared,
                path_status: status,
            };
            assert!(
                matches!(
                    running_observation(&bundle, &metadata, &running),
                    RunningObservation::NotAttributable(_)
                ),
                "{state:?}/{status:?} must not be attributable"
            );
        }

        let ghost = ExecutableMetadata {
            state: StringState::Present,
            declared_value: Some("Ghost".into()),
            path_status: PathStatus::PresentFile,
        };
        assert!(matches!(
            running_observation(&bundle, &ghost, &running),
            RunningObservation::NotAttributable(_)
        ));
    }

    #[test]
    fn failed_running_enumeration_marks_every_record_unknown() {
        // Non-macOS hosts exercise the native-failure fallback directly;
        // the macOS success path is covered by manual smoke instead.
        #[cfg(not(target_os = "macos"))]
        {
            let mut apps = vec![unknown_record(
                PathBuf::from("/nonexistent/Fixture.app"),
                FileIdentity::Unix {
                    device: 1,
                    inode: 1,
                },
            )];
            attribute_running_state(&mut apps);
            assert_eq!(apps[0].running, RunningObservation::Unknown);
        }
    }

    fn parse_xml_for_test(xml: &[u8]) -> ParsedPlist {
        parse_xml_for_mode(xml, AppInventoryMetadataReadMode::Baseline)
    }

    fn parse_xml_for_mode(
        xml: &[u8],
        metadata_read_mode: AppInventoryMetadataReadMode,
    ) -> ParsedPlist {
        let cancellation = Cancellation::default();
        let context = ProbeContext {
            cancellation: &cancellation,
            deadline: Instant::now() + Duration::from_secs(1),
            limits: AppInventoryLimits::default(),
            metadata_read_mode,
            now: wall_clock_now,
        };
        let mut budget = ProbeBudget::default();
        parse_xml_plist(xml, context, &mut budget).expect("xml parse")
    }

    fn parse_xml_error_for_test(xml: &[u8]) -> AppError {
        let cancellation = Cancellation::default();
        let context = ProbeContext {
            cancellation: &cancellation,
            deadline: Instant::now() + Duration::from_secs(1),
            limits: AppInventoryLimits::default(),
            metadata_read_mode: AppInventoryMetadataReadMode::Baseline,
            now: wall_clock_now,
        };
        let mut budget = ProbeBudget::default();
        match parse_xml_plist(xml, context, &mut budget) {
            Ok(_) => panic!("expected XML parser error"),
            Err(error) => error,
        }
    }

    fn parse_binary_for_mode(
        bytes: &[u8],
        metadata_read_mode: AppInventoryMetadataReadMode,
    ) -> ParsedPlist {
        let cancellation = Cancellation::default();
        let context = ProbeContext {
            cancellation: &cancellation,
            deadline: Instant::now() + Duration::from_secs(1),
            limits: AppInventoryLimits::default(),
            metadata_read_mode,
            now: wall_clock_now,
        };
        let mut budget = ProbeBudget::default();
        parse_binary_plist(bytes, context, &mut budget).expect("binary parse")
    }

    fn single_entry_binary_plist(key: &str, value: &str) -> Vec<u8> {
        let mut objects = Vec::new();
        objects.push(vec![0xD1, 0x01, 0x02]);

        let mut key_object = Vec::new();
        if key.len() < 0x0f {
            key_object.push(0x50 | key.len() as u8);
        } else {
            key_object.extend([0x5f, 0x10, key.len() as u8]);
        }
        key_object.extend(key.as_bytes());
        objects.push(key_object);

        let mut value_object = Vec::new();
        if value.len() < 0x0f {
            value_object.push(0x50 | value.len() as u8);
        } else {
            value_object.extend([0x5f, 0x10, value.len() as u8]);
        }
        value_object.extend(value.as_bytes());
        objects.push(value_object);

        let mut bytes = b"bplist00".to_vec();
        let mut offsets = Vec::new();
        for object in objects {
            offsets.push(bytes.len() as u8);
            bytes.extend(object);
        }
        let offset_table_start = bytes.len();
        bytes.extend(offsets);

        let mut trailer = [0u8; 32];
        trailer[6] = 1;
        trailer[7] = 1;
        trailer[8..16].copy_from_slice(&3u64.to_be_bytes());
        trailer[16..24].copy_from_slice(&0u64.to_be_bytes());
        trailer[24..32].copy_from_slice(&(offset_table_start as u64).to_be_bytes());
        bytes.extend(trailer);
        bytes
    }

    fn synthetic_entry(path: &str, identity: FileIdentity) -> ScanEntry {
        ScanEntry {
            id: 0,
            path: PathBuf::from(path),
            kind: ResourceKind::Directory,
            identity,
            logical_bytes: None,
            allocated_bytes: None,
            dataless: false,
            counted: false,
            depth: 0,
        }
    }

    #[cfg(target_os = "macos")]
    fn scan_entry(path: &Path, kind: ResourceKind, id: u64) -> ScanEntry {
        let meta = fs::symlink_metadata(path).expect("metadata");
        ScanEntry {
            id,
            path: path.to_path_buf(),
            kind,
            identity: FileIdentity::Unix {
                device: meta.dev(),
                inode: meta.ino(),
            },
            logical_bytes: None,
            allocated_bytes: None,
            dataless: false,
            counted: false,
            depth: 0,
        }
    }

    #[cfg(target_os = "macos")]
    fn test_report(root: &Path, app: &Path) -> ScanReport {
        ScanReport {
            task_id: ScanTaskId::synthetic(7),
            roots: vec![root.to_path_buf()],
            status: ScanStatus::Complete,
            complete: true,
            entries: vec![
                scan_entry(root, ResourceKind::Directory, 1),
                scan_entry(app, ResourceKind::Directory, 2),
            ],
            issues: vec![],
            issues_omitted: 0,
            totals: ScanTotals::default(),
            metrics: ScanMetrics::default(),
        }
    }

    #[cfg(target_os = "macos")]
    #[derive(Clone, Copy)]
    struct ScriptClock {
        origin: Instant,
        step_ms: u64,
    }

    #[cfg(target_os = "macos")]
    static SCRIPT_CLOCK: OnceLock<Mutex<Option<ScriptClock>>> = OnceLock::new();
    #[cfg(target_os = "macos")]
    static SCRIPT_TICKS: AtomicU64 = AtomicU64::new(0);

    #[cfg(target_os = "macos")]
    fn scripted_now() -> Instant {
        let cell = SCRIPT_CLOCK.get_or_init(|| Mutex::new(None));
        let guard = cell.lock().expect("clock lock");
        let script = guard.expect("script clock configured");
        let tick = SCRIPT_TICKS.fetch_add(1, Ordering::Relaxed);
        script.origin + Duration::from_millis(script.step_ms.saturating_mul(tick))
    }

    #[test]
    fn executable_path_validation_rejects_nested_components() {
        assert!(valid_single_component_executable("run"));
        assert!(!valid_single_component_executable("../run"));
        assert!(!valid_single_component_executable("foo/bar"));
        assert!(!valid_single_component_executable(""));
    }

    #[test]
    fn single_bundle_identifier_read_is_honest() {
        let root = tempfile::tempdir().expect("tempdir");
        let bundle = root.path().join("Demo.app");
        let macos = bundle.join("Contents").join("MacOS");
        std::fs::create_dir_all(&macos).expect("tree");
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.example.demo</string>
</dict></plist>"#;
        std::fs::write(bundle.join("Contents").join("Info.plist"), xml).expect("plist");
        match read_bundle_identifier(&bundle) {
            BundleIdentifierRead::Parsed(field) => {
                assert_eq!(field.state, StringState::Present);
                assert_eq!(field.value.as_deref(), Some("com.example.demo"));
            }
            BundleIdentifierRead::Unreadable(reason) => panic!("expected a parsed field: {reason}"),
        }
        // A missing plist is an explicit unreadable state, never a guess.
        let bare = root.path().join("Bare.app");
        std::fs::create_dir_all(bare.join("Contents")).expect("tree");
        assert!(matches!(
            read_bundle_identifier(&bare),
            BundleIdentifierRead::Unreadable(_)
        ));
    }

    #[test]
    fn xml_parser_extracts_selected_fields() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleDisplayName</key><string>Example</string>
<key>CFBundleIdentifier</key><string>com.example.demo</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleExecutable</key><string>Demo</string>
</dict></plist>"#;
        let parsed = parse_xml_for_test(xml);
        assert_eq!(parsed.display_name.value.as_deref(), Some("Example"));
        assert_eq!(parsed.bundle_id.value.as_deref(), Some("com.example.demo"));
        assert_eq!(parsed.package_type.value.as_deref(), Some("APPL"));
        assert_eq!(parsed.executable.value.as_deref(), Some("Demo"));
    }

    #[test]
    fn cr_product_dir_name_is_opt_in_for_related_mode_xml() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CrProductDirName</key><string>Google/Chrome</string>
</dict></plist>"#;
        let baseline = parse_xml_for_mode(xml, AppInventoryMetadataReadMode::Baseline);
        assert_eq!(baseline.cr_product_dir_name.state, StringState::Missing);
        let related = parse_xml_for_mode(xml, AppInventoryMetadataReadMode::AppRelated);
        assert_eq!(
            related.cr_product_dir_name.value.as_deref(),
            Some("Google/Chrome")
        );
    }

    #[test]
    fn cr_product_dir_name_is_opt_in_for_related_mode_binary() {
        let binary = single_entry_binary_plist("CrProductDirName", "Google/Chrome");
        let baseline = parse_binary_for_mode(&binary, AppInventoryMetadataReadMode::Baseline);
        assert_eq!(baseline.cr_product_dir_name.state, StringState::Missing);
        let related = parse_binary_for_mode(&binary, AppInventoryMetadataReadMode::AppRelated);
        assert_eq!(
            related.cr_product_dir_name.value.as_deref(),
            Some("Google/Chrome")
        );
    }

    #[test]
    fn cr_product_dir_name_respects_selected_string_bounds() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CrProductDirName</key><integer>1</integer>
</dict></plist>"#;
        let related = parse_xml_for_mode(xml, AppInventoryMetadataReadMode::AppRelated);
        assert_eq!(related.cr_product_dir_name.state, StringState::NotString);
        let baseline = parse_xml_for_mode(xml, AppInventoryMetadataReadMode::Baseline);
        assert_eq!(baseline.cr_product_dir_name.state, StringState::Missing);
    }

    #[test]
    fn xml_parser_marks_selected_non_string_types() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleDisplayName</key><integer>1</integer>
<key>CFBundleName</key><true/>
<key>CFBundleIdentifier</key><data>QQ==</data>
<key>CFBundleShortVersionString</key><array><string>1</string></array>
<key>CFBundleVersion</key><dict><key>a</key><string>b</string></dict>
</dict></plist>"#;
        let parsed = parse_xml_for_test(xml);
        assert_eq!(parsed.display_name.state, StringState::NotString);
        assert_eq!(parsed.bundle_name.state, StringState::NotString);
        assert_eq!(parsed.bundle_id.state, StringState::NotString);
        assert_eq!(parsed.short_version.state, StringState::NotString);
        assert_eq!(parsed.build_version.state, StringState::NotString);
    }

    #[test]
    fn xml_parser_handles_cdata_for_selected_key_and_value() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key><![CDATA[CFBundlePackageType]]></key><string><![CDATA[APPL]]></string>
</dict></plist>"#;
        let parsed = parse_xml_for_test(xml);
        assert_eq!(parsed.package_type.value.as_deref(), Some("APPL"));
        assert_eq!(parsed.package_type.state, StringState::Present);
    }

    #[test]
    fn xml_parser_decodes_general_refs_and_preserves_spaces() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleDisplayName</key><string>A &amp; B</string>
<key>CFBundleI<![CDATA[dent]]>ifier</key><string>com.example&#x3A9;&#169;</string>
<key>CFBundleName</key><string><![CDATA[Left ]]>&lt;&gt;&quot;&apos;&#937;<![CDATA[ Right]]></string>
</dict></plist>"#;
        let parsed = parse_xml_for_test(xml);
        assert_eq!(parsed.display_name.value.as_deref(), Some("A & B"));
        assert_eq!(parsed.bundle_id.value.as_deref(), Some("com.exampleΩ©"));
        assert_eq!(
            parsed.bundle_name.value.as_deref(),
            Some("Left <>\"'Ω Right")
        );
    }

    #[test]
    fn xml_parser_rejects_invalid_or_unsupported_general_refs() {
        let custom = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>CFBundleName</key><string>&custom;</string></dict></plist>"#;
        let nul = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>CFBundleName</key><string>&#0;</string></dict></plist>"#;
        let bad_num = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>CFBundleName</key><string>&#x110000;</string></dict></plist>"#;
        for xml in [&custom[..], &nul[..], &bad_num[..]] {
            let error = parse_xml_error_for_test(xml);
            assert_eq!(error.code, AppIssueCode::MalformedPlist);
        }
    }

    #[test]
    fn xml_general_ref_budget_counts_decoded_chars() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleDisplayName</key><string>A &amp; B</string>
</dict></plist>"#;
        let cancellation = Cancellation::default();
        let limits = AppInventoryLimits {
            max_string_bytes: 4,
            ..AppInventoryLimits::default()
        };
        let context = ProbeContext {
            cancellation: &cancellation,
            deadline: Instant::now() + Duration::from_secs(1),
            limits,
            metadata_read_mode: AppInventoryMetadataReadMode::Baseline,
            now: wall_clock_now,
        };
        let mut budget = ProbeBudget::default();
        let error = match parse_xml_plist(xml, context, &mut budget) {
            Ok(_) => panic!("expected parse-limit error"),
            Err(error) => error,
        };
        assert_eq!(error.code, AppIssueCode::PlistParseLimit);
    }

    #[test]
    fn exclusion_matcher_handles_prefix_identity_and_empty_cases() {
        let id_a = FileIdentity::Unix {
            device: 1,
            inode: 10,
        };
        let id_b = FileIdentity::Unix {
            device: 1,
            inode: 20,
        };
        let id_c = FileIdentity::Unix {
            device: 1,
            inode: 30,
        };
        let entries = vec![
            synthetic_entry("/roots/Alias.app", id_a),
            synthetic_entry("/roots/Copy.app", id_a),
            synthetic_entry("/roots/Exact.app", id_b),
            synthetic_entry("/roots/Other.app", id_c),
        ];
        let cancellation = Cancellation::default();
        let context = ProbeContext {
            cancellation: &cancellation,
            deadline: Instant::now() + Duration::from_secs(1),
            limits: AppInventoryLimits::default(),
            metadata_read_mode: AppInventoryMetadataReadMode::Baseline,
            now: wall_clock_now,
        };
        let excludes = vec![
            PathBuf::from("/roots/Alias.app"),
            PathBuf::from("/roots/Exact.app/Contents"),
        ];
        let matcher = ExclusionMatcher::build(&entries, &excludes, context).expect("build matcher");
        assert!(matcher.contains(&entries[0]), "direct prefix excluded");
        assert!(
            matcher.contains(&entries[1]),
            "identity alias excluded from single pass identity set"
        );
        assert!(matcher.contains(&entries[2]), "prefix descendant excluded");
        assert!(
            !matcher.contains(&entries[3]),
            "nonexcluded entry preserved"
        );

        let context = ProbeContext {
            cancellation: &cancellation,
            deadline: Instant::now() + Duration::from_secs(1),
            limits: AppInventoryLimits::default(),
            metadata_read_mode: AppInventoryMetadataReadMode::Baseline,
            now: wall_clock_now,
        };
        let empty = ExclusionMatcher::build(&entries, &[], context).expect("empty matcher");
        assert!(!empty.contains(&entries[0]));
        assert!(!empty.contains(&entries[3]));
    }

    #[test]
    fn collect_excluded_identities_scans_entries_once() {
        let entries = (0..256usize)
            .map(|index| {
                synthetic_entry(
                    &format!("/roots/Item{index}.app"),
                    FileIdentity::Unix {
                        device: 2,
                        inode: 100 + index as u64,
                    },
                )
            })
            .collect::<Vec<_>>();
        let excludes = vec![
            PathBuf::from("/roots/Item1.app"),
            PathBuf::from("/roots/Item2.app"),
        ];
        let mut seen = 0usize;
        let cancellation = Cancellation::default();
        let context = ProbeContext {
            cancellation: &cancellation,
            deadline: Instant::now() + Duration::from_secs(1),
            limits: AppInventoryLimits::default(),
            metadata_read_mode: AppInventoryMetadataReadMode::Baseline,
            now: wall_clock_now,
        };
        let identities = collect_excluded_identities(&entries, &excludes, context, || {
            seen = seen.saturating_add(1);
        })
        .expect("collect identities");
        assert_eq!(seen, entries.len());
        assert_eq!(identities.len(), 2);
    }

    #[test]
    fn xml_parser_detects_duplicate_selected_keys_even_with_type_mismatch() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>one</string>
<key>CFBundleIdentifier</key><integer>2</integer>
</dict></plist>"#;
        let cancellation = Cancellation::default();
        let context = ProbeContext {
            cancellation: &cancellation,
            deadline: Instant::now() + Duration::from_secs(1),
            limits: AppInventoryLimits::default(),
            metadata_read_mode: AppInventoryMetadataReadMode::Baseline,
            now: wall_clock_now,
        };
        let mut budget = ProbeBudget::default();
        match parse_xml_plist(xml, context, &mut budget) {
            Ok(_) => panic!("duplicate key must be rejected"),
            Err(error) => assert_eq!(error.code, AppIssueCode::MalformedPlist),
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn inventory_timeout_budget_stops_metadata_without_unbudgeted_reads() {
        let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .canonicalize()
            .expect("canonical crate root");
        let repo_root = crate_root
            .parent()
            .and_then(|p| p.parent())
            .expect("repo root")
            .to_path_buf();
        let root = repo_root.join("target/apps-timeout-budget-test");
        let app = root.join("Timeout.app");
        let contents = app.join("Contents");
        let macos = contents.join("MacOS");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&macos).expect("create app tree");
        fs::write(
            contents.join("Info.plist"),
            br#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundlePackageType</key><string>APPL</string></dict></plist>"#,
        )
        .expect("write plist");
        fs::write(macos.join("Timeout"), b"inert").expect("write executable");

        let report = test_report(&root, &app);
        {
            let cell = SCRIPT_CLOCK.get_or_init(|| Mutex::new(None));
            let mut guard = cell.lock().expect("clock lock");
            *guard = Some(ScriptClock {
                origin: Instant::now(),
                step_ms: 2,
            });
        }
        SCRIPT_TICKS.store(0, Ordering::Relaxed);

        let cancellation = Cancellation::default();
        let result = inventory_apps_with_now(
            report,
            &AppInventoryOptions {
                filter: String::new(),
                excludes: vec![],
                limits: AppInventoryLimits::default(),
                metadata_read_mode: AppInventoryMetadataReadMode::Baseline,
                running_attribution: false,
            },
            &cancellation,
            Duration::from_millis(1),
            scripted_now,
        );

        let _ = fs::remove_dir_all(&root);
        assert!(
            result
                .issues
                .iter()
                .any(|issue| issue.code == AppIssueCode::DurationLimit),
            "issues: {:?}",
            result.issues
        );
        assert_eq!(
            result.status,
            AppInventoryStatus::Partial,
            "issues: {:?}",
            result.issues
        );
        assert_eq!(result.counts.inspected_candidates, 1);
        assert_eq!(result.counts.unknown, 1);
        assert_eq!(result.metrics.plist_read_bytes, 0);
    }

    #[test]
    fn binary_parser_rejects_invalid_offsets() {
        let mut bytes = b"bplist00".to_vec();
        bytes.resize(64, 0);
        let trailer_start = bytes.len() - 32;
        bytes[trailer_start + 6] = 1;
        bytes[trailer_start + 7] = 1;
        bytes[trailer_start + 8..trailer_start + 16].copy_from_slice(&1u64.to_be_bytes());
        bytes[trailer_start + 16..trailer_start + 24].copy_from_slice(&0u64.to_be_bytes());
        bytes[trailer_start + 24..trailer_start + 32].copy_from_slice(&60u64.to_be_bytes());
        let cancellation = Cancellation::default();
        let context = ProbeContext {
            cancellation: &cancellation,
            deadline: Instant::now() + Duration::from_secs(1),
            limits: AppInventoryLimits::default(),
            metadata_read_mode: AppInventoryMetadataReadMode::Baseline,
            now: wall_clock_now,
        };
        let mut budget = ProbeBudget::default();
        assert!(parse_binary_plist(&bytes, context, &mut budget).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn missing_leaf_revalidation_detects_macos_directory_replacement() {
        let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .canonicalize()
            .expect("canonical crate root");
        let repo_root = crate_root
            .parent()
            .and_then(|p| p.parent())
            .expect("repo root")
            .to_path_buf();
        let root = repo_root.join("target/apps-macos-missing-leaf-race");
        let app = root.join("Race.app");
        let macos = app.join("Contents/MacOS");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&macos).expect("create MacOS");
        fs::write(
            app.join("Contents/Info.plist"),
            br#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleExecutable</key><string>Run</string></dict></plist>"#,
        )
        .expect("write plist");

        let root_entry = scan_entry(&root, ResourceKind::Directory, 1);
        let app_entry = scan_entry(&app, ResourceKind::Directory, 2);
        let relative = app
            .strip_prefix(&root)
            .expect("app relative to root")
            .to_path_buf();
        let mut inspected =
            InspectedBundle::open(&app_entry, &root, root_entry.identity, &relative, &[])
                .expect("open inspected bundle");
        assert_eq!(
            inspected
                .stat_executable("Run")
                .expect("missing leaf status"),
            PathStatus::Missing
        );

        fs::remove_dir(&macos).expect("remove MacOS");
        fs::create_dir_all(&macos).expect("recreate MacOS");

        let finish = inspected
            .finish()
            .expect_err("replacement should invalidate freshness");
        assert_eq!(finish.code, AppIssueCode::Changed);
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(target_os = "macos")]
    fn open_inspected_for_exec(root: &Path, app: &Path) -> InspectedBundle {
        let root_entry = scan_entry(root, ResourceKind::Directory, 1);
        let app_entry = scan_entry(app, ResourceKind::Directory, 2);
        let relative = app
            .strip_prefix(root)
            .expect("app relative to root")
            .to_path_buf();
        InspectedBundle::open(&app_entry, root, root_entry.identity, &relative, &[])
            .expect("open inspected bundle")
    }

    #[cfg(target_os = "macos")]
    fn write_exec_plist(app: &Path) {
        fs::write(
            app.join("Contents/Info.plist"),
            br#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleExecutable</key><string>Run</string></dict></plist>"#,
        )
        .expect("write plist");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn present_leaf_revalidation_detects_replacement_inode() {
        let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .canonicalize()
            .expect("canonical crate root");
        let repo_root = crate_root
            .parent()
            .and_then(|p| p.parent())
            .expect("repo root")
            .to_path_buf();
        let root = repo_root.join("target/apps-macos-present-leaf-replace");
        let app = root.join("Race.app");
        let macos = app.join("Contents/MacOS");
        let exec = macos.join("Run");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&macos).expect("create MacOS");
        write_exec_plist(&app);
        fs::write(&exec, b"one").expect("write executable");

        let mut inspected = open_inspected_for_exec(&root, &app);
        assert_eq!(
            inspected
                .stat_executable("Run")
                .expect("present leaf status"),
            PathStatus::PresentFile
        );

        fs::remove_file(&exec).expect("remove executable");
        fs::write(&exec, b"two").expect("replace executable");

        let finish = inspected
            .finish()
            .expect_err("replacement should invalidate");
        assert_eq!(finish.code, AppIssueCode::Changed);
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn present_leaf_revalidation_detects_removal_or_kind_change() {
        let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .canonicalize()
            .expect("canonical crate root");
        let repo_root = crate_root
            .parent()
            .and_then(|p| p.parent())
            .expect("repo root")
            .to_path_buf();
        let root = repo_root.join("target/apps-macos-present-leaf-removal");
        let app = root.join("Race.app");
        let macos = app.join("Contents/MacOS");
        let exec = macos.join("Run");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&macos).expect("create MacOS");
        write_exec_plist(&app);
        fs::write(&exec, b"one").expect("write executable");

        let mut inspected = open_inspected_for_exec(&root, &app);
        assert_eq!(
            inspected
                .stat_executable("Run")
                .expect("present leaf status"),
            PathStatus::PresentFile
        );
        fs::remove_file(&exec).expect("remove executable");
        let finish = inspected.finish().expect_err("missing should invalidate");
        assert_eq!(finish.code, AppIssueCode::Changed);

        fs::write(&exec, b"one").expect("restore executable");
        let mut inspected = open_inspected_for_exec(&root, &app);
        assert_eq!(
            inspected
                .stat_executable("Run")
                .expect("present leaf status"),
            PathStatus::PresentFile
        );
        fs::remove_file(&exec).expect("remove executable");
        fs::create_dir(&exec).expect("replace with directory");
        let finish = inspected.finish().expect_err("non-file should invalidate");
        assert_eq!(finish.code, AppIssueCode::Changed);
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn present_leaf_revalidation_detects_symlink_swap_and_symlink_changes() {
        let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .canonicalize()
            .expect("canonical crate root");
        let repo_root = crate_root
            .parent()
            .and_then(|p| p.parent())
            .expect("repo root")
            .to_path_buf();
        let root = repo_root.join("target/apps-macos-present-leaf-symlink");
        let app = root.join("Race.app");
        let macos = app.join("Contents/MacOS");
        let exec = macos.join("Run");
        let outside_a = root.join("outside-a");
        let outside_b = root.join("outside-b");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&macos).expect("create MacOS");
        fs::create_dir_all(&outside_a).expect("outside a");
        fs::create_dir_all(&outside_b).expect("outside b");
        write_exec_plist(&app);
        fs::write(&exec, b"one").expect("write executable");

        let mut inspected = open_inspected_for_exec(&root, &app);
        assert_eq!(
            inspected
                .stat_executable("Run")
                .expect("present leaf status"),
            PathStatus::PresentFile
        );
        fs::remove_file(&exec).expect("remove executable");
        symlink(&outside_a, &exec).expect("swap to symlink");
        let finish = inspected.finish().expect_err("symlink should invalidate");
        assert_eq!(finish.code, AppIssueCode::Changed);

        fs::remove_file(&exec).expect("remove symlink");
        symlink(&outside_a, &exec).expect("create symlink");
        let mut inspected = open_inspected_for_exec(&root, &app);
        assert_eq!(
            inspected.stat_executable("Run").expect("symlink observed"),
            PathStatus::NotFollowedSymlink
        );
        fs::remove_file(&exec).expect("remove symlink");
        symlink(&outside_b, &exec).expect("change symlink target");
        let finish = inspected
            .finish()
            .expect_err("symlink metadata change should invalidate");
        assert_eq!(finish.code, AppIssueCode::Changed);
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn unchanged_present_and_missing_observations_validate() {
        let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .canonicalize()
            .expect("canonical crate root");
        let repo_root = crate_root
            .parent()
            .and_then(|p| p.parent())
            .expect("repo root")
            .to_path_buf();
        let root = repo_root.join("target/apps-macos-present-missing-unchanged");
        let app = root.join("Race.app");
        let macos = app.join("Contents/MacOS");
        let exec = macos.join("Run");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&macos).expect("create MacOS");
        write_exec_plist(&app);
        fs::write(&exec, b"one").expect("write executable");

        let mut present = open_inspected_for_exec(&root, &app);
        assert_eq!(
            present.stat_executable("Run").expect("present status"),
            PathStatus::PresentFile
        );
        present.finish().expect("present unchanged must validate");

        fs::remove_file(&exec).expect("remove executable");
        let mut missing = open_inspected_for_exec(&root, &app);
        assert_eq!(
            missing.stat_executable("Run").expect("missing status"),
            PathStatus::Missing
        );
        missing.finish().expect("missing unchanged must validate");

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn missing_leaf_revalidation_detects_macos_symlink_swap() {
        let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .canonicalize()
            .expect("canonical crate root");
        let repo_root = crate_root
            .parent()
            .and_then(|p| p.parent())
            .expect("repo root")
            .to_path_buf();
        let root = repo_root.join("target/apps-macos-missing-leaf-symlink");
        let app = root.join("Race.app");
        let macos = app.join("Contents/MacOS");
        let outside = root.join("outside-sentinel");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&macos).expect("create MacOS");
        fs::create_dir_all(&outside).expect("create outside sentinel");
        fs::write(
            app.join("Contents/Info.plist"),
            br#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleExecutable</key><string>Run</string></dict></plist>"#,
        )
        .expect("write plist");

        let root_entry = scan_entry(&root, ResourceKind::Directory, 1);
        let app_entry = scan_entry(&app, ResourceKind::Directory, 2);
        let relative = app
            .strip_prefix(&root)
            .expect("app relative to root")
            .to_path_buf();
        let mut inspected =
            InspectedBundle::open(&app_entry, &root, root_entry.identity, &relative, &[])
                .expect("open inspected bundle");
        assert_eq!(
            inspected
                .stat_executable("Run")
                .expect("missing leaf status"),
            PathStatus::Missing
        );

        fs::remove_dir(&macos).expect("remove MacOS");
        symlink(&outside, &macos).expect("swap MacOS to symlink");

        let finish = inspected.finish().expect_err("symlink swap should fail");
        assert!(matches!(
            finish.code,
            AppIssueCode::Changed | AppIssueCode::LinkSkipped
        ));
        let _ = fs::remove_dir_all(&root);
    }
}
