// SPDX-License-Identifier: MPL-2.0

//! Read-only uninstall preview contract for one explicit `.app` bundle (T9).
//!
//! This module defines the evidence, protections and refusal surface that
//! the execution slice (`revalidated_bundle_trash_v1`,
//! docs/UNINSTALL_EXECUTION.md) consumes. It performs no effects itself: no
//! Trash, no deletion, no signals to processes; nothing here authorizes
//! removal.

use crate::app_inventory::{
    AppInventoryLimits, AppInventoryMetadataReadMode, AppInventoryOptions, AppInventoryStatus,
    BundleIdentifierRead, RunningObservation, StringState, inventory_apps, read_bundle_identifier,
    running_process_paths,
};
use crate::model::{Cancellation, FileIdentity};
use crate::scan::{ScanLimits, scan_prune_app_bundles};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Execution state published by every preview of this slice.
pub const EXECUTION_DEFERRED: &str = "deferred_contract";

/// Recovery statement published by every preview of this slice.
pub const RECOVERY_NOTE: &str = "the bundle moves to the user Trash; recovery is Finder 'Put Back', with no programmatic restore";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UninstallRefusalCode {
    NotFound,
    NotDirectory,
    NotAppBundle,
    SymlinkBundle,
    MissingInfoPlist,
    InfoPlistNotRegularFile,
    SystemLocation,
    NonLocalVolume,
    Running,
    UnsupportedPlatform,
    Internal,
}

impl UninstallRefusalCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::NotDirectory => "not_directory",
            Self::NotAppBundle => "not_app_bundle",
            Self::SymlinkBundle => "symlink_bundle",
            Self::MissingInfoPlist => "missing_info_plist",
            Self::InfoPlistNotRegularFile => "info_plist_not_regular_file",
            Self::SystemLocation => "system_location",
            Self::NonLocalVolume => "non_local_volume",
            Self::Running => "running",
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::Internal => "internal_error",
        }
    }
}

#[derive(Clone, Debug)]
pub struct UninstallRefusal {
    pub code: UninstallRefusalCode,
    pub message: String,
    pub os_code: Option<i32>,
}

impl UninstallRefusal {
    fn new(code: UninstallRefusalCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            os_code: None,
        }
    }

    fn os(code: UninstallRefusalCode, message: impl Into<String>, error: &std::io::Error) -> Self {
        Self {
            code,
            message: message.into(),
            os_code: error.raw_os_error(),
        }
    }
}

/// Bundle directory identity captured without following links.
#[derive(Clone, Debug)]
pub struct BundleIdentity {
    pub device: u64,
    pub inode: u64,
    pub logical_bytes: u64,
    pub modified: SystemTime,
}

/// Coexisting-copy observation states. A missing copy list is never
/// evidence that no other copy exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopiesStatus {
    /// No roots were supplied; nothing was searched.
    NotChecked,
    /// The target's own identifier could not be established, so no
    /// trustworthy comparison exists.
    NotAttributable,
    /// Copy observation currently requires macOS.
    UnsupportedPlatform,
    Complete,
    Partial,
    Cancelled,
    Failed,
}

impl CopiesStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotChecked => "not_checked",
            Self::NotAttributable => "not_attributable",
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
        }
    }
}

/// Published with every copies observation so a list of coexisting copies
/// can never be mistaken for a selection.
pub const COPIES_NOTE: &str = "coexisting copies are evidence only: an uninstall moves exactly the named bundle and never touches, signals or cleans up after any other copy";

/// One observed coexisting copy of the previewed bundle's identifier.
#[derive(Clone, Debug)]
pub struct CopyEvidence {
    pub bundle_path: PathBuf,
    pub observed_roots: Vec<PathBuf>,
    pub running: RunningObservation,
}

/// Read-only coexisting-copy observation for the previewed bundle.
#[derive(Clone, Debug)]
pub struct CopiesEvidence {
    pub status: CopiesStatus,
    pub reason: Option<&'static str>,
    /// The previewed bundle's own observed identifier, when attributable.
    pub target_bundle_id: Option<String>,
    pub requested_roots: Vec<PathBuf>,
    pub copies: Vec<CopyEvidence>,
    /// Effective budgets when a scan actually ran: the artifact scan keeps
    /// the engine's cooperative default capped by the caller budget, and
    /// the inventory metadata pass gets the caller budget.
    pub scan_budget_sec: Option<u64>,
    pub inventory_budget_sec: Option<u64>,
    pub note: &'static str,
}

impl CopiesEvidence {
    pub fn not_checked() -> Self {
        Self {
            status: CopiesStatus::NotChecked,
            reason: Some("no copies roots were given"),
            target_bundle_id: None,
            requested_roots: Vec::new(),
            copies: Vec::new(),
            scan_budget_sec: None,
            inventory_budget_sec: None,
            note: COPIES_NOTE,
        }
    }
}

/// Observes coexisting copies of the previewed bundle's identifier under
/// the explicitly given roots, using the bounded app-bundle scan and the
/// inventory's plist metadata and running attribution. Read-only: copies
/// are evidence, never targets, and the named bundle itself is excluded by
/// device/inode identity, not by path text.
pub fn observe_copies(
    preview: &UninstallPreview,
    roots: &[PathBuf],
    cancellation: &Cancellation,
    budget: Duration,
) -> CopiesEvidence {
    let requested_roots = roots.to_vec();
    let evidence =
        |status, reason, target_bundle_id, copies, scan_budget_sec, inventory_budget_sec| {
            CopiesEvidence {
                status,
                reason,
                target_bundle_id,
                requested_roots,
                copies,
                scan_budget_sec,
                inventory_budget_sec,
                note: COPIES_NOTE,
            }
        };
    if roots.is_empty() {
        return CopiesEvidence::not_checked();
    }
    if !cfg!(target_os = "macos") {
        return evidence(
            CopiesStatus::UnsupportedPlatform,
            Some("copy observation currently requires macOS"),
            None,
            Vec::new(),
            None,
            None,
        );
    }
    if preview.identity.is_none() {
        // Without the target's device/inode there is no trustworthy
        // exclusion, so the named bundle could be listed as its own copy.
        return evidence(
            CopiesStatus::NotAttributable,
            Some("the target bundle identity is unavailable"),
            None,
            Vec::new(),
            None,
            None,
        );
    }
    let target_bundle_id = match read_bundle_identifier(&preview.bundle_path) {
        BundleIdentifierRead::Parsed(crate::app_inventory::StringField {
            state: StringState::Present,
            value: Some(id),
        }) => id,
        BundleIdentifierRead::Parsed(field) => {
            let reason = match field.state {
                StringState::Missing => "the target bundle declares no bundle identifier",
                StringState::NotString => "the target bundle identifier is not a string",
                StringState::Duplicate => "the target bundle identifier is declared twice",
                StringState::TooLong => "the target bundle identifier exceeds the parser limit",
                StringState::Present => "the target bundle identifier is unavailable",
            };
            return evidence(
                CopiesStatus::NotAttributable,
                Some(reason),
                None,
                Vec::new(),
                None,
                None,
            );
        }
        BundleIdentifierRead::Unreadable(reason) => {
            return evidence(
                CopiesStatus::NotAttributable,
                Some(reason),
                None,
                Vec::new(),
                None,
                None,
            );
        }
    };
    let mut scan_limits = ScanLimits::default();
    scan_limits.time_budget = scan_limits.time_budget.min(budget);
    let report = match scan_prune_app_bundles(roots, &scan_limits, cancellation, |_| {}) {
        Ok(report) => report,
        Err(_) => {
            return evidence(
                CopiesStatus::Failed,
                Some("the coexisting-copies scan failed"),
                Some(target_bundle_id),
                Vec::new(),
                Some(scan_limits.time_budget.as_secs()),
                None,
            );
        }
    };
    let inventory = inventory_apps(
        report,
        &AppInventoryOptions {
            filter: String::new(),
            excludes: Vec::new(),
            limits: AppInventoryLimits::default(),
            metadata_read_mode: AppInventoryMetadataReadMode::Baseline,
            running_attribution: true,
        },
        cancellation,
        budget,
    );
    let status = match inventory.status {
        AppInventoryStatus::Complete => CopiesStatus::Complete,
        AppInventoryStatus::Partial => CopiesStatus::Partial,
        AppInventoryStatus::Cancelled => CopiesStatus::Cancelled,
        AppInventoryStatus::Failed => CopiesStatus::Failed,
    };
    let target_identity = preview
        .identity
        .as_ref()
        .map(|identity| FileIdentity::Unix {
            device: identity.device,
            inode: identity.inode,
        });
    let copies = inventory
        .apps
        .iter()
        .filter(|app| app.bundle_id.value.as_deref() == Some(target_bundle_id.as_str()))
        .filter(|app| Some(app.bundle_identity) != target_identity)
        .map(|app| CopyEvidence {
            bundle_path: app.bundle_path.clone(),
            observed_roots: app.observed_roots.clone(),
            running: app.running.clone(),
        })
        .collect();
    evidence(
        status,
        None,
        Some(target_bundle_id),
        copies,
        Some(scan_limits.time_budget.as_secs()),
        Some(budget.as_secs()),
    )
}

/// Read-only preview of uninstalling one explicit `.app` bundle.
#[derive(Clone, Debug)]
pub struct UninstallPreview {
    pub bundle_path: PathBuf,
    pub display_name: String,
    pub identity: Option<BundleIdentity>,
    /// Regular files observed directly under `Contents/MacOS` (nofollow).
    pub executables_observed: Option<usize>,
    pub running: RunningObservation,
    /// Coexisting copies of the same bundle identifier, observed only when
    /// the caller explicitly supplies roots; evidence, never targets.
    pub copies: CopiesEvidence,
    pub protections: Vec<&'static str>,
    pub recovery: &'static str,
    pub execution: &'static str,
    pub refusals: Vec<UninstallRefusal>,
}

impl UninstallPreview {
    /// This slice never authorizes execution; the field exists so callers
    /// cannot mistake a clean preview for approval.
    pub fn can_execute(&self) -> bool {
        false
    }
}

fn protections() -> Vec<&'static str> {
    vec![
        "related data, preferences, caches and credentials are never touched by this contract",
        "other copies of the same bundle ID are independent and never touched",
        "a running bundle is refused, never signaled or terminated",
        "no permanent deletion fallback exists after any failed Trash operation",
        "system locations (/System) are refused regardless of permissions",
    ]
}

fn base_preview(bundle_path: PathBuf) -> UninstallPreview {
    let display_name = bundle_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("(unknown)")
        .to_owned();
    UninstallPreview {
        bundle_path,
        display_name,
        identity: None,
        executables_observed: None,
        running: RunningObservation::NotChecked,
        copies: CopiesEvidence::not_checked(),
        protections: protections(),
        recovery: RECOVERY_NOTE,
        execution: EXECUTION_DEFERRED,
        refusals: Vec::new(),
    }
}

/// Captures the read-only uninstall preview for one explicit `.app` bundle.
/// Refusals are data, not errors; only internal failures abort the preview.
pub fn preview_bundle_uninstall(bundle: &Path) -> UninstallPreview {
    let absolute = std::path::absolute(bundle).unwrap_or_else(|_| bundle.to_path_buf());
    let mut preview = base_preview(absolute.clone());
    if absolute.starts_with("/System") {
        preview.refusals.push(UninstallRefusal::new(
            UninstallRefusalCode::SystemLocation,
            "system locations are never uninstall targets",
        ));
        // /System is a closed refusal boundary: no metadata, volume,
        // plist, executable or running inspection happens beneath it.
        return preview;
    }
    let metadata = match std::fs::symlink_metadata(&absolute) {
        Ok(metadata) => metadata,
        Err(error) => {
            let code = if error.kind() == std::io::ErrorKind::NotFound {
                UninstallRefusalCode::NotFound
            } else {
                UninstallRefusalCode::Internal
            };
            preview.refusals.push(UninstallRefusal::os(
                code,
                format!("cannot inspect {}: {error}", absolute.display()),
                &error,
            ));
            return preview;
        }
    };
    if metadata.file_type().is_symlink() {
        preview.refusals.push(UninstallRefusal::new(
            UninstallRefusalCode::SymlinkBundle,
            "the bundle path itself is a symbolic link and is never followed",
        ));
        return preview;
    }
    if !metadata.is_dir() {
        preview.refusals.push(UninstallRefusal::new(
            UninstallRefusalCode::NotDirectory,
            "the bundle path is not a directory",
        ));
        return preview;
    }
    if absolute
        .file_name()
        .and_then(|name| name.to_str())
        .is_none_or(|name| !name.ends_with(".app"))
    {
        preview.refusals.push(UninstallRefusal::new(
            UninstallRefusalCode::NotAppBundle,
            "the directory name does not end in .app",
        ));
    }
    preview.identity = Some(BundleIdentity {
        device: identity_device(&metadata),
        inode: identity_inode(&metadata),
        logical_bytes: metadata.len(),
        modified: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
    });
    match local_volume(&absolute) {
        Ok(true) => {}
        Ok(false) => preview.refusals.push(UninstallRefusal::new(
            UninstallRefusalCode::NonLocalVolume,
            "the bundle does not reside on a local volume",
        )),
        Err(error) => preview.refusals.push(UninstallRefusal::os(
            UninstallRefusalCode::Internal,
            format!("cannot verify the bundle volume: {error}"),
            &error,
        )),
    }
    let plist = absolute.join("Contents").join("Info.plist");
    match std::fs::symlink_metadata(&plist) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => preview.refusals.push(UninstallRefusal::new(
            UninstallRefusalCode::InfoPlistNotRegularFile,
            "Contents/Info.plist is not a regular file (links are not followed)",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            preview.refusals.push(UninstallRefusal::new(
                UninstallRefusalCode::MissingInfoPlist,
                "Contents/Info.plist is missing",
            ));
        }
        Err(error) => preview.refusals.push(UninstallRefusal::os(
            UninstallRefusalCode::Internal,
            format!("cannot inspect Contents/Info.plist: {error}"),
            &error,
        )),
    }
    observe_running(&mut preview, &absolute);
    preview
}

/// Public running observation for one bundle directory, reused by the
/// execution session's plan and last-native-guard checks. Fails closed:
/// anything but a proven absence yields Running, Unknown or
/// NotAttributable, never NotRunning.
pub fn bundle_running(bundle: &Path) -> RunningObservation {
    let macos_dir = bundle.join("Contents").join("MacOS");
    let entries = match std::fs::read_dir(&macos_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return RunningObservation::NotAttributable("no Contents/MacOS directory");
        }
        Err(_) => return RunningObservation::Unknown,
    };
    let mut executables = Vec::new();
    for entry in entries {
        let Ok(entry) = entry else {
            return RunningObservation::Unknown;
        };
        match entry.file_type() {
            Ok(kind) if kind.is_file() => executables.push(entry.path()),
            Ok(_) => {}
            Err(_) => return RunningObservation::Unknown,
        }
    }
    if executables.is_empty() {
        return RunningObservation::NotAttributable("no regular executable observed");
    }
    let running = match running_process_paths() {
        Ok(running) => running,
        Err(_) => return RunningObservation::Unknown,
    };
    // Every observed executable must resolve before "not running" holds.
    let mut resolved = Vec::with_capacity(executables.len());
    for executable in &executables {
        match std::fs::canonicalize(executable) {
            Ok(path) => resolved.push(path),
            Err(_) => {
                return RunningObservation::NotAttributable("executable path cannot be resolved");
            }
        }
    }
    let mut pids = Vec::new();
    for executable in &resolved {
        if let Some(found) = running.get(executable) {
            pids.extend(found.iter().copied());
        }
    }
    pids.sort_unstable();
    pids.dedup();
    if pids.is_empty() {
        RunningObservation::NotRunning
    } else {
        RunningObservation::Running(pids)
    }
}

/// Matches every regular file directly under `Contents/MacOS` against the
/// visible running processes. Any match refuses uninstall; an enumeration
/// failure is explicit Unknown, never "not running".
fn observe_running(preview: &mut UninstallPreview, bundle: &Path) {
    let macos_dir = bundle.join("Contents").join("MacOS");
    let entries = match std::fs::read_dir(&macos_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            preview.executables_observed = Some(0);
            preview.running = RunningObservation::NotAttributable("no Contents/MacOS directory");
            return;
        }
        Err(error) => {
            preview.running = RunningObservation::Unknown;
            preview.refusals.push(UninstallRefusal::os(
                UninstallRefusalCode::Internal,
                format!("cannot read Contents/MacOS: {error}"),
                &error,
            ));
            return;
        }
    };
    let mut executables = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                preview.running = RunningObservation::Unknown;
                preview.refusals.push(UninstallRefusal::os(
                    UninstallRefusalCode::Internal,
                    format!("cannot read a Contents/MacOS entry: {error}"),
                    &error,
                ));
                return;
            }
        };
        match entry.file_type() {
            Ok(kind) if kind.is_file() => executables.push(entry.path()),
            Ok(_) => {}
            Err(error) => {
                preview.running = RunningObservation::Unknown;
                preview.refusals.push(UninstallRefusal::os(
                    UninstallRefusalCode::Internal,
                    format!("cannot inspect a Contents/MacOS entry: {error}"),
                    &error,
                ));
                return;
            }
        }
    }
    preview.executables_observed = Some(executables.len());
    if executables.is_empty() {
        preview.running = RunningObservation::NotAttributable("no regular executable observed");
        return;
    }
    let running = match running_process_paths() {
        Ok(running) => running,
        Err(_) => {
            preview.running = RunningObservation::Unknown;
            return;
        }
    };
    // Every observed executable must resolve before "not running" can be
    // claimed; an unresolvable one makes the bundle not attributable.
    let mut resolved = Vec::with_capacity(executables.len());
    for executable in &executables {
        match std::fs::canonicalize(executable) {
            Ok(path) => resolved.push(path),
            Err(_) => {
                preview.running =
                    RunningObservation::NotAttributable("executable path cannot be resolved");
                return;
            }
        }
    }
    let mut pids = Vec::new();
    for executable in &resolved {
        if let Some(found) = running.get(executable) {
            pids.extend(found.iter().copied());
        }
    }
    pids.sort_unstable();
    pids.dedup();
    if pids.is_empty() {
        preview.running = RunningObservation::NotRunning;
    } else {
        preview.running = RunningObservation::Running(pids.clone());
        preview.refusals.push(UninstallRefusal::new(
            UninstallRefusalCode::Running,
            format!("bundle executables are running (pids: {pids:?}); refused, never signaled"),
        ));
    }
}

#[cfg(target_os = "macos")]
fn local_volume(path: &Path) -> std::io::Result<bool> {
    let file = std::fs::File::open(path)?;
    let stat = rustix::fs::fstatfs(&file)?;
    Ok(stat.f_flags & (libc::MNT_LOCAL as u32) != 0)
}

#[cfg(not(target_os = "macos"))]
fn local_volume(_: &Path) -> std::io::Result<bool> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "uninstall preview volume checks currently require macOS",
    ))
}

#[cfg(unix)]
fn identity_device(metadata: &std::fs::Metadata) -> u64 {
    std::os::unix::fs::MetadataExt::dev(metadata)
}

#[cfg(not(unix))]
fn identity_device(_: &std::fs::Metadata) -> u64 {
    0
}

#[cfg(unix)]
fn identity_inode(metadata: &std::fs::Metadata) -> u64 {
    std::os::unix::fs::MetadataExt::ino(metadata)
}

#[cfg(not(unix))]
fn identity_inode(_: &std::fs::Metadata) -> u64 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fixture_bundle(root: &Path, name: &str) -> PathBuf {
        let bundle = root.join(name);
        let macos = bundle.join("Contents").join("MacOS");
        fs::create_dir_all(&macos).expect("create bundle tree");
        fs::write(bundle.join("Contents").join("Info.plist"), b"plist").expect("write plist");
        fs::write(macos.join("Run"), b"inert").expect("write executable");
        bundle
    }

    fn fixture_bundle_with_id(root: &Path, name: &str, id: &str) -> PathBuf {
        let bundle = root.join(name);
        let macos = bundle.join("Contents").join("MacOS");
        fs::create_dir_all(&macos).expect("create bundle tree");
        let plist = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>{id}</string>
<key>CFBundleExecutable</key><string>Run</string>
</dict></plist>"#
        );
        fs::write(bundle.join("Contents").join("Info.plist"), plist).expect("write plist");
        fs::write(macos.join("Run"), b"inert").expect("write executable");
        bundle
    }

    #[test]
    fn valid_bundle_previews_without_refusals_but_never_executable() {
        let root = tempfile::tempdir().expect("tempdir");
        let bundle = fixture_bundle(root.path(), "Fixture.app");
        let preview = preview_bundle_uninstall(&bundle);
        assert!(preview.refusals.is_empty(), "{:?}", preview.refusals);
        assert!(!preview.can_execute());
        assert_eq!(preview.execution, EXECUTION_DEFERRED);
        assert_eq!(preview.executables_observed, Some(1));
        assert_eq!(preview.running, RunningObservation::NotRunning);
        assert!(preview.identity.is_some());
        assert!(preview.recovery.contains("Put Back"));
        assert!(preview.protections.len() >= 4);
        assert_eq!(preview.copies.status, CopiesStatus::NotChecked);
    }

    #[test]
    fn empty_copies_roots_stay_not_checked() {
        let root = tempfile::tempdir().expect("tempdir");
        let bundle = fixture_bundle(root.path(), "Fixture.app");
        let preview = preview_bundle_uninstall(&bundle);
        let evidence = observe_copies(&preview, &[], &Cancellation::default(), Duration::ZERO);
        assert_eq!(evidence.status, CopiesStatus::NotChecked);
        assert!(evidence.copies.is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn copies_across_roots_are_evidence_and_the_target_is_excluded() {
        let target_root = tempfile::tempdir().expect("tempdir");
        let other_root = tempfile::tempdir().expect("tempdir");
        let target = fixture_bundle_with_id(target_root.path(), "Demo.app", "com.example.demo");
        let copy = fixture_bundle_with_id(other_root.path(), "Demo.app", "com.example.demo");
        let _different =
            fixture_bundle_with_id(other_root.path(), "Other.app", "com.example.other");
        let preview = preview_bundle_uninstall(&target);
        let roots = vec![
            target_root.path().to_path_buf(),
            other_root.path().to_path_buf(),
        ];
        let evidence = observe_copies(
            &preview,
            &roots,
            &Cancellation::default(),
            Duration::from_secs(60),
        );
        assert_eq!(evidence.status, CopiesStatus::Complete);
        assert_eq!(
            evidence.target_bundle_id.as_deref(),
            Some("com.example.demo")
        );
        // The published budgets are the effective ones: the scan keeps the
        // engine's 30-second cooperative cap, the inventory gets the call.
        assert_eq!(evidence.scan_budget_sec, Some(30));
        assert_eq!(evidence.inventory_budget_sec, Some(60));
        assert_eq!(evidence.requested_roots, roots);
        // Exactly the other same-ID bundle: the target is excluded by
        // device/inode identity and the different-ID bundle by comparison.
        assert_eq!(evidence.copies.len(), 1, "{:?}", evidence.copies);
        assert_eq!(evidence.copies[0].bundle_path, copy);
        assert_eq!(evidence.note, COPIES_NOTE);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn invalid_copies_root_publishes_only_the_scan_budget() {
        let root = tempfile::tempdir().expect("tempdir");
        let target = fixture_bundle_with_id(root.path(), "Demo.app", "com.example.demo");
        let preview = preview_bundle_uninstall(&target);
        // A lexically invalid root fails root normalization, so the scan
        // returns an error before any traversal or inventory pass runs.
        let evidence = observe_copies(
            &preview,
            &[PathBuf::from("relative-root")],
            &Cancellation::default(),
            Duration::from_secs(60),
        );
        assert_eq!(evidence.status, CopiesStatus::Failed);
        assert_eq!(evidence.scan_budget_sec, Some(30));
        assert!(evidence.inventory_budget_sec.is_none());
        assert!(evidence.copies.is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn missing_copies_root_fails_the_scan_but_runs_the_inventory() {
        let root = tempfile::tempdir().expect("tempdir");
        let target = fixture_bundle_with_id(root.path(), "Demo.app", "com.example.demo");
        let preview = preview_bundle_uninstall(&target);
        // A missing root is lexically valid: it is retained for admission,
        // fails as a scan issue, and with zero accepted roots the report
        // comes back Failed — the inventory pass still ran on that report,
        // so both effective budgets are published honestly.
        let missing_root = root.path().join("no-such-root");
        let evidence = observe_copies(
            &preview,
            &[missing_root],
            &Cancellation::default(),
            Duration::from_secs(60),
        );
        assert_eq!(evidence.status, CopiesStatus::Failed);
        assert_eq!(evidence.scan_budget_sec, Some(30));
        assert_eq!(evidence.inventory_budget_sec, Some(60));
        assert!(evidence.copies.is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn copies_need_a_target_identity_for_exclusion() {
        let root = tempfile::tempdir().expect("tempdir");
        // A missing bundle previews with no identity: without device/inode
        // there is no trustworthy exclusion, so the observation refuses
        // instead of risking the named bundle listed as its own copy.
        let preview = preview_bundle_uninstall(&root.path().join("Ghost.app"));
        assert!(preview.identity.is_none());
        let evidence = observe_copies(
            &preview,
            &[root.path().to_path_buf()],
            &Cancellation::default(),
            Duration::from_secs(30),
        );
        assert_eq!(evidence.status, CopiesStatus::NotAttributable);
        assert_eq!(
            evidence.reason,
            Some("the target bundle identity is unavailable")
        );
        assert!(evidence.copies.is_empty());
        assert!(evidence.scan_budget_sec.is_none());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn copies_need_an_attributable_target_identifier() {
        let root = tempfile::tempdir().expect("tempdir");
        let bundle = fixture_bundle(root.path(), "Fixture.app");
        let preview = preview_bundle_uninstall(&bundle);
        let evidence = observe_copies(
            &preview,
            &[root.path().to_path_buf()],
            &Cancellation::default(),
            Duration::from_secs(30),
        );
        // The fixture plist is deliberately not parseable: no identifier
        // means no trustworthy comparison, never an empty "no copies" claim.
        assert_eq!(evidence.status, CopiesStatus::NotAttributable);
        assert!(evidence.target_bundle_id.is_none());
        assert!(evidence.copies.is_empty());
    }

    #[test]
    fn missing_not_directory_not_app_and_missing_plist_are_refused() {
        let root = tempfile::tempdir().expect("tempdir");
        let missing = preview_bundle_uninstall(&root.path().join("Ghost.app"));
        assert!(
            missing
                .refusals
                .iter()
                .any(|r| r.code == UninstallRefusalCode::NotFound)
        );

        let file = root.path().join("File.app");
        fs::write(&file, b"not a directory").expect("write file");
        let not_dir = preview_bundle_uninstall(&file);
        assert!(
            not_dir
                .refusals
                .iter()
                .any(|r| r.code == UninstallRefusalCode::NotDirectory)
        );

        let plain = fixture_bundle(root.path(), "PlainDir");
        let not_app = preview_bundle_uninstall(&plain);
        assert!(
            not_app
                .refusals
                .iter()
                .any(|r| r.code == UninstallRefusalCode::NotAppBundle)
        );

        let no_plist = root.path().join("NoPlist.app");
        fs::create_dir_all(no_plist.join("Contents").join("MacOS")).expect("tree");
        let missing_plist = preview_bundle_uninstall(&no_plist);
        assert!(
            missing_plist
                .refusals
                .iter()
                .any(|r| r.code == UninstallRefusalCode::MissingInfoPlist)
        );
    }

    #[test]
    fn system_location_is_refused_before_any_inspection() {
        let preview =
            preview_bundle_uninstall(Path::new("/System/Library/CoreServices/Finder.app"));
        assert!(
            preview
                .refusals
                .iter()
                .any(|r| r.code == UninstallRefusalCode::SystemLocation)
        );
        // The refusal is a closed boundary: nothing beneath /System is probed.
        assert!(preview.identity.is_none());
        assert!(preview.executables_observed.is_none());
        assert_eq!(preview.running, RunningObservation::NotChecked);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn symlink_bundle_is_never_followed() {
        let root = tempfile::tempdir().expect("tempdir");
        let bundle = fixture_bundle(root.path(), "Real.app");
        let link = root.path().join("Link.app");
        std::os::unix::fs::symlink(&bundle, &link).expect("symlink");
        let preview = preview_bundle_uninstall(&link);
        assert!(
            preview
                .refusals
                .iter()
                .any(|r| r.code == UninstallRefusalCode::SymlinkBundle)
        );
    }
}
