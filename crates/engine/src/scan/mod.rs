// SPDX-License-Identifier: MPL-2.0

//! Bounded read-only traversal. Results describe observations, not a filesystem
//! snapshot or authorization to perform maintenance.

pub mod diagnostics;
pub mod directory_review;
pub mod index;
pub mod task;
pub mod wire;
use diagnostics::ScanDiagnostics;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(any(target_os = "macos", windows, test))]
mod walk;
#[cfg(windows)]
mod windows;

use crate::model::{Cancellation, FileIdentity, ResourceKind};
#[cfg(target_os = "macos")]
use rustix::fd::OwnedFd;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

#[cfg(target_os = "macos")]
pub(crate) fn validate_local_internal_volume_fd(fd: &OwnedFd) -> Result<(), ScanError> {
    macos::validate_local_internal_volume_fd(fd)
}

static NEXT_TASK: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TraversalPolicy {
    Default,
    PruneAppBundles,
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    #[test]
    fn windows_roots_preserve_native_strings_and_reject_unsafe_forms() {
        let mut units: Vec<u16> = r"C:\sayaka-fixture\".encode_utf16().collect();
        units.push(0xd800);
        let native = PathBuf::from(OsString::from_wide(&units));
        let limits = ScanLimits::default();
        assert_eq!(
            walk::normalize_roots(std::slice::from_ref(&native), &limits).unwrap(),
            vec![native]
        );
        for path in [
            r"C:\",
            r"C:relative",
            r"\relative",
            r"C:\fixture\..\outside",
        ] {
            assert_eq!(
                walk::normalize_roots(&[PathBuf::from(path)], &limits)
                    .unwrap_err()
                    .code,
                ScanCode::InvalidRoot,
                "{path:?}"
            );
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ScanTaskId {
    process: u32,
    sequence: u64,
}

impl fmt::Display for ScanTaskId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.process, self.sequence)
    }
}

impl ScanTaskId {
    fn new() -> Result<Self, ScanError> {
        let sequence = NEXT_TASK
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| ScanError::new(ScanCode::Internal, "scan task IDs exhausted"))?;
        Ok(Self {
            process: std::process::id(),
            sequence,
        })
    }

    #[cfg(test)]
    pub(crate) const fn synthetic(sequence: u64) -> Self {
        Self {
            process: 1,
            sequence,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ScanLimits {
    pub workers: usize,
    pub queue_capacity: usize,
    pub event_capacity: usize,
    pub max_open_dirs: usize,
    pub max_depth: usize,
    pub max_entries: usize,
    pub max_path_bytes: usize,
    pub max_issues: usize,
    pub time_budget: Duration,
    pub progress_every: usize,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            workers: 4,
            queue_capacity: 64,
            event_capacity: 128,
            max_open_dirs: 128,
            max_depth: 128,
            max_entries: 100_000,
            max_path_bytes: 32 * 1024 * 1024,
            max_issues: 128,
            time_budget: Duration::from_secs(30),
            progress_every: 128,
        }
    }
}

impl ScanLimits {
    pub fn validate(&self) -> Result<(), ScanError> {
        let valid = (1..=32).contains(&self.workers)
            && (1..=4096).contains(&self.queue_capacity)
            && (1..=4096).contains(&self.event_capacity)
            && (self.workers + 2..=4096).contains(&self.max_open_dirs)
            && (1..=1024).contains(&self.max_depth)
            && (1..=1_000_000).contains(&self.max_entries)
            && (1..=256 * 1024 * 1024).contains(&self.max_path_bytes)
            && (1..=1024).contains(&self.max_issues)
            && !self.time_budget.is_zero()
            && self.time_budget <= Duration::from_secs(86_400)
            && (1..=65_536).contains(&self.progress_every);
        if valid {
            Ok(())
        } else {
            Err(ScanError::new(
                ScanCode::InvalidLimits,
                "invalid scan resource limits",
            ))
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanCode {
    InvalidLimits,
    InvalidRoot,
    UnsupportedPlatform,
    UnsupportedVolume,
    VolumeUnknown,
    PermissionDenied,
    Busy,
    NotFound,
    LinkSkipped,
    MountBoundary,
    CloudDirectorySkipped,
    DuplicateRoot,
    DuplicateDirectory,
    ChangedEntry,
    Io,
    PolicyFailure,
    DepthLimit,
    OpenHandleLimit,
    EntryLimit,
    PathBytesLimit,
    DurationLimit,
    Cancelled,
    Overflow,
    WorkerPanic,
    WorkerStartFailed,
    Internal,
}

impl ScanCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidLimits => "invalid_limits",
            Self::InvalidRoot => "invalid_root",
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::UnsupportedVolume => "unsupported_volume",
            Self::VolumeUnknown => "volume_unknown",
            Self::PermissionDenied => "permission_denied",
            Self::Busy => "busy",
            Self::NotFound => "not_found",
            Self::LinkSkipped => "link_skipped",
            Self::MountBoundary => "mount_boundary",
            Self::CloudDirectorySkipped => "cloud_directory_skipped",
            Self::DuplicateRoot => "duplicate_root",
            Self::DuplicateDirectory => "duplicate_directory",
            Self::ChangedEntry => "changed_entry",
            Self::Io => "io_error",
            Self::PolicyFailure => "policy_failure",
            Self::DepthLimit => "depth_limit",
            Self::OpenHandleLimit => "open_handle_limit",
            Self::EntryLimit => "entry_limit",
            Self::PathBytesLimit => "path_bytes_limit",
            Self::DurationLimit => "duration_limit",
            Self::Cancelled => "cancelled",
            Self::Overflow => "measurement_overflow",
            Self::WorkerPanic => "worker_panic",
            Self::WorkerStartFailed => "worker_start_failed",
            Self::Internal => "internal_error",
        }
    }

    pub const fn is_gap(self) -> bool {
        !matches!(
            self,
            Self::LinkSkipped | Self::DuplicateRoot | Self::DuplicateDirectory
        )
    }
}

#[derive(Clone, Debug)]
pub struct ScanError {
    pub code: ScanCode,
    pub message: String,
    pub os_code: Option<i32>,
}

impl ScanError {
    pub fn new(code: ScanCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            os_code: None,
        }
    }

    #[cfg(any(target_os = "macos", windows))]
    pub(crate) fn io(error: std::io::Error) -> Self {
        let code = match error.kind() {
            std::io::ErrorKind::PermissionDenied => ScanCode::PermissionDenied,
            std::io::ErrorKind::NotFound => ScanCode::NotFound,
            _ => ScanCode::Io,
        };
        #[cfg(windows)]
        let code = match error.raw_os_error() {
            Some(32 | 33) => ScanCode::Busy,
            Some(267) => ScanCode::InvalidRoot,
            _ => code,
        };
        Self {
            code,
            message: error.to_string(),
            os_code: error.raw_os_error(),
        }
    }
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {:?}", self.code.as_str(), self.message)
    }
}
impl std::error::Error for ScanError {}

#[derive(Clone, Debug)]
pub struct ScanIssue {
    pub path: Option<PathBuf>,
    pub code: ScanCode,
    pub message: String,
    pub os_code: Option<i32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanStatus {
    Complete,
    Partial,
    Cancelled,
    Failed,
}

impl ScanStatus {
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

#[derive(Clone, Debug)]
pub struct ScanEntry {
    /// Unique only within the associated scan task.
    pub id: u64,
    pub path: PathBuf,
    pub kind: ResourceKind,
    pub identity: FileIdentity,
    pub logical_bytes: Option<u64>,
    pub allocated_bytes: Option<u64>,
    pub dataless: bool,
    /// Only the first occurrence of a regular-file identity contributes bytes.
    pub counted: bool,
    pub depth: usize,
}

#[derive(Clone, Debug, Default)]
pub struct ScanTotals {
    pub regular_files: u64,
    pub unique_files: u64,
    pub duplicate_files: u64,
    pub directories: u64,
    pub links: u64,
    pub other: u64,
    pub logical_bytes_known: u64,
    pub logical_bytes_unknown_files: u64,
    pub allocated_bytes_known: u64,
    pub allocated_bytes_unknown_files: u64,
}

#[derive(Clone, Debug, Default)]
pub struct ScanMetrics {
    pub elapsed_ms: u64,
    pub first_result_ms: Option<u64>,
    pub peak_workers: usize,
    pub peak_queued_dirs: usize,
    pub peak_open_dirs: usize,
    pub peak_pending_events: usize,
    pub retained_path_bytes: usize,
    pub accepted_roots: usize,
}

#[derive(Clone, Debug)]
pub struct ScanProgress {
    pub task_id: ScanTaskId,
    pub entries: usize,
    pub unique_files: u64,
    pub logical_bytes_known: u64,
    pub issues: usize,
    pub elapsed_ms: u64,
}

#[derive(Clone, Debug)]
pub struct ScanReport {
    pub task_id: ScanTaskId,
    pub roots: Vec<PathBuf>,
    pub status: ScanStatus,
    /// Complete traversal within the declared no-links policy, not a snapshot.
    pub complete: bool,
    pub entries: Vec<ScanEntry>,
    pub issues: Vec<ScanIssue>,
    pub issues_omitted: usize,
    pub totals: ScanTotals,
    pub metrics: ScanMetrics,
}

pub fn display_path(path: &Path) -> String {
    format!("{:?}", path.as_os_str())
}

/// Read-only freshness check for an explicit external-viewer request. This is
/// not an atomic handoff to the viewer and never authorizes filesystem mutation.
pub fn verify_entry(scope: &ScanEntry, entry: &ScanEntry) -> Result<(), ScanError> {
    if scope.kind != ResourceKind::Directory
        || !crate::model::valid_absolute_path(&scope.path)
        || scope.path.parent().is_none()
        || !crate::model::valid_absolute_path(&entry.path)
        || !entry.path.starts_with(&scope.path)
    {
        return Err(ScanError::new(
            ScanCode::InvalidRoot,
            "invalid observation scope",
        ));
    }

    #[cfg(target_os = "macos")]
    {
        macos::verify_entry(scope, entry)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = entry;
        Err(ScanError::new(
            ScanCode::UnsupportedPlatform,
            "native viewing requires macOS",
        ))
    }
}

/// Synchronous result collection with bounded worker/descriptor/event budgets.
/// Progress is delivered on the calling thread and must return promptly.
pub fn scan(
    roots: &[PathBuf],
    limits: &ScanLimits,
    cancellation: &Cancellation,
    progress: impl FnMut(&ScanProgress),
) -> Result<ScanReport, ScanError> {
    scan_with_policy(
        roots,
        limits,
        cancellation,
        TraversalPolicy::Default,
        progress,
    )
}

/// Read-only scan variant that emits `.app` bundle directories but does not
/// descend into them.
pub fn scan_prune_app_bundles(
    roots: &[PathBuf],
    limits: &ScanLimits,
    cancellation: &Cancellation,
    progress: impl FnMut(&ScanProgress),
) -> Result<ScanReport, ScanError> {
    scan_with_policy(
        roots,
        limits,
        cancellation,
        TraversalPolicy::PruneAppBundles,
        progress,
    )
}

pub(crate) fn scan_with_policy(
    roots: &[PathBuf],
    limits: &ScanLimits,
    cancellation: &Cancellation,
    traversal_policy: TraversalPolicy,
    progress: impl FnMut(&ScanProgress),
) -> Result<ScanReport, ScanError> {
    scan_internal(
        roots,
        limits,
        cancellation,
        traversal_policy,
        progress,
        None,
    )
}

/// Same default scan policy, with opt-in macOS admission diagnostics.
/// Unsupported diagnostic fields stay absent; normal platform errors still apply.
pub fn scan_with_diagnostics(
    roots: &[PathBuf],
    limits: &ScanLimits,
    cancellation: &Cancellation,
    progress: impl FnMut(&ScanProgress),
    diagnostics: &mut ScanDiagnostics,
) -> Result<ScanReport, ScanError> {
    *diagnostics = ScanDiagnostics::default();
    scan_internal(
        roots,
        limits,
        cancellation,
        TraversalPolicy::Default,
        progress,
        Some(diagnostics),
    )
}

fn scan_internal(
    roots: &[PathBuf],
    limits: &ScanLimits,
    cancellation: &Cancellation,
    traversal_policy: TraversalPolicy,
    progress: impl FnMut(&ScanProgress),
    diagnostics: Option<&mut ScanDiagnostics>,
) -> Result<ScanReport, ScanError> {
    limits.validate()?;
    let task_id = ScanTaskId::new()?;
    #[cfg(target_os = "macos")]
    {
        let roots = walk::normalize_roots(roots, limits)?;
        macos::scan_native(
            roots,
            limits,
            cancellation,
            task_id,
            traversal_policy,
            progress,
            diagnostics,
        )
    }
    #[cfg(windows)]
    {
        let _ = diagnostics;
        let roots = walk::normalize_roots(roots, limits)?;
        windows::scan_native(
            roots,
            limits,
            cancellation,
            task_id,
            traversal_policy,
            progress,
        )
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        let _ = (
            roots,
            cancellation,
            task_id,
            traversal_policy,
            progress,
            diagnostics,
        );
        Err(ScanError::new(
            ScanCode::UnsupportedPlatform,
            "native scanning requires macOS or Windows",
        ))
    }
}
