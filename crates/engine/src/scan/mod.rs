// SPDX-License-Identifier: MPL-2.0

//! Bounded read-only traversal. Results describe observations, not a filesystem
//! snapshot or authorization to perform maintenance.

#[cfg(target_os = "macos")]
mod macos;
#[cfg(any(target_os = "macos", test))]
mod walk;

use crate::model::{Cancellation, FileIdentity, ResourceKind};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static NEXT_TASK: AtomicU64 = AtomicU64::new(1);

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

    #[cfg(target_os = "macos")]
    pub(crate) fn io(error: std::io::Error) -> Self {
        let code = match error.kind() {
            std::io::ErrorKind::PermissionDenied => ScanCode::PermissionDenied,
            std::io::ErrorKind::NotFound => ScanCode::NotFound,
            _ => ScanCode::Io,
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

#[derive(Debug)]
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

/// Synchronous result collection with bounded worker/descriptor/event budgets.
/// Progress is delivered on the calling thread and must return promptly.
pub fn scan(
    roots: &[PathBuf],
    limits: &ScanLimits,
    cancellation: &Cancellation,
    progress: impl FnMut(&ScanProgress),
) -> Result<ScanReport, ScanError> {
    limits.validate()?;
    let task_id = ScanTaskId::new()?;
    #[cfg(target_os = "macos")]
    {
        let roots = walk::normalize_roots(roots, limits)?;
        macos::scan_native(roots, limits, cancellation, task_id, progress)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (roots, cancellation, task_id, progress);
        Err(ScanError::new(
            ScanCode::UnsupportedPlatform,
            "native scanning currently requires macOS",
        ))
    }
}
