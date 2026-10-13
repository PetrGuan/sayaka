// SPDX-License-Identifier: MPL-2.0

use super::*;
use crate::model::Cancellation;
use crate::readonly_task::ReadOnlyTask;
use crate::scan::task::{ScanTaskSnapshot, ScanTaskState, validate_roots};
use crate::scan::{self, ScanCode, ScanError, ScanLimits, ScanProgress};
use std::time::Instant;
mod projects;
#[cfg(target_os = "macos")]
pub(crate) use projects::verify_metadata;
pub use projects::{ClassifyLimits, SizeLimits};

/// Cache accounting may visit millions of files without retaining their paths.
/// The UI remains cancellable; other profiles keep the generic 30-second budget.
pub fn preview_limits(profile: PurgeProfile) -> ScanLimits {
    let mut limits = ScanLimits::default();
    if profile == PurgeProfile::Projects {
        limits.time_budget = Duration::from_secs(90);
    }
    if profile == PurgeProfile::DeveloperCaches {
        limits.time_budget = Duration::from_secs(300);
        // This caps each numeric identity table during cache measurement, not
        // the number of files visited. Discovery retains the generic limits.
        limits.max_entries = 1_000_000;
    }
    limits
}

/// Owned preview lifecycle; cache aggregation stays on the cancellable worker.
pub struct PurgePreviewTask {
    inner: ReadOnlyTask<PurgePreview, ScanProgress>,
}
impl PurgePreviewTask {
    pub fn start(
        roots: Vec<PathBuf>,
        limits: ScanLimits,
        options: PurgeOptions,
    ) -> Result<Self, ScanError> {
        validate_roots(&roots, &limits)?;
        options
            .validate()
            .map_err(|s| ScanError::new(ScanCode::InvalidLimits, s))?;
        Ok(Self {
            inner: ReadOnlyTask::spawn("sayaka-purge-preview", move |cancel, progress| {
                scan_preview(&roots, &limits, &options, cancel, progress)
            })?,
        })
    }
    pub fn cancel(&self) {
        self.inner.cancel();
    }
    pub fn is_finished(&self) -> bool {
        self.inner.is_finished()
    }
    pub fn poll(&mut self) -> Result<ScanTaskSnapshot, ScanError> {
        let slot = self.inner.poll()?;
        let state = match self.inner.outcome() {
            None => ScanTaskState::Running,
            Some(Err(error)) if error.code == ScanCode::Cancelled => ScanTaskState::Cancelled,
            Some(Err(_)) => ScanTaskState::Failed,
            Some(Ok(preview)) => match preview.status {
                PurgeStatus::Complete => ScanTaskState::Complete,
                PurgeStatus::Partial => ScanTaskState::Partial,
                PurgeStatus::Cancelled => ScanTaskState::Cancelled,
                PurgeStatus::Failed => ScanTaskState::Failed,
            },
        };
        Ok(ScanTaskSnapshot {
            state,
            cancellation_requested: slot.cancellation_requested,
            progress_sequence: slot.progress_sequence,
            progress: slot.progress,
        })
    }
    pub fn result(&mut self) -> Option<&Result<PurgePreview, ScanError>> {
        self.inner.result()
    }
}

/// Same preview contract for CLI and bindings. Only cache previews use streaming totals.
pub fn scan_preview(
    roots: &[PathBuf],
    limits: &ScanLimits,
    options: &PurgeOptions,
    cancellation: &Cancellation,
    mut progress: impl FnMut(&ScanProgress),
) -> Result<PurgePreview, ScanError> {
    validate_roots(roots, limits)?;
    options
        .validate()
        .map_err(|s| ScanError::new(ScanCode::InvalidLimits, s))?;
    let started = Instant::now();
    let mut timings = PreviewTimings::default();
    let mut options = options.clone();
    options.cache_discovery_deadline = Some(started + Duration::from_secs(30));
    let mut discovery_limits = ClassifyLimits::from_request(limits).scan;
    if options.profile == PurgeProfile::Worktrees {
        discovery_limits.time_budget = discovery_limits.time_budget.min(Duration::from_secs(5));
    }
    let report = match options.profile {
        PurgeProfile::DeveloperCaches => {
            let home =
                effective_account_home().map_err(|s| ScanError::new(ScanCode::InvalidRoot, s))?;
            let leaves = developer_cache_rule_locations(&home)
                .map_err(|s| ScanError::new(ScanCode::InvalidRoot, s))?
                .into_iter()
                .map(|location| location.path)
                .collect::<Vec<_>>();
            let mut discovery_limits = limits.clone();
            discovery_limits.time_budget = Duration::from_secs(30)
                .saturating_sub(started.elapsed())
                .min(limits.time_budget);
            discovery_limits.max_entries = limits.max_entries.min(10_000);
            discovery_limits.max_path_bytes = limits.max_path_bytes.min(32 * 1024 * 1024);
            scan::scan_with_policy(
                roots,
                &discovery_limits,
                cancellation,
                scan::TraversalPolicy::CacheDiscovery {
                    generic_root: home.join("Library/Caches"),
                    scopes: cache_scopes()?.into(),
                    leaves: leaves.into(),
                },
                &mut progress,
            )?
        }
        PurgeProfile::FinderMetadata => {
            scan::scan_prune_native_packages(roots, limits, cancellation, &mut progress)?
        }
        PurgeProfile::Projects | PurgeProfile::Worktrees => scan::scan_with_policy(
            roots,
            &discovery_limits,
            cancellation,
            scan::TraversalPolicy::ProjectDiscovery,
            |update| {
                let mut discovery = update.clone();
                discovery.logical_bytes_known = 0;
                progress(&discovery);
            },
        )?,
    };
    timings.discovery_us = micros(started);
    let phase_started = Instant::now();
    let task_id = report.task_id;
    let mut observed = report.entries.len();
    let index = ScanTree::build(report, cancellation)?;
    timings.index_us = micros(phase_started);
    let phase_started = Instant::now();
    let classified = if options.profile == PurgeProfile::DeveloperCaches {
        let home = effective_account_home().map_err(|s| ScanError::new(ScanCode::InvalidRoot, s))?;
        developer_cache_preview_with_progress(&index, &options, &home, &mut |phase, completed, total| {
            if cancellation.is_cancelled() { return Err("classification cancelled".into()); }
            progress(&ScanProgress {
                classification: Some(crate::scan::ClassificationProgress { phase, completed, total }),
                total_artifacts: 0, sized_artifacts: 0, task_id,
                entries: observed, unique_files: index.report().totals.unique_files,
                logical_bytes_known: index.report().totals.logical_bytes_known,
                issues: index.report().issues.len(), elapsed_ms: started.elapsed().as_millis() as u64,
            });
            Ok(())
        })
    } else { purge_preview(&index, &options, SystemTime::now()) };
    if cancellation.is_cancelled() { return Err(ScanError::new(ScanCode::Cancelled, "classification cancelled")); }
    let mut preview = classified.map_err(|s| ScanError::new(ScanCode::InvalidLimits, s))?;
    timings.classification_us = micros(phase_started);
    let git_started = Instant::now();
    if options.profile == PurgeProfile::Projects {
        let paths = preview
            .projects
            .iter()
            .flat_map(|p| p.artifacts.iter().map(|a| a.path.clone()))
            .collect::<Vec<_>>();
        preview.scan_metrics = Some(ProjectScanMetrics {
            classification_entries: index.report().entries.len(),
            artifact_descendant_entries: index
                .report()
                .entries
                .iter()
                .filter(|e| paths.iter().any(|p| e.path != *p && e.path.starts_with(p)))
                .count(),
            vcs_descendant_entries: index
                .report()
                .entries
                .iter()
                .filter(|e| crate::project_git::is_metadata_path(&e.path))
                .count(),
            classification_ms: index.report().metrics.elapsed_ms,
            ..Default::default()
        });
        let observations =
            crate::project_git::inspect_before(&paths, cancellation, started + limits.time_budget);
        for artifact in preview.projects.iter_mut().flat_map(|p| &mut p.artifacts) {
            if artifact.git.state != crate::project_git::GitState::ContainsMetadata {
                artifact.git = observations
                    .get(&artifact.path)
                    .cloned()
                    .unwrap_or_default();
            }
        }
    }
    timings.git_us = if options.profile == PurgeProfile::Projects {
        micros(git_started)
    } else {
        0
    };
    if options.profile == PurgeProfile::Projects {
        let phase_started = Instant::now();
        crate::project_activity::observe(&mut preview, cancellation, started + limits.time_budget);
        timings.activity_us = micros(phase_started);
        let phase_started = Instant::now();
        projects::measure(
            &mut preview,
            &index,
            limits,
            started,
            cancellation,
            &mut progress,
        );
        timings.sizing_us = micros(phase_started);
    }
    if options.profile == PurgeProfile::Worktrees {
        let phase_started = Instant::now();
        preview.worktrees = crate::worktrees::observe(&index, cancellation, started + limits.time_budget);
        timings.worktrees_us = micros(phase_started);
        // Discovery is only the first phase. Stop during Git or sizing must
        // remain cancelled at the task/FFI/CLI boundary too.
        if cancellation.is_cancelled() {
            preview.status = PurgeStatus::Cancelled;
            preview.complete = false;
            preview.worktrees.complete = false;
        } else if !preview.worktrees.complete && preview.status == PurgeStatus::Complete {
            preview.status = PurgeStatus::Partial;
            preview.complete = false;
        }
    }
    if options.profile != PurgeProfile::DeveloperCaches {
        timings.total_us = micros(started);
        preview.timings = Some(timings);
        return Ok(preview);
    }
    let sizing_started = Instant::now();
    let mut files = 0u64;
    let mut logical = 0u64;
    let count = preview.developer_caches.len();
    for candidate_index in 0..count {
        let candidate = &mut preview.developer_caches[candidate_index];
        // Discovery coverage cannot be repaired by measuring a leaf alone.
        let discovered_complete = candidate.complete;
        candidate.complete = false;
        candidate.private_bytes = None;
        candidate.logical_bytes = None;
        candidate.allocated_bytes = None;
        let remaining = limits.time_budget.saturating_sub(started.elapsed());
        let result = if remaining.is_zero() || cancellation.is_cancelled() {
            Err(ScanError::new(
                if cancellation.is_cancelled() {
                    ScanCode::Cancelled
                } else {
                    ScanCode::DurationLimit
                },
                "cache preview stopped before all measurements completed",
            ))
        } else {
            let mut measurement_limits = limits.clone();
            measurement_limits.time_budget = remaining;
            scan::cache::scan(
                &candidate.path,
                candidate.identity,
                &measurement_limits,
                cancellation,
                |entries, unique, bytes| {
                    progress(&ScanProgress {
                        classification: None,
                        total_artifacts: 0,
                        sized_artifacts: 0,
                        task_id,
                        entries: observed.saturating_add(entries),
                        unique_files: files.saturating_add(unique),
                        logical_bytes_known: logical.saturating_add(bytes),
                        issues: preview.scan_issues.len(),
                        elapsed_ms: started.elapsed().as_millis() as u64,
                    });
                },
            )
        };
        let (issues, omitted) = match result {
            Ok(summary) => {
                candidate.complete = discovered_complete && summary.complete;
                candidate.logical_bytes = summary.logical;
                candidate.allocated_bytes = summary.allocated;
                candidate.private_bytes = candidate.complete.then_some(summary.private).flatten();
                candidate.links_not_followed = summary.links;
                observed = observed.saturating_add(summary.entries);
                files = files.saturating_add(summary.files);
                logical = logical.saturating_add(summary.logical.unwrap_or(0));
                if summary.cancelled {
                    preview.status = PurgeStatus::Cancelled;
                }
                (summary.issues, summary.omitted)
            }
            Err(error) => {
                if error.code == ScanCode::Cancelled {
                    preview.status = PurgeStatus::Cancelled;
                }
                (
                    vec![scan::ScanIssue {
                        owner: None,
                        path: Some(candidate.path.clone()),
                        code: error.code,
                        message: error.message,
                        os_code: error.os_code,
                    }],
                    0,
                )
            }
        };
        if !candidate.complete {
            preview.complete = false;
        }
        preview.scan_issues_omitted += omitted;
        for issue in issues {
            if preview.scan_issues.len() < limits.max_issues {
                preview.scan_issues.push(issue);
            } else {
                preview.scan_issues_omitted += 1;
            }
        }
    }
    if !preview.complete {
        for candidate in &mut preview.developer_caches {
            candidate.complete = false;
        }
    }
    if !preview.complete && preview.status == PurgeStatus::Complete {
        preview.status = PurgeStatus::Partial;
    }
    timings.sizing_us = micros(sizing_started);
    timings.total_us = micros(started);
    preview.timings = Some(timings);
    Ok(preview)
}

fn micros(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}
