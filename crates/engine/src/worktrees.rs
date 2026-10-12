// SPDX-License-Identifier: MPL-2.0
//! Bounded Git observations. No selections, cleanup authority, or file-content reads.
use std::path::PathBuf;

#[derive(Clone, Debug, Default)]
pub struct WorktreeReport {
    pub items: Vec<WorktreeObservation>,
    pub complete: bool,
    pub unavailable_repositories: usize,
}
#[derive(Clone, Debug)]
pub struct WorktreeObservation {
    pub repository: PathBuf,
    pub path: PathBuf,
    pub branch: Option<String>,
    pub detached: bool,
    pub bare: bool,
    pub locked: bool,
    pub prunable: bool,
    pub changed_files: Option<u64>,
    pub local_only_commits: Option<u64>,
    pub last_commit_ms: Option<i64>,
    pub logical_bytes: Option<u64>,
    pub size_complete: bool,
}

pub(crate) fn observe(
    index: &crate::scan::index::ScanTree,
    cancellation: &crate::model::Cancellation,
    request_deadline: std::time::Instant,
) -> WorktreeReport {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (index, cancellation, request_deadline);
        WorktreeReport::default()
    }
    #[cfg(target_os = "macos")]
    {
        use crate::{
            model::ResourceKind,
            scan::{ScanLimits, cache},
        };
        use std::{
            collections::BTreeSet,
            time::{Duration, Instant},
        };
        let source = index.report();
        let mut report = WorktreeReport {
            complete: source.complete,
            ..Default::default()
        };
        // Discovery records .git even when there are no artifact candidates.
        let repositories: BTreeSet<_> = source
            .vcs_metadata
            .iter()
            .filter_map(|path| {
                if path
                    .file_name()
                    .is_some_and(|n| n.eq_ignore_ascii_case(".git"))
                {
                    path.parent().map(|p| p.to_owned())
                } else {
                    Some(path.clone())
                } // observed bare repository
            })
            .collect();
        let Ok(reader) = sayaka_platform_macos::project_git::GitReader::new() else {
            report.complete = false;
            report.unavailable_repositories = repositories.len();
            return report;
        };
        let deadline = request_deadline.min(Instant::now() + Duration::from_secs(12));
        let mut seen = BTreeSet::new();
        for (position, repo) in repositories.iter().enumerate() {
            if seen.contains(repo) {
                continue;
            }
            if position >= 64 || cancellation.is_cancelled() || Instant::now() >= deadline {
                report.complete = false;
                report.unavailable_repositories += 1;
                continue;
            }
            let Ok(items) = reader.worktrees(
                repo,
                deadline.saturating_duration_since(Instant::now()),
                &|| cancellation.is_cancelled(),
            ) else {
                report.complete = false;
                report.unavailable_repositories += 1;
                continue;
            };
            let repository = items.first().map(|item| item.path.clone()).unwrap_or_else(|| repo.clone());
            for item in items {
                if !seen.insert(item.path.clone()) {
                    continue;
                }
                if report.items.len() == 256 {
                    report.complete = false;
                    break;
                }
                let details = if item.bare
                    || item.prunable
                    || cancellation.is_cancelled()
                    || Instant::now() >= deadline
                {
                    Default::default()
                } else {
                    reader.worktree_details(
                        &item.path,
                        deadline.saturating_duration_since(Instant::now()),
                        &|| cancellation.is_cancelled(),
                    )
                };
                if !item.bare
                    && (details.changed_files.is_none()
                        || details.local_only_commits.is_none()
                        || details.last_commit_ms.is_none())
                {
                    report.complete = false;
                }
                report.items.push(WorktreeObservation {
                    repository: repository.clone(),
                    path: item.path,
                    branch: item.branch,
                    detached: item.detached,
                    bare: item.bare,
                    locked: item.locked,
                    prunable: item.prunable,
                    changed_files: details.changed_files,
                    local_only_commits: details.local_only_commits,
                    last_commit_ms: details.last_commit_ms,
                    logical_bytes: None,
                    size_complete: false,
                });
            }
        }
        // Size only already-observed directories in the saved scope, never arbitrary
        // linked paths outside it. Streaming native metadata traversal skips .git,
        // follows no links and cannot read source/AI file contents.
        let size_deadline = request_deadline.min(Instant::now() + Duration::from_secs(3));
        let budget = cache::ProjectSizeBudget {
            visited: Default::default(),
            max_entries: 100_000,
            deadline: size_deadline,
        };
        for item in &mut report.items {
            if item.bare
                || item.prunable
                || cancellation.is_cancelled()
                || Instant::now() >= size_deadline
            {
                continue;
            }
            let Some(entry) = source
                .entries
                .iter()
                .find(|e| e.path == item.path && e.kind == ResourceKind::Directory && !e.dataless)
            else {
                continue;
            };
            let limits = ScanLimits {
                workers: 1,
                time_budget: Duration::from_millis(500)
                    .min(size_deadline.saturating_duration_since(Instant::now())),
                max_entries: 100_000,
                ..Default::default()
            };
            if let Ok(summary) = cache::scan_project(
                &item.path,
                entry.identity,
                &limits,
                &budget,
                cancellation,
                |_, _, _| {},
            ) {
                item.logical_bytes = summary.logical;
                // An excluded Git directory makes this a lower bound, never a
                // claim of full on-disk size or reclaimable bytes.
                item.size_complete = summary.complete;
            }
        }
        report.items.sort_by(|a, b| a.path.cmp(&b.path));
        report
    }
}
