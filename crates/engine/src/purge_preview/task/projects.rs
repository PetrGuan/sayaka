// SPDX-License-Identifier: MPL-2.0

//! Two independent budgets: retained classification records and streaming sizing.
use super::*;
use crate::scan::cache::{self, ProjectSizeBudget};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;

#[derive(Clone, Debug)]
pub struct ClassifyLimits {
    pub scan: ScanLimits,
}
impl ClassifyLimits {
    pub fn from_request(request: &ScanLimits) -> Self {
        let mut scan = request.clone();
        scan.time_budget = scan.time_budget.min(Duration::from_secs(30));
        Self { scan }
    }
}
#[derive(Clone, Debug)]
pub struct SizeLimits {
    pub max_entries: usize,
    pub time_budget: Duration,
    pub workers: usize,
}
impl Default for SizeLimits {
    fn default() -> Self {
        Self {
            max_entries: 2_000_000,
            time_budget: Duration::from_secs(60),
            workers: 4,
        }
    }
}
impl SizeLimits {
    fn active_workers(&self, request: &ScanLimits, jobs: usize) -> usize {
        self.workers
            .min(request.workers)
            .min(jobs)
            .min(request.max_open_dirs / 3)
            .min(request.max_path_bytes)
    }

    fn scan(
        &self,
        request: &ScanLimits,
        deadline: Instant,
        worker: usize,
        workers: usize,
    ) -> ScanLimits {
        // Disjoint partitions sum to the caller's aggregate caps, including
        // remainders. One active artifact can use the entire requested budget.
        let share = |total: usize| total / workers + usize::from(worker < total % workers);
        let mut limits = request.clone();
        limits.max_entries = self.max_entries.min(1_000_000);
        limits.workers = 1;
        limits.max_open_dirs = share(request.max_open_dirs);
        limits.max_path_bytes = share(request.max_path_bytes);
        limits.time_budget = deadline.saturating_duration_since(Instant::now());
        limits
    }
}

enum Event {
    Progress(usize, usize, u64, u64),
    Result(usize, Result<cache::Summary, ScanError>),
}

pub(super) fn measure(
    preview: &mut PurgePreview,
    index: &ScanTree,
    request: &ScanLimits,
    started: Instant,
    cancellation: &Cancellation,
    progress: &mut impl FnMut(&ScanProgress),
) {
    let sizing_started = Instant::now();
    let limits = SizeLimits::default();
    let deadline = (started + request.time_budget).min(sizing_started + limits.time_budget);
    let budget = ProjectSizeBudget {
        visited: AtomicUsize::new(0),
        max_entries: limits.max_entries,
        deadline,
    };
    let identities: HashMap<_, _> = index
        .report()
        .entries
        .iter()
        .filter(|e| e.kind == ResourceKind::Directory)
        .map(|e| (e.path.clone(), e.identity))
        .collect();
    let jobs = preview
        .projects
        .iter()
        .flat_map(|p| p.artifacts.iter())
        .map(|a| (a.path.clone(), identities.get(&a.path).copied()))
        .collect::<Vec<_>>();
    let artifacts = preview
        .projects
        .iter_mut()
        .flat_map(|p| &mut p.artifacts)
        .collect::<Vec<_>>();
    let discovery_complete = artifacts.iter().map(|a| a.complete).collect::<Vec<_>>();
    let mut artifacts = artifacts;
    for artifact in &mut artifacts {
        artifact.complete = false;
        artifact.size_complete = false;
        artifact.private_bytes = None;
        artifact.logical_bytes = None;
        artifact.allocated_bytes = None;
    }
    let mut live = vec![(0usize, 0u64, 0u64); jobs.len()];
    let mut completed = 0;
    let classification_entries = index.report().entries.len();
    let emit = |live: &[(usize, u64, u64)],
                completed: usize,
                issues: usize,
                progress: &mut dyn FnMut(&ScanProgress)| {
        progress(&ScanProgress {
            task_id: index.report().task_id,
            total_artifacts: jobs.len(),
            sized_artifacts: completed,
            entries: classification_entries.saturating_add(live.iter().map(|v| v.0).sum::<usize>()),
            unique_files: live.iter().fold(0u64, |sum, v| sum.saturating_add(v.1)),
            logical_bytes_known: live.iter().fold(0u64, |sum, v| sum.saturating_add(v.2)),
            issues,
            elapsed_ms: started.elapsed().as_millis() as u64,
        });
    };
    // Publish discovery before any size is available; no unvisited artifact is zero.
    emit(&live, completed, preview.scan_issues.len(), progress);
    let next = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        let (sender, receiver) = mpsc::sync_channel(16);
        let mut workers = Vec::new();
        let active_workers = limits.active_workers(request, jobs.len());
        for worker_index in 0..active_workers {
            let sender = sender.clone();
            let jobs = &jobs;
            let next = &next;
            let budget = &budget;
            let limits = &limits;
            let worker = std::thread::Builder::new()
                .name("sayaka-project-size".into())
                .spawn_scoped(scope, move || {
                    loop {
                        let position = next.fetch_add(1, Ordering::Relaxed);
                        let Some((path, identity)) = jobs.get(position) else {
                            break;
                        };
                        let result = if cancellation.is_cancelled() || Instant::now() >= deadline {
                            Err(ScanError::new(
                                if cancellation.is_cancelled() {
                                    ScanCode::Cancelled
                                } else {
                                    ScanCode::DurationLimit
                                },
                                "project sizing stopped before this artifact completed",
                            ))
                        } else if budget.visited.load(Ordering::Acquire) >= budget.max_entries {
                            Err(ScanError::new(
                                ScanCode::EntryLimit,
                                "shared project sizing entry budget reached",
                            ))
                        } else if let Some(identity) = identity {
                            cache::scan_project(
                                path,
                                *identity,
                                &limits.scan(request, deadline, worker_index, active_workers),
                                budget,
                                cancellation,
                                |entries, files, bytes| {
                                    let _ = sender
                                        .send(Event::Progress(position, entries, files, bytes));
                                },
                            )
                        } else {
                            Err(ScanError::new(
                                ScanCode::ChangedEntry,
                                "artifact identity unavailable",
                            ))
                        };
                        if sender.send(Event::Result(position, result)).is_err() {
                            break;
                        }
                    }
                });
            match worker {
                Ok(worker) => workers.push(worker),
                Err(error) => {
                    preview.complete = false;
                    if preview.scan_issues.len() < request.max_issues {
                        preview.scan_issues.push(scan::ScanIssue {
                            owner: None,
                            path: None,
                            code: ScanCode::WorkerStartFailed,
                            message: error.to_string(),
                            os_code: None,
                        });
                    } else {
                        preview.scan_issues_omitted += 1;
                    }
                }
            }
        }
        drop(sender);
        for event in receiver {
            match event {
                Event::Progress(i, entries, files, bytes) => live[i] = (entries, files, bytes),
                Event::Result(i, result) => {
                    completed += 1;
                    let artifact = &mut artifacts[i];
                    match result {
                        Ok(summary) => {
                            live[i] = (
                                summary.entries,
                                summary.files,
                                summary.logical.unwrap_or(live[i].2),
                            );
                            artifact.logical_bytes = summary.logical;
                            artifact.allocated_bytes = summary.allocated;
                            artifact.private_bytes = (discovery_complete[i] && summary.complete).then_some(summary.private).flatten();
                            artifact.size_complete = summary.complete;
                            artifact.complete = discovery_complete[i] && summary.complete;
                            if summary.vcs_metadata > 0 {
                                artifact.git =
                                    crate::project_git::GitObservation::contains_metadata();
                                preview.counts.vcs_metadata += summary.vcs_metadata;
                                preview.counts.excluded += summary.vcs_metadata;
                            }
                            if !summary.complete
                                && (summary.vcs_metadata == 0
                                    || !summary.issues.is_empty()
                                    || summary.omitted > 0
                                    || summary.cancelled)
                            {
                                preview.complete = false;
                            }
                            if summary.cancelled {
                                preview.status = PurgeStatus::Cancelled;
                            }
                            preview.scan_issues_omitted += summary.omitted;
                            for issue in summary.issues {
                                if preview.scan_issues.len() < request.max_issues {
                                    preview.scan_issues.push(issue);
                                } else {
                                    preview.scan_issues_omitted += 1;
                                }
                            }
                        }
                        Err(error) => {
                            if error.code == ScanCode::Cancelled {
                                preview.status = PurgeStatus::Cancelled;
                            }
                            preview.complete = false;
                            if preview.scan_issues.len() < request.max_issues {
                                preview.scan_issues.push(scan::ScanIssue {
                                    owner: None,
                                    path: Some(artifact.path.clone()),
                                    code: error.code,
                                    message: error.message,
                                    os_code: error.os_code,
                                });
                            } else {
                                preview.scan_issues_omitted += 1;
                            }
                        }
                    }
                }
            }
            emit(&live, completed, preview.scan_issues.len(), progress);
        }
        for worker in workers {
            if worker.join().is_err() {
                preview.complete = false;
                if preview.scan_issues.len() < request.max_issues {
                    preview.scan_issues.push(scan::ScanIssue {
                        owner: None,
                        path: None,
                        code: ScanCode::WorkerPanic,
                        message: "project sizing worker panicked".into(),
                        os_code: None,
                    });
                } else {
                    preview.scan_issues_omitted += 1;
                }
            }
        }
    });
    if completed < jobs.len() {
        preview.complete = false;
    }
    if cancellation.is_cancelled() {
        preview.complete = false;
        preview.status = PurgeStatus::Cancelled;
    }
    if !preview.complete && preview.status == PurgeStatus::Complete {
        preview.status = PurgeStatus::Partial;
    }
    if let Some(metrics) = &mut preview.scan_metrics {
        metrics.sizing_entries = budget.visited.load(Ordering::Acquire);
        metrics.sizing_ms = sizing_started.elapsed().as_millis() as u64;
    }
    emit(&live, completed, preview.scan_issues.len(), progress);
}

/// Execution uses streaming metadata too: never reintroduce the retained 100k
/// index cap when a large artifact reached complete preview coverage.
#[cfg(target_os = "macos")]
pub(crate) fn verify_metadata(
    paths: &[PathBuf],
    cancellation: &Cancellation,
) -> Result<(), String> {
    let limits = SizeLimits::default();
    let deadline = Instant::now() + limits.time_budget;
    let budget = ProjectSizeBudget {
        visited: AtomicUsize::new(0),
        max_entries: limits.max_entries,
        deadline,
    };
    for path in paths {
        let identity =
            scan::project_root_identity(path).map_err(|_| "Git metadata coverage unknown")?;
        let summary = cache::scan_project(
            path,
            identity,
            &limits.scan(&ScanLimits::default(), deadline, 0, 1),
            &budget,
            cancellation,
            |_, _, _| {},
        )
        .map_err(|_| "Git metadata coverage unknown")?;
        if summary.vcs_metadata > 0 {
            return Err("Contains Git metadata".into());
        }
        if !summary.complete {
            return Err("Git metadata coverage unknown".into());
        }
    }
    Ok(())
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    #[test]
    fn sizing_partitions_respect_caller_caps_and_actual_concurrency() {
        let limits = SizeLimits::default();
        for (workers, handles, path_bytes, jobs, expected) in [
            (1, 3, 7, 8, 1),
            (4, 6, 17, 8, 2),
            (4, 128, 4096, 1, 1),
            (4, 128, 1, 8, 1),
        ] {
            let request = ScanLimits {
                workers,
                max_open_dirs: handles,
                max_path_bytes: path_bytes,
                ..ScanLimits::default()
            };
            let active = limits.active_workers(&request, jobs);
            assert_eq!(active, expected);
            let shares = (0..active)
                .map(|i| {
                    limits.scan(
                        &request,
                        Instant::now() + Duration::from_secs(60),
                        i,
                        active,
                    )
                })
                .collect::<Vec<_>>();
            assert_eq!(
                shares.iter().map(|s| s.max_open_dirs).sum::<usize>(),
                handles
            );
            assert_eq!(
                shares.iter().map(|s| s.max_path_bytes).sum::<usize>(),
                path_bytes
            );
            assert!(shares.iter().all(|s| s.validate().is_ok()));
        }
        assert_eq!(limits.active_workers(&ScanLimits::default(), 0), 0);
    }

    #[test]
    fn streaming_sizes_deduplicate_links_and_preserve_bounded_subtotals() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        std::fs::write(root.join("first"), b"abcd").unwrap();
        std::fs::hard_link(root.join("first"), root.join("second")).unwrap();
        let identity = scan::project_root_identity(&root).unwrap();
        let budget = ProjectSizeBudget {
            visited: AtomicUsize::new(0),
            max_entries: 10,
            deadline: Instant::now() + Duration::from_secs(10),
        };
        let summary = cache::scan_project(
            &root,
            identity,
            &ScanLimits::default(),
            &budget,
            &Cancellation::default(),
            |_, _, _| {},
        )
        .unwrap();
        assert!(summary.complete);
        assert_eq!(summary.logical, Some(4));
        assert_eq!(summary.files, 1);
        let budget = ProjectSizeBudget {
            visited: AtomicUsize::new(0),
            max_entries: 1,
            deadline: Instant::now() + Duration::from_secs(10),
        };
        let summary = cache::scan_project(
            &root,
            identity,
            &ScanLimits::default(),
            &budget,
            &Cancellation::default(),
            |_, _, _| {},
        )
        .unwrap();
        assert!(!summary.complete);
        assert_eq!(summary.logical, Some(4));
        assert_eq!(budget.visited.load(Ordering::Acquire), 1);
        assert!(
            summary
                .issues
                .iter()
                .any(|i| i.code == ScanCode::EntryLimit)
        );
    }

    #[test]
    fn streaming_sizing_keeps_git_metadata_unvisited() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join(".git/objects")).unwrap();
        std::fs::write(root.join(".git/objects/history"), b"history").unwrap();
        let identity = scan::project_root_identity(&root).unwrap();
        let budget = ProjectSizeBudget {
            visited: AtomicUsize::new(0),
            max_entries: 10,
            deadline: Instant::now() + Duration::from_secs(10),
        };
        let summary = cache::scan_project(
            &root,
            identity,
            &ScanLimits::default(),
            &budget,
            &Cancellation::default(),
            |_, _, _| {},
        )
        .unwrap();
        assert_eq!(summary.vcs_metadata, 1);
        assert_eq!(summary.files, 0);
        assert_eq!(summary.logical, Some(0));
        assert!(!summary.complete);
    }

    #[test]
    fn all_discovered_artifacts_survive_an_expired_sizing_deadline() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        std::fs::write(root.join("Cargo.toml"), b"[package]").unwrap();
        std::fs::create_dir(root.join("target")).unwrap();
        let cancellation = Cancellation::default();
        let request = ScanLimits::default();
        let report = scan::scan_with_policy(
            &[root],
            &request,
            &cancellation,
            scan::TraversalPolicy::ProjectDiscovery,
            |_| {},
        )
        .unwrap();
        let index = ScanTree::build(report, &cancellation).unwrap();
        let mut preview =
            purge_preview(&index, &PurgeOptions::default(), SystemTime::now()).unwrap();
        measure(
            &mut preview,
            &index,
            &request,
            Instant::now() - Duration::from_secs(31),
            &cancellation,
            &mut |_| {},
        );
        assert_eq!(preview.projects[0].artifacts.len(), 1);
        let artifact = &preview.projects[0].artifacts[0];
        assert!(!artifact.size_complete);
        assert!(!artifact.complete);
        assert_eq!(artifact.logical_bytes, None);
        assert_eq!(preview.status, PurgeStatus::Partial);
    }
}
