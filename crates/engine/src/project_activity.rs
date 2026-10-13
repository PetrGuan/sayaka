// SPDX-License-Identifier: MPL-2.0
//! Project-level observations, never cached across preview/execute boundaries.
use serde::Serialize;
#[derive(Clone, Debug, Default, Serialize)]
pub struct ProjectActivity {
    pub last_commit_at: Option<i64>,
    pub last_source_change_at: Option<i64>,
    pub artifact_modified_at: Option<i64>,
    pub uncommitted: Option<bool>,
    /// None means process visibility could not establish inactivity.
    pub build_running: Option<bool>,
    pub source_complete: bool,
}
impl ProjectActivity {
    pub fn last_activity(&self) -> Option<i64> {
        // Build-folder mtime is only a fallback: rebuilding old output is not editing source.
        self.last_commit_at
            .max(self.last_source_change_at)
            .or(self.artifact_modified_at)
    }
    pub fn stale(&self, now_ms: i64, days: u32) -> Option<bool> {
        if !self.source_complete || self.uncommitted.is_none() || self.build_running.is_none() {
            return None;
        }
        if self.uncommitted == Some(true) || self.build_running == Some(true) {
            return Some(false);
        }
        self.last_activity()
            .map(|date| now_ms.saturating_sub(date) >= i64::from(days) * 86_400_000)
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn observe(
    preview: &mut crate::purge_preview::PurgePreview,
    cancellation: &crate::model::Cancellation,
    deadline: std::time::Instant,
) {
    use sayaka_platform_macos::{project_activity as native, project_git::GitReader};
    use std::collections::BTreeMap;
    use std::time::{Instant, SystemTime, UNIX_EPOCH};
    preview.counts.stale_artifacts = 0;
    // Classification has already finished. With no artifact to assess, process
    // enumeration and signed Git-tool resolution cannot change any observation.
    // Do not spend a fresh native activity budget on an empty saved location.
    if preview.projects.iter().all(|project| project.artifacts.is_empty()) {
        return;
    }
    let builds = native::builds(&|| cancellation.is_cancelled() || Instant::now() >= deadline);
    let reader = GitReader::new().ok();
    let mut git = BTreeMap::new();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|v| i64::try_from(v.as_millis()).ok())
        .unwrap_or(0);
    for project in &mut preview.projects {
        let artifacts = project
            .artifacts
            .iter()
            .map(|a| a.path.clone())
            .collect::<Vec<_>>();
        let source = native::sources(&project.root, &artifacts, &|| {
            cancellation.is_cancelled() || Instant::now() >= deadline
        });
        let repo = project
            .artifacts
            .iter()
            .find_map(|a| a.git.repository.as_ref());
        let (commit, dirty) = if let Some(repo) = repo {
            *git.entry(repo.clone()).or_insert_with(|| {
                reader
                    .as_ref()
                    .map(|r| {
                        r.activity(
                            repo,
                            deadline.saturating_duration_since(Instant::now()),
                            &|| cancellation.is_cancelled(),
                        )
                    })
                    .unwrap_or((None, None))
            })
        } else if project
            .artifacts
            .iter()
            .all(|a| a.git.state == crate::project_git::GitState::NotRepository)
        {
            (None, Some(false))
        } else {
            (None, None)
        };
        let lock = native::locks(&project.root, &|| {
            cancellation.is_cancelled() || Instant::now() >= deadline
        });
        let running = combine(builds.running(&project.root), lock);
        for artifact in &mut project.artifacts {
            let activity = ProjectActivity {
                last_commit_at: commit,
                last_source_change_at: source.newest_unix_ms,
                artifact_modified_at: artifact.modified_unix_ms,
                uncommitted: dirty,
                build_running: running,
                source_complete: source.complete,
            };
            artifact.stale = activity.stale(now, preview.stale_days);
            if artifact.stale == Some(true) {
                preview.counts.stale_artifacts += 1;
            }
            artifact.project_activity = Some(activity);
        }
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn require_idle(
    roots: &[std::path::PathBuf],
    cancellation: &crate::model::Cancellation,
) -> Result<(), String> {
    let builds = sayaka_platform_macos::project_activity::builds(&|| cancellation.is_cancelled());
    for root in roots {
        match combine(
            builds.running(root),
            sayaka_platform_macos::project_activity::locks(root, &|| cancellation.is_cancelled()),
        ) {
            Some(false) => {}
            Some(true) => return Err("A build is running in this project".into()),
            None => return Err("Project build activity could not be verified".into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_activity_overrides_fresh_output_and_unknown_is_not_stale() {
        let day = 86_400_000;
        let mut a = ProjectActivity {
            last_commit_at: Some(day),
            last_source_change_at: Some(day),
            artifact_modified_at: Some(60 * day),
            uncommitted: Some(false),
            build_running: Some(false),
            source_complete: true,
        };
        assert_eq!(a.stale(61 * day, 30), Some(true));
        a.last_commit_at = Some(61 * day);
        assert_eq!(a.stale(61 * day, 30), Some(false));
        a.build_running = None;
        assert_eq!(a.stale(61 * day, 30), None);
    }
}

#[cfg(target_os = "macos")]
fn combine(process: Option<bool>, lock: Option<bool>) -> Option<bool> {
    if process == Some(true) || lock == Some(true) {
        Some(true)
    } else if process == Some(false) && lock == Some(false) {
        Some(false)
    } else {
        None
    }
}
