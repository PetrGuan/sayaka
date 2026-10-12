// SPDX-License-Identifier: MPL-2.0

//! Observed Git state for marker-bound artifacts. Unknown never grants cleanup.
use crate::model::Cancellation;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GitState {
    Untracked,
    Tracked,
    NotRepository,
    ContainsMetadata,
    #[default]
    Unknown,
}
impl GitState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Untracked => "untracked",
            Self::Tracked => "tracked",
            Self::NotRepository => "not_repository",
            Self::ContainsMetadata => "vcs_metadata",
            Self::Unknown => "unknown",
        }
    }
    pub fn reason(self) -> &'static str {
        match self {
            Self::Untracked => "No files tracked by git",
            Self::Tracked => "Contains files tracked by git",
            Self::NotRepository => "Outside a Git repository",
            Self::ContainsMetadata => "Contains Git metadata",
            Self::Unknown => "Git state unknown",
        }
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GitObservation {
    pub state: GitState,
    pub repository: Option<PathBuf>,
    pub ignored: Option<bool>,
    pub tool: Option<String>,
}
impl GitObservation {
    pub fn contains_metadata() -> Self {
        Self {
            state: GitState::ContainsMetadata,
            ..Self::default()
        }
    }
    pub fn permits_cleanup(&self) -> bool {
        matches!(self.state, GitState::Untracked | GitState::NotRepository)
    }
}

pub fn is_metadata_path(path: &Path) -> bool {
    path.components()
        .any(|c| c.as_os_str().eq_ignore_ascii_case(".git"))
}

/// Metadata-only bare repository signature. Fail closed on observation errors;
/// no repository or AI-tool file contents are read. Links at signature paths
/// count conservatively as metadata rather than being followed.
pub(crate) fn bare_repository(path: &Path) -> Result<bool, std::io::Error> {
    for (name, directory) in [("HEAD", false), ("objects", true), ("refs", true)] {
        match std::fs::symlink_metadata(path.join(name)) {
            Ok(m)
                if m.file_type().is_symlink()
                    || (if directory { m.is_dir() } else { m.is_file() }) => {}
            Ok(_) => return Ok(false),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

fn repository(path: &Path) -> Result<Option<PathBuf>, ()> {
    for (depth, ancestor) in path.ancestors().enumerate() {
        if depth >= 64 {
            return Err(());
        }
        match std::fs::symlink_metadata(ancestor) {
            Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {}
            _ => return Err(()),
        }
        match std::fs::symlink_metadata(ancestor.join(".git")) {
            Ok(m) if m.is_dir() || m.is_file() => return Ok(Some(ancestor.to_path_buf())),
            Ok(_) => return Err(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(()),
        }
        // Bare repositories are never treated as generated project output.
        if bare_repository(ancestor).map_err(|_| ())? {
            return Err(());
        }
    }
    Ok(None)
}

/// Groups queries per repository and resolves the fixed executable once per call.
/// Observations are cached only for this preview/approval, never across operations.
pub fn inspect(
    paths: &[PathBuf],
    cancellation: &Cancellation,
) -> BTreeMap<PathBuf, GitObservation> {
    inspect_before(
        paths,
        cancellation,
        Instant::now() + Duration::from_secs(30),
    )
}

pub(crate) fn inspect_before(
    paths: &[PathBuf],
    cancellation: &Cancellation,
    deadline: Instant,
) -> BTreeMap<PathBuf, GitObservation> {
    let mut result = BTreeMap::new();
    let mut repositories: BTreeMap<PathBuf, Vec<PathBuf>> = BTreeMap::new();
    for path in paths {
        let mut observation = GitObservation::default();
        if is_metadata_path(path) {
            observation = GitObservation::contains_metadata();
        } else if !cancellation.is_cancelled() && Instant::now() < deadline {
            match path.parent().ok_or(()).and_then(repository) {
                Ok(Some(repo)) => {
                    observation.repository = Some(repo.clone());
                    repositories.entry(repo).or_default().push(path.clone());
                }
                Ok(None) => observation.state = GitState::NotRepository,
                Err(()) => {}
            }
        }
        result.insert(path.clone(), observation);
    }
    #[cfg(target_os = "macos")]
    if !repositories.is_empty()
        && let Ok(reader) = sayaka_platform_macos::project_git::GitReader::new()
    {
        for (repo, paths) in repositories {
            if cancellation.is_cancelled() || Instant::now() >= deadline {
                break;
            }
            for path in &paths {
                result.get_mut(path).unwrap().tool = Some(reader.evidence().to_owned());
            }
            if let Ok(states) = reader.inspect(
                &repo,
                &paths,
                deadline.saturating_duration_since(Instant::now()),
                &|| cancellation.is_cancelled(),
            ) {
                for (path, state) in paths.iter().zip(states) {
                    let observation = result.get_mut(path).unwrap();
                    observation.state = if state.tracked {
                        GitState::Tracked
                    } else if state.ignored.is_some() {
                        GitState::Untracked
                    } else {
                        GitState::Unknown
                    };
                    observation.ignored = state.ignored;
                }
            }
        }
    }
    result
}

/// Fresh filesystem coverage is required at the native session boundary too:
/// public selections are not trusted proof that a directory has no nested repo.
#[cfg(target_os = "macos")]
pub(crate) fn require_cleanup(
    paths: &[PathBuf],
    cancellation: &Cancellation,
) -> Result<(), String> {
    let observations = inspect(paths, cancellation);
    for path in paths {
        let observation = observations.get(path).ok_or("Git state unknown")?;
        if !observation.permits_cleanup() {
            return Err(observation.state.reason().into());
        }
    }
    crate::purge_preview::task::verify_metadata(paths, cancellation)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn metadata_exclusion_is_component_based_and_fail_closed() {
        assert!(is_metadata_path(Path::new("/repo/.GIT/objects")));
        assert!(!is_metadata_path(Path::new("/repo/.github/build")));
        assert!(!GitObservation::default().permits_cleanup());
        assert!(!GitObservation::contains_metadata().permits_cleanup());
        assert!(
            !GitObservation {
                state: GitState::Tracked,
                ..Default::default()
            }
            .permits_cleanup()
        );
        assert!(
            GitObservation {
                state: GitState::Untracked,
                ..Default::default()
            }
            .permits_cleanup()
        );
    }
}

#[cfg(all(test, target_os = "macos"))]
mod admission_tests {
    use super::*;
    #[test]
    fn nested_bare_repository_refuses_cleanup_admission() {
        let temporary = tempfile::tempdir().unwrap();
        let artifact = temporary.path().canonicalize().unwrap().join("target");
        let bare = artifact.join("saved-history");
        std::fs::create_dir_all(bare.join("objects")).unwrap();
        std::fs::create_dir_all(bare.join("refs")).unwrap();
        std::fs::write(bare.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
        assert!(bare_repository(&bare).unwrap());
        assert_eq!(
            require_cleanup(&[artifact], &Cancellation::default()).unwrap_err(),
            "Contains Git metadata"
        );
    }
}
