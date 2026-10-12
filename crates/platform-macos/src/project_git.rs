// SPDX-License-Identifier: MPL-2.0

//! Fixed read-only Git boundary. No shell, inherited Git configuration environment,
//! credentials, hooks, fsmonitor process, index refresh, or worktree operations.
use crate::devtools;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

const GIT: &str = "/usr/bin/git";
const MAX_OUTPUT: usize = 1024 * 1024;
const MAX_ARGUMENT_BYTES: usize = 64 * 1024;

pub struct GitReader {
    identity: String,
    env: Vec<(OsString, OsString)>,
}

#[derive(Debug)]
pub struct ArtifactState {
    pub tracked: bool,
    pub ignored: Option<bool>,
}

fn identity() -> Result<String, ()> {
    let path = std::fs::canonicalize(GIT).map_err(|_| ())?;
    let m = std::fs::metadata(&path).map_err(|_| ())?;
    if !m.is_file() {
        return Err(());
    }
    Ok(format!(
        "{}:{}:{}:{}:{}:{}",
        path.display(),
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec()
    ))
}

impl GitReader {
    pub fn new() -> Result<Self, ()> {
        devtools::verify_code_requirement(Path::new(GIT), "anchor apple").map_err(|_| ())?;
        let identity = identity()?;
        let mut env = devtools::allowed_environment().map_err(|_| ())?;
        for (k, v) in [
            ("GIT_OPTIONAL_LOCKS", "0"),
            ("GIT_CONFIG_NOSYSTEM", "1"),
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
            ("GIT_TERMINAL_PROMPT", "0"),
            ("GIT_NO_LAZY_FETCH", "1"),
        ] {
            env.push((k.into(), v.into()));
        }
        Ok(Self { identity, env })
    }
    pub fn evidence(&self) -> &str {
        &self.identity
    }

    /// Exactly two batched read-only queries sharing one two-second repository budget.
    /// Failed/oversized/ambiguous output is unknown, never proof of an empty index.
    pub fn inspect(
        &self,
        repo: &Path,
        artifacts: &[PathBuf],
        remaining: Duration,
        cancel: &dyn Fn() -> bool,
    ) -> Result<Vec<ArtifactState>, ()> {
        let deadline = Instant::now() + remaining.min(Duration::from_secs(2));
        if !repo.is_absolute() || artifacts.is_empty() {
            return Err(());
        }
        let paths = artifacts
            .iter()
            .map(|p| {
                let rel = p.strip_prefix(repo).map_err(|_| ())?;
                if rel.as_os_str().is_empty()
                    || !rel.components().all(|c| matches!(c, Component::Normal(_)))
                {
                    return Err(());
                }
                Ok(rel.to_path_buf())
            })
            .collect::<Result<Vec<_>, ()>>()?;
        let prefix = || {
            vec![
                OsString::from("-c"),
                "core.fsmonitor=false".into(),
                "-c".into(),
                "core.hooksPath=/dev/null".into(),
                "-C".into(),
                repo.as_os_str().to_owned(),
            ]
        };
        let mut args = prefix();
        args.extend([
            "ls-files".into(),
            "--cached".into(),
            "--full-name".into(),
            "-z".into(),
            "--".into(),
        ]);
        // A fixed magic prefix makes metacharacters literal; case folding prevents
        // ordinary macOS filename-case differences from hiding tracked descendants.
        args.extend(paths.iter().map(|p| {
            let mut spec = OsString::from(":(icase,literal)");
            spec.push(p.as_os_str());
            spec
        }));
        let tracked = self.run(&args, deadline, cancel, None)?;
        if !tracked.success {
            return Err(());
        }
        let mut states = paths
            .iter()
            .map(|_| ArtifactState {
                tracked: false,
                ignored: None,
            })
            .collect::<Vec<_>>();
        for file in nul_paths(&tracked.stdout)? {
            let mut matched = false;
            for (i, path) in paths.iter().enumerate() {
                if prefix_ascii_case(&file, path) {
                    states[i].tracked = true;
                    matched = true;
                }
            }
            if !matched {
                return Err(());
            }
        }
        let mut args = prefix();
        args.extend(["check-ignore".into(), "-z".into(), "--stdin".into()]);
        let mut input = Vec::new();
        for path in &paths {
            input.extend_from_slice(path.as_os_str().as_bytes());
            input.push(0);
        }
        let Ok(ignored) = self.run(&args, deadline, cancel, Some(&input)) else {
            return Ok(states);
        };
        if !matches!(ignored.code, Some(0 | 1)) {
            return Ok(states);
        }
        let Ok(ignored_paths) = nul_paths(&ignored.stdout) else {
            return Ok(states);
        };
        for state in &mut states {
            state.ignored = Some(false);
        }
        for file in ignored_paths {
            let Some(i) = paths.iter().position(|p| p == &file) else {
                return Err(());
            };
            states[i].ignored = Some(true);
        }
        Ok(states)
    }

    /// Commit date and porcelain status, bounded to two seconds and no index refresh.
    pub fn activity(&self, repo: &Path, remaining: Duration, cancel: &dyn Fn() -> bool)
        -> (Option<i64>, Option<bool>) {
        let deadline = Instant::now() + remaining.min(Duration::from_secs(2));
        let prefix = || vec![OsString::from("-c"), "core.fsmonitor=false".into(),
            "-c".into(), "core.hooksPath=/dev/null".into(), "-C".into(), repo.as_os_str().to_owned()];
        let mut args = prefix();
        args.extend(["log".into(), "-1".into(), "--format=%ct".into(), "--no-show-signature".into()]);
        let commit = self.run(&args, deadline, cancel, None).ok().filter(|o| o.success)
            .and_then(|o| std::str::from_utf8(&o.stdout).ok()?.trim().parse::<i64>().ok())
            .filter(|n| *n >= 0).and_then(|n| n.checked_mul(1000));
        let mut args = prefix();
        args.extend(["status".into(), "--porcelain=v1".into(), "-z".into(), "--untracked-files=normal".into(), "--ignore-submodules=all".into()]);
        let dirty = self.run(&args, deadline, cancel, None).ok().filter(|o| o.success)
            .map(|o| !o.stdout.is_empty());
        (commit, dirty)
    }

    /// NUL-delimited records preserve native paths, including newlines.
    pub fn worktrees(&self, repo: &Path, remaining: Duration, cancel: &dyn Fn() -> bool) -> Result<Vec<Worktree>, ()> {
        let deadline = Instant::now() + remaining.min(Duration::from_secs(2));
        let output = self.worktree_command(repo, &["worktree", "list", "--porcelain", "-z"], deadline, cancel)?;
        parse_worktrees(&output)
    }

    pub fn worktree_details(&self, path: &Path, remaining: Duration, cancel: &dyn Fn() -> bool) -> WorktreeDetails {
        let deadline = Instant::now() + remaining.min(Duration::from_secs(2));
        let command = |args: &[&str]| self.worktree_command(path, args, deadline, cancel);
        let changed_files = command(&["status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none"])
            .ok().and_then(|bytes| status_count(&bytes).ok());
        let last_commit_ms = command(&["log", "-1", "--format=%ct", "--no-show-signature"]).ok()
            .and_then(|b| parse_number(&b)).and_then(|n| i64::try_from(n).ok()).and_then(|n| n.checked_mul(1000));
        // Shallow history cannot establish whether all commits occur on remote refs.
        let complete_history = command(&["rev-parse", "--is-shallow-repository"]).ok().is_some_and(|b| b == b"false\n");
        let local_only_commits = if complete_history {
            command(&["rev-list", "--count", "HEAD", "--not", "--remotes"]).ok().and_then(|b| parse_number(&b))
        } else { None };
        WorktreeDetails { changed_files, last_commit_ms, local_only_commits }
    }

    fn worktree_command(&self, repo: &Path, command: &[&str], deadline: Instant, cancel: &dyn Fn() -> bool) -> Result<Vec<u8>, ()> {
        if !repo.is_absolute() { return Err(()); }
        let mut args = vec!["-c".into(), "core.fsmonitor=false".into(), "-c".into(), "core.hooksPath=/dev/null".into(), "--no-replace-objects".into(), "-C".into(), repo.as_os_str().to_owned()];
        args.extend(command.iter().map(OsString::from));
        let result = self.run(&args, deadline, cancel, None)?;
        if result.success { Ok(result.stdout) } else { Err(()) }
    }

    fn run(
        &self,
        args: &[OsString],
        deadline: Instant,
        cancel: &dyn Fn() -> bool,
        input: Option<&[u8]>,
    ) -> Result<devtools::ToolOutput, ()> {
        if args.iter().map(|s| s.len() + 1).sum::<usize>() > MAX_ARGUMENT_BYTES
            || identity()? != self.identity
        {
            return Err(());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(());
        }
        if input.is_some_and(|data| data.len() > MAX_ARGUMENT_BYTES) {
            return Err(());
        }
        let result = devtools::run_bounded_native_input_cancellable(
            Path::new(GIT),
            args,
            &self.env,
            remaining,
            MAX_OUTPUT,
            16 * 1024,
            cancel,
            input,
        )
        .map_err(|_| ())?;
        if Instant::now() >= deadline || identity()? != self.identity {
            return Err(());
        }
        Ok(result)
    }
}

fn nul_paths(bytes: &[u8]) -> Result<Vec<PathBuf>, ()> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if bytes.last() != Some(&0) {
        return Err(());
    }
    bytes[..bytes.len() - 1]
        .split(|b| *b == 0)
        .map(|bytes| {
            let path = PathBuf::from(OsString::from_vec(bytes.to_vec()));
            if bytes.is_empty() || !path.components().all(|c| matches!(c, Component::Normal(_))) {
                return Err(());
            }
            Ok(path)
        })
        .collect()
}

fn prefix_ascii_case(path: &Path, prefix: &Path) -> bool {
    let mut parts = path.components();
    prefix.components().all(|p| {
        parts.next().is_some_and(|next| {
            OsStr::as_bytes(next.as_os_str()).eq_ignore_ascii_case(p.as_os_str().as_bytes())
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn literal_native_records_and_component_boundaries() {
        let records = nul_paths(b"build/a\nfile\0build/\xff\0").unwrap();
        assert_eq!(records.len(), 2);
        assert!(prefix_ascii_case(&records[0], Path::new("BUILD")));
        assert!(!prefix_ascii_case(
            Path::new("build-other/a"),
            Path::new("build")
        ));
        assert!(nul_paths(b"../outside\0").is_err());
        assert!(nul_paths(b"build/a").is_err());
    }
}

/// Observations only: never cleanup authority.
#[derive(Clone, Debug)]
pub struct Worktree {
    pub path: PathBuf,
    pub branch: Option<String>,
    pub detached: bool,
    pub bare: bool,
    pub locked: bool,
    pub prunable: bool,
}
#[derive(Clone, Debug, Default)]
pub struct WorktreeDetails {
    pub changed_files: Option<u64>,
    pub last_commit_ms: Option<i64>,
    pub local_only_commits: Option<u64>,
}
fn parse_number(bytes: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(bytes).ok()?.trim();
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) { return None; }
    text.parse().ok()
}
fn parse_worktrees(bytes: &[u8]) -> Result<Vec<Worktree>, ()> {
    if bytes.is_empty() || !bytes.ends_with(b"\0\0") { return Err(()); }
    let mut result = Vec::new();
    let mut current: Option<Worktree> = None;
    for record in bytes[..bytes.len()-1].split(|b| *b == 0) {
        if record.is_empty() {
            result.push(current.take().ok_or(())?);
            if result.len() > 256 { return Err(()); }
        } else if let Some(path) = record.strip_prefix(b"worktree ") {
            if current.is_some() { return Err(()); }
            let path = PathBuf::from(OsString::from_vec(path.to_vec()));
            if !path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir | Component::CurDir)) { return Err(()); }
            current = Some(Worktree { path, branch: None, detached: false, bare: false, locked: false, prunable: false });
        } else {
            let item = current.as_mut().ok_or(())?;
            if let Some(branch) = record.strip_prefix(b"branch ") { item.branch = Some(String::from_utf8_lossy(branch).into_owned()); }
            else if record == b"detached" { item.detached = true; }
            else if record == b"bare" { item.bare = true; }
            else if record == b"locked" || record.starts_with(b"locked ") { item.locked = true; }
            else if record == b"prunable" || record.starts_with(b"prunable ") { item.prunable = true; }
            else if !record.starts_with(b"HEAD ") { return Err(()); }
        }
    }
    if current.is_some() { return Err(()); }
    Ok(result)
}
fn status_count(bytes: &[u8]) -> Result<u64, ()> {
    if bytes.is_empty() { return Ok(0); }
    if bytes.last() != Some(&0) { return Err(()); }
    let mut records = bytes[..bytes.len()-1].split(|b| *b == 0);
    let mut count = 0;
    while let Some(record) = records.next() {
        if record.len() < 4 || record[2] != b' ' { return Err(()); }
        if record[..2].iter().any(|b| !b" MTADRCU?!".contains(b)) { return Err(()); }
        if record[..2].iter().any(|b| *b == b'R' || *b == b'C') && records.next().is_none_or(|r| r.is_empty()) { return Err(()); }
        count += 1;
    }
    Ok(count)
}

#[cfg(test)]
mod worktree_tests {
    use super::*;
    #[test]
    fn nul_records_keep_native_paths_and_flags() {
        let items = parse_worktrees(b"worktree /repo\nname\0HEAD abc\0branch refs/heads/main\0\0worktree /other/\xff\0HEAD def\0detached\0locked reason\nnext\0prunable missing\0\0").unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].path.as_os_str().as_bytes(), b"/repo\nname");
        assert!(items[1].locked && items[1].prunable && items[1].detached);
        assert_eq!(items[1].path.as_os_str().as_bytes(), b"/other/\xff");
        assert!(parse_worktrees(b"worktree relative\0\0").is_err());
        assert!(parse_worktrees(b"worktree /repo\0").is_err());
    }
    #[test]
    fn rename_counts_once_and_untracked_files_are_counted() {
        assert_eq!(status_count(b"R  new\0old\0?? new file\0 M tracked\0"), Ok(3));
        assert_eq!(status_count(b""), Ok(0));
        assert!(status_count(b"R  new\0").is_err());
        assert!(status_count(b"?? path").is_err());
        assert_eq!(parse_number(b"12\n"), Some(12));
        assert_eq!(parse_number(b"-1\n"), None);
    }
}
