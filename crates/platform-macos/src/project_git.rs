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
