// SPDX-License-Identifier: MPL-2.0
//! Bounded metadata-only activity observations. No source or AI-tool contents.
use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Default)]
pub struct Sources {
    pub newest_unix_ms: Option<i64>,
    pub complete: bool,
}
#[derive(Default)]
pub struct Builds {
    pub directories: Vec<PathBuf>,
    pub complete: bool,
}
impl Builds {
    pub fn running(&self, project: &Path) -> Option<bool> {
        if self.directories.iter().any(|cwd| cwd.starts_with(project)) {
            Some(true)
        } else if self.complete {
            Some(false)
        } else {
            None
        }
    }
}
fn build_tool(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|n| n.to_str()),
        Some(
            "cargo"
                | "rustc"
                | "xcodebuild"
                | "swift-build"
                | "swift"
                | "node"
                | "npm"
                | "pnpm"
                | "yarn"
                | "gradle"
                | "java"
        )
    )
}
/// Same-user census. Unreadable or changing processes cannot prove inactivity.
/// Reused once per preview; native execution takes a fresh census.
pub fn builds(cancel: &dyn Fn() -> bool) -> Builds {
    let mut result = Builds {
        complete: true,
        ..Builds::default()
    };
    let deadline = Instant::now() + Duration::from_secs(2);
    let uid = unsafe { libc::geteuid() };
    let mut pids = vec![0i32; 65536];
    let capacity = std::mem::size_of_val(pids.as_slice());
    // SAFETY: writable PID buffer with exact capacity, same-user metadata query.
    let bytes = unsafe { libc::proc_listpids(4, uid, pids.as_mut_ptr().cast(), capacity as i32) };
    if bytes <= 0 || bytes as usize >= capacity || bytes as usize % 4 != 0 {
        return Builds::default();
    }
    for &pid in &pids[..bytes as usize / 4] {
        if pid <= 0 {
            continue;
        }
        if cancel() || Instant::now() >= deadline {
            result.complete = false;
            break;
        }
        let before = match crate::related::process_identity(pid) {
            Ok(v) if v.0 == uid => v,
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => continue,
            _ => {
                result.complete = false;
                continue;
            }
        };
        let mut path = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        // SAFETY: capacity-sized writable buffer for executable path.
        let n = unsafe { libc::proc_pidpath(pid, path.as_mut_ptr().cast(), path.len() as u32) };
        if n <= 0 || n as usize >= path.len() {
            result.complete = false;
            continue;
        }
        let executable = Path::new(std::ffi::OsStr::from_bytes(&path[..n as usize]));
        if crate::related::process_identity(pid).ok() != Some(before) {
            result.complete = false;
            continue;
        }
        if !build_tool(executable) {
            continue;
        }
        // SAFETY: initialized native structure with exact size and known flavor.
        let mut info: libc::proc_vnodepathinfo = unsafe { std::mem::zeroed() };
        let n = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDVNODEPATHINFO,
                0,
                (&mut info as *mut libc::proc_vnodepathinfo).cast(),
                std::mem::size_of_val(&info) as i32,
            )
        };
        if n as usize != std::mem::size_of_val(&info)
            || crate::related::process_identity(pid).ok() != Some(before)
        {
            result.complete = false;
            continue;
        }
        let raw: Vec<i8> = info.pvi_cdir.vip_path.iter().flatten().copied().collect();
        let Some(end) = raw.iter().position(|c| *c == 0) else {
            result.complete = false;
            continue;
        };
        let bytes: Vec<u8> = raw[..end].iter().map(|b| *b as u8).collect();
        let cwd = PathBuf::from(std::ffi::OsStr::from_bytes(&bytes));
        if cwd.is_absolute() {
            result.directories.push(cwd);
        } else {
            result.complete = false;
        }
    }
    result
}

fn directory(path: &Path) -> io::Result<OwnedFd> {
    let path = CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: NUL-terminated path; no-follow applies to every component.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_NOFOLLOW_ANY
                | libc::O_NONBLOCK
                | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}
fn stat(fd: i32, name: &CStr) -> io::Result<libc::stat> {
    let mut s: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: live directory fd, NUL name, initialized output; no links followed.
    if unsafe { libc::fstatat(fd, name.as_ptr(), &mut s, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(s)
    }
}
fn time(s: &libc::stat) -> Option<i64> {
    s.st_mtime
        .checked_mul(1000)?
        .checked_add(s.st_mtime_nsec / 1_000_000)
}
fn excluded(name: &[u8]) -> bool {
    // Artifact directories and tool-owned data are not source activity signals.
    matches!(
        name,
        b".git"
            | b".claude"
            | b".codex"
            | b".copilot"
            | b".cursor"
            | b".aider"
            | b".gemini"
            | b".windsurf"
            | b".vscode"
            | b".idea"
            | b"target"
            | b"node_modules"
            | b"dist"
            | b"build"
            | b".build"
            | b".next"
            | b".nuxt"
            | b".output"
            | b".svelte-kit"
            | b".angular"
            | b".parcel-cache"
            | b".turbo"
            | b".vite"
            | b".gradle"
            | b"Pods"
            | b".dart_tool"
            | b".venv"
            | b"venv"
            | b"__pycache__"
            | b".pytest_cache"
            | b".mypy_cache"
            | b".ruff_cache"
            | b".cache"
    )
}
/// At most two levels / 500 directory entries / one second per project.
/// Unknown metadata or a spent budget is explicitly incomplete.
pub fn sources(root: &Path, artifacts: &[PathBuf], cancel: &dyn Fn() -> bool) -> Sources {
    let mut out = Sources {
        complete: true,
        ..Sources::default()
    };
    let Ok(_policy) = crate::ReadOnlyPolicy::enter() else {
        return Sources::default();
    };
    let Ok(fd) = directory(root) else {
        return Sources::default();
    };
    let Ok(root_stat) = stat(fd.as_raw_fd(), c".") else {
        return Sources::default();
    };
    if root_stat.st_flags & 0x40000000 != 0 {
        return Sources::default();
    }
    let mut remaining = 500usize;
    let deadline = Instant::now() + Duration::from_secs(1);
    fn walk(
        fd: OwnedFd,
        path: &Path,
        depth: u8,
        device: i32,
        artifacts: &[PathBuf],
        remaining: &mut usize,
        deadline: Instant,
        cancel: &dyn Fn() -> bool,
        out: &mut Sources,
    ) {
        // SAFETY: dup creates a separate fd owned by fdopendir/closedir.
        let copy = unsafe { libc::dup(fd.as_raw_fd()) };
        if copy < 0 {
            out.complete = false;
            return;
        }
        let dir = unsafe { libc::fdopendir(copy) };
        if dir.is_null() {
            unsafe { libc::close(copy) };
            out.complete = false;
            return;
        }
        loop {
            if cancel() || Instant::now() >= deadline || *remaining == 0 {
                out.complete = false;
                break;
            }
            // SAFETY: live DIR; errno is thread-local. d_name is NUL terminated.
            unsafe {
                *libc::__error() = 0;
            }
            let entry = unsafe { libc::readdir(dir) };
            if entry.is_null() {
                if unsafe { *libc::__error() } != 0 {
                    out.complete = false;
                }
                break;
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            if matches!(name.to_bytes(), b"." | b"..") {
                continue;
            }
            *remaining -= 1;
            let child = path.join(std::ffi::OsStr::from_bytes(name.to_bytes()));
            if excluded(name.to_bytes()) || artifacts.iter().any(|a| child.starts_with(a)) {
                continue;
            }
            let Ok(s) = stat(fd.as_raw_fd(), name) else {
                out.complete = false;
                continue;
            };
            if s.st_flags & 0x40000000 != 0 || s.st_dev != device {
                out.complete = false;
                continue;
            }
            if s.st_mode & libc::S_IFMT == libc::S_IFREG {
                out.newest_unix_ms = out.newest_unix_ms.max(time(&s));
            } else if s.st_mode & libc::S_IFMT == libc::S_IFDIR && depth < 1 {
                // SAFETY: descriptor-relative no-follow open; compare identity before walking.
                let child_fd = unsafe {
                    libc::openat(
                        fd.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY
                            | libc::O_DIRECTORY
                            | libc::O_NOFOLLOW
                            | libc::O_NONBLOCK
                            | libc::O_CLOEXEC,
                    )
                };
                if child_fd < 0 {
                    out.complete = false;
                    continue;
                }
                let child_fd = unsafe { OwnedFd::from_raw_fd(child_fd) };
                if stat(child_fd.as_raw_fd(), c".").is_ok_and(|v| {
                    v.st_dev == s.st_dev && v.st_ino == s.st_ino && v.st_flags & 0x40000000 == 0
                }) {
                    walk(
                        child_fd,
                        &child,
                        depth + 1,
                        device,
                        artifacts,
                        remaining,
                        deadline,
                        cancel,
                        out,
                    );
                } else {
                    out.complete = false;
                }
            }
        }
        unsafe {
            libc::closedir(dir);
        }
    }
    walk(
        fd,
        root,
        0,
        root_stat.st_dev,
        artifacts,
        &mut remaining,
        deadline,
        cancel,
        &mut out,
    );
    // Read only the HEAD/index metadata; never enumerate objects or read Git contents.
    if let Ok(git) = directory(&root.join(".git")) {
        for name in [c"HEAD", c"index"] {
            match stat(git.as_raw_fd(), name) {
                Ok(s) if s.st_mode & libc::S_IFMT == libc::S_IFREG => {
                    out.newest_unix_ms = out.newest_unix_ms.max(time(&s))
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                _ => out.complete = false,
            }
        }
    }
    out
}

/// Lock checks supplement the process census. Shared nonblocking flock is
/// released immediately; no lock file is created, truncated or written.
pub fn locks(root: &Path, cancel: &dyn Fn() -> bool) -> Option<bool> {
    let _policy = crate::ReadOnlyPolicy::enter().ok()?;
    let base = directory(root).ok()?;
    let dev = stat(base.as_raw_fd(), c".").ok()?.st_dev;
    fn lock(fd: i32, name: &CStr, dev: i32) -> Option<bool> {
        let before = match stat(fd, name) {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Some(false),
            _ => return None,
        };
        if before.st_mode & libc::S_IFMT != libc::S_IFREG
            || before.st_flags & 0x40000000 != 0
            || before.st_dev != dev
        {
            return None;
        }
        // SAFETY: read-only no-follow descriptor, identity checked after open.
        let raw = unsafe {
            libc::openat(
                fd,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return None;
        }
        let file = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut after: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(file.as_raw_fd(), &mut after) } != 0
            || before.st_dev != after.st_dev
            || before.st_ino != after.st_ino
        {
            return None;
        }
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } != 0 {
            return if io::Error::last_os_error().raw_os_error() == Some(libc::EWOULDBLOCK) {
                Some(true)
            } else {
                None
            };
        }
        unsafe {
            libc::flock(file.as_raw_fd(), libc::LOCK_UN);
        }
        let mut query: libc::flock = unsafe { std::mem::zeroed() };
        query.l_type = libc::F_WRLCK;
        query.l_whence = libc::SEEK_SET as i16;
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETLK, &mut query) } < 0 {
            return None;
        }
        Some(query.l_type != libc::F_UNLCK)
    }
    let deadline = Instant::now() + Duration::from_millis(250);
    let mut budget = 500usize;
    fn walk(
        fd: OwnedFd,
        depth: u8,
        dev: i32,
        budget: &mut usize,
        deadline: Instant,
        cancel: &dyn Fn() -> bool,
    ) -> Option<bool> {
        if cancel() || Instant::now() >= deadline {
            return None;
        }
        if lock(fd.as_raw_fd(), c".cargo-lock", dev)? {
            return Some(true);
        }
        let raw = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if raw < 0 {
            return None;
        }
        let dir = unsafe { libc::fdopendir(raw) };
        if dir.is_null() {
            unsafe { libc::close(raw) };
            return None;
        }
        struct Dir(*mut libc::DIR);
        impl Drop for Dir {
            fn drop(&mut self) {
                unsafe {
                    libc::closedir(self.0);
                }
            }
        }
        let dir = Dir(dir);
        loop {
            if *budget == 0 || cancel() || Instant::now() >= deadline {
                return None;
            }
            unsafe {
                *libc::__error() = 0;
            }
            let entry = unsafe { libc::readdir(dir.0) };
            if entry.is_null() {
                return if unsafe { *libc::__error() } == 0 {
                    Some(false)
                } else {
                    None
                };
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            // Cargo never stores its profile-level lock inside generated leaf trees.
            if matches!(
                name.to_bytes(),
                b"." | b".." | b"deps" | b"build" | b"incremental" | b".fingerprint" | b".git"
            ) {
                continue;
            }
            *budget -= 1;
            let s = stat(fd.as_raw_fd(), name).ok()?;
            if s.st_mode & libc::S_IFMT != libc::S_IFDIR {
                continue;
            }
            if depth >= 3 || s.st_flags & 0x40000000 != 0 || s.st_dev != dev {
                return None;
            }
            let raw = unsafe {
                libc::openat(
                    fd.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY
                        | libc::O_DIRECTORY
                        | libc::O_NOFOLLOW
                        | libc::O_NONBLOCK
                        | libc::O_CLOEXEC,
                )
            };
            if raw < 0 {
                return None;
            }
            let child = unsafe { OwnedFd::from_raw_fd(raw) };
            let check = stat(child.as_raw_fd(), c".").ok()?;
            if check.st_dev != s.st_dev
                || check.st_ino != s.st_ino
                || check.st_flags & 0x40000000 != 0
            {
                return None;
            }
            if walk(child, depth + 1, dev, budget, deadline, cancel)? {
                return Some(true);
            }
        }
    }
    let cargo = match directory(&root.join("target")) {
        Ok(fd) => walk(fd, 0, dev, &mut budget, deadline, cancel),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Some(false),
        _ => None,
    };
    if cargo == Some(true) {
        return cargo;
    }
    let swift = match directory(&root.join(".build")) {
        Ok(fd) => match stat(fd.as_raw_fd(), c"workspace-state.json") {
            Ok(s)
                if s.st_mode & libc::S_IFMT == libc::S_IFREG
                    && s.st_dev == dev
                    && s.st_flags & 0x40000000 == 0 =>
            {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .ok()?
                    .as_millis();
                // A recent/future modification is conservatively treated as an active write.
                Some(time(&s).is_some_and(|t| t >= 0 && now.saturating_sub(t as u128) < 2000))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Some(false),
            _ => None,
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => Some(false),
        _ => None,
    };
    if swift == Some(true) {
        Some(true)
    } else if cargo == Some(false) && swift == Some(false) {
        Some(false)
    } else {
        None
    }
}
