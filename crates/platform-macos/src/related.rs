// SPDX-License-Identifier: MPL-2.0

//! Native observations for the separately approved related-data contract.
//! No registry or process result proves exclusive ownership of user data.

use objc2::rc::{Retained, autoreleasepool};
use objc2::runtime::{AnyClass, AnyObject};
use objc2::{msg_send, sel};
use std::ffi::{CStr, OsStr};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[link(name = "AppKit", kind = "framework")]
unsafe extern "C" {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    Caches,
    Logs,
    SavedState,
    HttpStorages,
    HttpCookies,
    WebKit,
    Cookies,
    Preferences,
    ApplicationSupport,
    Containers,
}

impl Rule {
    pub const ALL: [Self; 10] = [
        Self::Caches,
        Self::Logs,
        Self::SavedState,
        Self::HttpStorages,
        Self::HttpCookies,
        Self::WebKit,
        Self::Cookies,
        Self::Preferences,
        Self::ApplicationSupport,
        Self::Containers,
    ];
    pub fn key(self) -> &'static str {
        match self {
            Self::Caches => "caches",
            Self::Logs => "logs",
            Self::SavedState => "saved_state",
            Self::HttpStorages => "http_storages",
            Self::HttpCookies => "http_storages_cookies",
            Self::WebKit => "webkit",
            Self::Cookies => "cookies",
            Self::Preferences => "preferences",
            Self::ApplicationSupport => "application_support",
            Self::Containers => "containers",
        }
    }
    pub fn location(self) -> (&'static str, &'static str) {
        match self {
            Self::Caches => ("Caches", ""),
            Self::Logs => ("Logs", ""),
            Self::SavedState => ("Saved Application State", ".savedState"),
            Self::HttpStorages => ("HTTPStorages", ""),
            Self::HttpCookies => ("HTTPStorages", ".binarycookies"),
            Self::WebKit => ("WebKit", ""),
            Self::Cookies => ("Cookies", ".binarycookies"),
            Self::Preferences => ("Preferences", ".plist"),
            Self::ApplicationSupport => ("Application Support", ""),
            Self::Containers => ("Containers", ""),
        }
    }
    pub fn is_file(self) -> bool {
        matches!(self, Self::HttpCookies | Self::Cookies | Self::Preferences)
    }
    pub fn path(self, home: &Path, id: &str) -> io::Result<PathBuf> {
        if !valid_bundle_id(id) {
            return Err(invalid("invalid_bundle_id"));
        }
        let (parent, suffix) = self.location();
        Ok(home
            .join("Library")
            .join(parent)
            .join(format!("{id}{suffix}")))
    }
}

pub fn valid_bundle_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 255
        && id.split('.').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}
fn invalid(reason: &str) -> io::Error {
    io::Error::other(reason)
}

/// Held no-follow identity chain for read-only bundle/root observations.
/// Files bind size/mtime too; directory content changes do not change identity.
pub struct PathWitness {
    path: PathBuf,
    chain: Vec<(PathBuf, File, Stamp)>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Stamp {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    mtime: (i64, i64),
}
impl Stamp {
    fn read(m: &std::fs::Metadata) -> Self {
        Self {
            device: m.dev(),
            inode: m.ino(),
            mode: m.mode(),
            uid: m.uid(),
            gid: m.gid(),
            size: if m.is_dir() { 0 } else { m.len() },
            mtime: if m.is_dir() {
                (0, 0)
            } else {
                (m.mtime(), m.mtime_nsec())
            },
        }
    }
}
impl PathWitness {
    pub fn capture(path: &Path) -> io::Result<Self> {
        if !path.is_absolute()
            || path.as_os_str().as_bytes().len() > 4096
            || path.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err(invalid("invalid_path"));
        }
        let mut chain = Vec::new();
        let policy = crate::ReadOnlyPolicy::enter()?;
        let result = (|| {
            for part in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
                let f = OpenOptions::new()
                    .read(true)
                    .custom_flags(
                        libc::O_NOFOLLOW | 0x20000000 | libc::O_CLOEXEC | libc::O_NONBLOCK,
                    )
                    .open(part)?;
                let m = f.metadata()?;
                use std::os::macos::fs::MetadataExt;
                if m.st_flags() & (0x40000000 | 0x00080000 | 0x00100000) != 0
                    || (part != path && !m.is_dir())
                    || (!m.is_dir() && !m.is_file())
                {
                    return Err(invalid("unsafe_path"));
                }
                chain.push((part.to_owned(), f, Stamp::read(&m)));
            }
            Ok(Self {
                path: path.to_owned(),
                chain,
            })
        })();
        let restored = policy.restore();
        let witness = result?;
        restored?;
        witness.revalidate()?;
        Ok(witness)
    }
    pub fn identity(&self) -> (u64, u64) {
        let s = &self.chain.last().expect("absolute path").2;
        (s.device, s.inode)
    }
    pub fn is_directory(&self) -> bool {
        self.chain.last().expect("path").2.mode & libc::S_IFMT as u32 == libc::S_IFDIR as u32
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn physical_path(&self) -> io::Result<PathBuf> {
        use std::os::fd::AsRawFd;
        self.revalidate()?;
        let mut buffer = vec![0u8; 4096];
        let fd = self
            .chain
            .last()
            .ok_or_else(|| invalid("missing witness"))?
            .1
            .as_raw_fd();
        // SAFETY: F_GETPATH_NOFIRMLINK writes a NUL-terminated path to MAXPATHLEN storage.
        if unsafe { libc::fcntl(fd, 102, buffer.as_mut_ptr()) } == -1 {
            return Err(io::Error::last_os_error());
        }
        let end = buffer
            .iter()
            .position(|b| *b == 0)
            .ok_or_else(|| invalid("physical_path_unavailable"))?;
        self.revalidate()?;
        Ok(PathBuf::from(OsStr::from_bytes(&buffer[..end])))
    }

    pub fn revalidate(&self) -> io::Result<()> {
        for (path, held, stamp) in &self.chain {
            if Stamp::read(&held.metadata()?) != *stamp
                || Stamp::read(&std::fs::symlink_metadata(path)?) != *stamp
            {
                return Err(invalid("resource_changed"));
            }
        }
        Ok(())
    }
}

fn native_string(text: &str) -> io::Result<Retained<AnyObject>> {
    let class = AnyClass::get(c"NSString").ok_or_else(|| invalid("NSString unavailable"))?;
    let bytes = std::ffi::CString::new(text).map_err(|_| invalid("invalid NSString input"))?;
    // SAFETY: Documented NSString factory copies the live NUL-terminated UTF-8 input.
    let value: Option<Retained<AnyObject>> =
        unsafe { msg_send![class, stringWithUTF8String: bytes.as_ptr()] };
    value.ok_or_else(|| invalid("NSString conversion failed"))
}

/// All registered URLs, never the best-match-only selector. Bounded and fail closed.
pub fn registered_applications(id: &str) -> io::Result<Vec<PathBuf>> {
    if !valid_bundle_id(id) {
        return Err(invalid("invalid_bundle_id"));
    }
    objc2::exception::catch(|| autoreleasepool(|_| {
        let id=native_string(id)?;
        let class=AnyClass::get(c"NSWorkspace").ok_or_else(||invalid("NSWorkspace unavailable"))?;
        // SAFETY: Public AppKit signatures; retained objects and pool cover all borrows.
        let workspace:Option<Retained<AnyObject>>=unsafe{msg_send![class,sharedWorkspace]};
        let workspace=workspace.ok_or_else(||invalid("workspace unavailable"))?;
        let available:bool=unsafe{msg_send![&workspace,respondsToSelector:sel!(URLsForApplicationsWithBundleIdentifier:)]};
        if !available {return Err(invalid("copies_unknown"));}
        let urls:Option<Retained<AnyObject>>=unsafe{msg_send![&workspace,URLsForApplicationsWithBundleIdentifier:&*id]};
        let urls=urls.ok_or_else(||invalid("copies_unknown"))?;
        let count:usize=unsafe{msg_send![&urls,count]};
        if count>256{return Err(invalid("copies_truncated"));}
        let mut result=Vec::new();
        for i in 0..count {
            let url:&AnyObject=unsafe{msg_send![&urls,objectAtIndex:i]};
            let file:bool=unsafe{msg_send![url,isFileURL]};
            if !file{return Err(invalid("non_file_registry_url"));}
            let bytes:*const std::ffi::c_char=unsafe{msg_send![url,fileSystemRepresentation]};
            if bytes.is_null(){return Err(invalid("invalid_registry_url"));}
            let bytes=unsafe{CStr::from_ptr(bytes)}.to_bytes();
            if bytes.len()>4096{return Err(invalid("registry_path_too_long"));}
            let path=PathBuf::from(OsStr::from_bytes(bytes));
            if !path.is_absolute(){return Err(invalid("relative_registry_url"));}
            result.push(path);
        }
        Ok(result)
    })).map_err(|_|invalid("LaunchServices exception"))?
}

pub fn bundle_id_running(id: &str) -> io::Result<bool> {
    if !valid_bundle_id(id) {
        return Err(invalid("invalid_bundle_id"));
    }
    objc2::exception::catch(|| {
        autoreleasepool(|_| {
            let id = native_string(id)?;
            let class = AnyClass::get(c"NSRunningApplication")
                .ok_or_else(|| invalid("running query unavailable"))?;
            // SAFETY: Documented class query with a retained NSString, within the pool.
            let apps: Option<Retained<AnyObject>> =
                unsafe { msg_send![class,runningApplicationsWithBundleIdentifier:&*id] };
            let apps = apps.ok_or_else(|| invalid("running_unknown"))?;
            let count: usize = unsafe { msg_send![&apps, count] };
            Ok(count != 0)
        })
    })
    .map_err(|_| invalid("running query exception"))?
}

/// Effective-UID census with process identity observed on both sides of proc_pidpath.
pub fn executable_paths() -> io::Result<Vec<PathBuf>> {
    let start = Instant::now();
    let uid = unsafe { libc::geteuid() };
    let mut pids = vec![0i32; 65536];
    let capacity = std::mem::size_of_val(pids.as_slice());
    // SAFETY: PROC_UID_ONLY writes integer PIDs into the capacity-sized buffer.
    let bytes = unsafe { libc::proc_listpids(4, uid, pids.as_mut_ptr().cast(), capacity as i32) };
    if bytes <= 0 || bytes as usize >= capacity || bytes as usize % 4 != 0 {
        return Err(invalid("running_unknown"));
    }
    let mut result = Vec::new();
    for &pid in &pids[..bytes as usize / 4] {
        if pid <= 0 {
            continue;
        }
        if start.elapsed() > Duration::from_secs(5) {
            return Err(invalid("running_timeout"));
        }
        let before = match process_identity(pid) {
            Ok(v) => v,
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => continue,
            Err(e) => return Err(e),
        };
        if before.0 != uid {
            return Err(invalid("process_uid_changed"));
        }
        let mut buffer = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        // SAFETY: proc_pidpath writes at most the passed buffer capacity.
        let n = unsafe { libc::proc_pidpath(pid, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
        if n <= 0 || n as usize >= buffer.len() {
            return Err(invalid("process_path_unavailable"));
        }
        let after = process_identity(pid)?;
        if before != after {
            return Err(invalid("process_identity_changed"));
        }
        let path = PathBuf::from(OsStr::from_bytes(&buffer[..n as usize]));
        if !path.is_absolute() {
            return Err(invalid("invalid_process_path"));
        }
        result.push(path);
    }
    Ok(result)
}
fn process_identity(pid: i32) -> io::Result<(u32, u64, u64)> {
    let mut value: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    // SAFETY: Initialized C output and exact PROC_PIDTBSDINFO buffer size.
    let n = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut value as *mut libc::proc_bsdinfo).cast(),
            std::mem::size_of_val(&value) as i32,
        )
    };
    if n <= 0 {
        return Err(io::Error::last_os_error());
    }
    if n as usize != std::mem::size_of_val(&value) || value.pbi_pid != pid as u32 {
        return Err(invalid("invalid_process_identity"));
    }
    Ok((value.pbi_uid, value.pbi_start_tvsec, value.pbi_start_tvusec))
}
