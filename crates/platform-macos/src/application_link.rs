// SPDX-License-Identifier: MPL-2.0
//! Read-only link evidence for bounded installed-application observations.
//! No target following and no conversion to native Trash admission.
use crate::{orphans, related::PathWitness};
use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Path, PathBuf},
};
const NOFOLLOW_ANY: i32 = 0x20000000;
fn unknown() -> io::Error {
    io::Error::other("application_link_changed_or_unavailable")
}
#[derive(Clone, PartialEq, Eq)]
struct Stamp {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    flags: u32,
    size: u64,
    mtime: (i64, i64),
}
impl Stamp {
    fn read(m: &std::fs::Metadata) -> Self {
        use std::os::macos::fs::MetadataExt;
        Self {
            dev: m.dev(),
            ino: m.ino(),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode(),
            flags: m.st_flags(),
            size: if m.is_dir() { 0 } else { m.len() },
            mtime: if m.is_dir() {
                (0, 0)
            } else {
                (m.mtime(), m.mtime_nsec())
            },
        }
    }
}
pub struct Link {
    path: PathBuf,
    parent: PathWitness,
    directory: File,
    directory_stamp: Stamp,
    directory_acl: Option<Vec<u8>>,
    held: File,
    stamp: Stamp,
    target: Vec<u8>,
}
impl Link {
    /// Observe only the link inode and its text, never follow its target.
    pub fn capture(path: &Path) -> io::Result<Self> {
        let policy = crate::ReadOnlyPolicy::enter()?;
        let result = Self::capture_inner(path);
        let restored = policy.restore();
        let link = result?;
        restored?;
        Ok(link)
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn target(&self) -> &Path {
        Path::new(std::ffi::OsStr::from_bytes(&self.target))
    }

    fn read_target(&self) -> io::Result<Vec<u8>> {
        let name = CString::new(self.path.file_name().ok_or_else(unknown)?.as_bytes())
            .map_err(|_| unknown())?;
        let mut bytes = vec![0u8; 4096];
        // SAFETY: live no-follow parent descriptor and bounded writable output.
        let n = unsafe {
            libc::readlinkat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n as usize >= bytes.len() {
            return Err(unknown());
        }
        bytes.truncate(n as usize);
        Ok(bytes)
    }
    fn capture_inner(path: &Path) -> io::Result<Self> {
        let path = path.to_owned();
        let parent = orphans::exact(path.parent().ok_or_else(unknown)?)?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(NOFOLLOW_ANY | libc::O_CLOEXEC | libc::O_DIRECTORY)
            .open(parent.path())?;
        let dm = directory.metadata()?;
        if (dm.dev(), dm.ino()) != parent.identity() || !dm.is_dir() {
            return Err(unknown());
        }
        let directory_stamp = Stamp::read(&dm);
        let directory_acl = crate::acl::snapshot(&directory)?;
        let name = CString::new(path.file_name().ok_or_else(unknown)?.as_bytes())
            .map_err(|_| unknown())?;
        // SAFETY: O_SYMLINK opens the link itself relative to the held directory.
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_SYMLINK | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful openat returns one newly owned descriptor.
        let held = unsafe { File::from_raw_fd(fd) };
        let stamp = Stamp::read(&held.metadata()?);
        if stamp.flags & 0x40000000 != 0
            || stamp.mode & u32::from(libc::S_IFMT) != u32::from(libc::S_IFLNK)
        {
            return Err(unknown());
        }
        let mut link = Self {
            path,
            parent,
            directory,
            directory_stamp,
            directory_acl,
            held,
            stamp,
            target: Vec::new(),
        };
        link.target = link.read_target()?;
        link.revalidate()?;
        Ok(link)
    }
    pub fn revalidate(&self) -> io::Result<()> {
        self.parent.revalidate()?;
        if Stamp::read(&self.directory.metadata()?) != self.directory_stamp
            || crate::acl::snapshot(&self.directory)? != self.directory_acl
        {
            return Err(unknown());
        }
        if Stamp::read(&self.held.metadata()?) != self.stamp
            || Stamp::read(&std::fs::symlink_metadata(&self.path)?) != self.stamp
            || self.read_target()? != self.target
        {
            return Err(unknown());
        }
        self.parent.revalidate()
    }
}
