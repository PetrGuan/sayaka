// SPDX-License-Identifier: MPL-2.0
//! Owner-approved, observation-only exception for the exact system Safari chain.
//! Never used by target admission or by a generic symlink resolver.
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

pub const ENTRY: &str = "/Applications/Safari.app";
const FIRST_TARGET: &str = "../System/Cryptexes/App/System/Applications/Safari.app";
const CRYPTEX: &str = "/System/Cryptexes/App";
const CRYPTEX_TARGET: &str = "../../System/Volumes/Preboot/Cryptexes/App";
const DESTINATION: &str = "/System/Volumes/Preboot/Cryptexes/App/System/Applications/Safari.app";
const NOFOLLOW_ANY: i32 = 0x20000000;
const NOUNLINK: u32 = 0x00100000;
fn unknown() -> io::Error {
    io::Error::other("copies_unknown: system Safari evidence")
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
struct Link {
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
    fn capture(path: &str, target: &str) -> io::Result<Self> {
        let path = PathBuf::from(path);
        let parent = orphans::exact(path.parent().ok_or_else(unknown)?)?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(NOFOLLOW_ANY | libc::O_CLOEXEC | libc::O_DIRECTORY)
            .open(parent.path())?;
        let dm = directory.metadata()?;
        if (dm.dev(), dm.ino()) != parent.identity()
            || dm.uid() != 0
            || dm.mode() & 0o002 != 0
            || (dm.mode() & 0o020 != 0
                && (parent.path() != Path::new("/Applications") || dm.gid() != 80))
            || crate::has_extended_acl(&directory)?
        {
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
                libc::O_SYMLINK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful openat returns one newly owned descriptor.
        let held = unsafe { File::from_raw_fd(fd) };
        let stamp = Stamp::read(&held.metadata()?);
        if stamp.uid != 0 || stamp.mode & u32::from(libc::S_IFMT) != u32::from(libc::S_IFLNK) {
            return Err(unknown());
        }
        let link = Self {
            path,
            parent,
            directory,
            directory_stamp,
            directory_acl,
            held,
            stamp,
            target: target.as_bytes().to_vec(),
        };
        link.revalidate()?;
        Ok(link)
    }
    fn revalidate(&self) -> io::Result<()> {
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
struct Directory {
    path: PathBuf,
    held: File,
    stamp: Stamp,
    acl: Option<Vec<u8>>,
}
impl Directory {
    fn capture(path: &Path) -> io::Result<Self> {
        let held = OpenOptions::new()
            .read(true)
            .custom_flags(NOFOLLOW_ANY | libc::O_CLOEXEC | libc::O_DIRECTORY)
            .open(path)?;
        let stamp = Stamp::read(&held.metadata()?);
        if stamp.uid != 0
            || stamp.mode & u32::from(libc::S_IFMT) != u32::from(libc::S_IFDIR)
            || stamp.flags & 0x40000000 != 0
        {
            return Err(unknown());
        }
        let acl = crate::acl::snapshot(&held)?;
        // The narrow supported OS layout has no ACL grants on this chain.
        if crate::has_extended_acl(&held)? {
            return Err(unknown());
        }
        Ok(Self {
            path: path.to_owned(),
            held,
            stamp,
            acl,
        })
    }
    fn revalidate(&self) -> io::Result<()> {
        if Stamp::read(&self.held.metadata()?) != self.stamp
            || Stamp::read(&std::fs::symlink_metadata(&self.path)?) != self.stamp
            || crate::acl::snapshot(&self.held)? != self.acl
        {
            return Err(unknown());
        }
        Ok(())
    }
}
/// Retained read-only evidence. Has no conversion to any Trash candidate type.
pub struct Observation {
    links: [Link; 2],
    directories: Vec<Directory>,
    destination: PathWitness,
}
impl Observation {
    pub fn capture() -> io::Result<Self> {
        Self::capture_with(|_| Ok(())).map(|(observation, ())| observation)
    }
    /// Inspect within retained chain evidence before the mandatory full signature
    /// validation. No partially validated Observation escapes on any error.
    pub fn capture_with<T>(inspect: impl FnOnce(&Path) -> io::Result<T>) -> io::Result<(Self, T)> {
        let policy = crate::ReadOnlyPolicy::enter()?;
        let result = (|| {
            let links = [
                Link::capture(ENTRY, FIRST_TARGET)?,
                Link::capture(CRYPTEX, CRYPTEX_TARGET)?,
            ];
            let path = Path::new(DESTINATION);
            let parts: Vec<_> = path.ancestors().collect();
            if parts.len() > 64 {
                return Err(unknown());
            }
            let mut directories = Vec::new();
            for p in parts.into_iter().rev() {
                directories.push(Directory::capture(p)?);
            }
            for (i, d) in directories.iter().enumerate() {
                if d.stamp.mode & 0o022 != 0 {
                    // Darwin's OS-owned Cryptexes container is mode 0777. Only
                    // its exact root-owned, SF_NOUNLINK-protected App edge is
                    // allowed; no generally writable ancestor is trusted.
                    if d.path != Path::new("/System/Volumes/Preboot/Cryptexes")
                        || directories.get(i + 1).is_none_or(|child| {
                            child.path != Path::new("/System/Volumes/Preboot/Cryptexes/App")
                                || child.stamp.flags & NOUNLINK == 0
                        })
                    {
                        return Err(unknown());
                    }
                }
            }
            let destination = orphans::exact(path)?;
            let observation = Self {
                links,
                directories,
                destination,
            };
            let value = timed("manifest_capture", || inspect(observation.path()))?;
            observation.revalidate()?;
            Ok((observation, value))
        })();
        let restored = policy.restore();
        let observation = result?;
        restored?;
        Ok(observation)
    }
    pub fn path(&self) -> &Path {
        self.destination.path()
    }
    pub fn revalidate(&self) -> io::Result<()> {
        let policy = crate::ReadOnlyPolicy::enter()?;
        let result = (|| {
            for link in &self.links {
                link.revalidate()?;
            }
            for d in &self.directories {
                d.revalidate()?;
            }
            self.destination.revalidate()?;
            timed("signature_check", || {
                crate::devtools::verify_code_requirement(
                    self.path(), r#"anchor apple and identifier "com.apple.Safari""#,
                ).map_err(|_| unknown())
            })?;
            for d in &self.directories {
                d.revalidate()?;
            }
            for link in &self.links {
                link.revalidate()?;
            }
            self.destination.revalidate()
        })();
        let restored = policy.restore();
        result?;
        restored
    }
}

fn timed<T>(operation: &str, action: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    #[cfg(debug_assertions)]
    let start = std::time::Instant::now();
    let result = action();
    #[cfg(debug_assertions)]
    {
        use std::io::Write;
        let _ = writeln!(io::stderr().lock(), "[SayakaSafari] event=operation operation={operation} wall_us={} success={}", start.elapsed().as_micros(), result.is_ok());
    }
    #[cfg(not(debug_assertions))]
    let _ = operation;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // Native regression sources only. Agent validation compiles, never runs them.
    #[test]
    #[ignore = "native acceptance requires the explicit supported system Safari Cryptex layout"]
    fn observes_only_the_exact_signed_system_layout() {
        let observation = Observation::capture().expect("supported system Safari layout");
        assert_eq!(observation.path(), Path::new(DESTINATION));
        observation
            .revalidate()
            .expect("unchanged signed system evidence");
    }
    #[test]
    #[ignore = "native acceptance requires the explicit supported system Safari Cryptex layout"]
    fn wrong_link_target_text_is_not_accepted() {
        assert!(Link::capture(ENTRY, "../Applications/Replacement.app").is_err());
        assert!(Link::capture(CRYPTEX, "../../Applications").is_err());
    }
}
