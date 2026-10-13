// SPDX-License-Identifier: MPL-2.0
//! Single-enumeration application directory evidence. All children are inspected;
//! a regular file's Finder alias flag is never inferred from its extension.
use crate::{orphans, related::PathWitness};
use std::{
    ffi::CString,
    fs::{DirEntry, File, OpenOptions, ReadDir},
    io,
    os::unix::{
        ffi::OsStrExt,
        fs::{DirEntryExt, MetadataExt, OpenOptionsExt},
    },
    path::Path,
};
fn changed() -> io::Error {
    io::Error::other("application_directory_changed_or_unavailable")
}
#[derive(PartialEq, Eq)]
struct Stamp {
    dev: u64,
    ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    flags: u32,
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}
impl Stamp {
    fn read(m: &std::fs::Metadata) -> Self {
        use std::os::macos::fs::MetadataExt;
        Self {
            dev: m.dev(),
            ino: m.ino(),
            mode: m.mode(),
            uid: m.uid(),
            gid: m.gid(),
            flags: m.st_flags(),
            size: m.len(),
            mtime: (m.mtime(), m.mtime_nsec()),
            ctime: (m.ctime(), m.ctime_nsec()),
        }
    }
}
/// The parent is checked exactly once; unchanged directory generation binds the
/// spellings and inode numbers yielded by its enumeration. No cleanup capability.
pub struct Observation {
    witness: PathWitness,
    held: File,
    stamp: Stamp,
    entries: ReadDir,
    policy: Option<crate::ReadOnlyPolicy>,
}
impl Observation {
    pub fn capture(path: &Path) -> io::Result<Self> {
        let witness = orphans::exact(path)?;
        let policy = crate::ReadOnlyPolicy::enter()?;
        let result = (|| {
            let held = OpenOptions::new()
                .read(true)
                .custom_flags(0x20000000 | libc::O_CLOEXEC | libc::O_DIRECTORY)
                .open(path)?;
            let stamp = Stamp::read(&held.metadata()?);
            if (stamp.dev, stamp.ino) != witness.identity() || !witness.is_directory() {
                return Err(changed());
            }
            let entries = std::fs::read_dir(path)?;
            let value = Self {
                witness,
                held,
                stamp,
                entries,
                policy: None,
            };
            value.revalidate()?;
            Ok(value)
        })();
        match result {
            Ok(mut value) => {
                value.policy = Some(policy);
                Ok(value)
            }
            Err(error) => {
                policy.restore()?;
                Err(error)
            }
        }
    }
    /// Restore the thread policy explicitly on successful enumeration. On an
    /// error, the owned non-Send guard restores it while unwinding this scope.
    pub fn finish(mut self) -> io::Result<()> {
        let result = self.revalidate();
        let restored = self.policy.take().ok_or_else(changed)?.restore();
        result?;
        restored
    }
    pub fn next_entry(&mut self) -> io::Result<Option<DirEntry>> {
        self.entries.next().transpose()
    }
    pub fn revalidate(&self) -> io::Result<()> {
        self.witness.revalidate()?;
        self.generation()
    }
    fn generation(&self) -> io::Result<()> {
        if Stamp::read(&self.held.metadata()?) != self.stamp {
            return Err(changed());
        }
        Ok(())
    }
    /// The caller must revalidate the directory after finishing its enumeration.
    /// No repeated ancestor listing: name and inode come from this enumeration,
    /// not from an arbitrary or case-folded path supplied by the caller.
    pub fn is_finder_alias(&self, entry: &DirEntry) -> io::Result<bool> {
        if entry.path().parent() != Some(self.witness.path()) {
            return Err(changed());
        }
        self.generation()?;
        (|| {
            let path = entry.path();
            let native_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| changed())?;
            let meta = std::fs::symlink_metadata(&path)?;
            let before = Stamp::read(&meta);
            if !meta.is_file()
                || before.flags & 0x40000000 != 0
                || (before.dev, before.ino) != (self.stamp.dev, entry.ino())
            {
                return Err(changed());
            }
            let mut info = [0u8; 32];
            // Public sys/xattr.h flag. Unlike XATTR_NOFOLLOW (leaf only), this
            // rejects links anywhere in the path, without opening file content.
            const XATTR_NOFOLLOW_ANY: i32 = 0x0040;
            // SAFETY: a NUL-terminated path, constant attribute, bounded writable
            // buffer and kernel-enforced no-follow for every path component.
            let n = unsafe {
                libc::getxattr(
                    native_path.as_ptr(),
                    c"com.apple.FinderInfo".as_ptr(),
                    info.as_mut_ptr().cast(),
                    info.len(),
                    0,
                    XATTR_NOFOLLOW_ANY,
                )
            };
            let alias = if n == -1 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ENOATTR) {
                    false
                } else {
                    return Err(error);
                }
            } else if n == 32 {
                u16::from_be_bytes([info[8], info[9]]) & 0x8000 != 0
            } else {
                return Err(io::Error::other("finder_alias_unknown"));
            };
            if Stamp::read(&std::fs::symlink_metadata(&path)?) != before {
                return Err(changed());
            }
            self.generation()?;
            Ok(alias)
        })()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    fn fixture() -> (tempfile::TempDir, std::path::PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let path = std::fs::canonicalize(temp.path()).unwrap();
        (temp, path)
    }
    #[test]
    fn observes_plain_files_and_alias_flags_without_extension_inference() {
        let (_temp, path) = fixture();
        std::fs::write(path.join("normal.html"), b"fixture").unwrap();
        let alias_path = path.join("shortcut.html");
        let alias = File::create(&alias_path).unwrap();
        let mut flags = [0u8; 32];
        flags[8] = 0x80;
        // SAFETY: owned isolated fixture FD and live fixed-size attribute data.
        assert_eq!(
            unsafe {
                libc::fsetxattr(
                    alias.as_raw_fd(),
                    c"com.apple.FinderInfo".as_ptr(),
                    flags.as_ptr().cast(),
                    flags.len(),
                    0,
                    0,
                )
            },
            0
        );
        let mut directory = Observation::capture(&path).unwrap();
        let mut seen = 0;
        while let Some(entry) = directory.next_entry().unwrap() {
            assert_eq!(
                directory.is_finder_alias(&entry).unwrap(),
                entry.file_name() == "shortcut.html"
            );
            seen += 1;
        }
        assert_eq!(seen, 2);
        directory.revalidate().unwrap();
    }
    #[test]
    fn replacement_and_case_rename_invalidate_enumeration() {
        let (_temp, path) = fixture();
        std::fs::write(path.join("Sample"), b"fixture").unwrap();
        let mut directory = Observation::capture(&path).unwrap();
        let entry = directory.next_entry().unwrap().unwrap();
        std::fs::rename(path.join("Sample"), path.join("SAMPLE")).unwrap();
        assert!(directory.is_finder_alias(&entry).is_err());
        assert!(directory.revalidate().is_err());
    }
    #[test]
    fn linked_leaf_is_not_admitted_as_a_regular_file() {
        let (_temp, path) = fixture();
        std::fs::write(path.join("target"), b"fixture").unwrap();
        std::os::unix::fs::symlink("target", path.join("link")).unwrap();
        let mut directory = Observation::capture(&path).unwrap();
        while let Some(entry) = directory.next_entry().unwrap() {
            if entry.file_name() == "link" {
                assert!(directory.is_finder_alias(&entry).is_err());
            }
        }
    }
}
