// SPDX-License-Identifier: MPL-2.0
//! Single-enumeration application directory evidence. All children are inspected;
//! a regular file's Finder alias flag is never inferred from its extension.
use crate::{orphans, related::PathWitness};
use std::{
    ffi::{CStr, CString},
    fs::{DirEntry, File, OpenOptions, ReadDir},
    io,
    os::fd::AsRawFd,
    os::unix::{
        ffi::OsStrExt,
        fs::{DirEntryExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    rc::Rc,
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
    fn read_at(parent: &File, name: &CStr) -> io::Result<Self> {
        let mut value = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: live directory descriptor, one NUL-terminated enumerated
        // component, writable stat storage. AT_SYMLINK_NOFOLLOW never follows
        // a replaced leaf; no ancestor path is resolved by this call.
        if unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                name.as_ptr(),
                value.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful fstatat initialized every stat field used below.
        let m = unsafe { value.assume_init() };
        Ok(Self {
            dev: m.st_dev as u64,
            ino: m.st_ino,
            mode: u32::from(m.st_mode),
            uid: m.st_uid,
            gid: m.st_gid,
            flags: m.st_flags,
            size: m.st_size as u64,
            mtime: (m.st_mtime, m.st_mtime_nsec),
            ctime: (m.st_ctime, m.st_ctime_nsec),
        })
    }
}
/// Exact directory names are inherited only from the same parent enumeration.
/// Shared ancestry holds one descriptor per directory, not a fresh descriptor
/// chain and repeated ancestor listings for every descendant.
struct Evidence {
    path: PathBuf,
    held: File,
    stamp: Stamp,
    parent: Option<Rc<Evidence>>,
    root: Option<PathWitness>,
}
impl Evidence {
    fn generation(&self) -> io::Result<()> {
        if Stamp::read(&self.held.metadata()?) != self.stamp {
            return Err(changed());
        }
        Ok(())
    }
    fn revalidate(&self) -> io::Result<()> {
        let mut current = self;
        loop {
            current.generation()?;
            if Stamp::read(&std::fs::symlink_metadata(&current.path)?) != current.stamp {
                return Err(changed());
            }
            match &current.parent {
                Some(parent) => current = parent,
                None => {
                    // The root's ancestors were not discovered by this walker.
                    // Retain their original identities and verify their spelling.
                    current.root.as_ref().ok_or_else(changed)?.revalidate()?;
                    let exact = orphans::exact(&current.path)?;
                    if exact.identity() != (current.stamp.dev, current.stamp.ino) {
                        return Err(changed());
                    }
                    return Ok(());
                }
            }
        }
    }
}
/// Opaque, same-enumeration child evidence; arbitrary paths cannot construct it.
/// Capture rechecks all retained parent generations before trusting its spelling.
pub struct DiscoveredDirectory {
    path: PathBuf,
    identity: (u64, u64),
    parent: Rc<Evidence>,
}

pub struct Observation {
    evidence: Rc<Evidence>,
    entries: ReadDir,
    policy: Option<crate::ReadOnlyPolicy>,
}
impl Observation {
    pub fn capture(path: &Path) -> io::Result<Self> {
        Self::capture_inner(path, None, Some(orphans::exact(path)?))
    }
    pub fn capture_discovered(child: DiscoveredDirectory) -> io::Result<Self> {
        child.parent.revalidate()?;
        let path = child.path.clone();
        Self::capture_inner(&path, Some(child), None)
    }
    fn capture_inner(
        path: &Path,
        child: Option<DiscoveredDirectory>,
        root: Option<PathWitness>,
    ) -> io::Result<Self> {
        let policy = crate::ReadOnlyPolicy::enter()?;
        let result = (|| {
            let held = OpenOptions::new()
                .read(true)
                .custom_flags(0x20000000 | libc::O_CLOEXEC | libc::O_DIRECTORY)
                .open(path)?;
            let meta = held.metadata()?;
            let stamp = Stamp::read(&meta);
            let expected = child
                .as_ref()
                .map(|c| c.identity)
                .or_else(|| root.as_ref().map(PathWitness::identity))
                .ok_or_else(changed)?;
            if !meta.is_dir() || stamp.flags & 0x40000000 != 0 || (stamp.dev, stamp.ino) != expected
            {
                return Err(changed());
            }
            let evidence = Rc::new(Evidence {
                path: path.to_owned(),
                held,
                stamp,
                parent: child.map(|c| c.parent),
                root,
            });
            let entries = std::fs::read_dir(path)?;
            let value = Self {
                evidence,
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
        self.evidence.revalidate()
    }
    pub fn discovered_directory(&self, entry: &DirEntry) -> io::Result<DiscoveredDirectory> {
        if entry.path().parent() != Some(self.evidence.path.as_path())
            || !entry.file_type()?.is_dir()
        {
            return Err(changed());
        }
        self.evidence.generation()?;
        let name = CString::new(entry.file_name().as_bytes()).map_err(|_| changed())?;
        let actual = Stamp::read_at(&self.evidence.held, &name)?;
        if actual.mode & libc::S_IFMT as u32 != libc::S_IFDIR as u32
            || actual.flags & 0x40000000 != 0
        {
            return Err(changed());
        }
        self.evidence.generation()?;
        Ok(DiscoveredDirectory {
            path: entry.path(),
            // A mount point's enumerated inode belongs to the covered directory;
            // the child we must traverse can have a different device and inode.
            identity: (actual.dev, actual.ino),
            parent: self.evidence.clone(),
        })
    }

    /// Keep the explicit ENOATTR-only absence decision and before/after stamp
    /// checks. The first stat is descriptor-relative; a full-path stat immediately
    /// after getxattr binds its result to that same leaf. No content open or
    /// extension inference.
    pub fn is_finder_alias(&self, entry: &DirEntry) -> io::Result<bool> {
        self.evidence.generation()?;
        let alias = self.is_finder_alias_during_enumeration(entry)?;
        self.evidence.generation()?;
        Ok(alias)
    }

    /// Batch form for a complete enumeration that MUST successfully call finish()
    /// before publishing any inventory. Parent generation checks are amortized at
    /// capture/finish; all per-file identity, dataless, no-follow and FinderInfo
    /// checks remain immediate. Any early exit must discard the whole inventory.
    pub fn is_finder_alias_during_enumeration(&self, entry: &DirEntry) -> io::Result<bool> {
        if entry.path().parent() != Some(self.evidence.path.as_path()) {
            return Err(changed());
        }
        let path = entry.path();
        let name = CString::new(entry.file_name().as_bytes()).map_err(|_| changed())?;
        let before = Stamp::read_at(&self.evidence.held, &name)?;
        if before.mode & libc::S_IFMT as u32 != libc::S_IFREG as u32
            || before.flags & 0x40000000 != 0
            || (before.dev, before.ino) != (self.evidence.stamp.dev, entry.ino())
        {
            return Err(io::Error::other(
                "finder_alias_identity_type_or_dataless_changed",
            ));
        }
        let native_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| changed())?;
        let mut info = [0u8; 32];
        // Public sys/xattr.h flag; rejects links in every path component.
        const XATTR_NOFOLLOW_ANY: i32 = 0x0040;
        // SAFETY: a NUL-terminated path, constant attribute, bounded writable
        // storage, and kernel-enforced no-follow for every path component.
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
        let result = if n == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        };
        validate_alias_stamp(&self.evidence.held, &name, &path, &before)?;
        let alias = finder_info_result(result, &info)?;
        Ok(alias)
    }
}
fn validate_alias_stamp(parent: &File, name: &CStr, path: &Path, before: &Stamp) -> io::Result<()> {
    // getxattr uses the full path: a held-parent-only check could validate the
    // old file after an ancestor is replaced. Keep this path observation adjacent
    // to getxattr, then also check the retained directory's original leaf.
    if Stamp::read(&std::fs::symlink_metadata(path)?) != *before {
        return Err(io::Error::other("finder_alias_path_changed"));
    }
    if Stamp::read_at(parent, name)? != *before {
        return Err(changed());
    }
    Ok(())
}
fn finder_info_result(result: io::Result<usize>, info: &[u8; 32]) -> io::Result<bool> {
    match result {
        Ok(32) => Ok(u16::from_be_bytes([info[8], info[9]]) & 0x8000 != 0),
        Err(error) if error.raw_os_error() == Some(libc::ENOATTR) => Ok(false),
        Err(error) => Err(error),
        Ok(_) => Err(io::Error::other("finder_alias_unknown")),
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
    fn only_explicit_missing_finder_info_means_no_alias() {
        let mut info = [0; 32];
        assert!(
            !finder_info_result(Err(io::Error::from_raw_os_error(libc::ENOATTR)), &info).unwrap()
        );
        assert!(!finder_info_result(Ok(32), &info).unwrap());
        info[8] = 0x80;
        assert!(finder_info_result(Ok(32), &info).unwrap());
        for code in [
            libc::EACCES,
            libc::EPERM,
            libc::ENOTSUP,
            libc::ENOENT,
            libc::EIO,
        ] {
            assert!(finder_info_result(Err(io::Error::from_raw_os_error(code)), &info).is_err());
        }
        for size in [0, 31, 33] {
            assert!(finder_info_result(Ok(size), &info).is_err());
        }
    }
    #[test]
    fn descriptor_relative_metadata_preserves_file_stamps_and_no_follow() {
        let (_temp, path) = fixture();
        let file = path.join("regular");
        std::fs::write(&file, b"fixture").unwrap();
        let parent = File::open(&path).unwrap();
        assert!(
            Stamp::read_at(&parent, c"regular").unwrap()
                == Stamp::read(&std::fs::symlink_metadata(&file).unwrap())
        );
        std::os::unix::fs::symlink("regular", path.join("link")).unwrap();
        assert_eq!(
            Stamp::read_at(&parent, c"link").unwrap().mode & libc::S_IFMT as u32,
            libc::S_IFLNK as u32
        );
        assert!(Stamp::read_at(&parent, c"missing").is_err());
    }
    #[test]
    fn alias_path_binding_rejects_replaced_ancestor_with_unchanged_held_leaf() {
        let (_temp, base) = fixture();
        let directory = base.join("Observed");
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("regular");
        std::fs::write(&path, b"fixture").unwrap();
        let parent = File::open(&directory).unwrap();
        let before = Stamp::read_at(&parent, c"regular").unwrap();
        validate_alias_stamp(&parent, c"regular", &path, &before).unwrap();
        std::fs::rename(&directory, base.join("Moved")).unwrap();
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(&path, b"fixture").unwrap();
        // Both descriptor-relative stamps still match the old leaf. The path
        // queried by getxattr now names a distinct leaf and must not supply proof.
        assert!(Stamp::read_at(&parent, c"regular").unwrap() == before);
        assert_eq!(
            validate_alias_stamp(&parent, c"regular", &path, &before)
                .unwrap_err()
                .to_string(),
            "finder_alias_path_changed"
        );
    }
    fn child(directory: &mut Observation, name: &str) -> DiscoveredDirectory {
        while let Some(entry) = directory.next_entry().unwrap() {
            if entry.file_name() == name {
                return directory.discovered_directory(&entry).unwrap();
            }
        }
        panic!("missing fixture directory");
    }
    #[test]
    fn discovered_children_preserve_deep_enumeration() {
        let (_temp, path) = fixture();
        std::fs::create_dir_all(path.join("SDK/Tools/Nested.app")).unwrap();
        let mut root = Observation::capture(&path).unwrap();
        let sdk = child(&mut root, "SDK");
        root.finish().unwrap();
        let mut sdk = Observation::capture_discovered(sdk).unwrap();
        let tools = child(&mut sdk, "Tools");
        sdk.finish().unwrap();
        let mut tools = Observation::capture_discovered(tools).unwrap();
        assert_eq!(
            tools.next_entry().unwrap().unwrap().file_name(),
            "Nested.app"
        );
        tools.finish().unwrap();
    }
    #[test]
    fn queued_child_rejects_replacement_and_case_renames() {
        for rename_only in [false, true] {
            let (_temp, path) = fixture();
            std::fs::create_dir(path.join("Tools")).unwrap();
            let mut root = Observation::capture(&path).unwrap();
            let tools = child(&mut root, "Tools");
            root.finish().unwrap();
            std::fs::rename(
                path.join("Tools"),
                path.join(if rename_only { "TOOLS" } else { "moved" }),
            )
            .unwrap();
            if !rename_only {
                std::fs::create_dir(path.join("Tools")).unwrap();
            }
            assert!(Observation::capture_discovered(tools).is_err());
        }
    }
    #[test]
    fn queued_descendant_rejects_ancestor_replacement_and_links() {
        for link in [false, true] {
            let (_temp, path) = fixture();
            std::fs::create_dir_all(path.join("SDK/Tools")).unwrap();
            let mut root = Observation::capture(&path).unwrap();
            let sdk = child(&mut root, "SDK");
            root.finish().unwrap();
            let mut sdk = Observation::capture_discovered(sdk).unwrap();
            let tools = child(&mut sdk, "Tools");
            sdk.finish().unwrap();
            std::fs::rename(path.join("SDK"), path.join("moved")).unwrap();
            if link {
                std::os::unix::fs::symlink("moved", path.join("SDK")).unwrap();
            } else {
                std::fs::create_dir_all(path.join("SDK/Tools")).unwrap();
            }
            assert!(Observation::capture_discovered(tools).is_err());
        }
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
                directory.is_finder_alias_during_enumeration(&entry).unwrap(),
                entry.file_name() == "shortcut.html"
            );
            seen += 1;
        }
        assert_eq!(seen, 2);
        directory.finish().unwrap();
    }
    #[test]
    fn batched_alias_checks_require_unchanged_parent_at_finish() {
        let (_temp, path) = fixture();
        std::fs::write(path.join("regular"), b"fixture").unwrap();
        let mut directory = Observation::capture(&path).unwrap();
        let entry = directory.next_entry().unwrap().unwrap();
        assert!(!directory.is_finder_alias_during_enumeration(&entry).unwrap());
        std::fs::write(path.join("added"), b"mutation").unwrap();
        assert!(directory.finish().is_err());
    }
    #[test]
    fn batched_alias_checks_reject_replaced_leaf_immediately() {
        let (_temp, path) = fixture();
        std::fs::write(path.join("regular"), b"fixture").unwrap();
        let mut directory = Observation::capture(&path).unwrap();
        let entry = directory.next_entry().unwrap().unwrap();
        std::fs::rename(path.join("regular"), path.join("old")).unwrap();
        std::os::unix::fs::symlink("old", path.join("regular")).unwrap();
        assert!(directory.is_finder_alias_during_enumeration(&entry).is_err());
        assert!(directory.finish().is_err());
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
