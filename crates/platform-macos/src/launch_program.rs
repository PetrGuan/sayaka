// SPDX-License-Identifier: MPL-2.0
//! Bounded read-only writer-location evidence; never a cleanup capability.
use std::{
    collections::{BTreeSet, VecDeque},
    ffi::{CStr, CString, OsStr},
    fs::{File, Metadata, OpenOptions},
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Path, PathBuf},
    time::Instant,
};
fn unknown() -> io::Error {
    io::Error::other("launch_agent_path_unknown")
}
#[derive(PartialEq, Eq)]
struct Stamp {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    flags: u32,
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
    birthtime: (i64, i64),
    generation: u32,
}
impl Stamp {
    fn read(m: &Metadata) -> Self {
        use std::os::macos::fs::MetadataExt;
        Self {
            ctime: if m.is_dir() {
                (0, 0)
            } else {
                (m.ctime(), m.ctime_nsec())
            },
            birthtime: (m.st_birthtime(), m.st_birthtime_nsec()),
            generation: m.st_gen(),
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
struct Node {
    file: Option<File>,
    volume: Volume,
    stamp: Stamp,
    parent: Option<usize>,
    name: Option<CString>,
    link: Option<Vec<u8>>,
    acl: Option<Vec<u8>>,
}
pub struct ProgramPath {
    nodes: Vec<Node>,
    resolved: PathBuf,
}
fn check(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(unknown())
    } else {
        Ok(())
    }
}
fn link_text(parent: &File, name: &CStr) -> io::Result<Vec<u8>> {
    let mut b = vec![0u8; 4096];
    // SAFETY: held directory, valid name and bounded output.
    let n = unsafe {
        libc::readlinkat(
            parent.as_raw_fd(),
            name.as_ptr(),
            b.as_mut_ptr().cast(),
            b.len(),
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if n as usize >= b.len() {
        return Err(unknown());
    }
    b.truncate(n as usize);
    Ok(b)
}
#[derive(PartialEq, Eq, Clone)]
struct Volume {
    fsid: [i32; 2],
    kind: Vec<u8>,
    flags: u32,
    mount: Vec<u8>,
    source: Vec<u8>,
}
impl Volume {
    fn read(file: &File) -> io::Result<Self> {
        let mut v = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: live descriptor and initialized output on success.
        if unsafe { libc::fstatfs(file.as_raw_fd(), v.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let v = unsafe { v.assume_init() };
        let bytes = |v: &[libc::c_char]| {
            v.iter()
                .map(|b| *b as u8)
                .take_while(|b| *b != 0)
                .collect::<Vec<_>>()
        };
        let kind = bytes(&v.f_fstypename);
        if kind != b"apfs" || v.f_flags & libc::MNT_LOCAL as u32 == 0 {
            return Err(unknown());
        }
        Ok(Self {
            // Darwin fsid_t is an initialized pair of 32-bit values.
            fsid: unsafe { std::mem::transmute::<libc::fsid_t, [i32; 2]>(v.f_fsid) },
            kind,
            flags: v.f_flags,
            mount: bytes(&v.f_mntonname),
            source: bytes(&v.f_mntfromname),
        })
    }
}
fn child_stamp(parent: &File, name: &CStr) -> io::Result<Stamp> {
    let mut m = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: held directory, one name, no implicit link traversal.
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            m.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let m = unsafe { m.assume_init() };
    let dir = m.st_mode & libc::S_IFMT == libc::S_IFDIR;
    Ok(Stamp {
        ctime: if dir {
            (0, 0)
        } else {
            (m.st_ctime, m.st_ctime_nsec)
        },
        birthtime: (m.st_birthtime, m.st_birthtime_nsec),
        generation: m.st_gen,
        dev: m.st_dev as u64,
        ino: m.st_ino,
        uid: m.st_uid,
        gid: m.st_gid,
        mode: m.st_mode as u32,
        flags: m.st_flags,
        size: if dir { 0 } else { m.st_size as u64 },
        mtime: if dir {
            (0, 0)
        } else {
            (m.st_mtime, m.st_mtime_nsec)
        },
    })
}
fn open_child(parent: &File, name: &CStr) -> io::Result<File> {
    // O_DIRECTORY rejects a replacement device before a device open operation;
    // non-directory nodes are observed only with fstatat/readlinkat.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_DIRECTORY | 0x20000000 | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}
impl Node {
    fn directory(&self) -> io::Result<&File> {
        self.file.as_ref().ok_or_else(unknown)
    }
}
fn physical_path(file: &File) -> io::Result<PathBuf> {
    let mut bytes = vec![0u8; 4096];
    // SAFETY: live descriptor and bounded F_GETPATH_NOFIRMLINK output.
    if unsafe { libc::fcntl(file.as_raw_fd(), 102, bytes.as_mut_ptr()) } == -1 {
        return Err(io::Error::last_os_error());
    }
    let end = bytes.iter().position(|b| *b == 0).ok_or_else(unknown)?;
    Ok(PathBuf::from(OsStr::from_bytes(&bytes[..end])))
}
fn exact_name(parent: &File, name: &CStr, deadline: Instant) -> io::Result<()> {
    // SAFETY: opening dot returns an independent directory stream, not a shared offset.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fdopendir takes ownership of fd on success.
    let dir = unsafe { libc::fdopendir(fd) };
    if dir.is_null() {
        unsafe { libc::close(fd) };
        return Err(io::Error::last_os_error());
    }
    let result = (|| {
        for _ in 0..100_000 {
            check(deadline)?;
            // SAFETY: stream is live; result is borrowed only until next readdir.
            let entry = unsafe { libc::readdir(dir) };
            if entry.is_null() {
                return Err(unknown());
            }
            let actual = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            if actual.to_bytes() == name.to_bytes() {
                return Ok(());
            }
        }
        Err(unknown())
    })();
    // SAFETY: close this stream once, including its owned fd.
    if unsafe { libc::closedir(dir) } != 0 {
        return Err(io::Error::last_os_error());
    }
    result
}
impl ProgramPath {
    pub fn capture(path: &Path, deadline: Instant) -> io::Result<Self> {
        let policy = crate::ReadOnlyPolicy::enter()?;
        let result = Self::capture_inner(path, deadline);
        let restored = policy.restore();
        let value = result?;
        restored?;
        Ok(value)
    }
    fn capture_inner(path: &Path, deadline: Instant) -> io::Result<Self> {
        let bytes = path.as_os_str().as_bytes();
        if !path.is_absolute()
            || bytes.len() > 4096
            || bytes.contains(&0)
            || bytes.windows(2).any(|p| p == b"//")
        {
            return Err(unknown());
        }
        let mut pending: VecDeque<Vec<u8>> = bytes
            .split(|b| *b == b'/')
            .skip(1)
            .map(|s| s.to_vec())
            .collect();
        if pending
            .iter()
            .any(|p| p.is_empty() || p == b"." || p == b"..")
        {
            return Err(unknown());
        }
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(0x20000000 | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open("/")?;
        let root_stamp = Stamp::read(&root.metadata()?);
        let root_acl = crate::acl::snapshot(&root)?;
        let mut value = Self {
            nodes: vec![Node {
                volume: Volume::read(&root)?,
                file: Some(root),
                stamp: root_stamp,
                parent: None,
                name: None,
                link: None,
                acl: root_acl,
            }],
            resolved: PathBuf::from("/"),
        };
        let mut stack = vec![0usize];
        let mut links = BTreeSet::new();
        let mut count = 0;
        let mut final_index = 0;
        while let Some(part) = pending.pop_front() {
            check(deadline)?;
            count += 1;
            if count > 64 {
                return Err(unknown());
            }
            if part == b"." {
                continue;
            }
            if part == b".." {
                if stack.len() == 1 {
                    return Err(unknown());
                }
                stack.pop();
                value.resolved.pop();
                final_index = *stack.last().ok_or_else(unknown)?;
                continue;
            }
            let parent = *stack.last().ok_or_else(unknown)?;
            let name = CString::new(part).map_err(|_| unknown())?;
            exact_name(value.nodes[parent].directory()?, &name, deadline)?;
            let parent_file = value.nodes[parent].directory()?;
            let stamp = child_stamp(parent_file, &name)?;
            let kind = stamp.mode as u16 & libc::S_IFMT;
            let is_dir = kind == libc::S_IFDIR;
            let is_link = kind == libc::S_IFLNK;
            if stamp.flags & 0x40000000 != 0 || (!is_dir && !is_link && kind != libc::S_IFREG) {
                return Err(unknown());
            }
            let file = if is_dir {
                Some(open_child(parent_file, &name)?)
            } else {
                None
            };
            let volume = if let Some(file) = &file {
                if Stamp::read(&file.metadata()?) != stamp {
                    return Err(unknown());
                }
                Volume::read(file)?
            } else {
                if stamp.dev != value.nodes[parent].stamp.dev {
                    return Err(unknown());
                }
                value.nodes[parent].volume.clone()
            };
            let link = if is_link {
                Some(link_text(parent_file, &name)?)
            } else {
                None
            };
            let acl = if let Some(file) = &file {
                crate::acl::snapshot(file)?
            } else {
                None
            };
            if child_stamp(parent_file, &name)? != stamp {
                return Err(unknown());
            }
            let identity = (stamp.dev, stamp.ino);
            let index = value.nodes.len();
            value.nodes.push(Node {
                file,
                volume,
                stamp,
                parent: Some(parent),
                name: Some(name),
                link: link.clone(),
                acl,
            });
            if let Some(target) = link {
                if links.len() >= 8
                    || !links.insert(identity)
                    || target.is_empty()
                    || target.contains(&0)
                {
                    return Err(unknown());
                }
                if target.starts_with(b"/") {
                    stack.truncate(1);
                    value.resolved = PathBuf::from("/");
                    final_index = 0;
                }
                let parts: Vec<_> = target
                    .split(|b| *b == b'/')
                    .enumerate()
                    .filter_map(|(i, p)| {
                        if i == 0 && target.starts_with(b"/") {
                            None
                        } else {
                            Some(p.to_vec())
                        }
                    })
                    .collect();
                if parts.iter().any(Vec::is_empty) || parts.len() + pending.len() + count > 64 {
                    return Err(unknown());
                }
                for p in parts.into_iter().rev() {
                    pending.push_front(p);
                }
            } else {
                value.resolved.push(OsStr::from_bytes(
                    value.nodes[index].name.as_ref().unwrap().to_bytes(),
                ));
                if !pending.is_empty() && !is_dir {
                    return Err(unknown());
                }
                final_index = index;
                if is_dir {
                    stack.push(index);
                }
            }
        }
        let final_node = &value.nodes[final_index];
        value.resolved = if let Some(file) = &final_node.file {
            physical_path(file)?
        } else {
            physical_path(value.nodes[final_node.parent.ok_or_else(unknown)?].directory()?)?.join(
                OsStr::from_bytes(final_node.name.as_ref().ok_or_else(unknown)?.to_bytes()),
            )
        };
        if !value.resolved.is_absolute() {
            return Err(unknown());
        }
        value.revalidate(deadline)?;
        Ok(value)
    }
    pub fn same_evidence(&self, other: &Self) -> bool {
        self.resolved == other.resolved
            && self.nodes.len() == other.nodes.len()
            && self.nodes.iter().zip(&other.nodes).all(|(a, b)| {
                a.stamp == b.stamp
                    && a.volume == b.volume
                    && a.parent == b.parent
                    && a.name == b.name
                    && a.link == b.link
                    && a.acl == b.acl
            })
    }
    pub fn path(&self) -> &Path {
        &self.resolved
    }
    pub fn revalidate(&self, deadline: Instant) -> io::Result<()> {
        let policy = crate::ReadOnlyPolicy::enter()?;
        let result = (|| {
            for node in &self.nodes {
                check(deadline)?;
                if let Some(file) = &node.file {
                    if Stamp::read(&file.metadata()?) != node.stamp
                        || Volume::read(file)? != node.volume
                        || crate::acl::snapshot(file)? != node.acl
                    {
                        return Err(unknown());
                    }
                }
                if let Some(parent) = node.parent {
                    let name = node.name.as_ref().ok_or_else(unknown)?;
                    exact_name(self.nodes[parent].directory()?, name, deadline)?;
                    if child_stamp(self.nodes[parent].directory()?, name)? != node.stamp {
                        return Err(unknown());
                    }
                    if let Some(target) = &node.link {
                        if link_text(self.nodes[parent].directory()?, name)? != *target
                            || child_stamp(self.nodes[parent].directory()?, name)? != node.stamp
                        {
                            return Err(unknown());
                        }
                    }
                } else {
                    let fresh = std::fs::symlink_metadata("/")?;
                    if Stamp::read(&fresh) != node.stamp {
                        return Err(unknown());
                    }
                }
            }
            check(deadline)
        })();
        let restored = policy.restore();
        result?;
        restored
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::symlink,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let p = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "sayaka-launch-source-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }
    #[test]
    fn retains_multihop_identity_and_refuses_link_replacement() {
        let f = Fixture::new();
        std::fs::write(f.0.join("program"), b"fixture").unwrap();
        symlink("program", f.0.join("second")).unwrap();
        symlink("second", f.0.join("first")).unwrap();
        let observed = ProgramPath::capture(&f.0.join("first"), deadline()).unwrap();
        let direct = ProgramPath::capture(&f.0.join("program"), deadline()).unwrap();
        assert_eq!(observed.path(), direct.path());
        observed.revalidate(deadline()).unwrap();
        std::fs::remove_file(f.0.join("second")).unwrap();
        symlink("program", f.0.join("second")).unwrap();
        assert!(observed.revalidate(deadline()).is_err());
    }
    #[test]
    fn cycles_missing_targets_relative_inputs_and_hop_limit_are_unknown() {
        let f = Fixture::new();
        symlink("cycle", f.0.join("cycle")).unwrap();
        symlink("absent", f.0.join("missing")).unwrap();
        assert!(ProgramPath::capture(&f.0.join("cycle"), deadline()).is_err());
        assert!(ProgramPath::capture(&f.0.join("missing"), deadline()).is_err());
        assert!(ProgramPath::capture(Path::new("relative/program"), deadline()).is_err());
        std::fs::write(f.0.join("leaf"), b"fixture").unwrap();
        for i in (0..9).rev() {
            symlink(
                if i == 8 {
                    "leaf".to_owned()
                } else {
                    format!("hop{}", i + 1)
                },
                f.0.join(format!("hop{i}")),
            )
            .unwrap();
        }
        assert!(ProgramPath::capture(&f.0.join("hop0"), deadline()).is_err());
    }
}
