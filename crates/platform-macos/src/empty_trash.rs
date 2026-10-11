// SPDX-License-Identifier: MPL-2.0
//! Read-only, descriptor-relative home-Trash evidence. No deletion or Apple Events.
use std::{
    ffi::{CStr, CString, OsStr},
    fs::{File, Metadata, OpenOptions},
    io,
    mem::MaybeUninit,
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Path, PathBuf},
    time::Instant,
};
fn invalid() -> io::Error {
    io::Error::other("empty_trash_evidence_unknown_or_changed")
}
fn deadline(d: Instant) -> io::Result<()> {
    if Instant::now() >= d {
        Err(invalid())
    } else {
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stamp {
    pub device: u64,
    pub inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    flags: u32,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
    created: (i64, i64),
    generation: u32,
}
impl Stamp {
    fn metadata(m: &Metadata) -> Self {
        use std::os::macos::fs::MetadataExt;
        let dir = m.is_dir();
        Self {
            device: m.dev(),
            inode: m.ino(),
            mode: m.mode(),
            uid: m.uid(),
            gid: m.gid(),
            flags: m.st_flags(),
            size: if dir { 0 } else { m.len() },
            modified: if dir {
                (0, 0)
            } else {
                (m.mtime(), m.mtime_nsec())
            },
            changed: if dir {
                (0, 0)
            } else {
                (m.ctime(), m.ctime_nsec())
            },
            created: (m.st_birthtime(), m.st_birthtime_nsec()),
            generation: m.st_gen(),
        }
    }
    fn stat(m: libc::stat) -> Self {
        Self {
            device: m.st_dev as u64,
            inode: m.st_ino,
            mode: m.st_mode as u32,
            uid: m.st_uid,
            gid: m.st_gid,
            flags: m.st_flags,
            size: m.st_size as u64,
            modified: (m.st_mtime, m.st_mtime_nsec),
            changed: (m.st_ctime, m.st_ctime_nsec),
            created: (m.st_birthtime, m.st_birthtime_nsec),
            generation: m.st_gen,
        }
    }
}
struct Directory {
    path: PathBuf,
    file: File,
    stamp: Stamp,
    acl: Option<Vec<u8>>,
}
pub struct Root {
    path: PathBuf,
    chain: Vec<Directory>,
}
fn physical(file: &File) -> io::Result<PathBuf> {
    let mut bytes = [0u8; 4096]; // SAFETY: live fd and bounded output for F_GETPATH_NOFIRMLINK.
    if unsafe { libc::fcntl(file.as_raw_fd(), 102, bytes.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let end = bytes.iter().position(|b| *b == 0).ok_or_else(invalid)?;
    Ok(PathBuf::from(OsStr::from_bytes(&bytes[..end])))
}
impl Root {
    pub fn capture(d: Instant) -> io::Result<Self> {
        Self::capture_path(crate::effective_account_home()?.join(".Trash"), d, true)
    }
    /// Fixed account state base; callers cannot choose an alternative barrier.
    pub fn state_base(d: Instant) -> io::Result<Self> {
        Self::capture_path(
            crate::effective_account_home()?.join("Library/Application Support/SayakaCleaner"),
            d,
            false,
        )
    }
    fn capture_path(path: PathBuf, d: Instant, trash: bool) -> io::Result<Self> {
        let policy = crate::ReadOnlyPolicy::enter()?;
        let result = (|| {
            let mut chain = Vec::new();
            for p in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
                deadline(d)?;
                let file = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | 0x20000000)
                    .open(p)?;
                let m = file.metadata()?;
                let stamp = Stamp::metadata(&m);
                if stamp.flags & 0x40000000 != 0
                    || (p.parent().is_some() && physical(&file)?.file_name() != p.file_name())
                {
                    return Err(invalid());
                }
                let acl = crate::acl::snapshot(&file)?;
                chain.push(Directory {
                    path: p.to_owned(),
                    file,
                    stamp,
                    acl,
                });
            }
            let root = Self { path, chain };
            let last = root.chain.last().ok_or_else(invalid)?;
            let home = root.chain.get(root.chain.len() - 2).ok_or_else(invalid)?;
            if last.stamp.uid != unsafe { libc::geteuid() }
                || last.stamp.mode & 0o022 != 0
                || last.stamp.device != home.stamp.device
                || (trash && physical(&last.file)? != physical(&home.file)?.join(".Trash"))
            {
                return Err(invalid());
            }
            root.revalidate(d)?;
            Ok(root)
        })();
        let restored = policy.restore();
        let root = result?;
        restored?;
        Ok(root)
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn identity(&self) -> (u64, u64) {
        let s = &self.chain.last().expect("captured root").stamp;
        (s.device, s.inode)
    }
    pub fn revalidate(&self, d: Instant) -> io::Result<()> {
        for part in &self.chain {
            deadline(d)?;
            if Stamp::metadata(&part.file.metadata()?) != part.stamp
                || Stamp::metadata(&std::fs::symlink_metadata(&part.path)?) != part.stamp
                || crate::acl::snapshot(&part.file)? != part.acl
            {
                return Err(invalid());
            }
        }
        deadline(d)
    }
    /// ENOENT only means this exact leaf is absent under the unchanged held root.
    pub fn observe(&self, path: &Path, d: Instant) -> io::Result<Option<Stamp>> {
        let policy = crate::ReadOnlyPolicy::enter()?;
        let result = (|| {
            self.revalidate(d)?;
            if path.parent() != Some(self.path()) || path.as_os_str().as_bytes().len() > 4096 {
                return Err(invalid());
            }
            let name = CString::new(path.file_name().ok_or_else(invalid)?.as_bytes())
                .map_err(|_| invalid())?;
            if self
                .path
                .join(OsStr::from_bytes(name.to_bytes()))
                .as_os_str()
                .as_bytes()
                != path.as_os_str().as_bytes()
            {
                return Err(invalid());
            }
            if name.to_bytes().is_empty()
                || [b".".as_slice(), b"..".as_slice()].contains(&name.to_bytes())
            {
                return Err(invalid());
            }
            let fd = self.chain.last().ok_or_else(invalid)?.file.as_raw_fd();
            let mut stat = MaybeUninit::<libc::stat>::uninit(); // SAFETY: initialized on success, no-follow one component relative to held directory.
            if unsafe {
                libc::fstatat(
                    fd,
                    name.as_ptr(),
                    stat.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } < 0
            {
                let e = io::Error::last_os_error();
                self.revalidate(d)?;
                return if e.raw_os_error() == Some(libc::ENOENT) {
                    Ok(None)
                } else {
                    Err(e)
                };
            }
            let stamp = Stamp::stat(unsafe { stat.assume_init() });
            if stamp.flags & 0x40000000 != 0 || stamp.device != self.identity().0 {
                return Err(invalid());
            }
            // ATTR_CMN_NAME reports native spelling without enumerating Trash or opening the leaf.
            let mut attrs: libc::attrlist = unsafe { std::mem::zeroed() };
            attrs.bitmapcount = 5;
            attrs.commonattr = 1;
            let mut bytes = [0u8; 8192];
            if unsafe {
                libc::getattrlistat(
                    fd,
                    name.as_ptr(),
                    (&mut attrs as *mut libc::attrlist).cast(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                    1,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            let len = u32::from_ne_bytes(bytes[0..4].try_into().unwrap()) as usize;
            let offset = i32::from_ne_bytes(bytes[4..8].try_into().unwrap());
            let size = u32::from_ne_bytes(bytes[8..12].try_into().unwrap()) as usize;
            let start = 4i64 + offset as i64;
            if len > bytes.len()
                || len < 12
                || start < 12
                || size == 0
                || (start as usize)
                    .checked_add(size)
                    .is_none_or(|end| end > len)
            {
                return Err(invalid());
            }
            let actual = CStr::from_bytes_with_nul(&bytes[start as usize..start as usize + size])
                .map_err(|_| invalid())?;
            if actual != name.as_c_str() {
                return Err(invalid());
            }
            if unsafe {
                libc::fstatat(
                    fd,
                    name.as_ptr(),
                    stat.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
                || Stamp::stat(unsafe { stat.assume_init() }) != stamp
            {
                return Err(invalid());
            }
            self.revalidate(d)?;
            Ok(Some(stamp))
        })();
        let restored = policy.restore();
        let result = result?;
        restored?;
        Ok(result)
    }
}
