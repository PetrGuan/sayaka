// SPDX-License-Identifier: MPL-2.0
//! Metadata-only firmware observation, with descriptor-relative enumeration.
use std::{
    ffi::CStr,
    fs::{File, OpenOptions},
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
    time::Instant,
};

pub struct Leaf {
    pub present: bool,
    pub count: u64,
    pub bytes: u64,
    pub complete: bool,
    pub issue: Option<&'static str>,
}
fn fail(code: &'static str) -> io::Error {
    io::Error::other(code)
}
fn safe(m: &std::fs::Metadata) -> bool {
    use std::os::macos::fs::MetadataExt;
    m.st_flags() & 0x40000000 == 0
}
/// Open all ancestry without links. The policy prevents data materialization.
pub fn directory(path: &Path) -> io::Result<File> {
    let policy = crate::ReadOnlyPolicy::enter()?;
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(0x20000000 | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    for p in path.ancestors() {
        if !safe(&std::fs::symlink_metadata(p)?) {
            return Err(fail("dataless_ancestry"));
        }
    }
    if !safe(&f.metadata()?) {
        return Err(fail("dataless_directory"));
    }
    policy.restore()?;
    Ok(f)
}
pub struct Entries(*mut libc::DIR);
impl Drop for Entries {
    fn drop(&mut self) {
        unsafe {
            libc::closedir(self.0);
        }
    }
}
impl Entries {
    pub fn new(file: &File) -> io::Result<Self> {
        // SAFETY: duplicate remains owned here until fdopendir takes ownership.
        let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let ptr = unsafe { libc::fdopendir(fd) };
        if ptr.is_null() {
            unsafe {
                libc::close(fd);
            };
            return Err(io::Error::last_os_error());
        }
        Ok(Self(ptr))
    }
    pub fn next_name(&mut self) -> io::Result<Option<std::ffi::CString>> {
        loop {
            // SAFETY: owned DIR; readdir pointer copied before next iteration.
            unsafe {
                *libc::__error() = 0;
                let e = libc::readdir(self.0);
                if e.is_null() {
                    return if *libc::__error() == 0 {
                        Ok(None)
                    } else {
                        Err(io::Error::last_os_error())
                    };
                }
                let name = CStr::from_ptr((*e).d_name.as_ptr());
                if name.to_bytes() == b"." || name.to_bytes() == b".." {
                    continue;
                }
                return Ok(Some(name.to_owned()));
            }
        }
    }
}
pub fn child_metadata(parent: &File, name: &CStr) -> io::Result<libc::stat> {
    let mut s = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: parent remains open; name is copied dirent name, no slash.
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            s.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { s.assume_init() })
}
/// Child directory open for read-only clients; never follow a substituted link.
pub fn child_directory(parent: &File, name: &CStr) -> io::Result<File> {
    let policy = crate::ReadOnlyPolicy::enter()?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    if !safe(&file.metadata()?) {
        return Err(fail("dataless_directory"));
    }
    policy.restore()?;
    Ok(file)
}
pub fn observe(home: &Path, leaf: &str, deadline: Instant) -> io::Result<Leaf> {
    if Instant::now() >= deadline {
        return Err(fail("budget"));
    }
    let policy = crate::ReadOnlyPolicy::enter()?;
    let result = observe_inner(home, leaf, deadline);
    let restored = policy.restore();
    restored?;
    if Instant::now() >= deadline {
        return Err(fail("budget"));
    }
    result
}
fn observe_inner(home: &Path, leaf: &str, deadline: Instant) -> io::Result<Leaf> {
    // Ancestors are opened independently rather than following a failed full path.
    let mut current = directory(home)?;
    let volume = crate::volume_info(home)?;
    let mut fs = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: live owned descriptor and writable statfs storage.
    if unsafe { libc::fstatfs(current.as_raw_fd(), fs.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let fs = unsafe { fs.assume_init() };
    let named = std::fs::symlink_metadata(home)?;
    let held = current.metadata()?;
    if fs.f_flags & libc::MNT_LOCAL == 0
        || !volume.local
        || !volume.internal
        || volume.removable
        || volume.ejectable
        || named.dev() != held.dev()
        || named.ino() != held.ino()
    {
        return Err(fail("unsupported_or_changed_home_volume"));
    }
    let device = current.metadata()?.dev();
    for name in ["Library", "iTunes", leaf] {
        if Instant::now() >= deadline {
            return Err(fail("budget"));
        }
        let name = std::ffi::CString::new(name).map_err(|_| fail("name"))?;
        let metadata = match child_metadata(&current, &name) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Ok(Leaf {
                    present: false,
                    count: 0,
                    bytes: 0,
                    complete: true,
                    issue: None,
                });
            }
            Err(e) => return Err(e),
        };
        if metadata.st_mode & libc::S_IFMT != libc::S_IFDIR
            || metadata.st_flags & 0x40000000 != 0
            || metadata.st_dev as u64 != device
        {
            return Err(fail("unsafe_ancestry"));
        }
        current = child_directory(&current, &name)?;
        let m = current.metadata()?;
        if m.dev() != device || m.ino() != metadata.st_ino {
            return Err(fail("changed"));
        }
    }
    let before = current.metadata()?;
    let mut entries = Entries::new(&current)?;
    let mut out = Leaf {
        present: true,
        count: 0,
        bytes: 0,
        complete: true,
        issue: None,
    };
    let mut seen = 0;
    loop {
        if Instant::now() >= deadline || seen >= 4096 {
            out.complete = false;
            out.issue = Some("budget");
            break;
        }
        let Some(name) = entries.next_name()? else {
            break;
        };
        seen += 1;
        let s = child_metadata(&current, &name)?;
        if !name.to_bytes().ends_with(b".ipsw")
            || s.st_mode & libc::S_IFMT != libc::S_IFREG
            || s.st_flags & 0x40000000 != 0
            || s.st_dev as u64 != device
            || s.st_size < 0
        {
            out.complete = false;
            out.issue = Some("excluded_contents");
            continue;
        }
        out.bytes = out
            .bytes
            .checked_add(s.st_size as u64)
            .ok_or_else(|| fail("overflow"))?;
        out.count += 1;
    }
    let after = current.metadata()?;
    if before.mtime() != after.mtime() || before.mtime_nsec() != after.mtime_nsec() {
        out.complete = false;
        out.issue = Some("changed");
    }
    Ok(out)
}
