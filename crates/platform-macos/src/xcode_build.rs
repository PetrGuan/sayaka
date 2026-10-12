// SPDX-License-Identifier: MPL-2.0
//! Fixed, bounded, no-follow Xcode build-directory signature probes.
use std::ffi::{CStr, CString, c_long, c_ulong, c_void};
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd};
use std::os::macos::fs::MetadataExt as _;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    pub signals: Vec<&'static str>,
    pub workspace: Option<PathBuf>,
    pub workspace_state: &'static str,
}

pub fn managed(path: &Path) -> io::Result<bool> {
    Ok(path
        .starts_with(crate::effective_account_home()?.join("Library/Developer/Xcode/DerivedData")))
}

// One fixed child at a time; do not follow aliases, mount points, or dataless
// objects. No directory enumeration is needed to classify a candidate.
pub(crate) fn child(fd: BorrowedFd<'_>, name: &str, directory: bool, device: u64) -> io::Result<Option<File>> {
    let name = CString::new(name).expect("fixed signature name");
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fd is borrowed/live, name and stat storage are valid.
    if unsafe {
        libc::fstatat(
            fd.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        let e = io::Error::last_os_error();
        return if e.kind() == io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(e)
        };
    }
    // SAFETY: fstatat succeeded and initialized stat.
    let stat = unsafe { stat.assume_init() };
    let kind = if directory {
        libc::S_IFDIR
    } else {
        libc::S_IFREG
    };
    if stat.st_mode & libc::S_IFMT != kind
        || stat.st_flags & 0x40000000 != 0
        || stat.st_dev as u64 != device
    {
        return Ok(None);
    }
    // SAFETY: same valid fd/name; nofollow and nonblock exclude replacement links/FIFOs.
    let raw = unsafe {
        libc::openat(
            fd.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | if directory { libc::O_DIRECTORY } else { 0 },
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: newly owned descriptor from successful openat.
    let file = unsafe { File::from_raw_fd(raw) };
    let m = file.metadata()?;
    if m.dev() != device
        || m.ino() != stat.st_ino
        || m.mode() & libc::S_IFMT as u32 != kind as u32
        || m.st_flags() & 0x40000000 != 0
    {
        return Err(io::Error::other("Xcode signature entry changed"));
    }
    Ok(Some(file))
}

pub fn inspect(fd: BorrowedFd<'_>, path: &Path) -> io::Result<Option<Evidence>> {
    use std::os::fd::AsFd;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: borrowed live fd and valid output storage.
    if unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful fstat initialized stat.
    let device = unsafe { stat.assume_init() }.st_dev as u64;
    let Some(build) = child(fd, "Build", true, device)? else {
        return Ok(None);
    };
    let mut signals = Vec::new();
    for (name, label) in [
        ("Intermediates.noindex", "Build/Intermediates.noindex"),
        ("Products", "Build/Products"),
    ] {
        if child(build.as_fd(), name, true, device)?.is_some() {
            signals.push(label);
        }
    }
    drop(build);
    if signals.is_empty() || managed(path)? {
        return Ok(None);
    }
    let first = signals.len();
    if let Some(logs) = child(fd, "Logs", true, device)? {
        if child(logs.as_fd(), "Build", true, device)?.is_some() {
            signals.push("Logs/Build");
        }
    }
    for name in ["ModuleCache.noindex", "Index.noindex", "SourcePackages"] {
        if child(fd, name, true, device)?.is_some() {
            signals.push(name);
        }
    }
    let mut workspace = None;
    if let Some(file) = child(fd, "info.plist", false, device)? {
        // Malformed/oversized plist is not a signal. Other independent signals
        // can still match, but unavailable workspace provenance stays unknown.
        if file.metadata()?.len() <= 16_384 {
            let mut bytes = Vec::new();
            file.take(16_385).read_to_end(&mut bytes)?;
            if bytes.len() <= 16_384 {
                workspace = workspace_path(&bytes);
            }
        }
    }
    if workspace.is_some() {
        signals.push("info.plist:WorkspacePath");
    }
    if signals.len() == first {
        return Ok(None);
    }
    let workspace_state = match workspace.as_ref().map(std::fs::symlink_metadata) {
        Some(Ok(_)) => "present",
        Some(Err(e)) if e.kind() == io::ErrorKind::NotFound => "not_found",
        _ => "unknown",
    };
    Ok(Some(Evidence {
        signals,
        workspace,
        workspace_state,
    }))
}

pub fn inspect_path(path: &Path) -> io::Result<Option<Evidence>> {
    use std::os::fd::AsFd;
    let policy = crate::ReadOnlyPolicy::enter()?;
    let result = (|| {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(0x20000000 | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_DIRECTORY)
            .open(path)?;
        if file.metadata()?.st_flags() & 0x40000000 != 0 {
            return Err(io::Error::other("dataless Xcode build directory"));
        }
        inspect(file.as_fd(), path)
    })();
    let restored = policy.restore();
    let result = result?;
    restored?;
    Ok(result)
}

// Existing platform modules use distinct opaque CF pointer types for these
// same C ABI functions; this narrow reader uses void pointers after type checks.
#[allow(clashing_extern_declarations)]
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFDataCreate(a: *const c_void, b: *const u8, n: c_long) -> *const c_void;
    fn CFPropertyListCreateWithData(
        a: *const c_void,
        d: *const c_void,
        o: c_ulong,
        f: *mut c_ulong,
        e: *mut *const c_void,
    ) -> *const c_void;
    fn CFGetTypeID(v: *const c_void) -> c_ulong;
    fn CFDictionaryGetTypeID() -> c_ulong;
    fn CFDictionaryGetValue(d: *const c_void, k: *const c_void) -> *const c_void;
    fn CFStringCreateWithCString(a: *const c_void, s: *const i8, e: u32) -> *const c_void;
    fn CFStringGetTypeID() -> c_ulong;
    fn CFStringGetLength(s: *const c_void) -> c_long;
    fn CFStringGetCString(s: *const c_void, b: *mut i8, n: c_long, e: u32) -> u8;
    fn CFRelease(v: *const c_void);
}
struct OwnedCF(*const c_void);
impl Drop for OwnedCF {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CFRelease(self.0) };
        }
    }
}
fn workspace_path(bytes: &[u8]) -> Option<PathBuf> {
    const UTF8: u32 = 0x08000100;
    // SAFETY: bounded bytes are copied into CFData; owned CF objects live for
    // the entire lookup, borrowed dictionary values are type-checked.
    unsafe {
        let data = OwnedCF(CFDataCreate(
            std::ptr::null(),
            bytes.as_ptr(),
            bytes.len() as c_long,
        ));
        if data.0.is_null() {
            return None;
        }
        let list = OwnedCF(CFPropertyListCreateWithData(
            std::ptr::null(),
            data.0,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        ));
        if list.0.is_null() || CFGetTypeID(list.0) != CFDictionaryGetTypeID() {
            return None;
        }
        let key = OwnedCF(CFStringCreateWithCString(
            std::ptr::null(),
            c"WorkspacePath".as_ptr(),
            UTF8,
        ));
        if key.0.is_null() {
            return None;
        }
        let value = CFDictionaryGetValue(list.0, key.0);
        if value.is_null() || CFGetTypeID(value) != CFStringGetTypeID() {
            return None;
        }
        let mut buffer = [0i8; 4097];
        if CFStringGetCString(value, buffer.as_mut_ptr(), buffer.len() as c_long, UTF8) == 0 {
            return None;
        }
        let cf_length = CFStringGetLength(value);
        let value = CStr::from_ptr(buffer.as_ptr()).to_str().ok()?;
        if value.encode_utf16().count() as c_long != cf_length {
            return None;
        }
        let path = PathBuf::from(value);
        if !path.is_absolute()
            || value.chars().any(char::is_control)
            || path.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return None;
        }
        Some(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    fn with_dir(f: impl FnOnce(&Path)) {
        let root = std::env::temp_dir().join(format!(
            "sayaka-xcode-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let root = root.canonicalize().unwrap();
        f(&root);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn requires_two_independent_signals_not_folder_name() {
        with_dir(|root| {
            let data = root.join("arbitrary-name");
            std::fs::create_dir_all(data.join("Build/Products")).unwrap();
            assert!(inspect_path(&data).unwrap().is_none());
            std::fs::create_dir_all(data.join("Logs/Build")).unwrap();
            let found = inspect_path(&data).unwrap().unwrap();
            assert_eq!(found.signals, ["Build/Products", "Logs/Build"]);
            assert_eq!(found.workspace_state, "unknown");
        });
    }
    #[test]
    fn links_and_invalid_plists_are_not_signature_evidence() {
        with_dir(|root| {
            let data = root.join("data");
            std::fs::create_dir_all(data.join("Build/Products")).unwrap();
            std::fs::create_dir_all(root.join("other")).unwrap();
            symlink(root.join("other"), data.join("ModuleCache.noindex")).unwrap();
            std::fs::write(data.join("info.plist"), b"not a plist").unwrap();
            assert!(inspect_path(&data).unwrap().is_none());
            symlink(&data, root.join("alias")).unwrap();
            assert!(inspect_path(&root.join("alias")).is_err());
        });
    }
    #[test]
    fn workspace_path_is_provenance_and_missing_is_explicit() {
        with_dir(|root| {
            std::fs::create_dir_all(root.join("Build/Intermediates.noindex")).unwrap();
            let path = root.join("Gone.xcodeproj");
            let xml = format!(
                "<plist version=\"1.0\"><dict><key>WorkspacePath</key><string>{}</string></dict></plist>",
                path.display()
            );
            std::fs::write(root.join("info.plist"), xml).unwrap();
            let e = inspect_path(root).unwrap().unwrap();
            assert_eq!(e.workspace, Some(path.clone()));
            assert_eq!(e.workspace_state, "not_found");
            std::fs::create_dir(&path).unwrap();
            assert_eq!(
                inspect_path(root).unwrap().unwrap().workspace_state,
                "present"
            );
        });
        let standard = crate::effective_account_home()
            .unwrap()
            .join("Library/Developer/Xcode/DerivedData/Some-project");
        assert!(managed(&standard).unwrap());
        assert!(
            !managed(
                &crate::effective_account_home()
                    .unwrap()
                    .join("Documents/CustomData")
            )
            .unwrap()
        );
    }
}
