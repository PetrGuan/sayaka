// SPDX-License-Identifier: MPL-2.0
//! Bounded no-follow marker and cache-tag observations. No project code is run.
use crate::project_rules::{self, PROJECT_ARTIFACT_RULES};
use crate::xcode_build::child;
use std::ffi::CStr;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::macos::fs::MetadataExt as _;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    pub rule_id: Option<&'static str>,
    pub project_root: PathBuf,
    pub markers: Vec<PathBuf>,
    pub cache_tag: bool,
}
const TAG: &[u8; 43] = b"Signature: 8a477f597d28d172789f06886806bc55";

fn open_directory(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(0x20000000 | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_DIRECTORY)
        .open(path)?;
    if file.metadata()?.st_flags() & 0x40000000 != 0 {
        return Err(io::Error::other("dataless project directory"));
    }
    Ok(file)
}

// The root plus one duplicated directory descriptor fits the scanner's two
// transient descriptor permits. Drop enumeration before opening any marker.
fn names(root: &File) -> io::Result<Vec<String>> {
    // SAFETY: live borrowed fd; fdopendir owns the duplicate on success.
    let raw = unsafe { libc::fcntl(root.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let dir = unsafe { libc::fdopendir(raw) };
    if dir.is_null() {
        let e = io::Error::last_os_error();
        unsafe {
            libc::close(raw);
        }
        return Err(e);
    }
    struct Directory(*mut libc::DIR);
    impl Drop for Directory {
        fn drop(&mut self) {
            unsafe {
                libc::closedir(self.0);
            }
        }
    }
    let dir = Directory(dir);
    let mut result = Vec::new();
    for _ in 0..4096 {
        // SAFETY: owned live DIR; errno distinguishes end of stream from error.
        unsafe {
            *libc::__error() = 0;
        }
        let entry = unsafe { libc::readdir(dir.0) };
        if entry.is_null() {
            let code = unsafe { *libc::__error() };
            if code != 0 {
                return Err(io::Error::from_raw_os_error(code));
            }
            result.sort();
            return Ok(result);
        }
        let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if let Ok(name) = bytes.to_str() {
            result.push(name.to_owned());
        }
    }
    Err(io::Error::other("project marker sibling limit reached"))
}

fn marker(
    root: &File,
    pattern: &str,
    directory: bool,
    listing: &mut Option<Vec<String>>,
) -> io::Result<Option<String>> {
    if pattern.contains('*') && listing.is_none() {
        *listing = Some(names(root)?);
    }
    let candidates: Vec<&str> = if pattern.contains('*') {
        listing
            .as_ref()
            .unwrap()
            .iter()
            .map(String::as_str)
            .filter(|n| project_rules::name_matches(pattern, n))
            .collect()
    } else {
        pattern.split('|').collect()
    };
    let device = root.metadata()?.dev();
    for name in candidates {
        if child(root.as_fd(), name, directory, device)?.is_some() {
            return Ok(Some(name.to_owned()));
        }
    }
    Ok(None)
}

pub fn inspect(fd: BorrowedFd<'_>, path: &Path) -> io::Result<Option<Evidence>> {
    // SAFETY: live borrowed descriptor and initialized storage on success.
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let device = unsafe { stat.assume_init() }.st_dev as u64;
    let cache_tag = match child(fd, "CACHEDIR.TAG", false, device)? {
        Some(mut f) => {
            let mut bytes = [0; 43];
            match f.read_exact(&mut bytes) {
                Ok(()) => &bytes == TAG,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => false,
                Err(e) => return Err(e),
            }
        }
        None => false,
    };
    let mut current_root: Option<(PathBuf, File, Option<Vec<String>>)> = None;
    for rule in PROJECT_ARTIFACT_RULES {
        let Some(root_path) = project_rules::project_root(rule, path) else {
            continue;
        };
        if current_root
            .as_ref()
            .is_none_or(|(p, _, _)| p != &root_path)
        {
            let root = open_directory(&root_path)?;
            if root.metadata()?.dev() != device {
                return Err(io::Error::other("project marker mount crossing"));
            }
            current_root = Some((root_path.clone(), root, None));
        }
        let (_, root, listing) = current_root.as_mut().unwrap();
        let Some(name) = marker(root, rule.marker, rule.directory_marker, listing)? else {
            continue;
        };
        let mut markers = vec![root_path.join(name)];
        if let Some(required) = rule.prerequisite {
            let Some(name) = marker(root, required, false, listing)? else {
                continue;
            };
            markers.push(root_path.join(name));
        }
        return Ok(Some(Evidence {
            rule_id: Some(rule.id),
            project_root: root_path,
            markers,
            cache_tag,
        }));
    }
    Ok(cache_tag.then(|| Evidence {
        rule_id: None,
        project_root: path.parent().unwrap_or(path).to_path_buf(),
        markers: vec![],
        cache_tag,
    }))
}

pub fn inspect_path(path: &Path) -> io::Result<Option<Evidence>> {
    let policy = crate::ReadOnlyPolicy::enter()?;
    let result = (|| {
        let file = open_directory(path)?;
        inspect(file.as_fd(), path)
    })();
    let restored = policy.restore();
    let result = result?;
    restored?;
    Ok(result)
}

/// Hidden names are permitted only within this rule's exact artifact suffix.
/// Project ancestors and scope retain the standard protection policy.
pub fn protected_spelling(path: &Path, evidence: &Evidence) -> PathBuf {
    match path.strip_prefix(&evidence.project_root) {
        Ok(relative) => evidence.project_root.join(
            relative
                .components()
                .map(|c| {
                    let name = c.as_os_str().to_string_lossy();
                    name.strip_prefix('.').unwrap_or(&name).to_owned()
                })
                .collect::<PathBuf>(),
        ),
        Err(_) => path.to_path_buf(),
    }
}
