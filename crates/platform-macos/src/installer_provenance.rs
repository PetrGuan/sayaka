// SPDX-License-Identifier: MPL-2.0

//! Bounded, descriptor-based reads of macOS download-origin metadata.

use std::ffi::{CStr, c_long, c_ulong, c_void};
use std::io;
use std::os::fd::RawFd;

const WHERE_FROMS: &CStr = c"com.apple.metadata:kMDItemWhereFroms";
const QUARANTINE: &CStr = c"com.apple.quarantine";
const MAX_XATTR: usize = 8192;
const MAX_URLS: usize = 8;
const MAX_URL_BYTES: usize = 2048;
const UTF8: u32 = 0x0800_0100;

#[repr(C)]
struct CfArray {
    _private: [u8; 0],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetadataState {
    Present,
    Missing,
    Unavailable,
}

#[derive(Debug)]
pub struct InstallerOrigin {
    pub where_froms: MetadataState,
    pub quarantine: MetadataState,
    pub source_urls: Vec<String>,
    pub quarantine_agent: Option<String>,
    pub bytes_read: usize,
}

pub fn read_installer_origin(fd: RawFd) -> InstallerOrigin {
    let where_froms = read_xattr(fd, WHERE_FROMS);
    let quarantine = read_xattr(fd, QUARANTINE);
    let mut origin = InstallerOrigin {
        where_froms: state(&where_froms),
        quarantine: state(&quarantine),
        source_urls: Vec::new(),
        quarantine_agent: None,
        bytes_read: 0,
    };
    if let Ok(Some(bytes)) = &where_froms {
        origin.bytes_read += bytes.len();
        origin.source_urls = parse_where_froms(bytes);
    }
    if let Ok(Some(bytes)) = &quarantine {
        origin.bytes_read += bytes.len();
        origin.quarantine_agent = std::str::from_utf8(bytes)
            .ok()
            .and_then(|text| text.split(';').nth(2))
            .filter(|agent| {
                !agent.is_empty() && agent.len() <= 128 && agent.chars().all(|c| !c.is_control())
            })
            .map(str::to_owned);
    }
    origin
}

fn state(value: &io::Result<Option<Vec<u8>>>) -> MetadataState {
    match value {
        Ok(Some(_)) => MetadataState::Present,
        Ok(None) => MetadataState::Missing,
        Err(_) => MetadataState::Unavailable,
    }
}

fn read_xattr(fd: RawFd, name: &CStr) -> io::Result<Option<Vec<u8>>> {
    // SAFETY: fd is owned by the caller; name is NUL-terminated; no buffer is passed.
    let length = unsafe { libc::fgetxattr(fd, name.as_ptr(), std::ptr::null_mut(), 0, 0, 0) };
    if length < 0 {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::ENOATTR) {
            Ok(None)
        } else {
            Err(error)
        };
    }
    let length = usize::try_from(length).map_err(|_| io::Error::other("xattr size overflow"))?;
    if length > MAX_XATTR {
        return Err(io::Error::other("xattr exceeds inspection limit"));
    }
    let mut bytes = vec![0u8; length];
    // SAFETY: bytes is writable for its exact length; fd and name remain valid.
    let read =
        unsafe { libc::fgetxattr(fd, name.as_ptr(), bytes.as_mut_ptr().cast(), length, 0, 0) };
    if read < 0 {
        return Err(io::Error::last_os_error());
    }
    if usize::try_from(read).ok() != Some(length) {
        return Err(io::Error::other("xattr changed during read"));
    }
    Ok(Some(bytes))
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFDataCreate(allocator: *const c_void, bytes: *const u8, length: c_long) -> *const c_void;
    fn CFPropertyListCreateWithData(
        allocator: *const c_void,
        data: *const c_void,
        options: c_ulong,
        format: *mut c_ulong,
        error: *mut *const c_void,
    ) -> *const c_void;
    fn CFGetTypeID(value: *const c_void) -> c_ulong;
    fn CFArrayGetTypeID() -> c_ulong;
    fn CFArrayGetCount(array: *const CfArray) -> c_long;
    fn CFArrayGetValueAtIndex(array: *const CfArray, index: c_long) -> *const c_void;
    fn CFStringGetTypeID() -> c_ulong;
    fn CFStringGetCString(
        string: *const c_void,
        buffer: *mut i8,
        capacity: c_long,
        encoding: u32,
    ) -> u8;
    fn CFRelease(value: *const c_void);
}

struct OwnedCF(*const c_void);
impl Drop for OwnedCF {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CFRelease(self.0) };
        }
    }
}

fn parse_where_froms(bytes: &[u8]) -> Vec<String> {
    let Ok(length) = c_long::try_from(bytes.len()) else {
        return Vec::new();
    };
    // SAFETY: bytes remains alive while CoreFoundation copies it into CFData.
    let data = OwnedCF(unsafe { CFDataCreate(std::ptr::null(), bytes.as_ptr(), length) });
    if data.0.is_null() {
        return Vec::new();
    }
    // SAFETY: valid CFData; null optional out-pointers. The returned object is owned.
    let list = OwnedCF(unsafe {
        CFPropertyListCreateWithData(
            std::ptr::null(),
            data.0,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    });
    if list.0.is_null() || unsafe { CFGetTypeID(list.0) } != unsafe { CFArrayGetTypeID() } {
        return Vec::new();
    }
    let count = unsafe { CFArrayGetCount(list.0.cast()) };
    if !(0..=MAX_URLS as c_long).contains(&count) {
        return Vec::new();
    }
    let mut result = Vec::new();
    for index in 0..count {
        // SAFETY: index is below the checked array count; returned element is borrowed.
        let value = unsafe { CFArrayGetValueAtIndex(list.0.cast(), index) };
        if value.is_null() || unsafe { CFGetTypeID(value) } != unsafe { CFStringGetTypeID() } {
            continue;
        }
        let mut buffer = [0i8; MAX_URL_BYTES + 1];
        // SAFETY: buffer is writable; CFStringGetCString NUL-terminates on success.
        if unsafe { CFStringGetCString(value, buffer.as_mut_ptr(), buffer.len() as c_long, UTF8) }
            == 0
        {
            continue;
        }
        let text = unsafe { CStr::from_ptr(buffer.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        if (text.starts_with("https://") || text.starts_with("http://"))
            && !text.chars().any(char::is_control)
        {
            result.push(text);
        }
    }
    result
}
