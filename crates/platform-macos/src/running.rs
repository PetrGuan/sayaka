// SPDX-License-Identifier: MPL-2.0

//! Running-application observation by exact bundle identifier (T10
//! saved-state contract): the official, unprivileged AppKit query.
//! An empty answer means no application runs under the identifier;
//! a query failure is an error, never an empty answer.

use std::io;

#[cfg(target_os = "macos")]
mod native {
    use objc2::msg_send;
    use objc2::runtime::AnyClass;
    use objc2::runtime::AnyObject;
    use std::ffi::CString;
    use std::io;

    #[link(name = "AppKit", kind = "framework")]
    unsafe extern "C" {}

    /// PIDs of applications currently running under `bundle_id`, via
    /// +[NSRunningApplication runningApplicationsWithBundleIdentifier:].
    /// The documented empty-array answer maps to an empty Vec; anything
    /// unexpected (missing class, nil string, nil array) is an error so a
    /// broken query can never masquerade as "not running".
    pub fn running_pids(bundle_id: &str) -> io::Result<Vec<u32>> {
        objc2::rc::autoreleasepool(|_| {
            let class = AnyClass::get(c"NSRunningApplication")
                .ok_or_else(|| io::Error::other("NSRunningApplication unavailable"))?;
            let string_class = AnyClass::get(c"NSString")
                .ok_or_else(|| io::Error::other("NSString unavailable"))?;
            let identifier = CString::new(bundle_id).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "bundle identifier contains NUL",
                )
            })?;
            // SAFETY: documented NSString factory with a valid NUL-terminated string.
            let ns_string: *mut AnyObject =
                unsafe { msg_send![string_class, stringWithUTF8String: identifier.as_ptr()] };
            if ns_string.is_null() {
                return Err(io::Error::other("NSString creation failed"));
            }
            // SAFETY: documented class query returning an NSArray (possibly empty).
            let applications: *mut AnyObject =
                unsafe { msg_send![class, runningApplicationsWithBundleIdentifier: ns_string] };
            if applications.is_null() {
                return Err(io::Error::other(
                    "runningApplicationsWithBundleIdentifier returned no object",
                ));
            }
            // SAFETY: NSArray responds to count.
            let count: usize = unsafe { msg_send![applications, count] };
            let mut pids = Vec::with_capacity(count.min(1024));
            for index in 0..count.min(1024) {
                // SAFETY: NSArray objectAtIndex: within the observed bounds.
                let application: *mut AnyObject =
                    unsafe { msg_send![applications, objectAtIndex: index] };
                if application.is_null() {
                    continue;
                }
                // SAFETY: NSRunningApplication responds to processIdentifier.
                let pid: i32 = unsafe { msg_send![application, processIdentifier] };
                if pid > 0 {
                    pids.push(pid as u32);
                }
            }
            pids.sort_unstable();
            pids.dedup();
            Ok(pids)
        })
    }
}

/// Running PIDs for one exact bundle identifier (empty = not running).
#[cfg(target_os = "macos")]
pub fn running_pids_with_bundle_identifier(bundle_id: &str) -> io::Result<Vec<u32>> {
    native::running_pids(bundle_id)
}

#[cfg(not(target_os = "macos"))]
pub fn running_pids_with_bundle_identifier(_bundle_id: &str) -> io::Result<Vec<u32>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "running application query is macOS-only",
    ))
}

/// The fixed per-user `Saved Application State` location, resolved from the
/// native account record (getpwuid), never from `$HOME` text.
#[cfg(unix)]
pub fn saved_state_location() -> io::Result<std::path::PathBuf> {
    use std::ffi::{CStr, OsStr};
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;
    // SAFETY: getpwuid's returned pointer is borrowed static storage, read
    // only here, and checked for null before use.
    // SAFETY: getuid needs no arguments and cannot fail.
    let uid = unsafe { libc::getuid() };
    let pw = unsafe { libc::getpwuid(uid) };
    if pw.is_null() {
        return Err(io::Error::other("native account record unavailable"));
    }
    // SAFETY: pw is non-null; pw_dir is checked before reading.
    let dir = unsafe { (*pw).pw_dir };
    if dir.is_null() {
        return Err(io::Error::other("native home directory unavailable"));
    }
    // SAFETY: dir is a valid NUL-terminated path string per getpwuid.
    let bytes = unsafe { CStr::from_ptr(dir) }.to_bytes();
    Ok(PathBuf::from(OsStr::from_bytes(bytes))
        .join("Library")
        .join("Saved Application State"))
}

#[cfg(not(unix))]
pub fn saved_state_location() -> io::Result<std::path::PathBuf> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "the saved-state location currently requires a unix account record",
    ))
}
