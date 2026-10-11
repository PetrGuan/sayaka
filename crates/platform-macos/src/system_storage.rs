// SPDX-License-Identifier: MPL-2.0
//! Closed, read-only system storage boundary. No caller-supplied commands.
use crate::devtools::{run_bounded, verify_code_requirement};
use std::ffi::{OsString, c_long, c_void};
use std::path::Path;
use std::time::Duration;

#[derive(Clone, Copy)]
pub enum Query {
    Snapshots,
    Status,
    Destinations,
}

pub fn query(query: Query) -> Result<Vec<u8>, &'static str> {
    let path = Path::new("/usr/bin/tmutil");
    verify_code_requirement(path, "anchor apple and identifier \"com.apple.tmutil\"")
        .map_err(|_| "tool_trust_unavailable")?;
    let args = match query {
        Query::Snapshots => vec!["listlocalsnapshots".into(), "/".into()],
        Query::Status => vec!["status".into()],
        Query::Destinations => vec!["destinationinfo".into()],
    };
    let env = [
        (OsString::from("LANG"), OsString::from("C")),
        (OsString::from("LC_ALL"), OsString::from("C")),
    ];
    let output = run_bounded(
        path,
        &args,
        &env,
        Duration::from_secs(5),
        256 * 1024,
        16 * 1024,
    )
    .map_err(|error| match error {
        crate::devtools::ToolError::Timeout => "command_timeout",
        crate::devtools::ToolError::OutputCap => "output_limit",
        _ => "command_unavailable",
    })?;
    if !output.success {
        return Err("command_failed");
    }
    if !output.stderr.is_empty() {
        return Err("command_diagnostic");
    }
    Ok(output.stdout)
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFURLCreateFromFileSystemRepresentation(
        a: *const c_void,
        b: *const u8,
        n: c_long,
        d: u8,
    ) -> *const c_void;
    fn CFArrayCreate(
        a: *const c_void,
        values: *const *const c_void,
        count: c_long,
        callbacks: *const c_void,
    ) -> *const c_void;
    fn CFURLCopyResourcePropertiesForKeys(
        url: *const c_void,
        keys: *const c_void,
        error: *mut *const c_void,
    ) -> *const c_void;
    fn CFDictionaryGetValue(dictionary: *const c_void, key: *const c_void) -> *const c_void;
    fn CFRelease(v: *const c_void);
    fn CFGetTypeID(v: *const c_void) -> usize;
    fn CFNumberGetTypeID() -> usize;
    fn CFNumberGetValue(v: *const c_void, t: c_long, out: *mut c_void) -> u8;
    static kCFURLVolumeAvailableCapacityKey: *const c_void;
}
// Important-usage capacity is a Foundation NSURL resource key, bridged to CFURL.
#[link(name = "Foundation", kind = "framework")]
unsafe extern "C" {
    static NSURLVolumeAvailableCapacityForImportantUsageKey: *const c_void;
}
struct Owned(*const c_void);
impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CFRelease(self.0) };
        }
    }
}
fn number(dictionary: &Owned, key: *const c_void) -> Result<u64, &'static str> {
    // SAFETY: dictionary is the live Copy result; returned value is borrowed.
    let value = unsafe { CFDictionaryGetValue(dictionary.0, key) };
    if value.is_null() {
        return Err("capacity_unavailable");
    }
    let mut n: i64 = -1;
    // SAFETY: type checked before numeric access; 4 is kCFNumberSInt64Type.
    if unsafe {
        CFGetTypeID(value) != CFNumberGetTypeID()
            || CFNumberGetValue(value, 4, (&mut n as *mut i64).cast()) == 0
    } {
        return Err("capacity_type");
    }
    u64::try_from(n).map_err(|_| "capacity_negative")
}
pub fn capacity() -> Result<(u64, u64), &'static str> {
    let path = Path::new("/System/Volumes/Data");
    let volume = crate::volume_info(path).map_err(|_| "volume_unavailable")?;
    if !volume.local {
        return Err("volume_not_local");
    }
    let bytes = b"/System/Volumes/Data";
    // SAFETY: byte slice lives through creation; returned +1 object is released.
    let url = Owned(unsafe {
        CFURLCreateFromFileSystemRepresentation(
            std::ptr::null(),
            bytes.as_ptr(),
            bytes.len() as c_long,
            1,
        )
    });
    if url.0.is_null() {
        return Err("volume_unavailable");
    }
    // SAFETY: keys are immutable framework objects. The array borrows them
    // with null callbacks; both keys outlive the array. Copy returns +1 ownership.
    let keys = unsafe {
        [
            kCFURLVolumeAvailableCapacityKey,
            NSURLVolumeAvailableCapacityForImportantUsageKey,
        ]
    };
    let array =
        Owned(unsafe { CFArrayCreate(std::ptr::null(), keys.as_ptr(), 2, std::ptr::null()) });
    if array.0.is_null() {
        return Err("capacity_unavailable");
    }
    let mut error = std::ptr::null();
    let dictionary =
        Owned(unsafe { CFURLCopyResourcePropertiesForKeys(url.0, array.0, &mut error) });
    let error = Owned(error);
    if dictionary.0.is_null() || !error.0.is_null() {
        return Err("capacity_unavailable");
    }
    Ok((number(&dictionary, keys[0])?, number(&dictionary, keys[1])?))
}
