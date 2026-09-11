// SPDX-License-Identifier: MPL-2.0

use super::{ReadOnlyPolicy, VolumeInfo};
use std::ffi::{c_long, c_ulong, c_void};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{self, NonNull};

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFURLCreateFromFileSystemRepresentation(
        allocator: *const c_void,
        bytes: *const u8,
        length: c_long,
        is_directory: u8,
    ) -> *const c_void;
    fn CFURLCopyResourcePropertyForKey(
        url: *const c_void,
        key: *const c_void,
        value: *mut *const c_void,
        error: *mut *const c_void,
    ) -> u8;
    fn CFRelease(value: *const c_void);
    fn CFGetTypeID(value: *const c_void) -> c_ulong;
    fn CFBooleanGetTypeID() -> c_ulong;
    fn CFBooleanGetValue(value: *const c_void) -> u8;
    static kCFURLVolumeIsLocalKey: *const c_void;
    static kCFURLVolumeIsInternalKey: *const c_void;
    static kCFURLVolumeIsRemovableKey: *const c_void;
    static kCFURLVolumeIsEjectableKey: *const c_void;
}

struct OwnedCf(NonNull<c_void>);
impl OwnedCf {
    fn pointer(&self) -> *const c_void {
        self.0.as_ptr().cast_const()
    }
}

impl Drop for OwnedCf {
    fn drop(&mut self) {
        // SAFETY: This private owner is constructed only for non-null +1
        // Create/Copy outputs. It is not Clone; borrowed property keys stay unowned.
        unsafe { CFRelease(self.pointer()) };
    }
}

enum Flag {
    Local,
    Internal,
    Removable,
    Ejectable,
}

fn boolean(url: &OwnedCf, flag: Flag) -> io::Result<bool> {
    // SAFETY: These are immutable, framework-owned exported CFString references.
    let (key, label) = unsafe {
        match flag {
            Flag::Local => (kCFURLVolumeIsLocalKey, "local"),
            Flag::Internal => (kCFURLVolumeIsInternalKey, "internal"),
            Flag::Removable => (kCFURLVolumeIsRemovableKey, "removable"),
            Flag::Ejectable => (kCFURLVolumeIsEjectableKey, "ejectable"),
        }
    };
    let mut value = ptr::null();
    let mut error = ptr::null();
    // SAFETY: URL and key are live CF references. Both writable out-pointers
    // are initialized, aligned, and valid for the synchronous call.
    let success =
        unsafe { CFURLCopyResourcePropertyForKey(url.pointer(), key, &mut value, &mut error) };
    let value = NonNull::new(value.cast_mut()).map(OwnedCf);
    let _error = NonNull::new(error.cast_mut()).map(OwnedCf);
    if success == 0 {
        return Err(io::Error::other(format!(
            "could not read volume {label} property"
        )));
    }
    let value =
        value.ok_or_else(|| io::Error::other(format!("volume {label} property is unavailable")))?;
    // SAFETY: A non-null Copy output is a live CF object. Runtime type checking
    // precedes Boolean access, so unexpected property types are not reinterpreted.
    if unsafe { CFGetTypeID(value.pointer()) != CFBooleanGetTypeID() } {
        return Err(io::Error::other(format!(
            "volume {label} property is not boolean"
        )));
    }
    // SAFETY: The owned value was checked to be a CFBoolean above.
    Ok(unsafe { CFBooleanGetValue(value.pointer()) } != 0)
}

/// Reads all four native flags without collapsing unavailable properties to false.
pub fn volume_info(path: &Path) -> io::Result<VolumeInfo> {
    let policy = ReadOnlyPolicy::enter()?;
    // CFURL resource queries may create internal autoreleased Objective-C
    // temporaries. Only owned Rust flags/errors escape this pool.
    let result = objc2::rc::autoreleasepool(|_| read_volume_info(path));
    let restored = policy.restore();
    match (result, restored) {
        (Ok(info), Ok(())) => Ok(info),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(first), Err(second)) => Err(io::Error::other(format!(
            "{first}; restoring thread policy failed: {second}"
        ))),
    }
}

fn read_volume_info(path: &Path) -> io::Result<VolumeInfo> {
    let bytes = path.as_os_str().as_bytes();
    if !path.is_absolute() || bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid volume path",
        ));
    }
    let length = c_long::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "volume path is too long"))?;
    // SAFETY: The byte slice remains valid during this synchronous copying
    // constructor; null selects the default allocator. No UTF-8 conversion occurs.
    let url =
        unsafe { CFURLCreateFromFileSystemRepresentation(ptr::null(), bytes.as_ptr(), length, 1) };
    let url = OwnedCf(
        NonNull::new(url.cast_mut())
            .ok_or_else(|| io::Error::other("could not create native volume URL"))?,
    );
    Ok(VolumeInfo {
        local: boolean(&url, Flag::Local)?,
        internal: boolean(&url, Flag::Internal)?,
        removable: boolean(&url, Flag::Removable)?,
        ejectable: boolean(&url, Flag::Ejectable)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_volume_properties_are_present_and_typed() {
        let info = volume_info(Path::new("/")).unwrap();
        assert!(info.local);
    }

    #[test]
    fn invalid_volume_paths_fail_without_a_false_classification() {
        for path in ["relative", "/invalid\0path"] {
            assert_eq!(
                volume_info(Path::new(path)).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }
}
