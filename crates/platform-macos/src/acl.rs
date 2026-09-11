// SPDX-License-Identifier: MPL-2.0

use std::fs::File;
use std::io;

/// Inspects the descriptor's macOS extended ACL without changing permissions.
///
/// Any entry (including deny-only or inherited entries) returns `true`. Missing
/// support, retrieval/validation failures, and cleanup failures are errors, never
/// evidence that mode bits alone establish privacy. This is an observation, not
/// a lock against later ACL changes; callers must recheck at their use boundary.
pub fn has_extended_acl(file: &File) -> io::Result<bool> {
    #[cfg(target_os = "macos")]
    {
        with_policy(|| native::query(file))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = file;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "macOS extended ACL inspection is unavailable",
        ))
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn snapshot(file: &File) -> io::Result<Option<Vec<u8>>> {
    with_policy(|| native::snapshot(file))
}

/// TEST recovery privacy predicate, not the journal's stricter no-ACL policy.
///
/// Apple chmod(1), "ACL MANIPULATION OPTIONS", defines entries as granting or
/// denying permissions; <sys/acl.h> names the two extended tags. A deny entry
/// cannot grant additional access regardless of its qualifier or inheritance.
/// This does not prove recovery availability or prevent concurrent ACL changes;
/// the caller still binds the exact ACL snapshot and checks native prerequisites.
#[cfg(all(test, target_os = "macos"))]
pub(crate) fn recovery_acl_is_non_granting(file: &File) -> io::Result<bool> {
    with_policy(|| native::recovery_acl_is_non_granting(file))
}

#[cfg(target_os = "macos")]
fn with_policy<T>(action: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    let policy = crate::ReadOnlyPolicy::enter()?;
    let result = action();
    match (result, policy.restore()) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(first), Err(second)) => Err(io::Error::other(format!(
            "{first}; restoring thread policy failed: {second}"
        ))),
    }
}

#[cfg(target_os = "macos")]
mod native {
    use super::*;
    use std::ffi::{c_int, c_void};
    use std::mem::MaybeUninit;
    use std::os::fd::AsRawFd;
    use std::ptr::{self, NonNull};

    const ACL_TYPE_EXTENDED: c_int = 0x100;
    const ACL_FIRST_ENTRY: c_int = 0;

    #[link(name = "System")]
    unsafe extern "C" {
        fn acl_get_fd_np(fd: c_int, acl_type: c_int) -> *mut c_void;
        fn acl_valid(acl: *mut c_void) -> c_int;
        fn acl_get_entry(acl: *mut c_void, entry_id: c_int, entry: *mut *mut c_void) -> c_int;
        #[cfg(test)]
        fn acl_get_tag_type(entry: *mut c_void, tag: *mut c_int) -> c_int;
        fn acl_free(acl: *mut c_void) -> c_int;
        fn acl_size(acl: *mut c_void) -> isize;
        fn acl_copy_ext(buffer: *mut c_void, acl: *mut c_void, size: isize) -> isize;
        fn filesec_init() -> *mut c_void;
        fn filesec_free(security: *mut c_void);
        fn filesec_query_property(
            security: *mut c_void,
            property: c_int,
            present: *mut c_int,
        ) -> c_int;
        #[cfg_attr(target_arch = "x86_64", link_name = "fstatx_np$INODE64")]
        fn fstatx_np(fd: c_int, stat: *mut libc::stat, security: *mut c_void) -> c_int;
    }

    pub(super) fn query(file: &File) -> io::Result<bool> {
        with_acl(file, false, entries)
    }

    #[cfg(test)]
    pub(super) fn recovery_acl_is_non_granting(file: &File) -> io::Result<bool> {
        with_acl(file, true, |acl| {
            // entries validates the owned ACL before interpreting Darwin's
            // EINVAL end marker. FIRST_ENTRY below restarts that same ACL.
            entries(acl)?;
            let mut has_allow = false;
            let mut cursor = ACL_FIRST_ENTRY;
            // Darwin <sys/acl.h>: ACL_MAX_ENTRIES=128, ACL_NEXT_ENTRY=-1.
            // One extra query establishes the end of a maximum-sized ACL.
            for count in 0..=128 {
                let mut entry = ptr::null_mut();
                // SAFETY: Live validated ACL, documented cursor and writable
                // initialized entry output; the pointer stays within this owner.
                let status = unsafe { acl_get_entry(acl.as_ptr(), cursor, &mut entry) };
                if status == -1 {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() == Some(libc::EINVAL) && entry.is_null() {
                        return Ok(!has_allow);
                    }
                    return Err(error);
                }
                if status != 0 || entry.is_null() {
                    return Err(io::Error::other("inconsistent native ACL entry result"));
                }
                if count == 128 {
                    return Err(io::Error::other(
                        "native ACL exceeds the entry inspection bound",
                    ));
                }
                let mut tag = 0;
                // SAFETY: Live entry returned by acl_get_entry and an initialized
                // integer out-parameter, as documented by acl_get_tag_type(3).
                if unsafe { acl_get_tag_type(entry, &mut tag) } != 0 {
                    return Err(io::Error::last_os_error());
                }
                has_allow |= tag_grants_access(tag)?;
                cursor = -1;
            }
            Err(io::Error::other("native ACL has no bounded end marker"))
        })
    }

    #[cfg(test)]
    fn tag_grants_access(tag: c_int) -> io::Result<bool> {
        match tag {
            1 => Ok(true),  // ACL_EXTENDED_ALLOW
            2 => Ok(false), // ACL_EXTENDED_DENY
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown native ACL entry tag; recovery privacy is not established",
            )),
        }
    }

    pub(super) fn snapshot(file: &File) -> io::Result<Option<Vec<u8>>> {
        with_acl(file, None, |acl| {
            entries(acl)?;
            // SAFETY: Valid, owned, unchanging ACL. acl_size reports the complete
            // public external representation size, not a private struct layout.
            let size = unsafe { acl_size(acl.as_ptr()) };
            if size == -1 {
                return Err(io::Error::last_os_error());
            }
            if !(1..=16 * 1024).contains(&size) {
                return Err(io::Error::other("native ACL exceeds bounded evidence size"));
            }
            #[repr(align(8))]
            struct ExternalBuffer([u8; 16 * 1024]);
            let mut buffer = ExternalBuffer([0u8; 16 * 1024]);
            // SAFETY: Valid ACL, aligned writable buffer covering the exact size.
            // The public big-endian format includes ACL flags and ordered ACEs.
            let written = unsafe { acl_copy_ext(buffer.0.as_mut_ptr().cast(), acl.as_ptr(), size) };
            if written == -1 {
                return Err(io::Error::last_os_error());
            }
            if written != size {
                return Err(io::Error::other("incomplete native ACL evidence"));
            }
            Ok(Some(buffer.0[..size as usize].to_vec()))
        })
    }

    fn with_acl<T>(
        file: &File,
        absent: T,
        inspect: impl FnOnce(NonNull<c_void>) -> io::Result<T>,
    ) -> io::Result<T> {
        // SAFETY: Live borrowed descriptor and Darwin's documented extended ACL
        // type. The allocated output is owned here, never stored on the file.
        let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
        let Some(acl) = NonNull::new(acl) else {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ENOENT) {
                return Err(error);
            }
            // Darwin also returns NULL/ENOENT when FILESEC_ACL is absent.
            // Do not infer absence from errno alone: obtain a successful
            // descriptor security snapshot and explicitly query the property.
            return confirm_absence(file)
                .map(|_| absent)
                .map_err(|confirmation| {
                    io::Error::other(format!(
                        "ACL retrieval: {error}; confirming absence failed: {confirmation}"
                    ))
                });
        };
        let result = inspect(acl);
        // SAFETY: This is the sole release of acl_get_fd_np's owned allocation;
        // entries borrows it synchronously and retains no entry pointers.
        let freed = unsafe { acl_free(acl.as_ptr()) };
        if freed != 0 {
            let error = io::Error::last_os_error();
            return match result {
                Ok(_) => Err(error),
                Err(first) => Err(io::Error::other(format!(
                    "{first}; freeing native ACL failed: {error}"
                ))),
            };
        }
        result
    }

    fn confirm_absence(file: &File) -> io::Result<bool> {
        // SAFETY: Allocate an empty owned filesec container.
        let security = unsafe { filesec_init() };
        let security = NonNull::new(security).ok_or_else(io::Error::last_os_error)?;
        let result = (|| {
            let mut stat = MaybeUninit::<libc::stat>::uninit();
            // SAFETY: Live descriptor, writable Darwin inode64 stat storage and
            // owned filesec container; successful fstatx initializes both.
            if unsafe { fstatx_np(file.as_raw_fd(), stat.as_mut_ptr(), security.as_ptr()) } != 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: Successful fstatx initialized the complete stat structure.
            let stat = unsafe { stat.assume_init() };
            if !matches!(stat.st_mode & libc::S_IFMT, libc::S_IFREG | libc::S_IFDIR) {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "ACL absence requires a regular file or directory descriptor",
                ));
            }
            let mut present = -1;
            // SAFETY: Successful descriptor security snapshot, FILESEC_ACL=5,
            // and initialized writable output. This does not retrieve contents.
            if unsafe { filesec_query_property(security.as_ptr(), 5, &mut present) } != 0 {
                return Err(io::Error::last_os_error());
            }
            match present {
                0 => Ok(false),
                _ => Err(io::Error::other(
                    "ACL appeared or security-property result is unknown",
                )),
            }
        })();
        // SAFETY: Release the sole-owned filesec container on every result path.
        // Darwin filesec_free returns void, unlike acl_free.
        unsafe { filesec_free(security.as_ptr()) };
        result
    }

    fn entries(acl: NonNull<c_void>) -> io::Result<bool> {
        // SAFETY: Borrowed live ACL allocated by acl_get_fd_np. Validation is
        // required before interpreting Darwin's ambiguous EINVAL end marker.
        if unsafe { acl_valid(acl.as_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut entry = ptr::null_mut();
        // SAFETY: Valid ACL, known FIRST_ENTRY constant, initialized writable
        // output pointer. No entry is accessed or retained after this query.
        let result = unsafe { acl_get_entry(acl.as_ptr(), ACL_FIRST_ENTRY, &mut entry) };
        match result {
            0 if !entry.is_null() => Ok(true),
            -1 => {
                let error = io::Error::last_os_error();
                // Darwin acl_get_entry returns 0 for an entry and -1/EINVAL
                // beyond the entry count (unlike Linux's 1/0 convention).
                // With this validated owned ACL and FIRST_ENTRY, EINVAL and an
                // untouched null output mean there are no entries.
                if error.raw_os_error() == Some(libc::EINVAL) && entry.is_null() {
                    Ok(false)
                } else {
                    Err(error)
                }
            }
            _ => Err(io::Error::other(
                "inconsistent native ACL entry result; privacy is unknown",
            )),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn recovery_tag_policy_rejects_unknown_tags() {
            assert!(tag_grants_access(1).unwrap());
            assert!(!tag_grants_access(2).unwrap());
            for tag in [0, -1, 3, i32::MAX] {
                assert_eq!(
                    tag_grants_access(tag).unwrap_err().kind(),
                    io::ErrorKind::InvalidData,
                );
            }
        }
    }
}
