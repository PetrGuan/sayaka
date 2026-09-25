// SPDX-License-Identifier: MPL-2.0

//! Audited macOS I/O policy, metadata, and revalidated Foundation Trash boundary.
//! Path-based Trash retains a last-check/path-replacement race; it is not atomic.

#![deny(unsafe_op_in_unsafe_fn)]

use std::io;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::rc::Rc;

#[cfg(target_os = "macos")]
mod volume;
#[cfg(target_os = "macos")]
pub use volume::{VolumeDiagnostics, volume_info, volume_info_with_diagnostics};

mod trash;
pub use trash::{
    BundleTrashCandidate, CacheTrashCandidate, NativeAdmissionWitness, NativeCaptureFailure,
    NativeFileInfo, NativeLastGuard, NativeRecoveryEvidence, NativeRuleBindingWitness,
    NativeTargetMarker, NativeTrashOutcome, NativeWitnessInfo, PurgeTrashCandidate, TrashCandidate,
    full_sync,
};

mod acl;
pub use acl::has_extended_acl;

pub mod status;

#[cfg(target_os = "macos")]
mod installer_provenance;
#[cfg(target_os = "macos")]
pub use installer_provenance::{InstallerOrigin, MetadataState, read_installer_origin};

/// Host-wide mach-absolute nanoseconds, in Darwin's CLOCK_UPTIME_RAW domain.
#[cfg(target_os = "macos")]
pub fn diagnostic_monotonic_ns() -> io::Result<u64> {
    let mut scale = MachTimebaseInfo { numer: 0, denom: 0 };
    // SAFETY: The initialized writable structure is valid for this synchronous call.
    let result = unsafe { mach_timebase_info(&mut scale) };
    if result != 0 || scale.denom == 0 {
        return Err(io::Error::other("monotonic timebase unavailable"));
    }
    // SAFETY: This read-only clock takes no arguments or pointers.
    let ticks = unsafe { mach_absolute_time() };
    u64::try_from(u128::from(ticks) * u128::from(scale.numer) / u128::from(scale.denom))
        .map_err(|_| io::Error::other("monotonic time conversion overflow"))
}

/// Returns the effective user's passwd-database home directory.
#[cfg(target_os = "macos")]
pub fn effective_account_home() -> io::Result<PathBuf> {
    use std::ffi::CStr;
    use std::mem::MaybeUninit;

    const FALLBACK_BUFFER_LEN: usize = 1024;
    const MAX_BUFFER_LEN: usize = 1024 * 1024;

    // SAFETY: `geteuid` takes no arguments and returns the effective uid.
    let uid = unsafe { libc::geteuid() };
    // SAFETY: `sysconf` takes a constant selector and has no memory safety preconditions.
    let suggested = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut buffer_len = if suggested > 0 {
        usize::try_from(suggested)
            .unwrap_or(MAX_BUFFER_LEN)
            .min(MAX_BUFFER_LEN)
    } else {
        FALLBACK_BUFFER_LEN
    };
    loop {
        let mut pwd = MaybeUninit::<libc::passwd>::uninit();
        let mut result = std::ptr::null_mut();
        let mut buffer = vec![0 as libc::c_char; buffer_len];
        // SAFETY: `pwd` points to writable storage, `buffer` is valid for `buffer.len()` bytes,
        // and `result` is a valid out-pointer for this synchronous call.
        let status = unsafe {
            libc::getpwuid_r(
                uid,
                pwd.as_mut_ptr(),
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::EINTR {
            continue;
        }
        if status == libc::ERANGE && buffer_len < MAX_BUFFER_LEN {
            buffer_len = buffer_len.saturating_mul(2).min(MAX_BUFFER_LEN);
            continue;
        }
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status));
        }
        if result.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("passwd database has no entry for effective uid {uid}"),
            ));
        }
        // SAFETY: `getpwuid_r` succeeded and returned a non-null result pointing at `pwd`.
        let pwd = unsafe { pwd.assume_init() };
        if pwd.pw_dir.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "passwd database returned an empty account home",
            ));
        }
        // SAFETY: POSIX passwd entries expose `pw_dir` as a null-terminated C string.
        let home = unsafe { CStr::from_ptr(pwd.pw_dir) }
            .to_str()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if home.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "passwd database returned an empty account home",
            ));
        }
        return Ok(PathBuf::from(home));
    }
}

#[cfg(not(target_os = "macos"))]
pub fn effective_account_home() -> io::Result<PathBuf> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "passwd account home lookup is only available on macOS",
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VolumeInfo {
    pub local: bool,
    pub internal: bool,
    pub removable: bool,
    pub ejectable: bool,
}

#[cfg(not(target_os = "macos"))]
pub fn volume_info(_: &std::path::Path) -> io::Result<VolumeInfo> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "macOS volume metadata is unavailable",
    ))
}

/// Disables cloud materialization on this thread.
/// The guard cannot move between threads. Call `restore` to observe errors.
///
/// ```compile_fail
/// use sayaka_platform_macos::ReadOnlyPolicy;
/// fn requires_send<T: Send>() {}
/// requires_send::<ReadOnlyPolicy>();
/// ```
#[must_use]
pub struct ReadOnlyPolicy {
    previous: i32,
    active: bool,
    same_thread: PhantomData<Rc<()>>,
}

impl ReadOnlyPolicy {
    pub fn enter() -> io::Result<Self> {
        let previous = get_policy()?;
        set_policy(1)?;
        Ok(Self {
            previous,
            active: true,
            same_thread: PhantomData,
        })
    }

    pub fn restore(mut self) -> io::Result<()> {
        self.restore_inner()
    }

    fn restore_inner(&mut self) -> io::Result<()> {
        if !self.active {
            return Ok(());
        }
        set_policy(self.previous)?;
        self.active = false;
        Ok(())
    }
}

impl Drop for ReadOnlyPolicy {
    fn drop(&mut self) {
        if let Err(error) = self.restore_inner() {
            eprintln!("Sayaka could not restore thread-local I/O policy: {error}");
        }
    }
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct MachTimebaseInfo {
    numer: u32,
    denom: u32,
}

#[cfg(target_os = "macos")]
#[link(name = "System")]
unsafe extern "C" {
    fn mach_timebase_info(info: *mut MachTimebaseInfo) -> std::ffi::c_int;
    fn mach_absolute_time() -> u64;
    fn getiopolicy_np(policy: std::ffi::c_int, scope: std::ffi::c_int) -> std::ffi::c_int;
    fn setiopolicy_np(
        policy: std::ffi::c_int,
        scope: std::ffi::c_int,
        value: std::ffi::c_int,
    ) -> std::ffi::c_int;
}

#[cfg(target_os = "macos")]
fn get_policy() -> io::Result<i32> {
    // SAFETY: Integer-only OS API, using a public policy and current-thread scope.
    let result = unsafe { getiopolicy_np(3, 1) };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

#[cfg(target_os = "macos")]
fn set_policy(value: i32) -> io::Result<()> {
    // SAFETY: Integer-only OS API. Values are OFF or previously returned policies;
    // scope is the current thread, never process-wide or system-wide.
    let result = unsafe { setiopolicy_np(3, 1, value) };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "macos"))]
fn get_policy() -> io::Result<i32> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "macOS I/O policy is unavailable",
    ))
}

#[cfg(not(target_os = "macos"))]
fn set_policy(_: i32) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "macOS I/O policy is unavailable",
    ))
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_clock_is_monotonic() {
        let first = diagnostic_monotonic_ns().unwrap();
        let second = diagnostic_monotonic_ns().unwrap();
        assert!(first > 0);
        assert!(second >= first);
    }

    #[test]
    fn native_thread_policy_is_set_and_explicitly_restored() {
        let before = get_policy().unwrap();
        let guard = ReadOnlyPolicy::enter().unwrap();
        assert_eq!(get_policy().unwrap(), 1);
        guard.restore().unwrap();
        assert_eq!(get_policy().unwrap(), before);
    }

    #[test]
    fn nested_guards_restore_their_own_prior_state() {
        let before = get_policy().unwrap();
        let outer = ReadOnlyPolicy::enter().unwrap();
        ReadOnlyPolicy::enter().unwrap().restore().unwrap();
        assert_eq!(get_policy().unwrap(), 1);
        outer.restore().unwrap();
        assert_eq!(get_policy().unwrap(), before);
    }
}
