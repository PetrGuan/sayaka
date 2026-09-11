// SPDX-License-Identifier: MPL-2.0

//! Audited macOS I/O policy, metadata, and revalidated Foundation Trash boundary.
//! Path-based Trash retains a last-check/path-replacement race; it is not atomic.

#![deny(unsafe_op_in_unsafe_fn)]

use std::io;
use std::marker::PhantomData;
use std::rc::Rc;

#[cfg(target_os = "macos")]
mod volume;
#[cfg(target_os = "macos")]
pub use volume::volume_info;

mod trash;
pub use trash::{
    NativeFileInfo, NativeRecoveryEvidence, NativeTrashOutcome, TrashCandidate, full_sync,
};

mod acl;
pub use acl::has_extended_acl;

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
#[link(name = "System")]
unsafe extern "C" {
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
