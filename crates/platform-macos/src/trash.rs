// SPDX-License-Identifier: MPL-2.0

use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Diagnostic context only; the original error retains its kind and OS code.
#[derive(Debug)]
pub struct NativeCaptureFailure {
    pub phase: &'static str,
    pub operation: &'static str,
    pub error: io::Error,
    pub restoration_error: Option<io::Error>,
}

impl NativeCaptureFailure {
    /// Preserve the pre-existing capture API's combined-error behavior.
    fn into_legacy_error(self) -> io::Error {
        match self.restoration_error {
            Some(restore) => io::Error::other(format!(
                "{}; restoring thread policy failed: {restore}",
                self.error
            )),
            None => self.error,
        }
    }
}

impl std::fmt::Display for NativeCaptureFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.error)?;
        if let Some(restore) = &self.restoration_error {
            write!(formatter, "; restoring thread policy failed: {restore}")?;
        }
        Ok(())
    }
}

impl std::error::Error for NativeCaptureFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeFileInfo {
    pub device: u64,
    pub inode: u64,
    pub logical_bytes: u64,
    pub modified_at: SystemTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeWitnessInfo {
    pub path: PathBuf,
    pub kind: &'static str,
    pub device: u64,
    pub inode: u64,
    pub logical_bytes: u64,
    pub modified_unix_seconds: i64,
    pub modified_nanoseconds: i64,
    pub changed_unix_seconds: i64,
    pub changed_nanoseconds: i64,
    pub created_unix_seconds: i64,
    pub created_nanoseconds: i64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub nlink: u64,
    pub flags: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeRuleBindingWitness {
    pub target: NativeWitnessInfo,
    pub source: NativeWitnessInfo,
    pub root: NativeWitnessInfo,
    pub target_ancestors: Vec<NativeWitnessInfo>,
    pub source_ancestors: Vec<NativeWitnessInfo>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeAdmissionWitness {
    pub target: NativeWitnessInfo,
    pub root: NativeWitnessInfo,
    pub target_ancestors: Vec<NativeWitnessInfo>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeTargetMarker {
    Prefix4([u8; 4]),
}

#[derive(Debug)]
pub enum NativeTrashOutcome {
    Moved {
        destination: PathBuf,
    },
    Refused(String),
    Failed(String),
    Unknown {
        message: String,
        evidence: NativeRecoveryEvidence,
    },
}

#[derive(Debug, Clone)]
pub enum NativeLastGuard {
    Proceed,
    Cancelled,
    PolicyRefused(String),
}

/// Recovery observations, never authorization to restore, retry, or delete.
/// `returned_destination` is an UNVERIFIED Foundation pathname hint, not proof
/// of an approved object. Held-source observations describe the retained
/// descriptor at observation time and may differ from the approved snapshot.
#[derive(Debug, Clone)]
pub struct NativeRecoveryEvidence {
    pub approved: NativeFileInfo,
    pub returned_destination: Option<PathBuf>,
    pub held_source: Option<NativeFileInfo>,
    pub held_source_path: Option<PathBuf>,
    pub observation_errors: Vec<String>,
}

#[cfg(target_os = "macos")]
impl NativeRecoveryEvidence {
    fn record_error(&mut self, mut error: String) {
        if let Some((boundary, _)) = error.char_indices().nth(1024) {
            error.truncate(boundary);
            error.push_str(" [truncated]");
        }
        if self.observation_errors.len() < 8 {
            self.observation_errors.push(error);
        } else if let Some(last) = self.observation_errors.last_mut() {
            *last = "additional observation errors omitted at the eight-error bound".into();
        }
    }
}

/// Retained evidence for an explicitly selected file, not a race-free capability.
///
/// Descriptors prevent inode reuse while retained, but Foundation acts on a URL.
/// Another process can replace that path after the final check. Never replay an
/// interrupted call, retry an ambiguous outcome, or roll back an unverified URL.
/// Targets retain full file metadata. Ancestry/protections retain identity,
/// physical path, kind, owner/group, mode, flags, creation time and exact ACLs;
/// unrelated directory content timestamps, size and link counts are not approval
/// inputs. This permits sibling changes without refreshing the selected target.
pub struct TrashCandidate {
    #[cfg(target_os = "macos")]
    native: native::Candidate,
    #[cfg(not(target_os = "macos"))]
    unavailable: std::convert::Infallible,
}

impl TrashCandidate {
    /// Captures at most 64 ancestor/protection handles and paths of at most
    /// 4096 bytes. Requires ordinary user authority, a single-link regular file,
    /// and a local internal writable APFS volume. Links, dataless objects,
    /// unknown extended attributes, writable/untrusted ancestry, system roots,
    /// hidden paths, Library, native package boundaries, and recognized app/cloud
    /// roots are excluded. Unknown native package classification is an error.
    /// Supplied protections must resolve to existing inspectable objects.
    /// These exclusions do not establish whether an application has a file open.
    pub fn capture(scope: &Path, path: &Path, protected: &[PathBuf]) -> io::Result<Self> {
        Self::capture_diagnostic(scope, path, protected)
            .map_err(NativeCaptureFailure::into_legacy_error)
    }

    pub fn capture_diagnostic(
        scope: &Path,
        path: &Path,
        protected: &[PathBuf],
    ) -> Result<Self, NativeCaptureFailure> {
        #[cfg(target_os = "macos")]
        {
            native::Candidate::capture_diagnostic(scope, path, protected)
                .map(|native| Self { native })
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (scope, path, protected);
            Err(NativeCaptureFailure {
                phase: "platform",
                operation: "availability",
                error: unsupported(),
                restoration_error: None,
            })
        }
    }

    pub fn capture_with_source(
        scope: &Path,
        target: &Path,
        source: &Path,
        protected: &[PathBuf],
    ) -> io::Result<Self> {
        Self::capture_with_source_and_marker(scope, target, source, None, protected)
    }

    pub fn capture_with_source_and_marker(
        scope: &Path,
        target: &Path,
        source: &Path,
        marker: Option<NativeTargetMarker>,
        protected: &[PathBuf],
    ) -> io::Result<Self> {
        #[cfg(target_os = "macos")]
        {
            native::Candidate::capture_with_source_and_marker(
                scope, target, source, marker, protected,
            )
            .map(|native| Self { native })
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (scope, target, source, marker, protected);
            Err(unsupported())
        }
    }

    pub fn info(&self) -> &NativeFileInfo {
        #[cfg(target_os = "macos")]
        {
            &self.native.info
        }
        #[cfg(not(target_os = "macos"))]
        match self.unavailable {}
    }

    pub fn path(&self) -> &Path {
        #[cfg(target_os = "macos")]
        {
            &self.native.path
        }
        #[cfg(not(target_os = "macos"))]
        match self.unavailable {}
    }

    pub fn revalidate(&self) -> io::Result<()> {
        #[cfg(target_os = "macos")]
        {
            self.native.revalidate()
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(unsupported())
        }
    }

    pub fn rule_binding_witness(&self) -> Option<&NativeRuleBindingWitness> {
        #[cfg(target_os = "macos")]
        {
            self.native.rule_binding_witness()
        }
        #[cfg(not(target_os = "macos"))]
        {
            None
        }
    }

    /// Read-only metadata from the retained capture, not refreshed path lookups.
    pub fn admission_witness(&self) -> io::Result<NativeAdmissionWitness> {
        #[cfg(target_os = "macos")]
        {
            self.native.admission_witness()
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(unsupported())
        }
    }

    /// Matches overlap conservatively by spelling and by native identities.
    /// Existing aliases are resolved by no-follow filesystem lookup, including
    /// case/Unicode aliases understood by that volume. Missing unrelated paths
    /// do not match; links, inaccessible paths and unknown evidence are errors.
    /// Never refreshes the selected file or its retained ancestor identities.
    pub fn matches_exclusion(&self, exclusion: &Path) -> io::Result<bool> {
        #[cfg(target_os = "macos")]
        {
            self.native.matches_exclusion(exclusion)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = exclusion;
            Err(unsupported())
        }
    }

    /// The caller must durably record intent before entering this method.
    /// Cancellation is evaluated once after revalidation, immediately before the
    /// sole synchronous Foundation call; it cannot cancel an already-entered call.
    /// A candidate can be submitted only once, including refused/cancelled calls.
    pub fn move_to_trash(&self, cancelled: impl FnOnce() -> bool) -> NativeTrashOutcome {
        self.move_to_trash_with_last_guard(cancelled, || NativeLastGuard::Proceed)
    }

    /// Executes the final native call with an additional typed last guard.
    /// The guard runs after final revalidation and before Foundation.
    pub fn move_to_trash_with_last_guard(
        &self,
        cancelled: impl FnOnce() -> bool,
        last_guard: impl FnOnce() -> NativeLastGuard,
    ) -> NativeTrashOutcome {
        #[cfg(target_os = "macos")]
        {
            self.native
                .move_to_trash_with_last_guard(cancelled, last_guard)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (cancelled, last_guard);
            NativeTrashOutcome::Refused(unsupported().to_string())
        }
    }
}

/// Sealed `.app` bundle directory candidate for T9 bundle uninstall.
/// The target is the package itself; ancestor/protection/volume rules are
/// unchanged from ordinary candidates. See docs/UNINSTALL_EXECUTION.md.
pub struct BundleTrashCandidate {
    #[cfg(target_os = "macos")]
    native: native::Candidate,
    #[cfg(not(target_os = "macos"))]
    unavailable: std::convert::Infallible,
}

impl BundleTrashCandidate {
    /// Captures a bundle directory: ordinary user-owned `.app` directory with
    /// a regular-file Contents/Info.plist, strictly beneath the explicit
    /// scope on the same supported volume. Links and dataless objects are
    /// refused; the package-boundary rejection applies to ancestors only.
    pub fn capture(scope: &Path, path: &Path, protected: &[PathBuf]) -> io::Result<Self> {
        #[cfg(target_os = "macos")]
        {
            native::Candidate::capture_bundle_diagnostic(scope, path, protected)
                .map(|native| Self { native })
                .map_err(NativeCaptureFailure::into_legacy_error)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (scope, path, protected);
            Err(unsupported())
        }
    }

    pub fn info(&self) -> &NativeFileInfo {
        #[cfg(target_os = "macos")]
        {
            &self.native.info
        }
        #[cfg(not(target_os = "macos"))]
        match self.unavailable {}
    }

    pub fn path(&self) -> &Path {
        #[cfg(target_os = "macos")]
        {
            &self.native.path
        }
        #[cfg(not(target_os = "macos"))]
        match self.unavailable {}
    }

    pub fn revalidate(&self) -> io::Result<()> {
        #[cfg(target_os = "macos")]
        {
            self.native.revalidate()
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(unsupported())
        }
    }

    /// Same single-attempt contract as ordinary candidates: durable intent
    /// first, cancellation evaluated once before the sole Foundation call,
    /// never submitted twice.
    pub fn move_to_trash_with_last_guard(
        &self,
        cancelled: impl FnOnce() -> bool,
        last_guard: impl FnOnce() -> NativeLastGuard,
    ) -> NativeTrashOutcome {
        #[cfg(target_os = "macos")]
        {
            self.native
                .move_to_trash_with_last_guard(cancelled, last_guard)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (cancelled, last_guard);
            NativeTrashOutcome::Refused(unsupported().to_string())
        }
    }
}

/// Sealed Trash candidate for one marker-bound project artifact directory
/// (T8 purge). The artifact moves as one container; its marker files are
/// captured as revalidation evidence and are never targets. Admission,
/// ancestry, protection and volume rules are the ordinary-candidate rules
/// without a bundle-name requirement.
pub struct PurgeTrashCandidate {
    #[cfg(target_os = "macos")]
    native: native::Candidate,
    #[cfg(not(target_os = "macos"))]
    unavailable: std::convert::Infallible,
}

/// Sealed Trash candidate for one documented developer-cache directory.
/// Rule/home anchoring is verified by the engine before capture and again
/// through the engine guard; this native candidate seals the directory
/// identity, ancestry, protections and Trash-only move. The explicit scope may
/// be the cache directory itself or one of its ancestors.
pub struct CacheTrashCandidate {
    #[cfg(target_os = "macos")]
    native: native::Candidate,
    #[cfg(not(target_os = "macos"))]
    unavailable: std::convert::Infallible,
}

impl CacheTrashCandidate {
    pub fn capture(scope: &Path, path: &Path, protected: &[PathBuf]) -> io::Result<Self> {
        #[cfg(target_os = "macos")]
        {
            native::Candidate::capture_cache_diagnostic(scope, path, protected)
                .map(|native| Self { native })
                .map_err(NativeCaptureFailure::into_legacy_error)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (scope, path, protected);
            Err(unsupported())
        }
    }

    pub fn info(&self) -> &NativeFileInfo {
        #[cfg(target_os = "macos")]
        {
            &self.native.info
        }
        #[cfg(not(target_os = "macos"))]
        match self.unavailable {}
    }

    pub fn revalidate(&self) -> io::Result<()> {
        #[cfg(target_os = "macos")]
        {
            self.native.revalidate()
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(unsupported())
        }
    }

    pub fn move_to_trash_with_last_guard(
        &self,
        cancelled: impl FnOnce() -> bool,
        last_guard: impl FnOnce() -> NativeLastGuard,
    ) -> NativeTrashOutcome {
        #[cfg(target_os = "macos")]
        {
            self.native
                .move_to_trash_with_last_guard(cancelled, last_guard)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (cancelled, last_guard);
            NativeTrashOutcome::Refused(unsupported().to_string())
        }
    }
}

impl PurgeTrashCandidate {
    /// Captures an artifact directory with its sealed marker files:
    /// ordinary user-owned directory strictly beneath the explicit scope on
    /// the same supported volume; every marker an ordinary user-owned
    /// regular file beneath the scope, distinct from the artifact. Links
    /// and dataless objects are refused.
    pub fn capture(
        scope: &Path,
        path: &Path,
        purge_markers: &[PathBuf],
        protected: &[PathBuf],
    ) -> io::Result<Self> {
        #[cfg(target_os = "macos")]
        {
            native::Candidate::capture_purge_diagnostic(scope, path, purge_markers, protected)
                .map(|native| Self { native })
                .map_err(NativeCaptureFailure::into_legacy_error)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (scope, path, purge_markers, protected);
            Err(unsupported())
        }
    }

    pub fn info(&self) -> &NativeFileInfo {
        #[cfg(target_os = "macos")]
        {
            &self.native.info
        }
        #[cfg(not(target_os = "macos"))]
        match self.unavailable {}
    }

    pub fn path(&self) -> &Path {
        #[cfg(target_os = "macos")]
        {
            &self.native.path
        }
        #[cfg(not(target_os = "macos"))]
        match self.unavailable {}
    }

    pub fn revalidate(&self) -> io::Result<()> {
        #[cfg(target_os = "macos")]
        {
            self.native.revalidate()
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(unsupported())
        }
    }

    /// Same single-attempt contract as ordinary candidates: durable intent
    /// first, cancellation evaluated once before the sole Foundation call,
    /// never submitted twice.
    pub fn move_to_trash_with_last_guard(
        &self,
        cancelled: impl FnOnce() -> bool,
        last_guard: impl FnOnce() -> NativeLastGuard,
    ) -> NativeTrashOutcome {
        #[cfg(target_os = "macos")]
        {
            self.native
                .move_to_trash_with_last_guard(cancelled, last_guard)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (cancelled, last_guard);
            NativeTrashOutcome::Refused(unsupported().to_string())
        }
    }
}

/// Requests Darwin F_FULLFSYNC, with no fsync-only durability fallback.
pub fn full_sync(file: &std::fs::File) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: A borrowed live descriptor and an argument-free fcntl command.
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_FULLFSYNC) } == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = file;
        Err(unsupported())
    }
}

#[cfg(not(target_os = "macos"))]
fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "native macOS Trash is unavailable",
    )
}

#[cfg(target_os = "macos")]
#[path = "trash/native.rs"]
mod native;

#[cfg(test)]
mod diagnostic_error_tests {
    use super::*;

    #[test]
    fn diagnostic_dual_failure_keeps_errors_and_legacy_conversion() {
        let failure = NativeCaptureFailure {
            phase: "ancestor",
            operation: "acl_snapshot",
            error: io::Error::from_raw_os_error(1),
            restoration_error: Some(io::Error::from_raw_os_error(5)),
        };
        assert_eq!(failure.error.raw_os_error(), Some(1));
        assert_eq!(
            failure.restoration_error.as_ref().unwrap().raw_os_error(),
            Some(5)
        );
        let description = failure.to_string();
        assert!(description.contains("restoring thread policy failed"));
        let legacy = failure.into_legacy_error();
        assert_eq!(legacy.kind(), io::ErrorKind::Other);
        assert_eq!(legacy.to_string(), description);
    }
}
