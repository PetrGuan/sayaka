// SPDX-License-Identifier: MPL-2.0

//! Read-only uninstall preview contract for one explicit `.app` bundle (T9).
//!
//! This module defines the evidence, protections and refusal surface that a
//! future execution slice must satisfy. It performs no effects: no Trash, no
//! deletion, no signals to processes. Execution is explicitly deferred to a
//! separately reviewed contract; nothing here authorizes removal.

use crate::app_inventory::{RunningObservation, running_process_paths};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Execution state published by every preview of this slice.
pub const EXECUTION_DEFERRED: &str = "deferred_contract";

/// Recovery statement published by every preview of this slice.
pub const RECOVERY_NOTE: &str = "the future execution slice moves the bundle to the user Trash; recovery is Finder 'Put Back', with no programmatic restore";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UninstallRefusalCode {
    NotFound,
    NotDirectory,
    NotAppBundle,
    SymlinkBundle,
    MissingInfoPlist,
    InfoPlistNotRegularFile,
    SystemLocation,
    NonLocalVolume,
    Running,
    UnsupportedPlatform,
    Internal,
}

impl UninstallRefusalCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::NotDirectory => "not_directory",
            Self::NotAppBundle => "not_app_bundle",
            Self::SymlinkBundle => "symlink_bundle",
            Self::MissingInfoPlist => "missing_info_plist",
            Self::InfoPlistNotRegularFile => "info_plist_not_regular_file",
            Self::SystemLocation => "system_location",
            Self::NonLocalVolume => "non_local_volume",
            Self::Running => "running",
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::Internal => "internal_error",
        }
    }
}

#[derive(Clone, Debug)]
pub struct UninstallRefusal {
    pub code: UninstallRefusalCode,
    pub message: String,
    pub os_code: Option<i32>,
}

impl UninstallRefusal {
    fn new(code: UninstallRefusalCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            os_code: None,
        }
    }

    fn os(code: UninstallRefusalCode, message: impl Into<String>, error: &std::io::Error) -> Self {
        Self {
            code,
            message: message.into(),
            os_code: error.raw_os_error(),
        }
    }
}

/// Bundle directory identity captured without following links.
#[derive(Clone, Debug)]
pub struct BundleIdentity {
    pub device: u64,
    pub inode: u64,
    pub logical_bytes: u64,
    pub modified: SystemTime,
}

/// Read-only preview of uninstalling one explicit `.app` bundle.
#[derive(Clone, Debug)]
pub struct UninstallPreview {
    pub bundle_path: PathBuf,
    pub display_name: String,
    pub identity: Option<BundleIdentity>,
    /// Regular files observed directly under `Contents/MacOS` (nofollow).
    pub executables_observed: Option<usize>,
    pub running: RunningObservation,
    pub protections: Vec<&'static str>,
    pub recovery: &'static str,
    pub execution: &'static str,
    pub refusals: Vec<UninstallRefusal>,
}

impl UninstallPreview {
    /// This slice never authorizes execution; the field exists so callers
    /// cannot mistake a clean preview for approval.
    pub fn can_execute(&self) -> bool {
        false
    }
}

fn protections() -> Vec<&'static str> {
    vec![
        "related data, preferences, caches and credentials are never touched by this contract",
        "other copies of the same bundle ID are independent and never touched",
        "a running bundle is refused, never signaled or terminated",
        "no permanent deletion fallback exists after any failed Trash operation",
        "system locations (/System) are refused regardless of permissions",
    ]
}

fn base_preview(bundle_path: PathBuf) -> UninstallPreview {
    let display_name = bundle_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("(unknown)")
        .to_owned();
    UninstallPreview {
        bundle_path,
        display_name,
        identity: None,
        executables_observed: None,
        running: RunningObservation::NotChecked,
        protections: protections(),
        recovery: RECOVERY_NOTE,
        execution: EXECUTION_DEFERRED,
        refusals: Vec::new(),
    }
}

/// Captures the read-only uninstall preview for one explicit `.app` bundle.
/// Refusals are data, not errors; only internal failures abort the preview.
pub fn preview_bundle_uninstall(bundle: &Path) -> UninstallPreview {
    let absolute = std::path::absolute(bundle).unwrap_or_else(|_| bundle.to_path_buf());
    let mut preview = base_preview(absolute.clone());
    if absolute.starts_with("/System") {
        preview.refusals.push(UninstallRefusal::new(
            UninstallRefusalCode::SystemLocation,
            "system locations are never uninstall targets",
        ));
        // /System is a closed refusal boundary: no metadata, volume,
        // plist, executable or running inspection happens beneath it.
        return preview;
    }
    let metadata = match std::fs::symlink_metadata(&absolute) {
        Ok(metadata) => metadata,
        Err(error) => {
            let code = if error.kind() == std::io::ErrorKind::NotFound {
                UninstallRefusalCode::NotFound
            } else {
                UninstallRefusalCode::Internal
            };
            preview.refusals.push(UninstallRefusal::os(
                code,
                format!("cannot inspect {}: {error}", absolute.display()),
                &error,
            ));
            return preview;
        }
    };
    if metadata.file_type().is_symlink() {
        preview.refusals.push(UninstallRefusal::new(
            UninstallRefusalCode::SymlinkBundle,
            "the bundle path itself is a symbolic link and is never followed",
        ));
        return preview;
    }
    if !metadata.is_dir() {
        preview.refusals.push(UninstallRefusal::new(
            UninstallRefusalCode::NotDirectory,
            "the bundle path is not a directory",
        ));
        return preview;
    }
    if absolute
        .file_name()
        .and_then(|name| name.to_str())
        .is_none_or(|name| !name.ends_with(".app"))
    {
        preview.refusals.push(UninstallRefusal::new(
            UninstallRefusalCode::NotAppBundle,
            "the directory name does not end in .app",
        ));
    }
    preview.identity = Some(BundleIdentity {
        device: identity_device(&metadata),
        inode: identity_inode(&metadata),
        logical_bytes: metadata.len(),
        modified: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
    });
    match local_volume(&absolute) {
        Ok(true) => {}
        Ok(false) => preview.refusals.push(UninstallRefusal::new(
            UninstallRefusalCode::NonLocalVolume,
            "the bundle does not reside on a local volume",
        )),
        Err(error) => preview.refusals.push(UninstallRefusal::os(
            UninstallRefusalCode::Internal,
            format!("cannot verify the bundle volume: {error}"),
            &error,
        )),
    }
    let plist = absolute.join("Contents").join("Info.plist");
    match std::fs::symlink_metadata(&plist) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => preview.refusals.push(UninstallRefusal::new(
            UninstallRefusalCode::InfoPlistNotRegularFile,
            "Contents/Info.plist is not a regular file (links are not followed)",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            preview.refusals.push(UninstallRefusal::new(
                UninstallRefusalCode::MissingInfoPlist,
                "Contents/Info.plist is missing",
            ));
        }
        Err(error) => preview.refusals.push(UninstallRefusal::os(
            UninstallRefusalCode::Internal,
            format!("cannot inspect Contents/Info.plist: {error}"),
            &error,
        )),
    }
    observe_running(&mut preview, &absolute);
    preview
}

/// Public running observation for one bundle directory, reused by the
/// execution session's plan and last-native-guard checks. Fails closed:
/// anything but a proven absence yields Running, Unknown or
/// NotAttributable, never NotRunning.
pub fn bundle_running(bundle: &Path) -> RunningObservation {
    let macos_dir = bundle.join("Contents").join("MacOS");
    let entries = match std::fs::read_dir(&macos_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return RunningObservation::NotAttributable("no Contents/MacOS directory");
        }
        Err(_) => return RunningObservation::Unknown,
    };
    let mut executables = Vec::new();
    for entry in entries {
        let Ok(entry) = entry else {
            return RunningObservation::Unknown;
        };
        match entry.file_type() {
            Ok(kind) if kind.is_file() => executables.push(entry.path()),
            Ok(_) => {}
            Err(_) => return RunningObservation::Unknown,
        }
    }
    if executables.is_empty() {
        return RunningObservation::NotAttributable("no regular executable observed");
    }
    let running = match running_process_paths() {
        Ok(running) => running,
        Err(_) => return RunningObservation::Unknown,
    };
    // Every observed executable must resolve before "not running" holds.
    let mut resolved = Vec::with_capacity(executables.len());
    for executable in &executables {
        match std::fs::canonicalize(executable) {
            Ok(path) => resolved.push(path),
            Err(_) => {
                return RunningObservation::NotAttributable("executable path cannot be resolved");
            }
        }
    }
    let mut pids = Vec::new();
    for executable in &resolved {
        if let Some(found) = running.get(executable) {
            pids.extend(found.iter().copied());
        }
    }
    pids.sort_unstable();
    pids.dedup();
    if pids.is_empty() {
        RunningObservation::NotRunning
    } else {
        RunningObservation::Running(pids)
    }
}

/// Matches every regular file directly under `Contents/MacOS` against the
/// visible running processes. Any match refuses uninstall; an enumeration
/// failure is explicit Unknown, never "not running".
fn observe_running(preview: &mut UninstallPreview, bundle: &Path) {
    let macos_dir = bundle.join("Contents").join("MacOS");
    let entries = match std::fs::read_dir(&macos_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            preview.executables_observed = Some(0);
            preview.running = RunningObservation::NotAttributable("no Contents/MacOS directory");
            return;
        }
        Err(error) => {
            preview.running = RunningObservation::Unknown;
            preview.refusals.push(UninstallRefusal::os(
                UninstallRefusalCode::Internal,
                format!("cannot read Contents/MacOS: {error}"),
                &error,
            ));
            return;
        }
    };
    let mut executables = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                preview.running = RunningObservation::Unknown;
                preview.refusals.push(UninstallRefusal::os(
                    UninstallRefusalCode::Internal,
                    format!("cannot read a Contents/MacOS entry: {error}"),
                    &error,
                ));
                return;
            }
        };
        match entry.file_type() {
            Ok(kind) if kind.is_file() => executables.push(entry.path()),
            Ok(_) => {}
            Err(error) => {
                preview.running = RunningObservation::Unknown;
                preview.refusals.push(UninstallRefusal::os(
                    UninstallRefusalCode::Internal,
                    format!("cannot inspect a Contents/MacOS entry: {error}"),
                    &error,
                ));
                return;
            }
        }
    }
    preview.executables_observed = Some(executables.len());
    if executables.is_empty() {
        preview.running = RunningObservation::NotAttributable("no regular executable observed");
        return;
    }
    let running = match running_process_paths() {
        Ok(running) => running,
        Err(_) => {
            preview.running = RunningObservation::Unknown;
            return;
        }
    };
    // Every observed executable must resolve before "not running" can be
    // claimed; an unresolvable one makes the bundle not attributable.
    let mut resolved = Vec::with_capacity(executables.len());
    for executable in &executables {
        match std::fs::canonicalize(executable) {
            Ok(path) => resolved.push(path),
            Err(_) => {
                preview.running =
                    RunningObservation::NotAttributable("executable path cannot be resolved");
                return;
            }
        }
    }
    let mut pids = Vec::new();
    for executable in &resolved {
        if let Some(found) = running.get(executable) {
            pids.extend(found.iter().copied());
        }
    }
    pids.sort_unstable();
    pids.dedup();
    if pids.is_empty() {
        preview.running = RunningObservation::NotRunning;
    } else {
        preview.running = RunningObservation::Running(pids.clone());
        preview.refusals.push(UninstallRefusal::new(
            UninstallRefusalCode::Running,
            format!("bundle executables are running (pids: {pids:?}); refused, never signaled"),
        ));
    }
}

#[cfg(target_os = "macos")]
fn local_volume(path: &Path) -> std::io::Result<bool> {
    let file = std::fs::File::open(path)?;
    let stat = rustix::fs::fstatfs(&file)?;
    Ok(stat.f_flags & (libc::MNT_LOCAL as u32) != 0)
}

#[cfg(not(target_os = "macos"))]
fn local_volume(_: &Path) -> std::io::Result<bool> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "uninstall preview volume checks currently require macOS",
    ))
}

#[cfg(unix)]
fn identity_device(metadata: &std::fs::Metadata) -> u64 {
    std::os::unix::fs::MetadataExt::dev(metadata)
}

#[cfg(not(unix))]
fn identity_device(_: &std::fs::Metadata) -> u64 {
    0
}

#[cfg(unix)]
fn identity_inode(metadata: &std::fs::Metadata) -> u64 {
    std::os::unix::fs::MetadataExt::ino(metadata)
}

#[cfg(not(unix))]
fn identity_inode(_: &std::fs::Metadata) -> u64 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fixture_bundle(root: &Path, name: &str) -> PathBuf {
        let bundle = root.join(name);
        let macos = bundle.join("Contents").join("MacOS");
        fs::create_dir_all(&macos).expect("create bundle tree");
        fs::write(bundle.join("Contents").join("Info.plist"), b"plist").expect("write plist");
        fs::write(macos.join("Run"), b"inert").expect("write executable");
        bundle
    }

    #[test]
    fn valid_bundle_previews_without_refusals_but_never_executable() {
        let root = tempfile::tempdir().expect("tempdir");
        let bundle = fixture_bundle(root.path(), "Fixture.app");
        let preview = preview_bundle_uninstall(&bundle);
        assert!(preview.refusals.is_empty(), "{:?}", preview.refusals);
        assert!(!preview.can_execute());
        assert_eq!(preview.execution, EXECUTION_DEFERRED);
        assert_eq!(preview.executables_observed, Some(1));
        assert_eq!(preview.running, RunningObservation::NotRunning);
        assert!(preview.identity.is_some());
        assert!(preview.recovery.contains("Put Back"));
        assert!(preview.protections.len() >= 4);
    }

    #[test]
    fn missing_not_directory_not_app_and_missing_plist_are_refused() {
        let root = tempfile::tempdir().expect("tempdir");
        let missing = preview_bundle_uninstall(&root.path().join("Ghost.app"));
        assert!(
            missing
                .refusals
                .iter()
                .any(|r| r.code == UninstallRefusalCode::NotFound)
        );

        let file = root.path().join("File.app");
        fs::write(&file, b"not a directory").expect("write file");
        let not_dir = preview_bundle_uninstall(&file);
        assert!(
            not_dir
                .refusals
                .iter()
                .any(|r| r.code == UninstallRefusalCode::NotDirectory)
        );

        let plain = fixture_bundle(root.path(), "PlainDir");
        let not_app = preview_bundle_uninstall(&plain);
        assert!(
            not_app
                .refusals
                .iter()
                .any(|r| r.code == UninstallRefusalCode::NotAppBundle)
        );

        let no_plist = root.path().join("NoPlist.app");
        fs::create_dir_all(no_plist.join("Contents").join("MacOS")).expect("tree");
        let missing_plist = preview_bundle_uninstall(&no_plist);
        assert!(
            missing_plist
                .refusals
                .iter()
                .any(|r| r.code == UninstallRefusalCode::MissingInfoPlist)
        );
    }

    #[test]
    fn system_location_is_refused_before_any_inspection() {
        let preview =
            preview_bundle_uninstall(Path::new("/System/Library/CoreServices/Finder.app"));
        assert!(
            preview
                .refusals
                .iter()
                .any(|r| r.code == UninstallRefusalCode::SystemLocation)
        );
        // The refusal is a closed boundary: nothing beneath /System is probed.
        assert!(preview.identity.is_none());
        assert!(preview.executables_observed.is_none());
        assert_eq!(preview.running, RunningObservation::NotChecked);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn symlink_bundle_is_never_followed() {
        let root = tempfile::tempdir().expect("tempdir");
        let bundle = fixture_bundle(root.path(), "Real.app");
        let link = root.path().join("Link.app");
        std::os::unix::fs::symlink(&bundle, &link).expect("symlink");
        let preview = preview_bundle_uninstall(&link);
        assert!(
            preview
                .refusals
                .iter()
                .any(|r| r.code == UninstallRefusalCode::SymlinkBundle)
        );
    }
}
