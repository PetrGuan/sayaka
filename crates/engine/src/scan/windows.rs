// SPDX-License-Identifier: MPL-2.0

use super::walk::{self, Backend, Cursor, DirItem, Metadata, ThreadPolicy};
use super::*;
use sayaka_platform_windows::{Directory, Error};
use std::time::Instant;

struct WindowsBackend;
struct WindowsDirectory(Directory);
struct NoThreadPolicy;

impl ThreadPolicy for NoThreadPolicy {
    fn restore(self) -> Result<(), ScanError> {
        Ok(())
    }
}

fn native_error(error: Error) -> ScanError {
    match error {
        Error::Io(error) => ScanError::io(error),
        Error::Open(error) => {
            let mut error = ScanError::io(error);
            error.message = format!("native directory open: {}", error.message);
            error
        }
        Error::InvalidPath => ScanError::new(
            ScanCode::InvalidRoot,
            "expected an absolute directory path without streams, devices or traversal",
        ),
        Error::Reparse => ScanError::new(
            ScanCode::LinkSkipped,
            "reparse paths, including junction ancestors, are not followed",
        ),
        Error::Cloud => ScanError::new(
            ScanCode::CloudDirectorySkipped,
            "offline or recall-marked directories are not enumerated",
        ),
        Error::UnsupportedVolume => ScanError::new(
            ScanCode::UnsupportedVolume,
            "Windows scanning requires a local fixed NTFS volume",
        ),
        Error::VolumeUnknown(error) => ScanError {
            code: ScanCode::VolumeUnknown,
            message: error.to_string(),
            os_code: error.raw_os_error(),
        },
    }
}

fn metadata(info: &sayaka_platform_windows::Metadata) -> Metadata {
    let kind = if info.directory && info.dataless {
        ResourceKind::Directory
    } else if info.reparse {
        ResourceKind::Link
    } else if info.directory {
        ResourceKind::Directory
    } else {
        ResourceKind::File
    };
    Metadata {
        identity: FileIdentity::Windows {
            volume_serial: info.volume_serial,
            file_id: info.file_id,
        },
        kind,
        logical_bytes: info.logical_bytes,
        allocated_bytes: info.allocated_bytes,
        dataless: info.dataless,
    }
}

impl Backend for WindowsBackend {
    type Directory = WindowsDirectory;
    type Policy = NoThreadPolicy;

    fn enter_thread(&self) -> Result<Self::Policy, ScanError> {
        Ok(NoThreadPolicy)
    }

    fn open_root(&self, path: &Path) -> Result<Self::Directory, ScanError> {
        Directory::open_root(path)
            .map(WindowsDirectory)
            .map_err(native_error)
    }
}

impl Cursor for WindowsDirectory {
    fn metadata(&self) -> Metadata {
        metadata(self.0.metadata())
    }

    fn next_entry(&mut self) -> Option<Result<DirItem, ScanError>> {
        self.0.next_entry().map(|entry| {
            entry
                .map(|entry| DirItem {
                    name: entry.name,
                    metadata: Ok(metadata(&entry.metadata)),
                })
                .map_err(native_error)
        })
    }

    fn open_child(&self, item: &DirItem) -> Result<Self, ScanError> {
        self.0
            .open_child(&item.name)
            .map(Self)
            .map_err(native_error)
    }

    fn unchanged(&self) -> Result<bool, ScanError> {
        self.0.unchanged().map_err(native_error)
    }
}

pub(super) fn scan_native(
    roots: Vec<PathBuf>,
    limits: &ScanLimits,
    cancellation: &Cancellation,
    task_id: ScanTaskId,
    progress: impl FnMut(&ScanProgress),
) -> Result<ScanReport, ScanError> {
    walk::run(
        &WindowsBackend,
        roots,
        limits,
        cancellation,
        task_id,
        Instant::now(),
        progress,
    )
}
