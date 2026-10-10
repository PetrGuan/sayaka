// SPDX-License-Identifier: MPL-2.0

//! Bulk metadata for cache measurement only. Directory admission, open flags,
//! identity checks and modification stamps match the generic macOS cursor.
use super::*;
use sayaka_platform_macos::scan_bulk::{BulkDirectory, BulkKind, BulkMetadata};
use std::os::fd::BorrowedFd;

pub(super) struct CacheBackend;
impl Backend for CacheBackend {
    type Directory = CacheDirectory;
    type Policy = NativePolicy;
    fn enter_thread(&self) -> Result<NativePolicy, ScanError> {
        MacBackend.enter_thread()
    }
    fn open_root(&self, path: &Path) -> Result<CacheDirectory, ScanError> {
        let fd = fs::open(path, directory_flags(), Mode::empty()).map_err(native_error)?;
        validate_local_internal_volume_fd(&fd)?;
        CacheDirectory::from_fd(fd)
    }
}

enum Reader {
    Bulk(BulkDirectory),
    Legacy(MacDirectory),
    Failed,
}

pub(super) struct CacheDirectory {
    reader: Reader,
    original: Metadata,
    stamp: Stamp,
}
impl CacheDirectory {
    fn from_fd(fd: OwnedFd) -> Result<Self, ScanError> {
        let stat = fs::fstat(&fd).map_err(native_error)?;
        let original = from_stat(&stat);
        if original.dataless {
            return Err(ScanError::new(
                ScanCode::CloudDirectorySkipped,
                "dataless directory cannot be enumerated",
            ));
        }
        Ok(Self {
            reader: Reader::Bulk(BulkDirectory::new(fd)),
            original,
            stamp: stamp(&stat),
        })
    }
    fn fd(&self) -> Result<BorrowedFd<'_>, ScanError> {
        match &self.reader {
            Reader::Bulk(reader) => Ok(reader.fd()),
            Reader::Legacy(reader) => reader.stream.fd().map_err(native_error),
            Reader::Failed => Err(ScanError::new(ScanCode::Io, "cache cursor unavailable")),
        }
    }
    fn fallback(&mut self) -> Result<(), ScanError> {
        let Reader::Bulk(reader) = std::mem::replace(&mut self.reader, Reader::Failed) else {
            return Err(ScanError::new(
                ScanCode::Internal,
                "invalid cache cursor fallback",
            ));
        };
        let fd = reader.into_fd();
        fs::seek(&fd, fs::SeekFrom::Start(0)).map_err(native_error)?;
        let reader = MacDirectory::from_fd(fd)?;
        if reader.original != self.original || reader.stamp != self.stamp {
            return Err(ScanError::new(
                ScanCode::ChangedEntry,
                "cache directory changed before cursor fallback",
            ));
        }
        self.reader = Reader::Legacy(reader);
        Ok(())
    }
}
impl Cursor for CacheDirectory {
    fn metadata(&self) -> Metadata {
        self.original.clone()
    }
    fn next_entry(&mut self) -> Option<Result<DirItem, ScanError>> {
        let entry = match &mut self.reader {
            Reader::Legacy(reader) => return reader.next_entry(),
            Reader::Failed => return None,
            Reader::Bulk(reader) => match reader.next_entry()? {
                Ok(entry) => entry,
                Err(error)
                    if error.kind() == std::io::ErrorKind::Unsupported && reader.can_fallback() =>
                {
                    return match self.fallback() {
                        Ok(()) => self.next_entry(),
                        Err(error) => Some(Err(error)),
                    };
                }
                Err(error) => return Some(Err(ScanError::io(error))),
            },
        };
        let metadata = match entry.metadata {
            Ok(Some(metadata)) => from_bulk(metadata),
            Ok(None) => self.fd().and_then(|fd| {
                let stat =
                    fs::statat(fd, &entry.name, AtFlags::SYMLINK_NOFOLLOW).map_err(native_error)?;
                let metadata = from_stat(&stat);
                if metadata.kind == ResourceKind::Directory || stat.st_flags & 0x0080_0000 != 0 {
                    // Path stat may observe a firmlink's target. It cannot
                    // recover missing underlying directory boundary flags.
                    return Err(ScanError::new(
                        ScanCode::Io,
                        "cache directory boundary metadata unavailable",
                    ));
                }
                Ok(metadata)
            }),
            Err(error) => Err(ScanError::io(error)),
        };
        Some(Ok(DirItem {
            name: entry.name,
            metadata,
        }))
    }
    fn open_child(&self, item: &DirItem) -> Result<Self, ScanError> {
        let fd = fs::openat(self.fd()?, &item.name, directory_flags(), Mode::empty())
            .map_err(native_error)?;
        Self::from_fd(fd)
    }
    fn unchanged(&self) -> Result<bool, ScanError> {
        let stat = fs::fstat(self.fd()?).map_err(native_error)?;
        Ok(stamp(&stat) == self.stamp && from_stat(&stat).identity == self.original.identity)
    }
}

fn from_bulk(value: BulkMetadata) -> Result<Metadata, ScanError> {
    // getattrlistbulk reports attributes of an underlying mount point or
    // firmlink, not its target. Reject these before opening the child.
    if value.mount_point || value.flags & 0x0080_0000 != 0 {
        return Err(ScanError::new(
            ScanCode::MountBoundary,
            "cache mount or firmlink boundary not traversed",
        ));
    }
    let kind = match value.kind {
        BulkKind::File => ResourceKind::File,
        BulkKind::Directory => ResourceKind::Directory,
        BulkKind::Link => ResourceKind::Link,
        BulkKind::Other => ResourceKind::Other,
    };
    let regular = kind == ResourceKind::File;
    Ok(Metadata {
        identity: FileIdentity::Unix {
            device: value.device,
            inode: value.inode,
        },
        kind,
        logical_bytes: regular.then_some(value.logical_bytes).flatten(),
        allocated_bytes: regular.then_some(value.allocated_bytes).flatten(),
        link_count: value.link_count,
        modified_unix_ms: None,
        dataless: value.flags & 0x4000_0000 != 0,
    })
}
