// SPDX-License-Identifier: MPL-2.0

//! Bounded Darwin directory metadata batches. No file contents or link targets
//! are opened. The caller must enter ReadOnlyPolicy and admit the directory.
use std::ffi::OsString;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;

// Public sys/attr.h flag, not yet exported by libc.
const ATTR_CMN_ERROR: u32 = 0x2000_0000;
const COMMON: u32 = libc::ATTR_CMN_RETURNED_ATTRS
    | ATTR_CMN_ERROR
    | libc::ATTR_CMN_NAME
    | libc::ATTR_CMN_DEVID
    | libc::ATTR_CMN_OBJTYPE
    | libc::ATTR_CMN_FLAGS
    | libc::ATTR_CMN_FILEID;
const FILE: u32 =
    libc::ATTR_FILE_LINKCOUNT | libc::ATTR_FILE_ALLOCSIZE | libc::ATTR_FILE_DATALENGTH;
const DIRECTORY: u32 = libc::ATTR_DIR_MOUNTSTATUS;
const BUFFER_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BulkKind {
    File,
    Directory,
    Link,
    Other,
}

#[derive(Debug)]
pub struct BulkMetadata {
    pub device: u64,
    pub inode: u64,
    pub kind: BulkKind,
    pub flags: u32,
    pub mount_point: bool,
    pub link_count: Option<u64>,
    pub logical_bytes: Option<u64>,
    pub allocated_bytes: Option<u64>,
}

pub struct BulkEntry {
    pub name: OsString,
    /// None requires descriptor-relative no-follow stat. Per-entry errors must
    /// remain errors, rather than being interpreted as absent/empty files.
    pub metadata: io::Result<Option<BulkMetadata>>,
}

/// Owns one descriptor and at most 64 KiB of batch storage. Never mix readdir
/// with this descriptor's bulk iteration. Only an unsupported *first* call
/// permits the caller to rewind and fall back to its original cursor.
pub struct BulkDirectory {
    fd: OwnedFd,
    buffer: Vec<u64>,
    offset: usize,
    remaining: usize,
    started: bool,
    ended: bool,
}

impl BulkDirectory {
    pub fn new(fd: OwnedFd) -> Self {
        Self {
            fd,
            buffer: Vec::new(),
            offset: 0,
            remaining: 0,
            started: false,
            ended: false,
        }
    }
    pub fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
    pub fn into_fd(self) -> OwnedFd {
        self.fd
    }
    pub fn can_fallback(&self) -> bool {
        !self.started
    }

    pub fn next_entry(&mut self) -> Option<io::Result<BulkEntry>> {
        if self.ended {
            return None;
        }
        let result = self.read_entry();
        match result {
            Ok(Some(entry)) => Some(Ok(entry)),
            Ok(None) => {
                self.ended = true;
                None
            }
            Err(error) => {
                self.ended = true;
                Some(Err(error))
            }
        }
    }

    fn read_entry(&mut self) -> io::Result<Option<BulkEntry>> {
        if self.remaining == 0 {
            self.buffer.resize(BUFFER_BYTES / 8, 0);
            let mut attrs = libc::attrlist {
                bitmapcount: libc::ATTR_BIT_MAP_COUNT as u16,
                reserved: 0,
                commonattr: COMMON,
                volattr: 0,
                dirattr: DIRECTORY,
                fileattr: FILE,
                forkattr: 0,
            };
            // SAFETY: live owned descriptor; initialized attrlist; aligned,
            // writable 64 KiB allocation alive for this synchronous call.
            let count = unsafe {
                libc::getattrlistbulk(
                    self.fd.as_raw_fd(),
                    (&mut attrs as *mut libc::attrlist).cast(),
                    self.buffer.as_mut_ptr().cast(),
                    BUFFER_BYTES,
                    0,
                )
            };
            if count < 0 {
                let error = io::Error::last_os_error();
                if !self.started
                    && matches!(
                        error.raw_os_error(),
                        Some(libc::ENOTSUP | libc::ENOSYS | libc::EINVAL)
                    )
                {
                    return Err(io::Error::new(io::ErrorKind::Unsupported, error));
                }
                return Err(error);
            }
            if count == 0 {
                return Ok(None);
            }
            self.started = true;
            self.remaining = usize::try_from(count).map_err(|_| invalid())?;
            if self.remaining > BUFFER_BYTES / 24 {
                return Err(invalid());
            }
            self.offset = 0;
        }
        // SAFETY: u64 storage is fully initialized and has no padding; the
        // immutable byte view cannot outlive the buffer or overlap a mutation.
        let bytes =
            unsafe { std::slice::from_raw_parts(self.buffer.as_ptr().cast::<u8>(), BUFFER_BYTES) };
        let tail = bytes.get(self.offset..).ok_or_else(invalid)?;
        let length = u32::from_ne_bytes(
            tail.get(..4)
                .ok_or_else(invalid)?
                .try_into()
                .map_err(|_| invalid())?,
        ) as usize;
        if length < 24 || length % 8 != 0 {
            return Err(invalid());
        }
        let record = tail.get(..length).ok_or_else(invalid)?;
        let entry = parse(record)?;
        self.offset += length;
        self.remaining -= 1;
        Ok(Some(entry))
    }
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid bulk directory metadata record",
    )
}

struct Fields<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl Fields<'_> {
    fn read<const N: usize>(&mut self) -> io::Result<[u8; N]> {
        let end = self.offset.checked_add(N).ok_or_else(invalid)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?;
        self.offset = end;
        Ok(value)
    }
    fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_ne_bytes(self.read()?))
    }
    fn u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_ne_bytes(self.read()?))
    }
    fn optional32(&mut self, present: bool) -> io::Result<Option<u32>> {
        present.then(|| self.u32()).transpose()
    }
    fn optional64(&mut self, present: bool) -> io::Result<Option<u64>> {
        present.then(|| self.u64()).transpose()
    }
}

fn parse(record: &[u8]) -> io::Result<BulkEntry> {
    // Darwin packs attributes on four-byte boundaries. Decode bytes instead
    // of casting packed fields to potentially misaligned native references.
    let mut f = Fields {
        bytes: record,
        offset: 4,
    };
    let common = f.u32()?;
    let volume = f.u32()?;
    let directory = f.u32()?;
    let file = f.u32()?;
    let fork = f.u32()?;
    if common & !COMMON != 0
        || volume != 0
        || directory & !DIRECTORY != 0
        || file & !FILE != 0
        || fork != 0
        || common & (libc::ATTR_CMN_NAME | libc::ATTR_CMN_RETURNED_ATTRS)
            != (libc::ATTR_CMN_NAME | libc::ATTR_CMN_RETURNED_ATTRS)
    {
        return Err(invalid());
    }
    // ATTR_CMN_ERROR is special: immediately after the returned-attribute set.
    let error = f.optional32(common & ATTR_CMN_ERROR != 0)?;
    let name_reference = f.offset;
    let name_offset = i32::from_ne_bytes(f.read()?);
    let name_length = f.u32()? as usize;
    let device = f.optional32(common & libc::ATTR_CMN_DEVID != 0)?;
    let kind = f.optional32(common & libc::ATTR_CMN_OBJTYPE != 0)?;
    let flags = f.optional32(common & libc::ATTR_CMN_FLAGS != 0)?;
    let inode = f.optional64(common & libc::ATTR_CMN_FILEID != 0)?;
    let mount = f.optional32(directory & DIRECTORY != 0)?;
    let links = f.optional32(file & libc::ATTR_FILE_LINKCOUNT != 0)?;
    let allocated = f.optional64(file & libc::ATTR_FILE_ALLOCSIZE != 0)?;
    let logical = f.optional64(file & libc::ATTR_FILE_DATALENGTH != 0)?;
    let start = name_reference
        .checked_add_signed(name_offset as isize)
        .ok_or_else(invalid)?;
    let end = start.checked_add(name_length).ok_or_else(invalid)?;
    if start < f.offset || name_length < 2 {
        return Err(invalid());
    }
    let name = record.get(start..end).ok_or_else(invalid)?;
    if name.last() != Some(&0) || name[..name.len() - 1].iter().any(|b| *b == 0 || *b == b'/') {
        return Err(invalid());
    }
    let name = &name[..name.len() - 1];
    if name == b"." || name == b".." {
        return Err(invalid());
    }
    let metadata = if let Some(error) = error.filter(|error| *error != 0) {
        Err(io::Error::from_raw_os_error(
            i32::try_from(error).map_err(|_| invalid())?,
        ))
    } else if let (Some(device), Some(kind), Some(flags), Some(inode)) =
        (device, kind, flags, inode)
    {
        // Public vnode types from sys/vnode.h, distinct from stat mode bits.
        let kind = match kind {
            1 => BulkKind::File,
            2 => BulkKind::Directory,
            5 => BulkKind::Link,
            _ => BulkKind::Other,
        };
        Ok(
            if (kind == BulkKind::Directory && mount.is_none())
                || (kind == BulkKind::File
                    && (links.is_none() || logical.is_none() || allocated.is_none()))
            {
                None
            } else {
                Some(BulkMetadata {
                    device: u64::from(device),
                    inode,
                    kind,
                    flags,
                    mount_point: mount.is_some_and(|value| value & 1 != 0),
                    link_count: links.map(u64::from),
                    logical_bytes: logical.filter(|value| *value <= i64::MAX as u64),
                    allocated_bytes: allocated.filter(|value| *value <= i64::MAX as u64),
                })
            },
        )
    } else {
        Ok(None)
    };
    Ok(BulkEntry {
        name: OsString::from_vec(name.to_vec()),
        metadata,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finish(mut record: Vec<u8>, name_reference: usize) -> Vec<u8> {
        let offset = i32::try_from(record.len() - name_reference).unwrap();
        record[name_reference..name_reference + 4].copy_from_slice(&offset.to_ne_bytes());
        record[name_reference + 4..name_reference + 8].copy_from_slice(&5u32.to_ne_bytes());
        record.extend_from_slice(b"item\0");
        record.resize(record.len().next_multiple_of(8), 0);
        let length = record.len() as u32;
        record[..4].copy_from_slice(&length.to_ne_bytes());
        record
    }

    fn file_record(flags_present: bool) -> Vec<u8> {
        let common = if flags_present {
            COMMON
        } else {
            COMMON & !libc::ATTR_CMN_FLAGS
        };
        let mut record = Vec::new();
        for value in [0, common, 0, 0, FILE, 0, 0, 0, 0, 7, 1] {
            record.extend_from_slice(&value.to_ne_bytes());
        }
        if flags_present {
            record.extend_from_slice(&0u32.to_ne_bytes());
        }
        record.extend_from_slice(&11u64.to_ne_bytes());
        record.extend_from_slice(&2u32.to_ne_bytes());
        record.extend_from_slice(&8192u64.to_ne_bytes());
        record.extend_from_slice(&5u64.to_ne_bytes());
        finish(record, 28)
    }

    #[test]
    fn decodes_unaligned_identity_and_file_attributes() {
        let record = file_record(true);
        let entry = parse(&record).unwrap();
        assert_eq!(entry.name, "item");
        let metadata = entry.metadata.unwrap().unwrap();
        assert_eq!((metadata.device, metadata.inode), (7, 11));
        assert_eq!(metadata.kind, BulkKind::File);
        assert_eq!(metadata.link_count, Some(2));
        assert_eq!(metadata.allocated_bytes, Some(8192));
        assert_eq!(metadata.logical_bytes, Some(5));
    }

    #[test]
    fn missing_safety_attribute_requires_stat_and_entry_error_is_preserved() {
        assert!(
            parse(&file_record(false))
                .unwrap()
                .metadata
                .unwrap()
                .is_none()
        );
        let mut denied = Vec::new();
        for value in [
            0,
            libc::ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_ERROR | libc::ATTR_CMN_NAME,
            0,
            0,
            0,
            0,
            libc::EACCES as u32,
            0,
            0,
        ] {
            denied.extend_from_slice(&value.to_ne_bytes());
        }
        let denied = finish(denied, 28);
        let error = parse(&denied).unwrap().metadata.unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EACCES));
    }

    #[test]
    fn rejects_truncated_fields_and_out_of_record_names() {
        let record = file_record(true);
        assert!(parse(&record[..record.len() - 8]).is_err());
        for offset in [i32::MIN, -28, i32::MAX] {
            let mut bad = record.clone();
            bad[28..32].copy_from_slice(&offset.to_ne_bytes());
            assert!(parse(&bad).is_err());
        }
        let mut bad = record.clone();
        bad[32..36].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert!(parse(&bad).is_err());
    }
}
