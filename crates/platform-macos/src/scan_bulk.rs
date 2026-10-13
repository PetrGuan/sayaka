// SPDX-License-Identifier: MPL-2.0

//! Bounded Darwin directory metadata batches. No file contents or link targets
//! are opened. The caller must enter ReadOnlyPolicy and admit the directory.
use std::ffi::OsString;
use std::cell::RefCell;
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
// Public sys/attr.h; queried opportunistically, never inferred from allocation.
const PRIVATE: u32 = 0x0000_0008; // ATTR_CMNEXT_PRIVATESIZE
const EXTENDED: u64 = 0x0000_0020; // FSOPT_ATTR_CMN_EXTENDED
const BUFFER_BYTES: usize = 64 * 1024;

thread_local! {
    // One initialized 64 KiB spare per enumerating thread, not per directory.
    static SPARE_BUFFER: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
}
struct Buffer(Vec<u64>);
impl Default for Buffer {
    fn default() -> Self {
        Self(SPARE_BUFFER.try_with(|slot| std::mem::take(&mut *slot.borrow_mut())).unwrap_or_default())
    }
}
impl Drop for Buffer {
    fn drop(&mut self) {
        if self.0.len() == BUFFER_BYTES / 8 {
            let _ = SPARE_BUFFER.try_with(|slot| {
                let mut slot = slot.borrow_mut();
                if slot.is_empty() { *slot = std::mem::take(&mut self.0); }
            });
        }
    }
}
#[derive(Clone, Copy, Default)]
pub struct BulkTimings {
    pub calls: u64,
    pub entries: u64,
    pub syscall_us: u64,
    pub max_syscall_us: u64,
    pub calls_ge_10ms: u64,
    pub buffers_allocated: u64,
    pub buffers_reused: u64,
}

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
    pub private_bytes: Option<u64>,
    pub modified_unix_ms: Option<i64>,
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
    include_modified: bool,
    fd: OwnedFd,
    buffer: Buffer,
    timings: BulkTimings,
    offset: usize,
    remaining: usize,
    started: bool,
    ended: bool,
}

impl BulkDirectory {
    pub fn new(fd: OwnedFd) -> Self {
        Self {
            include_modified: false,
            fd,
            buffer: Buffer(Vec::new()),
            timings: BulkTimings::default(),
            offset: 0,
            remaining: 0,
            started: false,
            ended: false,
        }
    }
    /// Full scans retain modification time for age-based review. Cache sizing
    /// keeps its smaller existing attribute request.
    pub fn with_modified_times(fd: OwnedFd) -> Self {
        let mut reader = Self::new(fd);
        reader.include_modified = true;
        reader
    }
    pub fn timings(&self) -> BulkTimings { self.timings }
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
                self.release_buffer();
                None
            }
            Err(error) => {
                self.ended = true;
                self.release_buffer();
                Some(Err(error))
            }
        }
    }

    fn release_buffer(&mut self) {
        drop(Buffer(std::mem::take(&mut self.buffer.0)));
    }

    fn read_entry(&mut self) -> io::Result<Option<BulkEntry>> {
        if self.remaining == 0 {
            // A drained parent batch must not pin storage while its child is
            // traversed. Borrow a thread-local spare only when reading a batch.
            if self.buffer.0.is_empty() {
                self.buffer = Buffer::default();
                #[cfg(debug_assertions)]
                if self.buffer.0.is_empty() { self.timings.buffers_allocated += 1; }
                else { self.timings.buffers_reused += 1; }
                self.buffer.0.resize(BUFFER_BYTES / 8, 0);
            }
            let mut attrs = libc::attrlist {
                bitmapcount: libc::ATTR_BIT_MAP_COUNT as u16,
                reserved: 0,
                commonattr: COMMON | if self.include_modified { libc::ATTR_CMN_MODTIME } else { 0 },
                volattr: 0,
                dirattr: DIRECTORY,
                fileattr: FILE,
                forkattr: PRIVATE,
            };
            // SAFETY: live owned descriptor; initialized attrlist; aligned,
            // writable 64 KiB allocation alive for this synchronous call.
            #[cfg(debug_assertions)]
            let syscall_started = std::time::Instant::now();
            let count = unsafe {
                libc::getattrlistbulk(
                    self.fd.as_raw_fd(),
                    (&mut attrs as *mut libc::attrlist).cast(),
                    self.buffer.0.as_mut_ptr().cast(),
                    BUFFER_BYTES,
                    EXTENDED,
                )
            };
            let error = (count < 0).then(io::Error::last_os_error);
            #[cfg(debug_assertions)]
            {
                self.timings.calls += 1;
                self.timings.entries += count.max(0) as u64;
                let elapsed = syscall_started.elapsed().as_micros().min(u64::MAX as u128) as u64;
                self.timings.syscall_us += elapsed;
                self.timings.max_syscall_us = self.timings.max_syscall_us.max(elapsed);
                self.timings.calls_ge_10ms += u64::from(elapsed >= 10_000);
            }
            if count < 0 {
                let error = error.expect("negative native result");
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
            unsafe { std::slice::from_raw_parts(self.buffer.0.as_ptr().cast::<u8>(), BUFFER_BYTES) };
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
        if self.remaining == 0 {
            // BulkEntry owns its name/metadata, so no returned record borrows
            // this allocation. Keep fd/cursor position and all EOF checks.
            self.release_buffer();
        }
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
    if common & !(COMMON | libc::ATTR_CMN_MODTIME) != 0
        || volume != 0
        || directory & !DIRECTORY != 0
        || file & !FILE != 0
        || fork & !PRIVATE != 0
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
    // Darwin's packed 64-bit timespec precedes ATTR_CMN_FLAGS.
    let modified_unix_ms = if common & libc::ATTR_CMN_MODTIME != 0 {
        let seconds = i64::from_ne_bytes(f.read()?);
        let nanos = i64::from_ne_bytes(f.read()?);
        if !(0..1_000_000_000).contains(&nanos) { return Err(invalid()); }
        seconds.checked_mul(1000).and_then(|v| v.checked_add(nanos / 1_000_000))
    } else { None };
    let flags = f.optional32(common & libc::ATTR_CMN_FLAGS != 0)?;
    let inode = f.optional64(common & libc::ATTR_CMN_FILEID != 0)?;
    let mount = f.optional32(directory & DIRECTORY != 0)?;
    let links = f.optional32(file & libc::ATTR_FILE_LINKCOUNT != 0)?;
    let allocated = f.optional64(file & libc::ATTR_FILE_ALLOCSIZE != 0)?;
    let logical = f.optional64(file & libc::ATTR_FILE_DATALENGTH != 0)?;
    let private = f.optional64(fork & PRIVATE != 0)?;
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
                    modified_unix_ms: (kind == BulkKind::File).then_some(modified_unix_ms).flatten(),
                    private_bytes: private.filter(|v| *v <= i64::MAX as u64 && kind == BulkKind::File && links == Some(1) && flags & 0x4000_0000 == 0),
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

    #[test]
    fn spare_buffer_is_initialized_exclusive_and_bounded() {
        SPARE_BUFFER.with(|slot| slot.borrow_mut().clear());
        let mut first = Buffer::default();
        first.0.resize(BUFFER_BYTES / 8, 17);
        let pointer = first.0.as_ptr();
        drop(first);
        let reused = Buffer::default();
        assert_eq!(reused.0.as_ptr(), pointer);
        assert!(reused.0.iter().all(|v| *v == 17));
        let mut other = Buffer::default();
        other.0.resize(BUFFER_BYTES / 8, 23);
        assert_ne!(other.0.as_ptr(), pointer);
        drop(reused);
        drop(other);
        SPARE_BUFFER.with(|slot| {
            let buffer = slot.borrow();
            assert_eq!(buffer.len(), BUFFER_BYTES / 8);
            assert!(buffer.iter().all(|v| *v == 17));
        });
    }


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

    fn timed_file_record(seconds: i64, nanos: i64) -> Vec<u8> {
        let mut record = file_record(true);
        record[4..8].copy_from_slice(&(COMMON | libc::ATTR_CMN_MODTIME).to_ne_bytes());
        let mut time = seconds.to_ne_bytes().to_vec();
        time.extend_from_slice(&nanos.to_ne_bytes());
        record.splice(44..44, time);
        let offset = i32::from_ne_bytes(record[28..32].try_into().unwrap()) + 16;
        record[28..32].copy_from_slice(&offset.to_ne_bytes());
        let length = record.len() as u32;
        record[..4].copy_from_slice(&length.to_ne_bytes());
        record
    }

    #[test]
    fn full_scan_time_preserves_packed_identity_and_sizes() {
        let entry = parse(&timed_file_record(123, 456_789_000)).unwrap();
        assert_eq!(entry.name, "item");
        let metadata = entry.metadata.unwrap().unwrap();
        assert_eq!(metadata.modified_unix_ms, Some(123456));
        assert_eq!((metadata.device, metadata.inode), (7, 11));
        assert_eq!(metadata.logical_bytes, Some(5));
        assert_eq!(metadata.allocated_bytes, Some(8192));
        assert_eq!(metadata.link_count, Some(2));
        assert_eq!(parse(&file_record(true)).unwrap().metadata.unwrap().unwrap().modified_unix_ms, None);
    }

    #[test]
    fn invalid_or_unrepresentable_times_never_become_a_valid_age() {
        assert!(parse(&timed_file_record(123, 1_000_000_000)).is_err());
        assert!(parse(&timed_file_record(123, -1)).is_err());
        assert_eq!(parse(&timed_file_record(-1, 500_000_000)).unwrap().metadata.unwrap().unwrap().modified_unix_ms, Some(-500));
        for seconds in [i64::MIN, i64::MAX] {
            assert_eq!(parse(&timed_file_record(seconds, 0)).unwrap().metadata.unwrap().unwrap().modified_unix_ms, None);
        }
        let mut truncated = timed_file_record(123, 0);
        truncated.truncate(50);
        assert!(parse(&truncated).is_err());
    }

    #[test]
    fn drained_batch_recycles_storage_without_releasing_descriptor_or_entries() {
        SPARE_BUFFER.with(|slot| slot.borrow_mut().clear());
        let temp = tempfile::tempdir().unwrap();
        let fd: OwnedFd = std::fs::File::open(temp.path()).unwrap().into();
        let mut reader = BulkDirectory::new(fd);
        assert!(reader.buffer.0.is_empty());
        let record = file_record(true);
        reader.buffer.0.resize(BUFFER_BYTES / 8, 0);
        for (word, bytes) in reader.buffer.0.iter_mut().zip(record.chunks_exact(8).chain(record.chunks_exact(8))) {
            *word = u64::from_ne_bytes(bytes.try_into().unwrap());
        }
        let pointer = reader.buffer.0.as_ptr();
        reader.remaining = 2;
        reader.started = true;
        let first = reader.next_entry().unwrap().unwrap();
        assert_eq!(reader.remaining, 1);
        assert!(!reader.buffer.0.is_empty());
        SPARE_BUFFER.with(|slot| assert!(slot.borrow().is_empty()));
        let second = reader.next_entry().unwrap().unwrap();
        assert_eq!(reader.remaining, 0);
        assert!(reader.buffer.0.is_empty());
        assert!(!reader.ended); // Draining a batch does not mean directory EOF.
        assert!(!reader.can_fallback());
        let mut spare = Buffer::default();
        assert_eq!(spare.0.as_ptr(), pointer);
        spare.0.fill(0); // Returned entries must own everything they expose.
        assert_eq!(first.name, "item");
        assert_eq!(second.metadata.unwrap().unwrap().logical_bytes, Some(5));
        let file = std::fs::File::from(reader.into_fd());
        assert!(file.metadata().unwrap().is_dir());
    }

    #[test]
    fn malformed_batch_recycles_storage_and_stays_terminal() {
        SPARE_BUFFER.with(|slot| slot.borrow_mut().clear());
        let temp = tempfile::tempdir().unwrap();
        let mut reader = BulkDirectory::new(std::fs::File::open(temp.path()).unwrap().into());
        reader.buffer.0.resize(BUFFER_BYTES / 8, 0); // Invalid zero record length.
        reader.remaining = 1;
        reader.started = true;
        assert!(reader.next_entry().unwrap().is_err());
        assert!(reader.buffer.0.is_empty());
        assert!(reader.ended);
        assert!(!reader.can_fallback());
        assert!(reader.next_entry().is_none());
        SPARE_BUFFER.with(|slot| assert_eq!(slot.borrow().len(), BUFFER_BYTES / 8));
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
    fn private_size_requires_returned_bit_and_single_link() {
        let record = file_record(true);
        assert_eq!(parse(&record).unwrap().metadata.unwrap().unwrap().private_bytes, None);
        let mut fields = record[..76].to_vec();
        fields[20..24].copy_from_slice(&PRIVATE.to_ne_bytes());
        fields[56..60].copy_from_slice(&1u32.to_ne_bytes());
        fields.extend_from_slice(&0u64.to_ne_bytes());
        let shared = finish(fields.clone(), 28);
        assert_eq!(parse(&shared).unwrap().metadata.unwrap().unwrap().private_bytes, Some(0));
        fields[76..84].copy_from_slice(&4096u64.to_ne_bytes());
        assert_eq!(parse(&finish(fields.clone(), 28)).unwrap().metadata.unwrap().unwrap().private_bytes, Some(4096));
        fields[56..60].copy_from_slice(&2u32.to_ne_bytes());
        assert_eq!(parse(&finish(fields, 28)).unwrap().metadata.unwrap().unwrap().private_bytes, None);
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


/// Optional metadata-only observation relative to an admitted directory. The
/// caller holds ReadOnlyPolicy. Does not open file contents or follow links.
pub fn private_size_at(fd: BorrowedFd<'_>, name: &std::ffi::CStr, device: u64, inode: u64) -> Option<u64> {
    unsafe extern "C" {
        fn getattrlistat(fd: libc::c_int, path: *const libc::c_char, attrs: *mut libc::attrlist,
            buffer: *mut libc::c_void, size: usize, options: libc::c_ulong) -> libc::c_int;
    }
    let common = libc::ATTR_CMN_RETURNED_ATTRS | libc::ATTR_CMN_DEVID | libc::ATTR_CMN_OBJTYPE
        | libc::ATTR_CMN_FLAGS | libc::ATTR_CMN_FILEID;
    let mut attrs = libc::attrlist { bitmapcount: 5, reserved: 0, commonattr: common,
        volattr: 0, dirattr: 0, fileattr: libc::ATTR_FILE_LINKCOUNT, forkattr: PRIVATE };
    let mut buffer = [0u64; 8];
    // SAFETY: admitted live FD, NUL-terminated component, initialized attrlist,
    // aligned writable buffer, and no-follow metadata flags. macOS 10.10+ API.
    let code = unsafe { getattrlistat(fd.as_raw_fd(), name.as_ptr(), &mut attrs,
        buffer.as_mut_ptr().cast(), 64, libc::FSOPT_NOFOLLOW as libc::c_ulong | EXTENDED) };
    if code != 0 { return None; }
    // SAFETY: fully initialized u64 storage, borrowed only during parsing.
    let bytes = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), 64) };
    let length = u32::from_ne_bytes(bytes[..4].try_into().ok()?) as usize;
    let mut f = Fields { bytes: bytes.get(..length)?, offset: 4 };
    if f.u32().ok()? != common || f.u32().ok()? != 0 || f.u32().ok()? != 0
        || f.u32().ok()? != libc::ATTR_FILE_LINKCOUNT || f.u32().ok()? != PRIVATE { return None; }
    if u64::from(f.u32().ok()?) != device || f.u32().ok()? != 1 { return None; }
    if f.u32().ok()? & 0x4000_0000 != 0 || f.u64().ok()? != inode || f.u32().ok()? != 1 { return None; }
    f.u64().ok().filter(|v| *v <= i64::MAX as u64)
}
