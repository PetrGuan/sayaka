// SPDX-License-Identifier: MPL-2.0

//! Bulk metadata for cache measurement and unrestricted full scans. Directory admission, open flags,
//! identity checks and modification stamps match the generic macOS cursor.
use super::*;
use sayaka_platform_macos::scan_bulk::{BulkDirectory, BulkKind, BulkMetadata};
use std::os::fd::BorrowedFd;
use std::sync::{Arc, atomic::AtomicU64};
#[cfg(debug_assertions)]
use std::sync::atomic::Ordering;

#[derive(Default)]
#[cfg_attr(not(debug_assertions), allow(dead_code))]
struct Timing {
    full_scan: Option<(PathBuf, std::time::Instant)>,
    opens: AtomicU64, open_us: AtomicU64, open_api_us: AtomicU64, max_open_api_us: AtomicU64, slow_opens: AtomicU64, capture_us: AtomicU64, volume_us: AtomicU64, checks: AtomicU64, check_us: AtomicU64,
    max_bulk_us: AtomicU64, slow_batches: AtomicU64, batches: AtomicU64, bulk_entries: AtomicU64, bulk_us: AtomicU64,
    allocated: AtomicU64, reused: AtomicU64, fallbacks: AtomicU64, stat_fallbacks: AtomicU64,
}
impl Drop for Timing {
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        if let Some((path, started)) = &self.full_scan {
            let n = |v: &AtomicU64| v.load(Ordering::Relaxed);
            eprintln!("[SayakaTraversal] event=native_summary path={:?} wall_us={} child_opens={} child_open_api_us={} max_open_api_us={} opens_ge_10ms={} capture_us={} checks={} check_us={} batches={} bulk_entries={} bulk_us={} max_bulk_us={} batches_ge_10ms={} legacy_fallbacks={} stat_fallbacks={}",
                path, started.elapsed().as_micros(), n(&self.opens), n(&self.open_api_us), n(&self.max_open_api_us), n(&self.slow_opens), n(&self.capture_us), n(&self.checks), n(&self.check_us), n(&self.batches), n(&self.bulk_entries), n(&self.bulk_us), n(&self.max_bulk_us), n(&self.slow_batches), n(&self.fallbacks), n(&self.stat_fallbacks));
        }
    }
}

impl Timing {
    #[cfg(debug_assertions)]
    fn opened(&self, started: std::time::Instant) {
        let elapsed = started.elapsed().as_micros().min(u64::MAX as u128) as u64;
        self.open_api_us.fetch_add(elapsed, Ordering::Relaxed);
        self.max_open_api_us.fetch_max(elapsed, Ordering::Relaxed);
        if elapsed >= 10_000 { self.slow_opens.fetch_add(1, Ordering::Relaxed); }
    }
    fn bulk(&self, _reader: &BulkDirectory) {
        #[cfg(debug_assertions)]
        {
        let reader = _reader;
        let t = reader.timings();
        self.max_bulk_us.fetch_max(t.max_syscall_us, Ordering::Relaxed);
        self.slow_batches.fetch_add(t.calls_ge_10ms, Ordering::Relaxed);
        for (counter, value) in [(&self.batches, t.calls), (&self.bulk_entries, t.entries),
            (&self.bulk_us, t.syscall_us), (&self.allocated, t.buffers_allocated), (&self.reused, t.buffers_reused)] {
            counter.fetch_add(value, Ordering::Relaxed);
        }
        }
    }
}


#[cfg_attr(not(debug_assertions), allow(dead_code))]
pub(super) struct CacheBackend { timing: Arc<Timing>, path: PathBuf, started: std::time::Instant }
impl CacheBackend {
    pub fn new(path: &Path) -> Self { Self { timing: Arc::new(Timing::default()), path: path.to_owned(), started: std::time::Instant::now() } }
}
impl Drop for CacheBackend {
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        {
            let t = &self.timing;
            let n = |v: &AtomicU64| v.load(Ordering::Relaxed);
            eprintln!("[SayakaSizing] event=native_summary path={:?} wall_us={} opens={} open_us={} open_api_us={} max_open_api_us={} opens_ge_10ms={} capture_us={} volume_us={} checks={} check_us={} batches={} bulk_entries={} bulk_us={} max_bulk_us={} batches_ge_10ms={} buffers_allocated={} buffers_reused={} legacy_fallbacks={} stat_fallbacks={}",
                self.path, self.started.elapsed().as_micros(), n(&t.opens), n(&t.open_us), n(&t.open_api_us), n(&t.max_open_api_us), n(&t.slow_opens), n(&t.capture_us), n(&t.volume_us), n(&t.checks), n(&t.check_us),
                n(&t.batches), n(&t.bulk_entries), n(&t.bulk_us), n(&t.max_bulk_us), n(&t.slow_batches), n(&t.allocated), n(&t.reused), n(&t.fallbacks), n(&t.stat_fallbacks));
        }
    }
}
impl Backend for CacheBackend {
    type Directory = CacheDirectory;
    type Policy = NativePolicy;
    fn enter_thread(&self) -> Result<NativePolicy, ScanError> {
        MacBackend.enter_thread()
    }
    fn open_root(&self, path: &Path) -> Result<CacheDirectory, ScanError> {
        #[cfg(debug_assertions)]
        let started = std::time::Instant::now();
        let result = (|| {
            let fd = fs::open(path, directory_flags(), Mode::empty()).map_err(native_error);
            #[cfg(debug_assertions)]
            self.timing.opened(started);
            let fd = fd?;
            #[cfg(debug_assertions)]
            let volume_started = std::time::Instant::now();
            let volume = validate_local_internal_volume_fd(&fd);
            #[cfg(debug_assertions)]
            self.timing.volume_us.fetch_add(volume_started.elapsed().as_micros() as u64, Ordering::Relaxed);
            volume?;
            CacheDirectory::from_fd(fd, Arc::clone(&self.timing))
        })();
        #[cfg(debug_assertions)]
        {
            self.timing.opens.fetch_add(1, Ordering::Relaxed);
            self.timing.open_us.fetch_add(started.elapsed().as_micros() as u64, Ordering::Relaxed);
        }
        result
    }
}

enum Reader {
    Bulk(BulkDirectory),
    Legacy(MacDirectory),
    Failed,
}

pub(super) struct CacheDirectory {
    timing: Arc<Timing>,
    reader: Reader,
    original: Metadata,
    stamp: Stamp,
}
// Held by the calling backend until all traversal workers have joined. Never
// print from a worker destructor: the CLI can hold stderr on its caller thread.
pub(super) struct FullScanTiming { _timing: Arc<Timing> }

impl CacheDirectory {
    pub(super) fn for_full_scan(fd: OwnedFd, path: &Path) -> Result<(Self, FullScanTiming), ScanError> {
        let mut timing = Timing::default();
        timing.full_scan = Some((path.to_owned(), std::time::Instant::now()));
        let timing = Arc::new(timing);
        let directory = Self::from_fd(fd, Arc::clone(&timing))?;
        Ok((directory, FullScanTiming { _timing: timing }))
    }

    fn from_fd(fd: OwnedFd, timing: Arc<Timing>) -> Result<Self, ScanError> {
        #[cfg(debug_assertions)]
        let started = std::time::Instant::now();
        let stat = fs::fstat(&fd).map_err(native_error);
        #[cfg(debug_assertions)]
        timing.capture_us.fetch_add(started.elapsed().as_micros() as u64, Ordering::Relaxed);
        let stat = stat?;
        let original = from_stat(&stat);
        if original.dataless {
            return Err(ScanError::new(
                ScanCode::CloudDirectorySkipped,
                "dataless directory cannot be enumerated",
            ));
        }
        Ok(Self {
            timing: Arc::clone(&timing),
            reader: Reader::Bulk(if timing.full_scan.is_some() { BulkDirectory::with_modified_times(fd) } else { BulkDirectory::new(fd) }),
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
        self.timing.bulk(&reader);
        #[cfg(debug_assertions)]
        self.timing.fallbacks.fetch_add(1, Ordering::Relaxed);
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
impl Drop for CacheDirectory {
    fn drop(&mut self) {
        if let Reader::Bulk(reader) = &self.reader { self.timing.bulk(reader); }
    }
}
impl Cursor for CacheDirectory {
    fn bare_repository(&self) -> Result<bool, ScanError> {
        bare_repository_at(self.fd()?, &self.original)
    }
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
                #[cfg(debug_assertions)]
                self.timing.stat_fallbacks.fetch_add(1, Ordering::Relaxed);
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
        #[cfg(debug_assertions)]
        let started = std::time::Instant::now();
        let result = (|| {
            let fd = fs::openat(self.fd()?, &item.name, directory_flags(), Mode::empty()).map_err(native_error);
            #[cfg(debug_assertions)]
            self.timing.opened(started);
            let fd = fd?;
            Self::from_fd(fd, Arc::clone(&self.timing))
        })();
        #[cfg(debug_assertions)]
        {
            self.timing.opens.fetch_add(1, Ordering::Relaxed);
            self.timing.open_us.fetch_add(started.elapsed().as_micros() as u64, Ordering::Relaxed);
        }
        result
    }
    fn unchanged(&self) -> Result<bool, ScanError> {
        #[cfg(debug_assertions)]
        let started = std::time::Instant::now();
        let result = (|| {
            let stat = fs::fstat(self.fd()?).map_err(native_error)?;
            Ok(stamp(&stat) == self.stamp && from_stat(&stat).identity == self.original.identity)
        })();
        #[cfg(debug_assertions)]
        {
            self.timing.checks.fetch_add(1, Ordering::Relaxed);
            self.timing.check_us.fetch_add(started.elapsed().as_micros() as u64, Ordering::Relaxed);
        }
        result
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
        private_bytes: value.private_bytes,
        identity: FileIdentity::Unix {
            device: value.device,
            inode: value.inode,
        },
        kind,
        logical_bytes: regular.then_some(value.logical_bytes).flatten(),
        allocated_bytes: regular.then_some(value.allocated_bytes).flatten(),
        link_count: value.link_count,
        modified_unix_ms: value.modified_unix_ms,
        dataless: value.flags & 0x4000_0000 != 0,
    })
}
