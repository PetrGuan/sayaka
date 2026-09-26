// SPDX-License-Identifier: MPL-2.0

//! Narrow v1 C ABI for scan, installer and purge tasks. See include/sayaka.h.
//! Foreign pointer validity is the caller's responsibility; errors cannot
//! recover invalid memory. No callbacks, signals or CLI children.

#![deny(unsafe_op_in_unsafe_fn)]

mod browse;
pub use browse::*;
mod ai_footprint;
pub use ai_footprint::*;
mod diagnostics;
pub use diagnostics::*;
mod exclusions;
pub use exclusions::*;
mod installer;
pub use installer::*;
mod maintenance_catalog;
pub use maintenance_catalog::*;
mod purge;
pub use purge::*;
mod system_status;
pub use system_status::*;
mod uninstall;
pub use uninstall::*;

use sayaka_engine::scan::index::ScanTree;
use sayaka_engine::scan::task::{ScanTask, ScanTaskState};
use sayaka_engine::scan::{ScanCode, ScanLimits, wire};
use std::collections::HashMap;
use std::ffi::c_char;
use std::io::{self, Write};
use std::mem::{align_of, size_of};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, TryLockError};

pub const ABI_VERSION: u32 = 1;
pub const MAX_TASKS: usize = 4;
pub const MAX_RESULT_BYTES: usize = 64 * 1024 * 1024;
pub const OK: i32 = 0;
pub const INVALID_ARGUMENT: i32 = 1;
pub const UNSUPPORTED_VERSION: i32 = 2;
pub const UNSUPPORTED_PLATFORM: i32 = 3;
pub const INVALID_HANDLE: i32 = 4;
pub const LIMIT_EXCEEDED: i32 = 5;
pub const NOT_READY: i32 = 6;
pub const BUFFER_TOO_SMALL: i32 = 7;
pub const BUSY: i32 = 8;
pub const INTERNAL_ERROR: i32 = 9;
pub const PANIC: i32 = 10;
pub const INVALID_NODE: i32 = 11;
pub const NOT_DIRECTORY: i32 = 12;
pub const QUERY_UNAVAILABLE: i32 = 13;
pub const INVALID_CANDIDATE: i32 = 14;

pub const UNIX_BYTES: u32 = 1;
pub const WINDOWS_UTF16LE: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SayakaPathV1 {
    pub encoding: u32,
    pub bytes: *const u8,
    pub byte_length: usize,
}

#[repr(C)]
pub struct SayakaScanRequestV1 {
    pub abi_version: u32,
    pub struct_size: u32,
    pub roots: *const SayakaPathV1,
    pub root_count: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SayakaScanSnapshotV1 {
    pub abi_version: u32,
    pub struct_size: u32,
    pub state: u32,
    pub cancellation_requested: u32,
    pub has_progress: u32,
    pub reserved: u32,
    pub progress_sequence: u64,
    pub observed_entries: u64,
    pub unique_files: u64,
    pub logical_bytes_known: u64,
    pub observed_issues: u64,
    pub elapsed_ms: u64,
}

struct Job {
    task: ScanTask,
    result: Option<Result<Vec<u8>, i32>>,
    tree: Option<Result<ScanTree, i32>>,
    largest_files: [Option<browse::LargestFilesOrder>; 2],
    closed: bool,
}

struct Registry {
    next_handle: u64,
    jobs: HashMap<u64, Arc<Mutex<Job>>>,
    installers: HashMap<u64, Arc<Mutex<installer::InstallerJob>>>,
    purges: HashMap<u64, Arc<Mutex<purge::PurgeJob>>>,
    uninstalls: HashMap<u64, Arc<Mutex<uninstall::UninstallJob>>>,
}

impl Registry {
    fn allocate_handle(&mut self) -> Result<u64, i32> {
        if self.jobs.len() + self.installers.len() + self.purges.len() + self.uninstalls.len()
            >= MAX_TASKS
        {
            return Err(LIMIT_EXCEEDED);
        }
        let handle = self.next_handle;
        self.next_handle = handle.checked_add(1).ok_or(LIMIT_EXCEEDED)?;
        Ok(handle)
    }
}

fn registry() -> &'static Mutex<Registry> {
    static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        Mutex::new(Registry {
            next_handle: 1,
            jobs: HashMap::new(),
            installers: HashMap::new(),
            purges: HashMap::new(),
            uninstalls: HashMap::new(),
        })
    })
}

fn boundary(action: impl FnOnce() -> Result<(), i32>) -> i32 {
    match catch_unwind(AssertUnwindSafe(action)) {
        Ok(Ok(())) => OK,
        Ok(Err(code)) => code,
        Err(payload) => {
            // A user-defined panic payload destructor can itself panic.
            std::mem::forget(payload);
            PANIC
        }
    }
}

fn pointer<T>(ptr: *const T) -> Result<(), i32> {
    if ptr.is_null() || !(ptr as usize).is_multiple_of(align_of::<T>()) {
        Err(INVALID_ARGUMENT)
    } else {
        Ok(())
    }
}

fn get(handle: u64) -> Result<Arc<Mutex<Job>>, i32> {
    registry()
        .lock()
        .map_err(|_| INTERNAL_ERROR)?
        .jobs
        .get(&handle)
        .cloned()
        .ok_or(INVALID_HANDLE)
}

fn ensure_open(job: &Job) -> Result<(), i32> {
    if job.closed {
        Err(INVALID_HANDLE)
    } else {
        Ok(())
    }
}

fn lock_job<T>(slot: &Mutex<T>) -> Result<MutexGuard<'_, T>, i32> {
    slot.try_lock().map_err(|error| match error {
        TryLockError::WouldBlock => BUSY,
        TryLockError::Poisoned(_) => INTERNAL_ERROR,
    })
}

unsafe fn decode_path(path: SayakaPathV1) -> Result<PathBuf, i32> {
    pointer(path.bytes)?;
    if path.byte_length == 0 || path.byte_length > 65_536 {
        return Err(INVALID_ARGUMENT);
    }
    // SAFETY: The caller supplies readable input for the bounded length. No
    // borrowed input survives start; the native OsString is copied below.
    let bytes = unsafe { std::slice::from_raw_parts(path.bytes, path.byte_length) };
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        if path.encoding != UNIX_BYTES || bytes.contains(&0) {
            return Err(INVALID_ARGUMENT);
        }
        Ok(std::ffi::OsString::from_vec(bytes.to_vec()).into())
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        if path.encoding != WINDOWS_UTF16LE || !bytes.len().is_multiple_of(2) {
            return Err(INVALID_ARGUMENT);
        }
        let units = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        if units.contains(&0) {
            return Err(INVALID_ARGUMENT);
        }
        Ok(std::ffi::OsString::from_wide(&units).into())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = bytes;
        Err(UNSUPPORTED_PLATFORM)
    }
}

/// Returns the ABI version implemented by these explicitly versioned symbols.
#[unsafe(no_mangle)]
pub extern "C" fn sayaka_abi_version_v1() -> u32 {
    ABI_VERSION
}

/// Returns a static UTF-8 status description, never caller-owned memory.
#[unsafe(no_mangle)]
pub extern "C" fn sayaka_status_message_v1(code: i32) -> *const c_char {
    match code {
        OK => c"ok",
        INVALID_ARGUMENT => c"invalid pointer, path, encoding, or argument",
        UNSUPPORTED_VERSION => c"unsupported ABI version or structure size",
        UNSUPPORTED_PLATFORM => c"requested native operation is unavailable on this platform",
        INVALID_HANDLE => c"unknown, released, or wrong-kind task handle",
        LIMIT_EXCEEDED => c"task, input, or result resource limit exceeded",
        NOT_READY => c"task result is not ready",
        BUFFER_TOO_SMALL => c"caller buffer is too small; consult required bytes",
        BUSY => c"task or concurrent handle operation is busy; retain handle and retry later",
        INTERNAL_ERROR => c"internal task, state, or output failure",
        PANIC => c"Rust panic contained at the native boundary",
        INVALID_NODE => c"unknown node or node reference belongs to another scan handle",
        NOT_DIRECTORY => c"node is not an observed directory",
        QUERY_UNAVAILABLE => c"task failed; inspect its result for details",
        INVALID_CANDIDATE => c"unknown, duplicate, stale, or cross-task candidate/item reference",
        _ => c"unknown status code",
    }
    .as_ptr()
}

/// Copies native roots and starts a read-only task using default scan limits.
///
/// # Safety
/// Request and roots must reference readable properly aligned v1 structures.
/// Each path must be readable for byte_length. out_handle must be writable and
/// non-overlapping with inputs for the call. Inputs may be released on return.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_scan_start_v1(
    request: *const SayakaScanRequestV1,
    out_handle: *mut u64,
) -> i32 {
    boundary(|| {
        pointer(out_handle)?;
        // SAFETY: The caller owns the aligned writable output slot.
        unsafe {
            out_handle.write(0);
        }
        pointer(request)?;
        // SAFETY: The caller supplies a valid request structure for this call.
        let request = unsafe { &*request };
        if request.abi_version != ABI_VERSION
            || request.struct_size as usize != size_of::<SayakaScanRequestV1>()
        {
            return Err(UNSUPPORTED_VERSION);
        }
        if !cfg!(any(target_os = "macos", windows)) {
            return Err(UNSUPPORTED_PLATFORM);
        }
        if request.root_count == 0 || request.root_count > 64 {
            return Err(INVALID_ARGUMENT);
        }
        pointer(request.roots)?;
        // SAFETY: root_count is bounded and caller provides that many structures.
        let roots = unsafe { std::slice::from_raw_parts(request.roots, request.root_count) };
        let roots = roots
            .iter()
            .map(|path| unsafe { decode_path(*path) })
            .collect::<Result<Vec<_>, _>>()?;
        let mut registry = registry().lock().map_err(|_| INTERNAL_ERROR)?;
        let handle = registry.allocate_handle()?;
        let task =
            ScanTask::start(roots, ScanLimits::default()).map_err(|error| match error.code {
                ScanCode::InvalidRoot | ScanCode::InvalidLimits => INVALID_ARGUMENT,
                ScanCode::UnsupportedPlatform => UNSUPPORTED_PLATFORM,
                _ => INTERNAL_ERROR,
            })?;
        registry.jobs.insert(
            handle,
            Arc::new(Mutex::new(Job {
                task,
                result: None,
                tree: None,
                largest_files: Default::default(),
                closed: false,
            })),
        );
        // SAFETY: The output is writable and remains valid until return.
        unsafe {
            out_handle.write(handle);
        }
        Ok(())
    })
}

/// Retrieves the latest coalesced progress/lifecycle, not a queue of callbacks.
///
/// # Safety
/// out_snapshot must be aligned, writable v1 storage with no concurrent access.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_scan_poll_v1(
    handle: u64,
    out_snapshot: *mut SayakaScanSnapshotV1,
) -> i32 {
    boundary(|| {
        pointer(out_snapshot)?;
        // SAFETY: Caller supplies valid writable output, initialized on failures.
        unsafe {
            out_snapshot.write(SayakaScanSnapshotV1::default());
        }
        let slot = get(handle)?;
        let mut job = lock_job(&slot)?;
        ensure_open(&job)?;
        let snapshot = job.task.poll().map_err(|_| INTERNAL_ERROR)?;
        let mut out = SayakaScanSnapshotV1 {
            abi_version: ABI_VERSION,
            struct_size: size_of::<SayakaScanSnapshotV1>() as u32,
            state: match snapshot.state {
                ScanTaskState::Running => 1,
                ScanTaskState::Complete => 2,
                ScanTaskState::Partial => 3,
                ScanTaskState::Cancelled => 4,
                ScanTaskState::Failed => 5,
            },
            cancellation_requested: u32::from(snapshot.cancellation_requested),
            progress_sequence: snapshot.progress_sequence,
            ..Default::default()
        };
        if let Some(progress) = snapshot.progress {
            out.has_progress = 1;
            out.observed_entries = progress.entries as u64;
            out.unique_files = progress.unique_files;
            out.logical_bytes_known = progress.logical_bytes_known;
            out.observed_issues = progress.issues as u64;
            out.elapsed_ms = progress.elapsed_ms;
        }
        // SAFETY: Output structure is valid for one complete write.
        unsafe {
            out_snapshot.write(out);
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn sayaka_scan_cancel_v1(handle: u64) -> i32 {
    boundary(|| {
        let slot = get(handle)?;
        let job = lock_job(&slot)?;
        ensure_open(&job)?;
        job.task.cancel();
        Ok(())
    })
}

struct LimitedBuffer {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

fn bounded_json(value: &impl serde::Serialize, limit: usize) -> Result<Vec<u8>, i32> {
    let mut writer = LimitedBuffer {
        bytes: Vec::new(),
        limit,
        exceeded: false,
    };
    match serde_json::to_writer(&mut writer, value) {
        Ok(()) => Ok(writer.bytes),
        Err(_) if writer.exceeded => Err(LIMIT_EXCEEDED),
        Err(_) => Err(INTERNAL_ERROR),
    }
}

#[cfg(test)]
static NATIVE_TEST_LOCK: Mutex<()> = Mutex::new(());

impl Write for LimitedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self
            .bytes
            .len()
            .checked_add(bytes.len())
            .is_none_or(|size| size > self.limit)
        {
            self.exceeded = true;
            return Err(io::Error::other("native result byte limit exceeded"));
        }
        self.bytes
            .try_reserve(bytes.len())
            .map_err(io::Error::other)?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn result_bytes(job: &mut Job) -> Result<&[u8], i32> {
    if job.result.is_none() {
        let outcome = job.task.result().ok_or(NOT_READY)?;
        let mut writer = LimitedBuffer {
            bytes: Vec::new(),
            limit: MAX_RESULT_BYTES,
            exceeded: false,
        };
        let written = match outcome {
            Ok(report) => wire::report(&mut writer, report),
            Err(error) => wire::fatal(&mut writer, error),
        };
        job.result = Some(match written {
            Ok(()) => Ok(writer.bytes),
            Err(_) if writer.exceeded => Err(LIMIT_EXCEEDED),
            Err(_) => Err(INTERNAL_ERROR),
        });
    }
    match job.result.as_ref().expect("initialized result cache") {
        Ok(bytes) => Ok(bytes),
        Err(code) => Err(*code),
    }
}

/// Copies shared v1 report/fatal JSON to caller storage, with no trailing NUL.
/// Query with buffer=null, capacity=0; BUFFER_TOO_SMALL returns required length.
///
/// # Safety
/// required is writable/aligned. A nonzero-capacity buffer is writable for that
/// capacity and cannot overlap required or be accessed concurrently by the host.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_scan_result_v1(
    handle: u64,
    buffer: *mut u8,
    capacity: usize,
    required: *mut usize,
) -> i32 {
    boundary(|| {
        // SAFETY: The caller supplies non-overlapping writable output storage.
        unsafe { prepare_output(buffer, capacity, required, MAX_RESULT_BYTES)? };
        let slot = get(handle)?;
        let mut job = lock_job(&slot)?;
        ensure_open(&job)?;
        let bytes = result_bytes(&mut job)?;
        // SAFETY: Output was validated above; bytes are privately owned.
        unsafe { copy_output(bytes, buffer, capacity, required) }
    })
}

unsafe fn prepare_output(
    buffer: *mut u8,
    capacity: usize,
    required: *mut usize,
    limit: usize,
) -> Result<(), i32> {
    pointer(required)?;
    // SAFETY: Caller-provided aligned output slot.
    unsafe { required.write(0) };
    if capacity > limit {
        return Err(INVALID_ARGUMENT);
    }
    if capacity > 0 {
        pointer(buffer)?;
    }
    Ok(())
}

unsafe fn copy_output(
    bytes: &[u8],
    buffer: *mut u8,
    capacity: usize,
    required: *mut usize,
) -> Result<(), i32> {
    // SAFETY: prepare_output validated the caller-provided output slot.
    unsafe { required.write(bytes.len()) };
    if capacity < bytes.len() {
        return Err(BUFFER_TOO_SMALL);
    }
    if !bytes.is_empty() {
        pointer(buffer)?;
        // SAFETY: Caller provides sufficient non-overlapping writable storage.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, bytes.len()) };
    }
    Ok(())
}

/// Cancels active work and returns BUSY until it exits; retry with the same
/// handle. OK invalidates the handle. Never unload the library with live handles.
#[unsafe(no_mangle)]
pub extern "C" fn sayaka_scan_release_v1(handle: u64) -> i32 {
    boundary(|| {
        let slot = get(handle)?;
        // A poisoned job may still own work: release is its explicit cleanup
        // path after INTERNAL_ERROR/PANIC, not permission to reuse its result.
        let mut job = match slot.try_lock() {
            Ok(job) => job,
            Err(TryLockError::WouldBlock) => return Err(BUSY),
            Err(TryLockError::Poisoned(poison)) => poison.into_inner(),
        };
        ensure_open(&job)?;
        if !job.task.is_finished() {
            job.task.cancel();
            return Err(BUSY);
        }
        job.task.result();
        job.closed = true;
        registry()
            .lock()
            .map_err(|_| INTERNAL_ERROR)?
            .jobs
            .remove(&handle)
            .ok_or(INVALID_HANDLE)?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_version_pointer_and_stale_handle_errors_are_explicit() {
        assert_eq!(sayaka_abi_version_v1(), 1);
        let mut handle = 99;
        assert_eq!(
            unsafe { sayaka_scan_start_v1(std::ptr::null(), &mut handle) },
            INVALID_ARGUMENT
        );
        assert_eq!(handle, 0);
        let request = SayakaScanRequestV1 {
            abi_version: 2,
            struct_size: size_of::<SayakaScanRequestV1>() as u32,
            roots: std::ptr::null(),
            root_count: 0,
        };
        assert_eq!(
            unsafe { sayaka_scan_start_v1(&request, &mut handle) },
            UNSUPPORTED_VERSION
        );
        assert_eq!(sayaka_scan_cancel_v1(0), INVALID_HANDLE);
        assert_eq!(sayaka_scan_release_v1(u64::MAX), INVALID_HANDLE);
        let mut snapshot = SayakaScanSnapshotV1::default();
        assert_eq!(
            unsafe { sayaka_scan_poll_v1(0, &mut snapshot) },
            INVALID_HANDLE
        );
        assert_eq!(snapshot.state, 0);
        let mut required = 99;
        assert_eq!(
            unsafe { sayaka_scan_result_v1(0, std::ptr::null_mut(), 0, &mut required) },
            INVALID_HANDLE
        );
        assert_eq!(required, 0);
    }

    #[test]
    fn result_writer_refuses_truncation_and_boundary_contains_panics() {
        let mut writer = LimitedBuffer {
            bytes: vec![],
            limit: 3,
            exceeded: false,
        };
        writer.write_all(b"abc").unwrap();
        assert!(writer.write_all(b"d").is_err());
        assert!(writer.exceeded);
        assert_eq!(writer.bytes, b"abc");
        assert_eq!(boundary(|| panic!("injected ABI panic")), PANIC);
    }

    #[cfg(unix)]
    #[test]
    fn native_path_bytes_are_lossless_and_wrong_encoding_is_rejected() {
        use std::os::unix::ffi::OsStrExt;
        let bytes = b"/fixture/\xff";
        let path = SayakaPathV1 {
            encoding: UNIX_BYTES,
            bytes: bytes.as_ptr(),
            byte_length: bytes.len(),
        };
        assert_eq!(
            unsafe { decode_path(path) }.unwrap().as_os_str().as_bytes(),
            bytes
        );
        assert_eq!(
            unsafe {
                decode_path(SayakaPathV1 {
                    encoding: WINDOWS_UTF16LE,
                    ..path
                })
            }
            .unwrap_err(),
            INVALID_ARGUMENT
        );
        assert_eq!(
            unsafe {
                decode_path(SayakaPathV1 {
                    byte_length: 0,
                    ..path
                })
            }
            .unwrap_err(),
            INVALID_ARGUMENT
        );
    }

    #[test]
    fn abi_layout_and_invalid_request_bounds_match_the_header() {
        assert_eq!(size_of::<SayakaScanSnapshotV1>(), 72);
        assert_eq!(
            std::mem::offset_of!(SayakaScanSnapshotV1, progress_sequence),
            24
        );
        if size_of::<usize>() == 8 {
            assert_eq!(size_of::<SayakaPathV1>(), 24);
            assert_eq!(size_of::<SayakaScanRequestV1>(), 24);
        }
        let mut handle = 99;
        let mut request = SayakaScanRequestV1 {
            abi_version: ABI_VERSION,
            struct_size: size_of::<SayakaScanRequestV1>() as u32,
            roots: std::ptr::null(),
            root_count: 65,
        };
        assert_eq!(
            unsafe { sayaka_scan_start_v1(&request, &mut handle) },
            if cfg!(any(target_os = "macos", windows)) {
                INVALID_ARGUMENT
            } else {
                UNSUPPORTED_PLATFORM
            }
        );
        assert_eq!(handle, 0);
        request.struct_size -= 1;
        assert_eq!(
            unsafe { sayaka_scan_start_v1(&request, &mut handle) },
            UNSUPPORTED_VERSION
        );
        let mut required = 99;
        assert_eq!(
            unsafe { sayaka_scan_result_v1(0, std::ptr::null_mut(), 1, &mut required) },
            INVALID_ARGUMENT
        );
        assert_eq!(required, 0);
    }

    #[cfg(windows)]
    #[test]
    fn windows_paths_preserve_unpaired_native_utf16() {
        use std::os::windows::ffi::OsStrExt;
        let units = [b'C' as u16, b':' as u16, b'\\' as u16, 0xd800];
        let bytes = units
            .iter()
            .flat_map(|unit| unit.to_le_bytes())
            .collect::<Vec<_>>();
        let path = SayakaPathV1 {
            encoding: WINDOWS_UTF16LE,
            bytes: bytes.as_ptr(),
            byte_length: bytes.len(),
        };
        assert_eq!(
            unsafe { decode_path(path) }
                .unwrap()
                .as_os_str()
                .encode_wide()
                .collect::<Vec<_>>(),
            units
        );
        assert_eq!(
            unsafe {
                decode_path(SayakaPathV1 {
                    byte_length: bytes.len() - 1,
                    ..path
                })
            }
            .unwrap_err(),
            INVALID_ARGUMENT
        );
        assert_eq!(
            unsafe {
                decode_path(SayakaPathV1 {
                    encoding: UNIX_BYTES,
                    ..path
                })
            }
            .unwrap_err(),
            INVALID_ARGUMENT
        );
    }
}
