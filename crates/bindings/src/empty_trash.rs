// SPDX-License-Identifier: MPL-2.0
//! Synchronous, bounded calls. Hosts must call away from their main/UI thread.
use super::*;
#[cfg(target_os = "macos")]
use sayaka_engine::empty_trash::{EmptyTrashSession, FinderObservation, FinishInput, SourceInput};
#[repr(C)]
pub struct SayakaEmptyTrashRequestV1 {
    pub abi_version: u32,
    pub struct_size: u32,
    pub handle: u64,
    pub json: *const u8,
    pub json_length: usize,
    pub reserved: u64,
}
pub(super) struct EmptyTrashJob {
    #[cfg(target_os = "macos")]
    session: EmptyTrashSession,
    bytes: Vec<u8>,
    closed: bool,
}
const INPUT_LIMIT: usize = 128 * 1024;
const OUTPUT_LIMIT: usize = 8 * 1024 * 1024;
unsafe fn request<'a>(
    r: *const SayakaEmptyTrashRequestV1,
) -> Result<&'a SayakaEmptyTrashRequestV1, i32> {
    pointer(r)?;
    let r = unsafe { &*r };
    if r.abi_version != 1
        || r.struct_size as usize != size_of::<SayakaEmptyTrashRequestV1>()
        || r.reserved != 0
    {
        return Err(UNSUPPORTED_VERSION);
    }
    if !cfg!(target_os = "macos") {
        return Err(UNSUPPORTED_PLATFORM);
    }
    if r.json_length == 0 || r.json_length > INPUT_LIMIT {
        return Err(INVALID_ARGUMENT);
    }
    pointer(r.json)?;
    Ok(r)
}
#[cfg(target_os = "macos")]
unsafe fn input<T: serde::de::DeserializeOwned>(r: &SayakaEmptyTrashRequestV1) -> Result<T, i32> {
    serde_json::from_slice(unsafe { std::slice::from_raw_parts(r.json, r.json_length) })
        .map_err(|_| INVALID_ARGUMENT)
}
fn get(handle: u64) -> Result<Arc<Mutex<EmptyTrashJob>>, i32> {
    registry()
        .lock()
        .map_err(|_| INTERNAL_ERROR)?
        .empty_trash
        .get(&handle)
        .cloned()
        .ok_or(INVALID_HANDLE)
}
#[cfg(target_os = "macos")]
fn failure(job: &mut EmptyTrashJob, e: std::io::Error) -> Result<(), i32> {
    job.bytes = bounded_json(
        &serde_json::json!({"kind":"sayaka_empty_trash_error","schema_version":1,"message":e.to_string().chars().take(512).collect::<String>(),"effects_confirmed":false}),
        OUTPUT_LIMIT,
    )?;
    Err(NOT_READY)
}
/// # Safety
/// Readable aligned request and input bytes; writable aligned output handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_empty_trash_preview_v1(
    r: *const SayakaEmptyTrashRequestV1,
    out: *mut u64,
) -> i32 {
    boundary(|| {
        pointer(out)?;
        unsafe { out.write(0) };
        let r = unsafe { request(r)? };
        if r.handle != 0 {
            return Err(INVALID_ARGUMENT);
        }
        #[cfg(target_os = "macos")]
        {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Input {
                sources: Vec<SourceInput>,
                #[serde(deserialize_with = "required_option")]
                finder: Option<FinderObservation>,
            }
            let i: Input = unsafe { input(r)? };
            let session = EmptyTrashSession::prepare(i.sources, i.finder).map_err(|_| NOT_READY)?;
            let bytes = bounded_json(session.preview(), OUTPUT_LIMIT)?;
            let mut registry = registry().lock().map_err(|_| INTERNAL_ERROR)?;
            let h = registry.allocate_handle()?;
            registry.empty_trash.insert(
                h,
                Arc::new(Mutex::new(EmptyTrashJob {
                    session,
                    bytes,
                    closed: false,
                })),
            );
            unsafe { out.write(h) };
            Ok(())
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(UNSUPPORTED_PLATFORM)
        }
    })
}
/// # Safety
/// Readable aligned request and input bytes. The live preview is single-use.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_empty_trash_begin_v1(r: *const SayakaEmptyTrashRequestV1) -> i32 {
    boundary(|| {
        let r = unsafe { request(r)? };
        let slot = get(r.handle)?;
        let mut job = slot.try_lock().map_err(|e| match e {
            TryLockError::WouldBlock => BUSY,
            _ => INTERNAL_ERROR,
        })?;
        if job.closed {
            return Err(INVALID_HANDLE);
        }
        #[cfg(target_os = "macos")]
        {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Input {
                plan_digest: String,
                approval_token: String,
                finder: FinderObservation,
            }
            let i: Input = unsafe { input(r)? };
            match job
                .session
                .begin(&i.plan_digest, &i.approval_token, i.finder)
            {
                Ok(p) => {
                    job.bytes = bounded_json(&p, OUTPUT_LIMIT)?;
                    Ok(())
                }
                Err(e) => failure(&mut job, e),
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(UNSUPPORTED_PLATFORM)
        }
    })
}
/// # Safety
/// Writable aligned milliseconds. OK consumes the single dispatch permit.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_empty_trash_claim_dispatch_v1(
    handle: u64,
    remaining_milliseconds: *mut u64,
) -> i32 {
    boundary(|| {
        pointer(remaining_milliseconds)?;
        unsafe { remaining_milliseconds.write(0) };
        if !cfg!(target_os = "macos") {
            return Err(UNSUPPORTED_PLATFORM);
        }
        let slot = get(handle)?;
        let mut job = slot.try_lock().map_err(|_| BUSY)?;
        if job.closed {
            return Err(INVALID_HANDLE);
        }
        #[cfg(target_os = "macos")]
        {
            match job.session.claim_dispatch() {
                Ok(ms) => {
                    unsafe { remaining_milliseconds.write(ms) };
                    Ok(())
                }
                Err(e) => failure(&mut job, e),
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(UNSUPPORTED_PLATFORM)
        }
    })
}
/// # Safety
/// Readable aligned request/input. Finish never sends or retries an event.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_empty_trash_finish_v1(r: *const SayakaEmptyTrashRequestV1) -> i32 {
    boundary(|| {
        let r = unsafe { request(r)? };
        let slot = get(r.handle)?;
        let mut job = slot.try_lock().map_err(|_| BUSY)?;
        if job.closed {
            return Err(INVALID_HANDLE);
        }
        #[cfg(target_os = "macos")]
        {
            let i: FinishInput = unsafe { input(r)? };
            match job.session.finish(i) {
                Ok(record) => {
                    job.bytes = bounded_json(record, OUTPUT_LIMIT)?;
                    Ok(())
                }
                Err(e) => failure(&mut job, e),
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(UNSUPPORTED_PLATFORM)
        }
    })
}
/// # Safety
/// Same two-call buffer convention as scan_result; copies current preview,
/// permit, durable receipt, or failure. No result bytes restore authorization.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_empty_trash_result_v1(
    handle: u64,
    buffer: *mut u8,
    capacity: usize,
    required: *mut usize,
) -> i32 {
    boundary(|| {
        unsafe { prepare_output(buffer, capacity, required, OUTPUT_LIMIT)? };
        if !cfg!(target_os = "macos") {
            return Err(UNSUPPORTED_PLATFORM);
        }
        let slot = get(handle)?;
        let job = slot.try_lock().map_err(|_| BUSY)?;
        if job.closed {
            return Err(INVALID_HANDLE);
        }
        unsafe { copy_output(&job.bytes, buffer, capacity, required) }
    })
}
/// Release before begin cancels the preview. Release after begin preserves the
/// durable unresolved barrier; it cannot cancel Finder or permit another event.
#[unsafe(no_mangle)]
pub extern "C" fn sayaka_empty_trash_release_v1(handle: u64) -> i32 {
    boundary(|| {
        if !cfg!(target_os = "macos") {
            return Err(UNSUPPORTED_PLATFORM);
        }
        let slot = get(handle)?;
        let mut job = match slot.try_lock() {
            Ok(j) => j,
            Err(TryLockError::WouldBlock) => return Err(BUSY),
            Err(TryLockError::Poisoned(p)) => p.into_inner(),
        };
        if job.closed {
            return Err(INVALID_HANDLE);
        }
        job.closed = true;
        registry()
            .lock()
            .map_err(|_| INTERNAL_ERROR)?
            .empty_trash
            .remove(&handle)
            .ok_or(INVALID_HANDLE)?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_requests_never_allocate_authority() {
        let mut handle = 99;
        assert_eq!(
            unsafe { sayaka_empty_trash_preview_v1(std::ptr::null(), &mut handle) },
            INVALID_ARGUMENT
        );
        assert_eq!(handle, 0);
        let r = SayakaEmptyTrashRequestV1 {
            abi_version: 2,
            struct_size: size_of::<SayakaEmptyTrashRequestV1>() as u32,
            handle: 0,
            json: std::ptr::null(),
            json_length: 0,
            reserved: 0,
        };
        assert_eq!(
            unsafe { sayaka_empty_trash_preview_v1(&r, &mut handle) },
            UNSUPPORTED_VERSION
        );
        assert_eq!(handle, 0);
    }
}

fn required_option<'de, D: serde::Deserializer<'de>, T: serde::Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    <Option<T> as serde::Deserialize>::deserialize(d)
}
/// Strict read-only schema-10 validation shared with host history decoders.
/// No handle is allocated and no receipt can become executable authority.
/// # Safety
/// Input references json_length readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_empty_trash_validate_record_v1(
    json: *const u8,
    json_length: usize,
) -> i32 {
    boundary(|| {
        if json_length == 0 || json_length > 1048576 {
            return Err(INVALID_ARGUMENT);
        }
        pointer(json)?;
        let r: sayaka_engine::journal::Record =
            serde_json::from_slice(unsafe { std::slice::from_raw_parts(json, json_length) })
                .map_err(|_| INVALID_ARGUMENT)?;
        if r.schema_version != 10 {
            return Err(UNSUPPORTED_VERSION);
        }
        r.validate().map_err(|_| INVALID_ARGUMENT)
    })
}
