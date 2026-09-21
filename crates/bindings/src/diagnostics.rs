// SPDX-License-Identifier: MPL-2.0

use super::*;
use sayaka_engine::scan::{ScanError, ScanReport};
use serde::Serialize;

pub const MAX_PAGE_ISSUES: u32 = 128;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SayakaIssuePageRequestV1 {
    pub abi_version: u32,
    pub struct_size: u32,
    pub offset: u64,
    pub limit: u32,
    pub reserved: u32,
}

impl SayakaIssuePageRequestV1 {
    fn validate(&self) -> Result<usize, i32> {
        if self.abi_version != ABI_VERSION || self.struct_size as usize != size_of::<Self>() {
            return Err(UNSUPPORTED_VERSION);
        }
        if self.limit == 0 || self.limit > MAX_PAGE_ISSUES || self.reserved != 0 {
            return Err(INVALID_ARGUMENT);
        }
        usize::try_from(self.offset).map_err(|_| INVALID_ARGUMENT)
    }
}

#[derive(Serialize)]
struct IssuePage<'a> {
    offset: usize,
    total: usize,
    next_offset: Option<usize>,
    issues: Vec<wire::Issue<'a>>,
}

#[derive(Serialize)]
struct Query<'a> {
    schema_version: u32,
    task_handle: String,
    scan_task_id: Option<String>,
    scan_status: &'static str,
    scan_complete: bool,
    observed_issues: usize,
    issues_omitted: usize,
    data: IssuePage<'a>,
}

fn page(
    outcome: Option<&Result<ScanReport, ScanError>>,
    handle: u64,
    offset: usize,
    limit: u32,
) -> Result<Vec<u8>, i32> {
    let outcome = outcome.ok_or(NOT_READY)?;
    let (task_id, status, complete, total, omitted) = match outcome {
        Ok(report) => (
            Some(report.task_id.to_string()),
            report.status.as_str(),
            report.complete,
            report.issues.len(),
            report.issues_omitted,
        ),
        Err(_) => (None, "failed", false, 1, 0),
    };
    if offset > total {
        return Err(INVALID_ARGUMENT);
    }
    let end = offset.saturating_add(limit as usize).min(total);
    let issues = match outcome {
        Ok(report) => report.issues[offset..end]
            .iter()
            .map(wire::Issue::from)
            .collect(),
        Err(error) if offset < end => vec![wire::Issue::from(error)],
        Err(_) => Vec::new(),
    };
    bounded_json(
        &Query {
            schema_version: 1,
            task_handle: handle.to_string(),
            scan_task_id: task_id,
            scan_status: status,
            scan_complete: complete,
            observed_issues: total,
            issues_omitted: omitted,
            data: IssuePage {
                offset,
                total,
                next_offset: (end < total).then_some(end),
                issues,
            },
        },
        MAX_QUERY_BYTES,
    )
}

/// Returns recorded terminal diagnostics without building a tree or full JSON.
///
/// # Safety
/// request is readable/aligned. Output follows sayaka_scan_roots_v1's
/// caller-buffer contract; all input/output storage is non-overlapping.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_scan_issues_v1(
    handle: u64,
    request: *const SayakaIssuePageRequestV1,
    buffer: *mut u8,
    capacity: usize,
    required: *mut usize,
) -> i32 {
    boundary(|| {
        // SAFETY: Caller supplies valid non-overlapping input/output storage.
        unsafe { prepare_output(buffer, capacity, required, MAX_QUERY_BYTES)? };
        pointer(request)?;
        let request = unsafe { *request };
        let offset = request.validate()?;
        let slot = get(handle)?;
        let mut job = lock_job(&slot)?;
        ensure_open(&job)?;
        let bytes = page(job.task.result(), handle, offset, request.limit)?;
        // SAFETY: Output was validated above; bytes are privately owned.
        unsafe { copy_output(&bytes, buffer, capacity, required) }
    })
}

#[cfg(test)]
mod tests;
