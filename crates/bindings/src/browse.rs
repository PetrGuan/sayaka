// SPDX-License-Identifier: MPL-2.0

use super::*;
use sayaka_engine::model::{Cancellation, ResourceKind};
use sayaka_engine::scan::index::{DirectorySummary, Metric, Sort};
use sayaka_engine::scan::{ScanEntry, ScanStatus};
use serde::Serialize;

pub const MAX_PAGE_NODES: u32 = 256;
pub const MAX_QUERY_BYTES: usize = 1024 * 1024;
const MAX_NODE_ALIASES: usize = 16;
const MAX_NODE_ISSUES: usize = 8;
pub const SORT_NAME: u32 = 1;
pub const SORT_LOGICAL_SIZE: u32 = 2;
pub const SORT_ALLOCATED_SIZE: u32 = 3;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SayakaNodeRefV1 {
    pub task_handle: u64,
    pub node_id: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SayakaPageRequestV1 {
    pub abi_version: u32,
    pub struct_size: u32,
    pub offset: u64,
    pub limit: u32,
    pub sort: u32,
}

impl SayakaPageRequestV1 {
    pub(super) fn validate(&self) -> Result<(usize, Sort, Metric), i32> {
        if self.abi_version != ABI_VERSION || self.struct_size as usize != size_of::<Self>() {
            return Err(UNSUPPORTED_VERSION);
        }
        if self.limit == 0 || self.limit > MAX_PAGE_NODES {
            return Err(INVALID_ARGUMENT);
        }
        let (sort, metric) = match self.sort {
            SORT_NAME => (Sort::Name, Metric::Logical),
            SORT_LOGICAL_SIZE => (Sort::Size, Metric::Logical),
            SORT_ALLOCATED_SIZE => (Sort::Size, Metric::Allocated),
            _ => return Err(INVALID_ARGUMENT),
        };
        let offset = usize::try_from(self.offset).map_err(|_| INVALID_ARGUMENT)?;
        Ok((offset, sort, metric))
    }
}

fn tree(job: &mut Job) -> Result<&ScanTree, i32> {
    if job.tree.is_none() {
        let report = job
            .task
            .result()
            .ok_or(NOT_READY)?
            .as_ref()
            .map_err(|_| QUERY_UNAVAILABLE)?;
        if report.status == ScanStatus::Failed {
            return Err(QUERY_UNAVAILABLE);
        }
        job.tree = Some(
            ScanTree::build(report.clone(), &Cancellation::default()).map_err(|error| match error
                .code
            {
                ScanCode::EntryLimit | ScanCode::PathBytesLimit | ScanCode::Overflow => {
                    LIMIT_EXCEEDED
                }
                _ => INTERNAL_ERROR,
            }),
        );
    }
    job.tree
        .as_ref()
        .expect("initialized tree cache")
        .as_ref()
        .map_err(|code| *code)
}

#[derive(Serialize)]
struct Reference {
    task_handle: String,
    node_id: String,
}

fn reference(handle: u64, id: u64) -> Reference {
    Reference {
        task_handle: handle.to_string(),
        node_id: id.to_string(),
    }
}

#[derive(Serialize)]
struct Node<'a> {
    reference: Reference,
    resource_id: String,
    parent: Option<Reference>,
    path: wire::NativePath<'a>,
    kind: &'static str,
    logical_bytes: Option<u64>,
    allocated_bytes: Option<u64>,
    directory_summary: Option<&'a DirectorySummary>,
    child_count: Option<usize>,
    dataless: bool,
}

fn node<'a>(tree: &'a ScanTree, handle: u64, entry: &'a ScanEntry) -> Node<'a> {
    Node {
        reference: reference(handle, entry.id),
        resource_id: format!("{}/{}", tree.report().task_id, entry.id),
        parent: tree.parent(entry.id).map(|id| reference(handle, id)),
        path: wire::NativePath(&entry.path),
        kind: match entry.kind {
            ResourceKind::File => "file",
            ResourceKind::Directory => "directory",
            ResourceKind::Link => "link",
            ResourceKind::Other => "other",
        },
        logical_bytes: tree.size(entry.id, Metric::Logical),
        allocated_bytes: tree.size(entry.id, Metric::Allocated),
        directory_summary: tree.summary(entry.id),
        child_count: tree.children(entry.id).map(<[u64]>::len),
        dataless: entry.dataless,
    }
}

#[derive(Serialize)]
struct Alias<'a> {
    resource_id: String,
    path: wire::NativePath<'a>,
    counted: bool,
}

#[derive(Serialize)]
struct NodeEvidence<'a> {
    node: Node<'a>,
    identity: wire::Identity,
    depth: usize,
    counted: bool,
    observed_alias_count: usize,
    aliases: Vec<Alias<'a>>,
    matching_issue_count: usize,
    issues: Vec<wire::Issue<'a>>,
}

/// Orders paths by the same native units serialized in `path.raw`.
#[cfg(unix)]
fn raw_path_le(left: &ScanEntry, right: &ScanEntry) -> bool {
    use std::os::unix::ffi::OsStrExt;
    left.path.as_os_str().as_bytes() <= right.path.as_os_str().as_bytes()
}

#[cfg(windows)]
fn raw_path_le(left: &ScanEntry, right: &ScanEntry) -> bool {
    use std::os::windows::ffi::OsStrExt;
    left.path
        .as_os_str()
        .encode_wide()
        .le(right.path.as_os_str().encode_wide())
}

fn node_evidence<'a>(tree: &'a ScanTree, handle: u64, entry: &'a ScanEntry) -> NodeEvidence<'a> {
    let report = tree.report();
    let mut observed_alias_count = 0;
    let mut aliases: Vec<&ScanEntry> = Vec::with_capacity(MAX_NODE_ALIASES);
    if entry.kind == ResourceKind::File {
        for alias in report.entries.iter().filter(|candidate| {
            candidate.kind == ResourceKind::File && candidate.identity == entry.identity
        }) {
            observed_alias_count += 1;
            // Keep only the first MAX_NODE_ALIASES paths in raw byte order.
            let position = aliases.partition_point(|kept| raw_path_le(kept, alias));
            if position < MAX_NODE_ALIASES {
                if aliases.len() == MAX_NODE_ALIASES {
                    aliases.pop();
                }
                aliases.insert(position, alias);
            }
        }
    }
    let aliases = aliases
        .into_iter()
        .map(|alias| Alias {
            resource_id: format!("{}/{}", report.task_id, alias.id),
            path: wire::NativePath(&alias.path),
            counted: alias.counted,
        })
        .collect();
    let mut matching_issue_count = 0;
    let mut issues = Vec::new();
    for issue in &report.issues {
        if issue.path.as_deref() == Some(entry.path.as_path()) {
            matching_issue_count += 1;
            if issues.len() < MAX_NODE_ISSUES {
                issues.push(wire::Issue::from(issue));
            }
        }
    }
    NodeEvidence {
        node: node(tree, handle, entry),
        identity: wire::Identity::from(entry.identity),
        depth: entry.depth,
        counted: entry.counted,
        observed_alias_count,
        aliases,
        matching_issue_count,
        issues,
    }
}

#[derive(Serialize)]
struct Query<T: Serialize> {
    schema_version: u32,
    task_handle: String,
    scan_task_id: String,
    scan_status: &'static str,
    scan_complete: bool,
    observed_issues: usize,
    issues_omitted: usize,
    data: T,
}

fn serialize(tree: &ScanTree, handle: u64, data: impl Serialize) -> Result<Vec<u8>, i32> {
    let report = tree.report();
    let value = Query {
        schema_version: 1,
        task_handle: handle.to_string(),
        scan_task_id: report.task_id.to_string(),
        scan_status: report.status.as_str(),
        scan_complete: report.complete,
        observed_issues: report.issues.len(),
        issues_omitted: report.issues_omitted,
        data,
    };
    bounded_json(&value, MAX_QUERY_BYTES)
}

#[derive(Serialize)]
struct Page<'a> {
    offset: usize,
    total: usize,
    next_offset: Option<usize>,
    nodes: Vec<Node<'a>>,
}

fn page(
    tree: &ScanTree,
    handle: u64,
    ids: &[u64],
    offset: usize,
    limit: u32,
) -> Result<Vec<u8>, i32> {
    if offset > ids.len() {
        return Err(INVALID_ARGUMENT);
    }
    let end = offset.saturating_add(limit as usize).min(ids.len());
    let nodes = ids[offset..end]
        .iter()
        .map(|id| {
            tree.entry(*id)
                .map(|entry| node(tree, handle, entry))
                .ok_or(INTERNAL_ERROR)
        })
        .collect::<Result<Vec<_>, _>>()?;
    serialize(
        tree,
        handle,
        Page {
            offset,
            total: ids.len(),
            next_offset: (end < ids.len()).then_some(end),
            nodes,
        },
    )
}

unsafe fn read_reference(handle: u64, node: *const SayakaNodeRefV1) -> Result<u64, i32> {
    pointer(node)?;
    // SAFETY: Caller supplies a readable aligned node-reference structure.
    let node = unsafe { *node };
    if node.task_handle != handle {
        return Err(INVALID_NODE);
    }
    Ok(node.node_id)
}

/// Returns a bounded page of observed forest roots, including their details.
///
/// # Safety
/// request is readable/aligned. Output follows sayaka_scan_result_v1's contract,
/// with MAX_QUERY_BYTES capacity. All input/output storage is non-overlapping.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_scan_roots_v1(
    handle: u64,
    request: *const SayakaPageRequestV1,
    buffer: *mut u8,
    capacity: usize,
    required: *mut usize,
) -> i32 {
    boundary(|| {
        // SAFETY: Caller supplies valid non-overlapping input/output storage.
        unsafe { prepare_output(buffer, capacity, required, MAX_QUERY_BYTES)? };
        pointer(request)?;
        let request = unsafe { *request };
        let (offset, sort, metric) = request.validate()?;
        let slot = get(handle)?;
        let mut job = lock_job(&slot)?;
        ensure_open(&job)?;
        let tree = tree(&mut job)?;
        let bytes = page(
            tree,
            handle,
            tree.ordered_roots(sort, metric),
            offset,
            request.limit,
        )?;
        // SAFETY: Output was validated above; bytes are privately owned.
        unsafe { copy_output(&bytes, buffer, capacity, required) }
    })
}

/// Returns one observed node's details; references are bound to their handle.
///
/// # Safety
/// node is readable/aligned. Output follows sayaka_scan_roots_v1's contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_scan_node_v1(
    handle: u64,
    node_ref: *const SayakaNodeRefV1,
    buffer: *mut u8,
    capacity: usize,
    required: *mut usize,
) -> i32 {
    boundary(|| {
        // SAFETY: Caller supplies valid non-overlapping input/output storage.
        unsafe { prepare_output(buffer, capacity, required, MAX_QUERY_BYTES)? };
        let id = unsafe { read_reference(handle, node_ref)? };
        let slot = get(handle)?;
        let mut job = lock_job(&slot)?;
        ensure_open(&job)?;
        let tree = tree(&mut job)?;
        let entry = tree.entry(id).ok_or(INVALID_NODE)?;
        let bytes = serialize(tree, handle, node(tree, handle, entry))?;
        // SAFETY: Output was validated above; bytes are privately owned.
        unsafe { copy_output(&bytes, buffer, capacity, required) }
    })
}

/// Returns one observed node's bounded evidence; references are bound to their handle.
///
/// # Safety
/// node is readable/aligned. Output follows sayaka_scan_roots_v1's contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_scan_node_evidence_v1(
    handle: u64,
    node_ref: *const SayakaNodeRefV1,
    buffer: *mut u8,
    capacity: usize,
    required: *mut usize,
) -> i32 {
    boundary(|| {
        // SAFETY: Caller supplies valid non-overlapping input/output storage.
        unsafe { prepare_output(buffer, capacity, required, MAX_QUERY_BYTES)? };
        let id = unsafe { read_reference(handle, node_ref)? };
        let slot = get(handle)?;
        let mut job = lock_job(&slot)?;
        ensure_open(&job)?;
        let tree = tree(&mut job)?;
        let entry = tree.entry(id).ok_or(INVALID_NODE)?;
        let bytes = serialize(tree, handle, node_evidence(tree, handle, entry))?;
        // SAFETY: Output was validated above; bytes are privately owned.
        unsafe { copy_output(&bytes, buffer, capacity, required) }
    })
}

/// Returns a bounded page of immediate observed children, never a live listing.
///
/// # Safety
/// parent and request are readable/aligned. Outputs follow
/// sayaka_scan_roots_v1's contract; all storage is non-overlapping.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_scan_children_v1(
    handle: u64,
    parent: *const SayakaNodeRefV1,
    request: *const SayakaPageRequestV1,
    buffer: *mut u8,
    capacity: usize,
    required: *mut usize,
) -> i32 {
    boundary(|| {
        // SAFETY: Caller supplies valid non-overlapping input/output storage.
        unsafe { prepare_output(buffer, capacity, required, MAX_QUERY_BYTES)? };
        let id = unsafe { read_reference(handle, parent)? };
        pointer(request)?;
        let request = unsafe { *request };
        let (offset, sort, metric) = request.validate()?;
        let slot = get(handle)?;
        let mut job = lock_job(&slot)?;
        ensure_open(&job)?;
        let tree = tree(&mut job)?;
        tree.entry(id).ok_or(INVALID_NODE)?;
        let ids = tree
            .ordered_children(id, sort, metric)
            .ok_or(NOT_DIRECTORY)?;
        let bytes = page(tree, handle, ids, offset, request.limit)?;
        // SAFETY: Output was validated above; bytes are privately owned.
        unsafe { copy_output(&bytes, buffer, capacity, required) }
    })
}

#[cfg(test)]
mod tests;
