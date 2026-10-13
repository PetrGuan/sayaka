// SPDX-License-Identifier: MPL-2.0

//! Immutable, task-local hierarchy over scan observations. Directory totals
//! deduplicate within each subtree, so sibling totals are not additive.

use super::{ScanCode, ScanEntry, ScanError, ScanLimits, ScanReport, ScanStatus};
use crate::model::{Cancellation, FileIdentity, ResourceKind, valid_absolute_path};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sort {
    Size,
    Name,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Metric {
    Logical,
    Allocated,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct DirectorySummary {
    pub private_bytes: Option<u64>,
    pub unique_files: u64,
    pub logical_bytes_known: u64,
    pub logical_bytes_unknown_files: u64,
    pub allocated_bytes_known: u64,
    pub allocated_bytes_unknown_files: u64,
    /// Traversal coverage of this subtree, independent of whether measurements
    /// are known. A partial scan may still cover a subtree that has no
    /// path-bounded gap; traversal-wide stops or omitted issues leave none complete.
    pub complete: bool,
}

#[derive(Debug)]
struct Node {
    parent: Option<usize>,
    children: Vec<u64>,
    size_orders: [Vec<u64>; 2],
    summary: Option<DirectorySummary>,
    contains_dataless: bool,
}

#[derive(Debug)]
pub struct ScanTree {
    report: Arc<ScanReport>,
    positions: HashMap<u64, usize>,
    nodes: Vec<Node>,
    roots: Vec<u64>,
    root_size_orders: [Vec<u64>; 2],
    complete: bool,
}

impl ScanTree {
    /// Builds without filesystem access or changing M2's measurements/counting.
    /// The retained entry paths are bounded independently of reported metrics.
    pub fn build(report: ScanReport, cancellation: &Cancellation) -> Result<Self, ScanError> {
        Self::build_with_limits(report, cancellation, &ScanLimits::default())
    }

    /// Index the same bounded observations accepted by the traversal profile.
    pub fn build_with_limits(report: ScanReport, cancellation: &Cancellation, limits: &ScanLimits) -> Result<Self, ScanError> {
        Self::build_shared(Arc::new(report), cancellation, limits)
    }

    /// Shares the terminal snapshot; no second retained entry/path allocation.
    pub fn build_shared(report: Arc<ScanReport>, cancellation: &Cancellation, limits: &ScanLimits) -> Result<Self, ScanError> {
        limits.validate()?;
        check_cancelled(cancellation)?;
        #[cfg(debug_assertions)]
        let mut phase_started = std::time::Instant::now();
        if report.entries.len() > limits.max_entries {
            return Err(ScanError::new(
                ScanCode::EntryLimit,
                "scan index entry limit",
            ));
        }
        if report.roots.len() > 64 {
            return Err(invalid("scan index has too many explicit roots"));
        }
        let mut explicit_roots = HashSet::new();
        let mut root_bytes = 0;
        for root in &report.roots {
            check_cancelled(cancellation)?;
            validate_path(root)?;
            add_path_bytes(&mut root_bytes, root, limits.max_path_bytes)?;
            if !explicit_roots.insert(root.as_path()) {
                return Err(invalid("duplicate explicit root path"));
            }
        }

        let mut positions = HashMap::with_capacity(report.entries.len());
        // Hash paths once per lookup instead of reparsing their components on
        // every B-tree comparison. Public ordering is restored per sibling set.
        let mut paths = HashMap::with_capacity(report.entries.len());
        let mut measurements: HashMap<FileIdentity, Measurements> = HashMap::new();
        let mut path_bytes = 0;
        let mut nodes = Vec::with_capacity(report.entries.len());
        for (position, entry) in report.entries.iter().enumerate() {
            check_cancelled(cancellation)?;
            validate_path(&entry.path)?;
            add_path_bytes(&mut path_bytes, &entry.path, limits.max_path_bytes)?;
            if positions.insert(entry.id, position).is_some() {
                return Err(invalid("duplicate scan entry ID"));
            }
            if paths.insert(entry.path.as_path(), position).is_some() {
                return Err(invalid("duplicate scan entry path"));
            }
            if explicit_roots.contains(entry.path.as_path())
                && entry.kind != ResourceKind::Directory
            {
                return Err(invalid("explicit root entry is not a directory"));
            }
            if entry.kind == ResourceKind::File {
                let observation = Measurements {
                    private: entry.private_bytes,
                    logical: entry.logical_bytes,
                    allocated: entry.allocated_bytes,
                };
                measurements
                    .entry(entry.identity)
                    .and_modify(|known| known.observe(observation))
                    .or_insert(observation);
            }
            nodes.push(Node {
                parent: None,
                children: Vec::new(),
                size_orders: Default::default(),
                summary: None,
                contains_dataless: entry.dataless,
            });
        }

        #[cfg(debug_assertions)]
        log_index_phase("validate", &mut phase_started, report.entries.len());
        let mut roots = Vec::new();
        for (&path, &position) in &paths {
            check_cancelled(cancellation)?;
            let parent = path.parent().and_then(|parent| paths.get(parent)).copied();
            if let Some(parent) = parent {
                if report.entries[parent].kind != ResourceKind::Directory {
                    return Err(invalid("scan entry parent is not a directory"));
                }
                nodes[position].parent = Some(parent);
                nodes[parent].children.push(report.entries[position].id);
            } else if explicit_roots.contains(path) {
                roots.push(report.entries[position].id);
            } else {
                return Err(invalid(
                    "scan entry has no observed parent or explicit root",
                ));
            }
        }

        let mut complete =
            report.complete && report.status == ScanStatus::Complete && report.issues_omitted == 0;
        // A partial report can still prove coverage for unrelated subtrees when
        // every gap is retained, path-bearing and bounded to that path. Anything
        // else, including traversal-wide stops, leaves every directory incomplete.
        let mut localized = report.status == ScanStatus::Partial && report.issues_omitted == 0;
        let mut incomplete_paths = HashSet::new();
        for issue in &report.issues {
            check_cancelled(cancellation)?;
            if !issue.code.is_gap() {
                continue;
            }
            complete = false;
            let bounded = issue.code.is_subtree_gap()
                && issue.path.as_deref().is_some_and(|path| {
                    valid_absolute_path(path)
                        && paths.get(path).is_none_or(|&position| {
                            report.entries[position].kind == ResourceKind::Directory
                        })
                });
            if !localized || !bounded {
                localized = false;
                continue;
            }
            let path = issue.path.as_deref().expect("bounded gap has a path");
            for ancestor in path.ancestors() {
                check_cancelled(cancellation)?;
                if !incomplete_paths.insert(ancestor) {
                    break;
                }
            }
        }
        localized &= !complete && !incomplete_paths.is_empty();
        // An absent requested root needs a reported intentional deduplication;
        // otherwise even a malformed success-shaped report has missing coverage.
        for root in &report.roots {
            check_cancelled(cancellation)?;
            if !paths.contains_key(root.as_path())
                && !report.issues.iter().any(|issue| {
                    issue.path.as_ref() == Some(root)
                        && matches!(
                            issue.code,
                            ScanCode::DuplicateRoot | ScanCode::DuplicateDirectory
                        )
                })
            {
                complete = false;
                localized = false;
            }
        }

        #[cfg(debug_assertions)]
        log_index_phase("hierarchy_coverage", &mut phase_started, report.entries.len());
        let mut bags: Vec<Option<IdentityBag>> = (0..report.entries.len()).map(|_| None).collect();
        // Explicit hierarchy postorder replaces global path sorting. Ancestors
        // are processed after all descendants, independent of scan entry order.
        let mut order = Vec::with_capacity(nodes.len());
        let mut pending = roots.clone();
        while let Some(id) = pending.pop() {
            check_cancelled(cancellation)?;
            let position = positions[&id];
            order.push(position);
            for &child in &nodes[position].children {
                check_cancelled(cancellation)?;
                pending.push(child);
            }
        }
        for &position in order.iter().rev() {
            check_cancelled(cancellation)?;
            let entry = &report.entries[position];
            let parent = nodes[position].parent;
            if let Some(parent) = parent {
                nodes[parent].contains_dataless |= nodes[position].contains_dataless;
            }
            match entry.kind {
                ResourceKind::File => {
                    if let Some(parent) = parent {
                        bags[parent]
                            .get_or_insert_with(IdentityBag::default)
                            .insert(entry.identity, &measurements, cancellation)?;
                    }
                }
                ResourceKind::Directory => {
                    let bag = bags[position].take().unwrap_or_default();
                    let mut summary = bag.summary.clone();
                    summary.complete =
                        complete || (localized && !incomplete_paths.contains(entry.path.as_path()));
                    if !summary.complete { summary.private_bytes = None; }
                    nodes[position].summary = Some(summary);
                    if let Some(parent) = parent {
                        bags[parent]
                            .get_or_insert_with(IdentityBag::default)
                            .merge(bag, &measurements, cancellation)?;
                    }
                }
                ResourceKind::Link | ResourceKind::Other => {}
            }
        }
        check_cancelled(cancellation)?;
        drop(incomplete_paths);
        drop(paths);
        drop(explicit_roots);
        #[cfg(debug_assertions)]
        log_index_phase("accounting", &mut phase_started, report.entries.len());
        let mut tree = Self {
            report,
            positions,
            nodes,
            roots,
            root_size_orders: Default::default(),
            complete,
        };
        for position in 0..tree.nodes.len() {
            check_cancelled(cancellation)?;
            let children = std::mem::take(&mut tree.nodes[position].children);
            let (names, sizes) = tree.build_orders(children, cancellation, true)?;
            tree.nodes[position].children = names;
            tree.nodes[position].size_orders = sizes;
        }
        let roots = std::mem::take(&mut tree.roots);
        (tree.roots, tree.root_size_orders) = tree.build_orders(roots, cancellation, false)?;
        #[cfg(debug_assertions)]
        log_index_phase("ordering", &mut phase_started, tree.nodes.len());
        Ok(tree)
    }

    pub fn contains_dataless(&self, id: u64) -> bool {
        self.positions.get(&id).is_some_and(|&index| self.nodes[index].contains_dataless)
    }

    pub fn report(&self) -> &ScanReport {
        &self.report
    }

    pub fn entry(&self, id: u64) -> Option<&ScanEntry> {
        self.positions
            .get(&id)
            .map(|&index| &self.report.entries[index])
    }

    /// Whole-scan coverage: no gap anywhere. Subtree summaries can be
    /// complete while this is false.
    pub fn complete(&self) -> bool {
        self.complete
    }

    /// Observed forest roots, in native path order.
    pub fn roots(&self) -> &[u64] {
        &self.roots
    }

    /// Directory children in native path order; files and unknown IDs have none.
    pub fn children(&self, id: u64) -> Option<&[u64]> {
        let &index = self.positions.get(&id)?;
        (self.report.entries[index].kind == ResourceKind::Directory)
            .then_some(self.nodes[index].children.as_slice())
    }

    pub fn parent(&self, id: u64) -> Option<u64> {
        let &index = self.positions.get(&id)?;
        self.nodes[index]
            .parent
            .map(|parent| self.report.entries[parent].id)
    }

    pub fn summary(&self, id: u64) -> Option<&DirectorySummary> {
        self.nodes[*self.positions.get(&id)?].summary.as_ref()
    }

    /// Sum of per-file exclusive bytes, not selection reclaimable capacity.
    /// Shared clone extents are not counted even when both clones are selected.
    pub fn private_size(&self, id: u64) -> Option<u64> {
        let entry = self.entry(id)?;
        match entry.kind {
            ResourceKind::File if !entry.dataless => entry.private_bytes,
            ResourceKind::Directory => self.summary(id).filter(|s| s.complete).and_then(|s| s.private_bytes),
            _ => None,
        }
    }

    /// Known subtotal, not necessarily a complete measurement. Consult summary
    /// unknown counts and coverage. Non-file payloads have no size.
    pub fn size(&self, id: u64, metric: Metric) -> Option<u64> {
        self.size_at(*self.positions.get(&id)?, metric)
    }

    fn size_at(&self, position: usize, metric: Metric) -> Option<u64> {
        let entry = &self.report.entries[position];
        match entry.kind {
            ResourceKind::Directory => {
                let summary = self.nodes[position].summary.as_ref()?;
                let (bytes, unknown) = match metric {
                    Metric::Logical => (
                        summary.logical_bytes_known,
                        summary.logical_bytes_unknown_files,
                    ),
                    Metric::Allocated => (
                        summary.allocated_bytes_known,
                        summary.allocated_bytes_unknown_files,
                    ),
                };
                if (bytes == 0 && unknown > 0) || (!summary.complete && summary.unique_files == 0) {
                    None
                } else {
                    Some(bytes)
                }
            }
            ResourceKind::File => match metric {
                Metric::Logical => entry.logical_bytes,
                Metric::Allocated => entry.allocated_bytes,
            },
            ResourceKind::Link | ResourceKind::Other => None,
        }
    }

    /// Name is native path ascending; size is known subtotal descending,
    /// unknown last, ties by native path ascending. Sibling sizes are not additive.
    pub fn ordered_children(&self, id: u64, sort: Sort, metric: Metric) -> Option<&[u64]> {
        let children = self.children(id)?;
        let node = &self.nodes[*self.positions.get(&id)?];
        Some(ordered(children, &node.size_orders, sort, metric))
    }

    pub fn ordered_roots(&self, sort: Sort, metric: Metric) -> &[u64] {
        ordered(&self.roots, &self.root_size_orders, sort, metric)
    }

    /// Sorting uses validated observation positions, not public resource IDs.
    /// Resolve each ID once; comparisons must not repeatedly hash IDs or walk
    /// the common parent components of long sibling paths.
    fn build_orders(
        &self,
        mut names: Vec<u64>,
        cancellation: &Cancellation,
        siblings: bool,
    ) -> Result<(Vec<u64>, [Vec<u64>; 2]), ScanError> {
        for id in &mut names {
            check_cancelled(cancellation)?;
            // Entries are bounded by ScanLimits, and every child/root ID was
            // taken from this report after unique-ID and parent validation.
            *id = self.positions[id] as u64;
        }
        let compare_name = |a: &u64, b: &u64| {
            let a = &self.report.entries[*a as usize].path;
            let b = &self.report.entries[*b as usize].path;
            if siblings {
                // A validated sibling set has the same normalized parent.
                // Compare native final components, preserving non-UTF8 names.
                a.file_name().cmp(&b.file_name())
            } else {
                a.cmp(b)
            }
        };
        cancellable_sort(&mut names, cancellation, compare_name)?;
        let mut orders = [names.clone(), names.clone()];
        for (order, metric) in orders.iter_mut().zip([Metric::Logical, Metric::Allocated]) {
            check_cancelled(cancellation)?;
            cancellable_sort(order, cancellation, |a, b| {
                self.size_at(*b as usize, metric)
                    .cmp(&self.size_at(*a as usize, metric))
                    .then_with(|| compare_name(a, b))
            })?;
        }
        for order in std::iter::once(&mut names).chain(orders.iter_mut()) {
            for position in order {
                check_cancelled(cancellation)?;
                *position = self.report.entries[*position as usize].id;
            }
        }
        Ok((names, orders))
    }

}

#[cfg(debug_assertions)]
fn log_index_phase(phase: &str, started: &mut std::time::Instant, entries: usize) {
    eprintln!("[SayakaTraversal] event=index.phase phase={phase} entries={entries} elapsed_us={}", started.elapsed().as_micros());
    *started = std::time::Instant::now();
}

fn cancellable_sort(
    ids: &mut [u64], cancellation: &Cancellation,
    compare: impl Fn(&u64, &u64) -> std::cmp::Ordering,
) -> Result<(), ScanError> {
    const CHUNK: usize = 256;
    for chunk in ids.chunks_mut(CHUNK) {
        check_cancelled(cancellation)?;
        chunk.sort_unstable_by(&compare);
    }
    if ids.len() <= CHUNK { return check_cancelled(cancellation); }
    let mut scratch = vec![0; ids.len()];
    let mut width = CHUNK;
    while width < ids.len() {
        for start in (0..ids.len()).step_by(width * 2) {
            let middle = (start + width).min(ids.len());
            let end = (middle + width).min(ids.len());
            let (mut left, mut right) = (start, middle);
            for output in start..end {
                if output % CHUNK == 0 { check_cancelled(cancellation)?; }
                let take_left = left < middle && (right == end || !compare(&ids[left], &ids[right]).is_gt());
                scratch[output] = if take_left { let value = ids[left]; left += 1; value }
                    else { let value = ids[right]; right += 1; value };
            }
        }
        for (target, source) in ids.chunks_mut(CHUNK).zip(scratch.chunks(CHUNK)) {
            check_cancelled(cancellation)?;
            target.copy_from_slice(source);
        }
        width *= 2;
    }
    check_cancelled(cancellation)
}

fn ordered<'a>(
    names: &'a [u64],
    sizes: &'a [Vec<u64>; 2],
    sort: Sort,
    metric: Metric,
) -> &'a [u64] {
    match (sort, metric) {
        (Sort::Name, _) => names,
        (Sort::Size, Metric::Logical) => &sizes[0],
        (Sort::Size, Metric::Allocated) => &sizes[1],
    }
}

#[derive(Clone, Copy)]
struct Measurements {
    private: Option<u64>,
    logical: Option<u64>,
    allocated: Option<u64>,
}

impl Measurements {
    fn observe(&mut self, other: Self) {
        if self.private != other.private { self.private = None; }
        if self.logical != other.logical {
            self.logical = None;
        }
        if self.allocated != other.allocated {
            self.allocated = None;
        }
    }
}

struct IdentityBag {
    identities: HashSet<FileIdentity>,
    summary: DirectorySummary,
}

impl Default for IdentityBag {
    fn default() -> Self {
        Self { identities: HashSet::new(), summary: DirectorySummary { private_bytes: Some(0), ..Default::default() } }
    }
}

impl IdentityBag {
    fn insert(
        &mut self,
        identity: FileIdentity,
        measurements: &HashMap<FileIdentity, Measurements>,
        cancellation: &Cancellation,
    ) -> Result<(), ScanError> {
        check_cancelled(cancellation)?;
        if self.identities.insert(identity) {
            let measurement = measurements[&identity];
            let prior = if self.summary.unique_files == 0 { Some(0u64) } else { self.summary.private_bytes };
            self.summary.private_bytes = prior.and_then(|a| measurement.private.and_then(|b| a.checked_add(b)));
            checked_add(&mut self.summary.unique_files, 1)?;
            match measurement.logical {
                Some(bytes) => checked_add(&mut self.summary.logical_bytes_known, bytes)?,
                None => checked_add(&mut self.summary.logical_bytes_unknown_files, 1)?,
            }
            match measurement.allocated {
                Some(bytes) => checked_add(&mut self.summary.allocated_bytes_known, bytes)?,
                None => checked_add(&mut self.summary.allocated_bytes_unknown_files, 1)?,
            }
        }
        Ok(())
    }

    fn merge(
        &mut self,
        mut other: Self,
        measurements: &HashMap<FileIdentity, Measurements>,
        cancellation: &Cancellation,
    ) -> Result<(), ScanError> {
        check_cancelled(cancellation)?;
        // Consume the smaller set; never retain a descendant set after merging.
        // Along unary chains the bag is moved, not copied or re-summed.
        if self.identities.len() < other.identities.len() {
            std::mem::swap(self, &mut other);
        }
        for identity in other.identities {
            self.insert(identity, measurements, cancellation)?;
        }
        Ok(())
    }
}

fn checked_add(total: &mut u64, value: u64) -> Result<(), ScanError> {
    *total = total
        .checked_add(value)
        .ok_or_else(|| ScanError::new(ScanCode::Overflow, "directory summary overflow"))?;
    Ok(())
}

pub(crate) fn check_cancelled(cancellation: &Cancellation) -> Result<(), ScanError> {
    if cancellation.is_cancelled() {
        Err(ScanError::new(ScanCode::Cancelled, "scan index cancelled"))
    } else {
        Ok(())
    }
}

fn invalid(message: &str) -> ScanError {
    ScanError::new(ScanCode::InvalidRoot, message)
}

fn validate_path(path: &std::path::Path) -> Result<(), ScanError> {
    if valid_absolute_path(path) && path.parent().is_some() {
        Ok(())
    } else {
        Err(invalid(
            "scan index requires non-root absolute paths without parent traversal or NUL",
        ))
    }
}

fn add_path_bytes(total: &mut usize, path: &std::path::Path, limit: usize) -> Result<(), ScanError> {
    *total = total
        .checked_add(path.as_os_str().len())
        .filter(|&bytes| bytes <= limit)
        .ok_or_else(|| ScanError::new(ScanCode::PathBytesLimit, "scan index path-byte limit"))?;
    Ok(())
}

#[cfg(test)]
mod tests;
