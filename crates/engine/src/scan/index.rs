// SPDX-License-Identifier: MPL-2.0

//! Immutable, task-local hierarchy over scan observations. Directory totals
//! deduplicate within each subtree, so sibling totals are not additive.

use super::{ScanCode, ScanEntry, ScanError, ScanReport, ScanStatus};
use crate::model::{Cancellation, FileIdentity, ResourceKind, valid_absolute_path};
use std::collections::{BTreeMap, HashMap, HashSet};

const MAX_ENTRIES: usize = 100_000;
const MAX_PATH_BYTES: usize = 32 * 1024 * 1024;

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
}

#[derive(Debug)]
pub struct ScanTree {
    report: ScanReport,
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
        check_cancelled(cancellation)?;
        if report.entries.len() > MAX_ENTRIES {
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
            add_path_bytes(&mut root_bytes, root)?;
            if !explicit_roots.insert(root.as_path()) {
                return Err(invalid("duplicate explicit root path"));
            }
        }

        let mut positions = HashMap::with_capacity(report.entries.len());
        // Path order also puts every ancestor before its descendants. Building
        // this order incrementally allows cancellation between insertions.
        let mut paths = BTreeMap::new();
        let mut measurements: HashMap<FileIdentity, Measurements> = HashMap::new();
        let mut path_bytes = 0;
        let mut nodes = Vec::with_capacity(report.entries.len());
        for (position, entry) in report.entries.iter().enumerate() {
            check_cancelled(cancellation)?;
            validate_path(&entry.path)?;
            add_path_bytes(&mut path_bytes, &entry.path)?;
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
            });
        }

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

        let mut bags: Vec<Option<IdentityBag>> = (0..report.entries.len()).map(|_| None).collect();
        for &position in paths.values().rev() {
            check_cancelled(cancellation)?;
            let entry = &report.entries[position];
            let parent = nodes[position].parent;
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
            tree.nodes[position].size_orders =
                tree.size_orders(&tree.nodes[position].children, cancellation)?;
        }
        tree.root_size_orders = tree.size_orders(&tree.roots, cancellation)?;
        Ok(tree)
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

    /// Known subtotal, not necessarily a complete measurement. Consult summary
    /// unknown counts and coverage. Non-file payloads have no size.
    pub fn size(&self, id: u64, metric: Metric) -> Option<u64> {
        let entry = self.entry(id)?;
        match entry.kind {
            ResourceKind::Directory => {
                let summary = self.summary(id)?;
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

    fn size_orders(
        &self,
        ids: &[u64],
        cancellation: &Cancellation,
    ) -> Result<[Vec<u64>; 2], ScanError> {
        let mut orders = [ids.to_vec(), ids.to_vec()];
        for (order, metric) in orders.iter_mut().zip([Metric::Logical, Metric::Allocated]) {
            check_cancelled(cancellation)?;
            order.sort_unstable_by(|a, b| {
                self.size(*b, metric)
                    .cmp(&self.size(*a, metric))
                    .then_with(|| {
                        self.entry(*a)
                            .unwrap()
                            .path
                            .cmp(&self.entry(*b).unwrap().path)
                    })
            });
        }
        check_cancelled(cancellation)?;
        Ok(orders)
    }
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
    logical: Option<u64>,
    allocated: Option<u64>,
}

impl Measurements {
    fn observe(&mut self, other: Self) {
        if self.logical != other.logical {
            self.logical = None;
        }
        if self.allocated != other.allocated {
            self.allocated = None;
        }
    }
}

#[derive(Default)]
struct IdentityBag {
    identities: HashSet<FileIdentity>,
    summary: DirectorySummary,
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

pub(super) fn check_cancelled(cancellation: &Cancellation) -> Result<(), ScanError> {
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

fn add_path_bytes(total: &mut usize, path: &std::path::Path) -> Result<(), ScanError> {
    *total = total
        .checked_add(path.as_os_str().len())
        .filter(|&bytes| bytes <= MAX_PATH_BYTES)
        .ok_or_else(|| ScanError::new(ScanCode::PathBytesLimit, "scan index path-byte limit"))?;
    Ok(())
}

#[cfg(test)]
mod tests;
