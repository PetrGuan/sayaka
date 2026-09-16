// SPDX-License-Identifier: MPL-2.0

//! Non-authorizing directory observations. No filesystem access or native plan.

use super::index::{DirectorySummary, ScanTree, check_cancelled};
use super::{ScanCode, ScanEntry, ScanError, ScanTaskId};
use crate::model::{Cancellation, ExecutionContract, FileIdentity, ResourceKind, Scope, overlaps};
use std::collections::{HashMap, HashSet};

pub const MAX_EXCLUSIONS: usize = 32;
pub const MAX_BLOCKER_EXAMPLES: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectorySelection {
    pub task_id: ScanTaskId,
    pub scope_id: u64,
    pub directory_id: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectoryBlockerCode {
    ScopeRoot,
    ProtectedLocation,
    IncompleteScan,
    ExcludedOverlap,
    ExcludedIdentityAlias,
    Link,
    SpecialEntry,
    Dataless,
    VolumeIdentityMismatch,
    ObservedFileAlias,
    ObservedDirectoryAlias,
    UnknownMeasurements,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryBlocker {
    pub code: DirectoryBlockerCode,
    pub entry_id: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnverifiedDirectoryGate {
    NativeIdentityAndFreshness,
    OwnershipPermissionsAndAcl,
    NativeVolumeCapability,
    NativePackageAndProtectedLocations,
    FullSubtreeCoverage,
    ExternalLinksAndExclusionResolution,
    ActivityAndConcurrentContents,
    ApprovedDirectoryExecutionAndRecoveryContract,
}

const UNVERIFIED: &[UnverifiedDirectoryGate] = &[
    UnverifiedDirectoryGate::NativeIdentityAndFreshness,
    UnverifiedDirectoryGate::OwnershipPermissionsAndAcl,
    UnverifiedDirectoryGate::NativeVolumeCapability,
    UnverifiedDirectoryGate::NativePackageAndProtectedLocations,
    UnverifiedDirectoryGate::FullSubtreeCoverage,
    UnverifiedDirectoryGate::ExternalLinksAndExclusionResolution,
    UnverifiedDirectoryGate::ActivityAndConcurrentContents,
    UnverifiedDirectoryGate::ApprovedDirectoryExecutionAndRecoveryContract,
];

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DirectoryObservedCounts {
    pub entries: usize,
    pub directories: usize,
    pub file_names: usize,
    pub links: usize,
    pub other: usize,
    pub dataless: usize,
}

/// Borrows a task-local immutable scan, not an exclusive filesystem snapshot.
/// Even an empty observed-blocker list leaves every native gate unverified.
///
/// ```compile_fail
/// use sayaka_engine::{execute::TrashSession, journal::Store};
/// use sayaka_engine::model::{Approval, Cancellation};
/// use sayaka_engine::scan::directory_review::DirectoryAssessment;
/// fn not_a_plan(session: &mut TrashSession, assessment: &DirectoryAssessment<'_>,
///               approval: &Approval, cancel: &Cancellation, store: &Store) {
///     session.execute(assessment, approval, cancel, store);
/// }
/// ```
#[derive(Debug)]
pub struct DirectoryAssessment<'a> {
    tree: &'a ScanTree,
    selection: DirectorySelection,
    ancestors: Vec<u64>,
    members: Vec<u64>,
    counts: DirectoryObservedCounts,
    blockers: Vec<DirectoryBlocker>,
    blockers_omitted: usize,
}

impl DirectoryAssessment<'_> {
    pub fn selection(&self) -> DirectorySelection {
        self.selection
    }

    pub fn scope(&self) -> &ScanEntry {
        self.tree
            .entry(self.selection.scope_id)
            .expect("validated immutable scope")
    }

    pub fn directory(&self) -> &ScanEntry {
        self.tree
            .entry(self.selection.directory_id)
            .expect("validated immutable directory")
    }

    pub fn members(&self) -> impl Iterator<Item = &ScanEntry> {
        self.members
            .iter()
            .map(|id| self.tree.entry(*id).expect("validated immutable member"))
    }

    /// Observed scope-to-parent chain, excluding the selected directory itself.
    pub fn ancestors(&self) -> impl Iterator<Item = &ScanEntry> {
        self.ancestors
            .iter()
            .map(|id| self.tree.entry(*id).expect("validated immutable ancestor"))
    }

    /// Totals/coverage of the supplied scan policy, not native closure or freed space.
    pub fn summary(&self) -> &DirectorySummary {
        self.tree
            .summary(self.selection.directory_id)
            .expect("validated directory summary")
    }

    pub fn counts(&self) -> &DirectoryObservedCounts {
        &self.counts
    }

    pub fn blockers(&self) -> &[DirectoryBlocker] {
        &self.blockers
    }

    pub fn blockers_omitted(&self) -> usize {
        self.blockers_omitted
    }

    pub fn unverified_gates(&self) -> &'static [UnverifiedDirectoryGate] {
        UNVERIFIED
    }

    pub const fn execution_contract(&self) -> ExecutionContract {
        ExecutionContract::ModelOnly
    }

    fn block(&mut self, code: DirectoryBlockerCode, entry_id: u64) {
        if self.blockers.len() < MAX_BLOCKER_EXAMPLES {
            self.blockers.push(DirectoryBlocker { code, entry_id });
        } else {
            self.blockers_omitted += 1;
        }
    }

    fn observe_barriers(
        &mut self,
        entry: &ScanEntry,
        identity_counts: &HashMap<FileIdentity, usize>,
        excluded_identities: &HashSet<FileIdentity>,
    ) {
        if entry.dataless {
            self.block(DirectoryBlockerCode::Dataless, entry.id);
        }
        if !same_volume(self.scope().identity, entry.identity) {
            self.block(DirectoryBlockerCode::VolumeIdentityMismatch, entry.id);
        }
        if excluded_identities.contains(&entry.identity) {
            self.block(DirectoryBlockerCode::ExcludedIdentityAlias, entry.id);
        }
        let alias = *identity_counts
            .get(&entry.identity)
            .expect("indexed observation identity")
            > 1;
        match entry.kind {
            ResourceKind::Directory if alias => {
                self.block(DirectoryBlockerCode::ObservedDirectoryAlias, entry.id)
            }
            ResourceKind::File if alias => {
                self.block(DirectoryBlockerCode::ObservedFileAlias, entry.id)
            }
            ResourceKind::Link => self.block(DirectoryBlockerCode::Link, entry.id),
            ResourceKind::Other => self.block(DirectoryBlockerCode::SpecialEntry, entry.id),
            _ => {}
        }
    }
}

pub fn assess_directory<'a>(
    tree: &'a ScanTree,
    selection: DirectorySelection,
    excluded_ids: &[u64],
    cancellation: &Cancellation,
) -> Result<DirectoryAssessment<'a>, ScanError> {
    check_cancelled(cancellation)?;
    if selection.task_id != tree.report().task_id {
        return Err(ScanError::new(
            ScanCode::ChangedEntry,
            "directory selection belongs to another scan; refresh",
        ));
    }
    if excluded_ids.len() > MAX_EXCLUSIONS {
        return Err(ScanError::new(
            ScanCode::InvalidLimits,
            "directory review accepts at most 32 exclusions",
        ));
    }
    let scope = tree
        .entry(selection.scope_id)
        .ok_or_else(|| invalid("unknown scope entry"))?;
    let target = tree
        .entry(selection.directory_id)
        .ok_or_else(|| invalid("unknown directory entry"))?;
    if tree.report().roots.len() != 1
        || tree.report().roots.first() != Some(&scope.path)
        || scope.kind != ResourceKind::Directory
        || target.kind != ResourceKind::Directory
        || !target.path.starts_with(&scope.path)
    {
        return Err(invalid(
            "select a directory within one observed explicit scan root",
        ));
    }
    let policy =
        Scope::new(scope.path.clone(), vec![]).map_err(|_| invalid("invalid directory scope"))?;
    let mut excluded = Vec::new();
    let mut excluded_seen = HashSet::new();
    let mut excluded_identities = HashSet::new();
    for id in excluded_ids {
        check_cancelled(cancellation)?;
        let entry = tree
            .entry(*id)
            .ok_or_else(|| invalid("unknown exclusion entry"))?;
        if !entry.path.starts_with(&scope.path) || !excluded_seen.insert(*id) {
            return Err(invalid(
                "exclusions must be distinct observed entries in this scope",
            ));
        }
        excluded.push(entry);
        excluded_identities.insert(entry.identity);
    }
    let mut identity_counts = HashMap::<FileIdentity, usize>::new();
    for entry in &tree.report().entries {
        check_cancelled(cancellation)?;
        *identity_counts.entry(entry.identity).or_default() += 1;
    }
    let mut assessment = DirectoryAssessment {
        tree,
        selection,
        ancestors: Vec::new(),
        members: Vec::new(),
        counts: DirectoryObservedCounts::default(),
        blockers: Vec::new(),
        blockers_omitted: 0,
    };
    if target.id == scope.id {
        assessment.block(DirectoryBlockerCode::ScopeRoot, target.id);
    } else if policy.protects(&target.path) {
        assessment.block(DirectoryBlockerCode::ProtectedLocation, target.id);
    }
    if !assessment.summary().complete {
        assessment.block(DirectoryBlockerCode::IncompleteScan, target.id);
    }
    if assessment.summary().logical_bytes_unknown_files > 0
        || assessment.summary().allocated_bytes_unknown_files > 0
    {
        assessment.block(DirectoryBlockerCode::UnknownMeasurements, target.id);
    }
    for entry in &excluded {
        if overlaps(&target.path, &entry.path) {
            assessment.block(DirectoryBlockerCode::ExcludedOverlap, entry.id);
        }
    }
    let mut parent = tree.parent(target.id);
    while let Some(id) = parent {
        check_cancelled(cancellation)?;
        let entry = tree.entry(id).expect("immutable index parent");
        assessment.ancestors.push(id);
        assessment.observe_barriers(entry, &identity_counts, &excluded_identities);
        if id == scope.id {
            break;
        }
        parent = tree.parent(id);
    }
    if target.id != scope.id && assessment.ancestors.last() != Some(&scope.id) {
        return Err(invalid(
            "directory ancestry is not connected to the observed scope",
        ));
    }
    assessment.ancestors.reverse();
    let mut pending = vec![target.id];
    while let Some(id) = pending.pop() {
        check_cancelled(cancellation)?;
        let entry = tree.entry(id).expect("immutable index child");
        assessment.members.push(id);
        assessment.counts.entries += 1;
        if entry.dataless {
            assessment.counts.dataless += 1;
        }
        assessment.observe_barriers(entry, &identity_counts, &excluded_identities);
        match entry.kind {
            ResourceKind::Directory => {
                assessment.counts.directories += 1;
                pending.extend(
                    tree.children(id)
                        .expect("directory children")
                        .iter()
                        .rev()
                        .copied(),
                );
            }
            ResourceKind::File => {
                assessment.counts.file_names += 1;
            }
            ResourceKind::Link => {
                assessment.counts.links += 1;
            }
            ResourceKind::Other => {
                assessment.counts.other += 1;
            }
        }
    }
    check_cancelled(cancellation)?;
    Ok(assessment)
}

fn same_volume(left: FileIdentity, right: FileIdentity) -> bool {
    match (left, right) {
        (FileIdentity::Unix { device: a, .. }, FileIdentity::Unix { device: b, .. }) => a == b,
        (
            FileIdentity::Windows {
                volume_serial: a, ..
            },
            FileIdentity::Windows {
                volume_serial: b, ..
            },
        ) => a == b,
        _ => false,
    }
}

fn invalid(message: &str) -> ScanError {
    ScanError::new(ScanCode::InvalidRoot, message)
}

#[cfg(test)]
mod tests;
