// SPDX-License-Identifier: MPL-2.0

use super::{
    NativeFileInfo, NativeLastGuard, NativeRecoveryEvidence, NativeRuleBindingWitness,
    NativeTargetMarker, NativeTrashOutcome, NativeWitnessInfo,
};
use crate::{ReadOnlyPolicy, VolumeInfo, volume_info};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::os::macos::fs::MetadataExt as MacMetadataExt;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::FileExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(test)]
use std::{cell::Cell, thread_local};

#[path = "foundation.rs"]
mod foundation;

const MAX_PATH_BYTES: usize = 4096;
const MAX_ANCESTORS: usize = 64;
const O_NOFOLLOW_ANY: i32 = 0x20000000;
const F_GETPATH_NOFIRMLINK: i32 = 102;
const SF_DATALESS: u32 = 0x40000000;
const SF_RESTRICTED: u32 = 0x00080000;
const SF_NOUNLINK: u32 = 0x00100000;
// Other flags, including immutable, append-only, datavault and unknown future
// flags, are deliberately outside this initial ordinary-file capability.
const ORDINARY_FLAGS: u32 = 0x00000001 | 0x00000020 | 0x00000040 | 0x00008000;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Stamp {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    size: u64,
    blocks: u64,
    flags: u32,
    modified: (i64, i64),
    changed: (i64, i64),
    created: (i64, i64),
}

impl Stamp {
    fn read(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            links: metadata.nlink(),
            size: metadata.size(),
            blocks: metadata.blocks(),
            flags: metadata.st_flags(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
            created: (metadata.st_birthtime(), metadata.st_birthtime_nsec()),
        }
    }

    fn identity(&self) -> (u64, u64) {
        (self.device, self.inode)
    }

    fn same_safety(&self, other: &Self) -> bool {
        self.identity() == other.identity()
            && self.mode == other.mode
            && self.uid == other.uid
            && self.gid == other.gid
            && self.flags == other.flags
            && self.created == other.created
            && (self.mode & u32::from(libc::S_IFMT) == u32::from(libc::S_IFDIR)
                || self.links == other.links)
    }

    fn same_post_move_stable_fields(&self, other: &Self) -> bool {
        self.identity() == other.identity()
            && self.mode == other.mode
            && self.uid == other.uid
            && self.gid == other.gid
            && self.links == other.links
            && self.size == other.size
            && self.blocks == other.blocks
            && self.flags == other.flags
            && self.created == other.created
            && self.modified == other.modified
    }

    fn post_move_stable_differences(&self, other: &Self) -> Vec<&'static str> {
        let mut differences = Vec::new();
        if self.device != other.device {
            differences.push("device");
        }
        if self.inode != other.inode {
            differences.push("inode");
        }
        if self.mode != other.mode {
            differences.push("mode");
        }
        if self.uid != other.uid {
            differences.push("uid");
        }
        if self.gid != other.gid {
            differences.push("gid");
        }
        if self.links != other.links {
            differences.push("nlink");
        }
        if self.size != other.size {
            differences.push("logical_bytes");
        }
        if self.blocks != other.blocks {
            differences.push("blocks");
        }
        if self.flags != other.flags {
            differences.push("flags");
        }
        if self.created != other.created {
            differences.push("created");
        }
        if self.modified != other.modified {
            differences.push("modified");
        }
        differences
    }

    fn differences(&self, other: &Self) -> Vec<&'static str> {
        let mut differences = self.post_move_stable_differences(other);
        if self.changed != other.changed {
            differences.push("changed");
        }
        differences
    }
}

#[derive(Clone, Copy)]
enum Binding {
    FullTarget,
    Safety,
    PostMoveTarget,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum TestProbeStage {
    OpenHandle,
    Complete,
    HeldAfterCapture,
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(super) enum TestProbeMutation {
    Device,
    Inode,
    Mode,
    Uid,
    Gid,
    Nlink,
    Size,
    Blocks,
    Flags,
    Modified,
    Changed,
    Created,
    ChangedAndSize,
}

impl Binding {
    fn matches(self, before: &Stamp, current: &Stamp) -> bool {
        match self {
            Self::FullTarget => before == current,
            Self::Safety => before.same_safety(current),
            Self::PostMoveTarget => before.same_post_move_stable_fields(current),
        }
    }
}

struct Evidence {
    path: PathBuf,
    physical: PathBuf,
    file: File,
    stamp: Stamp,
    acl: Option<Vec<u8>>,
    binding: Binding,
}

impl Evidence {
    fn open(path: &Path) -> io::Result<Self> {
        Self::open_bound(path, Binding::FullTarget)
    }

    fn open_safety(path: &Path) -> io::Result<Self> {
        Self::open_bound(path, Binding::Safety)
    }

    fn open_bound(path: &Path, binding: Binding) -> io::Result<Self> {
        let (file, stamp) = Self::open_handle(path, binding)?;
        Self::complete(path, binding, file, stamp)
    }

    fn open_handle(path: &Path, binding: Binding) -> io::Result<(File, Stamp)> {
        valid_path(path)?;
        let before = fs::symlink_metadata(path)?;
        if before.file_type().is_symlink() || before.st_flags() & SF_DATALESS != 0 {
            return Err(refused("link or dataless object"));
        }
        let file = OpenOptions::new()
            .read(true)
            // O_NOFOLLOW_ANY is mutually exclusive with O_NOFOLLOW on Darwin.
            // O_EVTONLY does not request file content; NONBLOCK avoids FIFO waits.
            .custom_flags(O_NOFOLLOW_ANY | libc::O_NONBLOCK | libc::O_EVTONLY | libc::O_CLOEXEC)
            .open(path)?;
        let mut stamp = Stamp::read(&file.metadata()?);
        apply_test_probe_hook(TestProbeStage::OpenHandle, &mut stamp);
        if !binding.matches(&stamp, &Stamp::read(&before)) {
            return Err(refused("object changed during no-follow capture"));
        }
        Ok((file, stamp))
    }

    fn complete(path: &Path, binding: Binding, file: File, stamp: Stamp) -> io::Result<Self> {
        let physical = physical_path(&file)?;
        let acl = crate::acl::snapshot(&file)?;
        let mut observed = Stamp::read(&file.metadata()?);
        apply_test_probe_hook(TestProbeStage::Complete, &mut observed);
        if !binding.matches(&stamp, &observed) {
            return Err(refused(&format!(
                "object safety changed during ACL capture: {}",
                describe_stamp_delta(&stamp, &observed)
            )));
        }
        Ok(Self {
            path: path.to_owned(),
            physical,
            file,
            stamp: observed,
            acl,
            binding,
        })
    }

    fn revalidate(&self) -> io::Result<()> {
        self.revalidate_at(&self.path)
    }

    fn revalidate_at(&self, path: &Path) -> io::Result<()> {
        if !self
            .binding
            .matches(&self.stamp, &Stamp::read(&self.file.metadata()?))
            || physical_path(&self.file)? != self.physical
            || crate::acl::snapshot(&self.file)? != self.acl
        {
            return Err(refused("retained object evidence or physical path changed"));
        }
        let current = Self::open_bound(path, self.binding)?;
        if !self.binding.matches(&self.stamp, &current.stamp)
            || current.physical != self.physical
            || current.acl != self.acl
        {
            return Err(refused(
                "path or ancestor no longer names the approved object",
            ));
        }
        Ok(())
    }
}

fn describe_stamp_delta(before: &Stamp, after: &Stamp) -> String {
    let mut fields = Vec::new();
    if before.device != after.device {
        fields.push("device");
    }
    if before.inode != after.inode {
        fields.push("inode");
    }
    if before.mode != after.mode {
        fields.push("mode");
    }
    if before.uid != after.uid {
        fields.push("uid");
    }
    if before.gid != after.gid {
        fields.push("gid");
    }
    if before.links != after.links {
        fields.push("nlink");
    }
    if before.size != after.size {
        fields.push("logical_bytes");
    }
    if before.blocks != after.blocks {
        fields.push("blocks");
    }
    if before.flags != after.flags {
        fields.push("flags");
    }
    if before.modified != after.modified {
        fields.push("modified");
    }
    if before.changed != after.changed {
        fields.push("changed");
    }
    if before.created != after.created {
        fields.push("created");
    }
    if fields.is_empty() {
        "none".into()
    } else {
        fields.join(",")
    }
}

fn verify_post_move_consistency(
    expected: &Stamp,
    held: &Stamp,
    result: &Stamp,
    acl_matches: bool,
) -> io::Result<()> {
    if expected != held {
        let changed = expected.differences(held);
        return Err(refused(&format!(
            "retained source diverged from approved object after move: {}",
            changed.join(",")
        )));
    }
    if expected != result || !acl_matches {
        let changed = expected.differences(result);
        return Err(refused(&format!(
            "result is not the unchanged, retained original file: {}{}",
            if changed.is_empty() {
                "none".into()
            } else {
                changed.join(",")
            },
            if !acl_matches {
                if changed.is_empty() {
                    "acl".into()
                } else {
                    ",acl".into()
                }
            } else {
                String::new()
            }
        )));
    }
    Ok(())
}

#[cfg(test)]
thread_local! {
    static TEST_PROBE_HOOK: Cell<Option<(TestProbeStage, TestProbeMutation)>> = const { Cell::new(None) };
}

#[cfg(not(test))]
fn apply_test_probe_hook(_: TestProbeStage, _: &mut Stamp) {}

#[cfg(test)]
fn apply_test_probe_hook(stage: TestProbeStage, stamp: &mut Stamp) {
    TEST_PROBE_HOOK.with(|hook| {
        if let Some((hook_stage, mutation)) = hook.get()
            && hook_stage == stage
        {
            match mutation {
                TestProbeMutation::Device => stamp.device = stamp.device.saturating_add(1),
                TestProbeMutation::Inode => stamp.inode = stamp.inode.saturating_add(1),
                TestProbeMutation::Mode => stamp.mode ^= 0o100,
                TestProbeMutation::Uid => stamp.uid = stamp.uid.saturating_add(1),
                TestProbeMutation::Gid => stamp.gid = stamp.gid.saturating_add(1),
                TestProbeMutation::Nlink => stamp.links = stamp.links.saturating_add(1),
                TestProbeMutation::Size => stamp.size = stamp.size.saturating_add(1),
                TestProbeMutation::Blocks => stamp.blocks = stamp.blocks.saturating_add(1),
                TestProbeMutation::Flags => stamp.flags ^= 0x1,
                TestProbeMutation::Modified => {
                    stamp.modified.1 = (stamp.modified.1 + 1).min(999_999_999)
                }
                TestProbeMutation::Changed => {
                    stamp.changed.1 = (stamp.changed.1 + 1).min(999_999_999)
                }
                TestProbeMutation::Created => {
                    stamp.created.1 = (stamp.created.1 + 1).min(999_999_999)
                }
                TestProbeMutation::ChangedAndSize => {
                    stamp.changed.1 = (stamp.changed.1 + 1).min(999_999_999);
                    stamp.size = stamp.size.saturating_add(1);
                }
            }
        }
    });
}

#[cfg(test)]
pub(super) fn set_test_probe_hook(hook: Option<(TestProbeStage, TestProbeMutation)>) {
    TEST_PROBE_HOOK.with(|value| value.set(hook));
}

#[cfg(test)]
pub(super) fn verify_destination_probe_for_test(path: &Path) -> io::Result<()> {
    let (file, stamp) = Evidence::open_handle(path, Binding::PostMoveTarget)?;
    reject_destination_attributes(&file)?;
    let _evidence = Evidence::complete(path, Binding::PostMoveTarget, file, stamp)?;
    Ok(())
}

#[cfg(test)]
pub(super) fn verify_destination_anchor_probe_for_test(
    path: &Path,
    revalidate_hook: Option<(TestProbeStage, TestProbeMutation)>,
) -> io::Result<()> {
    set_test_probe_hook(None);
    let (file, stamp) = Evidence::open_handle(path, Binding::PostMoveTarget)?;
    reject_destination_attributes(&file)?;
    let mut evidence = Evidence::complete(path, Binding::PostMoveTarget, file, stamp)?;
    evidence.binding = Binding::FullTarget;
    evidence.stamp = evidence.stamp.clone();
    set_test_probe_hook(revalidate_hook);
    let result = evidence.revalidate();
    set_test_probe_hook(None);
    result
}

#[cfg(test)]
pub(super) fn full_target_capture_probe_for_test(path: &Path) -> io::Result<()> {
    let _evidence = Evidence::open(path)?;
    Ok(())
}

#[cfg(test)]
pub(super) fn post_move_consistency_probe_for_test(
    held_mutation: Option<TestProbeMutation>,
    result_mutation: Option<TestProbeMutation>,
    acl_matches: bool,
) -> io::Result<()> {
    let base = Stamp {
        device: 1,
        inode: 2,
        mode: 0o100600,
        uid: 501,
        gid: 20,
        links: 1,
        size: 44,
        blocks: 8,
        flags: 0,
        modified: (1, 0),
        changed: (1, 0),
        created: (1, 0),
    };
    let approved = base.clone();
    let mut expected = approved.clone();
    expected.changed = (2, 0);
    let mut held = expected.clone();
    let mut result = expected.clone();

    let apply_mutation = |stamp: &mut Stamp, mutation: TestProbeMutation| match mutation {
        TestProbeMutation::Device => stamp.device += 1,
        TestProbeMutation::Inode => stamp.inode += 1,
        TestProbeMutation::Mode => stamp.mode ^= 0o100,
        TestProbeMutation::Uid => stamp.uid += 1,
        TestProbeMutation::Gid => stamp.gid += 1,
        TestProbeMutation::Nlink => stamp.links += 1,
        TestProbeMutation::Size => stamp.size += 1,
        TestProbeMutation::Blocks => stamp.blocks += 1,
        TestProbeMutation::Flags => stamp.flags ^= 1,
        TestProbeMutation::Modified => stamp.modified.1 += 1,
        TestProbeMutation::Changed => stamp.changed.1 += 1,
        TestProbeMutation::Created => stamp.created.1 += 1,
        TestProbeMutation::ChangedAndSize => {
            stamp.changed.1 += 1;
            stamp.size += 1;
        }
    };

    if let Some(mutation) = held_mutation {
        apply_mutation(&mut held, mutation);
    }
    if let Some(mutation) = result_mutation {
        apply_mutation(&mut result, mutation);
    }
    verify_post_move_consistency(&expected, &held, &result, acl_matches)
}

#[cfg(test)]
pub(super) fn post_move_capture_anchor_probe_for_test() -> io::Result<()> {
    let approved = Stamp {
        device: 1,
        inode: 2,
        mode: 0o100600,
        uid: 501,
        gid: 20,
        links: 1,
        size: 44,
        blocks: 8,
        flags: 0,
        modified: (1, 0),
        changed: (1, 0),
        created: (1, 0),
    };
    let mut held = approved.clone();
    let mut result = approved.clone();
    held.changed = (2, 0);
    result.changed = (2, 0);
    let mut expected = approved.clone();
    expected.changed = result.changed;
    verify_post_move_consistency(&expected, &held, &result, true)
}

pub(super) struct Candidate {
    pub(super) info: NativeFileInfo,
    pub(super) path: PathBuf,
    scope: PathBuf,
    uid: u32,
    ancestors: Vec<Evidence>,
    target: Evidence,
    source: Option<Evidence>,
    target_marker: Option<NativeTargetMarker>,
    protections: Vec<Evidence>,
    volume: VolumeInfo,
    attempted: AtomicBool,
    rule_binding_witness: Option<NativeRuleBindingWitness>,
}

impl Candidate {
    pub(super) fn capture(scope: &Path, path: &Path, protected: &[PathBuf]) -> io::Result<Self> {
        with_policy(|| Self::capture_inner(scope, path, None, None, protected))
    }

    pub(super) fn capture_with_source_and_marker(
        scope: &Path,
        target: &Path,
        source: &Path,
        marker: Option<NativeTargetMarker>,
        protected: &[PathBuf],
    ) -> io::Result<Self> {
        with_policy(|| Self::capture_inner(scope, target, Some(source), marker, protected))
    }

    fn capture_inner(
        scope: &Path,
        path: &Path,
        source_path: Option<&Path>,
        marker: Option<NativeTargetMarker>,
        protected: &[PathBuf],
    ) -> io::Result<Self> {
        let uid = ordinary_authority()?;
        valid_path(scope)?;
        valid_path(path)?;
        if path == scope || !path.starts_with(scope) {
            return Err(refused(
                "target must be strictly beneath its explicit scope",
            ));
        }
        let parents: Vec<_> = path.ancestors().skip(1).collect();
        if protected.len() > MAX_ANCESTORS || parents.len() > MAX_ANCESTORS - protected.len() {
            return Err(refused("candidate exceeds 64 ancestor/protection handles"));
        }
        let mut ancestors = Vec::with_capacity(parents.len());
        for parent in parents.into_iter().rev() {
            let evidence = Evidence::open_safety(parent)?;
            admissible_ancestor(&evidence.stamp, uid)?;
            reject_package(&evidence)?;
            ancestors.push(evidence);
        }
        let target = Evidence::open(path)?;
        admissible_file(&target.stamp, uid)?;
        reject_cloud_attributes(&target.file)?;
        let source = if let Some(source_path) = source_path {
            if source_path == path {
                return Err(refused("source and target must be different files"));
            }
            let source = Evidence::open(source_path)?;
            if source.stamp.identity() == target.stamp.identity() {
                return Err(refused("source and target identity must be different"));
            }
            admissible_file(&source.stamp, uid)?;
            reject_cloud_attributes(&source.file)?;
            Some(source)
        } else {
            None
        };
        let scope_evidence = ancestors
            .iter()
            .find(|ancestor| ancestor.path == scope)
            .ok_or_else(|| refused("scope identity is absent from ancestry"))?;
        let physical_scope = &scope_evidence.physical;
        if !target.physical.starts_with(physical_scope) || target.physical == *physical_scope {
            return Err(refused("physical target is outside scope"));
        }
        if let Some(source) = &source
            && (!source.physical.starts_with(physical_scope) || source.physical == *physical_scope)
        {
            return Err(refused("physical source is outside scope"));
        }
        let mut protections = Vec::with_capacity(protected.len());
        for protection in protected {
            valid_path(protection)?;
            // Exclusions may themselves be aliases. Resolve only the exclusion,
            // under the no-materialization policy, then retain its physical object.
            // Missing/inaccessible exclusions are unknown, not permission.
            let canonical = fs::canonicalize(protection)?;
            let mut evidence = Evidence::open_safety(&canonical)?;
            evidence.path = protection.clone();
            protections.push(evidence);
        }
        let volume = supported_volume(&target)?;
        if supported_volume(scope_evidence)? != volume
            || scope_evidence.stamp.device != target.stamp.device
        {
            return Err(refused(
                "scope and target must share the supported APFS volume",
            ));
        }
        let metadata = target.file.metadata()?;
        let candidate = Self {
            info: NativeFileInfo {
                device: target.stamp.device,
                inode: target.stamp.inode,
                logical_bytes: target.stamp.size,
                modified_at: metadata.modified()?,
            },
            path: path.to_owned(),
            scope: scope.to_owned(),
            uid,
            ancestors,
            target,
            source,
            target_marker: marker,
            protections,
            volume,
            attempted: AtomicBool::new(false),
            rule_binding_witness: None,
        };
        candidate.revalidate_inner()?;
        let mut candidate = candidate;
        candidate.rule_binding_witness = candidate.build_rule_binding_witness()?;
        Ok(candidate)
    }

    pub(super) fn rule_binding_witness(&self) -> Option<&NativeRuleBindingWitness> {
        self.rule_binding_witness.as_ref()
    }

    pub(super) fn revalidate(&self) -> io::Result<()> {
        with_policy(|| self.revalidate_inner())
    }

    pub(super) fn matches_exclusion(&self, exclusion: &Path) -> io::Result<bool> {
        with_policy(|| {
            valid_path(exclusion)?;
            self.revalidate_inner()?;
            let lexical =
                folded_beneath(&self.path, exclusion) || folded_beneath(exclusion, &self.path);
            let mut not_directory = None;
            for prefix in exclusion.ancestors() {
                match fs::symlink_metadata(prefix) {
                    Ok(_) => {
                        let observed = Evidence::open_safety(prefix)?;
                        let kind = observed.stamp.mode & u32::from(libc::S_IFMT);
                        if kind != u32::from(libc::S_IFDIR) && kind != u32::from(libc::S_IFREG) {
                            return Err(refused(
                                "exclusion prefix is not an ordinary file or directory",
                            ));
                        }
                        let selected = observed.stamp.identity() == self.target.stamp.identity();
                        let excluded_ancestor = prefix == exclusion
                            && self.ancestors.iter().any(|ancestor| {
                                ancestor.stamp.identity() == observed.stamp.identity()
                            });
                        observed.revalidate()?;
                        self.revalidate_inner()?;
                        if selected || excluded_ancestor {
                            return Ok(true);
                        }
                        if let Some(error) = not_directory {
                            return Err(error);
                        }
                        // A missing child beneath an existing common ancestor is
                        // not that ancestor's exclusion. Only a selected-file
                        // prefix can cover a nonexistent descendant of the file.
                        return Ok(lexical);
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) if error.raw_os_error() == Some(libc::ENOTDIR) => {
                        not_directory = Some(error);
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(refused("exclusion has no inspectable native prefix"))
        })
    }

    fn revalidate_inner(&self) -> io::Result<()> {
        if ordinary_authority()? != self.uid {
            return Err(refused("execution identity changed"));
        }
        for ancestor in &self.ancestors {
            ancestor.revalidate()?;
            admissible_ancestor(&ancestor.stamp, self.uid)?;
            reject_package(ancestor)?;
        }
        self.target.revalidate()?;
        admissible_file(&self.target.stamp, self.uid)?;
        reject_cloud_attributes(&self.target.file)?;
        if let Some(source) = &self.source {
            source.revalidate()?;
            admissible_file(&source.stamp, self.uid)?;
            reject_cloud_attributes(&source.file)?;
            if source.stamp.identity() == self.target.stamp.identity() {
                return Err(refused("source and target identity must stay distinct"));
            }
        }
        self.verify_target_marker()?;
        for protection in &self.protections {
            let canonical = fs::canonicalize(&protection.path)?;
            protection.revalidate_at(&canonical)?;
        }
        self.check_protection()?;
        if supported_volume(&self.target)? != self.volume {
            return Err(refused("native volume capabilities changed"));
        }
        // Resource queries are pathname-based too. Recheck held/path evidence
        // after them, without claiming this closes the final Foundation race.
        for ancestor in &self.ancestors {
            ancestor.revalidate()?;
            reject_package(ancestor)?;
        }
        for protection in &self.protections {
            let canonical = fs::canonicalize(&protection.path)?;
            protection.revalidate_at(&canonical)?;
        }
        self.target.revalidate()?;
        if let Some(source) = &self.source {
            source.revalidate()?;
        }
        self.verify_target_marker()?;
        Ok(())
    }

    fn verify_target_marker(&self) -> io::Result<()> {
        let Some(NativeTargetMarker::Prefix4(expected)) = self.target_marker else {
            return Ok(());
        };
        let before = Stamp::read(&self.target.file.metadata()?);
        if !self.target.binding.matches(&self.target.stamp, &before) {
            return Err(refused("target changed before marker verification"));
        }
        let mut prefix = [0_u8; 4];
        let read = self.target.file.read_at(&mut prefix, 0)?;
        if read < prefix.len() {
            return Err(refused("target marker short read"));
        }
        let after = Stamp::read(&self.target.file.metadata()?);
        if !self.target.binding.matches(&before, &after) {
            return Err(refused("target changed during marker verification"));
        }
        if prefix != expected {
            return Err(refused("target marker mismatch"));
        }
        Ok(())
    }

    fn check_protection(&self) -> io::Result<()> {
        for path in [&self.path, &self.target.physical, &self.scope] {
            if standard_protected(path) {
                return Err(refused(
                    "system, cloud, hidden, or application-managed path",
                ));
            }
        }
        for protection in &self.protections {
            if folded_beneath(&self.path, &protection.path)
                || folded_beneath(&self.target.physical, &protection.physical)
                || self
                    .source
                    .as_ref()
                    .is_some_and(|source| folded_beneath(&source.path, &protection.path))
                || self
                    .source
                    .as_ref()
                    .is_some_and(|source| folded_beneath(&source.physical, &protection.physical))
                || self.target.stamp.identity() == protection.stamp.identity()
                || self
                    .source
                    .as_ref()
                    .is_some_and(|source| source.stamp.identity() == protection.stamp.identity())
                || self
                    .ancestors
                    .iter()
                    .any(|ancestor| ancestor.stamp.identity() == protection.stamp.identity())
            {
                return Err(refused("target is physically or lexically protected"));
            }
        }
        Ok(())
    }

    pub(super) fn move_to_trash_with_last_guard(
        &self,
        cancelled: impl FnOnce() -> bool,
        last_guard: impl FnOnce() -> NativeLastGuard,
    ) -> NativeTrashOutcome {
        if self.attempted.swap(true, Ordering::AcqRel) {
            return NativeTrashOutcome::Refused(
                "candidate was already submitted; never retry".into(),
            );
        }
        let policy = match ReadOnlyPolicy::enter() {
            Ok(policy) => policy,
            Err(error) => return NativeTrashOutcome::Refused(error.to_string()),
        };
        let outcome = objc2::rc::autoreleasepool(|_| {
            let prepared = match foundation::Prepared::new(&self.path) {
                Ok(prepared) => prepared,
                Err(error) => return NativeTrashOutcome::Refused(error.to_string()),
            };
            if let Err(error) = self.revalidate_inner() {
                return NativeTrashOutcome::Refused(error.to_string());
            }
            match last_guard() {
                NativeLastGuard::Proceed => {}
                NativeLastGuard::Cancelled => {
                    return NativeTrashOutcome::Refused("cancelled".into());
                }
                NativeLastGuard::PolicyRefused(reason) => {
                    return NativeTrashOutcome::Refused(reason);
                }
            }
            self.interpret_response(prepared.trash(cancelled))
        });
        self.finish_restore(outcome, policy.restore())
    }

    fn observe_recovery(&self, returned_destination: Option<PathBuf>) -> NativeRecoveryEvidence {
        recovery_observations(
            &self.info,
            returned_destination,
            file_info(&self.target.file),
            physical_path(&self.target.file),
        )
    }

    fn interpret_response(&self, response: foundation::Outcome) -> NativeTrashOutcome {
        match response {
            foundation::Outcome::Cancelled => NativeTrashOutcome::Refused("cancelled".into()),
            foundation::Outcome::Failed(error) => NativeTrashOutcome::Failed(error),
            foundation::Outcome::Unknown {
                message,
                returned_destination,
                destination_error,
            } => {
                let mut evidence = self.observe_recovery(returned_destination);
                if let Some(error) = destination_error {
                    evidence.record_error(error);
                }
                NativeTrashOutcome::Unknown { message, evidence }
            }
            foundation::Outcome::Destination(destination) => {
                // Capture descriptor/path observations before optional destination
                // metadata checks. Later refusal must not erase recovery hints.
                let mut evidence = self.observe_recovery(Some(destination.clone()));
                match self.verify_destination(&destination) {
                    Ok(()) => NativeTrashOutcome::Moved { destination },
                    Err(error) => {
                        evidence.record_error(format!("destination verification: {error}"));
                        NativeTrashOutcome::Unknown {
                            message: format!(
                                "Foundation reported a move but destination verification failed: {error}"
                            ),
                            evidence,
                        }
                    }
                }
            }
        }
    }

    fn finish_restore(
        &self,
        outcome: NativeTrashOutcome,
        restored: io::Result<()>,
    ) -> NativeTrashOutcome {
        match restored {
            Ok(()) => outcome,
            Err(error) => match outcome {
                NativeTrashOutcome::Refused(cause) => NativeTrashOutcome::Refused(format!(
                    "{cause}; restoring thread policy failed: {error}"
                )),
                NativeTrashOutcome::Failed(cause) => NativeTrashOutcome::Failed(format!(
                    "{cause}; restoring thread policy failed: {error}"
                )),
                NativeTrashOutcome::Moved { destination } => {
                    let mut evidence = self.observe_recovery(Some(destination));
                    evidence
                        .record_error(format!("post-effect thread policy restoration: {error}"));
                    NativeTrashOutcome::Unknown {
                        message: format!(
                            "destination was verified, but restoring thread policy failed after the move: {error}"
                        ),
                        evidence,
                    }
                }
                NativeTrashOutcome::Unknown {
                    message,
                    mut evidence,
                } => {
                    evidence
                        .record_error(format!("post-effect thread policy restoration: {error}"));
                    NativeTrashOutcome::Unknown {
                        message: format!(
                            "{message}; restoring thread policy failed after possible effect: {error}"
                        ),
                        evidence,
                    }
                }
            },
        }
    }

    fn verify_destination(&self, destination: &Path) -> io::Result<()> {
        let (file, stamp) = Evidence::open_handle(destination, Binding::PostMoveTarget)?;
        if stamp.identity() != self.target.stamp.identity() {
            return Err(refused(
                "returned destination identity does not match the retained original",
            ));
        }
        admissible_file(&stamp, self.uid)?;
        reject_destination_attributes(&file)?;
        let mut result = Evidence::complete(destination, Binding::PostMoveTarget, file, stamp)?;
        let mut held = Stamp::read(&self.target.file.metadata()?);
        apply_test_probe_hook(TestProbeStage::HeldAfterCapture, &mut held);
        if held.identity() != self.target.stamp.identity() {
            return Err(refused(
                "retained source identity changed after reported move",
            ));
        }
        admissible_file(&held, self.uid)?;
        // The initial destination observation tolerates bounded ctime evolution
        // while metadata/ACL capture settles. Afterwards, pin the observed ctime
        // and require full target equality for held/source and final revalidation.
        let mut expected = self.target.stamp.clone();
        expected.changed = result.stamp.changed;
        verify_post_move_consistency(
            &expected,
            &held,
            &result.stamp,
            result.acl == self.target.acl,
        )?;
        if physical_path(&self.target.file)? != result.physical {
            return Err(refused("retained source and resulting URL disagree"));
        }
        match fs::symlink_metadata(&self.path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
            Ok(_) => return Err(refused("source path still exists after reported move")),
        }
        result.binding = Binding::FullTarget;
        result.stamp = expected;
        result.revalidate()?;
        Ok(())
    }

    fn build_rule_binding_witness(&self) -> io::Result<Option<NativeRuleBindingWitness>> {
        let Some(source) = &self.source else {
            return Ok(None);
        };
        let root = self
            .ancestors
            .iter()
            .find(|ancestor| ancestor.path == self.scope)
            .ok_or_else(|| refused("scope identity is absent from ancestry"))?;
        let target_ancestors = self
            .ancestors
            .iter()
            .filter(|ancestor| {
                ancestor.path != self.scope && ancestor.path.starts_with(&self.scope)
            })
            .map(native_witness)
            .collect();
        let source_ancestors = ancestors_between(&self.scope, &source.path)?
            .into_iter()
            .map(|path| Evidence::open_safety(&path))
            .collect::<io::Result<Vec<_>>>()?
            .into_iter()
            .map(|evidence| native_witness(&evidence))
            .collect();
        Ok(Some(NativeRuleBindingWitness {
            target: native_witness(&self.target),
            source: native_witness(source),
            root: native_witness(root),
            target_ancestors,
            source_ancestors,
        }))
    }
}

fn ancestors_between(scope: &Path, leaf: &Path) -> io::Result<Vec<PathBuf>> {
    if !leaf.starts_with(scope) || leaf == scope {
        return Err(refused("leaf must be inside scope"));
    }
    let relative = leaf
        .strip_prefix(scope)
        .map_err(|_| refused("leaf must be inside scope"))?;
    let mut current = scope.to_path_buf();
    let mut ancestors = Vec::new();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(refused("leaf path must be normal components"));
        };
        current.push(name);
        if current != leaf {
            ancestors.push(current.clone());
        }
    }
    Ok(ancestors)
}

fn native_witness(evidence: &Evidence) -> NativeWitnessInfo {
    let kind = match evidence.stamp.mode & u32::from(libc::S_IFMT) {
        x if x == u32::from(libc::S_IFREG) => "file",
        x if x == u32::from(libc::S_IFDIR) => "directory",
        x if x == u32::from(libc::S_IFLNK) => "link",
        _ => "other",
    };
    NativeWitnessInfo {
        path: evidence.path.clone(),
        kind,
        device: evidence.stamp.device,
        inode: evidence.stamp.inode,
        logical_bytes: evidence.stamp.size,
        modified_unix_seconds: evidence.stamp.modified.0,
        modified_nanoseconds: evidence.stamp.modified.1,
        changed_unix_seconds: evidence.stamp.changed.0,
        changed_nanoseconds: evidence.stamp.changed.1,
        created_unix_seconds: evidence.stamp.created.0,
        created_nanoseconds: evidence.stamp.created.1,
        uid: evidence.stamp.uid,
        gid: evidence.stamp.gid,
        mode: evidence.stamp.mode,
        nlink: evidence.stamp.links,
        flags: evidence.stamp.flags,
    }
}

fn file_info(file: &File) -> io::Result<NativeFileInfo> {
    let metadata = file.metadata()?;
    Ok(NativeFileInfo {
        device: metadata.dev(),
        inode: metadata.ino(),
        logical_bytes: metadata.size(),
        modified_at: metadata.modified()?,
    })
}

fn recovery_observations(
    approved: &NativeFileInfo,
    returned_destination: Option<PathBuf>,
    held_info: io::Result<NativeFileInfo>,
    held_path: io::Result<PathBuf>,
) -> NativeRecoveryEvidence {
    let mut evidence = NativeRecoveryEvidence {
        approved: approved.clone(),
        returned_destination,
        held_source: None,
        held_source_path: None,
        observation_errors: Vec::with_capacity(5),
    };
    if evidence.returned_destination.is_none() {
        evidence.record_error(
            "Foundation returned destination pathname is unavailable; no path was inferred".into(),
        );
    }
    match held_info {
        Ok(info) => evidence.held_source = Some(info),
        Err(error) => evidence.record_error(format!(
            "held-source fstat/mtime observation unavailable: {error}"
        )),
    }
    match held_path {
        Ok(path) => evidence.held_source_path = Some(path),
        Err(error) => evidence.record_error(format!(
            "held-source F_GETPATH observation unavailable: {error}"
        )),
    }
    evidence
}

fn refused(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn with_policy<T>(action: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    let policy = ReadOnlyPolicy::enter()?;
    let result = action();
    match (result, policy.restore()) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(first), Err(second)) => Err(io::Error::other(format!(
            "{first}; restoring thread policy failed: {second}"
        ))),
    }
}

fn valid_path(path: &Path) -> io::Result<()> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() > MAX_PATH_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path exceeds 4096 bytes",
        ));
    }
    if path.ancestors().skip(1).count() > MAX_ANCESTORS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path exceeds 64 ancestors",
        ));
    }
    if !path.is_absolute()
        || bytes.contains(&0)
        || bytes
            .split(|byte| *byte == b'/')
            .any(|part| part == b"." || part == b"..")
        || bytes.windows(2).any(|pair| pair == b"//")
        || (bytes.len() > 1 && bytes.ends_with(b"/"))
        || path
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path must be absolute and unambiguous",
        ));
    }
    Ok(())
}

fn ordinary_authority() -> io::Result<u32> {
    // SAFETY: These integer-only functions query the current process authority.
    let (uid, effective, gid, effective_gid) = unsafe {
        (
            libc::getuid(),
            libc::geteuid(),
            libc::getgid(),
            libc::getegid(),
        )
    };
    if uid == 0 || uid != effective || gid != effective_gid {
        return Err(refused(
            "root or changed-user/group execution is unsupported",
        ));
    }
    Ok(uid)
}

fn admissible_file(stamp: &Stamp, uid: u32) -> io::Result<()> {
    if stamp.mode & u32::from(libc::S_IFMT) != u32::from(libc::S_IFREG)
        || stamp.mode & 0o7022 != 0
        || stamp.uid != uid
        || stamp.links != 1
        || stamp.flags & !ORDINARY_FLAGS != 0
        || stamp.inode == 0
    {
        return Err(refused(
            "requires an ordinary single-link user-owned unprotected file",
        ));
    }
    Ok(())
}

fn admissible_ancestor(stamp: &Stamp, uid: u32) -> io::Result<()> {
    if stamp.mode & u32::from(libc::S_IFMT) != u32::from(libc::S_IFDIR)
        || stamp.mode & 0o7022 != 0
        || (stamp.uid != uid && stamp.uid != 0)
        || stamp.flags & !(ORDINARY_FLAGS | SF_RESTRICTED | SF_NOUNLINK) != 0
        || stamp.inode == 0
    {
        return Err(refused(
            "untrusted, writable, special, or dataless ancestor",
        ));
    }
    Ok(())
}

fn reject_package(evidence: &Evidence) -> io::Result<()> {
    if crate::volume::is_package(&evidence.path)? {
        return Err(refused("native application-managed package ancestor"));
    }
    // Resource queries are pathname-based. Preserve the original no-follow
    // identity/safety binding after classification; never admit a replacement.
    evidence.revalidate()
}

fn physical_path(file: &File) -> io::Result<PathBuf> {
    let mut bytes = [0u8; MAX_PATH_BYTES + 1];
    // SAFETY: F_GETPATH_NOFIRMLINK writes a NUL-terminated MAXPATHLEN path into
    // the provided oversized buffer; file is a live borrowed descriptor.
    if unsafe { libc::fcntl(file.as_raw_fd(), F_GETPATH_NOFIRMLINK, bytes.as_mut_ptr()) } == -1 {
        return Err(io::Error::last_os_error());
    }
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| refused("physical path is not terminated"))?;
    let path = PathBuf::from(OsString::from_vec(bytes[..end].to_vec()));
    valid_path(&path)?;
    Ok(path)
}

fn supported_volume(evidence: &Evidence) -> io::Result<VolumeInfo> {
    let mut stat = MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: fstatfs initializes the structure on success for this live fd.
    if unsafe { libc::fstatfs(evidence.file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: The successful call initialized the complete statfs value.
    let stat = unsafe { stat.assume_init() };
    let kind: Vec<u8> = stat
        .f_fstypename
        .iter()
        .map(|byte| *byte as u8)
        .take_while(|byte| *byte != 0)
        .collect();
    if kind != b"apfs" || stat.f_flags & libc::MNT_RDONLY as u32 != 0 {
        return Err(refused("requires writable APFS"));
    }
    let info = volume_info(&evidence.path)?;
    if !info.local || !info.internal || info.removable || info.ejectable {
        return Err(refused(
            "requires local internal nonremovable nonejectable volume",
        ));
    }
    Ok(info)
}

fn reject_cloud_attributes(file: &File) -> io::Result<()> {
    inspect_attributes(file, AttributePhase::Source)
}

fn reject_destination_attributes(file: &File) -> io::Result<()> {
    inspect_attributes(file, AttributePhase::PostEffectDestination)
}

#[derive(Clone, Copy)]
enum AttributePhase {
    Source,
    PostEffectDestination,
}

fn inspect_attributes(file: &File, phase: AttributePhase) -> io::Result<()> {
    let mut bytes = [0u8; 16 * 1024];
    // SAFETY: Live descriptor, writable buffer with its exact capacity; reading
    // attribute names does not request file contents. No resource-fork access.
    let count =
        unsafe { libc::flistxattr(file.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len(), 0) };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    if count as usize > bytes.len() {
        return Err(io::Error::other(
            "native attribute list exceeds the inspection bound",
        ));
    }
    check_attribute_names(&bytes[..count as usize], phase)
}

fn check_attribute_names(bytes: &[u8], phase: AttributePhase) -> io::Result<()> {
    for name in bytes
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
    {
        // An explicit narrow allowlist avoids treating unknown provider metadata
        // as proof of local materialization. No attributes are rewritten.
        let source_allowed = matches!(
            name,
            b"com.apple.quarantine" | b"com.apple.FinderInfo" | b"com.apple.provenance"
        ) || name.starts_with(b"com.apple.metadata:");
        // MACL was observed as system-added after a verified-source move.
        // This exception is exact and post-effect only; source admission
        // never accepts it. No value is read, inferred, or modified.
        let generated_destination_attribute =
            matches!(phase, AttributePhase::PostEffectDestination) && name == b"com.apple.macl";
        if !(source_allowed || generated_destination_attribute) {
            return Err(refused(
                "unknown or cloud/resource-fork extended attributes",
            ));
        }
    }
    Ok(())
}

fn folded_beneath(path: &Path, root: &Path) -> bool {
    let path: Vec<_> = path.components().collect();
    let root: Vec<_> = root.components().collect();
    root.len() <= path.len()
        && root
            .iter()
            .zip(path.iter())
            .all(|(left, right)| fold(left.as_os_str()) == fold(right.as_os_str()))
}

fn fold(value: &OsStr) -> Vec<u8> {
    match value.to_str() {
        Some(value) => value.to_lowercase().into_bytes(),
        None => value.as_bytes().to_ascii_lowercase(),
    }
}

fn standard_protected(path: &Path) -> bool {
    let parts: Vec<_> = path
        .components()
        .filter_map(|part| match part {
            Component::Normal(value) => Some(fold(value)),
            _ => None,
        })
        .collect();
    // F_GETPATH_NOFIRMLINK reveals the Data volume prefix. Interpret its root as
    // the corresponding live root, not as permission to bypass /System checks.
    let parts = if parts.starts_with(&[b"system".to_vec(), b"volumes".to_vec(), b"data".to_vec()]) {
        &parts[3..]
    } else {
        &parts[..]
    };
    let Some(first) = parts.first() else {
        return true;
    };
    if matches!(
        first.as_slice(),
        b"system"
            | b"library"
            | b"applications"
            | b"bin"
            | b"sbin"
            | b"usr"
            | b"etc"
            | b"private"
            | b"var"
            | b"dev"
            | b"volumes"
            | b"cores"
            | b"network"
            | b"opt"
            | b"home"
            | b"net"
    ) {
        return true;
    }
    parts.iter().any(|part| {
        part.starts_with(b".")
            || matches!(
                part.as_slice(),
                b"library"
                    | b"applications"
                    | b"dropbox"
                    | b"onedrive"
                    | b"google drive"
                    | b"icloud drive"
            )
            || part.starts_with(b"onedrive - ")
            || [
                b".app".as_slice(),
                b".bundle",
                b".framework",
                b".photoslibrary",
                b".musiclibrary",
                b".sparsebundle",
                b".vmwarevm",
                b".pvm",
                b".utm",
                b".vboxvm",
                b".virtualboxvm",
            ]
            .iter()
            .any(|suffix| part.ends_with(suffix))
    })
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
