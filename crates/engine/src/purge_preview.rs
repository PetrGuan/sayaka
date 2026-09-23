// SPDX-License-Identifier: MPL-2.0

//! Read-only project-artifact (purge) preview from one bounded scan (T8).
//!
//! Groups rebuildable artifact directories by their project root. A name
//! match alone never qualifies: an artifact must be a direct child of a
//! project root that carries the binding project marker, which is also the
//! rebuild evidence. Nested projects inside another project's artifact are
//! excluded, not merged. This preview performs no effects: directory effects
//! remain unapproved; see docs/DIRECTORY_ACTIONS.md.

use crate::execute::PurgeSelection;
use crate::model::ResourceKind;
use crate::scan::ScanStatus;
use crate::scan::index::{Metric, ScanTree};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const PURGE_SCHEMA_VERSION: u32 = 1;
pub const PURGE_KIND: &str = "sayaka.purge_preview";
pub const DEFAULT_STALE_DAYS: u32 = 30;
pub const MAX_STALE_DAYS: u32 = 3650;

/// Fixed project markers; each is also the rebuild evidence for its bound
/// artifact directory names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProjectMarker {
    CargoToml,
    PackageJson,
    PyprojectToml,
    PackageSwift,
}

impl ProjectMarker {
    /// Every marker kind, for re-evaluating the artifact/marker binding
    /// against the live filesystem at approval and guard time.
    pub const ALL: &'static [ProjectMarker] = &[
        Self::CargoToml,
        Self::PackageJson,
        Self::PyprojectToml,
        Self::PackageSwift,
    ];

    pub const fn file_name(self) -> &'static str {
        match self {
            Self::CargoToml => "Cargo.toml",
            Self::PackageJson => "package.json",
            Self::PyprojectToml => "pyproject.toml",
            Self::PackageSwift => "Package.swift",
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CargoToml => "cargo",
            Self::PackageJson => "node",
            Self::PyprojectToml => "python",
            Self::PackageSwift => "swift",
        }
    }

    /// Artifact directory names bound to this marker. Name equality without
    /// the marker never qualifies.
    pub const fn artifacts(self) -> &'static [&'static str] {
        match self {
            Self::CargoToml => &["target"],
            Self::PackageJson => &["node_modules", "dist"],
            Self::PyprojectToml => &["dist", "build"],
            Self::PackageSwift => &[".build"],
        }
    }

    fn from_file_name(name: &str) -> Option<Self> {
        match name {
            "Cargo.toml" => Some(Self::CargoToml),
            "package.json" => Some(Self::PackageJson),
            "pyproject.toml" => Some(Self::PyprojectToml),
            "Package.swift" => Some(Self::PackageSwift),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PurgeOptions {
    pub stale_days: u32,
}

impl Default for PurgeOptions {
    fn default() -> Self {
        Self {
            stale_days: DEFAULT_STALE_DAYS,
        }
    }
}

impl PurgeOptions {
    pub fn validate(self) -> Result<(), String> {
        if (1..=MAX_STALE_DAYS).contains(&self.stale_days) {
            Ok(())
        } else {
            Err(format!(
                "stale days must be in 1..={MAX_STALE_DAYS}, got {}",
                self.stale_days
            ))
        }
    }
}

#[derive(Clone, Debug)]
pub struct PurgeArtifact {
    pub path: PathBuf,
    pub name: String,
    /// Markers whose tables bind this directory name.
    pub markers: Vec<ProjectMarker>,
    /// Known subtotal, not necessarily a complete measurement.
    pub logical_bytes: Option<u64>,
    pub allocated_bytes: Option<u64>,
    /// Traversal coverage of the artifact subtree, independent of whether
    /// individual measurements are known.
    pub complete: bool,
    /// Observed directory mtime; an observation, not proof of disuse.
    pub modified_unix_ms: Option<i64>,
    /// Staleness vs the cutoff; None when mtime is unknown.
    pub stale: Option<bool>,
}

#[derive(Clone, Debug)]
pub struct PurgeProject {
    pub root: PathBuf,
    pub markers: Vec<ProjectMarker>,
    pub artifacts: Vec<PurgeArtifact>,
}

#[derive(Clone, Debug, Default)]
pub struct PurgeCounts {
    pub projects: usize,
    pub artifacts: usize,
    pub stale_artifacts: usize,
    /// Projects or artifacts excluded because they nest inside another
    /// project's artifact, or because the artifact is a dataless placeholder.
    pub excluded: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PurgeStatus {
    Complete,
    Partial,
    Cancelled,
    Failed,
}

impl PurgeStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Debug)]
pub struct PurgePreview {
    pub schema_version: u32,
    pub kind: &'static str,
    pub platform: &'static str,
    pub status: PurgeStatus,
    pub complete: bool,
    pub effects_performed: bool,
    pub roots: Vec<PathBuf>,
    pub stale_days: u32,
    pub projects: Vec<PurgeProject>,
    pub counts: PurgeCounts,
    /// Scan-side issues (denied subtrees, budget limits) explaining partial
    /// or failed coverage; never filtered away.
    pub scan_issues: Vec<crate::scan::ScanIssue>,
    pub scan_issues_omitted: usize,
}

/// Stable host-facing item reference for artifacts in a preview. Item ids are
/// scoped to one preview/digest and intentionally have no meaning on their own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PurgeItemId(pub u64);

impl PurgePreview {
    pub fn plan_digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.schema_version.to_le_bytes());
        hasher.update(self.kind.as_bytes());
        hasher.update(self.platform.as_bytes());
        hasher.update(self.status.as_str().as_bytes());
        hasher.update([u8::from(self.complete)]);
        hasher.update(self.stale_days.to_le_bytes());
        for root in &self.roots {
            hash_path(&mut hasher, root);
        }
        for project in &self.projects {
            hash_path(&mut hasher, &project.root);
            for marker in &project.markers {
                hasher.update(marker.as_str().as_bytes());
                hasher.update([0]);
            }
            for artifact in &project.artifacts {
                hash_path(&mut hasher, &artifact.path);
                hasher.update(artifact.name.as_bytes());
                hasher.update([0]);
                for marker in &artifact.markers {
                    hasher.update(marker.as_str().as_bytes());
                    hasher.update([0]);
                }
                hash_option_u64(&mut hasher, artifact.logical_bytes);
                hash_option_u64(&mut hasher, artifact.allocated_bytes);
                hasher.update([u8::from(artifact.complete)]);
                hash_option_i64(&mut hasher, artifact.modified_unix_ms);
                hasher.update(match artifact.stale {
                    Some(true) => [1],
                    Some(false) => [2],
                    None => [0],
                });
            }
        }
        hasher.update((self.counts.projects as u64).to_le_bytes());
        hasher.update((self.counts.artifacts as u64).to_le_bytes());
        hasher.update((self.counts.stale_artifacts as u64).to_le_bytes());
        hasher.update((self.counts.excluded as u64).to_le_bytes());
        let digest = hasher.finalize();
        let mut out = String::with_capacity(digest.len() * 2);
        for byte in digest {
            use std::fmt::Write;
            write!(&mut out, "{byte:02x}").expect("hex write");
        }
        out
    }

    pub fn item_count(&self) -> usize {
        self.projects
            .iter()
            .map(|project| project.artifacts.len())
            .sum()
    }

    pub fn item_id_for(&self, project_index: usize, artifact_index: usize) -> PurgeItemId {
        let mut value = 1u64;
        for project in &self.projects[..project_index] {
            value += project.artifacts.len() as u64;
        }
        PurgeItemId(value + artifact_index as u64)
    }
}

fn hash_path(hasher: &mut Sha256, path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        hasher.update(path.as_os_str().as_bytes());
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        for unit in path.as_os_str().encode_wide() {
            hasher.update(unit.to_le_bytes());
        }
    }
    hasher.update([0xff]);
}

fn hash_option_u64(hasher: &mut Sha256, value: Option<u64>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            hasher.update(value.to_le_bytes());
        }
        None => hasher.update([0]),
    }
}

fn hash_option_i64(hasher: &mut Sha256, value: Option<i64>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            hasher.update(value.to_le_bytes());
        }
        None => hasher.update([0]),
    }
}

pub fn resolve_selections_by_paths(
    preview: &PurgePreview,
    only: &[PathBuf],
) -> Result<Vec<PurgeSelection>, String> {
    let mut selections = Vec::with_capacity(only.len());
    for requested in only {
        if requested
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err("'..' traversal is not accepted in purge selections".into());
        }
        let requested = std::path::absolute(requested)
            .map_err(|error| format!("cannot resolve purge selection: {error}"))?;
        if selections
            .iter()
            .any(|selection: &PurgeSelection| selection.artifact == requested)
        {
            return Err(format!(
                "duplicate purge selection: {}",
                requested.display()
            ));
        }
        selections.push(selection_for_path(preview, &requested).ok_or_else(|| {
            format!(
                "selection names no artifact of this preview: {}",
                requested.display()
            )
        })?);
    }
    Ok(selections)
}

pub fn resolve_selections_by_ids(
    preview: &PurgePreview,
    item_ids: &[PurgeItemId],
) -> Result<Vec<PurgeSelection>, String> {
    let mut seen = HashSet::new();
    let mut selections = Vec::with_capacity(item_ids.len());
    for id in item_ids {
        if id.0 == 0 || !seen.insert(id.0) {
            return Err("purge item references must be unique nonzero ids".into());
        }
        selections.push(
            selection_for_id(preview, *id)
                .ok_or_else(|| format!("purge item id {} is not in this preview", id.0))?,
        );
    }
    Ok(selections)
}

fn selection_for_id(preview: &PurgePreview, id: PurgeItemId) -> Option<PurgeSelection> {
    let mut current = 1u64;
    for project in &preview.projects {
        for artifact in &project.artifacts {
            if current == id.0 {
                return Some(selection_from_parts(project, artifact));
            }
            current = current.checked_add(1)?;
        }
    }
    None
}

fn selection_for_path(preview: &PurgePreview, path: &std::path::Path) -> Option<PurgeSelection> {
    for project in &preview.projects {
        for artifact in &project.artifacts {
            if artifact.path == path {
                return Some(selection_from_parts(project, artifact));
            }
        }
    }
    None
}

fn selection_from_parts(project: &PurgeProject, artifact: &PurgeArtifact) -> PurgeSelection {
    PurgeSelection {
        artifact: artifact.path.clone(),
        project_root: project.root.clone(),
        markers: artifact
            .markers
            .iter()
            .map(|marker| project.root.join(marker.file_name()))
            .collect(),
    }
}

/// Builds the read-only purge preview from one finished scan index.
/// `now` is injected so staleness is deterministic in fixtures.
pub fn purge_preview(
    index: &ScanTree,
    options: &PurgeOptions,
    now: SystemTime,
) -> Result<PurgePreview, String> {
    options.validate()?;
    let cutoff = Duration::from_secs(u64::from(options.stale_days) * 86_400);
    let mut projects = Vec::new();
    let mut artifact_paths: Vec<PathBuf> = Vec::new();
    // First pass: project roots are directories with at least one marker
    // file as a direct child.
    let mut stack: Vec<u64> = index.roots().to_vec();
    let mut directories = Vec::new();
    while let Some(id) = stack.pop() {
        let Some(entry) = index.entry(id) else {
            continue;
        };
        if entry.kind != ResourceKind::Directory {
            continue;
        }
        directories.push(id);
        if let Some(children) = index.children(id) {
            stack.extend_from_slice(children);
        }
    }
    for &id in &directories {
        let mut markers = Vec::new();
        let Some(children) = index.children(id) else {
            continue;
        };
        for &child in children {
            let Some(entry) = index.entry(child) else {
                continue;
            };
            if entry.kind == ResourceKind::File
                && let Some(marker) = entry
                    .path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .and_then(ProjectMarker::from_file_name)
                && !markers.contains(&marker)
            {
                markers.push(marker);
            }
        }
        if markers.is_empty() {
            continue;
        }
        let root = index.entry(id).expect("directory entry").path.clone();
        let mut artifacts = Vec::new();
        for &child in children {
            let Some(entry) = index.entry(child) else {
                continue;
            };
            if entry.kind != ResourceKind::Directory {
                continue;
            }
            let Some(name) = entry.path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let bound: Vec<ProjectMarker> = markers
                .iter()
                .copied()
                .filter(|marker| marker.artifacts().contains(&name))
                .collect();
            if bound.is_empty() {
                continue;
            }
            artifact_paths.push(entry.path.clone());
            artifacts.push((child, entry.path.clone(), name.to_string(), bound));
        }
        if !artifacts.is_empty() {
            projects.push((root, markers, artifacts));
        }
    }
    // Second pass: drop projects/artifacts nested inside another project's
    // artifact; their evidence belongs to the outer project alone.
    artifact_paths.sort();
    let mut output = Vec::new();
    let mut counts = PurgeCounts::default();
    for (root, markers, artifacts) in projects {
        if artifact_paths
            .iter()
            .any(|artifact| root.starts_with(artifact))
        {
            counts.excluded += 1;
            continue;
        }
        let mut out_artifacts = Vec::new();
        for (child, path, name, bound) in artifacts {
            if artifact_paths
                .iter()
                .any(|artifact| path != *artifact && path.starts_with(artifact))
            {
                counts.excluded += 1;
                continue;
            }
            let entry = index.entry(child).expect("artifact entry");
            if entry.dataless {
                counts.excluded += 1;
                continue;
            }
            let summary = index.summary(child);
            let modified = std::fs::symlink_metadata(&path)
                .ok()
                .and_then(|metadata| metadata.modified().ok())
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                .and_then(|duration| i64::try_from(duration.as_millis()).ok());
            let stale = modified.map(|mtime| {
                now.duration_since(UNIX_EPOCH)
                    .ok()
                    .and_then(|since_epoch| {
                        since_epoch
                            .as_millis()
                            .checked_sub(mtime as u128)
                            .map(|age| Duration::from_millis(age as u64) > cutoff)
                    })
                    .unwrap_or(false)
            });
            if stale == Some(true) {
                counts.stale_artifacts += 1;
            }
            out_artifacts.push(PurgeArtifact {
                path,
                name,
                markers: bound,
                logical_bytes: index.size(child, Metric::Logical),
                allocated_bytes: index.size(child, Metric::Allocated),
                complete: summary.is_some_and(|summary| summary.complete),
                modified_unix_ms: modified,
                stale,
            });
        }
        if !out_artifacts.is_empty() {
            counts.artifacts += out_artifacts.len();
            output.push(PurgeProject {
                root,
                markers,
                artifacts: out_artifacts,
            });
        }
    }
    counts.projects = output.len();
    output.sort_by(|left, right| left.root.cmp(&right.root));
    let report = index.report();
    let status = match report.status {
        ScanStatus::Complete => PurgeStatus::Complete,
        ScanStatus::Partial => PurgeStatus::Partial,
        ScanStatus::Cancelled => PurgeStatus::Cancelled,
        ScanStatus::Failed => PurgeStatus::Failed,
    };
    Ok(PurgePreview {
        schema_version: PURGE_SCHEMA_VERSION,
        kind: PURGE_KIND,
        platform: if cfg!(target_os = "macos") {
            "macos"
        } else {
            "unsupported"
        },
        status,
        complete: report.status == ScanStatus::Complete,
        effects_performed: false,
        roots: report.roots.clone(),
        stale_days: options.stale_days,
        projects: output,
        counts,
        scan_issues: report.issues.clone(),
        scan_issues_omitted: report.issues_omitted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Cancellation;
    use crate::scan::{ScanLimits, index::ScanTree, scan};
    use std::fs;

    fn fixture_tree() -> tempfile::TempDir {
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path();
        // Rust project with a target dir.
        let rust = path.join("rust-app");
        fs::create_dir_all(rust.join("target").join("debug")).expect("rust tree");
        fs::write(rust.join("Cargo.toml"), b"[package]").expect("cargo");
        fs::write(rust.join("target").join("debug").join("bin"), b"x").expect("bin");
        // Node project with node_modules and dist.
        let node = path.join("web");
        fs::create_dir_all(node.join("node_modules").join("dep")).expect("node tree");
        fs::create_dir_all(node.join("dist")).expect("dist");
        fs::write(node.join("package.json"), b"{}").expect("pkg");
        // A bare "target" directory without a marker never qualifies.
        let bare = path.join("downloads");
        fs::create_dir_all(bare.join("target")).expect("bare target");
        // Nested project inside an artifact is excluded.
        let nested = node.join("node_modules").join("dep");
        fs::write(nested.join("package.json"), b"{}").expect("nested pkg");
        fs::create_dir_all(nested.join("dist")).expect("nested dist");
        root
    }

    fn preview_at(root: &std::path::Path, now: SystemTime) -> PurgePreview {
        let cancellation = Cancellation::default();
        let report = scan(
            &[root.to_path_buf()],
            &ScanLimits::default(),
            &cancellation,
            |_| {},
        )
        .expect("scan");
        let index = ScanTree::build(report, &cancellation).expect("index");
        purge_preview(&index, &PurgeOptions::default(), now).expect("preview")
    }

    #[test]
    fn artifacts_require_binding_markers_and_nesting_is_excluded() {
        let root = fixture_tree();
        let preview = preview_at(root.path(), SystemTime::now());
        assert_eq!(preview.status, PurgeStatus::Complete);
        assert!(!preview.effects_performed);
        assert_eq!(preview.counts.projects, 2);
        let names: Vec<&str> = preview
            .projects
            .iter()
            .flat_map(|project| {
                project
                    .artifacts
                    .iter()
                    .map(|artifact| artifact.name.as_str())
            })
            .collect();
        assert!(names.contains(&"target"));
        assert!(names.contains(&"node_modules"));
        assert_eq!(
            names.iter().filter(|name| **name == "dist").count(),
            1,
            "nested dep/dist must be excluded: {names:?}"
        );
        let rust = preview
            .projects
            .iter()
            .find(|project| project.root.ends_with("rust-app"))
            .expect("rust project");
        assert_eq!(rust.markers, vec![ProjectMarker::CargoToml]);
        assert_eq!(rust.artifacts[0].markers, vec![ProjectMarker::CargoToml]);
        assert!(rust.artifacts[0].logical_bytes.is_some());
        assert!(preview.counts.excluded >= 1);
        // The bare downloads/target directory never appears.
        assert!(
            preview
                .projects
                .iter()
                .all(|project| !project.root.ends_with("downloads"))
        );
    }

    #[test]
    fn staleness_uses_injected_now_and_validates_options() {
        let root = fixture_tree();
        let now = SystemTime::now();
        let fresh = preview_at(root.path(), now);
        assert!(
            fresh
                .projects
                .iter()
                .flat_map(|project| project.artifacts.iter())
                .all(|artifact| artifact.stale == Some(false))
        );
        let later = now + Duration::from_secs(31 * 86_400);
        let aged = preview_at(root.path(), later);
        assert!(
            aged.projects
                .iter()
                .flat_map(|project| project.artifacts.iter())
                .all(|artifact| artifact.stale == Some(true))
        );
        assert_eq!(aged.counts.stale_artifacts, aged.counts.artifacts);
        assert!(PurgeOptions { stale_days: 0 }.validate().is_err());
        assert!(
            PurgeOptions {
                stale_days: MAX_STALE_DAYS + 1
            }
            .validate()
            .is_err()
        );
    }
}
