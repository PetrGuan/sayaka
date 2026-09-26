// SPDX-License-Identifier: MPL-2.0

//! Read-only project-artifact (purge) preview from one bounded scan (T8).
//!
//! Groups rebuildable artifact directories by their project root. A name
//! match alone never qualifies: an artifact must be a direct child of a
//! project root that carries the binding project marker, which is also the
//! rebuild evidence. Nested projects inside another project's artifact are
//! excluded, not merged. This preview performs no effects: directory effects
//! remain unapproved; see docs/DIRECTORY_ACTIONS.md.

use crate::execute::{CacheSelection, PurgeSelection};
use crate::model::{FileIdentity, ResourceKind};
use crate::scan::ScanStatus;
use crate::scan::index::{Metric, ScanTree};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const PURGE_SCHEMA_VERSION: u32 = 1;
pub const PURGE_KIND: &str = "sayaka.purge_preview";
pub const DEFAULT_STALE_DAYS: u32 = 30;
pub const MAX_STALE_DAYS: u32 = 3650;
pub const DEVELOPER_CACHE_RULESET_REVISION: u32 = 1;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PurgeProfile {
    #[default]
    Projects,
    DeveloperCaches,
    FinderMetadata,
}

pub fn resolve_cache_selections_by_ids(
    preview: &PurgePreview,
    item_ids: &[PurgeItemId],
) -> Result<Vec<CacheSelection>, String> {
    if preview.profile != PurgeProfile::DeveloperCaches {
        return Err("cache execution is unsupported for this purge profile".into());
    }
    let mut seen = HashSet::new();
    let mut selections = Vec::with_capacity(item_ids.len());
    for id in item_ids {
        if id.0 == 0 || !seen.insert(id.0) {
            return Err("purge item references must be unique nonzero ids".into());
        }
        let cache = preview
            .developer_caches
            .get((id.0 - 1) as usize)
            .ok_or_else(|| format!("purge item id {} is not in this preview", id.0))?;
        if !cache.complete {
            return Err("developer cache item has incomplete scan coverage".into());
        }
        if !cache.cleanup_supported {
            return Err("developer cache item is not cleanup-supported".into());
        }
        let scope_root = preview
            .roots
            .iter()
            .filter(|root| cache.path == **root || cache.path.starts_with(root))
            .max_by_key(|root| root.components().count())
            .ok_or_else(|| {
                format!(
                    "developer cache item is outside every preview root: {}",
                    cache.path.display()
                )
            })?;
        selections.push(CacheSelection {
            scope_root: scope_root.clone(),
            path: cache.path.clone(),
            expected_identity: cache.identity,
            rule_id: cache.rule_id,
        });
    }
    Ok(selections)
}

pub fn resolve_finder_selections_by_ids(
    preview: &PurgePreview,
    item_ids: &[PurgeItemId],
) -> Result<Vec<(PathBuf, FileIdentity)>, String> {
    if preview.profile != PurgeProfile::FinderMetadata {
        return Err("Finder selection requires the Finder metadata profile".into());
    }
    let mut seen = HashSet::new();
    item_ids
        .iter()
        .map(|id| {
            if id.0 == 0 || !seen.insert(id.0) {
                return Err("Finder references must be unique nonzero ids".into());
            }
            let item = preview
                .finder_metadata
                .get((id.0 - 1) as usize)
                .ok_or_else(|| format!("Finder item {} is not in this preview", id.0))?;
            Ok((item.path.clone(), item.identity))
        })
        .collect()
}

impl PurgeProfile {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Projects => "projects",
            Self::DeveloperCaches => "developer_caches",
            Self::FinderMetadata => "finder_metadata",
        }
    }

    pub const fn from_ffi(value: u32) -> Option<Self> {
        match value {
            0 | 1 => Some(Self::Projects),
            2 => Some(Self::DeveloperCaches),
            3 => Some(Self::FinderMetadata),
            _ => None,
        }
    }

    pub const fn to_ffi(self) -> u32 {
        match self {
            Self::Projects => 1,
            Self::DeveloperCaches => 2,
            Self::FinderMetadata => 3,
        }
    }
}

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
    pub profile: PurgeProfile,
}

impl Default for PurgeOptions {
    fn default() -> Self {
        Self {
            stale_days: DEFAULT_STALE_DAYS,
            profile: PurgeProfile::Projects,
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

/// Finder's per-directory view settings file. Removing it loses custom view
/// settings; the file can be recreated, but it is never preselected.
#[derive(Clone, Debug)]
pub struct FinderMetadataCandidate {
    pub path: PathBuf,
    pub identity: FileIdentity,
    pub logical_bytes: Option<u64>,
    pub allocated_bytes: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeveloperCacheActivity {
    NotDetected,
    LockFileObserved,
}

impl DeveloperCacheActivity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotDetected => "not_detected",
            Self::LockFileObserved => "lock_file_observed",
        }
    }
}

#[derive(Clone, Debug)]
pub struct DeveloperCacheCandidate {
    pub tool: &'static str,
    pub rule_id: &'static str,
    pub rule_version: u32,
    pub ruleset_revision: u32,
    pub title: &'static str,
    pub path: PathBuf,
    pub location: &'static str,
    pub location_kind: &'static str,
    pub kind: &'static str,
    pub rebuildability_note: &'static str,
    pub user_product: bool,
    pub cleanup_supported: bool,
    pub unsupported_reason: Option<&'static str>,
    pub logical_bytes: Option<u64>,
    pub allocated_bytes: Option<u64>,
    pub complete: bool,
    pub modified_unix_ms: Option<i64>,
    pub identity: FileIdentity,
    pub activity: DeveloperCacheActivity,
    pub evidence: &'static [EvidenceSource],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnsupportedOperation {
    pub tool: &'static str,
    pub operation: &'static str,
    pub reason: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DeveloperCacheRule {
    tool: &'static str,
    rule_id: &'static str,
    rule_version: u32,
    title: &'static str,
    suffix: &'static [&'static str],
    location: &'static str,
    location_kind: &'static str,
    rebuildability_note: &'static str,
    lock_siblings: &'static [&'static str],
    evidence: &'static [EvidenceSource],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceSource {
    pub title: &'static str,
    pub url: &'static str,
    pub reviewed_utc: &'static str,
    pub license_note: &'static str,
}

// Each rule is a documented cache/download-store convention and intentionally
// excludes Xcode Archives, CoreSimulator Devices, package-manager config, logs,
// installed products, and other user-authored artifacts. Locations are matched
// only at their documented account-home-anchored absolute paths; the granted
// preview root may be that cache directory itself or any ancestor.
const DEVELOPER_CACHE_RULES: &[DeveloperCacheRule] = &[
    DeveloperCacheRule {
        tool: "xcode",
        rule_id: "com.apple.xcode.derived_data",
        rule_version: 1,
        title: "Xcode DerivedData build data",
        suffix: &["Library", "Developer", "Xcode", "DerivedData"],
        location: "~/Library/Developer/Xcode/DerivedData",
        location_kind: "directory",
        rebuildability_note: "xcodebuild documents -derivedDataPath as the folder used for derived data during builds; Xcode can recreate build intermediates and indexes. Archives are explicitly not part of this rule.",
        lock_siblings: &[],
        evidence: &[EvidenceSource {
            title: "xcodebuild manual: -derivedDataPath",
            url: "https://keith.github.io/xcode-man-pages/xcodebuild.1.html",
            reviewed_utc: "2026-09-24",
            license_note: "Apple command manual reference mirror",
        }],
    },
    DeveloperCacheRule {
        tool: "xcode",
        rule_id: "com.apple.xcode.cache",
        rule_version: 1,
        title: "Xcode app cache",
        suffix: &["Library", "Caches", "com.apple.dt.Xcode"],
        location: "~/Library/Caches/com.apple.dt.Xcode",
        location_kind: "directory",
        rebuildability_note: "macOS cache directory convention for the Xcode bundle identifier; treated as application cache only, not user products.",
        lock_siblings: &[],
        evidence: &[EvidenceSource {
            title: "Apple File System Programming Guide: Library/Caches",
            url: "https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemOverview/FileSystemOverview.html",
            reviewed_utc: "2026-09-24",
            license_note: "Apple archived developer documentation",
        }],
    },
    DeveloperCacheRule {
        tool: "xcode",
        rule_id: "com.apple.coresimulator.cache",
        rule_version: 1,
        title: "CoreSimulator cache files",
        suffix: &["Library", "Developer", "CoreSimulator", "Caches"],
        location: "~/Library/Developer/CoreSimulator/Caches",
        location_kind: "directory",
        rebuildability_note: "CoreSimulator cache directory only. Simulator Devices, runtimes, unavailable-device deletion and app data are non-targets.",
        lock_siblings: &[],
        evidence: &[EvidenceSource {
            title: "Apple File System Programming Guide: Library/Caches",
            url: "https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemOverview/FileSystemOverview.html",
            reviewed_utc: "2026-09-24",
            license_note: "Apple archived developer documentation",
        }],
    },
    DeveloperCacheRule {
        tool: "npm",
        rule_id: "org.npm.cacache",
        rule_version: 1,
        title: "npm content-addressable package cache",
        suffix: &[".npm", "_cacache"],
        location: "~/.npm/_cacache",
        location_kind: "directory",
        rebuildability_note: "npm documents ~/.npm as the POSIX cache root and _cacache as opaque content-addressable package/HTTP cache; packages are re-fetched as needed.",
        lock_siblings: &[],
        evidence: &[EvidenceSource {
            title: "npm-cache CLI documentation",
            url: "https://docs.npmjs.com/cli/v10/commands/npm-cache",
            reviewed_utc: "2026-09-24",
            license_note: "npm documentation terms",
        }],
    },
    DeveloperCacheRule {
        tool: "pnpm",
        rule_id: "io.pnpm.store",
        rule_version: 1,
        title: "pnpm package store",
        suffix: &["Library", "pnpm", "store"],
        location: "~/Library/pnpm/store",
        location_kind: "directory",
        rebuildability_note: "pnpm documents the macOS store location and `pnpm store path`; missing packages are restored from registries when needed.",
        lock_siblings: &[],
        evidence: &[EvidenceSource {
            title: "pnpm store settings",
            url: "https://pnpm.io/settings/store",
            reviewed_utc: "2026-09-24",
            license_note: "pnpm documentation license",
        }],
    },
    DeveloperCacheRule {
        tool: "yarn",
        rule_id: "com.yarnpkg.classic_cache",
        rule_version: 1,
        title: "Yarn package cache",
        suffix: &["Library", "Caches", "Yarn"],
        location: "~/Library/Caches/Yarn",
        location_kind: "directory",
        rebuildability_note: "Yarn documents `yarn cache dir` and `yarn cache clean`; cache entries are package downloads that can be fetched again.",
        lock_siblings: &[],
        evidence: &[EvidenceSource {
            title: "Yarn classic cache CLI documentation",
            url: "https://classic.yarnpkg.com/lang/en/docs/cli/cache/",
            reviewed_utc: "2026-09-24",
            license_note: "Yarn documentation license",
        }],
    },
    DeveloperCacheRule {
        tool: "pip",
        rule_id: "pypa.pip.cache",
        rule_version: 1,
        title: "pip HTTP and wheel cache",
        suffix: &["Library", "Caches", "pip"],
        location: "~/Library/Caches/pip",
        location_kind: "directory",
        rebuildability_note: "pip documents ~/Library/Caches/pip as the default macOS cache; HTTP responses and locally built wheels are regenerated or re-downloaded.",
        lock_siblings: &[],
        evidence: &[EvidenceSource {
            title: "pip caching documentation",
            url: "https://pip.pypa.io/en/stable/topics/caching/",
            reviewed_utc: "2026-09-24",
            license_note: "pip documentation license",
        }],
    },
    DeveloperCacheRule {
        tool: "cargo",
        rule_id: "org.rust-lang.cargo.registry_cache",
        rule_version: 1,
        title: "Cargo registry crate download cache",
        suffix: &[".cargo", "registry", "cache"],
        location: "~/.cargo/registry/cache",
        location_kind: "directory",
        rebuildability_note: "Cargo documents registry/cache as downloaded .crate files under CARGO_HOME; missing crates are downloaded again from registries.",
        lock_siblings: &[],
        evidence: &[EvidenceSource {
            title: "The Cargo Book: Cargo Home",
            url: "https://doc.rust-lang.org/cargo/guide/cargo-home.html",
            reviewed_utc: "2026-09-24",
            license_note: "Rust documentation license",
        }],
    },
    DeveloperCacheRule {
        tool: "gradle",
        rule_id: "org.gradle.modules_cache",
        rule_version: 1,
        title: "Gradle dependency artifact cache",
        suffix: &[".gradle", "caches", "modules-2", "files-2.1"],
        location: "~/.gradle/caches/modules-2/files-2.1",
        location_kind: "directory",
        rebuildability_note: "Gradle documents dependency caches under Gradle User Home and cleanup/re-download behavior for downloaded resources.",
        lock_siblings: &["modules-2.lock"],
        evidence: &[EvidenceSource {
            title: "Gradle-managed directories and caches",
            url: "https://docs.gradle.org/current/userguide/directory_layout.html",
            reviewed_utc: "2026-09-24",
            license_note: "Gradle documentation license",
        }],
    },
    DeveloperCacheRule {
        tool: "homebrew",
        rule_id: "sh.homebrew.downloads_cache",
        rule_version: 1,
        title: "Homebrew download cache",
        suffix: &["Library", "Caches", "Homebrew", "downloads"],
        location: "~/Library/Caches/Homebrew/downloads",
        location_kind: "directory",
        rebuildability_note: "Homebrew documents its cache via `brew --cache`; the downloads subdirectory stores fetched formula/cask resources and bottles, not installed Cellar products.",
        lock_siblings: &[],
        evidence: &[EvidenceSource {
            title: "Homebrew Tips and Tricks: cache",
            url: "https://docs.brew.sh/Tips-and-Tricks",
            reviewed_utc: "2026-09-24",
            license_note: "Homebrew documentation license",
        }],
    },
];

pub const UNSUPPORTED_OPERATIONS: &[UnsupportedOperation] = &[
    UnsupportedOperation {
        tool: "homebrew",
        operation: "brew cleanup",
        reason: "requires launching Homebrew and applying Homebrew policy outside the app sandbox; this profile only reports file-level download cache candidates under user-granted roots",
    },
    UnsupportedOperation {
        tool: "xcode",
        operation: "xcrun simctl delete unavailable",
        reason: "requires invoking Apple developer tools to mutate simulator device records; CoreSimulator Devices and user simulator data are not file-level cache targets",
    },
    UnsupportedOperation {
        tool: "xcode",
        operation: "delete Xcode Archives",
        reason: "archives are user build products, not rebuildable caches, and require separate explicit confirmation outside this profile",
    },
    UnsupportedOperation {
        tool: "npm",
        operation: "npm cache clean --force",
        reason: "requires launching npm; the app can only preview documented cache directories that the user grants",
    },
    UnsupportedOperation {
        tool: "pnpm",
        operation: "pnpm store prune",
        reason: "requires launching pnpm and interpreting store metadata; unsupported in the sandboxed app",
    },
    UnsupportedOperation {
        tool: "yarn",
        operation: "yarn cache clean",
        reason: "requires launching Yarn; unsupported in the sandboxed app",
    },
    UnsupportedOperation {
        tool: "pip",
        operation: "pip cache purge",
        reason: "requires launching pip; unsupported in the sandboxed app",
    },
    UnsupportedOperation {
        tool: "gradle",
        operation: "gradle --stop / cache cleanup",
        reason: "requires controlling Gradle daemons or Gradle cleanup policy; unsupported in the sandboxed app",
    },
];

#[derive(Clone, Debug, Default)]
pub struct PurgeCounts {
    pub projects: usize,
    pub artifacts: usize,
    pub stale_artifacts: usize,
    /// Projects or artifacts excluded because they nest inside another
    /// project's artifact, or because the artifact is a dataless placeholder.
    pub excluded: usize,
    pub developer_caches: usize,
    pub finder_metadata: usize,
    pub unsupported_operations: usize,
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
    pub profile: PurgeProfile,
    pub roots: Vec<PathBuf>,
    pub stale_days: u32,
    pub projects: Vec<PurgeProject>,
    pub developer_caches: Vec<DeveloperCacheCandidate>,
    pub finder_metadata: Vec<FinderMetadataCandidate>,
    pub unsupported_operations: &'static [UnsupportedOperation],
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
        hasher.update(self.profile.as_str().as_bytes());
        hasher.update(self.platform.as_bytes());
        hasher.update(self.status.as_str().as_bytes());
        hasher.update([u8::from(self.complete)]);
        hasher.update(self.stale_days.to_le_bytes());
        for root in &self.roots {
            hash_path(&mut hasher, root);
        }
        for cache in &self.developer_caches {
            hasher.update(cache.rule_id.as_bytes());
            hasher.update(cache.rule_version.to_le_bytes());
            hash_path(&mut hasher, &cache.path);
            hash_option_u64(&mut hasher, cache.logical_bytes);
            hash_option_u64(&mut hasher, cache.allocated_bytes);
            hasher.update([u8::from(cache.complete)]);
            hash_option_i64(&mut hasher, cache.modified_unix_ms);
            hasher.update(cache.activity.as_str().as_bytes());
            hasher.update([0]);
        }
        for item in &self.finder_metadata {
            hash_path(&mut hasher, &item.path);
            match item.identity {
                FileIdentity::Unix { device, inode } => {
                    hasher.update([1]);
                    hasher.update(device.to_le_bytes());
                    hasher.update(inode.to_le_bytes());
                }
                FileIdentity::Windows {
                    volume_serial,
                    file_id,
                } => {
                    hasher.update([2]);
                    hasher.update(volume_serial.to_le_bytes());
                    hasher.update(file_id);
                }
            }
            hash_option_u64(&mut hasher, item.logical_bytes);
            hash_option_u64(&mut hasher, item.allocated_bytes);
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
        hasher.update((self.counts.developer_caches as u64).to_le_bytes());
        hasher.update((self.counts.finder_metadata as u64).to_le_bytes());
        let digest = hasher.finalize();
        let mut out = String::with_capacity(digest.len() * 2);
        for byte in digest {
            use std::fmt::Write;
            write!(&mut out, "{byte:02x}").expect("hex write");
        }
        out
    }

    pub fn item_count(&self) -> usize {
        match self.profile {
            PurgeProfile::DeveloperCaches => return self.developer_caches.len(),
            PurgeProfile::FinderMetadata => return self.finder_metadata.len(),
            PurgeProfile::Projects => {}
        }
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
    if preview.profile != PurgeProfile::Projects {
        return Err("execution is unsupported for this purge profile".into());
    }
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
    if preview.profile != PurgeProfile::Projects {
        return Err("execution is unsupported for this purge profile".into());
    }
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
    match options.profile {
        PurgeProfile::Projects => project_purge_preview(index, options, now),
        PurgeProfile::DeveloperCaches => developer_cache_preview(index, options),
        PurgeProfile::FinderMetadata => finder_metadata_preview(index, options),
    }
}

fn preview_status(report: &crate::scan::ScanReport) -> PurgeStatus {
    match report.status {
        ScanStatus::Complete => PurgeStatus::Complete,
        ScanStatus::Partial => PurgeStatus::Partial,
        ScanStatus::Cancelled => PurgeStatus::Cancelled,
        ScanStatus::Failed => PurgeStatus::Failed,
    }
}

fn finder_metadata_preview(
    index: &ScanTree,
    options: &PurgeOptions,
) -> Result<PurgePreview, String> {
    let report = index.report();
    let mut candidates = report
        .entries
        .iter()
        .filter(|entry| {
            entry.kind == ResourceKind::File
                && !entry.dataless
                && entry.counted
                && entry.path.file_name() == Some(std::ffi::OsStr::new(".DS_Store"))
                && !entry.path.ancestors().any(|ancestor| {
                    ancestor.extension().is_some_and(|extension| {
                        ["app", "framework", "bundle", "xpc", "appex"]
                            .iter()
                            .any(|blocked| extension == std::ffi::OsStr::new(blocked))
                    })
                })
        })
        .map(|entry| FinderMetadataCandidate {
            path: entry.path.clone(),
            identity: entry.identity,
            logical_bytes: entry.logical_bytes,
            allocated_bytes: entry.allocated_bytes,
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.path.cmp(&right.path));
    let counts = PurgeCounts {
        finder_metadata: candidates.len(),
        ..Default::default()
    };
    Ok(PurgePreview {
        schema_version: PURGE_SCHEMA_VERSION,
        kind: PURGE_KIND,
        platform: if cfg!(target_os = "macos") {
            "macos"
        } else {
            "unsupported"
        },
        status: preview_status(report),
        complete: report.status == ScanStatus::Complete,
        effects_performed: false,
        profile: options.profile,
        roots: report.roots.clone(),
        stale_days: options.stale_days,
        projects: Vec::new(),
        developer_caches: Vec::new(),
        finder_metadata: candidates,
        unsupported_operations: &[],
        counts,
        scan_issues: report.issues.clone(),
        scan_issues_omitted: report.issues_omitted,
    })
}

fn project_purge_preview(
    index: &ScanTree,
    options: &PurgeOptions,
    now: SystemTime,
) -> Result<PurgePreview, String> {
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
    let status = preview_status(report);
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
        profile: options.profile,
        roots: report.roots.clone(),
        stale_days: options.stale_days,
        projects: output,
        developer_caches: Vec::new(),
        finder_metadata: Vec::new(),
        unsupported_operations: profile_unsupported_operations(PurgeProfile::Projects),
        counts,
        scan_issues: report.issues.clone(),
        scan_issues_omitted: report.issues_omitted,
    })
}

pub fn unsupported_operations() -> &'static [UnsupportedOperation] {
    UNSUPPORTED_OPERATIONS
}

pub fn profile_unsupported_operations(profile: PurgeProfile) -> &'static [UnsupportedOperation] {
    match profile {
        PurgeProfile::Projects => &[],
        PurgeProfile::DeveloperCaches => UNSUPPORTED_OPERATIONS,
        PurgeProfile::FinderMetadata => &[],
    }
}

fn developer_cache_preview(
    index: &ScanTree,
    options: &PurgeOptions,
) -> Result<PurgePreview, String> {
    let account_home = effective_account_home()?;
    developer_cache_preview_with_home(index, options, &account_home)
}

fn developer_cache_preview_with_home(
    index: &ScanTree,
    options: &PurgeOptions,
    account_home: &Path,
) -> Result<PurgePreview, String> {
    let report = index.report();
    let mut by_path = HashSet::new();
    for entry in &report.entries {
        by_path.insert(entry.path.clone());
    }
    let rule_locations = developer_cache_rule_locations(account_home)?;
    let mut directories = report
        .entries
        .iter()
        .filter(|entry| entry.kind == ResourceKind::Directory)
        .map(|entry| (entry, entry.path.clone()))
        .collect::<Vec<_>>();
    directories.sort_by(|left, right| left.1.cmp(&right.1));
    let mut candidates = Vec::new();
    let mut matched_locations: Vec<PathBuf> = Vec::new();
    let unsupported_operations = profile_unsupported_operations(options.profile);
    let mut counts = PurgeCounts {
        unsupported_operations: unsupported_operations.len(),
        ..Default::default()
    };
    for (entry, path) in directories {
        if matched_locations
            .iter()
            .any(|location| path.starts_with(location) && path != *location)
        {
            continue;
        }

        let can_contain_rule = rule_locations
            .iter()
            .any(|location| paths_are_related(&path, &location.path));
        if !can_contain_rule {
            continue;
        }

        let Some(location) = rule_locations.iter().find(|location| path == location.path) else {
            continue;
        };
        let rule = location.rule;
        if entry.dataless {
            counts.excluded += 1;
            continue;
        }
        matched_locations.push(path);
        let activity = if lock_sibling_observed(&entry.path, rule, &by_path) {
            DeveloperCacheActivity::LockFileObserved
        } else {
            DeveloperCacheActivity::NotDetected
        };
        let summary = index.summary(entry.id);
        let modified_unix_ms = std::fs::symlink_metadata(&entry.path)
            .ok()
            .and_then(|metadata| metadata.modified().ok())
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .and_then(|duration| i64::try_from(duration.as_millis()).ok());
        let active = activity == DeveloperCacheActivity::LockFileObserved;
        candidates.push(DeveloperCacheCandidate {
            tool: rule.tool,
            rule_id: rule.rule_id,
            rule_version: rule.rule_version,
            ruleset_revision: DEVELOPER_CACHE_RULESET_REVISION,
            title: rule.title,
            path: entry.path.clone(),
            location: rule.location,
            location_kind: rule.location_kind,
            kind: "directory",
            rebuildability_note: rule.rebuildability_note,
            user_product: false,
            cleanup_supported: !active,
            unsupported_reason: active.then_some(
                "activity lock file was observed near this cache; preview is conservative",
            ),
            logical_bytes: index.size(entry.id, Metric::Logical),
            allocated_bytes: index.size(entry.id, Metric::Allocated),
            complete: summary.is_some_and(|summary| summary.complete),
            modified_unix_ms,
            identity: entry.identity,
            activity,
            evidence: rule.evidence,
        });
    }
    candidates.sort_by(|left, right| left.path.cmp(&right.path));
    counts.developer_caches = candidates.len();
    let status = preview_status(report);
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
        profile: options.profile,
        roots: report.roots.clone(),
        stale_days: options.stale_days,
        projects: Vec::new(),
        developer_caches: candidates,
        finder_metadata: Vec::new(),
        unsupported_operations,
        counts,
        scan_issues: report.issues.clone(),
        scan_issues_omitted: report.issues_omitted,
    })
}

struct DeveloperCacheRuleLocation<'a> {
    rule: &'a DeveloperCacheRule,
    path: PathBuf,
}

fn developer_cache_rule_locations(
    account_home: &Path,
) -> Result<Vec<DeveloperCacheRuleLocation<'static>>, String> {
    let account_home = std::fs::canonicalize(account_home).map_err(|error| {
        format!(
            "failed to canonicalize passwd account home {}: {error}",
            account_home.display()
        )
    })?;
    Ok(DEVELOPER_CACHE_RULES
        .iter()
        .filter_map(|rule| {
            nofollow_existing_rule_directory(&account_home, rule)
                .map(|path| DeveloperCacheRuleLocation { rule, path })
        })
        .collect())
}

pub fn revalidate_developer_cache_selection(selection: &CacheSelection) -> Result<(), String> {
    let account_home = effective_account_home()?;
    revalidate_developer_cache_selection_with_home(selection, &account_home)
}

fn revalidate_developer_cache_selection_with_home(
    selection: &CacheSelection,
    account_home: &Path,
) -> Result<(), String> {
    let locations = developer_cache_rule_locations(account_home)?;
    let location = locations
        .iter()
        .find(|location| {
            location.rule.rule_id == selection.rule_id && location.path == selection.path
        })
        .ok_or_else(|| {
            "developer cache target is no longer the anchored passwd-home rule location".to_owned()
        })?;
    for lock_name in location.rule.lock_siblings {
        let Some(parent) = selection.path.parent() else {
            return Err("developer cache target has no parent".into());
        };
        if parent.join(lock_name).exists() {
            return Err("developer cache activity lock file is present".into());
        }
    }
    Ok(())
}

fn nofollow_existing_rule_directory(
    account_home: &Path,
    rule: &DeveloperCacheRule,
) -> Option<PathBuf> {
    let mut path = account_home.to_path_buf();
    for component in rule.suffix {
        path = path.join(component);
        let metadata = std::fs::symlink_metadata(&path).ok()?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return None;
        }
    }
    Some(path)
}

fn paths_are_related(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

#[cfg(target_os = "macos")]
fn effective_account_home() -> Result<PathBuf, String> {
    sayaka_platform_macos::effective_account_home().map_err(|error| {
        format!("failed to resolve effective account home from passwd database: {error}")
    })
}

#[cfg(not(target_os = "macos"))]
fn effective_account_home() -> Result<PathBuf, String> {
    Err("developer cache profile is only supported on macOS account homes".into())
}

fn lock_sibling_observed(
    path: &Path,
    rule: &DeveloperCacheRule,
    by_path: &HashSet<PathBuf>,
) -> bool {
    let Some(parent) = path.parent() else {
        return false;
    };
    rule.lock_siblings
        .iter()
        .any(|name| by_path.contains(&parent.join(name)))
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

    fn developer_cache_preview_at(
        root: &std::path::Path,
        account_home: &std::path::Path,
    ) -> PurgePreview {
        let cancellation = Cancellation::default();
        let report = scan(
            &[root.to_path_buf()],
            &ScanLimits::default(),
            &cancellation,
            |_| {},
        )
        .expect("scan");
        let index = ScanTree::build(report, &cancellation).expect("index");
        developer_cache_preview_with_home(
            &index,
            &PurgeOptions {
                stale_days: DEFAULT_STALE_DAYS,
                profile: PurgeProfile::DeveloperCaches,
            },
            account_home,
        )
        .expect("preview")
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
        assert!(
            PurgeOptions {
                stale_days: 0,
                profile: PurgeProfile::Projects,
            }
            .validate()
            .is_err()
        );
        assert!(
            PurgeOptions {
                stale_days: MAX_STALE_DAYS + 1,
                profile: PurgeProfile::Projects,
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn developer_cache_profile_matches_account_home_location_and_excludes_archives() {
        let root = tempfile::tempdir().expect("tempdir");
        let home = root.path();
        fs::create_dir_all(
            home.join("Library")
                .join("Developer")
                .join("Xcode")
                .join("DerivedData")
                .join("App-a1b2")
                .join("Build"),
        )
        .expect("derived data");
        fs::create_dir_all(
            home.join("Library")
                .join("Developer")
                .join("Xcode")
                .join("Archives")
                .join("2026-09-24"),
        )
        .expect("archives");
        fs::create_dir_all(home.join(".npm").join("_cacache").join("content-v2"))
            .expect("npm cache");
        let preview = developer_cache_preview_at(home, home);
        assert_eq!(preview.profile, PurgeProfile::DeveloperCaches);
        let rule_ids = preview
            .developer_caches
            .iter()
            .map(|cache| cache.rule_id)
            .collect::<Vec<_>>();
        assert!(rule_ids.contains(&"com.apple.xcode.derived_data"));
        assert!(rule_ids.contains(&"org.npm.cacache"));
        assert!(
            preview
                .developer_caches
                .iter()
                .all(|cache| !cache.path.to_string_lossy().contains("Archives"))
        );
        assert!(
            preview
                .developer_caches
                .iter()
                .all(|cache| !cache.user_product)
        );
        let selections =
            resolve_cache_selections_by_ids(&preview, &[PurgeItemId(1)]).expect("cache selection");
        assert_eq!(selections.len(), 1);
        assert_eq!(selections[0].scope_root, *home);
        assert_eq!(selections[0].path, preview.developer_caches[0].path);
        assert_eq!(selections[0].rule_id, preview.developer_caches[0].rule_id);
    }

    #[test]
    fn developer_cache_profile_rejects_suffix_false_positive() {
        let root = tempfile::tempdir().expect("tempdir");
        let home = root.path().join("account");
        let real_pip = home.join("Library").join("Caches").join("pip");
        let false_pip = root
            .path()
            .join("Downloads")
            .join("fixture")
            .join("Library")
            .join("Caches")
            .join("pip");
        fs::create_dir_all(real_pip.join("http-v2")).expect("real pip cache");
        fs::create_dir_all(false_pip.join("http-v2")).expect("false pip cache");

        let preview = developer_cache_preview_at(root.path(), &home);
        let paths = preview
            .developer_caches
            .iter()
            .map(|cache| cache.path.as_path())
            .collect::<Vec<_>>();

        assert!(paths.contains(&real_pip.as_path()));
        assert!(!paths.contains(&false_pip.as_path()));
    }

    #[test]
    fn developer_cache_profile_matches_when_root_is_cache_directory() {
        let root = tempfile::tempdir().expect("tempdir");
        let home = root.path().join("account");
        let pip = home.join("Library").join("Caches").join("pip");
        fs::create_dir_all(pip.join("http-v2")).expect("pip cache");

        let preview = developer_cache_preview_at(&pip, &home);

        assert_eq!(preview.developer_caches.len(), 1);
        assert_eq!(preview.developer_caches[0].rule_id, "pypa.pip.cache");
        assert_eq!(preview.developer_caches[0].path, pip);
        let selections =
            resolve_cache_selections_by_ids(&preview, &[PurgeItemId(1)]).expect("cache selection");
        assert_eq!(selections[0].scope_root, preview.roots[0]);
        assert_eq!(selections[0].scope_root, selections[0].path);
    }

    #[test]
    fn developer_cache_profile_matches_when_root_is_ancestor() {
        let root = tempfile::tempdir().expect("tempdir");
        let home = root.path().join("account");
        let caches = home.join("Library").join("Caches");
        let pip = caches.join("pip");
        fs::create_dir_all(pip.join("http-v2")).expect("pip cache");

        let preview = developer_cache_preview_at(&caches, &home);

        assert_eq!(preview.developer_caches.len(), 1);
        assert_eq!(preview.developer_caches[0].rule_id, "pypa.pip.cache");
        assert_eq!(preview.developer_caches[0].path, pip);
        let selections =
            resolve_cache_selections_by_ids(&preview, &[PurgeItemId(1)]).expect("cache selection");
        assert_eq!(selections[0].scope_root, caches);
        assert_ne!(selections[0].scope_root, selections[0].path);
    }

    #[test]
    fn developer_cache_profile_matches_when_root_is_home() {
        let root = tempfile::tempdir().expect("tempdir");
        let home = root.path().join("account");
        let pip = home.join("Library").join("Caches").join("pip");
        fs::create_dir_all(pip.join("http-v2")).expect("pip cache");

        let preview = developer_cache_preview_at(&home, &home);

        assert_eq!(preview.developer_caches.len(), 1);
        assert_eq!(preview.developer_caches[0].rule_id, "pypa.pip.cache");
        assert_eq!(preview.developer_caches[0].path, pip);
    }

    #[test]
    fn developer_cache_selection_refuses_activity_lock_items() {
        let root = tempfile::tempdir().expect("tempdir");
        let home = root.path().join("account");
        let modules = home
            .join(".gradle")
            .join("caches")
            .join("modules-2")
            .join("files-2.1");
        fs::create_dir_all(&modules).expect("gradle cache");
        fs::write(
            home.join(".gradle")
                .join("caches")
                .join("modules-2")
                .join("modules-2.lock"),
            b"lock",
        )
        .expect("gradle lock");

        let preview = developer_cache_preview_at(&home, &home);
        let cache = preview
            .developer_caches
            .iter()
            .find(|cache| cache.rule_id == "org.gradle.modules_cache")
            .expect("gradle cache");

        assert!(!cache.cleanup_supported);
        assert_eq!(cache.activity, DeveloperCacheActivity::LockFileObserved);
        assert_eq!(
            resolve_cache_selections_by_ids(&preview, &[PurgeItemId(1)]).unwrap_err(),
            "developer cache item is not cleanup-supported"
        );
    }

    #[test]
    fn symlinked_developer_cache_location_is_not_a_candidate() {
        let root = tempfile::tempdir().expect("tempdir");
        let home = root.path().join("account");
        let outside = root.path().join("outside-pip");
        let pip = home.join("Library").join("Caches").join("pip");
        fs::create_dir_all(&outside).expect("outside cache");
        fs::create_dir_all(pip.parent().expect("pip parent")).expect("pip parent");
        std::os::unix::fs::symlink(&outside, &pip).expect("pip symlink");

        let preview = developer_cache_preview_at(&home, &home);

        assert!(preview.developer_caches.is_empty());
    }

    #[test]
    fn symlinked_developer_cache_intermediate_is_not_a_candidate_or_selection() {
        let root = tempfile::tempdir().expect("tempdir");
        let home = root.path().join("account");
        let outside_gradle = root.path().join("outside-gradle");
        let modules = outside_gradle
            .join("caches")
            .join("modules-2")
            .join("files-2.1");
        fs::create_dir_all(&modules).expect("outside gradle cache");
        fs::create_dir_all(&home).expect("home");
        std::os::unix::fs::symlink(&outside_gradle, home.join(".gradle")).expect("gradle symlink");

        let preview = developer_cache_preview_at(root.path(), &home);

        assert!(preview.developer_caches.is_empty());
        let identity = FileIdentity::Unix {
            device: 0,
            inode: 0,
        };
        assert!(
            revalidate_developer_cache_selection_with_home(
                &CacheSelection {
                    scope_root: root.path().to_path_buf(),
                    path: modules.clone(),
                    expected_identity: identity,
                    rule_id: "org.gradle.modules_cache",
                },
                &home
            )
            .is_err()
        );
        assert!(
            revalidate_developer_cache_selection_with_home(
                &CacheSelection {
                    scope_root: root.path().to_path_buf(),
                    path: home
                        .join(".gradle")
                        .join("caches")
                        .join("modules-2")
                        .join("files-2.1"),
                    expected_identity: identity,
                    rule_id: "org.gradle.modules_cache",
                },
                &home
            )
            .is_err()
        );
    }
}
