// SPDX-License-Identifier: MPL-2.0

//! Evidence-backed read-only rules and preview. This module never executes
//! effects and cannot authorize Trash or other mutation contracts.

use crate::model::{Cancellation, FileIdentity, ResourceKind, Scope};
use crate::scan::index::ScanTree;
use crate::scan::{ScanEntry, ScanError, ScanIssue, ScanReport, ScanStatus};
use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub const PREVIEW_SCHEMA_VERSION: u32 = 1;
pub const RULESET_SCHEMA_VERSION: u32 = 1;
pub const BUILTIN_RULESET_REVISION: u32 = 2;

pub const CPYTHON_SOURCE_BACKED_PYC_RULE_ID: &str = "org.python.cpython.pep3147.source_backed_pyc";
pub const CPYTHON_SOURCE_BACKED_PYC_RULE_VERSION: u32 = 2;
pub const CPYTHON_SOURCE_BACKED_PYC_TRASH_SEMANTICS: &str =
    "cpython_source_backed_pyc_explicit_trash_v1";
pub const CPYTHON_SOURCE_BACKED_PYC_TRASH_SEMANTICS_DIGEST: &str =
    "sha256:2a85f813982f253a1177f95ec4f2dc7e30cf5f34cbaf17e08e6d334f4315fcd8";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    PreviewOnly,
    ManualReview,
    ExplicitNativeTrash,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EvidenceSource {
    pub title: &'static str,
    pub url: &'static str,
    pub reviewed_utc: &'static str,
    pub license_note: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RuleDefinition {
    pub id: &'static str,
    pub version: u32,
    pub title: &'static str,
    pub ruleset_schema_version: u32,
    pub ruleset_revision: u32,
    pub platforms: &'static [&'static str],
    pub software: &'static [&'static str],
    pub targets: &'static [&'static str],
    pub non_targets: &'static [&'static str],
    pub prerequisites: &'static [&'static str],
    pub actions: &'static [RuleAction],
    pub rebuild_cost: &'static str,
    pub recovery_cost: &'static str,
    pub concurrency: &'static str,
    pub failure: &'static str,
    pub evidence: &'static [EvidenceSource],
}

const CPYTHON_RULE: RuleDefinition = RuleDefinition {
    id: CPYTHON_SOURCE_BACKED_PYC_RULE_ID,
    version: CPYTHON_SOURCE_BACKED_PYC_RULE_VERSION,
    title: "CPython source-backed __pycache__ bytecode (PEP 3147/488)",
    ruleset_schema_version: RULESET_SCHEMA_VERSION,
    ruleset_revision: BUILTIN_RULESET_REVISION,
    platforms: &[
        "macos (metadata-backed preview verified)",
        "windows (read-only scanner available; rule runtime unverified in this slice)",
    ],
    software: &["CPython cache-tagged .pyc naming in __pycache__, Python 3.2+ semantics"],
    targets: &[
        "regular files named <module>.cpython-<digits>.pyc under __pycache__",
        "regular files named <module>.cpython-<digits>.opt-<alnum>.pyc under __pycache__",
        "only when a sibling source <module>.py is observed in the same explicit scan root",
    ],
    non_targets: &[
        "legacy adjacent .pyc, .pyo, extension binaries, directories and archives",
        "unknown implementation tags (for example pypy or malformed cache tags)",
        "missing-source or source-less caches, protected paths, links and ambiguous hardlinks",
    ],
    prerequisites: &[
        "explicit root scan only; no implicit HOME/cwd scan",
        "read-only evidence from scan and native metadata, never source parsing",
        "target and source identities must still match observed scan identities",
    ],
    actions: &[
        RuleAction::PreviewOnly,
        RuleAction::ManualReview,
        RuleAction::ExplicitNativeTrash,
    ],
    rebuild_cost: "Rebuild requires CPython writeable environment and source availability; concurrent compilation can recreate cache files.",
    recovery_cost: "Read-only preview only. Matched bytes are observed bytes, not reclaimable capacity.",
    concurrency: "Concurrent imports/compileall can replace cache files between observations.",
    failure: "Unknown ownership, incomplete evidence, protection, identity drift or unsupported platform yields explicit refusal.",
    evidence: &[
        EvidenceSource {
            title: "Python tutorial: compiled Python files",
            url: "https://docs.python.org/3/tutorial/modules.html#compiled-python-files",
            reviewed_utc: "2026-09-12",
            license_note: "PSF documentation license",
        },
        EvidenceSource {
            title: "PEP 3147 __pycache__ directories",
            url: "https://peps.python.org/pep-3147/",
            reviewed_utc: "2026-09-12",
            license_note: "PEP text is public domain",
        },
        EvidenceSource {
            title: "PEP 488 eliminating .pyo files",
            url: "https://peps.python.org/pep-0488/",
            reviewed_utc: "2026-09-12",
            license_note: "PEP text is public domain",
        },
        EvidenceSource {
            title: "py_compile module documentation",
            url: "https://docs.python.org/3/library/py_compile.html",
            reviewed_utc: "2026-09-12",
            license_note: "PSF documentation license",
        },
    ],
};

pub fn builtin_rules() -> &'static [RuleDefinition] {
    &[CPYTHON_RULE]
}

pub fn is_builtin_rule(rule_id: &str) -> bool {
    builtin_rules().iter().any(|rule| rule.id == rule_id)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExplicitRuleSelection {
    pub target_path: PathBuf,
    pub source_path: PathBuf,
    pub cache_tag: String,
    pub optimization_tag: Option<String>,
}

pub fn explicit_selection_for_target(path: &Path) -> Option<ExplicitRuleSelection> {
    if !looks_like_pyc(path) {
        return None;
    }
    let parent = path.parent()?;
    if parent.file_name().is_none_or(|name| name != "__pycache__") {
        return None;
    }
    let file_name = path.file_name()?;
    let parsed = parse_cpython_name(file_name)?;
    let source_path = parent
        .parent()?
        .join(format!("{}.py", parsed.module_basename));
    Some(ExplicitRuleSelection {
        target_path: path.to_path_buf(),
        source_path,
        cache_tag: parsed.cache_tag,
        optimization_tag: parsed.optimization,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalCode {
    UnsupportedRulePlatform,
    ScanIncomplete,
    CandidateNotRegularFile,
    CandidateDatalessOrCloud,
    NotPycacheChild,
    InvalidPep3147Name,
    SourceMissing,
    SourceNotRegularFile,
    SourceIsLink,
    SourceDatalessOrCloud,
    SourceOutsideRoot,
    ProtectedPath,
    IdentityUnknown,
    IdentityChanged,
    DuplicateOrHardlinkAmbiguous,
    NativePolicyFailure,
    OwnerUnknownOrRunning,
    Cancelled,
    BudgetExceeded,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RuleRefusal {
    pub rule_id: &'static str,
    pub rule_version: u32,
    pub ruleset_revision: u32,
    pub code: RefusalCode,
    pub path: Option<PathBuf>,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RuleCandidate {
    pub rule_id: &'static str,
    pub rule_version: u32,
    pub ruleset_revision: u32,
    pub action: RuleAction,
    pub target_entry_id: u64,
    pub source_entry_id: u64,
    pub target_path: PathBuf,
    pub source_path: PathBuf,
    pub target_identity: FileIdentity,
    pub source_identity: FileIdentity,
    pub matched_logical_bytes: Option<u64>,
    pub observed_cache_tag: String,
    pub observed_optimization_tag: Option<String>,
}

#[derive(Clone, Debug)]
pub struct RulePreview {
    pub schema_version: u32,
    pub kind: &'static str,
    pub ruleset_schema_version: u32,
    pub ruleset_revision: u32,
    pub rule_id: &'static str,
    pub rule_version: u32,
    pub scan_task_id: String,
    pub status: &'static str,
    pub complete: bool,
    pub roots: Vec<PathBuf>,
    pub issues: Vec<ScanIssue>,
    pub issues_omitted: usize,
    pub candidates: Vec<RuleCandidate>,
    pub refusals: Vec<RuleRefusal>,
    pub matched_bytes_known: u64,
    pub matched_bytes_unknown_files: u64,
    pub effects_performed: bool,
}

impl RulePreview {
    pub fn compatible_with_current_ruleset(&self) -> bool {
        self.ruleset_revision == BUILTIN_RULESET_REVISION
    }
}

#[derive(Debug)]
pub enum PreviewError {
    InvalidRuleId,
    Scan(ScanError),
}

impl std::fmt::Display for PreviewError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRuleId => write!(f, "invalid_rule_id"),
            Self::Scan(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for PreviewError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeFacts {
    identity: FileIdentity,
    kind: ResourceKind,
    nlink: Option<u64>,
    uid: Option<u32>,
    dataless: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeInspectError {
    Changed,
    Dataless,
    PolicyFailure,
    Unsupported,
    Cancelled,
}

trait NativeEvidence {
    fn current_uid(&self) -> Option<u32>;
    fn inspect_with_ancestry(
        &self,
        root: &Path,
        root_identity: FileIdentity,
        relative_path: &Path,
        ancestor_identities: &[(PathBuf, FileIdentity)],
        cancellation: &Cancellation,
    ) -> Result<NativeFacts, NativeInspectError>;
}

#[derive(Default)]
struct HostNativeEvidence;

impl NativeEvidence for HostNativeEvidence {
    fn current_uid(&self) -> Option<u32> {
        #[cfg(target_os = "macos")]
        {
            Some(rustix::process::geteuid().as_raw())
        }
        #[cfg(not(target_os = "macos"))]
        {
            None
        }
    }

    fn inspect_with_ancestry(
        &self,
        root: &Path,
        root_identity: FileIdentity,
        relative_path: &Path,
        ancestor_identities: &[(PathBuf, FileIdentity)],
        cancellation: &Cancellation,
    ) -> Result<NativeFacts, NativeInspectError> {
        #[cfg(target_os = "macos")]
        {
            use rustix::fd::OwnedFd;
            use rustix::fs::{self, AtFlags, Mode, OFlags, Stat};
            use sayaka_platform_macos::ReadOnlyPolicy;
            if !matches!(root_identity, FileIdentity::Unix { .. }) {
                return Err(NativeInspectError::Unsupported);
            }

            fn directory_flags() -> OFlags {
                OFlags::RDONLY
                    | OFlags::DIRECTORY
                    | OFlags::CLOEXEC
                    | OFlags::NONBLOCK
                    | OFlags::from_bits_retain(0x2000_0000)
            }

            fn from_stat(stat: &Stat) -> NativeFacts {
                let kind = match stat.st_mode & libc::S_IFMT {
                    libc::S_IFREG => ResourceKind::File,
                    libc::S_IFDIR => ResourceKind::Directory,
                    libc::S_IFLNK => ResourceKind::Link,
                    _ => ResourceKind::Other,
                };
                NativeFacts {
                    identity: FileIdentity::Unix {
                        device: u64::from(stat.st_dev.cast_unsigned()),
                        inode: stat.st_ino,
                    },
                    kind,
                    nlink: Some(u64::from(stat.st_nlink)),
                    uid: Some(stat.st_uid),
                    dataless: stat.st_flags & 0x4000_0000 != 0,
                }
            }

            let policy = ReadOnlyPolicy::enter().map_err(|_| NativeInspectError::PolicyFailure)?;
            let checked = (|| {
                let root_fd = fs::open(root, directory_flags(), Mode::empty())
                    .map_err(|_| NativeInspectError::Changed)?;
                let root_stat = fs::fstat(&root_fd).map_err(|_| NativeInspectError::Changed)?;
                let root_facts = from_stat(&root_stat);
                if root_facts.kind != ResourceKind::Directory
                    || root_facts.identity != root_identity
                {
                    return Err(NativeInspectError::Changed);
                }
                if root_facts.dataless {
                    return Err(NativeInspectError::Dataless);
                }

                let mut current_fd: OwnedFd = root_fd;
                for (name, expected_identity) in ancestor_identities {
                    if cancellation.is_cancelled() {
                        return Err(NativeInspectError::Cancelled);
                    }
                    let child_fd = fs::openat(&current_fd, name, directory_flags(), Mode::empty())
                        .map_err(|_| NativeInspectError::Changed)?;
                    let child_stat =
                        fs::fstat(&child_fd).map_err(|_| NativeInspectError::Changed)?;
                    let observed = from_stat(&child_stat);
                    if observed.kind != ResourceKind::Directory
                        || observed.identity != *expected_identity
                    {
                        return Err(NativeInspectError::Changed);
                    }
                    if observed.dataless {
                        return Err(NativeInspectError::Dataless);
                    }
                    current_fd = child_fd;
                }
                if cancellation.is_cancelled() {
                    return Err(NativeInspectError::Cancelled);
                }
                let leaf_name = relative_path
                    .file_name()
                    .ok_or(NativeInspectError::Changed)?;
                let leaf = fs::statat(&current_fd, leaf_name, AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|_| NativeInspectError::Changed)?;
                Ok(from_stat(&leaf))
            })();
            match (checked, policy.restore()) {
                (Ok(facts), Ok(())) => Ok(facts),
                (Err(error), Ok(())) => Err(error),
                (_, Err(_)) => Err(NativeInspectError::PolicyFailure),
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (
                root,
                root_identity,
                relative_path,
                ancestor_identities,
                cancellation,
            );
            Err(NativeInspectError::Unsupported)
        }
    }
}

fn facts_cancelled(cancellation: &Cancellation) -> bool {
    cancellation.is_cancelled()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuleRunStatus {
    Complete,
    Partial,
    Cancelled,
}

impl RuleRunStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => ScanStatus::Complete.as_str(),
            Self::Partial => ScanStatus::Partial.as_str(),
            Self::Cancelled => ScanStatus::Cancelled.as_str(),
        }
    }

    const fn complete(self) -> bool {
        matches!(self, Self::Complete)
    }
}

fn preview_with_provider(
    tree: &ScanTree,
    cancellation: &Cancellation,
    provider: &dyn NativeEvidence,
) -> RulePreview {
    let mut candidates = Vec::new();
    let mut refusals = Vec::new();
    let mut matched_bytes_known = 0u64;
    let mut matched_bytes_unknown_files = 0u64;
    let roots = tree.report().roots.clone();
    let scopes: Vec<_> = roots
        .iter()
        .filter_map(|root| Scope::new(root.clone(), vec![]).ok())
        .collect();
    let entries = &tree.report().entries;
    let mut by_path = HashMap::with_capacity(entries.len());
    let mut root_by_entry = HashMap::with_capacity(entries.len());
    let mut status = if tree.report().complete {
        RuleRunStatus::Complete
    } else {
        RuleRunStatus::Partial
    };

    if facts_cancelled(cancellation) {
        status = RuleRunStatus::Cancelled;
        refusals.push(global_refusal(
            RefusalCode::Cancelled,
            "rule preview cancelled before indexing",
        ));
    } else {
        for entry in entries {
            if facts_cancelled(cancellation) {
                status = RuleRunStatus::Cancelled;
                refusals.push(global_refusal(
                    RefusalCode::Cancelled,
                    "rule preview cancelled during indexing",
                ));
                break;
            };
            by_path.insert(entry.path.clone(), entry);
            root_by_entry.insert(
                entry.id,
                explicit_root_for_path(&roots, &entry.path).map(PathBuf::from),
            );
        }
    }
    if !tree.report().complete {
        refusals.push(global_refusal(
            RefusalCode::ScanIncomplete,
            "scan is partial; preview reflects observed subset only",
        ));
    }

    if !matches!(status, RuleRunStatus::Cancelled) {
        for entry in entries {
            if facts_cancelled(cancellation) {
                status = RuleRunStatus::Cancelled;
                refusals.push(global_refusal(
                    RefusalCode::Cancelled,
                    "rule preview cancelled during rule matching",
                ));
                break;
            }
            if !looks_like_pyc(&entry.path) {
                continue;
            }
            if entry.kind != ResourceKind::File {
                refusals.push(refusal(
                    entry,
                    RefusalCode::CandidateNotRegularFile,
                    "candidate is not a regular file",
                ));
                continue;
            }
            if entry.dataless {
                refusals.push(refusal(
                    entry,
                    RefusalCode::CandidateDatalessOrCloud,
                    "candidate is cloud-only or dataless",
                ));
                continue;
            }
            if protected(&scopes, &entry.path) {
                refusals.push(refusal(
                    entry,
                    RefusalCode::ProtectedPath,
                    "candidate path is protected",
                ));
                continue;
            }
            let Some(parent) = entry.path.parent() else {
                refusals.push(refusal(
                    entry,
                    RefusalCode::NotPycacheChild,
                    "candidate has no parent directory",
                ));
                continue;
            };
            if parent.file_name().is_none_or(|name| name != "__pycache__") {
                refusals.push(refusal(
                    entry,
                    RefusalCode::NotPycacheChild,
                    "candidate is not directly under __pycache__",
                ));
                continue;
            }
            let Some(file_name) = entry.path.file_name() else {
                refusals.push(refusal(
                    entry,
                    RefusalCode::InvalidPep3147Name,
                    "candidate has no file name",
                ));
                continue;
            };
            let Some(parsed) = parse_cpython_name(file_name) else {
                refusals.push(refusal(
                    entry,
                    RefusalCode::InvalidPep3147Name,
                    "candidate name is not a supported CPython cache tag",
                ));
                continue;
            };
            let Some(source_parent) = parent.parent() else {
                refusals.push(refusal(
                    entry,
                    RefusalCode::SourceMissing,
                    "source directory is unavailable",
                ));
                continue;
            };
            let source_path = source_parent.join(format!("{}.py", parsed.module_basename));
            let Some(source) = by_path.get(&source_path).copied() else {
                refusals.push(refusal(
                    entry,
                    RefusalCode::SourceMissing,
                    "source .py is not observed in this scan",
                ));
                continue;
            };
            if root_by_entry.get(&entry.id) != root_by_entry.get(&source.id) {
                refusals.push(refusal(
                    entry,
                    RefusalCode::SourceOutsideRoot,
                    "source and cache are not in the same explicit root",
                ));
                continue;
            }
            if source.kind == ResourceKind::Link {
                refusals.push(refusal(
                    entry,
                    RefusalCode::SourceIsLink,
                    "source is a link and is not accepted",
                ));
                continue;
            }
            if source.kind != ResourceKind::File {
                refusals.push(refusal(
                    entry,
                    RefusalCode::SourceNotRegularFile,
                    "source is not a regular file",
                ));
                continue;
            }
            if source.dataless {
                refusals.push(refusal(
                    entry,
                    RefusalCode::SourceDatalessOrCloud,
                    "source is cloud-only or dataless",
                ));
                continue;
            }
            if protected(&scopes, &source.path) {
                refusals.push(refusal(
                    entry,
                    RefusalCode::ProtectedPath,
                    "source path is protected",
                ));
                continue;
            }
            if !entry.counted || !source.counted || entry.identity == source.identity {
                refusals.push(refusal(
                    entry,
                    RefusalCode::DuplicateOrHardlinkAmbiguous,
                    "hardlink or duplicate identity ambiguity",
                ));
                continue;
            }
            if facts_cancelled(cancellation) {
                status = RuleRunStatus::Cancelled;
                refusals.push(global_refusal(
                    RefusalCode::Cancelled,
                    "rule preview cancelled before metadata verification",
                ));
                break;
            }
            let Some(target_root) = root_by_entry
                .get(&entry.id)
                .and_then(|root| root.as_deref())
            else {
                refusals.push(refusal(
                    entry,
                    RefusalCode::IdentityUnknown,
                    "candidate has no explicit root membership",
                ));
                continue;
            };
            let Some(source_root) = root_by_entry
                .get(&source.id)
                .and_then(|root| root.as_deref())
            else {
                refusals.push(refusal(
                    entry,
                    RefusalCode::IdentityUnknown,
                    "source has no explicit root membership",
                ));
                continue;
            };
            let Some(target_root_entry) = directory_entry(by_path.get(target_root).copied()) else {
                refusals.push(refusal(
                    entry,
                    RefusalCode::IdentityUnknown,
                    "target root directory identity is unavailable in scan facts",
                ));
                continue;
            };
            let Some(source_root_entry) = directory_entry(by_path.get(source_root).copied()) else {
                refusals.push(refusal(
                    entry,
                    RefusalCode::IdentityUnknown,
                    "source root directory identity is unavailable in scan facts",
                ));
                continue;
            };
            let Some(target_relative) = entry.path.strip_prefix(target_root).ok() else {
                refusals.push(refusal(
                    entry,
                    RefusalCode::IdentityUnknown,
                    "target relative path cannot be derived from explicit root",
                ));
                continue;
            };
            let Some(source_relative) = source.path.strip_prefix(source_root).ok() else {
                refusals.push(refusal(
                    entry,
                    RefusalCode::IdentityUnknown,
                    "source relative path cannot be derived from explicit root",
                ));
                continue;
            };
            let Some(target_ancestors) =
                ancestor_identities(target_root, target_relative, &by_path)
            else {
                refusals.push(refusal(
                    entry,
                    RefusalCode::IdentityUnknown,
                    "target ancestor identities are unavailable in scan facts",
                ));
                continue;
            };
            let Some(source_ancestors) =
                ancestor_identities(source_root, source_relative, &by_path)
            else {
                refusals.push(refusal(
                    entry,
                    RefusalCode::IdentityUnknown,
                    "source ancestor identities are unavailable in scan facts",
                ));
                continue;
            };

            let current_uid = provider.current_uid();
            let target_facts = match provider.inspect_with_ancestry(
                target_root,
                target_root_entry.identity,
                target_relative,
                &target_ancestors,
                cancellation,
            ) {
                Ok(target) => target,
                Err(NativeInspectError::Cancelled) if facts_cancelled(cancellation) => {
                    status = RuleRunStatus::Cancelled;
                    refusals.push(global_refusal(
                        RefusalCode::Cancelled,
                        "rule preview cancelled during metadata verification",
                    ));
                    break;
                }
                Err(NativeInspectError::PolicyFailure) => {
                    refusals.push(refusal(
                        entry,
                        RefusalCode::NativePolicyFailure,
                        "native read-only policy setup or restoration failed",
                    ));
                    continue;
                }
                Err(NativeInspectError::Dataless) => {
                    refusals.push(refusal(
                        entry,
                        RefusalCode::CandidateDatalessOrCloud,
                        "target or target ancestor became cloud-only or dataless",
                    ));
                    continue;
                }
                Err(NativeInspectError::Unsupported) => {
                    refusals.push(refusal(
                        entry,
                        RefusalCode::UnsupportedRulePlatform,
                        "native owner/link evidence unavailable on this platform",
                    ));
                    continue;
                }
                Err(NativeInspectError::Changed) | Err(NativeInspectError::Cancelled) => {
                    refusals.push(refusal(
                        entry,
                        RefusalCode::IdentityChanged,
                        "target or target ancestry changed after scan",
                    ));
                    continue;
                }
            };
            if facts_cancelled(cancellation) {
                status = RuleRunStatus::Cancelled;
                refusals.push(global_refusal(
                    RefusalCode::Cancelled,
                    "rule preview cancelled during metadata verification",
                ));
                break;
            }
            let source_facts = match provider.inspect_with_ancestry(
                source_root,
                source_root_entry.identity,
                source_relative,
                &source_ancestors,
                cancellation,
            ) {
                Ok(source) => source,
                Err(NativeInspectError::Cancelled) if facts_cancelled(cancellation) => {
                    status = RuleRunStatus::Cancelled;
                    refusals.push(global_refusal(
                        RefusalCode::Cancelled,
                        "rule preview cancelled during metadata verification",
                    ));
                    break;
                }
                Err(NativeInspectError::PolicyFailure) => {
                    refusals.push(refusal(
                        entry,
                        RefusalCode::NativePolicyFailure,
                        "native read-only policy setup or restoration failed",
                    ));
                    continue;
                }
                Err(NativeInspectError::Dataless) => {
                    refusals.push(refusal(
                        entry,
                        RefusalCode::SourceDatalessOrCloud,
                        "source or source ancestor became cloud-only or dataless",
                    ));
                    continue;
                }
                Err(NativeInspectError::Unsupported) => {
                    refusals.push(refusal(
                        entry,
                        RefusalCode::UnsupportedRulePlatform,
                        "native owner/link evidence unavailable on this platform",
                    ));
                    continue;
                }
                Err(NativeInspectError::Changed) | Err(NativeInspectError::Cancelled) => {
                    refusals.push(refusal(
                        entry,
                        RefusalCode::IdentityChanged,
                        "source or source ancestry changed after scan",
                    ));
                    continue;
                }
            };
            if facts_cancelled(cancellation) {
                status = RuleRunStatus::Cancelled;
                refusals.push(global_refusal(
                    RefusalCode::Cancelled,
                    "rule preview cancelled during metadata verification",
                ));
                break;
            }
            if target_facts.dataless {
                refusals.push(refusal(
                    entry,
                    RefusalCode::CandidateDatalessOrCloud,
                    "target became cloud-only or dataless after scan",
                ));
                continue;
            }
            if source_facts.dataless {
                refusals.push(refusal(
                    entry,
                    RefusalCode::SourceDatalessOrCloud,
                    "source became cloud-only or dataless after scan",
                ));
                continue;
            }
            if target_facts.identity != entry.identity || source_facts.identity != source.identity {
                refusals.push(refusal(
                    entry,
                    RefusalCode::IdentityChanged,
                    "target or source identity changed after scan",
                ));
                continue;
            }
            if target_facts.kind != ResourceKind::File || source_facts.kind != ResourceKind::File {
                refusals.push(refusal(
                    entry,
                    RefusalCode::IdentityChanged,
                    "target or source kind changed after scan",
                ));
                continue;
            }
            if !matches!(target_facts.nlink, Some(1)) || !matches!(source_facts.nlink, Some(1)) {
                refusals.push(refusal(
                    entry,
                    RefusalCode::DuplicateOrHardlinkAmbiguous,
                    "link count is not exactly one for target/source",
                ));
                continue;
            }
            let ownership_matches = matches!(
                (current_uid, target_facts.uid, source_facts.uid),
                (Some(current), Some(target), Some(source)) if current == target && current == source
            );
            if !ownership_matches {
                refusals.push(refusal(
                    entry,
                    RefusalCode::OwnerUnknownOrRunning,
                    "owner evidence is unknown or not current user",
                ));
                continue;
            }

            match entry.logical_bytes {
                Some(bytes) => {
                    if let Some(sum) = matched_bytes_known.checked_add(bytes) {
                        matched_bytes_known = sum;
                    } else {
                        refusals.push(refusal(
                            entry,
                            RefusalCode::BudgetExceeded,
                            "matched-bytes sum overflow",
                        ));
                        continue;
                    }
                }
                None => {
                    if let Some(sum) = matched_bytes_unknown_files.checked_add(1) {
                        matched_bytes_unknown_files = sum;
                    } else {
                        refusals.push(refusal(
                            entry,
                            RefusalCode::BudgetExceeded,
                            "unknown-byte file counter overflow",
                        ));
                        continue;
                    }
                }
            }

            candidates.push(RuleCandidate {
                rule_id: CPYTHON_SOURCE_BACKED_PYC_RULE_ID,
                rule_version: CPYTHON_SOURCE_BACKED_PYC_RULE_VERSION,
                ruleset_revision: BUILTIN_RULESET_REVISION,
                action: RuleAction::ManualReview,
                target_entry_id: entry.id,
                source_entry_id: source.id,
                target_path: entry.path.clone(),
                source_path: source.path.clone(),
                target_identity: entry.identity,
                source_identity: source.identity,
                matched_logical_bytes: entry.logical_bytes,
                observed_cache_tag: parsed.cache_tag,
                observed_optimization_tag: parsed.optimization,
            });
        }
    }
    if matches!(status, RuleRunStatus::Cancelled) {
        candidates.clear();
        matched_bytes_known = 0;
        matched_bytes_unknown_files = 0;
    }

    RulePreview {
        schema_version: PREVIEW_SCHEMA_VERSION,
        kind: "rule_preview",
        ruleset_schema_version: RULESET_SCHEMA_VERSION,
        ruleset_revision: BUILTIN_RULESET_REVISION,
        rule_id: CPYTHON_SOURCE_BACKED_PYC_RULE_ID,
        rule_version: CPYTHON_SOURCE_BACKED_PYC_RULE_VERSION,
        scan_task_id: tree.report().task_id.to_string(),
        status: status.as_str(),
        complete: status.complete(),
        roots,
        issues: tree.report().issues.clone(),
        issues_omitted: tree.report().issues_omitted,
        candidates,
        refusals,
        matched_bytes_known,
        matched_bytes_unknown_files,
        effects_performed: false,
    }
}

pub fn preview(
    report: ScanReport,
    rule_id: &str,
    cancellation: &Cancellation,
) -> Result<RulePreview, PreviewError> {
    if rule_id != CPYTHON_SOURCE_BACKED_PYC_RULE_ID {
        return Err(PreviewError::InvalidRuleId);
    }
    if facts_cancelled(cancellation) {
        return Ok(RulePreview {
            schema_version: PREVIEW_SCHEMA_VERSION,
            kind: "rule_preview",
            ruleset_schema_version: RULESET_SCHEMA_VERSION,
            ruleset_revision: BUILTIN_RULESET_REVISION,
            rule_id: CPYTHON_SOURCE_BACKED_PYC_RULE_ID,
            rule_version: CPYTHON_SOURCE_BACKED_PYC_RULE_VERSION,
            scan_task_id: report.task_id.to_string(),
            status: ScanStatus::Cancelled.as_str(),
            complete: false,
            roots: report.roots,
            issues: report.issues,
            issues_omitted: report.issues_omitted,
            candidates: Vec::new(),
            refusals: vec![global_refusal(
                RefusalCode::Cancelled,
                "rule preview cancelled before scan indexing",
            )],
            matched_bytes_known: 0,
            matched_bytes_unknown_files: 0,
            effects_performed: false,
        });
    }
    let tree = ScanTree::build(report, cancellation).map_err(PreviewError::Scan)?;
    Ok(preview_with_provider(
        &tree,
        cancellation,
        &HostNativeEvidence,
    ))
}

fn explicit_root_for_path<'a>(roots: &'a [PathBuf], path: &Path) -> Option<&'a Path> {
    roots
        .iter()
        .map(PathBuf::as_path)
        .filter(|root| path.starts_with(root))
        .max_by_key(|root| root.as_os_str().len())
}

fn refusal(entry: &ScanEntry, code: RefusalCode, message: &str) -> RuleRefusal {
    RuleRefusal {
        rule_id: CPYTHON_SOURCE_BACKED_PYC_RULE_ID,
        rule_version: CPYTHON_SOURCE_BACKED_PYC_RULE_VERSION,
        ruleset_revision: BUILTIN_RULESET_REVISION,
        code,
        path: Some(entry.path.clone()),
        message: message.to_owned(),
    }
}

fn global_refusal(code: RefusalCode, message: &str) -> RuleRefusal {
    RuleRefusal {
        rule_id: CPYTHON_SOURCE_BACKED_PYC_RULE_ID,
        rule_version: CPYTHON_SOURCE_BACKED_PYC_RULE_VERSION,
        ruleset_revision: BUILTIN_RULESET_REVISION,
        code,
        path: None,
        message: message.to_owned(),
    }
}

struct ParsedCacheName {
    module_basename: String,
    cache_tag: String,
    optimization: Option<String>,
}

fn parse_cpython_name(name: &std::ffi::OsStr) -> Option<ParsedCacheName> {
    let text = name.to_str()?;
    let suffix = ".pyc";
    let stem = text.strip_suffix(suffix)?;
    let marker = ".cpython-";
    let marker_index = stem.rfind(marker)?;
    let module = &stem[..marker_index];
    if module.is_empty() || module.contains(std::path::MAIN_SEPARATOR) {
        return None;
    }
    let after = &stem[marker_index + marker.len()..];
    let (version_digits, optimization) = match after.split_once(".opt-") {
        Some((digits, opt)) => (digits, Some(opt)),
        None => (after, None),
    };
    if version_digits.len() < 2
        || !version_digits.starts_with('3')
        || !version_digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let minor = version_digits[1..].parse::<u32>().ok()?;
    if minor < 2 {
        return None;
    }
    if optimization
        .is_some_and(|opt| opt.is_empty() || !opt.bytes().all(|byte| byte.is_ascii_alphanumeric()))
    {
        return None;
    }
    Some(ParsedCacheName {
        module_basename: module.to_owned(),
        cache_tag: format!("cpython-{version_digits}"),
        optimization: optimization.map(str::to_owned),
    })
}

fn looks_like_pyc(path: &Path) -> bool {
    path.file_name()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|name| name.ends_with(".pyc"))
}

fn protected(scopes: &[Scope], path: &Path) -> bool {
    scopes.iter().any(|scope| scope.protects(path))
}

fn directory_entry(entry: Option<&ScanEntry>) -> Option<&ScanEntry> {
    entry.filter(|entry| entry.kind == ResourceKind::Directory)
}

fn ancestor_identities(
    root: &Path,
    relative_path: &Path,
    by_path: &HashMap<PathBuf, &ScanEntry>,
) -> Option<Vec<(PathBuf, FileIdentity)>> {
    let mut ancestors = Vec::new();
    let mut current = root.to_path_buf();
    let mut parent = relative_path.to_path_buf();
    if !parent.pop() {
        return Some(ancestors);
    }
    for component in parent.components() {
        let std::path::Component::Normal(name) = component else {
            return None;
        };
        current.push(name);
        let entry = by_path.get(&current).copied()?;
        if entry.kind != ResourceKind::Directory {
            return None;
        }
        ancestors.push((PathBuf::from(name), entry.identity));
    }
    Some(ancestors)
}

#[cfg(test)]
mod tests;
