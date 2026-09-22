// SPDX-License-Identifier: MPL-2.0

//! Local audit records, never executable approvals. Interrupted work is unknown.

use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
#[cfg(unix)]
use std::{collections::HashSet, ffi::OsStr, os::unix::ffi::OsStrExt};

pub const SCHEMA_VERSION: u32 = 2;
const LEGACY_SCHEMA_VERSION: u32 = 1;
const LEGACY_PLAN_SCHEMA_VERSION: u32 = 2;
const LEGACY_ENGINE_VERSION: u32 = 2;
const LEGACY_RULES_VERSION: u32 = 1;
const RULE_BOUND_PLAN_SCHEMA_VERSION: u32 = 3;
const RULE_BOUND_ENGINE_VERSION: u32 = 2;
const RULE_BOUND_RULES_VERSION: u32 = 2;
const CLEAN_SCHEMA_VERSION: u32 = 3;
const CLEAN_PLAN_SCHEMA_VERSION: u32 = 3;
const CLEAN_ENGINE_VERSION: u32 = 2;
const CLEAN_RULES_VERSION: u32 = 2;
/// Bundle-trash records hold directory items under contract
/// `revalidated_bundle_trash_v1`; see docs/UNINSTALL_EXECUTION.md.
pub const BUNDLE_SCHEMA_VERSION: u32 = 4;
const BUNDLE_PLAN_SCHEMA_VERSION: u32 = 4;
const BUNDLE_ENGINE_VERSION: u32 = 2;
const BUNDLE_RULES_VERSION: u32 = 1;
pub const PURGE_SCHEMA_VERSION: u32 = 5;
const PURGE_PLAN_SCHEMA_VERSION: u32 = 5;
const PURGE_ENGINE_VERSION: u32 = 2;
const PURGE_RULES_VERSION: u32 = 1;
const SF_DATALESS: u32 = 0x40000000;
const SF_RESTRICTED: u32 = 0x00080000;
const SF_NOUNLINK: u32 = 0x00100000;
const ORDINARY_FLAGS: u32 = 0x00000001 | 0x00000020 | 0x00000040 | 0x00008000;
pub const MAX_ITEMS: usize = 32;
pub const MAX_RECORD_BYTES: u64 = 1024 * 1024;
pub const MAX_RECORDS: usize = 1024;
pub const MAX_READ_BYTES: usize = 16 * 1024 * 1024;

#[cfg(any(target_os = "macos", test))]
#[derive(Debug, Default)]
pub(crate) struct Publication {
    pub cleanup_error: Option<io::Error>,
}

#[cfg(any(target_os = "macos", test))]
impl Publication {
    pub fn require_clean(self) -> io::Result<()> {
        match self.cleanup_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct JournalRead {
    pub records: Vec<Record>,
    pub uncommitted_snapshots: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativePath {
    pub display: String,
    pub encoding: String,
    pub bytes: Vec<u8>,
}

impl NativePath {
    #[cfg(test)]
    pub(crate) fn unix_fixture(path: &str) -> Self {
        assert!(path.is_ascii());
        let value = Self {
            display: format!("{path:?}"),
            encoding: "unix_bytes".into(),
            bytes: path.as_bytes().to_vec(),
        };
        value.validate().expect("valid Unix wire fixture");
        value
    }

    pub fn from_path(path: &Path) -> Self {
        Self {
            display: format!("{:?}", path.as_os_str()),
            encoding: if cfg!(unix) {
                "unix_bytes"
            } else {
                "display_only"
            }
            .into(),
            bytes: if cfg!(unix) {
                path.as_os_str().as_encoded_bytes().to_vec()
            } else {
                Vec::new()
            },
        }
    }

    fn validate(&self) -> io::Result<()> {
        if self.encoding != "unix_bytes"
            || self.bytes.is_empty()
            || self.bytes.len() > 4096
            || self.bytes[0] != b'/'
            || self.bytes.contains(&0)
            || self
                .bytes
                .split(|byte| *byte == b'/')
                .any(|part| part == b".." || part == b".")
        {
            return Err(invalid("invalid native journal path"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let expected = format!("{:?}", std::ffi::OsStr::from_bytes(&self.bytes));
            if expected != self.display {
                return Err(invalid("journal display path disagrees with native path"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemState {
    Planned,
    Started,
    Succeeded,
    Skipped,
    Failed,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeTime {
    pub before_unix_epoch: bool,
    pub seconds: u64,
    pub nanoseconds: u32,
}

impl NativeTime {
    pub fn from_system_time(time: SystemTime) -> Self {
        let (before_unix_epoch, duration) = match time.duration_since(UNIX_EPOCH) {
            Ok(duration) => (false, duration),
            Err(error) => (true, error.duration()),
        };
        Self {
            before_unix_epoch,
            seconds: duration.as_secs(),
            nanoseconds: duration.subsec_nanos(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileEvidence {
    pub device: u64,
    pub inode: u64,
    pub logical_bytes: u64,
    pub modified: NativeTime,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleWitnessRecord {
    pub path: NativePath,
    pub device: u64,
    pub inode: u64,
    pub kind: String,
    pub logical_bytes: u64,
    pub modified: NativeTime,
    pub changed: NativeTime,
    pub created: NativeTime,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub nlink: u64,
    pub flags: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleBindingRecord {
    pub schema_version: u32,
    pub rule_id: String,
    pub rule_version: u32,
    pub ruleset_schema_version: u32,
    pub ruleset_revision: u32,
    pub semantics: String,
    pub semantics_digest: String,
    pub selected_root: NativePath,
    pub exclusions: Vec<NativePath>,
    pub target: RuleWitnessRecord,
    pub source: RuleWitnessRecord,
    pub root: RuleWitnessRecord,
    pub target_ancestors: Vec<RuleWitnessRecord>,
    pub source_ancestors: Vec<RuleWitnessRecord>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanPolicyPathRecord {
    pub encoding: String,
    pub bytes_hex: String,
    pub display: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanPolicyIdentityRecord {
    pub device: u64,
    pub inode: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanPolicyContextRecord {
    pub schema_version: u32,
    pub kind: String,
    pub root_path: CleanPolicyPathRecord,
    pub root_identity: CleanPolicyIdentityRecord,
    pub file_state: serde_json::Value,
    pub effective_exclusions: Vec<CleanPolicyPathRecord>,
}

/// Read-only observations, not verified restore targets or authorizations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryEvidence {
    pub approved: FileEvidence,
    pub returned_destination: Option<NativePath>,
    pub held_source: Option<FileEvidence>,
    pub held_source_path: Option<NativePath>,
    pub observation_errors: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemRecord {
    pub path: NativePath,
    pub device: u64,
    pub inode: u64,
    pub logical_bytes: u64,
    pub state: ItemState,
    pub reason: Option<String>,
    pub destination: Option<NativePath>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_binding: Option<RuleBindingRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_evidence: Option<RecoveryEvidence>,
    pub updated_unix_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub schema_version: u32,
    pub plan_schema_version: u32,
    pub engine_version: u32,
    pub rules_version: u32,
    pub operation_id: String,
    pub contract: String,
    pub scope: NativePath,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clean_policy: Option<CleanPolicyContextRecord>,
    pub created_unix_ms: u64,
    pub items: Vec<ItemRecord>,
}

impl Record {
    pub fn validate(&self) -> io::Result<()> {
        let legacy = self.schema_version == LEGACY_SCHEMA_VERSION
            && self.plan_schema_version == LEGACY_PLAN_SCHEMA_VERSION
            && self.engine_version == LEGACY_ENGINE_VERSION
            && self.rules_version == LEGACY_RULES_VERSION
            && self.contract == "revalidated_trash_v1";
        let rule_bound = self.schema_version == SCHEMA_VERSION
            && self.plan_schema_version == RULE_BOUND_PLAN_SCHEMA_VERSION
            && self.engine_version == RULE_BOUND_ENGINE_VERSION
            && self.rules_version == RULE_BOUND_RULES_VERSION
            && self.contract == "revalidated_trash_v1";
        let clean = self.schema_version == CLEAN_SCHEMA_VERSION
            && self.plan_schema_version == CLEAN_PLAN_SCHEMA_VERSION
            && self.engine_version == CLEAN_ENGINE_VERSION
            && self.rules_version == CLEAN_RULES_VERSION
            && self.contract == "revalidated_trash_v1";
        let bundle = self.schema_version == BUNDLE_SCHEMA_VERSION
            && self.plan_schema_version == BUNDLE_PLAN_SCHEMA_VERSION
            && self.engine_version == BUNDLE_ENGINE_VERSION
            && self.rules_version == BUNDLE_RULES_VERSION
            && self.contract == "revalidated_bundle_trash_v1";
        let purge = self.schema_version == PURGE_SCHEMA_VERSION
            && self.plan_schema_version == PURGE_PLAN_SCHEMA_VERSION
            && self.engine_version == PURGE_ENGINE_VERSION
            && self.rules_version == PURGE_RULES_VERSION
            && self.contract == "revalidated_purge_trash_v1";
        if !(legacy || rule_bound || clean || bundle || purge)
            || !valid_id(&self.operation_id)
            || self.items.is_empty()
            || self.items.len() > MAX_ITEMS
        {
            return Err(invalid("unsupported or invalid journal record"));
        }

        fn validate_clean_policy_context(context: &CleanPolicyContextRecord) -> io::Result<()> {
            if context.schema_version != 1
                || context.kind != "sayaka_clean_policy_context"
                || context.effective_exclusions.len() > MAX_ITEMS
            {
                return Err(invalid("invalid clean policy context metadata"));
            }
            validate_clean_policy_path(&context.root_path, true)?;
            for path in &context.effective_exclusions {
                validate_clean_policy_path(path, true)?;
            }
            if context
                .file_state
                .get("state")
                .and_then(serde_json::Value::as_str)
                .is_none()
            {
                return Err(invalid("clean policy file state is missing required state"));
            }
            Ok(())
        }

        fn validate_clean_policy_path(
            path: &CleanPolicyPathRecord,
            absolute: bool,
        ) -> io::Result<()> {
            if path.encoding != "unix_bytes" || path.bytes_hex.is_empty() {
                return Err(invalid("invalid clean policy path encoding"));
            }
            let bytes = decode_hex_bytes(&path.bytes_hex)
                .ok_or_else(|| invalid("invalid clean policy hex path"))?;
            if bytes.contains(&0) || (absolute && bytes.first() != Some(&b'/')) {
                return Err(invalid("invalid clean policy path bytes"));
            }
            #[cfg(unix)]
            {
                let expected = format!("{:?}", std::ffi::OsStr::from_bytes(&bytes));
                if expected != path.display {
                    return Err(invalid(
                        "clean policy display path disagrees with native path",
                    ));
                }
            }
            Ok(())
        }

        fn decode_hex_bytes(text: &str) -> Option<Vec<u8>> {
            if !text.len().is_multiple_of(2) {
                return None;
            }
            let mut bytes = Vec::with_capacity(text.len() / 2);
            for i in (0..text.len()).step_by(2) {
                let pair = &text[i..i + 2];
                bytes.push(u8::from_str_radix(pair, 16).ok()?);
            }
            Some(bytes)
        }
        self.scope.validate()?;
        if clean {
            validate_clean_policy_context(
                self.clean_policy
                    .as_ref()
                    .ok_or_else(|| invalid("missing clean policy context"))?,
            )?;
        } else if self.clean_policy.is_some() {
            return Err(invalid(
                "legacy/rule-bound record must not contain clean policy context",
            ));
        }
        let mut identities = std::collections::HashSet::new();
        let mut paths = std::collections::HashSet::new();
        for item in &self.items {
            item.path.validate()?;
            if let Some(destination) = &item.destination {
                destination.validate()?;
            }
            match (&item.rule_binding, rule_bound || clean) {
                (Some(binding), true) => validate_rule_binding(item, binding)?,
                (None, true) => return Err(invalid("missing rule binding for rule-bound record")),
                (Some(_), false) => {
                    return Err(invalid("legacy record must not contain rule binding"));
                }
                (None, false) => {}
            }
            if let Some(evidence) = &item.recovery_evidence {
                if item.state != ItemState::Unknown
                    || evidence.approved.device != item.device
                    || evidence.approved.inode != item.inode
                    || evidence.approved.logical_bytes != item.logical_bytes
                    || evidence.approved.modified.nanoseconds >= 1_000_000_000
                    || evidence
                        .held_source
                        .as_ref()
                        .is_some_and(|source| source.modified.nanoseconds >= 1_000_000_000)
                    || evidence.observation_errors.len() > 8
                {
                    return Err(invalid("inconsistent ambiguous-outcome evidence"));
                }
                for path in [&evidence.returned_destination, &evidence.held_source_path]
                    .into_iter()
                    .flatten()
                {
                    path.validate()?;
                }
            }
            if !identities.insert((item.device, item.inode))
                || !paths.insert(&item.path.bytes)
                || item.path.bytes.len() > 4096
                || item.path.encoding != "unix_bytes"
                || item.path.bytes.first() != Some(&b'/')
                || item.path.bytes.contains(&0)
                || (item.state == ItemState::Succeeded && item.destination.is_none())
                || (!matches!(item.state, ItemState::Succeeded | ItemState::Unknown)
                    && item.destination.is_some())
            {
                return Err(invalid("inconsistent journal item"));
            }
        }
        Ok(())
    }

    /// This is a read-time interpretation; it neither rewrites nor retries work.
    pub fn reconciled(mut self) -> Self {
        for item in &mut self.items {
            if item.state == ItemState::Started {
                item.state = ItemState::Unknown;
                item.reason =
                    Some("interrupted_after_durable_intent; never automatically retried".into());
            } else if item.state == ItemState::Planned {
                item.state = ItemState::Skipped;
                item.reason = Some("not_started_before_session_ended".into());
            }
        }
        self
    }

    /// Sum the approved logical sizes of verified moved identities, not a fresh
    /// destination measurement or a free-space delta.
    pub fn handled_bytes(&self) -> Option<u64> {
        self.items
            .iter()
            .filter(|item| item.state == ItemState::Succeeded)
            .try_fold(0u64, |sum, item| sum.checked_add(item.logical_bytes))
    }
}

#[cfg(any(target_os = "macos", test))]
pub(crate) fn now_ms() -> io::Result<u64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid("system clock is before the Unix epoch"))?
        .as_millis();
    u64::try_from(millis).map_err(|_| invalid("timestamp overflow"))
}

pub(crate) fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(unix)]
fn known_rule_binding_tuple(binding: &RuleBindingRecord) -> bool {
    let current_cpython = (
        crate::rules::CPYTHON_SOURCE_BACKED_PYC_RULE_ID,
        crate::rules::CPYTHON_SOURCE_BACKED_PYC_RULE_VERSION,
        crate::rules::RULESET_SCHEMA_VERSION,
        crate::rules::BUILTIN_RULESET_REVISION,
        crate::rules::CPYTHON_SOURCE_BACKED_PYC_TRASH_SEMANTICS,
        crate::rules::CPYTHON_SOURCE_BACKED_PYC_TRASH_SEMANTICS_DIGEST,
    );
    let historical_cpython_r2 = (
        crate::rules::CPYTHON_SOURCE_BACKED_PYC_RULE_ID,
        crate::rules::CPYTHON_SOURCE_BACKED_PYC_RULE_VERSION,
        crate::rules::RULESET_SCHEMA_VERSION,
        2_u32,
        crate::rules::CPYTHON_SOURCE_BACKED_PYC_TRASH_SEMANTICS,
        crate::rules::CPYTHON_SOURCE_BACKED_PYC_TRASH_SEMANTICS_DIGEST,
    );
    let current_javac = (
        crate::rules::JAVAC_SOURCE_BACKED_CLASS_RULE_ID,
        crate::rules::JAVAC_SOURCE_BACKED_CLASS_RULE_VERSION,
        crate::rules::RULESET_SCHEMA_VERSION,
        crate::rules::BUILTIN_RULESET_REVISION,
        crate::rules::JAVAC_SOURCE_BACKED_CLASS_TRASH_SEMANTICS,
        crate::rules::JAVAC_SOURCE_BACKED_CLASS_TRASH_SEMANTICS_DIGEST,
    );
    let observed = (
        binding.rule_id.as_str(),
        binding.rule_version,
        binding.ruleset_schema_version,
        binding.ruleset_revision,
        binding.semantics.as_str(),
        binding.semantics_digest.as_str(),
    );
    observed == current_cpython || observed == historical_cpython_r2 || observed == current_javac
}

fn validate_rule_binding(item: &ItemRecord, binding: &RuleBindingRecord) -> io::Result<()> {
    #[cfg(not(unix))]
    {
        let _ = (item, binding);
        return Err(invalid(
            "rule-bound journal records require unix path semantics",
        ));
    }
    #[cfg(unix)]
    if binding.schema_version != 1
        || binding.warnings.is_empty()
        || binding.target_ancestors.len() > MAX_ITEMS
        || binding.source_ancestors.len() > MAX_ITEMS
        || binding.exclusions.len() > MAX_ITEMS
        || !known_rule_binding_tuple(binding)
    {
        return Err(invalid("invalid rule binding metadata"));
    }
    binding.selected_root.validate()?;
    for path in &binding.exclusions {
        path.validate()?;
    }
    for witness in [&binding.target, &binding.source, &binding.root]
        .into_iter()
        .chain(binding.target_ancestors.iter())
        .chain(binding.source_ancestors.iter())
    {
        witness.path.validate()?;
        if witness.kind.is_empty()
            || witness.modified.nanoseconds >= 1_000_000_000
            || witness.changed.nanoseconds >= 1_000_000_000
            || witness.created.nanoseconds >= 1_000_000_000
        {
            return Err(invalid("invalid rule witness"));
        }
    }
    if binding.target.path != item.path
        || binding.target.device != item.device
        || binding.target.inode != item.inode
        || binding.target.logical_bytes != item.logical_bytes
    {
        return Err(invalid("rule binding target does not match item identity"));
    }
    #[cfg(unix)]
    {
        let regular_kind = u32::from(libc::S_IFREG);
        let directory_kind = u32::from(libc::S_IFDIR);
        let target_kind = binding.target.mode & u32::from(libc::S_IFMT);
        let source_kind = binding.source.mode & u32::from(libc::S_IFMT);
        let root_kind = binding.root.mode & u32::from(libc::S_IFMT);
        if target_kind != regular_kind
            || source_kind != regular_kind
            || root_kind != directory_kind
            || binding.target.mode & 0o7022 != 0
            || binding.source.mode & 0o7022 != 0
            || binding.root.mode & 0o7022 != 0
            || binding.target.nlink != 1
            || binding.source.nlink != 1
            || binding.target.flags & !ORDINARY_FLAGS != 0
            || binding.source.flags & !ORDINARY_FLAGS != 0
            || binding.root.flags & !(ORDINARY_FLAGS | SF_RESTRICTED | SF_NOUNLINK) != 0
            || binding.target.flags & SF_DATALESS != 0
            || binding.source.flags & SF_DATALESS != 0
            || binding.root.flags & SF_DATALESS != 0
        {
            return Err(invalid(
                "rule binding witness metadata is outside admissible bounds",
            ));
        }
        if binding.target.kind != "file"
            || binding.source.kind != "file"
            || binding.root.kind != "directory"
            || binding
                .target_ancestors
                .iter()
                .chain(binding.source_ancestors.iter())
                .any(|entry| entry.kind != "directory")
        {
            return Err(invalid("invalid rule witness kind"));
        }
        for entry in binding
            .target_ancestors
            .iter()
            .chain(binding.source_ancestors.iter())
        {
            let kind = entry.mode & u32::from(libc::S_IFMT);
            if kind != directory_kind
                || entry.mode & 0o7022 != 0
                || entry.flags & !(ORDINARY_FLAGS | SF_RESTRICTED | SF_NOUNLINK) != 0
                || entry.flags & SF_DATALESS != 0
            {
                return Err(invalid(
                    "ancestor witness metadata is outside admissible bounds",
                ));
            }
        }
        let target_path = native_to_path(&binding.target.path)?;
        let source_path = native_to_path(&binding.source.path)?;
        let selected_root = native_to_path(&binding.selected_root)?;
        let root_path = native_to_path(&binding.root.path)?;
        if selected_root != root_path {
            return Err(invalid("selected root disagrees with root witness path"));
        }
        if !target_path.starts_with(&selected_root)
            || !source_path.starts_with(&selected_root)
            || target_path == selected_root
            || source_path == selected_root
        {
            return Err(invalid("target/source path is outside selected root"));
        }
        let expected =
            crate::rules::explicit_selection_for_rule_target(&binding.rule_id, &target_path)
                .ok_or_else(|| invalid("target path does not match explicit rule"))?;
        if expected.source_path != source_path {
            return Err(invalid(
                "source path does not match explicit sibling source",
            ));
        }
        validate_ancestor_chain(
            &selected_root,
            &target_path,
            &binding.target_ancestors,
            "target",
        )?;
        validate_ancestor_chain(
            &selected_root,
            &source_path,
            &binding.source_ancestors,
            "source",
        )?;
        let mut exclusions = HashSet::new();
        for exclusion in &binding.exclusions {
            let path = native_to_path(exclusion)?;
            if !path.starts_with(&selected_root) {
                return Err(invalid("exclusion path is outside selected root"));
            }
            if !exclusions.insert(path) {
                return Err(invalid("duplicate exclusion path in rule binding"));
            }
        }
    }
    if binding.source.path == binding.target.path
        || binding.source.device == binding.target.device
            && binding.source.inode == binding.target.inode
    {
        return Err(invalid("rule binding source and target must be distinct"));
    }
    Ok(())
}

#[cfg(unix)]
fn native_to_path(path: &NativePath) -> io::Result<PathBuf> {
    if path.encoding != "unix_bytes" || path.bytes.is_empty() {
        return Err(invalid("invalid native path encoding"));
    }
    Ok(PathBuf::from(OsStr::from_bytes(&path.bytes)))
}

#[cfg(unix)]
fn validate_ancestor_chain(
    root: &Path,
    leaf: &Path,
    ancestors: &[RuleWitnessRecord],
    _label: &str,
) -> io::Result<()> {
    if !leaf.starts_with(root) || leaf == root {
        return Err(invalid("witness path must be inside root"));
    }
    let relative = leaf
        .strip_prefix(root)
        .map_err(|_| invalid("witness path must be inside root"))?;
    let mut current = root.to_path_buf();
    let mut expected = Vec::new();
    let component_count = relative.components().count();
    for (index, component) in relative.components().enumerate() {
        if index + 1 == component_count {
            break;
        }
        current.push(component.as_os_str());
        expected.push(current.clone());
    }
    if expected.len() != ancestors.len() {
        return Err(invalid("ancestor witness count mismatch"));
    }
    for (entry, path) in ancestors.iter().zip(expected.iter()) {
        if native_to_path(&entry.path)? != *path {
            return Err(invalid("ancestor witness path mismatch"));
        }
    }
    Ok(())
}

pub(crate) fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 100
        && id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
}

#[cfg(target_os = "macos")]
mod store;
#[cfg(target_os = "macos")]
pub use store::Store;

#[cfg(not(target_os = "macos"))]
pub struct Store;

#[cfg(not(target_os = "macos"))]
impl Store {
    pub fn open(_: &Path, _: bool) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native journal storage is macOS-only",
        ))
    }
    pub fn records(&self) -> io::Result<JournalRead> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native journal storage is macOS-only",
        ))
    }
}

pub fn default_directory() -> io::Result<PathBuf> {
    #[cfg(not(target_os = "macos"))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native journal storage is macOS-only",
        ))
    }
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var_os("HOME")
            .filter(|home| !home.is_empty())
            .ok_or_else(|| invalid("HOME is unavailable; supply --state-dir"))?;
        let home = PathBuf::from(home);
        if !home.is_absolute() {
            return Err(invalid("HOME must be absolute; supply --state-dir"));
        }
        Ok(home.join("Library/Application Support/Sayaka"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> Record {
        Record {
            schema_version: LEGACY_SCHEMA_VERSION,
            plan_schema_version: LEGACY_PLAN_SCHEMA_VERSION,
            engine_version: LEGACY_ENGINE_VERSION,
            rules_version: LEGACY_RULES_VERSION,
            operation_id: "a-1".into(),
            contract: "revalidated_trash_v1".into(),
            scope: NativePath::unix_fixture("/fixture"),
            clean_policy: None,
            created_unix_ms: 1,
            items: vec![ItemRecord {
                path: NativePath::unix_fixture("/fixture/file"),
                device: 1,
                inode: 2,
                logical_bytes: 5,
                state: ItemState::Started,
                reason: None,
                destination: None,
                rule_binding: None,
                recovery_evidence: None,
                updated_unix_ms: 1,
            }],
        }
    }

    #[test]
    fn interrupted_intent_is_unknown_without_replay() {
        let original = record();
        let recovered = original.clone().reconciled();
        assert_eq!(original.items[0].state, ItemState::Started);
        assert_eq!(recovered.items[0].state, ItemState::Unknown);
        assert_eq!(recovered.handled_bytes(), Some(0));
    }

    #[test]
    fn rejects_future_schema_duplicate_identity_and_false_success() {
        let mut value = record();
        value.validate().unwrap();
        value.schema_version = 99;
        assert!(value.validate().is_err());
        value.schema_version = LEGACY_SCHEMA_VERSION;
        value.items.push(value.items[0].clone());
        assert!(value.validate().is_err());
        value.items.pop();
        value.items[0].state = ItemState::Succeeded;
        assert!(value.validate().is_err());
    }

    #[test]
    fn rule_bound_schema_requires_complete_binding() {
        let mut value = record();
        value.schema_version = SCHEMA_VERSION;
        value.plan_schema_version = RULE_BOUND_PLAN_SCHEMA_VERSION;
        value.rules_version = RULE_BOUND_RULES_VERSION;
        value.items[0].path =
            NativePath::unix_fixture("/fixture/pkg/__pycache__/module.cpython-39.pyc");
        value.items[0].logical_bytes = 12;
        value.items[0].rule_binding = Some(RuleBindingRecord {
            schema_version: 1,
            rule_id: crate::rules::CPYTHON_SOURCE_BACKED_PYC_RULE_ID.into(),
            rule_version: crate::rules::CPYTHON_SOURCE_BACKED_PYC_RULE_VERSION,
            ruleset_schema_version: crate::rules::RULESET_SCHEMA_VERSION,
            ruleset_revision: crate::rules::BUILTIN_RULESET_REVISION,
            semantics: crate::rules::CPYTHON_SOURCE_BACKED_PYC_TRASH_SEMANTICS.into(),
            semantics_digest: crate::rules::CPYTHON_SOURCE_BACKED_PYC_TRASH_SEMANTICS_DIGEST.into(),
            selected_root: NativePath::unix_fixture("/fixture"),
            exclusions: vec![],
            target: RuleWitnessRecord {
                path: NativePath::unix_fixture("/fixture/pkg/__pycache__/module.cpython-39.pyc"),
                device: 1,
                inode: 2,
                kind: "file".into(),
                logical_bytes: 12,
                modified: NativeTime {
                    before_unix_epoch: false,
                    seconds: 1,
                    nanoseconds: 0,
                },
                changed: NativeTime {
                    before_unix_epoch: false,
                    seconds: 1,
                    nanoseconds: 0,
                },
                created: NativeTime {
                    before_unix_epoch: false,
                    seconds: 1,
                    nanoseconds: 0,
                },
                uid: 1,
                gid: 1,
                mode: 0o100600,
                nlink: 1,
                flags: 0,
            },
            source: RuleWitnessRecord {
                path: NativePath::unix_fixture("/fixture/pkg/module.py"),
                device: 1,
                inode: 3,
                kind: "file".into(),
                logical_bytes: 6,
                modified: NativeTime {
                    before_unix_epoch: false,
                    seconds: 1,
                    nanoseconds: 0,
                },
                changed: NativeTime {
                    before_unix_epoch: false,
                    seconds: 1,
                    nanoseconds: 0,
                },
                created: NativeTime {
                    before_unix_epoch: false,
                    seconds: 1,
                    nanoseconds: 0,
                },
                uid: 1,
                gid: 1,
                mode: 0o100600,
                nlink: 1,
                flags: 0,
            },
            root: RuleWitnessRecord {
                path: NativePath::unix_fixture("/fixture"),
                device: 1,
                inode: 1,
                kind: "directory".into(),
                logical_bytes: 0,
                modified: NativeTime {
                    before_unix_epoch: false,
                    seconds: 1,
                    nanoseconds: 0,
                },
                changed: NativeTime {
                    before_unix_epoch: false,
                    seconds: 1,
                    nanoseconds: 0,
                },
                created: NativeTime {
                    before_unix_epoch: false,
                    seconds: 1,
                    nanoseconds: 0,
                },
                uid: 1,
                gid: 1,
                mode: 0o040700,
                nlink: 1,
                flags: 0,
            },
            target_ancestors: vec![
                RuleWitnessRecord {
                    path: NativePath::unix_fixture("/fixture/pkg"),
                    device: 1,
                    inode: 4,
                    kind: "directory".into(),
                    logical_bytes: 0,
                    modified: NativeTime {
                        before_unix_epoch: false,
                        seconds: 1,
                        nanoseconds: 0,
                    },
                    changed: NativeTime {
                        before_unix_epoch: false,
                        seconds: 1,
                        nanoseconds: 0,
                    },
                    created: NativeTime {
                        before_unix_epoch: false,
                        seconds: 1,
                        nanoseconds: 0,
                    },
                    uid: 1,
                    gid: 1,
                    mode: 0o040700,
                    nlink: 1,
                    flags: 0,
                },
                RuleWitnessRecord {
                    path: NativePath::unix_fixture("/fixture/pkg/__pycache__"),
                    device: 1,
                    inode: 5,
                    kind: "directory".into(),
                    logical_bytes: 0,
                    modified: NativeTime {
                        before_unix_epoch: false,
                        seconds: 1,
                        nanoseconds: 0,
                    },
                    changed: NativeTime {
                        before_unix_epoch: false,
                        seconds: 1,
                        nanoseconds: 0,
                    },
                    created: NativeTime {
                        before_unix_epoch: false,
                        seconds: 1,
                        nanoseconds: 0,
                    },
                    uid: 1,
                    gid: 1,
                    mode: 0o040700,
                    nlink: 1,
                    flags: 0,
                },
            ],
            source_ancestors: vec![RuleWitnessRecord {
                path: NativePath::unix_fixture("/fixture/pkg"),
                device: 1,
                inode: 4,
                kind: "directory".into(),
                logical_bytes: 0,
                modified: NativeTime {
                    before_unix_epoch: false,
                    seconds: 1,
                    nanoseconds: 0,
                },
                changed: NativeTime {
                    before_unix_epoch: false,
                    seconds: 1,
                    nanoseconds: 0,
                },
                created: NativeTime {
                    before_unix_epoch: false,
                    seconds: 1,
                    nanoseconds: 0,
                },
                uid: 1,
                gid: 1,
                mode: 0o040700,
                nlink: 1,
                flags: 0,
            }],
            warnings: vec!["metadata-only".into()],
        });
        value.validate().unwrap();
        let mut missing = value.clone();
        missing.items[0].rule_binding = None;
        assert!(missing.validate().is_err());
        let mut legacy = value;
        legacy.schema_version = LEGACY_SCHEMA_VERSION;
        legacy.plan_schema_version = LEGACY_PLAN_SCHEMA_VERSION;
        legacy.rules_version = LEGACY_RULES_VERSION;
        assert!(legacy.validate().is_err());
    }

    #[test]
    fn rejects_tampered_rule_binding_tuple_fields() {
        let mut value = record();
        value.schema_version = SCHEMA_VERSION;
        value.plan_schema_version = RULE_BOUND_PLAN_SCHEMA_VERSION;
        value.rules_version = RULE_BOUND_RULES_VERSION;
        value.items[0].path =
            NativePath::unix_fixture("/fixture/pkg/__pycache__/module.cpython-39.pyc");
        value.items[0].logical_bytes = 12;
        value.items[0].rule_binding = Some(RuleBindingRecord {
            schema_version: 1,
            rule_id: crate::rules::CPYTHON_SOURCE_BACKED_PYC_RULE_ID.into(),
            rule_version: crate::rules::CPYTHON_SOURCE_BACKED_PYC_RULE_VERSION,
            ruleset_schema_version: crate::rules::RULESET_SCHEMA_VERSION,
            ruleset_revision: crate::rules::BUILTIN_RULESET_REVISION,
            semantics: crate::rules::CPYTHON_SOURCE_BACKED_PYC_TRASH_SEMANTICS.into(),
            semantics_digest: crate::rules::CPYTHON_SOURCE_BACKED_PYC_TRASH_SEMANTICS_DIGEST.into(),
            selected_root: NativePath::unix_fixture("/fixture"),
            exclusions: vec![NativePath::unix_fixture("/fixture/pkg/ignore")],
            target: RuleWitnessRecord {
                path: NativePath::unix_fixture("/fixture/pkg/__pycache__/module.cpython-39.pyc"),
                device: 1,
                inode: 2,
                kind: "file".into(),
                logical_bytes: 12,
                modified: NativeTime::from_system_time(UNIX_EPOCH),
                changed: NativeTime::from_system_time(UNIX_EPOCH),
                created: NativeTime::from_system_time(UNIX_EPOCH),
                uid: 1,
                gid: 1,
                mode: 0o100600,
                nlink: 1,
                flags: 0,
            },
            source: RuleWitnessRecord {
                path: NativePath::unix_fixture("/fixture/pkg/module.py"),
                device: 1,
                inode: 3,
                kind: "file".into(),
                logical_bytes: 6,
                modified: NativeTime::from_system_time(UNIX_EPOCH),
                changed: NativeTime::from_system_time(UNIX_EPOCH),
                created: NativeTime::from_system_time(UNIX_EPOCH),
                uid: 1,
                gid: 1,
                mode: 0o100600,
                nlink: 1,
                flags: 0,
            },
            root: RuleWitnessRecord {
                path: NativePath::unix_fixture("/fixture"),
                device: 1,
                inode: 1,
                kind: "directory".into(),
                logical_bytes: 0,
                modified: NativeTime::from_system_time(UNIX_EPOCH),
                changed: NativeTime::from_system_time(UNIX_EPOCH),
                created: NativeTime::from_system_time(UNIX_EPOCH),
                uid: 1,
                gid: 1,
                mode: 0o040700,
                nlink: 1,
                flags: 0,
            },
            target_ancestors: vec![
                RuleWitnessRecord {
                    path: NativePath::unix_fixture("/fixture/pkg"),
                    device: 1,
                    inode: 4,
                    kind: "directory".into(),
                    logical_bytes: 0,
                    modified: NativeTime::from_system_time(UNIX_EPOCH),
                    changed: NativeTime::from_system_time(UNIX_EPOCH),
                    created: NativeTime::from_system_time(UNIX_EPOCH),
                    uid: 1,
                    gid: 1,
                    mode: 0o040700,
                    nlink: 1,
                    flags: 0,
                },
                RuleWitnessRecord {
                    path: NativePath::unix_fixture("/fixture/pkg/__pycache__"),
                    device: 1,
                    inode: 5,
                    kind: "directory".into(),
                    logical_bytes: 0,
                    modified: NativeTime::from_system_time(UNIX_EPOCH),
                    changed: NativeTime::from_system_time(UNIX_EPOCH),
                    created: NativeTime::from_system_time(UNIX_EPOCH),
                    uid: 1,
                    gid: 1,
                    mode: 0o040700,
                    nlink: 1,
                    flags: 0,
                },
            ],
            source_ancestors: vec![RuleWitnessRecord {
                path: NativePath::unix_fixture("/fixture/pkg"),
                device: 1,
                inode: 4,
                kind: "directory".into(),
                logical_bytes: 0,
                modified: NativeTime::from_system_time(UNIX_EPOCH),
                changed: NativeTime::from_system_time(UNIX_EPOCH),
                created: NativeTime::from_system_time(UNIX_EPOCH),
                uid: 1,
                gid: 1,
                mode: 0o040700,
                nlink: 1,
                flags: 0,
            }],
            warnings: vec!["metadata-only".into()],
        });
        value.validate().unwrap();
        let mut historical = value.clone();
        historical.items[0]
            .rule_binding
            .as_mut()
            .unwrap()
            .ruleset_revision = 2;
        historical.validate().unwrap();
        let mut javac = value.clone();
        javac.items[0].path = NativePath::unix_fixture("/fixture/pkg/Foo.class");
        javac.items[0].rule_binding.as_mut().unwrap().rule_id =
            crate::rules::JAVAC_SOURCE_BACKED_CLASS_RULE_ID.into();
        let binding = javac.items[0].rule_binding.as_mut().unwrap();
        binding.rule_version = crate::rules::JAVAC_SOURCE_BACKED_CLASS_RULE_VERSION;
        binding.ruleset_revision = crate::rules::BUILTIN_RULESET_REVISION;
        binding.semantics = crate::rules::JAVAC_SOURCE_BACKED_CLASS_TRASH_SEMANTICS.into();
        binding.semantics_digest =
            crate::rules::JAVAC_SOURCE_BACKED_CLASS_TRASH_SEMANTICS_DIGEST.into();
        binding.target.path = NativePath::unix_fixture("/fixture/pkg/Foo.class");
        binding.source.path = NativePath::unix_fixture("/fixture/pkg/Foo.java");
        binding.target_ancestors = vec![RuleWitnessRecord {
            path: NativePath::unix_fixture("/fixture/pkg"),
            device: 1,
            inode: 4,
            kind: "directory".into(),
            logical_bytes: 0,
            modified: NativeTime::from_system_time(UNIX_EPOCH),
            changed: NativeTime::from_system_time(UNIX_EPOCH),
            created: NativeTime::from_system_time(UNIX_EPOCH),
            uid: 1,
            gid: 1,
            mode: 0o040700,
            nlink: 1,
            flags: 0,
        }];
        binding.source_ancestors = vec![RuleWitnessRecord {
            path: NativePath::unix_fixture("/fixture/pkg"),
            device: 1,
            inode: 4,
            kind: "directory".into(),
            logical_bytes: 0,
            modified: NativeTime::from_system_time(UNIX_EPOCH),
            changed: NativeTime::from_system_time(UNIX_EPOCH),
            created: NativeTime::from_system_time(UNIX_EPOCH),
            uid: 1,
            gid: 1,
            mode: 0o040700,
            nlink: 1,
            flags: 0,
        }];
        javac.validate().unwrap();

        let mut tampered = value.clone();
        tampered.items[0].rule_binding.as_mut().unwrap().rule_id = "evil".into();
        assert!(tampered.validate().is_err());

        tampered = value.clone();
        tampered.items[0]
            .rule_binding
            .as_mut()
            .unwrap()
            .rule_version += 1;
        assert!(tampered.validate().is_err());

        tampered = value.clone();
        tampered.items[0]
            .rule_binding
            .as_mut()
            .unwrap()
            .ruleset_revision += 1;
        assert!(tampered.validate().is_err());

        tampered = value.clone();
        tampered.items[0]
            .rule_binding
            .as_mut()
            .unwrap()
            .semantics_digest = "sha256:forged".into();
        assert!(tampered.validate().is_err());

        tampered = value.clone();
        tampered.items[0].rule_binding.as_mut().unwrap().source.path =
            NativePath::unix_fixture("/fixture/pkg/other.py");
        assert!(tampered.validate().is_err());

        tampered = value.clone();
        tampered.items[0]
            .rule_binding
            .as_mut()
            .unwrap()
            .target_ancestors
            .pop();
        assert!(tampered.validate().is_err());

        tampered = value.clone();
        tampered.items[0].rule_binding.as_mut().unwrap().exclusions =
            vec![NativePath::unix_fixture("/outside")];
        assert!(tampered.validate().is_err());

        tampered = value.clone();
        tampered.items[0].rule_binding.as_mut().unwrap().target.kind = "directory".into();
        assert!(tampered.validate().is_err());

        tampered = value.clone();
        tampered.items[0]
            .rule_binding
            .as_mut()
            .unwrap()
            .target
            .nlink = 2;
        assert!(tampered.validate().is_err());

        tampered = value.clone();
        tampered.items[0]
            .rule_binding
            .as_mut()
            .unwrap()
            .target
            .flags = SF_DATALESS;
        assert!(tampered.validate().is_err());

        tampered = value.clone();
        tampered.items[0].rule_binding.as_mut().unwrap().target.mode = 0o040700;
        assert!(tampered.validate().is_err());
    }

    #[test]
    fn evidence_preserves_pre_epoch_timestamps_without_fabricated_defaults() {
        let nanoseconds = if cfg!(windows) { 100 } else { 1 };
        let before_epoch = UNIX_EPOCH - std::time::Duration::from_nanos(nanoseconds);
        assert!(before_epoch < UNIX_EPOCH);
        let time = NativeTime::from_system_time(before_epoch);
        assert!(time.before_unix_epoch);
        assert_eq!(time.seconds, 0);
        assert_eq!(u64::from(time.nanoseconds), nanoseconds);
        let restored: NativeTime =
            serde_json::from_slice(&serde_json::to_vec(&time).unwrap()).unwrap();
        assert_eq!(restored, time);
        let serialized = serde_json::to_vec(&record()).unwrap();
        let restored: Record = serde_json::from_slice(&serialized).unwrap();
        assert!(restored.items[0].recovery_evidence.is_none());
    }

    #[cfg(windows)]
    #[test]
    fn windows_display_paths_cannot_be_accepted_as_unix_journal_records() {
        let mut value = record();
        value.scope = NativePath::from_path(Path::new(r"C:\fixture"));
        assert_eq!(value.scope.encoding, "display_only");
        assert!(value.validate().is_err());
        let mut value = record();
        value.items[0].path = NativePath::from_path(Path::new(r"C:\fixture\file"));
        assert!(value.validate().is_err());
    }
}
