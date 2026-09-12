// SPDX-License-Identifier: MPL-2.0

//! Local audit records, never executable approvals. Interrupted work is unknown.

use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const SCHEMA_VERSION: u32 = 1;
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
    pub created_unix_ms: u64,
    pub items: Vec<ItemRecord>,
}

impl Record {
    pub fn validate(&self) -> io::Result<()> {
        if self.schema_version != SCHEMA_VERSION
            || self.plan_schema_version != 2
            || self.engine_version != 2
            || self.rules_version != 1
            || self.contract != "revalidated_trash_v1"
            || !valid_id(&self.operation_id)
            || self.items.is_empty()
            || self.items.len() > MAX_ITEMS
        {
            return Err(invalid("unsupported or invalid journal record"));
        }
        self.scope.validate()?;
        let mut identities = std::collections::HashSet::new();
        let mut paths = std::collections::HashSet::new();
        for item in &self.items {
            item.path.validate()?;
            if let Some(destination) = &item.destination {
                destination.validate()?;
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
            schema_version: SCHEMA_VERSION,
            plan_schema_version: 2,
            engine_version: 2,
            rules_version: 1,
            operation_id: "a-1".into(),
            contract: "revalidated_trash_v1".into(),
            scope: NativePath::unix_fixture("/fixture"),
            created_unix_ms: 1,
            items: vec![ItemRecord {
                path: NativePath::unix_fixture("/fixture/file"),
                device: 1,
                inode: 2,
                logical_bytes: 5,
                state: ItemState::Started,
                reason: None,
                destination: None,
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
        value.schema_version += 1;
        assert!(value.validate().is_err());
        value.schema_version = SCHEMA_VERSION;
        value.items.push(value.items[0].clone());
        assert!(value.validate().is_err());
        value.items.pop();
        value.items[0].state = ItemState::Succeeded;
        assert!(value.validate().is_err());
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
