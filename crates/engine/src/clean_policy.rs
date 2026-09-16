// SPDX-License-Identifier: MPL-2.0

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{
    add_entries, guard_snapshot, list_root_entries, remove_entries, remove_root,
    resolve_config_path, snapshot_for_root,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnixIdentity {
    pub device: u64,
    pub inode: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWirePath {
    pub encoding: String,
    pub bytes_hex: String,
    pub display: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryRecord {
    pub literal_relative_path: NativeWirePath,
    pub entry_identity: UnixEntryIdentity,
    pub created_unix_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnixEntryIdentity {
    pub device: u64,
    pub inode: u64,
    pub kind: EntryKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    File,
    Directory,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootRecord {
    pub root_path: NativeWirePath,
    pub root_identity: UnixIdentity,
    pub created_unix_ms: u64,
    pub entries: Vec<EntryRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyFileState {
    Absent {
        expected_path: PathBuf,
        nearest_existing_parent: Option<PathBuf>,
        nearest_existing_parent_identity: Option<UnixIdentity>,
    },
    Present {
        path: PathBuf,
        identity: UnixIdentity,
        length: u64,
        modified_unix_ms: Option<u64>,
        sha256: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExclusionEntryStatus {
    pub relative_path: PathBuf,
    pub missing_attention: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicySnapshot {
    pub file_state: PolicyFileState,
    pub root: Option<RootRecord>,
    pub effective_exclusions: Vec<PathBuf>,
    pub missing_attention_entries: Vec<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyGuardStatus {
    Unchanged,
    Refused(String),
}

#[derive(Clone, Debug)]
pub struct ConfigPath {
    pub directory: PathBuf,
    pub file: PathBuf,
}

#[cfg(not(target_os = "macos"))]
mod unavailable {
    use super::*;
    use std::{io, path::Path};

    fn unsupported() -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "native clean policy is currently macOS-only",
        )
    }

    pub fn resolve_config_path(_: Option<&Path>) -> io::Result<ConfigPath> {
        Err(unsupported())
    }
    pub fn snapshot_for_root(_: &ConfigPath, _: &Path) -> io::Result<PolicySnapshot> {
        Err(unsupported())
    }
    pub fn guard_snapshot(
        _: &ConfigPath,
        _: &Path,
        _: &PolicySnapshot,
    ) -> io::Result<PolicyGuardStatus> {
        Err(unsupported())
    }
    pub fn list_root_entries(
        _: &ConfigPath,
        _: &Path,
    ) -> io::Result<(PolicySnapshot, Vec<ExclusionEntryStatus>)> {
        Err(unsupported())
    }
    pub fn add_entries(_: &ConfigPath, _: &Path, _: &[PathBuf]) -> io::Result<()> {
        Err(unsupported())
    }
    pub fn remove_entries(_: &ConfigPath, _: &Path, _: &[PathBuf]) -> io::Result<usize> {
        Err(unsupported())
    }
    pub fn remove_root(_: &ConfigPath, _: &Path) -> io::Result<bool> {
        Err(unsupported())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn unsupported_policy_never_reports_empty_success() {
            assert_eq!(
                resolve_config_path(None).unwrap_err().kind(),
                io::ErrorKind::Unsupported
            );
            let config = ConfigPath {
                directory: "unused".into(),
                file: "unused".into(),
            };
            assert_eq!(
                snapshot_for_root(&config, Path::new("unused"))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::Unsupported
            );
            assert_eq!(
                add_entries(&config, Path::new("unused"), &[])
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::Unsupported
            );
            assert_eq!(
                remove_root(&config, Path::new("unused"))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::Unsupported
            );
        }
    }
}

#[cfg(not(target_os = "macos"))]
pub use unavailable::{
    add_entries, guard_snapshot, list_root_entries, remove_entries, remove_root,
    resolve_config_path, snapshot_for_root,
};
