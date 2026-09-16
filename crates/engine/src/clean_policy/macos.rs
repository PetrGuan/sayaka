// SPDX-License-Identifier: MPL-2.0

use super::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::os::fd::OwnedFd;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const POLICY_FILE_NAME: &str = "exclusions-v1.json";
const POLICY_KIND: &str = "sayaka_clean_exclusions";
const POLICY_SCHEMA_VERSION: u32 = 1;
const MAX_POLICY_BYTES: u64 = 64 * 1024;
const MAX_ROOTS: usize = 512;
const MAX_ENTRIES_PER_ROOT: usize = 512;
const POLICY_LOCK_NAME: &str = ".exclusions-v1.lock";

#[cfg(unix)]
use rustix::fs::{AtFlags, Mode, OFlags};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    schema_version: u32,
    kind: String,
    roots: Vec<RootRecord>,
}

pub fn resolve_config_path(config_dir_override: Option<&Path>) -> io::Result<ConfigPath> {
    if let Some(path) = config_dir_override {
        return Ok(ConfigPath {
            directory: normalize_abs_dir(path)?,
            file: normalize_abs_dir(path)?.join(POLICY_FILE_NAME),
        });
    }
    if let Some(path) = std::env::var_os("SAYAKA_CONFIG_DIR").filter(|value| !value.is_empty()) {
        let directory = normalize_abs_dir(Path::new(&path))?;
        return Ok(ConfigPath {
            file: directory.join(POLICY_FILE_NAME),
            directory,
        });
    }
    if let Some(path) = std::env::var_os("XDG_CONFIG_HOME").filter(|value| !value.is_empty()) {
        let directory = normalize_abs_dir(Path::new(&path))?.join("sayaka");
        return Ok(ConfigPath {
            file: directory.join(POLICY_FILE_NAME),
            directory,
        });
    }
    let home = std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "HOME is unavailable"))?;
    let home = normalize_abs_dir(Path::new(&home))?;
    let directory = home.join(".config/sayaka");
    Ok(ConfigPath {
        file: directory.join(POLICY_FILE_NAME),
        directory,
    })
}

pub fn snapshot_for_root(config: &ConfigPath, root: &Path) -> io::Result<PolicySnapshot> {
    let root = normalize_existing_root(root)?;
    let root_identity = path_identity(&root)?;
    let load = load_policy_readonly(config)?;
    match load {
        LoadedPolicy::Absent(state) => Ok(PolicySnapshot {
            file_state: state,
            root: None,
            effective_exclusions: Vec::new(),
            missing_attention_entries: Vec::new(),
        }),
        LoadedPolicy::Present { file_state, policy } => {
            validate_policy(&policy)?;
            let selected = select_root_for_execution(&policy.roots, &root, root_identity)?;
            if let Some(record) = selected {
                let (effective, missing) = evaluate_entries(&record, &root, &root_identity)?;
                return Ok(PolicySnapshot {
                    file_state,
                    root: Some(record),
                    effective_exclusions: effective,
                    missing_attention_entries: missing,
                });
            }
            Ok(PolicySnapshot {
                file_state,
                root: None,
                effective_exclusions: Vec::new(),
                missing_attention_entries: Vec::new(),
            })
        }
    }
}

pub fn guard_snapshot(
    config: &ConfigPath,
    root: &Path,
    expected: &PolicySnapshot,
) -> io::Result<PolicyGuardStatus> {
    let current = snapshot_for_root(config, root)?;
    if current == *expected {
        return Ok(PolicyGuardStatus::Unchanged);
    }
    Ok(PolicyGuardStatus::Refused(policy_change_reason(
        expected, &current,
    )))
}

pub fn list_root_entries(
    config: &ConfigPath,
    root: &Path,
) -> io::Result<(PolicySnapshot, Vec<ExclusionEntryStatus>)> {
    let root_abs = normalize_root_like_input(root)?;
    let load = load_policy_readonly(config)?;
    let result = match load {
        LoadedPolicy::Absent(state) => PolicySnapshot {
            file_state: state,
            root: None,
            effective_exclusions: Vec::new(),
            missing_attention_entries: Vec::new(),
        },
        LoadedPolicy::Present { file_state, policy } => {
            validate_policy(&policy)?;
            let selected = select_root_for_management(&policy.roots, &root_abs)?;
            match selected {
                Some(record) => {
                    let root_identity = fs::symlink_metadata(&root_abs)
                        .ok()
                        .and_then(identity_from_meta);
                    let (effective, missing) = if let Some(identity) = root_identity {
                        evaluate_entries(&record, &root_abs, &identity)?
                    } else {
                        (
                            Vec::new(),
                            record
                                .entries
                                .iter()
                                .filter_map(|entry| {
                                    decode_relative(&entry.literal_relative_path)
                                        .ok()
                                        .map(|p| root_abs.join(p))
                                })
                                .collect(),
                        )
                    };
                    PolicySnapshot {
                        file_state,
                        root: Some(record),
                        effective_exclusions: effective,
                        missing_attention_entries: missing,
                    }
                }
                None => PolicySnapshot {
                    file_state,
                    root: None,
                    effective_exclusions: Vec::new(),
                    missing_attention_entries: Vec::new(),
                },
            }
        }
    };
    let statuses = result
        .root
        .as_ref()
        .map(|record| {
            record
                .entries
                .iter()
                .filter_map(|entry| {
                    decode_relative(&entry.literal_relative_path)
                        .ok()
                        .map(|relative| (entry, relative))
                })
                .map(|(entry, relative)| ExclusionEntryStatus {
                    relative_path: relative.clone(),
                    missing_attention: match inspect_anchored_entry(&root_abs, &relative, false) {
                        Ok(AnchoredEntryState::Present(observed)) => {
                            UnixEntryIdentity {
                                device: observed.device,
                                inode: observed.inode,
                                kind: observed.kind,
                            } != entry.entry_identity
                        }
                        Ok(AnchoredEntryState::Missing | AnchoredEntryState::NeedsAttention) => {
                            true
                        }
                        Err(_) => true,
                    },
                })
                .collect()
        })
        .unwrap_or_default();
    Ok((result, statuses))
}

pub fn add_entries(config: &ConfigPath, root: &Path, entries: &[PathBuf]) -> io::Result<()> {
    if entries.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "at least one path is required",
        ));
    }
    let root = normalize_existing_root(root)?;
    let root_identity = path_identity(&root)?;
    update_policy(config, |policy| {
        let root_record = ensure_root_record(policy, &root, root_identity)?;
        let mut existing = BTreeMap::<Vec<u8>, usize>::new();
        for (index, entry) in root_record.entries.iter().enumerate() {
            existing.insert(decode_relative_bytes(&entry.literal_relative_path)?, index);
        }
        for value in entries {
            let absolute = normalize_entry_inside_root(&root, value)?;
            let relative = absolute.strip_prefix(&root).map_err(io::Error::other)?;
            let observation = match inspect_anchored_entry(&root, relative, true)? {
                AnchoredEntryState::Present(observation) => observation,
                AnchoredEntryState::Missing | AnchoredEntryState::NeedsAttention => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "entry must be an existing physical path within root",
                    ));
                }
            };
            if matches!(observation.kind, EntryKind::File) && observation.nlink != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "hardlink ambiguity is not supported",
                ));
            }
            let relative_bytes = relative.as_os_str().as_bytes().to_vec();
            if existing.contains_key(&relative_bytes) {
                continue;
            }
            root_record.entries.push(EntryRecord {
                literal_relative_path: encode_relative(relative)?,
                entry_identity: UnixEntryIdentity {
                    device: observation.device,
                    inode: observation.inode,
                    kind: observation.kind,
                },
                created_unix_ms: now_ms()?,
            });
            existing.insert(relative_bytes, root_record.entries.len() - 1);
        }
        normalize_entries(root_record)
    })
}

pub fn remove_entries(config: &ConfigPath, root: &Path, entries: &[PathBuf]) -> io::Result<usize> {
    if entries.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "at least one path is required",
        ));
    }
    let root = normalize_root_like_input(root)?;
    let keys: BTreeSet<Vec<u8>> = entries
        .iter()
        .map(|entry| normalize_remove_entry(&root, entry))
        .collect::<io::Result<Vec<_>>>()?
        .into_iter()
        .collect();
    let mut removed = 0usize;
    update_policy(config, |policy| {
        if let Some(record) = find_root_record_mut(policy, &root)? {
            let before = record.entries.len();
            record.entries.retain(|entry| {
                let bytes = decode_relative_bytes(&entry.literal_relative_path).unwrap_or_default();
                !keys.contains(&bytes)
            });
            removed = before.saturating_sub(record.entries.len());
        }
        Ok(())
    })?;
    Ok(removed)
}

pub fn remove_root(config: &ConfigPath, root: &Path) -> io::Result<bool> {
    let root = normalize_root_like_input(root)?;
    let mut removed = false;
    update_policy(config, |policy| {
        let encoded = encode_absolute(&root)?;
        let before = policy.roots.len();
        policy.roots.retain(|record| record.root_path != encoded);
        removed = before != policy.roots.len();
        Ok(())
    })?;
    Ok(removed)
}

fn evaluate_entries(
    root: &RootRecord,
    root_path: &Path,
    identity: &UnixIdentity,
) -> io::Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    if root.root_identity != *identity {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "stored root identity does not match current root identity",
        ));
    }
    let mut effective = Vec::new();
    let mut missing = Vec::new();
    for entry in &root.entries {
        let relative = decode_relative(&entry.literal_relative_path)?;
        let absolute = root_path.join(&relative);
        match inspect_anchored_entry(root_path, &relative, false)? {
            AnchoredEntryState::Present(observation) => {
                let observed = UnixEntryIdentity {
                    device: observation.device,
                    inode: observation.inode,
                    kind: observation.kind,
                };
                if observed == entry.entry_identity {
                    effective.push(absolute);
                } else {
                    missing.push(absolute);
                }
            }
            AnchoredEntryState::Missing | AnchoredEntryState::NeedsAttention => {
                missing.push(absolute);
            }
        }
    }
    Ok((effective, missing))
}

fn validate_policy(policy: &PolicyFile) -> io::Result<()> {
    if policy.schema_version != POLICY_SCHEMA_VERSION || policy.kind != POLICY_KIND {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported clean policy schema",
        ));
    }
    if policy.roots.len() > MAX_ROOTS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "too many policy roots",
        ));
    }
    let mut identity_seen = BTreeSet::new();
    let mut path_seen = BTreeSet::new();
    for root in &policy.roots {
        if root.entries.len() > MAX_ENTRIES_PER_ROOT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "too many exclusions for one root",
            ));
        }
        let root_path = decode_absolute(&root.root_path)?;
        if !path_seen.insert(root_path.as_os_str().as_bytes().to_vec()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "duplicate root path record",
            ));
        }
        if !identity_seen.insert(root.root_identity) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "duplicate root identity record",
            ));
        }
        let mut entry_seen = BTreeSet::new();
        for entry in &root.entries {
            let key = decode_relative_bytes(&entry.literal_relative_path)?;
            if !entry_seen.insert(key) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "duplicate exclusion entry",
                ));
            }
        }
    }
    Ok(())
}

fn normalize_entries(root: &mut RootRecord) -> io::Result<()> {
    let mut by_key = BTreeMap::<Vec<u8>, EntryRecord>::new();
    for entry in root.entries.drain(..) {
        by_key.insert(decode_relative_bytes(&entry.literal_relative_path)?, entry);
    }
    root.entries = by_key.into_values().collect();
    Ok(())
}

enum LoadedPolicy {
    Absent(PolicyFileState),
    Present {
        file_state: PolicyFileState,
        policy: PolicyFile,
    },
}

fn load_policy_readonly(config: &ConfigPath) -> io::Result<LoadedPolicy> {
    let path = &config.file;
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let (parent, identity) = nearest_existing_parent(path)?;
            Ok(LoadedPolicy::Absent(PolicyFileState::Absent {
                expected_path: path.clone(),
                nearest_existing_parent: parent,
                nearest_existing_parent_identity: identity,
            }))
        }
        Err(error) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("cannot inspect clean policy file: {error}"),
        )),
        Ok(meta) => {
            verify_private_regular_file(path, &meta)?;
            let bytes = fs::read(path)?;
            if u64::try_from(bytes.len()).map_err(io::Error::other)? > MAX_POLICY_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "clean policy exceeds 64 KiB",
                ));
            }
            let policy: PolicyFile = serde_json::from_slice(&bytes)?;
            let hash = sha256_hex(&bytes);
            let file_state = PolicyFileState::Present {
                path: path.clone(),
                identity: UnixIdentity {
                    device: meta.dev(),
                    inode: meta.ino(),
                },
                length: meta.len(),
                modified_unix_ms: system_time_ms(meta.modified().ok()),
                sha256: hash,
            };
            Ok(LoadedPolicy::Present { file_state, policy })
        }
    }
}

fn update_policy(
    config: &ConfigPath,
    updater: impl FnOnce(&mut PolicyFile) -> io::Result<()>,
) -> io::Result<()> {
    ensure_private_config_dir(&config.directory)?;
    let lock = acquire_lock(config)?;
    let loaded = load_policy_readonly(config)?;
    let mut policy = match &loaded {
        LoadedPolicy::Absent(_) => PolicyFile {
            schema_version: POLICY_SCHEMA_VERSION,
            kind: POLICY_KIND.to_owned(),
            roots: Vec::new(),
        },
        LoadedPolicy::Present { policy, .. } => policy.clone(),
    };
    updater(&mut policy)?;
    validate_policy(&policy)?;
    write_policy_atomic(config, &policy, &loaded)?;
    drop(lock);
    Ok(())
}

fn write_policy_atomic(
    config: &ConfigPath,
    policy: &PolicyFile,
    loaded: &LoadedPolicy,
) -> io::Result<()> {
    let bytes = serde_json::to_vec_pretty(policy)?;
    if u64::try_from(bytes.len()).map_err(io::Error::other)? > MAX_POLICY_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "clean policy exceeds 64 KiB",
        ));
    }
    let stage = config.directory.join(".exclusions-v1.json.next");
    if stage.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "stale clean policy staging file exists",
        ));
    }
    let mut stage_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&stage)?;
    use std::io::Write;
    stage_file.write_all(&bytes)?;
    stage_file.sync_all()?;
    let meta = fs::symlink_metadata(&stage)?;
    verify_private_regular_file(&stage, &meta)?;
    ensure_expected_observed_state(config, loaded)?;
    fs::rename(&stage, &config.file)?;
    fs::set_permissions(&config.file, fs::Permissions::from_mode(0o600))?;
    let written = fs::read(&config.file)?;
    if sha256_hex(&written) != sha256_hex(&bytes) {
        return Err(io::Error::other("clean policy readback hash mismatch"));
    }
    Ok(())
}

fn ensure_expected_observed_state(config: &ConfigPath, loaded: &LoadedPolicy) -> io::Result<()> {
    match loaded {
        LoadedPolicy::Absent(state) => match fs::symlink_metadata(&config.file) {
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "clean policy changed while updating (now present)",
            )),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if let PolicyFileState::Absent {
                    nearest_existing_parent: expected_parent,
                    nearest_existing_parent_identity: expected_identity,
                    ..
                } = state
                {
                    let (current_parent, current_identity) = nearest_existing_parent(&config.file)?;
                    if &current_parent != expected_parent || &current_identity != expected_identity
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "clean policy parent changed while updating",
                        ));
                    }
                }
                Ok(())
            }
            Err(error) => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("cannot inspect clean policy before publish: {error}"),
            )),
        },
        LoadedPolicy::Present { file_state, .. } => {
            let meta = fs::symlink_metadata(&config.file)?;
            verify_private_regular_file(&config.file, &meta)?;
            let bytes = fs::read(&config.file)?;
            let current_hash = sha256_hex(&bytes);
            match file_state {
                PolicyFileState::Present {
                    identity,
                    length,
                    sha256,
                    ..
                } => {
                    if meta.dev() != identity.device
                        || meta.ino() != identity.inode
                        || meta.len() != *length
                        || current_hash != *sha256
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            "clean policy changed while updating",
                        ));
                    }
                    Ok(())
                }
                PolicyFileState::Absent { .. } => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected absent state for present policy",
                )),
            }
        }
    }
}

fn ensure_private_config_dir(path: &Path) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "config directory has no parent",
        )
    })?;
    if !parent.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "config parent does not exist",
        ));
    }
    if !path.exists() {
        fs::create_dir(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    let meta = fs::symlink_metadata(path)?;
    if !meta.file_type().is_dir() || meta.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "config directory must be a private directory",
        ));
    }
    if meta.uid() != rustix::process::geteuid().as_raw() || meta.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "config directory must be 0700 and owned by current user",
        ));
    }
    Ok(())
}

fn acquire_lock(config: &ConfigPath) -> io::Result<fs::File> {
    let path = config.directory.join(POLICY_LOCK_NAME);
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&path)?;
    let meta = lock.metadata()?;
    verify_private_regular_file(&path, &meta)?;
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(
        |error| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                format!("clean policy lock busy: {error}"),
            )
        },
    )?;
    Ok(lock)
}

fn verify_private_regular_file(path: &Path, meta: &fs::Metadata) -> io::Result<()> {
    if !meta.file_type().is_file() || meta.file_type().is_symlink() || meta.nlink() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "clean policy must be a private regular file",
        ));
    }
    if meta.uid() != rustix::process::geteuid().as_raw() || meta.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "clean policy must be 0600 and owned by current user",
        ));
    }
    for ancestor in path.ancestors() {
        let meta = fs::symlink_metadata(ancestor)?;
        if meta.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "config path must not traverse symlinks",
            ));
        }
    }
    Ok(())
}

fn find_root_record_mut<'a>(
    policy: &'a mut PolicyFile,
    root: &Path,
) -> io::Result<Option<&'a mut RootRecord>> {
    let encoded = encode_absolute(root)?;
    Ok(policy
        .roots
        .iter_mut()
        .find(|record| record.root_path == encoded))
}

fn ensure_root_record<'a>(
    policy: &'a mut PolicyFile,
    root: &Path,
    identity: UnixIdentity,
) -> io::Result<&'a mut RootRecord> {
    let encoded = encode_absolute(root)?;
    let matching: Vec<usize> = policy
        .roots
        .iter()
        .enumerate()
        .filter_map(|(index, record)| (record.root_identity == identity).then_some(index))
        .collect();
    if let Some(index) = matching.first().copied() {
        if matching.len() > 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ambiguous root records for same identity",
            ));
        }
        let record = &mut policy.roots[index];
        record.root_path = encoded;
        return Ok(record);
    }
    if policy
        .roots
        .iter()
        .any(|record| record.root_path == encoded)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "stored root path exists with different identity",
        ));
    }
    policy.roots.push(RootRecord {
        root_path: encoded,
        root_identity: identity,
        created_unix_ms: now_ms()?,
        entries: Vec::new(),
    });
    policy
        .roots
        .last_mut()
        .ok_or_else(|| io::Error::other("failed to create root record"))
}

fn select_root_for_execution(
    roots: &[RootRecord],
    root: &Path,
    identity: UnixIdentity,
) -> io::Result<Option<RootRecord>> {
    let mut by_identity = roots
        .iter()
        .filter(|record| record.root_identity == identity);
    if let Some(record) = by_identity.next() {
        if by_identity.next().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ambiguous clean policy root identity",
            ));
        }
        return Ok(Some(record.clone()));
    }
    let encoded = encode_absolute(root)?;
    if roots.iter().any(|record| record.root_path == encoded) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "clean policy root record is stale and requires explicit repair",
        ));
    }
    Ok(None)
}

fn select_root_for_management(roots: &[RootRecord], root: &Path) -> io::Result<Option<RootRecord>> {
    let encoded = encode_absolute(root)?;
    Ok(roots
        .iter()
        .find(|record| record.root_path == encoded)
        .cloned())
}

fn normalize_existing_root(root: &Path) -> io::Result<PathBuf> {
    let absolute = normalize_root_like_input(root)?;
    let meta = fs::symlink_metadata(&absolute)?;
    if !meta.file_type().is_dir() || meta.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "root must be an existing physical directory",
        ));
    }
    Ok(absolute)
}

fn normalize_root_like_input(path: &Path) -> io::Result<PathBuf> {
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "parent traversal is not accepted",
        ));
    }
    let absolute = std::path::absolute(path)?;
    if !absolute.is_absolute()
        || absolute.parent().is_none()
        || absolute.as_os_str().as_bytes().contains(&0)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "root must be a non-root absolute path",
        ));
    }
    Ok(absolute)
}

fn normalize_abs_dir(path: &Path) -> io::Result<PathBuf> {
    let absolute = std::path::absolute(path)?;
    if !absolute.is_absolute() || absolute.as_os_str().as_bytes().contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "config directory must be an absolute path",
        ));
    }
    Ok(absolute)
}

#[derive(Debug)]
enum AnchoredEntryState {
    Present(AnchoredEntryObservation),
    Missing,
    NeedsAttention,
}

#[derive(Clone, Copy, Debug)]
struct AnchoredEntryObservation {
    device: u64,
    inode: u64,
    nlink: u64,
    kind: EntryKind,
}

fn normalize_entry_inside_root(root: &Path, value: &Path) -> io::Result<PathBuf> {
    let absolute = std::path::absolute(value)?;
    if absolute
        .components()
        .any(|component| matches!(component, Component::ParentDir))
        || !absolute.starts_with(root)
        || absolute == root
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "entry must be an existing path within root",
        ));
    }
    let relative = absolute.strip_prefix(root).map_err(io::Error::other)?;
    match inspect_anchored_entry(root, relative, true)? {
        AnchoredEntryState::Present(_) => {}
        AnchoredEntryState::Missing | AnchoredEntryState::NeedsAttention => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "entry must be an existing path within root",
            ));
        }
    }
    Ok(absolute)
}

fn normalize_literal_relative(value: &Path) -> io::Result<Vec<u8>> {
    if value.is_absolute() || value.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "entry must be a relative path",
        ));
    }

    if value.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_) | Component::CurDir
        )
    }) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "entry must be a clean relative path",
        ));
    }
    Ok(value.as_os_str().as_bytes().to_vec())
}

fn normalize_remove_entry(root: &Path, entry: &Path) -> io::Result<Vec<u8>> {
    if entry.is_absolute() {
        let absolute = std::path::absolute(entry)?;
        if absolute
            .components()
            .any(|component| matches!(component, Component::ParentDir))
            || !absolute.starts_with(root)
            || absolute == root
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "entry must be within root",
            ));
        }
        let relative = absolute.strip_prefix(root).map_err(io::Error::other)?;
        match inspect_anchored_entry(root, relative, false)? {
            AnchoredEntryState::Present(_) | AnchoredEntryState::Missing => {}
            AnchoredEntryState::NeedsAttention => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "entry must be a physical path within root",
                ));
            }
        }
        return normalize_literal_relative(relative);
    }
    normalize_literal_relative(entry)
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

fn inspect_anchored_entry(
    root: &Path,
    relative: &Path,
    require_exists: bool,
) -> io::Result<AnchoredEntryState> {
    let root_fd = rustix::fs::open(root, directory_flags(), Mode::empty()).map_err(native_io)?;
    let root_meta = fs::symlink_metadata(root)?;
    let root_identity = identity_from_meta(root_meta)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing root identity"))?;
    let observed = rustix::fs::fstat(&root_fd).map_err(native_io)?;
    let observed_identity = UnixIdentity {
        device: u64::from(observed.st_dev.cast_unsigned()),
        inode: observed.st_ino,
    };
    if observed_identity != root_identity {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "root identity changed during policy operation",
        ));
    }
    inspect_anchored_from_fd(root_fd, relative, require_exists)
}

fn inspect_anchored_from_fd(
    root_fd: OwnedFd,
    relative: &Path,
    require_exists: bool,
) -> io::Result<AnchoredEntryState> {
    let mut components = Vec::<&OsStr>::new();
    for component in relative.components() {
        match component {
            Component::Normal(name) => components.push(name),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "entry must be a clean relative path",
                ));
            }
        }
    }
    if components.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "entry must not be the root itself",
        ));
    }
    let mut current = root_fd;
    for (index, name) in components.iter().enumerate() {
        let last = index + 1 == components.len();
        if !last {
            match rustix::fs::openat(&current, *name, directory_flags(), Mode::empty()) {
                Ok(fd) => {
                    current = fd;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    return if require_exists {
                        Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "entry must be an existing path within root",
                        ))
                    } else {
                        Ok(AnchoredEntryState::Missing)
                    };
                }
                Err(_) => return Ok(AnchoredEntryState::NeedsAttention),
            }
            continue;
        }

        let stat = match rustix::fs::statat(&current, *name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return if require_exists {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "entry must be an existing path within root",
                    ))
                } else {
                    Ok(AnchoredEntryState::Missing)
                };
            }
            Err(_) => return Ok(AnchoredEntryState::NeedsAttention),
        };
        let kind = match stat.st_mode & libc::S_IFMT {
            libc::S_IFREG => EntryKind::File,
            libc::S_IFDIR => EntryKind::Directory,
            libc::S_IFLNK => return Ok(AnchoredEntryState::NeedsAttention),
            _ => return Ok(AnchoredEntryState::NeedsAttention),
        };
        return Ok(AnchoredEntryState::Present(AnchoredEntryObservation {
            device: u64::from(stat.st_dev.cast_unsigned()),
            inode: stat.st_ino,
            nlink: u64::from(stat.st_nlink),
            kind,
        }));
    }
    Ok(AnchoredEntryState::Missing)
}

fn native_io(error: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(error.raw_os_error())
}

fn path_identity(path: &Path) -> io::Result<UnixIdentity> {
    let meta = fs::symlink_metadata(path)?;
    identity_from_meta(meta)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing root identity"))
}

fn identity_from_meta(meta: fs::Metadata) -> Option<UnixIdentity> {
    Some(UnixIdentity {
        device: meta.dev(),
        inode: meta.ino(),
    })
}

fn encode_absolute(path: &Path) -> io::Result<NativeWirePath> {
    let bytes = path.as_os_str().as_bytes();
    if !path.is_absolute() || bytes.is_empty() || bytes[0] != b'/' {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path must be absolute",
        ));
    }
    Ok(NativeWirePath {
        encoding: "unix_bytes".into(),
        bytes_hex: encode_hex(bytes),
        display: format!("{:?}", path.as_os_str()),
    })
}

fn encode_relative(path: &Path) -> io::Result<NativeWirePath> {
    let bytes = normalize_literal_relative(path)?;
    Ok(NativeWirePath {
        encoding: "unix_bytes".into(),
        bytes_hex: encode_hex(&bytes),
        display: format!("{:?}", path.as_os_str()),
    })
}

fn decode_absolute(path: &NativeWirePath) -> io::Result<PathBuf> {
    let bytes = decode_wire_bytes(path)?;
    if bytes.first() != Some(&b'/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "root path must be absolute",
        ));
    }
    Ok(PathBuf::from(OsStr::from_bytes(&bytes)))
}

fn decode_relative(path: &NativeWirePath) -> io::Result<PathBuf> {
    let bytes = decode_relative_bytes(path)?;
    Ok(PathBuf::from(OsStr::from_bytes(&bytes)))
}

fn decode_relative_bytes(path: &NativeWirePath) -> io::Result<Vec<u8>> {
    let bytes = decode_wire_bytes(path)?;
    if bytes.is_empty() || bytes.first() == Some(&b'/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "entry path must be relative",
        ));
    }
    if Path::new(OsStr::from_bytes(&bytes))
        .components()
        .any(|component| {
            matches!(
                component,
                Component::ParentDir
                    | Component::RootDir
                    | Component::Prefix(_)
                    | Component::CurDir
            )
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "entry path traversal is not accepted",
        ));
    }
    Ok(bytes)
}

fn decode_wire_bytes(path: &NativeWirePath) -> io::Result<Vec<u8>> {
    if path.encoding != "unix_bytes" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported path encoding",
        ));
    }
    decode_hex(&path.bytes_hex)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid hex path bytes"))
}

fn nearest_existing_parent(path: &Path) -> io::Result<(Option<PathBuf>, Option<UnixIdentity>)> {
    for ancestor in path.ancestors().skip(1) {
        match fs::symlink_metadata(ancestor) {
            Ok(meta) => {
                return Ok((Some(ancestor.to_path_buf()), identity_from_meta(meta)));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        }
    }
    Ok((None, None))
}

fn now_ms() -> io::Result<u64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| io::Error::other("clock before epoch"))?
        .as_millis();
    u64::try_from(millis).map_err(io::Error::other)
}

fn system_time_ms(time: Option<SystemTime>) -> Option<u64> {
    let value = time?;
    let millis = value.duration_since(UNIX_EPOCH).ok()?.as_millis();
    u64::try_from(millis).ok()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut text, "{byte:02x}");
    }
    text
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(text.len() / 2);
    let chars: Vec<_> = text.as_bytes().to_vec();
    for index in (0..chars.len()).step_by(2) {
        let pair = std::str::from_utf8(&chars[index..index + 2]).ok()?;
        bytes.push(u8::from_str_radix(pair, 16).ok()?);
    }
    Some(bytes)
}

fn policy_change_reason(expected: &PolicySnapshot, current: &PolicySnapshot) -> String {
    match (&expected.file_state, &current.file_state) {
        (PolicyFileState::Absent { .. }, PolicyFileState::Present { .. }) => {
            "policy_created_after_approval".to_owned()
        }
        (PolicyFileState::Present { .. }, PolicyFileState::Absent { .. }) => {
            "policy_removed_after_approval".to_owned()
        }
        (
            PolicyFileState::Present {
                sha256: lhs,
                identity: left_identity,
                ..
            },
            PolicyFileState::Present {
                sha256: rhs,
                identity: right_identity,
                ..
            },
        ) if lhs != rhs || left_identity != right_identity => {
            "policy_content_changed_after_approval".to_owned()
        }
        _ => "policy_snapshot_changed_after_approval".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::fs::{FlockOperation, flock};
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::fs::symlink;

    fn fixture() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("sayaka-clean-policy-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .unwrap()
    }

    #[test]
    fn absent_snapshot_does_not_create_config_files() {
        let fixture = fixture();
        let root = fixture.path().join("root");
        fs::create_dir(&root).unwrap();
        let config = ConfigPath {
            directory: fixture.path().join("config"),
            file: fixture.path().join("config/exclusions-v1.json"),
        };
        let snapshot = snapshot_for_root(&config, &root).unwrap();
        assert!(matches!(
            snapshot.file_state,
            PolicyFileState::Absent { .. }
        ));
        assert!(snapshot.effective_exclusions.is_empty());
        assert!(!config.directory.exists());
        assert!(!config.file.exists());
    }

    #[test]
    fn add_and_remove_entries_tracks_missing_attention() {
        let fixture = fixture();
        let root = fixture.path().join("root");
        fs::create_dir(&root).unwrap();
        let keep = root.join("keep");
        fs::create_dir(&keep).unwrap();
        let config = ConfigPath {
            directory: fixture.path().join("config"),
            file: fixture.path().join("config/exclusions-v1.json"),
        };
        add_entries(&config, &root, std::slice::from_ref(&keep)).unwrap();
        let snapshot = snapshot_for_root(&config, &root).unwrap();
        assert_eq!(snapshot.effective_exclusions, vec![keep.clone()]);
        fs::remove_dir(&keep).unwrap();
        let snapshot = snapshot_for_root(&config, &root).unwrap();
        assert!(snapshot.effective_exclusions.is_empty());
        assert_eq!(snapshot.missing_attention_entries, vec![keep.clone()]);
        let removed = remove_entries(&config, &root, &[PathBuf::from("keep")]).unwrap();
        assert_eq!(removed, 1);
        let snapshot = snapshot_for_root(&config, &root).unwrap();
        assert!(snapshot.missing_attention_entries.is_empty());
    }

    #[test]
    fn stale_root_identity_is_fail_closed() {
        let fixture = fixture();
        let root = fixture.path().join("root");
        fs::create_dir(&root).unwrap();
        let keep = root.join("keep.txt");
        fs::write(&keep, b"x").unwrap();
        let config = ConfigPath {
            directory: fixture.path().join("config"),
            file: fixture.path().join("config/exclusions-v1.json"),
        };
        add_entries(&config, &root, std::slice::from_ref(&keep)).unwrap();
        let bytes = fs::read(&config.file).unwrap();
        let mut policy: PolicyFile = serde_json::from_slice(&bytes).unwrap();
        policy.roots[0].root_identity.inode = policy.roots[0].root_identity.inode.saturating_add(1);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&config.file)
            .unwrap();
        file.write_all(&serde_json::to_vec(&policy).unwrap())
            .unwrap();
        let error = snapshot_for_root(&config, &root).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn guard_snapshot_refuses_absent_created_and_present_removed() {
        let fixture = fixture();
        let root = fixture.path().join("root");
        fs::create_dir(&root).unwrap();
        let config = ConfigPath {
            directory: fixture.path().join("config"),
            file: fixture.path().join("config/exclusions-v1.json"),
        };
        let absent = snapshot_for_root(&config, &root).unwrap();
        fs::create_dir(&config.directory).unwrap();
        fs::set_permissions(&config.directory, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(
            &config.file,
            br#"{"schema_version":1,"kind":"sayaka_clean_exclusions","roots":[]}"#,
        )
        .unwrap();
        fs::set_permissions(&config.file, fs::Permissions::from_mode(0o600)).unwrap();
        let created = guard_snapshot(&config, &root, &absent).unwrap();
        assert_eq!(
            created,
            PolicyGuardStatus::Refused("policy_created_after_approval".into())
        );
        let present = snapshot_for_root(&config, &root).unwrap();
        fs::remove_file(&config.file).unwrap();
        let removed = guard_snapshot(&config, &root, &present).unwrap();
        assert_eq!(
            removed,
            PolicyGuardStatus::Refused("policy_removed_after_approval".into())
        );
    }

    #[test]
    fn guard_snapshot_refuses_replaced_corrupt_and_same_inode_edits() {
        let fixture = fixture();
        let root = fixture.path().join("root");
        fs::create_dir(&root).unwrap();
        let keep = root.join("keep");
        fs::create_dir(&keep).unwrap();
        let config = ConfigPath {
            directory: fixture.path().join("config"),
            file: fixture.path().join("config/exclusions-v1.json"),
        };
        add_entries(&config, &root, std::slice::from_ref(&keep)).unwrap();
        let snapshot = snapshot_for_root(&config, &root).unwrap();
        {
            let mut edited = fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .mode(0o600)
                .open(&config.file)
                .unwrap();
            edited
                .write_all(br#"{"schema_version":1,"kind":"sayaka_clean_exclusions","roots":[]}"#)
                .unwrap();
            edited.sync_all().unwrap();
        }
        let edited = guard_snapshot(&config, &root, &snapshot).unwrap();
        assert_eq!(
            edited,
            PolicyGuardStatus::Refused("policy_content_changed_after_approval".into())
        );
        let snapshot = snapshot_for_root(&config, &root).unwrap();
        fs::write(&config.file, b"{not-json").unwrap();
        fs::set_permissions(&config.file, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(guard_snapshot(&config, &root, &snapshot).is_err());
        fs::write(
            &config.file,
            br#"{"schema_version":1,"kind":"sayaka_clean_exclusions","roots":[]}"#,
        )
        .unwrap();
        fs::set_permissions(&config.file, fs::Permissions::from_mode(0o600)).unwrap();
        let replacement = guard_snapshot(&config, &root, &snapshot).unwrap();
        assert_eq!(
            replacement,
            PolicyGuardStatus::Refused("policy_snapshot_changed_after_approval".into())
        );
    }

    #[test]
    fn remove_entries_accepts_absolute_inside_root_and_rejects_outside() {
        let fixture = fixture();
        let root = fixture.path().join("root");
        fs::create_dir(&root).unwrap();
        let keep = root.join("keep");
        fs::create_dir(&keep).unwrap();
        let config = ConfigPath {
            directory: fixture.path().join("config"),
            file: fixture.path().join("config/exclusions-v1.json"),
        };
        add_entries(&config, &root, std::slice::from_ref(&keep)).unwrap();
        let removed = remove_entries(&config, &root, std::slice::from_ref(&keep)).unwrap();
        assert_eq!(removed, 1);
        let error = remove_entries(
            &config,
            &root,
            std::slice::from_ref(&fixture.path().join("outside")),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn remove_root_works_when_root_path_is_stale_or_missing() {
        let fixture = fixture();
        let root = fixture.path().join("root");
        fs::create_dir(&root).unwrap();
        let keep = root.join("keep");
        fs::create_dir(&keep).unwrap();
        let config = ConfigPath {
            directory: fixture.path().join("config"),
            file: fixture.path().join("config/exclusions-v1.json"),
        };
        add_entries(&config, &root, std::slice::from_ref(&keep)).unwrap();
        fs::rename(&root, fixture.path().join("root-renamed")).unwrap();
        assert!(remove_root(&config, &root).unwrap());
    }

    #[test]
    fn update_policy_conflict_preserves_external_bytes_and_reports_conflict() {
        let fixture = fixture();
        let root = fixture.path().join("root");
        fs::create_dir(&root).unwrap();
        let keep = root.join("keep");
        fs::create_dir(&keep).unwrap();
        let config = ConfigPath {
            directory: fixture.path().join("config"),
            file: fixture.path().join("config/exclusions-v1.json"),
        };
        add_entries(&config, &root, std::slice::from_ref(&keep)).unwrap();
        let loaded = load_policy_readonly(&config).unwrap();
        let policy = match &loaded {
            LoadedPolicy::Present { policy, .. } => policy.clone(),
            LoadedPolicy::Absent(_) => panic!("expected present policy"),
        };
        let external = br#"{"schema_version":1,"kind":"sayaka_clean_exclusions","roots":[]}"#;
        fs::write(&config.file, external).unwrap();
        fs::set_permissions(&config.file, fs::Permissions::from_mode(0o600)).unwrap();
        let error = write_policy_atomic(&config, &policy, &loaded).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&config.file).unwrap(), external);
    }

    #[test]
    fn update_policy_lock_and_staging_faults_are_truthful_and_non_destructive() {
        let fixture = fixture();
        let root = fixture.path().join("root");
        fs::create_dir(&root).unwrap();
        let keep = root.join("keep");
        fs::create_dir(&keep).unwrap();
        let config = ConfigPath {
            directory: fixture.path().join("config"),
            file: fixture.path().join("config/exclusions-v1.json"),
        };
        add_entries(&config, &root, std::slice::from_ref(&keep)).unwrap();
        let before = fs::read(&config.file).unwrap();
        let lock_path = config.directory.join(POLICY_LOCK_NAME);
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&lock_path)
            .unwrap();
        flock(&lock, FlockOperation::NonBlockingLockExclusive).unwrap();
        let busy = add_entries(&config, &root, std::slice::from_ref(&keep)).unwrap_err();
        assert_eq!(busy.kind(), io::ErrorKind::WouldBlock);
        drop(lock);
        let stage = config.directory.join(".exclusions-v1.json.next");
        fs::write(&stage, b"stale").unwrap();
        fs::set_permissions(&stage, fs::Permissions::from_mode(0o600)).unwrap();
        let stale = add_entries(&config, &root, std::slice::from_ref(&keep)).unwrap_err();
        assert_eq!(stale.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&config.file).unwrap(), before);
    }

    #[test]
    fn identity_lookup_prevents_empty_policy_on_alias_spelling() {
        let fixture = fixture();
        let root = fixture.path().join("RootAlias");
        fs::create_dir(&root).unwrap();
        let keep = root.join("keep");
        fs::create_dir(&keep).unwrap();
        let config = ConfigPath {
            directory: fixture.path().join("config"),
            file: fixture.path().join("config/exclusions-v1.json"),
        };
        add_entries(&config, &root, std::slice::from_ref(&keep)).unwrap();
        let alias = fixture.path().join("rootalias");
        if let (Ok(a), Ok(b)) = (fs::symlink_metadata(&root), fs::symlink_metadata(&alias))
            && a.dev() == b.dev()
            && a.ino() == b.ino()
        {
            let snapshot = snapshot_for_root(&config, &alias).unwrap();
            assert_eq!(snapshot.effective_exclusions, vec![alias.join("keep")]);
        }
    }

    #[test]
    fn add_entries_rejects_intermediate_symlink_escape() {
        let fixture = fixture();
        let root = fixture.path().join("root");
        let outside = fixture.path().join("outside");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::create_dir(outside.join("keep")).unwrap();
        symlink(&outside, root.join("link_out")).unwrap();
        let config = ConfigPath {
            directory: fixture.path().join("config"),
            file: fixture.path().join("config/exclusions-v1.json"),
        };
        let error = add_entries(
            &config,
            &root,
            std::slice::from_ref(&root.join("link_out/keep")),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn remove_absolute_rejects_intermediate_symlink_escape_and_keeps_policy_bytes() {
        let fixture = fixture();
        let root = fixture.path().join("root");
        let outside = fixture.path().join("outside");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        let keep = root.join("keep");
        fs::create_dir(&keep).unwrap();
        fs::create_dir(outside.join("keep")).unwrap();
        let config = ConfigPath {
            directory: fixture.path().join("config"),
            file: fixture.path().join("config/exclusions-v1.json"),
        };
        add_entries(&config, &root, std::slice::from_ref(&keep)).unwrap();
        let before = fs::read(&config.file).unwrap();
        symlink(&outside, root.join("link_out")).unwrap();
        let error = remove_entries(
            &config,
            &root,
            std::slice::from_ref(&root.join("link_out/keep")),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(before, fs::read(&config.file).unwrap());
    }

    #[test]
    fn snapshot_marks_entry_missing_attention_when_ancestor_becomes_symlink() {
        let fixture = fixture();
        let root = fixture.path().join("root");
        let outside = fixture.path().join("outside");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        let config = ConfigPath {
            directory: fixture.path().join("config"),
            file: fixture.path().join("config/exclusions-v1.json"),
        };
        let container = root.join("cache");
        fs::create_dir(&container).unwrap();
        let keep = container.join("keep");
        fs::create_dir(&keep).unwrap();
        add_entries(&config, &root, std::slice::from_ref(&keep)).unwrap();
        let before = snapshot_for_root(&config, &root).unwrap();
        assert_eq!(before.effective_exclusions, vec![keep.clone()]);
        fs::rename(&container, root.join("cache-real")).unwrap();
        symlink(&outside, &container).unwrap();
        fs::create_dir(outside.join("keep")).unwrap();
        let after = snapshot_for_root(&config, &root).unwrap();
        assert!(after.effective_exclusions.is_empty());
        assert_eq!(after.missing_attention_entries, vec![keep.clone()]);
        let status = guard_snapshot(&config, &root, &before).unwrap();
        assert_eq!(
            status,
            PolicyGuardStatus::Refused("policy_snapshot_changed_after_approval".into())
        );
    }
}
