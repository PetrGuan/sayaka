// SPDX-License-Identifier: MPL-2.0
//! Schema 9 evidence is audit data, never executable authority.
use crate::journal::{NativePath, Record};
use serde::{Deserialize, Serialize};
use std::io;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootRecord {
    pub path: NativePath,
    pub state: String,
    pub device: u64,
    pub inode: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpotlightRecord {
    pub bundle_id: String,
    pub scope: String,
    pub status: String,
    pub result_count: usize,
    pub verified_trash_count: usize,
    pub stale_registrations: Vec<NativePath>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrashedBundle {
    pub path: NativePath,
    pub device: u64,
    pub inode: u64,
    pub manifest_device: u64,
    pub manifest_inode: u64,
    pub manifest_digest: String,
    pub trash_root: NativePath,
    pub trash_device: u64,
    pub trash_inode: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub item_id: String,
    pub bundle_id: String,
    pub tier: String,
    pub rule_id: String,
    pub rule_version: u32,
    pub path: NativePath,
    pub kind: String,
    pub consequence: String,
    pub measured_logical_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trashed_bundles: Option<Vec<TrashedBundle>>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub schema_version: u32,
    pub home: NativePath,
    pub library_device: u64,
    pub library_inode: u64,
    pub copy_roots: Vec<RootRecord>,
    pub coverage: String,
    pub spotlight: Vec<SpotlightRecord>,
    pub policy_digest: String,
    pub plan_digest: String,
    pub approved_unix_ms: u64,
    pub deadline_unix_ms: u64,
    pub selected: Vec<Binding>,
}
fn invalid() -> io::Error {
    io::Error::other("invalid orphan context")
}
fn hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && s.split('.').all(|p| {
            !p.is_empty()
                && p.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        })
}
fn path(p: &NativePath) -> io::Result<std::path::PathBuf> {
    p.validate()?;
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let path = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(&p.bytes));
        if p.encoding != "unix_bytes"
            || p.bytes.len() > 4096
            || p.bytes.contains(&0)
            || !path.is_absolute()
            || path.components().any(|p| {
                matches!(
                    p,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err(invalid());
        }
        Ok(path)
    }
    #[cfg(not(unix))]
    {
        Err(invalid())
    }
}
impl Context {
    pub fn validate(&self, record: &Record) -> io::Result<()> {
        let home = path(&self.home)?;
        if self.schema_version != 1
            || self.library_inode == 0
            || !hex(&self.policy_digest)
            || !hex(&self.plan_digest)
            || self.coverage != "registered_and_selected_roots"
            || self.copy_roots.len() < 2
            || self.copy_roots.len() > 10
            || self.selected.len() != record.items.len()
            || self.selected.len() > 32
            || self.selected.is_empty()
            || self.deadline_unix_ms.checked_sub(self.approved_unix_ms) != Some(120_000)
            || record.created_unix_ms != self.approved_unix_ms
            || path(&record.scope)? != home.join("Library")
        {
            return Err(invalid());
        }
        let mut roots = std::collections::HashSet::new();
        for root in &self.copy_roots {
            let p = path(&root.path)?;
            if !roots.insert(p.clone())
                || root.inode == 0
                || !matches!(root.state.as_str(), "present" | "absent")
                || (root.state == "absent" && p != home.join("Applications"))
            {
                return Err(invalid());
            }
        }
        if !roots.contains(std::path::Path::new("/Applications"))
            || !roots.contains(&home.join("Applications"))
        {
            return Err(invalid());
        }
        let mut expected_queries = std::collections::HashSet::<&String>::new();
        // Own the prefixes separately so comparison also rejects unrelated queries.
        let mut expected_ids = std::collections::HashSet::<String>::new();
        for binding in &self.selected {
            expected_ids.insert(binding.bundle_id.clone());
            for (offset, _) in binding.bundle_id.match_indices('.') {
                expected_ids.insert(binding.bundle_id[..offset].to_owned());
            }
        }
        expected_queries.extend(expected_ids.iter());
        let mut queries = std::collections::HashSet::new();
        for query in &self.spotlight {
            if query.stale_registrations.len() > 256 {
                return Err(invalid());
            }
            for stale in &query.stale_registrations {
                path(stale)?;
            }
            if !id(&query.bundle_id)
                || !queries.insert(&query.bundle_id)
                || query.scope != "local_computer"
                || query.status != "complete"
                || query.result_count > 256
                || query.verified_trash_count != query.result_count
            {
                return Err(invalid());
            }
        }
        if queries != expected_queries {
            return Err(invalid());
        }
        let mut ids = std::collections::HashSet::new();
        for (binding, item) in self.selected.iter().zip(&record.items) {
            let p = path(&binding.path)?;
            if item.updated_unix_ms < self.approved_unix_ms {
                return Err(invalid());
            }
            if !hex(&binding.item_id)
                || !ids.insert(&binding.item_id)
                || !id(&binding.bundle_id)
                || binding.path != item.path
                || binding.rule_version != 1
                || binding.consequence.is_empty()
                || binding.consequence.len() > 2048
                || !queries.contains(&binding.bundle_id)
            {
                return Err(invalid());
            }
            let table = [
                ("caches", "Caches", "", "directory"),
                ("logs", "Logs", "", "directory"),
                (
                    "saved_state",
                    "Saved Application State",
                    ".savedState",
                    "directory",
                ),
                ("http_storages", "HTTPStorages", "", "directory"),
                (
                    "http_storages_cookies",
                    "HTTPStorages",
                    ".binarycookies",
                    "file",
                ),
                ("webkit", "WebKit", "", "directory"),
                ("cookies", "Cookies", ".binarycookies", "file"),
                ("preferences", "Preferences", ".plist", "file"),
                (
                    "application_support",
                    "Application Support",
                    "",
                    "directory",
                ),
            ];
            let row = table
                .iter()
                .find(|r| {
                    binding.rule_id == format!("org.apple.library.{}.bundle_id_convention.v1", r.0)
                })
                .ok_or_else(invalid)?;
            if binding.kind != row.3
                || p != home
                    .join("Library")
                    .join(row.1)
                    .join(format!("{}{}", binding.bundle_id, row.2))
            {
                return Err(invalid());
            }
            match (binding.tier.as_str(), &binding.trashed_bundles) {
                ("name_only", None) if row.0 == "caches" => {}
                ("trashed_bundle", Some(bundles)) if !bundles.is_empty() && bundles.len() <= 8 => {
                    let mut identities = std::collections::HashSet::new();
                    for bundle in bundles {
                        let root = path(&bundle.trash_root)?;
                        let bp = path(&bundle.path)?;
                        if root != home.join(".Trash")
                            || bp == root
                            || !bp.starts_with(&root)
                            || bp.extension().is_none_or(|e| e != "app")
                            || bundle.inode == 0
                            || bundle.manifest_inode == 0
                            || bundle.trash_inode == 0
                            || bundle.device != bundle.trash_device
                            || bundle.manifest_device != bundle.device
                            || !hex(&bundle.manifest_digest)
                            || !identities.insert((bundle.device, bundle.inode))
                        {
                            return Err(invalid());
                        }
                    }
                }
                _ => return Err(invalid()),
            }
        }
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::journal::{ItemRecord, ItemState};
    use std::path::Path;
    fn fixture() -> Record {
        let p = NativePath::from_path(Path::new("/Users/fixture/Library/Caches/com.fixture.old"));
        Record {
            schema_version: 9,
            plan_schema_version: 9,
            engine_version: 1,
            rules_version: 1,
            operation_id: "orphan-fixture-1".into(),
            contract: "revalidated_orphan_trash_v1".into(),
            scope: NativePath::from_path(Path::new("/Users/fixture/Library")),
            created_unix_ms: 10,
            clean_policy: None,
            tool_operation: None,
            related_context: None,
            delegation: None,
            orphan_context: Some(Context {
                schema_version: 1,
                home: NativePath::from_path(Path::new("/Users/fixture")),
                library_device: 1,
                library_inode: 2,
                copy_roots: vec![
                    RootRecord {
                        path: NativePath::from_path(Path::new("/Applications")),
                        state: "present".into(),
                        device: 1,
                        inode: 3,
                    },
                    RootRecord {
                        path: NativePath::from_path(Path::new("/Users/fixture/Applications")),
                        state: "absent".into(),
                        device: 1,
                        inode: 4,
                    },
                ],
                coverage: "registered_and_selected_roots".into(),
                spotlight: ["com", "com.fixture", "com.fixture.old"]
                    .into_iter()
                    .map(|id| SpotlightRecord {
                        bundle_id: id.into(),
                        scope: "local_computer".into(),
                        status: "complete".into(),
                        result_count: 0,
                        verified_trash_count: 0,
                        stale_registrations: vec![],
                    })
                    .collect(),
                policy_digest: "a".repeat(64),
                plan_digest: "b".repeat(64),
                approved_unix_ms: 10,
                deadline_unix_ms: 120010,
                selected: vec![Binding {
                    item_id: "c".repeat(64),
                    bundle_id: "com.fixture.old".into(),
                    tier: "name_only".into(),
                    rule_id: "org.apple.library.caches.bundle_id_convention.v1".into(),
                    rule_version: 1,
                    path: p.clone(),
                    kind: "directory".into(),
                    consequence: "May redownload".into(),
                    measured_logical_bytes: None,
                    trashed_bundles: None,
                }],
            }),
            items: vec![ItemRecord {
                path: p,
                device: 1,
                inode: 5,
                logical_bytes: 96,
                state: ItemState::Planned,
                reason: None,
                destination: None,
                rule_binding: None,
                recovery_evidence: None,
                updated_unix_ms: 10,
            }],
        }
    }
    #[test]
    fn schema9_round_trip_and_missing_context() {
        let r = fixture();
        r.validate().unwrap();
        let bytes = serde_json::to_vec(&r).unwrap();
        let decoded: Record = serde_json::from_slice(&bytes).unwrap();
        decoded.validate().unwrap();
        let mut missing = r;
        missing.orphan_context = None;
        assert!(missing.validate().is_err());
    }
    #[test]
    fn name_only_cannot_authorize_user_data() {
        let mut r = fixture();
        let context = r.orphan_context.as_mut().unwrap();
        let b = &mut context.selected[0];
        b.rule_id = "org.apple.library.application_support.bundle_id_convention.v1".into();
        b.path = NativePath::from_path(Path::new(
            "/Users/fixture/Library/Application Support/com.fixture.old",
        ));
        r.items[0].path = b.path.clone();
        assert!(r.validate().is_err());
    }
    #[test]
    fn reject_binding_drift_and_unknown_queries() {
        let base = fixture();
        for change in 0..6 {
            let mut r = base.clone();
            let c = r.orphan_context.as_mut().unwrap();
            match change {
                0 => c.selected[0].bundle_id = "com.fixture.other".into(),
                1 => c.selected[0].kind = "file".into(),
                2 => c.spotlight[0].status = "unknown".into(),
                3 => c.spotlight[0].result_count = 1,
                4 => c.deadline_unix_ms += 1,
                _ => {
                    c.copy_roots.remove(0);
                }
            };
            assert!(r.validate().is_err(), "mutation {change}");
        }
    }
    #[test]
    fn interrupted_started_is_unknown_and_unmeasured_size_stays_unknown() {
        let mut r = fixture();
        r.items[0].state = ItemState::Started;
        assert_eq!(r.clone().reconciled().items[0].state, ItemState::Unknown);
        r.items[0].state = ItemState::Succeeded;
        r.items[0].destination = Some(NativePath::from_path(Path::new(
            "/Users/fixture/.Trash/com.fixture.old",
        )));
        r.validate().unwrap();
        assert_eq!(r.handled_bytes(), None);
        r.orphan_context.as_mut().unwrap().selected[0].measured_logical_bytes = Some(123);
        assert_eq!(r.handled_bytes(), Some(123));
    }
    #[test]
    fn trash_evidence_requires_same_native_root() {
        let mut r = fixture();
        let b = &mut r.orphan_context.as_mut().unwrap().selected[0];
        b.tier = "trashed_bundle".into();
        b.trashed_bundles = Some(vec![TrashedBundle {
            path: NativePath::from_path(Path::new("/Users/fixture/.Trash/Fixture.app")),
            device: 1,
            inode: 20,
            manifest_device: 1,
            manifest_inode: 21,
            manifest_digest: "d".repeat(64),
            trash_root: NativePath::from_path(Path::new("/Users/fixture/.Trash")),
            trash_device: 1,
            trash_inode: 22,
        }]);
        r.validate().unwrap();
        r.orphan_context.as_mut().unwrap().selected[0]
            .trashed_bundles
            .as_mut()
            .unwrap()[0]
            .path = NativePath::from_path(Path::new("/Volumes/External/.Trashes/501/Fixture.app"));
        assert!(r.validate().is_err());
    }
}
