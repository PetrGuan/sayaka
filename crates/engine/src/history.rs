// SPDX-License-Identifier: MPL-2.0

//! Bounded read-only queries. Filtering never hides uncommitted store evidence.

use crate::journal::{ItemState, JournalRead, MAX_RECORDS, Record, valid_id};
use serde::Serialize;
use std::collections::HashSet;
use std::io;

#[derive(Clone, Debug)]
pub struct Query {
    pub operation_id: Option<String>,
    pub states: Vec<ItemState>,
    pub since_unix_ms: Option<u64>,
    pub until_unix_ms: Option<u64>,
    pub offset: usize,
    pub limit: usize,
}

impl Default for Query {
    fn default() -> Self {
        Self {
            operation_id: None,
            states: Vec::new(),
            since_unix_ms: None,
            until_unix_ms: None,
            offset: 0,
            limit: 20,
        }
    }
}

impl Query {
    pub fn validate(&self) -> io::Result<()> {
        if self.operation_id.as_ref().is_some_and(|id| !valid_id(id))
            || self
                .states
                .iter()
                .any(|state| matches!(state, ItemState::Planned | ItemState::Started))
            || self.states.len() > 4
            || self.limit == 0
            || self.limit > MAX_RECORDS
            || self.offset > MAX_RECORDS
            || self
                .since_unix_ms
                .zip(self.until_unix_ms)
                .is_some_and(|(since, until)| since > until)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid history filter, time range or page bounds",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct Page {
    pub schema_version: u32,
    pub total_records: usize,
    pub matched_records: usize,
    pub offset: usize,
    pub limit: usize,
    pub records: Vec<Record>,
    /// Store-wide, deliberately not filtered or paginated.
    pub uncommitted_snapshots: Vec<String>,
}

pub fn query(read: JournalRead, query: &Query) -> io::Result<Page> {
    query.validate()?;
    if read.records.len() > MAX_RECORDS || read.uncommitted_snapshots.len() > MAX_RECORDS * 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "history input exceeds the journal budget",
        ));
    }
    let total_records = read.records.len();
    let mut ids = HashSet::new();
    let mut records = Vec::new();
    for record in read.records {
        record.validate()?;
        if !ids.insert(record.operation_id.clone()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "duplicate history operation identifier",
            ));
        }
        let record = record.reconciled();
        if query
            .operation_id
            .as_ref()
            .is_some_and(|id| id != &record.operation_id)
            || query
                .since_unix_ms
                .is_some_and(|since| record.created_unix_ms < since)
            || query
                .until_unix_ms
                .is_some_and(|until| record.created_unix_ms >= until)
            || (!query.states.is_empty()
                && !record
                    .items
                    .iter()
                    .any(|item| query.states.contains(&item.state)))
        {
            continue;
        }
        records.push(record);
    }
    records.sort_by(|a, b| {
        b.created_unix_ms
            .cmp(&a.created_unix_ms)
            .then(a.operation_id.cmp(&b.operation_id))
    });
    let matched_records = records.len();
    let records = records
        .into_iter()
        .skip(query.offset)
        .take(query.limit)
        .collect();
    Ok(Page {
        schema_version: 1,
        total_records,
        matched_records,
        offset: query.offset,
        limit: query.limit,
        records,
        uncommitted_snapshots: read.uncommitted_snapshots,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::{
        CleanPolicyContextRecord, CleanPolicyIdentityRecord, CleanPolicyPathRecord, ItemRecord,
        NativePath, RuleBindingRecord, RuleWitnessRecord,
    };

    fn record(id: &str, created: u64, state: ItemState) -> Record {
        Record {
            schema_version: 1,
            plan_schema_version: 2,
            engine_version: 2,
            rules_version: 1,
            operation_id: id.into(),
            contract: "revalidated_trash_v1".into(),
            scope: NativePath::unix_fixture("/fixture"),
            clean_policy: None,
            created_unix_ms: created,
            items: vec![ItemRecord {
                path: NativePath::unix_fixture("/fixture/file"),
                device: 1,
                inode: 2,
                logical_bytes: 1,
                state,
                reason: None,
                destination: None,
                rule_binding: None,
                recovery_evidence: None,
                updated_unix_ms: created,
            }],
        }
    }
    fn read(records: Vec<Record>) -> JournalRead {
        JournalRead {
            records,
            uncommitted_snapshots: vec!["a-1.pending".into()],
        }
    }

    fn rule_bound_record(id: &str, created: u64, state: ItemState) -> Record {
        Record {
            schema_version: 2,
            plan_schema_version: 3,
            engine_version: 2,
            rules_version: 2,
            operation_id: id.into(),
            contract: "revalidated_trash_v1".into(),
            scope: NativePath::unix_fixture("/fixture"),
            clean_policy: None,
            created_unix_ms: created,
            items: vec![ItemRecord {
                path: NativePath::unix_fixture("/fixture/pkg/__pycache__/module.cpython-39.pyc"),
                device: 1,
                inode: 12,
                logical_bytes: 7,
                state,
                reason: None,
                destination: None,
                rule_binding: Some(RuleBindingRecord {
                    schema_version: 1,
                    rule_id: crate::rules::CPYTHON_SOURCE_BACKED_PYC_RULE_ID.into(),
                    rule_version: crate::rules::CPYTHON_SOURCE_BACKED_PYC_RULE_VERSION,
                    ruleset_schema_version: crate::rules::RULESET_SCHEMA_VERSION,
                    ruleset_revision: crate::rules::BUILTIN_RULESET_REVISION,
                    semantics: crate::rules::CPYTHON_SOURCE_BACKED_PYC_TRASH_SEMANTICS.into(),
                    semantics_digest:
                        crate::rules::CPYTHON_SOURCE_BACKED_PYC_TRASH_SEMANTICS_DIGEST.into(),
                    selected_root: NativePath::unix_fixture("/fixture"),
                    exclusions: vec![],
                    target: RuleWitnessRecord {
                        path: NativePath::unix_fixture(
                            "/fixture/pkg/__pycache__/module.cpython-39.pyc",
                        ),
                        device: 1,
                        inode: 12,
                        kind: "file".into(),
                        logical_bytes: 7,
                        modified: crate::journal::NativeTime::from_system_time(
                            std::time::UNIX_EPOCH,
                        ),
                        changed: crate::journal::NativeTime::from_system_time(
                            std::time::UNIX_EPOCH,
                        ),
                        created: crate::journal::NativeTime::from_system_time(
                            std::time::UNIX_EPOCH,
                        ),
                        uid: 1,
                        gid: 1,
                        mode: 0o100600,
                        nlink: 1,
                        flags: 0,
                    },
                    source: RuleWitnessRecord {
                        path: NativePath::unix_fixture("/fixture/pkg/module.py"),
                        device: 1,
                        inode: 11,
                        kind: "file".into(),
                        logical_bytes: 8,
                        modified: crate::journal::NativeTime::from_system_time(
                            std::time::UNIX_EPOCH,
                        ),
                        changed: crate::journal::NativeTime::from_system_time(
                            std::time::UNIX_EPOCH,
                        ),
                        created: crate::journal::NativeTime::from_system_time(
                            std::time::UNIX_EPOCH,
                        ),
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
                        modified: crate::journal::NativeTime::from_system_time(
                            std::time::UNIX_EPOCH,
                        ),
                        changed: crate::journal::NativeTime::from_system_time(
                            std::time::UNIX_EPOCH,
                        ),
                        created: crate::journal::NativeTime::from_system_time(
                            std::time::UNIX_EPOCH,
                        ),
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
                            inode: 2,
                            kind: "directory".into(),
                            logical_bytes: 0,
                            modified: crate::journal::NativeTime::from_system_time(
                                std::time::UNIX_EPOCH,
                            ),
                            changed: crate::journal::NativeTime::from_system_time(
                                std::time::UNIX_EPOCH,
                            ),
                            created: crate::journal::NativeTime::from_system_time(
                                std::time::UNIX_EPOCH,
                            ),
                            uid: 1,
                            gid: 1,
                            mode: 0o040700,
                            nlink: 1,
                            flags: 0,
                        },
                        RuleWitnessRecord {
                            path: NativePath::unix_fixture("/fixture/pkg/__pycache__"),
                            device: 1,
                            inode: 3,
                            kind: "directory".into(),
                            logical_bytes: 0,
                            modified: crate::journal::NativeTime::from_system_time(
                                std::time::UNIX_EPOCH,
                            ),
                            changed: crate::journal::NativeTime::from_system_time(
                                std::time::UNIX_EPOCH,
                            ),
                            created: crate::journal::NativeTime::from_system_time(
                                std::time::UNIX_EPOCH,
                            ),
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
                        inode: 2,
                        kind: "directory".into(),
                        logical_bytes: 0,
                        modified: crate::journal::NativeTime::from_system_time(
                            std::time::UNIX_EPOCH,
                        ),
                        changed: crate::journal::NativeTime::from_system_time(
                            std::time::UNIX_EPOCH,
                        ),
                        created: crate::journal::NativeTime::from_system_time(
                            std::time::UNIX_EPOCH,
                        ),
                        uid: 1,
                        gid: 1,
                        mode: 0o040700,
                        nlink: 1,
                        flags: 0,
                    }],
                    warnings: vec!["metadata-only".into()],
                }),
                recovery_evidence: None,
                updated_unix_ms: created,
            }],
        }
    }

    #[test]
    fn newest_first_time_boundaries_and_pages_are_deterministic() {
        let page = query(
            read(vec![
                record("b", 20, ItemState::Failed),
                record("a", 20, ItemState::Failed),
                record("c", 30, ItemState::Failed),
                record("d", 10, ItemState::Failed),
            ]),
            &Query {
                since_unix_ms: Some(20),
                until_unix_ms: Some(30),
                offset: 1,
                limit: 1,
                ..Query::default()
            },
        )
        .unwrap();
        assert_eq!(page.total_records, 4);
        assert_eq!(page.matched_records, 2);
        assert_eq!(page.records[0].operation_id, "b");
        assert_eq!(page.uncommitted_snapshots, ["a-1.pending"]);
    }

    #[test]
    fn state_filter_reconciles_started_and_preserves_whole_operation() {
        let mut operation = record("a-1", 10, ItemState::Started);
        let mut second = operation.items[0].clone();
        second.path = NativePath::unix_fixture("/fixture/other");
        second.inode = 3;
        second.state = ItemState::Failed;
        operation.items.push(second);
        let page = query(
            read(vec![operation]),
            &Query {
                states: vec![ItemState::Unknown],
                ..Query::default()
            },
        )
        .unwrap();
        assert_eq!(page.records.len(), 1);
        assert_eq!(page.records[0].items.len(), 2);
        assert_eq!(page.records[0].items[0].state, ItemState::Unknown);
        assert_eq!(page.records[0].items[1].state, ItemState::Failed);
    }

    #[test]
    fn empty_filters_never_hide_global_pending_warnings_or_bad_records() {
        let page = query(
            read(vec![record("a", 10, ItemState::Failed)]),
            &Query {
                operation_id: Some("b".into()),
                ..Query::default()
            },
        )
        .unwrap();
        assert!(page.records.is_empty());
        assert!(!page.uncommitted_snapshots.is_empty());
        let mut invalid = record("a", 10, ItemState::Failed);
        invalid.schema_version = 99;
        assert!(
            query(
                read(vec![invalid]),
                &Query {
                    operation_id: Some("b".into()),
                    ..Query::default()
                }
            )
            .is_err()
        );
    }

    #[test]
    fn invalid_filters_and_duplicate_ids_are_explicit_errors() {
        assert!(
            Query {
                limit: 0,
                ..Query::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            Query {
                operation_id: Some("../a".into()),
                ..Query::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            Query {
                states: vec![ItemState::Started],
                ..Query::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            Query {
                since_unix_ms: Some(20),
                until_unix_ms: Some(10),
                ..Query::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            query(
                read(vec![
                    record("a", 10, ItemState::Failed),
                    record("a", 20, ItemState::Failed)
                ]),
                &Query::default()
            )
            .is_err()
        );
    }

    #[test]
    fn mixed_legacy_and_rule_bound_records_are_queryable() {
        let clean = Record {
            schema_version: 3,
            plan_schema_version: 3,
            engine_version: 2,
            rules_version: 2,
            operation_id: "c-3".into(),
            contract: "revalidated_trash_v1".into(),
            scope: NativePath::unix_fixture("/fixture"),
            clean_policy: Some(CleanPolicyContextRecord {
                schema_version: 1,
                kind: "sayaka_clean_policy_context".into(),
                root_path: CleanPolicyPathRecord {
                    encoding: "unix_bytes".into(),
                    bytes_hex: "2f66697874757265".into(),
                    display: "\"/fixture\"".into(),
                },
                root_identity: CleanPolicyIdentityRecord {
                    device: 1,
                    inode: 1,
                },
                file_state: serde_json::json!({"state":"absent"}),
                effective_exclusions: vec![],
            }),
            created_unix_ms: 30,
            items: vec![ItemRecord {
                path: NativePath::unix_fixture("/fixture/pkg/__pycache__/module.cpython-39.pyc"),
                device: 1,
                inode: 12,
                logical_bytes: 7,
                state: ItemState::Skipped,
                reason: Some("policy_refused_last_native_guard".into()),
                destination: None,
                rule_binding: rule_bound_record("x", 1, ItemState::Skipped).items[0]
                    .rule_binding
                    .clone(),
                recovery_evidence: None,
                updated_unix_ms: 30,
            }],
        };
        let page = query(
            read(vec![
                record("a-1", 10, ItemState::Failed),
                rule_bound_record("b-2", 20, ItemState::Skipped),
                clean,
            ]),
            &Query::default(),
        )
        .unwrap();
        assert_eq!(page.total_records, 3);
        assert_eq!(page.records[0].operation_id, "c-3");
        assert_eq!(page.records[0].schema_version, 3);
        assert!(page.records[0].clean_policy.is_some());
        assert_eq!(page.records[1].operation_id, "b-2");
        assert_eq!(page.records[1].schema_version, 2);
        assert_eq!(page.records[2].operation_id, "a-1");
        assert_eq!(page.records[2].schema_version, 1);
    }
}
