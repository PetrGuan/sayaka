// SPDX-License-Identifier: MPL-2.0
use super::*;
use crate::model::{Cancellation, FileIdentity};
use crate::scan::{ScanEntry, ScanMetrics, ScanReport, ScanStatus, ScanTaskId, ScanTotals};
use std::path::PathBuf;

fn footprint(children: &[(&str, ResourceKind)]) -> Footprint {
    let root = PathBuf::from(if cfg!(windows) {
        "C:/ai-fixture"
    } else {
        "/ai-fixture"
    });
    let entries = std::iter::once(("", ResourceKind::Directory))
        .chain(children.iter().copied())
        .enumerate()
        .map(|(index, (name, kind))| ScanEntry {
            id: index as u64 + 1,
            path: if name.is_empty() {
                root.clone()
            } else {
                root.join(name)
            },
            kind,
            identity: FileIdentity::Unix {
                device: 7,
                inode: index as u64 + 1,
            },
            logical_bytes: (kind == ResourceKind::File).then_some(0),
            allocated_bytes: (kind == ResourceKind::File).then_some(0),
            dataless: false,
            counted: false,
            depth: usize::MAX,
        })
        .collect();
    let tree = ScanTree::build(
        ScanReport {
            task_id: ScanTaskId::synthetic(1),
            roots: vec![root],
            status: ScanStatus::Complete,
            complete: true,
            entries,
            issues: vec![],
            issues_omitted: 0,
            totals: ScanTotals::default(),
            metrics: ScanMetrics::default(),
        },
        &Cancellation::default(),
    )
    .unwrap();
    project(&tree, Tool::Codex).unwrap()
}

#[test]
fn recognizes_documented_codex_layouts_without_requiring_active_sessions() {
    use ResourceKind::{Directory as D, File as F};
    for layout in [
        vec![("sessions", D), ("config.toml", F)],
        vec![("sessions", D), ("history.jsonl", F)],
        vec![("archived_sessions", D), ("config.toml", F)],
        vec![("session_index.jsonl", F), ("auth.json", F)],
        vec![("session_index.jsonl", F), ("config.toml", F)],
        vec![("config.toml", F), ("auth.json", F), ("version.json", F)],
    ] {
        let report = footprint(&layout);
        assert!(report.recognized, "{layout:?}");
        assert_eq!(report.rule_version, 2);
        assert!(
            report
                .components
                .iter()
                .all(|item| item.role != "logs_or_cache")
        );
    }
}

#[test]
fn generic_names_wrong_kinds_and_links_do_not_establish_codex_ownership() {
    use ResourceKind::{Directory as D, File as F, Link as L};
    for layout in [
        vec![("config.toml", F), ("auth.json", F)],
        vec![("log", D), ("version.json", F)],
        vec![("session_index.jsonl", F)],
        vec![("config.toml", F), ("auth.json", F), ("version.json", L)],
        vec![("session_index.jsonl", D), ("config.toml", F)],
        vec![("sessions", L), ("config.toml", F)],
    ] {
        let report = footprint(&layout);
        assert!(!report.recognized, "{layout:?}");
        assert!(report.components.is_empty());
    }
}
