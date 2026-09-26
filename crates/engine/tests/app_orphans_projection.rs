// SPDX-License-Identifier: MPL-2.0

#![cfg(target_os = "macos")]

use sayaka_engine::app_inventory::{
    AppInventory, AppInventoryCounts, AppInventoryMetrics, AppInventoryStatus, AppKind, AppRecord,
    ExecutableMetadata, NameSource, PathStatus, PlistFormat, RunningObservation, StringField,
    StringState,
};
use sayaka_engine::app_orphans::project_orphan_caches;
use sayaka_engine::model::{Cancellation, FileIdentity};
use sayaka_engine::scan::{ScanLimits, scan};
use std::fs;
use std::path::PathBuf;

fn field(value: &str) -> StringField {
    StringField {
        state: StringState::Present,
        value: Some(value.into()),
    }
}

fn installed_app(bundle_id: &str, display_name: &str, inode: u64) -> AppRecord {
    AppRecord {
        bundle_path: PathBuf::from(format!("/Applications/{display_name}.app")),
        observed_roots: vec![PathBuf::from("/Applications")],
        bundle_identity: FileIdentity::Unix { device: 1, inode },
        app_kind: AppKind::App,
        parser_format: PlistFormat::Xml,
        display_name: display_name.into(),
        display_name_source: NameSource::BundleDisplayName,
        localized: false,
        bundle_id: field(bundle_id),
        short_version: field("1"),
        build_version: field("1"),
        package_type: field("APPL"),
        declared_product_dir_name: StringField {
            state: StringState::Missing,
            value: None,
        },
        executable: ExecutableMetadata {
            state: StringState::Missing,
            declared_value: None,
            path_status: PathStatus::Missing,
        },
        running: RunningObservation::NotChecked,
    }
}

fn inventory(complete: bool) -> AppInventory {
    AppInventory {
        schema_version: 1,
        kind: "app_inventory",
        platform: "macos",
        status: if complete {
            AppInventoryStatus::Complete
        } else {
            AppInventoryStatus::Partial
        },
        complete,
        effects_performed: false,
        roots: vec![PathBuf::from("/Applications")],
        filter: String::new(),
        excludes: vec![],
        scan_task_id: "fixture:1".into(),
        counts: AppInventoryCounts::default(),
        apps: vec![installed_app("com.example.alpha", "Beta", 7)],
        scan_issues: vec![],
        issues: vec![],
        issues_omitted: 0,
        metrics: AppInventoryMetrics::default(),
    }
}

#[test]
fn exact_bundle_id_match_does_not_conflate_same_display_name_and_protects_shared_data() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/app-orphans-projection-fixture");
    let _ = fs::remove_dir_all(&root);
    let caches = root.join("Library/Caches");
    for name in [
        "com.example.alpha",
        "com.example.beta",
        "group.example.shared",
        "com.apple.control",
    ] {
        fs::create_dir_all(caches.join(name)).unwrap();
    }
    let report = scan(
        std::slice::from_ref(&caches),
        &ScanLimits {
            max_depth: 1,
            ..ScanLimits::default()
        },
        &Cancellation::default(),
        |_| {},
    )
    .unwrap();
    let preview = project_orphan_caches(&inventory(true), &report);
    assert!(!preview.globally_complete);
    assert!(!preview.effects_performed);
    let find = |name: &str| {
        preview
            .candidates
            .iter()
            .find(|c| c.bundle_id_hint == name)
            .unwrap()
    };
    assert_eq!(
        find("com.example.alpha").disposition,
        "installed_app_observed"
    );
    assert_eq!(
        find("com.example.beta").disposition,
        "possible_orphan_review_only"
    );
    assert_eq!(
        find("group.example.shared").disposition,
        "protected_shared_or_system"
    );
    assert_eq!(
        find("com.apple.control").disposition,
        "protected_shared_or_system"
    );
    assert!(
        preview
            .candidates
            .iter()
            .all(|c| !c.selected && c.authorized_action.is_none())
    );
    let partial = project_orphan_caches(&inventory(false), &report);
    assert!(
        partial
            .candidates
            .iter()
            .all(|c| c.uncertainty.contains(&"app_inventory_incomplete"))
    );
    let _ = fs::remove_dir_all(root);
}
