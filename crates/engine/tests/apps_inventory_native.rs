// SPDX-License-Identifier: MPL-2.0

#![cfg(target_os = "macos")]

use sayaka_engine::app_inventory::{
    AppInventoryLimits, AppInventoryMetadataReadMode, AppInventoryOptions, PathStatus,
    inventory_apps,
};
use sayaka_engine::model::Cancellation;
use sayaka_engine::scan::{ScanLimits, scan_prune_app_bundles};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

fn make_plist(bundle_id: &str, executable: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleDisplayName</key><string>{bundle_id}</string>
<key>CFBundleName</key><string>{bundle_id}</string>
<key>CFBundleIdentifier</key><string>{bundle_id}</string>
<key>CFBundleShortVersionString</key><string>1.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleExecutable</key><string>{executable}</string>
</dict></plist>"#
    )
}

fn oracle_root() -> Option<PathBuf> {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .ok()?;
    let target = repo.join("target");
    let mut roots = fs::read_dir(target)
        .ok()?
        .flatten()
        .filter(|entry| entry.file_type().ok().is_some_and(|ty| ty.is_dir()))
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("apps-oracle-"))
        })
        .collect::<Vec<_>>();
    roots.sort();
    roots.into_iter().next()
}

fn run_inventory(roots: &[PathBuf]) -> sayaka_engine::app_inventory::AppInventory {
    let cancellation = Cancellation::default();
    let report =
        scan_prune_app_bundles(roots, &ScanLimits::default(), &cancellation, |_| {}).unwrap();
    inventory_apps(
        report,
        &AppInventoryOptions {
            filter: String::new(),
            excludes: vec![],
            limits: AppInventoryLimits::default(),
            metadata_read_mode: AppInventoryMetadataReadMode::Baseline,
            running_attribution: false,
        },
        &cancellation,
        Duration::from_secs(30),
    )
}

#[test]
fn app_scan_prunes_bundle_descents_and_keeps_same_bundle_id_copies() {
    let Some(root) = oracle_root() else {
        return;
    };
    let report = scan_prune_app_bundles(
        std::slice::from_ref(&root),
        &ScanLimits::default(),
        &Cancellation::default(),
        |_| {},
    )
    .unwrap();
    assert!(
        report
            .entries
            .iter()
            .any(|entry| entry.path.ends_with("Example One.app"))
    );
    assert!(
        report
            .entries
            .iter()
            .any(|entry| entry.path.ends_with("Example Two.app"))
    );
    assert!(
        !report
            .entries
            .iter()
            .any(|entry| entry.path.to_string_lossy().contains("Nested Valid.app"))
    );
    assert!(
        !report
            .entries
            .iter()
            .any(|entry| entry.path.to_string_lossy().contains("Contents/Resources"))
    );

    let inventory = run_inventory(std::slice::from_ref(&root));
    let mut by_id = std::collections::HashMap::<String, Vec<PathBuf>>::new();
    for app in &inventory.apps {
        if let Some(id) = &app.bundle_id.value {
            by_id
                .entry(id.clone())
                .or_default()
                .push(app.bundle_path.clone());
        }
    }
    assert!(by_id.values().any(|paths| {
        let mut dedup = paths.clone();
        dedup.sort();
        dedup.dedup();
        dedup.len() >= 2
    }));

    let issue_by_name = |needle: &str, code: &str| {
        inventory.issues.iter().any(|issue| {
            issue.code.as_str() == code
                && issue
                    .path
                    .as_ref()
                    .is_some_and(|path| path.to_string_lossy().contains(needle))
        })
    };
    assert!(issue_by_name("Custom Entity.app", "malformed_plist"));
    assert!(issue_by_name("Truncated XML.app", "malformed_plist"));
    assert!(issue_by_name("Duplicate Name.app", "malformed_plist"));
    assert!(issue_by_name("Binary Overflow.app", "plist_parse_limit"));
    assert!(issue_by_name("Linked Info.app", "link_skipped"));
}

#[test]
fn direct_app_root_is_pruned_and_executable_escape_is_rejected() {
    let Some(root) = oracle_root() else {
        return;
    };
    let direct = root.join("Example One.app");
    let report = scan_prune_app_bundles(
        std::slice::from_ref(&direct),
        &ScanLimits::default(),
        &Cancellation::default(),
        |_| {},
    )
    .unwrap();
    assert!(report.entries.iter().any(|entry| entry.path == direct));
    assert!(
        !report
            .entries
            .iter()
            .any(|entry| entry.path.to_string_lossy().contains("Contents/"))
    );

    let inventory = run_inventory(&[root]);
    let escape = inventory
        .apps
        .iter()
        .find(|app| app.bundle_path.ends_with("Escape Executable.app"))
        .expect("escape executable fixture app present");
    assert_eq!(
        escape.executable.path_status,
        PathStatus::InvalidDeclaredPath
    );

    let direct_inventory = run_inventory(std::slice::from_ref(&direct));
    assert!(
        direct_inventory
            .apps
            .iter()
            .any(|app| app.bundle_path == direct),
        "direct .app root should still be inventoried"
    );
}

#[test]
fn overlapping_roots_share_one_row_with_both_observed_roots_and_unknown_rows_preserved() {
    let Some(root) = oracle_root() else {
        return;
    };
    let direct = root.join("Example One.app");
    let inventory = run_inventory(&[root.clone(), direct.clone()]);
    let app = inventory
        .apps
        .iter()
        .find(|row| row.bundle_path == direct)
        .expect("direct bundle present once");
    assert!(app.observed_roots.iter().any(|value| value == &root));
    assert!(app.observed_roots.iter().any(|value| value == &direct));
    assert_eq!(inventory.counts.duplicate_identities, 0);

    let is_oracle = inventory
        .apps
        .iter()
        .any(|row| row.bundle_path.ends_with("Binary Overflow.app"));
    if is_oracle {
        assert_eq!(inventory.apps.len(), inventory.counts.inspected_candidates);
        assert!(
            inventory.counts.unknown >= 7,
            "oracle fixtures should retain unknown rows for malformed and missing metadata"
        );
    }
}

#[test]
fn valid_metadata_is_preserved_when_macos_container_or_leaf_is_missing_or_non_directory() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root");
    let root = repo_root.join("target/apps-macos-optional-metadata");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("create root");

    let missing_dir = root.join("MissingMacOS.app/Contents");
    fs::create_dir_all(&missing_dir).expect("missing dir contents");
    fs::write(
        missing_dir.join("Info.plist"),
        make_plist("com.example.missing-dir", "Run"),
    )
    .expect("missing dir plist");

    let regular_macos_contents = root.join("MacOSIsFile.app/Contents");
    fs::create_dir_all(&regular_macos_contents).expect("regular MacOS contents");
    fs::write(
        regular_macos_contents.join("Info.plist"),
        make_plist("com.example.macos-file", "Run"),
    )
    .expect("regular MacOS plist");
    fs::write(regular_macos_contents.join("MacOS"), b"not-a-directory").expect("MacOS file");

    let missing_leaf_macos = root.join("MissingLeaf.app/Contents/MacOS");
    fs::create_dir_all(&missing_leaf_macos).expect("missing leaf MacOS dir");
    fs::write(
        root.join("MissingLeaf.app/Contents/Info.plist"),
        make_plist("com.example.missing-leaf", "Run"),
    )
    .expect("missing leaf plist");

    let empty_exec_macos = root.join("EmptyExecutable.app/Contents/MacOS");
    fs::create_dir_all(&empty_exec_macos).expect("empty executable MacOS dir");
    fs::write(
        root.join("EmptyExecutable.app/Contents/Info.plist"),
        make_plist("com.example.empty-exec", ""),
    )
    .expect("empty executable plist");

    let unsafe_exec_macos = root.join("UnsafeExecutable.app/Contents/MacOS");
    fs::create_dir_all(&unsafe_exec_macos).expect("unsafe executable MacOS dir");
    fs::write(
        root.join("UnsafeExecutable.app/Contents/Info.plist"),
        make_plist("com.example.unsafe-exec", "../Run"),
    )
    .expect("unsafe executable plist");

    let inventory = run_inventory(std::slice::from_ref(&root));
    let by_id = |id: &str| {
        inventory
            .apps
            .iter()
            .find(|app| app.bundle_id.value.as_deref() == Some(id))
            .expect("app by bundle id")
    };

    let missing_dir_row = by_id("com.example.missing-dir");
    assert_eq!(missing_dir_row.app_kind.as_str(), "app");
    assert_eq!(missing_dir_row.executable.path_status, PathStatus::Missing);

    let macos_file_row = by_id("com.example.macos-file");
    assert_eq!(macos_file_row.app_kind.as_str(), "app");
    assert_eq!(
        macos_file_row.executable.path_status,
        PathStatus::PresentNonFile
    );

    let missing_leaf_row = by_id("com.example.missing-leaf");
    assert_eq!(missing_leaf_row.app_kind.as_str(), "app");
    assert_eq!(missing_leaf_row.executable.path_status, PathStatus::Missing);

    let empty_exec_row = by_id("com.example.empty-exec");
    assert_eq!(empty_exec_row.app_kind.as_str(), "app");
    assert_eq!(
        empty_exec_row.executable.path_status,
        PathStatus::InvalidDeclaredPath
    );

    let unsafe_exec_row = by_id("com.example.unsafe-exec");
    assert_eq!(unsafe_exec_row.app_kind.as_str(), "app");
    assert_eq!(
        unsafe_exec_row.executable.path_status,
        PathStatus::InvalidDeclaredPath
    );

    let _ = fs::remove_dir_all(&root);
}
