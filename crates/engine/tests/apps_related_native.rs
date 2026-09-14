// SPDX-License-Identifier: MPL-2.0

#![cfg(target_os = "macos")]

use sayaka_engine::app_inventory::{
    AppInventory, AppInventoryCounts, AppInventoryMetrics, AppInventoryStatus, AppKind, AppRecord,
    ExecutableMetadata, NameSource, PathStatus, PlistFormat, StringField, StringState,
};
use sayaka_engine::app_related::preview_app_related_data;
use sayaka_engine::model::{Cancellation, FileIdentity};
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use std::time::Duration;

fn test_root(label: &str) -> PathBuf {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root");
    let root = repo_root.join(format!("target/app-related-native-{label}"));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("create root");
    root
}

fn field(value: Option<&str>) -> StringField {
    StringField {
        state: if value.is_some() {
            StringState::Present
        } else {
            StringState::Missing
        },
        value: value.map(str::to_string),
    }
}

fn firefox_inventory() -> AppInventory {
    AppInventory {
        schema_version: 1,
        kind: "app_inventory",
        platform: "macos",
        status: AppInventoryStatus::Complete,
        complete: true,
        effects_performed: false,
        roots: vec![PathBuf::from("/Applications")],
        filter: String::new(),
        excludes: vec![],
        scan_task_id: "native:1".into(),
        counts: AppInventoryCounts::default(),
        apps: vec![AppRecord {
            bundle_path: PathBuf::from("/Applications/Firefox.app"),
            observed_roots: vec![PathBuf::from("/Applications")],
            bundle_identity: FileIdentity::Unix {
                device: 1,
                inode: 7,
            },
            app_kind: AppKind::App,
            parser_format: PlistFormat::Xml,
            display_name: "Firefox".into(),
            display_name_source: NameSource::BundleDisplayName,
            localized: false,
            bundle_id: field(Some("org.mozilla.firefox")),
            short_version: field(Some("1.0")),
            build_version: field(Some("1")),
            package_type: field(Some("APPL")),
            declared_product_dir_name: field(None),
            executable: ExecutableMetadata {
                state: StringState::Present,
                declared_value: Some("firefox".into()),
                path_status: PathStatus::PresentFile,
            },
        }],
        scan_issues: vec![],
        issues: vec![],
        issues_omitted: 0,
        metrics: AppInventoryMetrics::default(),
    }
}

#[test]
fn symlink_library_root_is_not_followed() {
    let root = test_root("symlink-root");
    let physical = root.join("Physical/Library");
    fs::create_dir_all(&physical).unwrap();
    let alias_parent = root.join("Alias");
    fs::create_dir_all(&alias_parent).unwrap();
    let alias = alias_parent.join("Library");
    symlink(&physical, &alias).unwrap();
    let preview = preview_app_related_data(
        firefox_inventory(),
        vec![PathBuf::from("/Applications")],
        vec![alias.clone()],
        String::new(),
        &Cancellation::default(),
        Duration::from_secs(5),
    );
    assert!(preview.candidates.is_empty());
    assert!(preview.issues.iter().any(|issue| {
        (issue.code == "invalid_root" || issue.code == "not_followed_symlink")
            && issue.path.as_ref().is_some_and(|path| path == &alias)
    }));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn intermediate_symlink_component_is_not_followed() {
    let root = test_root("symlink-intermediate");
    let physical_parent = root.join("Physical");
    let linked_parent = root.join("Linked");
    fs::create_dir_all(physical_parent.join("Library")).unwrap();
    symlink(&physical_parent, &linked_parent).unwrap();
    let preview = preview_app_related_data(
        firefox_inventory(),
        vec![PathBuf::from("/Applications")],
        vec![linked_parent.join("Library")],
        String::new(),
        &Cancellation::default(),
        Duration::from_secs(5),
    );
    assert!(preview.candidates.is_empty());
    assert!(preview.issues.iter().any(|issue| {
        (issue.code == "invalid_root" || issue.code == "not_followed_symlink")
            && issue
                .path
                .as_ref()
                .is_some_and(|path| path == &linked_parent.join("Library"))
    }));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn candidate_symlink_leaf_is_reported_without_following() {
    let root = test_root("symlink-leaf");
    let library = root.join("Library");
    fs::create_dir_all(library.join("Application Support/Firefox")).unwrap();
    fs::create_dir_all(root.join("outside")).unwrap();
    symlink(
        root.join("outside"),
        library.join("Application Support/Firefox/Profiles"),
    )
    .unwrap();
    let preview = preview_app_related_data(
        firefox_inventory(),
        vec![PathBuf::from("/Applications")],
        vec![library.clone()],
        String::new(),
        &Cancellation::default(),
        Duration::from_secs(5),
    );
    let candidate = preview
        .candidates
        .iter()
        .find(|candidate| {
            candidate.source_rule_id == "org.mozilla.firefox.default_profiles.macos.v1"
        })
        .expect("profiles candidate");
    assert_eq!(candidate.path_state, "not_followed_symlink");
    let _ = fs::remove_dir_all(root);
}

#[test]
fn profile_contents_are_not_read_for_directory_probe() {
    let root = test_root("no-descent");
    let library = root.join("Library");
    let profile_root = library.join("Application Support/Firefox/Profiles");
    fs::create_dir_all(profile_root.join("secret")).unwrap();
    fs::write(profile_root.join("secret/passwords.txt"), b"fixture").unwrap();
    let mut permissions = fs::metadata(profile_root.join("secret"))
        .unwrap()
        .permissions();
    permissions.set_mode(0o000);
    fs::set_permissions(profile_root.join("secret"), permissions).unwrap();
    let preview = preview_app_related_data(
        firefox_inventory(),
        vec![PathBuf::from("/Applications")],
        vec![library.clone()],
        String::new(),
        &Cancellation::default(),
        Duration::from_secs(5),
    );
    let candidate = preview
        .candidates
        .iter()
        .find(|candidate| {
            candidate.source_rule_id == "org.mozilla.firefox.default_profiles.macos.v1"
        })
        .expect("profiles candidate");
    assert_eq!(candidate.path_state, "present_directory");
    assert!(
        !preview
            .issues
            .iter()
            .any(|issue| issue.code == "permission_denied")
    );
    let mut restore = fs::metadata(profile_root.join("secret"))
        .unwrap()
        .permissions();
    restore.set_mode(0o700);
    fs::set_permissions(profile_root.join("secret"), restore).unwrap();
    let _ = fs::remove_dir_all(root);
}
