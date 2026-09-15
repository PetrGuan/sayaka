// SPDX-License-Identifier: MPL-2.0

use serde_json::Value;
use std::fs;
use std::io::{BufRead, BufReader, Read};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
#[path = "../../engine/tests/support/owned_temp.rs"]
mod owned_temp;
use owned_temp::OwnedTempDir as TempDir;

const DEADLINE: Duration = Duration::from_secs(30);

#[cfg(target_os = "macos")]
fn history_fixture(fixture: &Fixture) -> PathBuf {
    use sayaka_engine::journal::{ItemRecord, ItemState, NativePath, Record, Store};
    use std::os::unix::fs::OpenOptionsExt;
    let state = fixture.base.join("history-journal");
    drop(Store::open(&state, true).unwrap());
    for (id, created, item_state) in [
        ("a", 1000, ItemState::Started),
        ("b", 2000, ItemState::Failed),
        ("c", 3000, ItemState::Succeeded),
    ] {
        let mut record = Record {
            schema_version: 1,
            plan_schema_version: 2,
            engine_version: 2,
            rules_version: 1,
            operation_id: id.into(),
            contract: "revalidated_trash_v1".into(),
            scope: NativePath::from_path(std::path::Path::new("/fixture")),
            clean_policy: None,
            created_unix_ms: created,
            items: vec![ItemRecord {
                path: NativePath::from_path(&std::path::Path::new("/fixture").join(id)),
                device: 1,
                inode: 2,
                logical_bytes: 1,
                destination: (item_state == ItemState::Succeeded)
                    .then(|| NativePath::from_path(std::path::Path::new("/fixture-trash/item"))),
                state: item_state,
                reason: None,
                rule_binding: None,
                recovery_evidence: None,
                updated_unix_ms: created,
            }],
        };
        record.validate().unwrap();
        let write = |name: &str, record: &Record| {
            let file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(state.join(name))
                .unwrap();
            serde_json::to_writer(file, record).unwrap();
        };
        write(&format!("{id}.json"), &record);
        if id == "c" {
            record.items[0].state = ItemState::Unknown;
            record.items[0].reason = Some("outcome_publication_not_confirmed".into());
            write("c.pending", &record);
        }
    }
    state
}

#[test]
#[cfg(target_os = "macos")]
fn history_filters_whole_reconciled_records_and_retains_global_pending() {
    let fixture = Fixture::new();
    let state = history_fixture(&fixture);
    let before = fs::read(state.join("c.pending")).unwrap();
    let mut command = fixture.command();
    command
        .args(["history", "--json", "--state", "unknown", "--limit", "1"])
        .arg("--state-dir")
        .arg(&state);
    let result = capture(command);
    assert_eq!(result.status.code(), Some(3));
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["history"]["total_records"], 3);
    assert_eq!(value["history"]["matched_records"], 2);
    assert_eq!(value["history"]["records"][0]["operation_id"], "c");
    assert_eq!(
        value["history"]["records"][0]["items"][0]["state"],
        "unknown"
    );
    assert_eq!(value["history"]["uncommitted_snapshots"][0], "c.pending");
    let mut command = fixture.command();
    command
        .args([
            "history",
            "--json",
            "--id",
            "b",
            "--since",
            "1970-01-01T00:00:02Z",
            "--until",
            "1970-01-01T00:00:03Z",
        ])
        .arg("--state-dir")
        .arg(&state);
    let result = capture(command);
    assert_eq!(result.status.code(), Some(3));
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["history"]["matched_records"], 1);
    assert_eq!(value["history"]["records"][0]["operation_id"], "b");
    assert_eq!(value["history"]["uncommitted_snapshots"][0], "c.pending");
    assert_eq!(fs::read(state.join("c.pending")).unwrap(), before);
}

#[test]
#[cfg(target_os = "macos")]
fn history_never_filters_away_corrupt_records_or_creates_missing_state() {
    let fixture = Fixture::new();
    let state = history_fixture(&fixture);
    fs::write(state.join("b.json"), b"{").unwrap();
    let mut command = fixture.command();
    command
        .args(["history", "--json", "--id", "a"])
        .arg("--state-dir")
        .arg(&state);
    let result = capture(command);
    assert_eq!(result.status.code(), Some(1));
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["status"], "failed");
    let missing = fixture.base.join("missing-history");
    let mut command = fixture.command();
    command
        .args(["history", "--json"])
        .arg("--state-dir")
        .arg(&missing);
    assert!(!capture(command).status.success());
    assert!(!missing.exists());
}

#[test]
#[cfg(target_os = "macos")]
fn history_preserves_fractional_boundaries_beyond_nanosecond_precision() {
    let fixture = Fixture::new();
    let state = history_fixture(&fixture);
    for (flag, expected) in [("--until", 1), ("--since", 2)] {
        let mut command = fixture.command();
        command
            .args(["history", "--json", flag, "1970-01-01T00:00:01.0000000001Z"])
            .arg("--state-dir")
            .arg(&state);
        let result = capture(command);
        assert_eq!(result.status.code(), Some(3));
        let value: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(value["history"]["matched_records"], expected);
    }
    let missing = fixture.base.join("missing-state");
    let mut command = fixture.command();
    command
        .args([
            "history",
            "--since",
            "1970-01-01T00:00:01.0000000001Z",
            "--until",
            "1970-01-01T00:00:01Z",
        ])
        .arg("--state-dir")
        .arg(&missing);
    assert_eq!(capture(command).status.code(), Some(2));
    assert!(!missing.exists());
}

#[test]
fn completion_is_stdout_only_and_covers_current_commands() {
    let fixture = Fixture::new();
    for shell in ["bash", "zsh", "fish"] {
        let mut command = fixture.command();
        command.args(["completions", shell]);
        let result = capture(command);
        assert!(result.status.success());
        let script = String::from_utf8(result.stdout).unwrap();
        for name in [
            "history",
            "status",
            "browse",
            "menu",
            "rules",
            "installer",
            "clean",
            "install",
            "update",
            "recover",
            "remove",
        ] {
            assert!(script.contains(name));
        }
        assert!(result.stderr.is_empty());
    }
    assert!(!fixture.base.join("home/.zshrc").exists());
    assert!(!fixture.base.join("home/.bashrc").exists());
}

#[test]
fn menu_requires_interactive_terminal_and_preserves_fixture_state() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("still-there.txt"), b"owned fixture").unwrap();
    let mut command = fixture.command();
    command.arg("menu");
    let output = capture(command);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("menu requires interactive stdin/stdout/stderr"));
    assert_eq!(
        fs::read(fixture.root.join("still-there.txt")).unwrap(),
        b"owned fixture"
    );
    assert!(
        fs::read_dir(fixture.base.join("state"))
            .unwrap()
            .next()
            .is_none()
    );
}

#[test]
fn menu_term_dumb_is_rejected_before_terminal_mode() {
    let fixture = Fixture::new();
    let mut command = fixture.command();
    command.arg("menu").env("TERM", "dumb");
    let output = capture(command);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("TERM != dumb")
    );
}

#[test]
#[cfg(target_os = "macos")]
fn menu_pty_dispatch_signal_and_restore_lifecycle() {
    let mut command = Command::new("python3");
    command
        .arg("scripts/check_menu_pty.py")
        .arg("--binary")
        .arg(env!("CARGO_BIN_EXE_sayaka"))
        .current_dir(
            env!("CARGO_MANIFEST_DIR")
                .rsplit_once("/crates/cli")
                .unwrap()
                .0,
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = command.output().expect("run menu pty script");
    assert!(
        output.status.success(),
        "menu PTY script failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn installer_requires_explicit_root_and_rejects_unknown_flags() {
    let fixture = Fixture::new();
    let mut missing = fixture.command();
    missing.arg("installer");
    let output = capture(missing);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("ROOT"));

    let mut invalid = fixture.command();
    invalid.args(["installer", ".", "--execute"]);
    let output = capture(invalid);
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn installer_json_is_stdout_only_and_never_claims_effects() {
    let fixture = Fixture::new();
    let root = fixture.root.join("installer");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("fake.pkg"), b"not-a-xar").unwrap();
    let mut command = fixture.command();
    command.args(["installer", root.to_str().unwrap(), "--json"]);
    let output = capture(command);
    assert_eq!(output.status.code(), Some(0));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["kind"], "installer_preview");
    assert_eq!(value["status"], "complete");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["effects_performed"], false);
    assert!(!value["candidates"].as_array().unwrap().is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn installer_rejects_exclude_outside_root_before_scan() {
    let fixture = Fixture::new();
    let root = fixture.root.join("installer");
    fs::create_dir(&root).unwrap();
    let outside = fixture.base.join("outside");
    fs::create_dir(&outside).unwrap();
    let mut command = fixture.command();
    command.args([
        "installer",
        root.to_str().unwrap(),
        "--exclude",
        outside.to_str().unwrap(),
        "--json",
    ]);
    let output = capture(command);
    assert_eq!(output.status.code(), Some(2));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["kind"], "installer_preview");
    assert_eq!(value["status"], "failed");
}

fn apps_oracle_root() -> Option<PathBuf> {
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

#[test]
fn apps_requires_explicit_root_and_rejects_out_of_scope_excludes() {
    let fixture = Fixture::new();
    let mut missing = fixture.command();
    missing.arg("apps");
    assert_eq!(capture(missing).status.code(), Some(2));

    let root = fixture.root.join("apps-root");
    fs::create_dir(&root).unwrap();
    let outside = fixture.base.join("outside");
    fs::create_dir(&outside).unwrap();
    let mut invalid = fixture.command();
    invalid.args([
        "apps",
        root.to_str().unwrap(),
        "--exclude",
        outside.to_str().unwrap(),
        "--json",
    ]);
    let output = capture(invalid);
    assert_eq!(output.status.code(), Some(2));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["kind"], "app_inventory");
    assert_eq!(value["status"], "failed");
}

#[test]
fn apps_json_reports_inventory_without_effects() {
    let Some(root) = apps_oracle_root() else {
        return;
    };
    let fixture = Fixture::new();
    let mut command = fixture.command();
    command.args(["apps", root.to_str().unwrap(), "--json"]);
    let output = capture(command);
    assert!(matches!(output.status.code(), Some(0 | 3)));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["kind"], "app_inventory");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["effects_performed"], false);
    assert!(value["status"] == "complete" || value["status"] == "partial");
    assert!(value["apps"].as_array().is_some());
}

#[test]
#[cfg(target_os = "macos")]
fn apps_metrics_do_not_change_with_cr_product_dir_name() {
    let fixture = Fixture::new();
    let with_key_root = fixture.root.join("with-key");
    let without_key_root = fixture.root.join("without-key");
    for (root, with_key) in [(&with_key_root, true), (&without_key_root, false)] {
        let macos = root.join("Google Chrome.app/Contents/MacOS");
        fs::create_dir_all(&macos).unwrap();
        let cr = if with_key {
            "<key>CrProductDirName</key><string>Google/Chrome</string>"
        } else {
            ""
        };
        fs::write(
            root.join("Google Chrome.app/Contents/Info.plist"),
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleDisplayName</key><string>Google Chrome</string><key>CFBundleIdentifier</key><string>com.google.Chrome</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleExecutable</key><string>chrome</string>{cr}</dict></plist>"#
            ),
        )
        .unwrap();
        fs::write(macos.join("chrome"), b"#!/bin/sh\n").unwrap();
    }

    let mut with_key = fixture.command();
    with_key.args(["apps", with_key_root.to_str().unwrap(), "--json"]);
    let with_key_output = capture(with_key);
    assert!(matches!(with_key_output.status.code(), Some(0 | 3)));
    let with_key_json: Value = serde_json::from_slice(&with_key_output.stdout).unwrap();

    let mut without_key = fixture.command();
    without_key.args(["apps", without_key_root.to_str().unwrap(), "--json"]);
    let without_key_output = capture(without_key);
    assert!(matches!(without_key_output.status.code(), Some(0 | 3)));
    let without_key_json: Value = serde_json::from_slice(&without_key_output.stdout).unwrap();

    assert_eq!(
        with_key_json["metrics"]["retained_metadata_string_bytes"],
        without_key_json["metrics"]["retained_metadata_string_bytes"]
    );
}

#[test]
#[cfg(target_os = "macos")]
fn apps_related_uses_declared_product_dir_name_only_in_related_mode() {
    let fixture = Fixture::new();
    let with_key = fixture.root.join("WithKey.app/Contents/MacOS");
    fs::create_dir_all(&with_key).unwrap();
    fs::write(
        fixture.root.join("WithKey.app/Contents/Info.plist"),
        br#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleDisplayName</key><string>Google Chrome</string><key>CFBundleIdentifier</key><string>com.google.Chrome</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleExecutable</key><string>chrome</string><key>CrProductDirName</key><string>Google/Chrome</string></dict></plist>"#,
    )
    .unwrap();
    fs::write(with_key.join("chrome"), b"#!/bin/sh\n").unwrap();

    let without_key = fixture.root.join("WithoutKey.app/Contents/MacOS");
    fs::create_dir_all(&without_key).unwrap();
    fs::write(
        fixture.root.join("WithoutKey.app/Contents/Info.plist"),
        br#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleDisplayName</key><string>Google Chrome</string><key>CFBundleIdentifier</key><string>com.google.Chrome</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleExecutable</key><string>chrome</string></dict></plist>"#,
    )
    .unwrap();
    fs::write(without_key.join("chrome"), b"#!/bin/sh\n").unwrap();

    let library = fixture.base.join("home/Library");
    fs::create_dir_all(library.join("Application Support/Google/Chrome")).unwrap();
    let mut command = fixture.command();
    command.args([
        "apps-related",
        "--app-root",
        fixture.root.to_str().unwrap(),
        "--library-root",
        library.to_str().unwrap(),
        "--json",
    ]);
    let output = capture(command);
    assert!(matches!(output.status.code(), Some(0 | 3)));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    let chrome_candidate = value["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .find(|candidate| {
            candidate["source_rule_id"] == "org.chromium.default_user_data.macos.v1"
                && candidate["relative_library_path"] == "Application Support/Google/Chrome"
        })
        .unwrap();
    let matched = chrome_candidate["matched_app_copy_ids"].as_array().unwrap();
    assert_eq!(matched.len(), 1);
}

#[test]
#[cfg(target_os = "macos")]
fn apps_related_requires_explicit_roots() {
    let fixture = Fixture::new();
    let mut command = fixture.command();
    command.arg("apps-related").arg("--json");
    let output = capture(command);
    assert_eq!(output.status.code(), Some(2));
}

#[test]
#[cfg(target_os = "macos")]
fn apps_related_json_is_read_only_and_never_authorizes_actions() {
    let fixture = Fixture::new();
    let app = fixture.root.join("Firefox.app/Contents/MacOS");
    fs::create_dir_all(&app).unwrap();
    fs::write(
        fixture.root.join("Firefox.app/Contents/Info.plist"),
        br#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleDisplayName</key><string>Firefox</string><key>CFBundleIdentifier</key><string>org.mozilla.firefox</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleExecutable</key><string>firefox</string></dict></plist>"#,
    )
    .unwrap();
    fs::write(app.join("firefox"), b"#!/bin/sh\n").unwrap();
    fs::create_dir_all(
        fixture
            .base
            .join("home/Library/Application Support/Firefox/Profiles"),
    )
    .unwrap();
    let mut command = fixture.command();
    command.args([
        "apps-related",
        "--app-root",
        fixture.root.to_str().unwrap(),
        "--library-root",
        fixture.base.join("home/Library").to_str().unwrap(),
        "--json",
    ]);
    let output = capture(command);
    assert!(matches!(output.status.code(), Some(0 | 3)));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["kind"], "app_related_data_preview");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["effects_performed"], false);
    for candidate in value["candidates"].as_array().unwrap() {
        assert_eq!(candidate["deletable"], false);
        assert!(candidate["authorized_action"].is_null());
        assert_eq!(
            candidate["preview_disposition"],
            "protect_for_manual_review"
        );
    }
}

#[test]
#[cfg(target_os = "macos")]
fn apps_related_json_preserves_malformed_plist_inventory_issue() {
    let fixture = Fixture::new();
    let app = fixture.root.join("Broken.app/Contents/MacOS");
    fs::create_dir_all(&app).unwrap();
    fs::write(
        fixture.root.join("Broken.app/Contents/Info.plist"),
        br#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleDisplayName</key><string>Broken</string>"#,
    )
    .unwrap();
    fs::write(app.join("broken"), b"#!/bin/sh\n").unwrap();
    let library = fixture.base.join("home/Library");
    fs::create_dir_all(library.join("Application Support/com.example.broken")).unwrap();
    let mut command = fixture.command();
    command.args([
        "apps-related",
        "--app-root",
        fixture.root.to_str().unwrap(),
        "--library-root",
        library.to_str().unwrap(),
        "--json",
    ]);
    let output = capture(command);
    assert_eq!(output.status.code(), Some(3));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "partial");
    assert_eq!(value["inventory_status"], "partial");
    assert!(value["issues"].as_array().unwrap().iter().any(|issue| {
        issue["code"] == "malformed_plist"
            && issue["message"]
                .as_str()
                .is_some_and(|message| message.contains("plist"))
    }));
}

#[test]
#[cfg(target_os = "macos")]
fn apps_related_rejects_non_library_leaf_root() {
    let fixture = Fixture::new();
    let app = fixture.root.join("Demo.app/Contents/MacOS");
    fs::create_dir_all(&app).unwrap();
    fs::write(
        fixture.root.join("Demo.app/Contents/Info.plist"),
        br#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleDisplayName</key><string>Demo</string><key>CFBundleIdentifier</key><string>com.example.demo</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleExecutable</key><string>demo</string></dict></plist>"#,
    )
    .unwrap();
    fs::write(app.join("demo"), b"#!/bin/sh\n").unwrap();
    let mut command = fixture.command();
    command.args([
        "apps-related",
        "--app-root",
        fixture.root.to_str().unwrap(),
        "--library-root",
        fixture.base.join("home").to_str().unwrap(),
        "--json",
    ]);
    let output = capture(command);
    assert_eq!(output.status.code(), Some(2));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["kind"], "app_related_data_preview");
    assert_eq!(value["status"], "failed");
    assert_eq!(value["issues"][0]["code"], "invalid_root");
}

#[test]
#[cfg(target_os = "macos")]
fn apps_related_filter_narrows_displayed_candidates_and_counters() {
    let fixture = Fixture::new();
    let chrome = fixture.root.join("Google Chrome.app/Contents/MacOS");
    fs::create_dir_all(&chrome).unwrap();
    fs::write(
        fixture.root.join("Google Chrome.app/Contents/Info.plist"),
        br#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleDisplayName</key><string>Google Chrome</string><key>CFBundleIdentifier</key><string>com.google.Chrome</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleExecutable</key><string>chrome</string><key>CrProductDirName</key><string>Google/Chrome</string></dict></plist>"#,
    )
    .unwrap();
    fs::write(chrome.join("chrome"), b"#!/bin/sh\n").unwrap();
    let demo = fixture.root.join("Demo.app/Contents/MacOS");
    fs::create_dir_all(&demo).unwrap();
    fs::write(
        fixture.root.join("Demo.app/Contents/Info.plist"),
        br#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleDisplayName</key><string>Demo</string><key>CFBundleIdentifier</key><string>com.example.demo</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleExecutable</key><string>demo</string></dict></plist>"#,
    )
    .unwrap();
    fs::write(demo.join("demo"), b"#!/bin/sh\n").unwrap();
    let library = fixture.base.join("home/Library");
    fs::create_dir_all(library.join("Application Support/Google/Chrome")).unwrap();
    fs::create_dir_all(library.join("Application Support/com.example.demo")).unwrap();
    let mut command = fixture.command();
    command.args([
        "apps-related",
        "--app-root",
        fixture.root.to_str().unwrap(),
        "--library-root",
        library.to_str().unwrap(),
        "--filter",
        "Chrome",
        "--json",
    ]);
    let output = capture(command);
    assert!(matches!(output.status.code(), Some(0 | 3)));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    let candidates = value["candidates"].as_array().unwrap();
    assert!(!candidates.is_empty());
    assert!(candidates.iter().all(|candidate| {
        !candidate["relative_library_path"]
            .as_str()
            .unwrap()
            .contains("com.example.demo")
    }));
    assert_eq!(value["counts"]["candidate_paths"], candidates.len());
    assert_eq!(value["counts"]["protected_candidates"], candidates.len());
}

#[test]
#[cfg(target_os = "macos")]
fn apps_related_human_output_stays_protective() {
    let fixture = Fixture::new();
    let app = fixture.root.join("Demo.app/Contents/MacOS");
    fs::create_dir_all(&app).unwrap();
    fs::write(
        fixture.root.join("Demo.app/Contents/Info.plist"),
        br#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleDisplayName</key><string>Demo</string><key>CFBundleIdentifier</key><string>com.example.demo</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleExecutable</key><string>demo</string></dict></plist>"#,
    )
    .unwrap();
    fs::write(app.join("demo"), b"#!/bin/sh\n").unwrap();
    let library = fixture.base.join("home/Library");
    fs::create_dir_all(library.join("Application Support/com.example.demo")).unwrap();
    let mut command = fixture.command();
    command.args([
        "apps-related",
        "--app-root",
        fixture.root.to_str().unwrap(),
        "--library-root",
        library.to_str().unwrap(),
    ]);
    let output = capture(command);
    assert!(matches!(output.status.code(), Some(0 | 3)));
    let text = String::from_utf8(output.stdout)
        .unwrap()
        .to_ascii_lowercase();
    assert!(text.contains("effects_performed: false"));
    for banned in ["safe to remove", "orphan", "reclaimable", "delete"] {
        assert!(!text.contains(banned), "{banned}");
    }
}

#[test]
#[cfg(target_os = "macos")]
fn apps_related_human_renders_scan_issues_and_preview_issues_with_escaped_text() {
    let fixture = Fixture::new();
    let broken = fixture.root.join("Broken.app/Contents/MacOS");
    fs::create_dir_all(&broken).unwrap();
    fs::write(
        fixture.root.join("Broken.app/Contents/Info.plist"),
        br#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleDisplayName</key><string>Broken</string>"#,
    )
    .unwrap();
    fs::write(broken.join("broken"), b"#!/bin/sh\n").unwrap();
    let missing = fixture.root.join("missing\n\u{1b}[2J");
    let library = fixture.base.join("home/Library");
    fs::create_dir_all(&library).unwrap();
    let mut command = fixture.command();
    command.args([
        "apps-related",
        "--app-root",
        fixture.root.to_str().unwrap(),
        "--app-root",
        missing.to_str().unwrap(),
        "--library-root",
        library.to_str().unwrap(),
    ]);
    let output = capture(command);
    assert_eq!(output.status.code(), Some(3));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("scan issues:"));
    assert!(text.contains("issues:"));
    assert!(text.contains("not_found"));
    assert!(text.contains("malformed_plist"));
    assert!(text.contains("\\n"));
    assert!(!text.contains('\x1b'));
}

#[test]
#[cfg(target_os = "macos")]
fn apps_related_missing_app_root_is_exit1_with_matching_human_and_json_diagnostic() {
    let fixture = Fixture::new();
    let missing = fixture.root.join("missing\n\u{1b}[2J");
    let library = fixture.base.join("home/Library");
    fs::create_dir_all(&library).unwrap();

    let mut human = fixture.command();
    human.args([
        "apps-related",
        "--app-root",
        missing.to_str().unwrap(),
        "--library-root",
        library.to_str().unwrap(),
    ]);
    let human = capture(human);
    assert_eq!(human.status.code(), Some(1));
    let human_text = format!(
        "{}{}",
        String::from_utf8(human.stdout).unwrap(),
        String::from_utf8(human.stderr).unwrap()
    );
    assert!(
        human_text.contains("Path not found") || human_text.contains("not_found"),
        "{human_text}"
    );
    assert!(human_text.contains("\\n"));
    assert!(!human_text.contains('\x1b'));

    let mut json = fixture.command();
    json.args([
        "apps-related",
        "--app-root",
        missing.to_str().unwrap(),
        "--library-root",
        library.to_str().unwrap(),
        "--json",
    ]);
    let json = capture(json);
    assert_eq!(json.status.code(), Some(1));
    let value: Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(value["kind"], "app_related_data_preview");
    assert_eq!(value["status"], "failed");
    let has_not_found = value["scan_issues"].as_array().is_some_and(|issues| {
        issues.iter().any(|issue| {
            issue["code"] == "not_found"
                && issue["path"]["display"]
                    .as_str()
                    .is_some_and(|path| path.contains("\\n"))
        })
    }) || value["issues"].as_array().is_some_and(|issues| {
        issues.iter().any(|issue| {
            issue["code"] == "not_found"
                && issue["message"]
                    .as_str()
                    .is_some_and(|message| message.contains("\\n"))
        })
    });
    assert!(has_not_found, "{value}");
}

#[test]
fn rules_list_human_and_json_catalog_expose_read_only_actions() {
    let fixture = Fixture::new();
    let mut command = fixture.command();
    command.args(["rules", "list"]);
    let human = capture(command);
    assert!(human.status.success());
    let text = String::from_utf8(human.stdout).unwrap();
    assert!(text.contains("org.python.cpython.pep3147.source_backed_pyc"));
    assert!(text.contains("org.openjdk.javac.source_backed_class"));
    assert!(text.contains("preview_only"));
    assert!(text.contains("manual_review"));

    let mut command = fixture.command();
    command.args(["rules", "list", "--json"]);
    let json = capture(command);
    assert_eq!(json.status.code(), Some(0));
    let value: Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(value["kind"], "rule_catalog");
    let rules = value["rules"].as_array().unwrap();
    assert!(rules.iter().any(|rule| {
        rule["id"] == "org.python.cpython.pep3147.source_backed_pyc"
            && rule["actions"][0] == "preview_only"
            && rule["actions"][1] == "manual_review"
            && rule["actions"][2] == "explicit_native_trash"
    }));
    assert!(rules.iter().any(|rule| {
        rule["id"] == "org.openjdk.javac.source_backed_class"
            && rule["actions"][0] == "preview_only"
            && rule["actions"][1] == "manual_review"
            && rule["actions"][2] == "explicit_native_trash"
    }));
}

#[test]
fn bare_rules_requires_subcommand_and_prints_usage() {
    let fixture = Fixture::new();
    let mut command = fixture.command();
    command.arg("rules");
    let result = capture(command);
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
    let stderr = String::from_utf8(result.stderr).unwrap();
    assert!(stderr.contains("Usage:"));
    assert!(stderr.contains("rules"));
}

#[test]
fn rules_preview_requires_explicit_inputs_and_rejects_unknown_rule() {
    let fixture = Fixture::new();
    let mut command = fixture.command();
    command.args(["rules", "preview"]);
    assert_eq!(capture(command).status.code(), Some(2));

    let mut command = fixture.command();
    command.args(["rules", "preview", ".", "--rule", "invalid", "--json"]);
    let result = capture(command);
    assert_eq!(result.status.code(), Some(2));
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["kind"], "rule_preview");
    assert_eq!(value["status"], "failed");
    assert!(
        value["issues"][0]["message"]
            .as_str()
            .unwrap()
            .contains("unknown rule ID")
    );
    assert!(result.stderr.is_empty());
}

#[test]
fn rules_preview_unknown_rule_fails_before_scan_or_progress() {
    let fixture = Fixture::new();
    let mut command = fixture.command();
    let missing = fixture.root.join("does-not-exist");
    command.args([
        "rules",
        "preview",
        missing.to_str().unwrap(),
        "--rule",
        "invalid",
        "--json",
        "--progress",
    ]);
    let result = capture(command);
    assert_eq!(result.status.code(), Some(2));
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["kind"], "rule_preview");
    assert_eq!(value["issues"][0]["code"], "invalid_root");
    assert!(
        value["issues"][0]["message"]
            .as_str()
            .unwrap()
            .contains("unknown rule ID")
    );
    assert!(
        result.stderr.is_empty(),
        "{:?}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn rules_preview_invalid_root_json_is_structured_and_no_progress() {
    let fixture = Fixture::new();
    let mut command = fixture.command();
    command.args([
        "rules",
        "preview",
        "root/../home",
        "--rule",
        "org.python.cpython.pep3147.source_backed_pyc",
        "--json",
        "--progress",
    ]);
    let result = capture(command);
    assert_eq!(result.status.code(), Some(2));
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["kind"], "rule_preview");
    assert_eq!(value["status"], "failed");
    assert_eq!(value["issues"][0]["code"], "invalid_root");
    assert!(result.stderr.is_empty());
}

#[test]
fn rules_preview_json_reports_candidates_source_relation_refusals_and_no_effects() {
    let fixture = Fixture::new();
    let root = fixture.root.join("pkg");
    fs::create_dir(&root).unwrap();
    fs::create_dir(root.join("__pycache__")).unwrap();
    fs::write(root.join("module.py"), b"print('ok')\n").unwrap();
    fs::write(
        root.join("__pycache__/module.cpython-39.pyc"),
        vec![3_u8; 218],
    )
    .unwrap();
    fs::write(
        root.join("__pycache__/missing.cpython-39.pyc"),
        vec![4_u8; 21],
    )
    .unwrap();
    fs::write(root.join("legacy.pyc"), vec![5_u8; 12]).unwrap();
    let mut command = fixture.command();
    command.args([
        "rules",
        "preview",
        fixture.root.to_str().unwrap(),
        "--rule",
        "org.python.cpython.pep3147.source_backed_pyc",
        "--json",
    ]);
    let output = capture(command);
    assert_eq!(output.status.code(), Some(3));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["kind"], "rule_preview");
    assert_eq!(
        value["rule_id"],
        "org.python.cpython.pep3147.source_backed_pyc"
    );
    assert_eq!(value["effects_performed"], false);
    assert_eq!(value["candidates"].as_array().unwrap().len(), 1);
    let candidate = &value["candidates"][0];
    assert_eq!(candidate["action"], "manual_review");
    assert!(
        candidate["source_path"]["display"]
            .as_str()
            .unwrap()
            .contains("module.py")
    );
    assert!(
        candidate["target_path"]["display"]
            .as_str()
            .unwrap()
            .contains("__pycache__")
    );
    assert_eq!(value["matched_bytes_known"], 218);
    assert!(value["refusals"].as_array().unwrap().iter().any(|item| {
        item["code"] == "source_missing"
            && item["path"]["display"]
                .as_str()
                .unwrap()
                .contains("missing.cpython-39.pyc")
    }));
    assert!(value["refusals"].as_array().unwrap().iter().any(|item| {
        item["code"] == "not_pycache_child"
            && item["path"]["display"]
                .as_str()
                .unwrap()
                .contains("legacy.pyc")
    }));
    assert!(
        fs::read_dir(fixture.base.join("state"))
            .unwrap()
            .next()
            .is_none()
    );
}

#[test]
fn rules_preview_javac_json_reports_marker_and_source_relation() {
    let fixture = Fixture::new();
    let root = fixture.root.join("javac");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("Foo.java"), b"class Foo {}\n").unwrap();
    fs::write(
        root.join("Foo.class"),
        [0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x3D],
    )
    .unwrap();
    fs::write(root.join("Wrong.java"), b"class Wrong {}\n").unwrap();
    fs::write(root.join("Wrong.class"), [0x00, 0x00, 0x00, 0x00]).unwrap();
    let mut command = fixture.command();
    command.args([
        "rules",
        "preview",
        fixture.root.to_str().unwrap(),
        "--rule",
        "org.openjdk.javac.source_backed_class",
        "--json",
    ]);
    let output = capture(command);
    assert_eq!(output.status.code(), Some(3));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["rule_id"], "org.openjdk.javac.source_backed_class");
    let candidates = value["candidates"].as_array().unwrap();
    assert_eq!(candidates.len(), 1);
    let candidate = &candidates[0];
    assert_eq!(candidate["source_relation"], "same_stem_sibling");
    assert_eq!(candidate["observed_target_marker"], "cafebabe");
    assert!(
        value["refusals"]
            .as_array()
            .unwrap()
            .iter()
            .any(|refusal| refusal["code"] == "target_marker_mismatch")
    );
}

#[test]
fn rules_preview_json_propagates_scan_issue_details() {
    let fixture = Fixture::new();
    let mut command = fixture.command();
    command.args([
        "rules",
        "preview",
        fixture.root.join("missing").to_str().unwrap(),
        "--rule",
        "org.python.cpython.pep3147.source_backed_pyc",
        "--json",
    ]);
    let output = capture(command);
    assert_eq!(output.status.code(), Some(3));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["kind"], "rule_preview");
    assert!(!value["complete"].as_bool().unwrap());
    assert!(value["issues"].as_array().unwrap().iter().any(|issue| {
        issue["code"] == "not_found"
            && issue["path"]["display"]
                .as_str()
                .unwrap()
                .contains("missing")
    }));
    assert!(
        value["refusals"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["code"] == "scan_incomplete")
    );
}

#[test]
fn rules_trash_rejects_json_execute_combo() {
    let fixture = Fixture::new();
    let mut command = fixture.command();
    command.args([
        "rules",
        "trash",
        fixture.root.to_str().unwrap(),
        "--rule",
        "org.python.cpython.pep3147.source_backed_pyc",
        "--select",
        "missing.pyc",
        "--json",
        "--execute",
    ]);
    let result = capture(command);
    assert_eq!(result.status.code(), Some(2));
}

#[test]
#[cfg(target_os = "macos")]
fn rules_trash_unknown_rule_is_exit2_json_invalid_input_and_no_state() {
    let fixture = Fixture::new();
    let state = fixture.base.join("rules-trash-unknown-rule-state");
    let pseudo_select = fixture.root.join("pkg/__pycache__/module.cpython-39.pyc");
    let mut command = fixture.command();
    command.args([
        "rules",
        "trash",
        fixture.root.to_str().unwrap(),
        "--rule",
        "invalid",
        "--select",
        pseudo_select.to_str().unwrap(),
        "--json",
        "--state-dir",
        state.to_str().unwrap(),
    ]);
    let result = capture(command);
    assert_eq!(result.status.code(), Some(2));
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["kind"], "rule_trash");
    assert_eq!(value["status"], "failed");
    assert_eq!(value["error"]["code"], "InvalidInput");
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("unknown rule ID")
    );
    assert!(!state.exists());
}

#[test]
#[cfg(target_os = "macos")]
fn rules_trash_invalid_select_is_exit2_json_invalid_input_and_no_state() {
    let fixture = Fixture::new();
    let pkg = fixture.root.join("pkg");
    fs::create_dir_all(&pkg).unwrap();
    let not_pyc = pkg.join("module.py");
    fs::write(&not_pyc, b"print('x')\n").unwrap();
    let state = fixture.base.join("rules-trash-invalid-select-state");
    let mut command = fixture.command();
    command.args([
        "rules",
        "trash",
        fixture.root.to_str().unwrap(),
        "--rule",
        "org.python.cpython.pep3147.source_backed_pyc",
        "--select",
        not_pyc.to_str().unwrap(),
        "--json",
        "--state-dir",
        state.to_str().unwrap(),
    ]);
    let result = capture(command);
    assert_eq!(result.status.code(), Some(2));
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["kind"], "rule_trash");
    assert_eq!(value["status"], "failed");
    assert_eq!(value["error"]["code"], "InvalidInput");
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("invalid --select target")
    );
    assert!(!state.exists());
}

#[test]
#[cfg(target_os = "macos")]
fn rules_trash_too_many_select_is_exit2_json_invalid_input_and_no_state() {
    let fixture = Fixture::new();
    let state = fixture.base.join("rules-trash-too-many-select-state");
    let mut command = fixture.command();
    command.args([
        "rules",
        "trash",
        fixture.root.to_str().unwrap(),
        "--rule",
        "org.python.cpython.pep3147.source_backed_pyc",
        "--json",
        "--state-dir",
        state.to_str().unwrap(),
    ]);
    for index in 0..33 {
        let select = fixture
            .root
            .join(format!("pkg/__pycache__/module{index}.cpython-39.pyc"));
        command.arg("--select").arg(select);
    }
    let result = capture(command);
    assert_eq!(result.status.code(), Some(2));
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["kind"], "rule_trash");
    assert_eq!(value["status"], "failed");
    assert_eq!(value["error"]["code"], "InvalidInput");
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("too many --select values")
    );
    assert!(!state.exists());
}

#[test]
#[cfg(target_os = "macos")]
fn rules_trash_too_many_exclude_is_exit2_json_invalid_input_and_no_state() {
    let fixture = Fixture::new();
    let state = fixture.base.join("rules-trash-too-many-exclude-state");
    let mut command = fixture.command();
    let select = fixture.root.join("pkg/__pycache__/module.cpython-39.pyc");
    command.args([
        "rules",
        "trash",
        fixture.root.to_str().unwrap(),
        "--rule",
        "org.python.cpython.pep3147.source_backed_pyc",
        "--select",
        select.to_str().unwrap(),
        "--json",
        "--state-dir",
        state.to_str().unwrap(),
    ]);
    for index in 0..33 {
        let excluded = fixture.root.join(format!("pkg/excluded-{index}"));
        command.arg("--exclude").arg(excluded);
    }
    let result = capture(command);
    assert_eq!(result.status.code(), Some(2));
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["kind"], "rule_trash");
    assert_eq!(value["status"], "failed");
    assert_eq!(value["error"]["code"], "InvalidInput");
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("too many --exclude values")
    );
    assert!(!state.exists());
}

#[test]
#[cfg(target_os = "macos")]
fn rules_trash_accepts_exactly_32_select_values() {
    let fixture = Fixture::new();
    let mut command = fixture.command();
    command.args([
        "rules",
        "trash",
        fixture.root.to_str().unwrap(),
        "--rule",
        "org.python.cpython.pep3147.source_backed_pyc",
        "--json",
    ]);
    for index in 0..32 {
        let select = fixture
            .root
            .join(format!("pkg/__pycache__/module{index}.cpython-39.pyc"));
        command.arg("--select").arg(select);
    }
    let result = capture(command);
    assert_ne!(result.status.code(), Some(2));
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_ne!(value["error"]["code"], "InvalidInput");
}

#[test]
#[cfg(target_os = "macos")]
fn rules_trash_preview_is_read_only_and_emits_rule_binding() {
    let fixture = Fixture::new();
    let pkg = fixture.root.join("pkg");
    fs::create_dir_all(pkg.join("__pycache__")).unwrap();
    fs::write(pkg.join("module.py"), b"print('ok')\n").unwrap();
    let pyc = pkg.join("__pycache__/module.cpython-39.pyc");
    fs::write(&pyc, vec![9_u8; 64]).unwrap();
    let state = fixture.base.join("rules-trash-state");
    let mut command = fixture.command();
    command.args([
        "rules",
        "trash",
        fixture.root.to_str().unwrap(),
        "--rule",
        "org.python.cpython.pep3147.source_backed_pyc",
        "--select",
        pyc.to_str().unwrap(),
        "--json",
        "--state-dir",
        state.to_str().unwrap(),
    ]);
    let output = capture(command);
    assert!(matches!(output.status.code(), Some(0 | 3)));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["kind"], "rule_trash_preview");
    assert_eq!(value["plan_schema_version"], 3);
    assert_eq!(value["effects_performed"], false);
    let items = value["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{value}");
    assert_eq!(
        items[0]["rule_binding"]["rule_id"],
        "org.python.cpython.pep3147.source_backed_pyc"
    );
    assert_eq!(items[0]["rule_binding"]["schema_version"], 1);
    assert!(
        items[0]["rule_binding"]["source"]["display"]
            .as_str()
            .unwrap()
            .contains("module.py")
    );
    assert!(!state.exists());
}

#[test]
#[cfg(target_os = "macos")]
fn clean_preview_json_uses_policy_without_creating_absent_config() {
    let fixture = Fixture::new();
    let pkg = fixture.root.join("pkg");
    fs::create_dir_all(pkg.join("__pycache__")).unwrap();
    fs::write(pkg.join("module.py"), b"print('ok')\n").unwrap();
    fs::write(
        pkg.join("__pycache__/module.cpython-39.pyc"),
        vec![1_u8; 11],
    )
    .unwrap();
    let config = fixture.base.join("clean-config");
    let state = fixture.base.join("clean-state");
    let mut command = fixture.command();
    command.args([
        "clean",
        fixture.root.to_str().unwrap(),
        "--json",
        "--config-dir",
        config.to_str().unwrap(),
        "--state-dir",
        state.to_str().unwrap(),
    ]);
    let result = capture(command);
    assert_eq!(result.status.code(), Some(0));
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["kind"], "clean_preview");
    assert_eq!(value["effects_performed"], false);
    assert_eq!(value["policy_file_state"]["state"], "absent");
    assert_eq!(value["counts"]["selected"], 0);
    assert_eq!(value["counts"]["refused"], 0);
    assert_eq!(value["counts"]["eligible"], 1);
    assert!(!config.exists());
    assert!(!state.exists());
}

#[test]
#[cfg(target_os = "macos")]
fn clean_default_rule_stays_cpython_and_explicit_rule_switches_to_javac() {
    let fixture = Fixture::new();
    let root = fixture.root.join("clean-rules");
    fs::create_dir_all(root.join("pkg/__pycache__")).unwrap();
    fs::create_dir_all(root.join("javac")).unwrap();
    fs::write(root.join("pkg/module.py"), b"print('ok')\n").unwrap();
    fs::write(
        root.join("pkg/__pycache__/module.cpython-39.pyc"),
        vec![1_u8; 16],
    )
    .unwrap();
    fs::write(root.join("javac/Foo.java"), b"class Foo {}\n").unwrap();
    fs::write(
        root.join("javac/Foo.class"),
        [0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x3D],
    )
    .unwrap();

    let mut default_clean = fixture.command();
    default_clean.args(["clean", root.to_str().unwrap(), "--json"]);
    let default_out = capture(default_clean);
    assert_eq!(default_out.status.code(), Some(0));
    let default_json: Value = serde_json::from_slice(&default_out.stdout).unwrap();
    assert_eq!(
        default_json["rule_id"],
        "org.python.cpython.pep3147.source_backed_pyc"
    );
    assert_eq!(default_json["counts"]["filtered"], 1);
    assert!(
        default_json["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| {
                item["target"]
                    .as_str()
                    .is_some_and(|path| path.contains("__pycache__"))
            })
    );

    let mut javac_clean = fixture.command();
    javac_clean.args([
        "clean",
        root.to_str().unwrap(),
        "--rule",
        "org.openjdk.javac.source_backed_class",
        "--json",
    ]);
    let javac_out = capture(javac_clean);
    assert_eq!(javac_out.status.code(), Some(0));
    let javac_json: Value = serde_json::from_slice(&javac_out.stdout).unwrap();
    assert_eq!(
        javac_json["rule_id"],
        "org.openjdk.javac.source_backed_class"
    );
    assert_eq!(javac_json["counts"]["filtered"], 1);
    assert!(javac_json["items"].as_array().unwrap().iter().all(|item| {
        item["target"]
            .as_str()
            .is_some_and(|path| path.contains("Foo.class"))
    }));
}

#[test]
#[cfg(target_os = "macos")]
fn clean_exclusions_add_list_remove_and_remove_root_are_explicit_config_updates() {
    let fixture = Fixture::new();
    let pkg = fixture.root.join("pkg");
    fs::create_dir_all(pkg.join("__pycache__")).unwrap();
    let keep = pkg.join("keep");
    fs::create_dir(&keep).unwrap();
    fs::write(pkg.join("module.py"), b"print('ok')\n").unwrap();
    fs::write(pkg.join("__pycache__/module.cpython-39.pyc"), vec![2_u8; 9]).unwrap();
    let config = fixture.base.join("clean-config");

    let mut command = fixture.command();
    command.args([
        "clean",
        "exclusions",
        "add",
        fixture.root.to_str().unwrap(),
        keep.to_str().unwrap(),
        "--config-dir",
        config.to_str().unwrap(),
    ]);
    let add = capture(command);
    assert_eq!(add.status.code(), Some(0));
    assert!(config.join("exclusions-v1.json").is_file());

    let mut command = fixture.command();
    command.args([
        "clean",
        "exclusions",
        "list",
        fixture.root.to_str().unwrap(),
        "--json",
        "--config-dir",
        config.to_str().unwrap(),
    ]);
    let listed = capture(command);
    assert_eq!(listed.status.code(), Some(0));
    let listed: Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(listed["entries"].as_array().unwrap().len(), 1);
    assert!(!listed["entries"][0]["missing_attention"].as_bool().unwrap());

    fs::remove_dir_all(&keep).unwrap();
    let mut command = fixture.command();
    command.args([
        "clean",
        fixture.root.to_str().unwrap(),
        "--json",
        "--config-dir",
        config.to_str().unwrap(),
    ]);
    let blocked = capture(command);
    assert_eq!(blocked.status.code(), Some(3));
    let blocked: Value = serde_json::from_slice(&blocked.stdout).unwrap();
    assert_eq!(blocked["counts"]["eligible"], 1);
    assert_eq!(
        blocked["missing_attention_entries"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(blocked["counts"]["persisted_excluded"], 0);
    assert_eq!(blocked["counts"]["refused"], 1);

    let mut command = fixture.command();
    command.args([
        "clean",
        "exclusions",
        "remove",
        fixture.root.to_str().unwrap(),
        Path::new("pkg/keep").to_str().unwrap(),
        "--config-dir",
        config.to_str().unwrap(),
    ]);
    assert_eq!(capture(command).status.code(), Some(0));

    let mut command = fixture.command();
    command.args([
        "clean",
        "exclusions",
        "remove-root",
        fixture.root.to_str().unwrap(),
        "--config-dir",
        config.to_str().unwrap(),
    ]);
    assert_eq!(capture(command).status.code(), Some(0));
}

#[test]
#[cfg(target_os = "macos")]
fn clean_preview_treats_persisted_exclusions_as_intentional_not_refused() {
    let fixture = Fixture::new();
    let pkg = fixture.root.join("pkg");
    fs::create_dir_all(pkg.join("__pycache__")).unwrap();
    let keep = pkg.join("__pycache__");
    fs::write(pkg.join("module.py"), b"print('ok')\n").unwrap();
    fs::write(pkg.join("__pycache__/module.cpython-39.pyc"), vec![3_u8; 9]).unwrap();
    let config = fixture.base.join("clean-config");
    let mut add = fixture.command();
    add.args([
        "clean",
        "exclusions",
        "add",
        fixture.root.to_str().unwrap(),
        keep.to_str().unwrap(),
        "--config-dir",
        config.to_str().unwrap(),
    ]);
    assert_eq!(capture(add).status.code(), Some(0));
    let mut command = fixture.command();
    command.args([
        "clean",
        fixture.root.to_str().unwrap(),
        "--json",
        "--config-dir",
        config.to_str().unwrap(),
    ]);
    let output = capture(command);
    assert_eq!(output.status.code(), Some(0));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["counts"]["persisted_excluded"], 1);
    assert_eq!(value["counts"]["refused"], 0);
    assert_eq!(value["counts"]["selected"], 0);
}

#[test]
#[cfg(target_os = "macos")]
fn clean_exclusions_remove_absolute_outside_root_is_invalid_input() {
    let fixture = Fixture::new();
    let pkg = fixture.root.join("pkg");
    fs::create_dir_all(pkg.join("__pycache__")).unwrap();
    fs::write(pkg.join("module.py"), b"print('ok')\n").unwrap();
    fs::write(pkg.join("__pycache__/module.cpython-39.pyc"), vec![4_u8; 9]).unwrap();
    let config = fixture.base.join("clean-config");
    let outside = fixture.base.join("outside");
    fs::create_dir(&outside).unwrap();
    let mut command = fixture.command();
    command.args([
        "clean",
        "exclusions",
        "remove",
        fixture.root.to_str().unwrap(),
        outside.to_str().unwrap(),
        "--config-dir",
        config.to_str().unwrap(),
    ]);
    let output = capture(command);
    assert_eq!(output.status.code(), Some(2));
}

#[test]
#[cfg(target_os = "macos")]
fn clean_exclusions_list_parent_traversal_json_reports_structured_invalid_input() {
    let fixture = Fixture::new();
    let config = fixture.base.join("clean-config");
    let mut command = fixture.command();
    command.args([
        "clean",
        "exclusions",
        "list",
        "../..",
        "--json",
        "--config-dir",
        config.to_str().unwrap(),
    ]);
    let output = capture(command);
    assert_eq!(output.status.code(), Some(2));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["kind"], "clean exclusions");
    assert_eq!(value["status"], "failed");
    assert_eq!(value["error"]["code"], "InvalidInput");
    assert!(output.stderr.is_empty());
    assert!(!config.exists());
}

#[test]
#[cfg(target_os = "macos")]
fn clean_exclusions_list_parent_traversal_human_stderr() {
    let fixture = Fixture::new();
    let config = fixture.base.join("clean-config");
    let mut command = fixture.command();
    command.args([
        "clean",
        "exclusions",
        "list",
        "../..",
        "--config-dir",
        config.to_str().unwrap(),
    ]);
    let output = capture(command);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("clean exclusions failed:"));
    assert!(!config.exists());
}

#[test]
#[cfg(target_os = "macos")]
fn clean_exclusions_list_corrupt_owned_policy_json_is_storage_error() {
    let fixture = Fixture::new();
    let root = fixture.root.clone();
    let config = fixture.base.join("clean-config");
    fs::create_dir_all(&config).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&config, std::fs::Permissions::from_mode(0o700)).unwrap();
    let policy_path = config.join("exclusions-v1.json");
    fs::write(&policy_path, b"{not-json").unwrap();
    #[cfg(unix)]
    fs::set_permissions(&policy_path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let mut command = fixture.command();
    command.args([
        "clean",
        "exclusions",
        "list",
        root.to_str().unwrap(),
        "--json",
        "--config-dir",
        config.to_str().unwrap(),
    ]);
    let output = capture(command);
    assert_eq!(output.status.code(), Some(1));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["kind"], "clean exclusions");
    assert_eq!(value["status"], "failed");
    assert_eq!(value["error"]["code"], "InvalidData");
}

#[test]
#[cfg(target_os = "macos")]
fn clean_exclusions_list_unreadable_owned_policy_json_is_storage_error() {
    let fixture = Fixture::new();
    let root = fixture.root.clone();
    let config = fixture.base.join("clean-config");
    fs::create_dir_all(&config).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&config, std::fs::Permissions::from_mode(0o700)).unwrap();
    let policy_path = config.join("exclusions-v1.json");
    fs::write(
        &policy_path,
        br#"{"schema_version":1,"kind":"sayaka_clean_exclusions","roots":[]}"#,
    )
    .unwrap();
    #[cfg(unix)]
    fs::set_permissions(&policy_path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let mut command = fixture.command();
    command.args([
        "clean",
        "exclusions",
        "list",
        root.to_str().unwrap(),
        "--json",
        "--config-dir",
        config.to_str().unwrap(),
    ]);
    let output = capture(command);
    assert_eq!(output.status.code(), Some(1));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["kind"], "clean exclusions");
    assert_eq!(value["status"], "failed");
    assert_eq!(value["error"]["code"], "PermissionDenied");
}

#[test]
#[cfg(target_os = "macos")]
fn clean_execute_rejects_non_tty_without_effect_or_state() {
    let fixture = Fixture::new();
    let pkg = fixture.root.join("pkg");
    fs::create_dir_all(pkg.join("__pycache__")).unwrap();
    let py = pkg.join("module.py");
    let pyc = pkg.join("__pycache__/module.cpython-39.pyc");
    fs::write(&py, b"print('ok')\n").unwrap();
    fs::write(&pyc, vec![5_u8; 16]).unwrap();
    let before_pyc = fs::read(&pyc).unwrap();
    let state = fixture.base.join("clean-state");
    let mut command = fixture.command();
    command.args([
        "clean",
        fixture.root.to_str().unwrap(),
        "--execute",
        "--state-dir",
        state.to_str().unwrap(),
    ]);
    let output = capture(command);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(fs::read(&pyc).unwrap(), before_pyc);
    assert!(!state.exists());
}

#[test]
#[cfg(target_os = "macos")]
fn local_install_preview_execute_and_owned_remove_preserve_user_state() {
    let fixture = Fixture::new();
    let prefix = fixture.base.join("managed-prefix");
    let history = fixture.base.join("state/preserve-history");
    fs::write(&history, b"not an installation artifact").unwrap();
    let mut command = fixture.command();
    command
        .args(["install", "--json"])
        .arg("--prefix")
        .arg(&prefix);
    let result = capture(command);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["effects_performed"], false);
    assert_eq!(value["plan"]["sha256"].as_str().unwrap().len(), 64);
    assert!(!prefix.exists());
    let mut command = fixture.command();
    command
        .args(["install", "--execute", "--json"])
        .arg("--prefix")
        .arg(&prefix);
    let result = capture(command);
    assert!(
        result.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(prefix.join("bin/sayaka").is_file());
    let mut command = fixture.command();
    command
        .args(["update", "--json"])
        .arg("--prefix")
        .arg(&prefix);
    let update_preview = capture(command);
    assert!(update_preview.status.success());
    let update_preview_json: Value = serde_json::from_slice(&update_preview.stdout).unwrap();
    assert_eq!(update_preview_json["plan"]["action"], "Update");
    let mut command = fixture.command();
    command
        .args(["update", "--execute", "--json"])
        .arg("--prefix")
        .arg(&prefix);
    let update_result = capture(command);
    assert!(update_result.status.success());
    let update_result_json: Value = serde_json::from_slice(&update_result.stdout).unwrap();
    assert_eq!(update_result_json["outcome"]["status"], "AlreadyInstalled");
    let mut command = fixture.command();
    command
        .args(["recover", "--execute", "--json"])
        .arg("--prefix")
        .arg(&prefix);
    let recover_result = capture(command);
    assert!(recover_result.status.success());
    let recover_result_json: Value = serde_json::from_slice(&recover_result.stdout).unwrap();
    assert_eq!(recover_result_json["outcome"]["status"], "Recovered");
    let mut installed = Command::new(prefix.join("bin/sayaka"));
    fixture.isolate(&mut installed);
    installed.arg("--version");
    assert!(capture(installed).status.success());
    let mut command = fixture.command();
    command
        .args(["remove", "--json"])
        .arg("--prefix")
        .arg(&prefix);
    let result = capture(command);
    assert!(result.status.success());
    assert!(prefix.join("bin/sayaka").is_file());
    let mut command = Command::new(prefix.join("bin/sayaka"));
    fixture.isolate(&mut command);
    command
        .args(["remove", "--execute", "--json"])
        .arg("--prefix")
        .arg(&prefix);
    let result = capture(command);
    assert!(
        result.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!prefix.join("bin/sayaka").exists());
    assert_eq!(fs::read(history).unwrap(), b"not an installation artifact");
}

#[test]
#[cfg(target_os = "macos")]
fn local_install_and_remove_refuse_unowned_prefix_contents() {
    let fixture = Fixture::new();
    let prefix = fixture.base.join("unowned");
    fs::create_dir(&prefix).unwrap();
    fs::write(prefix.join("keep"), b"user-owned data").unwrap();
    for action in ["install", "remove"] {
        let mut command = fixture.command();
        command
            .args([action, "--execute", "--json"])
            .arg("--prefix")
            .arg(&prefix);
        assert!(!capture(command).status.success());
        assert_eq!(fs::read(prefix.join("keep")).unwrap(), b"user-owned data");
    }
}

#[test]
#[cfg(target_os = "macos")]
fn status_json_measures_a_counter_window_and_exposes_capability_gaps() {
    let fixture = Fixture::new();
    let mut command = fixture.command();
    command.args(["status", "--json", "--interval-ms", "1000"]);
    let result = capture(command);
    assert!(
        result.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert!(value["sequence"].as_u64().unwrap() >= 2);
    assert_eq!(
        value["cpu"]["state"], "fresh",
        "CPU={} collection={}",
        value["cpu"], value["collection_ms"]
    );
    assert!((0.0..=100.0).contains(&value["cpu"]["value"]["busy_percent"].as_f64().unwrap()));
    assert!(value["cpu"]["value"]["window_ms"].as_u64().unwrap() > 0);
    assert_eq!(value["memory"]["state"], "fresh");
    assert!(value["memory"]["value"]["physical_bytes"].as_u64().unwrap() > 0);
    assert_eq!(value["gpu_utilization_percent"]["state"], "unsupported");
    assert!(value["gpu_utilization_percent"]["value"].is_null());
    assert_eq!(value["temperature_celsius"]["state"], "unsupported");
    assert!(value["temperature_celsius"]["value"].is_null());
    assert_eq!(value["process_top"]["state"], "unsupported");
    assert!(value["process_top"]["value"].is_null());
    assert!(!result.stdout.contains(&0x1b));
}

#[test]
#[cfg(target_os = "macos")]
fn status_watch_pipe_is_bounded_ndjson_with_stable_sampler_identity() {
    let fixture = Fixture::new();
    let mut command = fixture.command();
    command.args(["status", "--watch", "--count", "3", "--interval-ms", "250"]);
    let result = capture(command);
    assert!(
        matches!(result.status.code(), Some(0 | 3)),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let text = String::from_utf8(result.stdout).unwrap();
    let snapshots: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(snapshots.len(), 3);
    for pair in snapshots.windows(2) {
        assert_eq!(pair[0]["sampler_id"], pair[1]["sampler_id"]);
        assert!(pair[1]["sequence"].as_u64().unwrap() > pair[0]["sequence"].as_u64().unwrap());
    }
    assert_eq!(snapshots[0]["cpu"]["state"], "warming_up");
    assert!(snapshots[0]["cpu"]["value"].is_null());
    for sample in &snapshots[1..] {
        match sample["cpu"]["state"].as_str().unwrap() {
            "fresh" => assert!(
                (0.0..=100.0).contains(&sample["cpu"]["value"]["busy_percent"].as_f64().unwrap())
            ),
            "warming_up" => {
                assert!(sample["cpu"]["value"].is_null());
                assert!(sample["cpu"]["error"]["code"].is_string());
            }
            "stale" => assert!(sample["cpu"]["error"]["code"].is_string()),
            state => panic!(
                "unexpected native counter state: {state}; {}",
                sample["cpu"]
            ),
        }
    }
}

#[test]
fn status_rejects_invalid_interval_and_nonfinite_thresholds() {
    let fixture = Fixture::new();
    for args in [
        vec!["status", "--interval-ms", "249"],
        vec!["status", "--cpu-warn", "NaN"],
        vec!["status", "--memory-warn", "101"],
        vec!["status", "--count", "2"],
        vec!["status", "--top-sort", "cpu"],
        vec!["status", "--top", "0"],
        vec!["status", "--top", "33"],
    ] {
        let mut command = fixture.command();
        command.args(args);
        assert_eq!(capture(command).status.code(), Some(2));
    }
}

#[test]
#[cfg(target_os = "macos")]
fn status_top_json_is_opt_in_and_reports_structured_rows() {
    let fixture = Fixture::new();
    let mut command = fixture.command();
    command.args([
        "status",
        "--json",
        "--top",
        "2",
        "--top-sort",
        "cpu",
        "--interval-ms",
        "1000",
    ]);
    let result = capture(command);
    assert!(
        matches!(result.status.code(), Some(0 | 3)),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(matches!(
        value["process_top"]["state"].as_str(),
        Some("fresh" | "warming_up")
    ));
    assert_eq!(value["process_top"]["value"]["top_schema_version"], 1);
    assert_eq!(value["process_top"]["value"]["limit"], 2);
    assert_eq!(value["process_top"]["value"]["sort"], "cpu");
    assert!(value["process_top"]["value"]["probed"].as_u64().unwrap() > 0);
}

#[test]
#[cfg(target_os = "macos")]
fn status_top_watch_ndjson_reaches_second_top_generation() {
    let fixture = Fixture::new();
    let mut command = fixture.command();
    command.args([
        "status",
        "--watch",
        "--json",
        "--top",
        "2",
        "--count",
        "7",
        "--interval-ms",
        "1000",
    ]);
    let result = capture(command);
    assert!(
        matches!(result.status.code(), Some(0 | 3)),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let snapshots: Vec<Value> = String::from_utf8(result.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(snapshots.len(), 7);
    let top_states: Vec<_> = snapshots
        .iter()
        .map(|s| s["process_top"]["state"].as_str().unwrap())
        .collect();
    assert!(top_states.contains(&"fresh") || top_states.contains(&"warming_up"));
    let rows = snapshots
        .iter()
        .filter_map(|s| s["process_top"]["value"]["rows"].as_array())
        .flat_map(|rows| rows.iter())
        .collect::<Vec<_>>();
    assert!(!rows.is_empty());
    assert!(
        rows.iter()
            .all(|row| row["name"].as_str().is_some() && row["identity"]["pid"].is_u64())
    );
}

#[test]
#[cfg(target_os = "macos")]
fn status_top_tracks_owned_child_pid_without_stale_reuse() {
    let fixture = Fixture::new();
    let mut worker = std::process::Command::new("python3")
        .args([
            "-c",
            "import time\nend=time.time()+9\nx=0\nwhile time.time()<end:\n x+=1\nprint(x)\n",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let owned_pid = worker.id();
    let mut command = fixture.command();
    command.args([
        "status",
        "--watch",
        "--json",
        "--top",
        "32",
        "--top-sort",
        "cpu",
        "--count",
        "7",
        "--interval-ms",
        "1000",
    ]);
    let result = capture(command);
    let _ = worker.kill();
    let _ = worker.wait();
    assert!(
        matches!(result.status.code(), Some(0 | 3)),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let snapshots: Vec<Value> = String::from_utf8(result.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let mut seen_owned = false;
    let mut measured_owned = false;
    for sample in snapshots {
        if let Some(rows) = sample["process_top"]["value"]["rows"].as_array() {
            for row in rows {
                if row["pid"].as_u64() == Some(u64::from(owned_pid)) {
                    seen_owned = true;
                    if row["cpu_percent_one_core"].is_number() {
                        measured_owned = true;
                    }
                }
            }
        }
    }
    assert!(seen_owned, "owned process not present in top rows");
    assert!(measured_owned, "owned process never received measured CPU");
}

#[test]
#[cfg(target_os = "macos")]
fn status_broken_pipe_exits_without_leaving_the_sampler_running() {
    let fixture = Fixture::new();
    let mut command = fixture.command();
    command
        .args(["status", "--watch", "--json", "--interval-ms", "250"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = OwnedChild {
        process: command.spawn().unwrap(),
        reaped: false,
    };
    drop(child.process.stdout.take().unwrap());
    let deadline = Instant::now() + DEADLINE;
    let status = loop {
        if let Some(status) = child.process.try_wait().unwrap() {
            child.reaped = true;
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "status did not stop after broken pipe"
        );
        thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(status.code(), Some(1));
    let mut error = String::new();
    child
        .process
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut error)
        .unwrap();
    assert!(error.to_lowercase().contains("broken pipe"), "{error}");
}

#[test]
#[cfg(target_os = "macos")]
fn browse_plain_counts_hardlinks_independently_in_siblings() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.root.join("left")).unwrap();
    fs::create_dir(fixture.root.join("right")).unwrap();
    fs::write(fixture.root.join("left/data"), [0u8; 100]).unwrap();
    fs::hard_link(
        fixture.root.join("left/data"),
        fixture.root.join("right/alias"),
    )
    .unwrap();
    let state = fixture.base.join("browser-journal");
    let mut command = fixture.command();
    command
        .arg("browse")
        .arg(&fixture.root)
        .arg("--plain")
        .arg("--state-dir")
        .arg(&state);
    let result = capture(command);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let text = String::from_utf8(result.stdout).unwrap();
    assert!(!text.contains('\x1b'));
    assert!(text.contains("Root unique files: 1"), "{text}");
    assert!(
        text.contains("Root logical subtotal: 100 bytes; unknown files: 0; complete: true"),
        "{text}"
    );
    for directory in ["left", "right"] {
        assert!(
            text.lines().any(|line| line.contains("(known_bytes=100)")
                && line.ends_with(&format!("/{directory}\""))),
            "{text}"
        );
    }
    assert!(!state.exists());
}

#[test]
fn browse_requires_a_root_and_does_not_implicitly_scan() {
    let fixture = Fixture::new();
    let mut command = fixture.command();
    command.arg("browse");
    let result = capture(command);
    assert_eq!(result.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&result.stdout).contains("snapshot"));
}

#[test]
#[cfg(target_os = "macos")]
fn browse_pipe_fallback_and_alias_are_read_only_and_missing_scope_fails() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("kept.txt"), b"kept").unwrap();
    let mut command = fixture.command();
    command.arg("analyze").arg(&fixture.root);
    let result = capture(command);
    assert!(result.status.success());
    assert!(!result.stdout.contains(&0x1b));
    assert_eq!(fs::read(fixture.root.join("kept.txt")).unwrap(), b"kept");
    let mut command = fixture.command();
    command.arg("browse").arg(fixture.root.join("missing"));
    let result = capture(command);
    assert!(!result.status.success());
    assert!(!result.stdout.contains(&0x1b));
}

#[cfg(target_os = "macos")]
fn exclusion_preview(
    fixture: &Fixture,
    file: &std::path::Path,
    excluded: &std::path::Path,
) -> Value {
    let mut command = fixture.command();
    command
        .arg("trash")
        .arg("--scope")
        .arg(&fixture.root)
        .arg(file)
        .arg("--exclude")
        .arg(excluded)
        .arg("--json");
    let result = capture(command);
    assert!(
        matches!(result.status.code(), Some(0 | 3)),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice(&result.stdout).unwrap()
}

#[cfg(target_os = "macos")]
fn same_native_object(original: &std::path::Path, alias: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let original = fs::symlink_metadata(original).unwrap();
    match fs::symlink_metadata(alias) {
        Ok(alias) => (alias.dev(), alias.ino()) == (original.dev(), original.ino()),
        Err(error) => {
            assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
            false
        }
    }
}

#[test]
#[cfg(target_os = "macos")]
fn trash_file_case_alias_exclusion_is_not_ignored() {
    let fixture = Fixture::new();
    let file = fixture.root.join("Chosen.txt");
    let alias = fixture.root.join("chosen.txt");
    fs::write(&file, b"owned case alias fixture").unwrap();
    let value = exclusion_preview(&fixture, &file, &alias);
    assert_eq!(value["items"].as_array().unwrap().len(), 0, "{value}");
    assert_eq!(value["rejected"][0]["reason"], "excluded");
    assert_eq!(fs::read(file).unwrap(), b"owned case alias fixture");
}

#[test]
#[cfg(target_os = "macos")]
fn trash_ancestor_case_alias_exclusion_is_not_ignored() {
    let fixture = Fixture::new();
    let parent = fixture.root.join("ChosenFolder");
    fs::create_dir(&parent).unwrap();
    let file = parent.join("file.txt");
    fs::write(&file, b"owned ancestor alias fixture").unwrap();
    let alias = fixture.root.join("chosenfolder");
    let value = exclusion_preview(&fixture, &file, &alias);
    assert_eq!(value["items"].as_array().unwrap().len(), 0, "{value}");
    assert_eq!(value["rejected"][0]["reason"], "excluded");
    assert_eq!(fs::read(file).unwrap(), b"owned ancestor alias fixture");
}

#[test]
#[cfg(target_os = "macos")]
fn trash_unicode_alias_exclusion_uses_native_identity() {
    let fixture = Fixture::new();
    let file = fixture.root.join("caf\u{e9}.txt");
    let alias = fixture.root.join("cafe\u{301}.txt");
    fs::write(&file, b"owned normalization alias fixture").unwrap();
    let aliases = same_native_object(&file, &alias);
    let value = exclusion_preview(&fixture, &file, &alias);
    assert_eq!(
        value["items"].as_array().unwrap().len(),
        usize::from(!aliases),
        "{value}"
    );
    if aliases {
        assert_eq!(value["rejected"][0]["reason"], "excluded");
    }
    assert_eq!(
        fs::read(file).unwrap(),
        b"owned normalization alias fixture"
    );
}

#[test]
#[cfg(target_os = "macos")]
fn trash_missing_unrelated_exclusion_does_not_remove_selection() {
    let fixture = Fixture::new();
    let file = fixture.root.join("selected.txt");
    fs::write(&file, b"owned unrelated exclusion fixture").unwrap();
    let value = exclusion_preview(&fixture, &file, &fixture.root.join("unrelated/missing"));
    assert_eq!(value["items"].as_array().unwrap().len(), 1, "{value}");
    assert!(value["rejected"].as_array().unwrap().is_empty());
}

#[test]
#[cfg(target_os = "macos")]
fn trash_refuses_disk_image_and_vm_package_members() {
    let fixture = Fixture::new();
    for name in ["Disk.sparsebundle", "Machine.vmwarevm"] {
        let parent = fixture.root.join(name).join("bands");
        fs::create_dir_all(&parent).unwrap();
        let file = parent.join("0");
        fs::write(&file, b"owned package member fixture").unwrap();
        let mut command = fixture.command();
        command
            .arg("trash")
            .arg("--scope")
            .arg(&fixture.root)
            .arg(&file)
            .arg("--json");
        let result = capture(command);
        assert_eq!(result.status.code(), Some(3));
        let value: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert!(value["items"].as_array().unwrap().is_empty(), "{value}");
        assert_eq!(value["rejected"].as_array().unwrap().len(), 1);
        assert_eq!(fs::read(&file).unwrap(), b"owned package member fixture");
    }
}

#[test]
#[cfg(target_os = "macos")]
fn trash_preview_is_versioned_read_only_and_does_not_create_state() {
    let fixture = Fixture::new();
    let file = fixture.root.join("selected.txt");
    fs::write(&file, b"keep this fixture").unwrap();
    let state = fixture.base.join("journal");
    let mut command = fixture.command();
    command
        .arg("trash")
        .arg("--scope")
        .arg(&fixture.root)
        .arg(&file)
        .arg("--state-dir")
        .arg(&state)
        .arg("--json");
    let result = capture(command);
    assert!(
        result.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["plan_schema_version"], 2);
    assert_eq!(value["execution_contract"], "revalidated_trash_v1");
    assert_eq!(value["effects_performed"], false);
    assert_eq!(value["items"].as_array().unwrap().len(), 1, "{value}");
    assert!(
        value["warning"]
            .as_str()
            .unwrap()
            .contains("different file")
    );
    assert_eq!(fs::read(&file).unwrap(), b"keep this fixture");
    assert!(!state.exists());
}

#[test]
fn trash_execution_rejects_piped_confirmation_without_touching_state() {
    let fixture = Fixture::new();
    let file = fixture.root.join("selected.txt");
    fs::write(&file, b"untouched").unwrap();
    let state = fixture.base.join("journal");
    let mut command = fixture.command();
    command
        .arg("trash")
        .arg("--scope")
        .arg(&fixture.root)
        .arg(&file)
        .arg("--state-dir")
        .arg(&state)
        .arg("--execute");
    let result = capture(command);
    assert_eq!(result.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&result.stderr).contains("interactive terminal"));
    assert_eq!(fs::read(file).unwrap(), b"untouched");
    assert!(!state.exists());
}

#[test]
#[cfg(target_os = "macos")]
fn trash_mixed_refusals_are_not_empty_success_and_include_paths() {
    let fixture = Fixture::new();
    let file = fixture.root.join("selected.txt");
    fs::write(&file, b"untouched").unwrap();
    let missing = fixture.root.join("missing");
    let mut command = fixture.command();
    command
        .arg("trash")
        .arg("--scope")
        .arg(&fixture.root)
        .arg(&file)
        .arg(&missing)
        .arg("--json");
    let result = capture(command);
    assert_eq!(result.status.code(), Some(3));
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["items"].as_array().unwrap().len(), 1, "{value}");
    assert_eq!(value["rejected"].as_array().unwrap().len(), 1);
    assert!(
        value["rejected"][0]["path"]["display"]
            .as_str()
            .unwrap()
            .contains("missing")
    );
    assert_eq!(value["selection_issues"].as_array().unwrap().len(), 1);
    assert_eq!(fs::read(file).unwrap(), b"untouched");
}

#[test]
#[cfg(target_os = "macos")]
fn trash_exclusions_are_in_preview_and_never_eligible() {
    let fixture = Fixture::new();
    let file = fixture.root.join("selected.txt");
    fs::write(&file, b"untouched").unwrap();
    let mut command = fixture.command();
    command
        .arg("trash")
        .arg("--scope")
        .arg(&fixture.root)
        .arg(&file)
        .arg("--exclude")
        .arg(&file)
        .arg("--json");
    let result = capture(command);
    assert_eq!(result.status.code(), Some(3));
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(value["items"].as_array().unwrap().is_empty());
    assert_eq!(value["rejected"][0]["reason"], "excluded");
    assert_eq!(fs::read(file).unwrap(), b"untouched");
}

#[test]
fn receipt_missing_state_is_an_explicit_error_without_creation() {
    let fixture = Fixture::new();
    let state = fixture.base.join("absent-journal");
    let mut command = fixture.command();
    command
        .arg("receipt")
        .arg("--state-dir")
        .arg(&state)
        .arg("--json");
    let result = capture(command);
    assert!(!result.status.success());
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["kind"], "receipt");
    assert_eq!(value["status"], "failed");
    assert!(!state.exists());
}

#[test]
#[cfg(target_os = "macos")]
fn receipt_preserves_unverified_recovery_hints_without_retrying() {
    use sayaka_engine::journal::{
        FileEvidence, ItemRecord, ItemState, NativePath, NativeTime, Record, RecoveryEvidence,
        Store,
    };
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let fixture = Fixture::new();
    let file = fixture.root.join("untouched.txt");
    fs::write(&file, b"owned evidence fixture").unwrap();
    let metadata = fs::metadata(&file).unwrap();
    let evidence = FileEvidence {
        device: metadata.dev(),
        inode: metadata.ino(),
        logical_bytes: metadata.len(),
        modified: NativeTime::from_system_time(metadata.modified().unwrap()),
    };
    let state = fixture.base.join("evidence-journal");
    drop(Store::open(&state, true).unwrap());
    let record = Record {
        schema_version: 1,
        plan_schema_version: 2,
        engine_version: 2,
        rules_version: 1,
        operation_id: "b-2".into(),
        contract: "revalidated_trash_v1".into(),
        scope: NativePath::from_path(&fixture.root),
        clean_policy: None,
        created_unix_ms: 1,
        items: vec![ItemRecord {
            path: NativePath::from_path(&file),
            device: metadata.dev(),
            inode: metadata.ino(),
            logical_bytes: metadata.len(),
            state: ItemState::Unknown,
            reason: Some("synthetic unverified outcome".into()),
            destination: None,
            rule_binding: None,
            updated_unix_ms: 1,
            recovery_evidence: Some(RecoveryEvidence {
                approved: evidence.clone(),
                returned_destination: Some(NativePath::from_path(std::path::Path::new(
                    "/fixture-trash/unverified",
                ))),
                held_source: Some(evidence),
                held_source_path: Some(NativePath::from_path(&file)),
                observation_errors: vec!["synthetic destination verification failure".into()],
            }),
        }],
    };
    record.validate().unwrap();
    let output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(state.join("b-2.json"))
        .unwrap();
    serde_json::to_writer(output, &record).unwrap();
    let before = fs::read(state.join("b-2.json")).unwrap();
    let mut command = fixture.command();
    command
        .arg("receipt")
        .arg("--state-dir")
        .arg(&state)
        .arg("--json");
    let result = capture(command);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    let item = &value["journal"]["records"][0]["items"][0];
    assert_eq!(item["state"], "unknown");
    assert!(item["destination"].is_null());
    assert_eq!(
        item["recovery_evidence"]["approved"]["inode"],
        metadata.ino()
    );
    assert!(
        item["recovery_evidence"]["returned_destination"]["display"]
            .as_str()
            .unwrap()
            .contains("/fixture-trash/unverified")
    );
    let mut command = fixture.command();
    command.arg("receipt").arg("--state-dir").arg(&state);
    let result = capture(command);
    assert!(result.status.success());
    let text = String::from_utf8(result.stdout).unwrap();
    assert!(text.contains("Unverified OS destination"));
    assert!(text.contains("no automatic retry or restoration"));
    assert_eq!(fs::read(&file).unwrap(), b"owned evidence fixture");
    assert_eq!(fs::read(state.join("b-2.json")).unwrap(), before);
}

struct Fixture {
    directory: Option<TempDir>,
    base: PathBuf,
    root: PathBuf,
}

#[cfg(windows)]
#[test]
fn windows_journal_commands_reject_unsupported_storage_even_without_home() {
    let fixture = Fixture::new();
    for name in ["receipt", "history"] {
        let mut command = fixture.command();
        command.env_remove("HOME").args([name, "--json"]);
        let result = capture(command);
        assert_eq!(result.status.code(), Some(1));
        let value: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(value["status"], "failed");
        let output = String::from_utf8(result.stdout).unwrap();
        assert!(output.contains("native journal storage is macOS-only"));
        assert!(!output.contains("HOME is unavailable"));
    }
    assert!(
        fs::read_dir(fixture.base.join("state"))
            .unwrap()
            .next()
            .is_none()
    );
}

#[cfg(windows)]
#[test]
fn windows_scan_rejects_parent_traversal_before_path_normalization() {
    use std::ffi::OsString;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    let fixture = Fixture::new();
    let units: Vec<u16> = fixture.base.as_os_str().encode_wide().collect();
    assert!(units.starts_with(&[92, 92, 63, 92]));
    let ordinary = PathBuf::from(OsString::from_wide(&units[4..]));
    let mut verbatim = fixture.base.as_os_str().to_owned();
    verbatim.push(r"\root\..\home");
    for path in [
        PathBuf::from("root/../home"),
        ordinary.join("root/../home"),
        PathBuf::from(verbatim),
    ] {
        assert!(
            path.components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        );
        let mut command = fixture.command();
        command.arg("scan").arg(path).arg("--json");
        let value = json(&capture(command), 2);
        assert_eq!(value["issues"][0]["code"], "invalid_root");
        assert!(value["task_id"].is_null());
        assert!(value["entries"].as_array().unwrap().is_empty());
        assert!(value["totals"].is_null());
    }
}

impl Fixture {
    fn new() -> Self {
        // Never use the user's temp directory, HOME, or working tree as a scan root.
        let directory = TempDir::new(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")),
            "sayaka-cli-test-",
        )
        .expect("retain fixture ownership");
        let base = directory.path().to_path_buf();
        for name in ["root", "home", "config", "state", "cache", "temp"] {
            fs::create_dir(base.join(name)).expect("create fixture directory");
        }
        let root = base.join("root");
        Self {
            directory: Some(directory),
            base,
            root,
        }
    }

    fn isolate(&self, command: &mut Command) {
        command
            .env_clear()
            .current_dir(&self.base)
            .env("HOME", self.base.join("home"))
            .env("USERPROFILE", self.base.join("home"))
            .env("APPDATA", self.base.join("config"))
            .env("LOCALAPPDATA", self.base.join("state"))
            .env("XDG_CONFIG_HOME", self.base.join("config"))
            .env("XDG_STATE_HOME", self.base.join("state"))
            .env("XDG_CACHE_HOME", self.base.join("cache"))
            .env("TMPDIR", self.base.join("temp"))
            .env("TMP", self.base.join("temp"))
            .env("TEMP", self.base.join("temp"));
        #[cfg(windows)]
        if let Some(system_root) = std::env::var_os("SystemRoot") {
            command.env("SystemRoot", system_root);
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_sayaka"));
        self.isolate(&mut command);
        command
    }

    fn scan(&self, args: &[&str]) -> Captured {
        let mut command = self.command();
        command.arg("scan").arg(&self.root).args(args);
        capture(command)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(directory) = self.directory.take()
            && let Err(error) = directory.close()
        {
            eprintln!("fixture cleanup failed: {error}");
            if !thread::panicking() {
                panic!("fixture cleanup failed");
            }
        }
    }
}

struct OwnedChild {
    process: Child,
    reaped: bool,
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        match self.process.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) => {
                if let Err(error) = self.process.kill() {
                    eprintln!(
                        "could not stop owned CLI child {}: {error}",
                        self.process.id()
                    );
                }
                if let Err(error) = self.process.wait() {
                    eprintln!(
                        "could not reap owned CLI child {}: {error}",
                        self.process.id()
                    );
                }
            }
            Err(error) => eprintln!(
                "owned CLI child status is unknown; not signalling an unverified PID: {error}"
            ),
        }
    }
}

struct Captured {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

struct Running {
    child: OwnedChild,
    stdout: thread::JoinHandle<Vec<u8>>,
    stderr: thread::JoinHandle<Vec<u8>>,
    #[cfg(target_os = "macos")]
    first_progress: mpsc::Receiver<()>,
}

impl Running {
    fn start(mut command: Command) -> Self {
        let mut child = OwnedChild {
            process: command
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .stdin(Stdio::null())
                .spawn()
                .expect("spawn owned child"),
            reaped: false,
        };
        let mut stdout = child.process.stdout.take().expect("stdout pipe");
        let stderr = child.process.stderr.take().expect("stderr pipe");
        let (sender, _first_progress) = mpsc::channel();
        let stdout = thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout.read_to_end(&mut bytes).expect("read stdout");
            bytes
        });
        let stderr = thread::spawn(move || {
            let mut reader = BufReader::new(stderr);
            let mut bytes = Vec::new();
            let mut notified = false;
            loop {
                let start = bytes.len();
                if reader.read_until(b'\n', &mut bytes).expect("read stderr") == 0 {
                    break;
                }
                if !notified
                    && serde_json::from_slice::<Value>(&bytes[start..])
                        .is_ok_and(|value| value["type"] == "progress")
                {
                    let _ = sender.send(());
                    notified = true;
                }
            }
            bytes
        });
        Self {
            child,
            stdout,
            stderr,
            #[cfg(target_os = "macos")]
            first_progress: _first_progress,
        }
    }

    fn finish(mut self) -> Captured {
        let deadline = Instant::now() + DEADLINE;
        let status = loop {
            if let Some(status) = self.child.process.try_wait().expect("poll child") {
                self.child.reaped = true;
                break status;
            }
            if Instant::now() >= deadline {
                self.child
                    .process
                    .kill()
                    .expect("kill timed-out owned child");
                self.child
                    .process
                    .wait()
                    .expect("reap timed-out owned child");
                self.child.reaped = true;
                panic!("CLI exceeded finite test deadline");
            }
            thread::sleep(Duration::from_millis(5));
        };
        Captured {
            status,
            stdout: self.stdout.join().expect("stdout reader"),
            stderr: self.stderr.join().expect("stderr reader"),
        }
    }
}

fn capture(command: Command) -> Captured {
    Running::start(command).finish()
}

fn json(output: &Captured, exit: i32) -> Value {
    assert_eq!(
        output.status.code(),
        Some(exit),
        "stderr={:?}, stdout={:?}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(output.stdout.last(), Some(&b'\n'));
    assert_eq!(
        output.stdout.iter().filter(|&&byte| byte == b'\n').count(),
        1
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("one final JSON object");
    let mut keys: Vec<_> = value
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "complete",
            "entries",
            "issues",
            "issues_omitted",
            "metrics",
            "roots",
            "schema_version",
            "status",
            "task_id",
            "totals"
        ]
    );
    assert_eq!(value["schema_version"], 1);
    value
}

#[test]
fn help_version_and_required_root_are_portable() {
    let fixture = Fixture::new();
    for args in [vec!["--help"], vec!["--version"], vec!["scan", "--help"]] {
        let mut command = fixture.command();
        command.args(args);
        let output = capture(command);
        assert!(output.status.success());
        assert!(!output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
    for args in [vec!["scan"], vec!["scan", "--json"]] {
        let mut command = fixture.command();
        command.args(args);
        let output = capture(command);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains("\n\nUsage:"));
        assert!(!error.contains("\\n"));
        assert!(!error.contains("\\'"));
        assert!(error.contains("cargo run --quiet -p sayaka-cli -- scan ."));
        assert!(error.contains("current directory"));
        assert!(!error.contains("Scanning..."));
    }
}

#[test]
fn semantic_limits_are_fatal_json_but_syntax_errors_are_clap_diagnostics() {
    let fixture = Fixture::new();
    for args in [
        vec!["--workers", "0"],
        vec!["--queue-capacity", "0"],
        vec!["--max-open-dirs", "1"],
        vec!["--max-depth", "0"],
        vec!["--max-entries", "0"],
        vec!["--max-path-bytes", "0"],
        vec!["--timeout-ms", "0"],
        vec!["--timeout-ms", "86400001"],
    ] {
        let mut options = vec!["--json"];
        options.extend(args);
        let value = json(&fixture.scan(&options), 2);
        assert_eq!(value["status"], "failed");
        assert_eq!(value["complete"], false);
        assert!(value["task_id"].is_null());
        assert_eq!(value["roots"], serde_json::json!([]));
        assert_eq!(value["entries"], serde_json::json!([]));
        assert!(value["totals"].is_null());
        assert!(value["metrics"].is_null());
        assert_eq!(value["issues_omitted"], 0);
        assert_eq!(value["issues"][0]["code"], "invalid_limits");
        assert!(value["issues"][0]["path"].is_null());
    }
    for value in ["abc", "-1", "184467440737095516160", "\u{1b}[31m"] {
        let output = fixture.scan(&["--json", "--workers", value]);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
        assert!(!output.stderr.contains(&0x1b));
    }
}

#[cfg(not(any(target_os = "macos", windows)))]
#[test]
fn native_scanning_is_explicitly_unsupported() {
    let fixture = Fixture::new();
    let value = json(&fixture.scan(&["--json"]), 1);
    assert_eq!(value["issues"][0]["code"], "unsupported_platform");
    assert_eq!(value["complete"], false);
}

#[cfg(windows)]
#[test]
fn windows_scan_cli_keeps_native_paths_metrics_and_progress_contract() {
    use std::os::windows::ffi::OsStringExt;
    let fixture = Fixture::new();
    let name = std::ffi::OsString::from_wide(&[0x0061, 0xd800, 0x0062]);
    fs::write(fixture.root.join(&name), b"native").unwrap();
    let result = fixture.scan(&["--json", "--progress"]);
    let value = json(&result, 0);
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["status"], "complete");
    assert_eq!(value["complete"], true);
    assert_eq!(value["totals"]["logical_bytes_known"], 6);
    assert_eq!(value["totals"]["unique_files"], 1);
    let entry = value["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["kind"] == "file")
        .unwrap();
    assert_eq!(entry["identity"]["variant"], "windows");
    assert_eq!(entry["identity"]["file_id"].as_array().unwrap().len(), 16);
    assert_eq!(entry["path"]["encoding"], "windows_utf16_hex");
    assert!(entry["path"]["raw"].as_str().unwrap().contains("d800"));
    let progress: Vec<Value> = String::from_utf8(result.stderr)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(!progress.is_empty());
    assert!(
        progress
            .iter()
            .all(|event| event["task_id"] == value["task_id"])
    );
    assert_eq!(fs::read(fixture.root.join(name)).unwrap(), b"native");
}

#[cfg(windows)]
#[test]
fn windows_scan_cli_mixed_roots_are_partial_not_empty_success() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("readable"), b"1234").unwrap();
    let mut command = fixture.command();
    command
        .arg("scan")
        .arg(&fixture.root)
        .arg(fixture.base.join("missing"))
        .arg("--json");
    let value = json(&capture(command), 3);
    assert_eq!(value["status"], "partial");
    assert_eq!(value["complete"], false);
    assert_eq!(value["totals"]["logical_bytes_known"], 4);
    assert!(
        value["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| issue["code"] == "not_found")
    );
}

#[cfg(windows)]
#[test]
fn windows_trash_preview_is_refused_without_effects_or_journal_creation() {
    let fixture = Fixture::new();
    let file = fixture.root.join("selected.txt");
    fs::write(&file, b"untouched").unwrap();
    let state = fixture.base.join("journal");
    let mut command = fixture.command();
    command
        .arg("trash")
        .arg("--scope")
        .arg(&fixture.root)
        .arg(&file)
        .arg("--state-dir")
        .arg(&state)
        .arg("--json");
    let result = capture(command);
    assert_eq!(result.status.code(), Some(1));
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["status"], "failed");
    assert_eq!(value["schema_version"], 1);
    assert!(value.get("items").is_none());
    assert_eq!(fs::read(&file).unwrap(), b"untouched");
    assert!(!state.exists());
}

#[cfg(windows)]
#[test]
fn windows_scan_cli_reports_real_acl_denial_and_restores_fixture_permissions() {
    struct PermissionReset<'a> {
        fixture: &'a Fixture,
        directory: PathBuf,
        tool: PathBuf,
    }
    impl PermissionReset<'_> {
        fn invoke(&self, args: &[&str]) -> Captured {
            let mut command = Command::new(&self.tool);
            self.fixture.isolate(&mut command);
            command.arg(&self.directory).args(args);
            capture(command)
        }
    }
    impl Drop for PermissionReset<'_> {
        fn drop(&mut self) {
            let result = self.invoke(&["/remove:d", "*S-1-1-0"]);
            if !result.status.success() {
                eprintln!("owned ACL fixture restoration failed");
                if !thread::panicking() {
                    panic!("owned ACL fixture restoration failed");
                }
            }
        }
    }
    let fixture = Fixture::new();
    let denied = fixture.root.join("denied");
    fs::create_dir(&denied).unwrap();
    fs::write(denied.join("unseen"), b"owned ACL fixture").unwrap();
    fs::write(fixture.root.join("visible"), b"1234").unwrap();
    let reset = PermissionReset {
        fixture: &fixture,
        directory: denied.clone(),
        tool: PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32/icacls.exe"),
    };
    assert!(reset.invoke(&["/deny", "*S-1-1-0:(RD)"]).status.success());
    let precondition = fs::read_dir(&denied).is_err();
    let result = fixture.scan(&["--json"]);
    drop(reset);
    assert!(
        fs::read_dir(&denied).is_ok(),
        "ACL restoration did not restore access"
    );
    assert!(precondition, "owned ACL fixture did not deny enumeration");
    let value = json(&result, 3);
    assert_eq!(value["complete"], false);
    assert_eq!(value["totals"]["logical_bytes_known"], 4);
    assert!(
        value["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| issue["code"] == "permission_denied")
    );
    assert_eq!(
        fs::read(denied.join("unseen")).unwrap(),
        b"owned ACL fixture"
    );
}

#[cfg(target_os = "macos")]
mod native {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::symlink;
    use std::path::Path;

    fn raw(path: &Path) -> String {
        path.as_os_str()
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn entry<'a>(value: &'a Value, path: &Path) -> &'a Value {
        value["entries"]
            .as_array()
            .expect("entries")
            .iter()
            .find(|entry| entry["path"]["raw"] == raw(path))
            .expect("fixture entry")
    }

    #[test]
    fn exact_envelope_totals_empty_directories_and_hard_link_dedup() {
        let fixture = Fixture::new();
        fs::write(fixture.root.join("a"), b"hello").unwrap();
        fs::write(fixture.root.join("b"), b"abc").unwrap();
        fs::hard_link(fixture.root.join("a"), fixture.root.join("alias")).unwrap();
        fs::create_dir(fixture.root.join("empty")).unwrap();
        let output = fixture.scan(&["--json"]);
        let value = json(&output, 0);
        assert!(output.stderr.is_empty());
        assert_eq!(value["status"], "complete");
        assert_eq!(value["complete"], true);
        assert_eq!(value["totals"]["regular_files"], 3);
        assert_eq!(value["totals"]["unique_files"], 2);
        assert_eq!(value["totals"]["duplicate_files"], 1);
        assert_eq!(value["totals"]["directories"], 2);
        assert_eq!(value["totals"]["logical_bytes_known"], 8);
        assert_eq!(value["totals"]["logical_bytes_unknown_files"], 0);
        assert!(value["totals"]["allocated_bytes_known"].is_u64());
        assert_eq!(value["entries"].as_array().unwrap().len(), 5);
        assert_eq!(
            entry(&value, &fixture.root.join("empty"))["kind"],
            "directory"
        );
        let first = entry(&value, &fixture.root.join("a"));
        let alias = entry(&value, &fixture.root.join("alias"));
        assert_eq!(first["identity"], alias["identity"]);
        assert_ne!(first["resource_id"], alias["resource_id"]);
        assert_ne!(first["counted"], alias["counted"]);
        for item in value["entries"].as_array().unwrap() {
            assert_eq!(item.as_object().unwrap().len(), 9);
            assert!(
                item["resource_id"]
                    .as_str()
                    .unwrap()
                    .starts_with(&format!("{}/", value["task_id"].as_str().unwrap()))
            );
            assert_eq!(item["path"]["encoding"], "unix_bytes_hex");
            assert_eq!(item["identity"]["variant"], "unix");
            assert!(item["identity"]["device"].is_u64());
            assert!(item["identity"]["inode"].is_u64());
        }
    }

    #[test]
    fn native_utf8_control_paths_are_lossless_and_diagnostics_escape_controls() {
        let fixture = Fixture::new();
        let control = fixture.root.join("line\n\t\u{1b}[31m");
        fs::write(&control, b"ab").unwrap();
        let value = json(&fixture.scan(&["--json"]), 0);
        let item = entry(&value, &control);
        assert_eq!(item["path"]["raw"], raw(&control));
        assert!(
            !item["path"]["display"]
                .as_str()
                .unwrap()
                .chars()
                .any(char::is_control)
        );
        let link = fixture.root.join("link\n\u{1b}[2J");
        symlink(&control, &link).unwrap();
        let output = fixture.scan(&[]);
        assert_eq!(output.status.code(), Some(0));
        assert!(!output.stderr.contains(&0x1b));
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("Symbolic link skipped")
        );
    }

    #[test]
    fn invalid_byte_root_error_preserves_original_path_without_creating_a_file() {
        let fixture = Fixture::new();
        let root = fixture
            .root
            .join(OsString::from_vec(b"invalid-\xff".to_vec()));
        let mut command = fixture.command();
        command.arg("scan").arg(&root).arg("--json");
        let output = capture(command);
        assert!(matches!(output.status.code(), Some(1 | 3)));
        let value = json(&output, output.status.code().unwrap());
        assert_eq!(value["complete"], false);
        let expected = raw(&root);
        assert!(
            value["issues"].as_array().unwrap().iter().any(|issue| {
                issue["path"]["encoding"] == "unix_bytes_hex" && issue["path"]["raw"] == expected
            }),
            "failed native lookup must retain its original path: {value}"
        );
    }

    #[test]
    fn readable_reports_rank_files_and_keep_json_opt_in() {
        let fixture = Fixture::new();
        fs::write(fixture.root.join("small.txt"), b"1234").unwrap();
        let large = fs::File::create(fixture.root.join("large.bin")).unwrap();
        large.set_len(2 * 1024 * 1024).unwrap();
        drop(large);
        fs::hard_link(
            fixture.root.join("large.bin"),
            fixture.root.join("large-alias.bin"),
        )
        .unwrap();
        let output = fixture.scan(&[]);
        assert_eq!(output.status.code(), Some(0));
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.contains("Sayaka / Storage scan"));
        assert!(text.contains("Scan complete"));
        assert!(text.contains("2.0 MiB"));
        assert!(text.contains("Largest files"));
        assert!(text.contains("bytes counted once"));
        assert!(text.contains("Nothing was deleted"));
        assert!(!text.contains("schema_version"));
        assert!(!text.contains('\x1b'));
        assert!(output.stderr.is_empty());
        assert!(text.find("2.0 MiB  [").unwrap() < text.find("small.txt").unwrap());
        let wire = json(&fixture.scan(&["--json"]), 0);
        assert_eq!(wire["schema_version"], 1);
    }

    #[test]
    fn readable_missing_root_explains_the_path_and_next_step_without_zero_totals() {
        let fixture = Fixture::new();
        let mut command = fixture.command();
        command.arg("scan").arg(fixture.root.join("missing"));
        let output = capture(command);
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        let text = String::from_utf8(output.stderr).unwrap();
        assert!(text.contains("Could not scan"));
        assert!(text.contains("Path not found"));
        assert!(text.contains("sayaka scan ."));
        assert!(!text.contains("0 B"));
        assert!(!text.contains("schema_version"));
        assert!(!text.contains('\x1b'));
    }

    #[test]
    fn readable_progress_uses_words_while_json_progress_keeps_its_protocol() {
        let fixture = Fixture::new();
        fs::write(fixture.root.join("data"), b"hello").unwrap();
        let output = fixture.scan(&["--progress"]);
        assert_eq!(output.status.code(), Some(0));
        let progress = String::from_utf8(output.stderr).unwrap();
        assert!(progress.contains("Scanning"));
        assert!(!progress.contains("schema_version"));
        assert!(!progress.contains('\x1b'));
        let report = String::from_utf8(output.stdout).unwrap();
        assert!(report.contains("Scan complete"));
    }

    #[test]
    fn partial_readable_report_is_explicitly_a_subtotal() {
        let fixture = Fixture::new();
        fs::write(fixture.root.join("data"), b"hello").unwrap();
        let output = fixture.scan(&["--max-entries", "1"]);
        assert_eq!(output.status.code(), Some(3));
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.contains("Partial scan"));
        assert!(text.contains("Observed so far"));
        assert!(text.contains("not the complete folder total"));
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("Result limit reached")
        );
    }

    #[test]
    fn missing_and_invalid_roots_are_not_success() {
        let fixture = Fixture::new();
        let mut command = fixture.command();
        command
            .arg("scan")
            .arg(fixture.root.join("missing\n\u{1b}[2J"))
            .arg("--json");
        let output = capture(command);
        assert!(matches!(output.status.code(), Some(1 | 3)));
        let value = json(&output, output.status.code().unwrap());
        assert_eq!(value["complete"], false);
        assert!(
            value["issues"]
                .as_array()
                .unwrap()
                .iter()
                .any(|issue| issue["code"] == "not_found")
        );
        let mut command = fixture.command();
        command
            .arg("scan")
            .arg(fixture.root.join(".."))
            .arg("--json");
        let value = json(&capture(command), 2);
        assert_eq!(value["issues"][0]["code"], "invalid_root");
        assert!(value["task_id"].is_null());
    }

    #[test]
    fn root_and_ancestor_symlinks_are_never_followed() {
        let fixture = Fixture::new();
        let target = fixture.base.join("owned-target");
        fs::create_dir(&target).unwrap();
        fs::create_dir(target.join("child")).unwrap();
        fs::write(target.join("child/secret"), b"must not be traversed").unwrap();
        let link = fixture.root.join("link");
        symlink(&target, &link).unwrap();
        let value = json(&fixture.scan(&["--json"]), 0);
        assert_eq!(value["totals"]["regular_files"], 0);
        assert_eq!(value["totals"]["links"], 1);
        assert_eq!(entry(&value, &link)["kind"], "link");
        for root in [&link, &link.join("child")] {
            let mut command = fixture.command();
            command.arg("scan").arg(root).arg("--json");
            let output = capture(command);
            assert!(!output.status.success());
            let value = json(&output, output.status.code().unwrap());
            assert_eq!(value["complete"], false);
            assert!(
                value["entries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|item| item["kind"] != "file")
            );
        }
    }

    #[test]
    fn explicit_descendants_are_validated_before_any_overlap_deduplication() {
        let fixture = Fixture::new();
        fs::write(fixture.root.join("data"), b"1234").unwrap();
        let target = fixture.base.join("target");
        fs::create_dir(&target).unwrap();
        let alias = fixture.root.join("link");
        symlink(&target, &alias).unwrap();
        for (descendant, expected) in [
            (fixture.root.join("missing"), "not_found"),
            (alias, "link_skipped"),
            (fixture.root.join("data"), "invalid_root"),
        ] {
            let mut command = fixture.command();
            command
                .arg("scan")
                .arg(&fixture.root)
                .arg(&descendant)
                .arg("--json");
            let value = json(&capture(command), 3);
            assert_eq!(value["complete"], false);
            assert_eq!(value["totals"]["logical_bytes_known"], 4);
            assert!(value["issues"].as_array().unwrap().iter().any(|issue| {
                issue["code"] == expected && issue["path"]["raw"] == raw(&descendant)
            }));
        }
    }

    #[test]
    fn accepted_nested_roots_are_counted_and_traversed_once() {
        let fixture = Fixture::new();
        let child = fixture.root.join("one/two");
        fs::create_dir_all(&child).unwrap();
        fs::write(child.join("data"), b"1234").unwrap();
        let mut command = fixture.command();
        command
            .arg("scan")
            .arg(&fixture.root)
            .arg(&child)
            .args(["--json", "--max-depth", "1"]);
        let value = json(&capture(command), 0);
        assert_eq!(value["complete"], true);
        assert_eq!(value["roots"].as_array().unwrap().len(), 2);
        assert_eq!(value["totals"]["directories"], 3);
        assert_eq!(value["totals"]["regular_files"], 1);
        assert_eq!(value["totals"]["logical_bytes_known"], 4);
        let paths: std::collections::HashSet<_> = value["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["path"]["raw"].as_str().unwrap())
            .collect();
        assert_eq!(paths.len(), value["entries"].as_array().unwrap().len());
    }

    #[test]
    fn a_rejected_explicit_root_makes_a_mixed_scan_partial() {
        let fixture = Fixture::new();
        fs::write(fixture.root.join("data"), b"1234").unwrap();
        let other = fixture.base.join("other");
        fs::create_dir(&other).unwrap();
        let alias = fixture.base.join("other-link");
        symlink(&other, &alias).unwrap();
        let mut command = fixture.command();
        command
            .arg("scan")
            .arg(&fixture.root)
            .arg(&alias)
            .arg("--json");
        let value = json(&capture(command), 3);
        assert_eq!(value["status"], "partial");
        assert_eq!(value["complete"], false);
        assert_eq!(value["totals"]["unique_files"], 1);
        assert_eq!(value["totals"]["logical_bytes_known"], 4);
        assert!(value["issues"].as_array().unwrap().iter().any(|issue| {
            issue["code"] == "link_skipped" && issue["path"]["raw"] == raw(&alias)
        }));
    }

    #[test]
    fn entry_and_depth_budgets_are_partial() {
        let fixture = Fixture::new();
        fs::create_dir_all(fixture.root.join("one/two/three")).unwrap();
        fs::write(fixture.root.join("one/two/three/file"), b"x").unwrap();
        for (flag, limit, code) in [
            ("--max-entries", "1", "entry_limit"),
            ("--max-depth", "1", "depth_limit"),
        ] {
            let value = json(&fixture.scan(&["--json", flag, limit]), 3);
            assert_eq!(value["status"], "partial");
            assert_eq!(value["complete"], false);
            assert!(
                value["issues"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|issue| issue["code"] == code)
            );
        }
    }

    #[test]
    fn progress_is_versioned_ndjson_only_on_stderr() {
        let fixture = Fixture::new();
        fs::write(fixture.root.join("data"), b"hello").unwrap();
        let output = fixture.scan(&["--json", "--progress"]);
        let value = json(&output, 0);
        let stderr = std::str::from_utf8(&output.stderr).unwrap();
        assert!(!stderr.is_empty());
        for line in stderr.lines() {
            let progress: Value = serde_json::from_str(line).unwrap();
            assert_eq!(progress["schema_version"], 1);
            assert_eq!(progress["type"], "progress");
            assert_eq!(progress["task_id"], value["task_id"]);
            for key in [
                "entries",
                "unique_files",
                "logical_bytes_known",
                "issues",
                "elapsed_ms",
            ] {
                assert!(progress[key].is_u64());
            }
            assert_eq!(progress.as_object().unwrap().len(), 8);
        }
    }

    #[test]
    fn profile_scan_stderr_is_opt_in_and_keeps_stdout_json_contract() {
        let fixture = Fixture::new();
        fs::write(fixture.root.join("data"), b"hello").unwrap();
        let output = fixture.scan(&["--json", "--profile-scan-stderr"]);
        let value = json(&output, 0);
        assert_eq!(value["schema_version"], 1);
        assert!(value["entries"].is_array());
        let lines: Vec<&str> = std::str::from_utf8(&output.stderr)
            .unwrap()
            .lines()
            .collect();
        assert_eq!(lines.len(), 1);
        let profile: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(profile["schema_version"], 1);
        assert_eq!(profile["type"], "scan_profile");
        assert_eq!(profile["status"], value["status"]);
        assert!(profile["main_to_dispatch_ms"].is_number());
        assert!(profile["setup_ms"].is_number());
        assert!(profile["scan_ms"].is_number());
        assert!(profile["json_encode_write_flush_ms"].is_number());
        assert!(profile["stdout_json_bytes"].is_u64());
        assert_eq!(profile["stdout_json_bytes"], output.stdout.len());
        let plain = fixture.scan(&["--json"]);
        let plain_value = json(&plain, 0);
        assert_eq!(plain_value["totals"], value["totals"]);
        assert!(!String::from_utf8_lossy(&plain.stderr).contains("scan_profile"));
    }

    #[test]
    fn profile_scan_requires_json_and_marks_unrun_phases() {
        let fixture = Fixture::new();
        let no_json = fixture.scan(&["--profile-scan-stderr"]);
        assert_eq!(no_json.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&no_json.stderr).contains("--json"));

        let output = fixture.scan(&["--json", "--profile-scan-stderr", "--max-open-dirs", "0"]);
        let value = json(&output, 2);
        assert_eq!(value["status"], "failed");
        let profile: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(profile["status"], "failed");
        assert!(profile["setup_ms"].is_number());
        assert!(profile["scan_ms"].is_null());
        assert!(profile["engine_elapsed_ms"].is_null());
        assert_eq!(profile["output_error"], "invalid_limits");
    }

    #[test]
    fn sigint_cancels_an_owned_child_after_first_progress() {
        let fixture = Fixture::new();
        // Bounded, dedicated fixture; one worker keeps cancellation observable.
        for directory in 0..120 {
            let path = fixture.root.join(format!("dir-{directory}"));
            fs::create_dir(&path).unwrap();
            for file in 0..100 {
                fs::write(path.join(format!("file-{file}")), b"x").unwrap();
            }
        }
        let mut command = fixture.command();
        command.arg("scan").arg(&fixture.root).args([
            "--json",
            "--progress",
            "--workers",
            "1",
            "--timeout-ms",
            "20000",
        ]);
        let running = Running::start(command);
        running
            .first_progress
            .recv_timeout(Duration::from_secs(10))
            .expect("first progress");
        let mut signal = Command::new("/bin/kill");
        fixture.isolate(&mut signal);
        signal.args(["-INT", &running.child.process.id().to_string()]);
        assert!(capture(signal).status.success());
        let output = running.finish();
        let value = json(&output, 130);
        assert_eq!(value["status"], "cancelled");
        assert_eq!(value["complete"], false);
        assert!(value["entries"].as_array().unwrap().len() < 12_121);
    }
}
