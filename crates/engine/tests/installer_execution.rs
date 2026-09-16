// SPDX-License-Identifier: MPL-2.0

#![cfg(target_os = "macos")]

use sayaka_engine::execute::InstallerSession;
use sayaka_engine::installer_preview::{
    FormatStatus, InstallerPreview, InstallerPreviewOptions, InstallerStatus, SelectionCheckStatus,
    preview_installers, preview_selection,
};
use sayaka_engine::journal::{ItemState, Store};
use sayaka_engine::model::Cancellation;
use sayaka_engine::scan::{self, ScanLimits};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[path = "support/owned_temp.rs"]
mod owned_temp;

struct Fixture {
    owned: owned_temp::OwnedTempDir,
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let owned = owned_temp::OwnedTempDir::new(
            Path::new(env!("CARGO_MANIFEST_DIR")),
            "sayaka-installer-action-",
        )
        .unwrap();
        fs::set_permissions(owned.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let root = owned.path().join("downloads");
        fs::create_dir(&root).unwrap();
        Self { owned, root }
    }

    fn preview(&self, excludes: Vec<PathBuf>, limits: ScanLimits) -> InstallerPreview {
        let cancellation = Cancellation::default();
        let report = scan::scan(
            std::slice::from_ref(&self.root),
            &limits,
            &cancellation,
            |_| {},
        )
        .unwrap();
        preview_installers(
            report,
            &InstallerPreviewOptions {
                excludes,
                ..Default::default()
            },
            &cancellation,
            Duration::from_secs(30),
        )
    }

    fn store(&self) -> Store {
        Store::open(&self.owned.path().join("journal"), true).unwrap()
    }
}

fn dmg(path: &Path) {
    let mut bytes = vec![0u8; 2048];
    let footer = &mut bytes[1536..];
    footer[..4].copy_from_slice(b"koly");
    footer[4..8].copy_from_slice(&4u32.to_be_bytes());
    footer[8..12].copy_from_slice(&512u32.to_be_bytes());
    footer[0xd8..0xe0].copy_from_slice(&128u64.to_be_bytes());
    footer[0xe0..0xe8].copy_from_slice(&64u64.to_be_bytes());
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn pkg(path: &Path) {
    let xml = b"<xar><toc><file><name>PackageInfo</name><type>file</type></file></toc></xar>";
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(xml).unwrap();
    let toc = encoder.finish().unwrap();
    let mut bytes = vec![0u8; 28];
    bytes[..4].copy_from_slice(b"xar!");
    bytes[4..6].copy_from_slice(&28u16.to_be_bytes());
    bytes[6..8].copy_from_slice(&1u16.to_be_bytes());
    bytes[8..16].copy_from_slice(&(toc.len() as u64).to_be_bytes());
    bytes[16..24].copy_from_slice(&(xml.len() as u64).to_be_bytes());
    bytes.extend(toc);
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn readonly_selection_returns_exact_observations_without_plan_or_state() {
    let fixture = Fixture::new();
    dmg(&fixture.root.join("image.dmg"));
    pkg(&fixture.root.join("package.pkg"));
    let preview = fixture.preview(vec![], ScanLimits::default());
    let indices: Vec<_> = (0..preview.candidates.len()).collect();
    let checked = preview_selection(&preview, &indices, &Cancellation::default()).unwrap();
    assert_eq!(checked.status, SelectionCheckStatus::Checked);
    assert_eq!(checked.selected.len(), 2);
    assert!(checked.issues.is_empty());
    let json = sayaka_engine::installer_preview::wire::selection_json(&checked);
    assert_eq!(json["effects_performed"], false);
    assert_eq!(json["execution_authority"], false);
    assert_eq!(json["snapshot_only"], true);
    assert!(json.get("plan").is_none() && json.get("approval").is_none());
    assert!(!fixture.owned.path().join("journal").exists());
    assert!(fixture.root.join("image.dmg").exists());
    assert!(fixture.root.join("package.pkg").exists());
    for invalid in [vec![], vec![0, 0], vec![usize::MAX], vec![0; 33]] {
        assert!(preview_selection(&preview, &invalid, &Cancellation::default()).is_err());
    }
    let cancellation = Cancellation::default();
    cancellation.cancel();
    let cancelled = preview_selection(&preview, &indices, &cancellation).unwrap();
    assert_eq!(cancelled.status, SelectionCheckStatus::Cancelled);
    assert_eq!(cancelled.selected.len(), 2);
}

#[test]
fn readonly_selection_refuses_changed_target_root_and_ancestor() {
    for change in ["content", "target", "root", "ancestor", "mode", "partial"] {
        let fixture = Fixture::new();
        let nested = fixture.root.join("nested");
        fs::create_dir(&nested).unwrap();
        let image = nested.join("image.dmg");
        dmg(&image);
        let mut preview = fixture.preview(vec![], ScanLimits::default());
        match change {
            "content" => {
                let mut bytes = fs::read(&image).unwrap();
                bytes[0] ^= 1;
                fs::write(&image, bytes).unwrap();
            }
            "target" => {
                fs::rename(&image, nested.join("old.dmg")).unwrap();
                dmg(&image);
            }
            "root" => {
                fs::rename(&fixture.root, fixture.owned.path().join("old-downloads")).unwrap();
                fs::create_dir(&fixture.root).unwrap();
                fs::create_dir(&nested).unwrap();
                dmg(&image);
            }
            "ancestor" => {
                let old = fixture.root.join("old-nested");
                fs::rename(&nested, &old).unwrap();
                fs::create_dir(&nested).unwrap();
                fs::rename(old.join("image.dmg"), &image).unwrap();
            }
            "mode" => fs::set_permissions(&image, fs::Permissions::from_mode(0o640)).unwrap(),
            "partial" => {
                preview.complete = false;
                preview.status = InstallerStatus::Partial;
            }
            _ => unreachable!(),
        }
        let refused = preview_selection(&preview, &[0], &Cancellation::default()).unwrap();
        assert_eq!(refused.status, SelectionCheckStatus::Refused, "{change}");
        assert!(!refused.issues.is_empty(), "{change}");
        assert_eq!(refused.selected.len(), 1);
        assert!(image.exists());
        assert!(!fixture.owned.path().join("journal").exists());
    }
}

#[test]
fn readonly_selection_keeps_invalid_members_and_unknown_measurements_visible() {
    let fixture = Fixture::new();
    dmg(&fixture.root.join("good.dmg"));
    fs::write(fixture.root.join("bad.pkg"), b"not a package").unwrap();
    let preview = fixture.preview(vec![], ScanLimits::default());
    let refused = preview_selection(&preview, &[0, 1], &Cancellation::default()).unwrap();
    assert_eq!(refused.status, SelectionCheckStatus::Refused);
    assert_eq!(refused.selected.len(), 2);
    assert!(
        refused
            .issues
            .iter()
            .any(|issue| issue.code == "format_not_recognized")
    );
    let mut unknown = preview.clone();
    unknown.candidates[0].logical_bytes = None;
    let result = preview_selection(&unknown, &[0], &Cancellation::default()).unwrap();
    assert_eq!(result.status, SelectionCheckStatus::Refused);
    assert_eq!(result.selected[0].logical_bytes, None);
    assert_eq!(result.bytes.matched_logical_unknown_files, 1);
    assert_eq!(result.bytes.matched_logical_bytes, 0);
    assert!(!fixture.owned.path().join("journal").exists());
}

#[test]
fn installer_prepares_exact_recognized_files_without_state_or_effects() {
    let fixture = Fixture::new();
    let image = fixture.root.join("image.dmg");
    let package = fixture.root.join("package.pkg");
    dmg(&image);
    pkg(&package);
    fs::write(fixture.root.join("fake.pkg"), b"not an archive").unwrap();
    let preview = fixture.preview(vec![], ScanLimits::default());
    assert!(preview.selection_ready());
    assert_eq!(
        preview
            .candidates
            .iter()
            .filter(|candidate| candidate.selectable())
            .count(),
        2
    );
    let mut session = InstallerSession::prepare(
        &preview,
        &[image.clone(), package.clone()],
        &Cancellation::default(),
    )
    .unwrap();
    assert!(session.ready());
    assert_eq!(session.preview().items().len(), 2);
    assert_eq!(
        session
            .preview()
            .expires_at()
            .duration_since(session.preview().created_at())
            .unwrap(),
        Duration::from_secs(120)
    );
    session.approve().unwrap();
    assert!(image.is_file() && package.is_file());
    assert!(!fixture.owned.path().join("journal").exists());
}

#[test]
fn installer_selection_refuses_unrecognized_duplicates_bounds_and_tampered_context() {
    let fixture = Fixture::new();
    let image = fixture.root.join("image.dmg");
    let fake = fixture.root.join("fake.pkg");
    dmg(&image);
    fs::write(&fake, b"not a package").unwrap();
    let preview = fixture.preview(vec![], ScanLimits::default());
    let token = Cancellation::default();
    for paths in [
        vec![],
        vec![fake.clone()],
        vec![image.clone(), image.clone()],
        vec![image.clone(); 33],
    ] {
        assert!(InstallerSession::prepare(&preview, &paths, &token).is_err());
    }
    let mut forged = preview.clone();
    let candidate = forged
        .candidates
        .iter_mut()
        .find(|item| item.path == fake)
        .unwrap();
    candidate.format.status = FormatStatus::Recognized;
    assert!(!candidate.selectable());
    assert!(InstallerSession::prepare(&forged, &[fake], &token).is_err());
    let mut changed = preview.clone();
    changed.schema_version += 1;
    assert!(!changed.selection_ready());
    assert!(InstallerSession::prepare(&changed, std::slice::from_ref(&image), &token).is_err());
    let mut changed = preview.clone();
    changed.excludes.push(image.clone());
    assert!(!changed.selection_ready());
    assert!(InstallerSession::prepare(&changed, std::slice::from_ref(&image), &token).is_err());
    let mut partial = fixture.preview(
        vec![],
        ScanLimits {
            max_entries: 1,
            ..Default::default()
        },
    );
    assert!(!partial.selection_ready());
    partial.complete = true;
    partial.status = InstallerStatus::Complete;
    assert!(!partial.selection_ready());
    assert!(InstallerSession::prepare(&partial, &[image], &token).is_err());
}

#[test]
fn installer_rejects_same_size_content_change_after_inspection() {
    let fixture = Fixture::new();
    let image = fixture.root.join("image.dmg");
    dmg(&image);
    let preview = fixture.preview(vec![], ScanLimits::default());
    let mut bytes = fs::read(&image).unwrap();
    bytes[0] = 1;
    fs::write(&image, bytes).unwrap();
    assert!(InstallerSession::prepare(&preview, &[image], &Cancellation::default()).is_err());
}

#[test]
fn installer_rejects_target_and_root_replacement_after_inspection() {
    for replace_root in [false, true] {
        let fixture = Fixture::new();
        let image = fixture.root.join("image.dmg");
        dmg(&image);
        let preview = fixture.preview(vec![], ScanLimits::default());
        if replace_root {
            fs::rename(&fixture.root, fixture.owned.path().join("old-downloads")).unwrap();
            fs::create_dir(&fixture.root).unwrap();
        } else {
            fs::rename(&image, fixture.root.join("old-image")).unwrap();
        }
        dmg(&image);
        assert!(InstallerSession::prepare(&preview, &[image], &Cancellation::default()).is_err());
    }
}

#[test]
fn installer_rejects_changed_ancestor_but_allows_unrelated_sibling_creation() {
    let fixture = Fixture::new();
    let child = fixture.root.join("nested");
    fs::create_dir(&child).unwrap();
    let image = child.join("image.dmg");
    dmg(&image);
    let preview = fixture.preview(vec![], ScanLimits::default());
    fs::write(fixture.root.join("unrelated.txt"), b"unrelated").unwrap();
    assert!(
        InstallerSession::prepare(
            &preview,
            std::slice::from_ref(&image),
            &Cancellation::default()
        )
        .unwrap()
        .ready()
    );
    let old = fixture.root.join("old-nested");
    fs::rename(&child, &old).unwrap();
    fs::create_dir(&child).unwrap();
    fs::rename(old.join("image.dmg"), &image).unwrap();
    assert!(InstallerSession::prepare(&preview, &[image], &Cancellation::default()).is_err());
}

#[test]
fn installer_batch_does_not_approve_a_subset_of_native_refusals() {
    let fixture = Fixture::new();
    let first = fixture.root.join("first.dmg");
    let second = fixture.root.join("second.dmg");
    dmg(&first);
    dmg(&second);
    fs::set_permissions(&second, fs::Permissions::from_mode(0o660)).unwrap();
    let preview = fixture.preview(vec![], ScanLimits::default());
    let mut session =
        InstallerSession::prepare(&preview, &[first, second], &Cancellation::default()).unwrap();
    assert_eq!(session.preview().items().len(), 1);
    assert!(!session.ready());
    assert!(!session.refusals().is_empty());
    assert!(session.approve().is_err());
    assert!(!fixture.owned.path().join("journal").exists());
}

#[test]
fn installer_cancelled_execution_records_only_skips_without_native_effect() {
    let fixture = Fixture::new();
    let image = fixture.root.join("image.dmg");
    dmg(&image);
    let before = fs::read(&image).unwrap();
    let preview = fixture.preview(vec![], ScanLimits::default());
    let cancellation = Cancellation::default();
    let mut session =
        InstallerSession::prepare(&preview, std::slice::from_ref(&image), &cancellation).unwrap();
    let approval = session.approve().unwrap();
    cancellation.cancel();
    let store = fixture.store();
    let report = session.execute(&approval, &cancellation, &store).unwrap();
    assert_eq!(report.exit_code(), 130);
    assert_eq!(report.record.schema_version, 1);
    assert_eq!(report.record.items[0].state, ItemState::Skipped);
    assert!(report.record.items[0].destination.is_none());
    assert_eq!(fs::read(image).unwrap(), before);
    assert_eq!(store.records().unwrap().records.len(), 1);
}

#[test]
fn installer_changed_file_or_exclusion_cannot_be_reapproved() {
    for change_exclusion in [false, true] {
        let fixture = Fixture::new();
        let image = fixture.root.join("image.dmg");
        let keep = fixture.root.join("keep.txt");
        dmg(&image);
        fs::write(&keep, b"keep").unwrap();
        let preview = fixture.preview(vec![keep.clone()], ScanLimits::default());
        let cancellation = Cancellation::default();
        let mut session =
            InstallerSession::prepare(&preview, std::slice::from_ref(&image), &cancellation)
                .unwrap();
        session.approve().unwrap();
        if change_exclusion {
            fs::rename(&keep, fixture.root.join("old-keep")).unwrap();
            fs::write(&keep, b"replacement").unwrap();
        } else {
            fs::write(&image, b"changed after approval").unwrap();
        }
        let before = fs::read(&image).unwrap();
        assert!(session.approve().is_err());
        assert_eq!(fs::read(image).unwrap(), before);
        assert!(!fixture.owned.path().join("journal").exists());
    }
}
