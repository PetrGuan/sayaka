// SPDX-License-Identifier: MPL-2.0

#![cfg(target_os = "macos")]

#[path = "support/fixture.rs"]
mod fixture;

use fixture::Fixture;
use flate2::{Compression, write::ZlibEncoder};
use sayaka_engine::installer_preview::{
    CandidateNameKind, FormatStatus, INSTALLER_TOTAL_BUDGET, InstallerPreviewLimits,
    InstallerPreviewOptions, preview_installers,
};
use sayaka_engine::model::Cancellation;
use sayaka_engine::scan::{self, ScanLimits};
use std::fs;
use std::io::Write;
use std::path::Path;

fn scope(fixture: &Fixture) -> std::path::PathBuf {
    let root = fixture.path().canonicalize().unwrap().join("installer");
    fs::create_dir(&root).unwrap();
    root
}

fn fixture_parent() -> std::path::PathBuf {
    let parent = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("native-test-fixtures");
    fs::create_dir_all(&parent).unwrap();
    parent
}

fn write_udif_like(path: &Path) {
    let mut bytes = vec![0u8; 2048];
    let footer = &mut bytes[1536..2048];
    footer[0..4].copy_from_slice(b"koly");
    footer[4..8].copy_from_slice(&4u32.to_be_bytes());
    footer[8..12].copy_from_slice(&512u32.to_be_bytes());
    footer[0xd8..0xe0].copy_from_slice(&128u64.to_be_bytes());
    footer[0xe0..0xe8].copy_from_slice(&64u64.to_be_bytes());
    fs::write(path, bytes).unwrap();
}

fn write_flat_pkg(path: &Path, descriptor_name: &str) {
    let xml = format!(
        r#"<?xml version="1.0"?><xar><toc><file><name>{descriptor_name}</name><type>file</type></file></toc></xar>"#
    );
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(xml.as_bytes()).unwrap();
    let compressed = encoder.finish().unwrap();
    let mut header = vec![0u8; 28];
    header[0..4].copy_from_slice(&0x7861_7221u32.to_be_bytes());
    header[4..6].copy_from_slice(&28u16.to_be_bytes());
    header[6..8].copy_from_slice(&1u16.to_be_bytes());
    header[8..16].copy_from_slice(&(compressed.len() as u64).to_be_bytes());
    header[16..24].copy_from_slice(&(xml.len() as u64).to_be_bytes());
    header[24..28].copy_from_slice(&1u32.to_be_bytes());
    header.extend_from_slice(&compressed);
    fs::write(path, header).unwrap();
}

fn write_xar_with_xml(path: &Path, xml: &str) {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(xml.as_bytes()).unwrap();
    let compressed = encoder.finish().unwrap();
    let mut header = vec![0u8; 28];
    header[0..4].copy_from_slice(&0x7861_7221u32.to_be_bytes());
    header[4..6].copy_from_slice(&28u16.to_be_bytes());
    header[6..8].copy_from_slice(&1u16.to_be_bytes());
    header[8..16].copy_from_slice(&(compressed.len() as u64).to_be_bytes());
    header[16..24].copy_from_slice(&(xml.len() as u64).to_be_bytes());
    header[24..28].copy_from_slice(&1u32.to_be_bytes());
    header.extend_from_slice(&compressed);
    fs::write(path, header).unwrap();
}

fn write_xar_with_xml_declared_uncompressed(path: &Path, xml: &str, declared_uncompressed: u64) {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(xml.as_bytes()).unwrap();
    let compressed = encoder.finish().unwrap();
    let mut header = vec![0u8; 28];
    header[0..4].copy_from_slice(&0x7861_7221u32.to_be_bytes());
    header[4..6].copy_from_slice(&28u16.to_be_bytes());
    header[6..8].copy_from_slice(&1u16.to_be_bytes());
    header[8..16].copy_from_slice(&(compressed.len() as u64).to_be_bytes());
    header[16..24].copy_from_slice(&declared_uncompressed.to_be_bytes());
    header[24..28].copy_from_slice(&1u32.to_be_bytes());
    header.extend_from_slice(&compressed);
    fs::write(path, header).unwrap();
}

#[test]
fn installer_preview_recognizes_udif_and_pkg_descriptors() {
    let fixture = Fixture::new_in(&fixture_parent()).unwrap();
    let root = scope(&fixture);
    write_udif_like(&root.join("disk.dmg"));
    write_flat_pkg(&root.join("component.pkg"), "PackageInfo");
    write_flat_pkg(&root.join("product.pkg"), "Distribution");
    write_flat_pkg(&root.join("ordinary-xar.pkg"), "README.txt");
    let report = scan::scan(
        std::slice::from_ref(&root),
        &ScanLimits::default(),
        &Cancellation::default(),
        |_| {},
    )
    .unwrap();
    let preview = preview_installers(
        report,
        &InstallerPreviewOptions {
            filter: String::new(),
            excludes: vec![],
            limits: InstallerPreviewLimits::default(),
        },
        &Cancellation::default(),
        INSTALLER_TOTAL_BUDGET,
    );
    assert!(preview.candidates.iter().any(|item| {
        item.path.ends_with("disk.dmg") && item.format.status == FormatStatus::Recognized
    }));
    assert!(preview.candidates.iter().any(|item| {
        item.path.ends_with("component.pkg") && item.format.status == FormatStatus::Recognized
    }));
    assert!(preview.candidates.iter().any(|item| {
        item.path.ends_with("product.pkg") && item.format.status == FormatStatus::Recognized
    }));
    assert!(preview.candidates.iter().any(|item| {
        item.path.ends_with("ordinary-xar.pkg") && item.format.status != FormatStatus::Recognized
    }));
    fixture.close().unwrap();
}

#[test]
fn installer_preview_unsupported_and_corrupt_are_classified_without_partial_status() {
    let fixture = Fixture::new_in(&fixture_parent()).unwrap();
    let root = scope(&fixture);
    fs::write(root.join("wrong-magic.pkg"), vec![0x7f; 28]).unwrap();
    write_xar_with_xml(
        &root.join("truncated-xml.pkg"),
        r#"<?xml version="1.0"?><xar><toc><file><name>PackageInfo</name><type>file</type></file>"#,
    );
    let report = scan::scan(
        std::slice::from_ref(&root),
        &ScanLimits::default(),
        &Cancellation::default(),
        |_| {},
    )
    .unwrap();
    let preview = preview_installers(
        report,
        &InstallerPreviewOptions {
            filter: String::new(),
            excludes: vec![],
            limits: InstallerPreviewLimits::default(),
        },
        &Cancellation::default(),
        INSTALLER_TOTAL_BUDGET,
    );
    assert_eq!(preview.status.as_str(), "complete");
    assert!(preview.complete);
    assert!(preview.issues.is_empty());
    assert!(preview.candidates.iter().any(|item| {
        item.path.ends_with("wrong-magic.pkg") && item.format.status == FormatStatus::Unsupported
    }));
    assert!(preview.candidates.iter().any(|item| {
        item.path.ends_with("truncated-xml.pkg") && item.format.status == FormatStatus::Corrupt
    }));
    fixture.close().unwrap();
}

#[test]
fn installer_preview_rejects_non_top_level_or_incoherent_hints() {
    let fixture = Fixture::new_in(&fixture_parent()).unwrap();
    let root = scope(&fixture);
    write_xar_with_xml(
        &root.join("wrapped.pkg"),
        r#"<?xml version="1.0"?><xar><toc><metadata><file><name>PackageInfo</name><type>file</type></file></metadata></toc></xar>"#,
    );
    write_xar_with_xml(
        &root.join("dir.pkg"),
        r#"<?xml version="1.0"?><xar><toc><file><name>PackageInfo</name><type>directory</type></file></toc></xar>"#,
    );
    write_xar_with_xml(
        &root.join("dupe-name.pkg"),
        r#"<?xml version="1.0"?><xar><toc><file><name>PackageInfo</name><name>Distribution</name><type>file</type></file></toc></xar>"#,
    );
    let report = scan::scan(
        std::slice::from_ref(&root),
        &ScanLimits::default(),
        &Cancellation::default(),
        |_| {},
    )
    .unwrap();
    let preview = preview_installers(
        report,
        &InstallerPreviewOptions {
            filter: String::new(),
            excludes: vec![],
            limits: InstallerPreviewLimits::default(),
        },
        &Cancellation::default(),
        INSTALLER_TOTAL_BUDGET,
    );
    assert_eq!(preview.status.as_str(), "complete");
    assert!(
        preview
            .candidates
            .iter()
            .any(|item| item.path.ends_with("wrapped.pkg")
                && item.format.detection_level == "xar_archive_not_pkg")
    );
    assert!(
        preview
            .candidates
            .iter()
            .any(|item| item.path.ends_with("dir.pkg")
                && item.format.detection_level == "xar_archive_not_pkg")
    );
    assert!(
        preview
            .candidates
            .iter()
            .any(|item| item.path.ends_with("dupe-name.pkg")
                && item.format.status == FormatStatus::Corrupt)
    );
    fixture.close().unwrap();
}

#[test]
fn installer_preview_marks_over_cap_pkg_as_partial_not_corrupt() {
    let fixture = Fixture::new_in(&fixture_parent()).unwrap();
    let root = scope(&fixture);
    let xml = r#"<?xml version="1.0"?><xar><toc><file><name>PackageInfo</name><type>file</type></file></toc></xar>"#;
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(xml.as_bytes()).unwrap();
    let compressed = encoder.finish().unwrap();
    let mut header = vec![0u8; 28];
    header[0..4].copy_from_slice(&0x7861_7221u32.to_be_bytes());
    header[4..6].copy_from_slice(&28u16.to_be_bytes());
    header[6..8].copy_from_slice(&1u16.to_be_bytes());
    header[8..16].copy_from_slice(&(compressed.len() as u64).to_be_bytes());
    header[16..24].copy_from_slice(&(xml.len() as u64).to_be_bytes());
    header[24..28].copy_from_slice(&1u32.to_be_bytes());
    header.extend_from_slice(&compressed);
    fs::write(root.join("cap.pkg"), header).unwrap();
    let report = scan::scan(
        std::slice::from_ref(&root),
        &ScanLimits::default(),
        &Cancellation::default(),
        |_| {},
    )
    .unwrap();
    let preview = preview_installers(
        report,
        &InstallerPreviewOptions {
            filter: String::new(),
            excludes: vec![],
            limits: InstallerPreviewLimits {
                max_pkg_toc_compressed: 16,
                ..InstallerPreviewLimits::default()
            },
        },
        &Cancellation::default(),
        INSTALLER_TOTAL_BUDGET,
    );
    assert_eq!(preview.status.as_str(), "partial");
    assert!(
        preview
            .issues
            .iter()
            .any(|issue| issue.code.as_str() == "parse_limit")
    );
    assert!(
        preview
            .candidates
            .iter()
            .any(|item| item.path.ends_with("cap.pkg")
                && item.format.status == FormatStatus::Partial)
    );
    fixture.close().unwrap();
}

#[test]
fn installer_preview_declared_uncompressed_overflow_is_corrupt_not_partial() {
    let fixture = Fixture::new_in(&fixture_parent()).unwrap();
    let root = scope(&fixture);
    write_xar_with_xml_declared_uncompressed(
        &root.join("declared-too-small.pkg"),
        r#"<?xml version="1.0"?><xar><toc><file><name>PackageInfo</name><type>file</type></file></toc></xar>"#,
        1,
    );
    let report = scan::scan(
        std::slice::from_ref(&root),
        &ScanLimits::default(),
        &Cancellation::default(),
        |_| {},
    )
    .unwrap();
    let preview = preview_installers(
        report,
        &InstallerPreviewOptions {
            filter: String::new(),
            excludes: vec![],
            limits: InstallerPreviewLimits::default(),
        },
        &Cancellation::default(),
        INSTALLER_TOTAL_BUDGET,
    );
    assert_eq!(preview.status.as_str(), "complete");
    assert!(preview.complete);
    assert!(preview.issues.is_empty());
    assert_eq!(preview.metrics.expanded_bytes, 1);
    assert!(
        preview
            .candidates
            .iter()
            .any(|item| item.path.ends_with("declared-too-small.pkg")
                && item.format.status == FormatStatus::Corrupt
                && item.format.detection_level == "pkg_corrupt_or_truncated")
    );
    fixture.close().unwrap();
}

#[test]
fn installer_preview_aggregate_expanded_budget_shortage_is_partial() {
    let fixture = Fixture::new_in(&fixture_parent()).unwrap();
    let root = scope(&fixture);
    write_flat_pkg(&root.join("budget.pkg"), "PackageInfo");
    let report = scan::scan(
        std::slice::from_ref(&root),
        &ScanLimits::default(),
        &Cancellation::default(),
        |_| {},
    )
    .unwrap();
    let preview = preview_installers(
        report,
        &InstallerPreviewOptions {
            filter: String::new(),
            excludes: vec![],
            limits: InstallerPreviewLimits {
                max_expanded_bytes: 32,
                ..InstallerPreviewLimits::default()
            },
        },
        &Cancellation::default(),
        INSTALLER_TOTAL_BUDGET,
    );
    assert_eq!(preview.status.as_str(), "partial");
    assert!(!preview.complete);
    assert!(
        preview
            .issues
            .iter()
            .any(|issue| issue.code.as_str() == "parse_limit")
    );
    assert!(
        preview
            .candidates
            .iter()
            .any(|item| item.path.ends_with("budget.pkg")
                && item.format.status == FormatStatus::Partial
                && item.format.detection_level == "not_assessed")
    );
    fixture.close().unwrap();
}

#[test]
fn installer_preview_attribute_budget_exceeded_is_partial_not_recognized() {
    let fixture = Fixture::new_in(&fixture_parent()).unwrap();
    let root = scope(&fixture);
    let large_attr = "x".repeat(1024);
    write_xar_with_xml(
        &root.join("attr-over.pkg"),
        &format!(
            r#"<?xml version="1.0"?><xar><toc><file note="{large_attr}"><name>PackageInfo</name><type>file</type></file></toc></xar>"#
        ),
    );
    let report = scan::scan(
        std::slice::from_ref(&root),
        &ScanLimits::default(),
        &Cancellation::default(),
        |_| {},
    )
    .unwrap();
    let preview = preview_installers(
        report,
        &InstallerPreviewOptions {
            filter: String::new(),
            excludes: vec![],
            limits: InstallerPreviewLimits {
                max_retained_name_bytes: 256,
                ..InstallerPreviewLimits::default()
            },
        },
        &Cancellation::default(),
        INSTALLER_TOTAL_BUDGET,
    );
    assert_eq!(preview.status.as_str(), "partial");
    assert!(
        preview
            .issues
            .iter()
            .any(|issue| issue.code.as_str() == "parse_limit")
    );
    assert!(
        preview
            .candidates
            .iter()
            .any(|item| item.path.ends_with("attr-over.pkg")
                && item.format.status == FormatStatus::Partial)
    );
    fixture.close().unwrap();
}

#[test]
fn installer_preview_io_budget_denial_does_not_charge_candidate_bytes() {
    let fixture = Fixture::new_in(&fixture_parent()).unwrap();
    let root = scope(&fixture);
    write_udif_like(&root.join("cap.dmg"));
    let report = scan::scan(
        std::slice::from_ref(&root),
        &ScanLimits::default(),
        &Cancellation::default(),
        |_| {},
    )
    .unwrap();
    let preview = preview_installers(
        report,
        &InstallerPreviewOptions {
            filter: String::new(),
            excludes: vec![],
            limits: InstallerPreviewLimits {
                max_candidate_io_bytes: 511,
                ..InstallerPreviewLimits::default()
            },
        },
        &Cancellation::default(),
        INSTALLER_TOTAL_BUDGET,
    );
    assert_eq!(preview.status.as_str(), "partial");
    assert_eq!(preview.metrics.candidate_io_bytes, 0);
    assert!(
        preview
            .issues
            .iter()
            .any(|issue| issue.code.as_str() == "candidate_io_limit")
    );
    fixture.close().unwrap();
}

#[test]
fn installer_preview_marks_koly_range_overflow_as_corrupt_not_named_only() {
    let fixture = Fixture::new_in(&fixture_parent()).unwrap();
    let root = scope(&fixture);
    let mut bytes = vec![0u8; 2048];
    let footer = &mut bytes[1536..2048];
    footer[0..4].copy_from_slice(b"koly");
    footer[4..8].copy_from_slice(&4u32.to_be_bytes());
    footer[8..12].copy_from_slice(&512u32.to_be_bytes());
    footer[0xd8..0xe0].copy_from_slice(&u64::MAX.to_be_bytes());
    footer[0xe0..0xe8].copy_from_slice(&64u64.to_be_bytes());
    fs::write(root.join("overflow.dmg"), bytes).unwrap();
    let report = scan::scan(
        std::slice::from_ref(&root),
        &ScanLimits::default(),
        &Cancellation::default(),
        |_| {},
    )
    .unwrap();
    let preview = preview_installers(
        report,
        &InstallerPreviewOptions {
            filter: String::new(),
            excludes: vec![],
            limits: InstallerPreviewLimits::default(),
        },
        &Cancellation::default(),
        INSTALLER_TOTAL_BUDGET,
    );
    assert!(preview.candidates.iter().any(|item| {
        item.path.ends_with("overflow.dmg")
            && item.format.status == FormatStatus::Corrupt
            && item.format.detection_level == "corrupt_or_truncated"
    }));
    fixture.close().unwrap();
}

#[test]
fn installer_preview_deduplicates_totals_but_probes_hardlink_aliases() {
    let fixture = Fixture::new_in(&fixture_parent()).unwrap();
    let root = scope(&fixture);
    write_flat_pkg(&root.join("alias.pkg"), "PackageInfo");
    fs::hard_link(root.join("alias.pkg"), root.join("alias.dmg")).unwrap();
    let report = scan::scan(
        std::slice::from_ref(&root),
        &ScanLimits::default(),
        &Cancellation::default(),
        |_| {},
    )
    .unwrap();
    let preview = preview_installers(
        report,
        &InstallerPreviewOptions {
            filter: String::new(),
            excludes: vec![],
            limits: InstallerPreviewLimits::default(),
        },
        &Cancellation::default(),
        INSTALLER_TOTAL_BUDGET,
    );
    assert_eq!(preview.candidates.len(), 2);
    assert!(preview.candidates.iter().any(|item| {
        item.name_kind == CandidateNameKind::Pkg && item.format.status == FormatStatus::Recognized
    }));
    assert!(preview.candidates.iter().any(|item| {
        item.name_kind == CandidateNameKind::Dmg && item.format.status != FormatStatus::Recognized
    }));
    assert_eq!(preview.counts.aliases, 1);
    fixture.close().unwrap();
}

#[test]
fn installer_preview_excluding_one_alias_excludes_same_identity() {
    let fixture = Fixture::new_in(&fixture_parent()).unwrap();
    let root = scope(&fixture);
    write_flat_pkg(&root.join("target.pkg"), "PackageInfo");
    fs::hard_link(root.join("target.pkg"), root.join("target-copy.pkg")).unwrap();
    let report = scan::scan(
        std::slice::from_ref(&root),
        &ScanLimits::default(),
        &Cancellation::default(),
        |_| {},
    )
    .unwrap();
    let preview = preview_installers(
        report,
        &InstallerPreviewOptions {
            filter: String::new(),
            excludes: vec![root.join("target-copy.pkg")],
            limits: InstallerPreviewLimits::default(),
        },
        &Cancellation::default(),
        INSTALLER_TOTAL_BUDGET,
    );
    assert!(preview.candidates.is_empty());
    fixture.close().unwrap();
}
