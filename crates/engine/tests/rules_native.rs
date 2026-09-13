// SPDX-License-Identifier: MPL-2.0

#![cfg(target_os = "macos")]

#[path = "support/fixture.rs"]
mod fixture;

use fixture::Fixture;
use sayaka_engine::model::Cancellation;
use sayaka_engine::rules::{self, RefusalCode};
use sayaka_engine::scan::{self, ScanLimits};
use std::fs;

fn scope(fixture: &Fixture) -> std::path::PathBuf {
    let root = fixture.path().canonicalize().unwrap().join("rules");
    fs::create_dir(&root).unwrap();
    root
}

fn preview(root: &std::path::Path) -> rules::RulePreview {
    let report = scan::scan(
        &[root.to_path_buf()],
        &ScanLimits::default(),
        &Cancellation::default(),
        |_| {},
    )
    .unwrap();
    rules::preview(
        report,
        rules::CPYTHON_SOURCE_BACKED_PYC_RULE_ID,
        &Cancellation::default(),
    )
    .unwrap()
}

#[test]
fn cpython_source_backed_preview_matches_multiple_distinct_pyc_identities() {
    let fixture = Fixture::new().unwrap();
    let root = scope(&fixture);
    fs::create_dir(root.join("pkg")).unwrap();
    fs::create_dir(root.join("pkg/__pycache__")).unwrap();
    fs::write(root.join("pkg/module.py"), b"print('x')\n").unwrap();
    let pyc = vec![0x6a; 218];
    fs::write(root.join("pkg/__pycache__/module.cpython-39.pyc"), &pyc).unwrap();
    fs::write(
        root.join("pkg/__pycache__/module.cpython-39.opt-2.pyc"),
        &pyc,
    )
    .unwrap();
    let result = preview(&root);
    assert_eq!(result.candidates.len(), 2, "{:?}", result.refusals);
    assert!(result.refusals.is_empty());
    assert_eq!(result.matched_bytes_known, 436);
    assert_eq!(result.candidates[0].source_path, root.join("pkg/module.py"));
    assert_eq!(result.candidates[1].source_path, root.join("pkg/module.py"));
    assert_ne!(
        result.candidates[0].target_identity,
        result.candidates[1].target_identity
    );
    fixture.close().unwrap();
}

#[test]
fn cpython_preview_refuses_hardlink_aliases_and_identity_changes() {
    let fixture = Fixture::new().unwrap();
    let root = scope(&fixture);
    fs::create_dir_all(root.join("pkg/__pycache__")).unwrap();
    fs::write(root.join("pkg/module.py"), b"print('x')\n").unwrap();
    let pyc = root.join("pkg/__pycache__/module.cpython-39.pyc");
    fs::write(&pyc, vec![0x11; 32]).unwrap();
    fs::hard_link(&pyc, fixture.path().join("pyc-alias")).unwrap();
    let first = preview(&root);
    assert!(first.candidates.is_empty());
    assert!(
        first
            .refusals
            .iter()
            .any(|item| item.code == RefusalCode::DuplicateOrHardlinkAmbiguous)
    );
    fs::remove_file(fixture.path().join("pyc-alias")).unwrap();

    let report = scan::scan(
        std::slice::from_ref(&root),
        &ScanLimits::default(),
        &Cancellation::default(),
        |_| {},
    )
    .unwrap();
    fs::write(root.join("pkg/module.py.tmp"), b"changed\n").unwrap();
    fs::rename(root.join("pkg/module.py.tmp"), root.join("pkg/module.py")).unwrap();
    let second = rules::preview(
        report,
        rules::CPYTHON_SOURCE_BACKED_PYC_RULE_ID,
        &Cancellation::default(),
    )
    .unwrap();
    assert!(second.candidates.is_empty());
    assert!(
        second
            .refusals
            .iter()
            .any(|item| item.code == RefusalCode::IdentityChanged)
    );
    fixture.close().unwrap();
}

#[test]
fn cpython_preview_refuses_missing_or_linked_sources() {
    let fixture = Fixture::new().unwrap();
    let root = scope(&fixture);
    fs::create_dir_all(root.join("pkg/__pycache__")).unwrap();
    fs::write(
        root.join("pkg/__pycache__/module.cpython-39.pyc"),
        vec![0x22; 64],
    )
    .unwrap();
    let missing = preview(&root);
    assert!(missing.candidates.is_empty());
    assert!(
        missing
            .refusals
            .iter()
            .any(|item| item.code == RefusalCode::SourceMissing)
    );
    #[cfg(target_os = "macos")]
    {
        std::os::unix::fs::symlink("module.py.real", root.join("pkg/module.py")).unwrap();
        let linked = preview(&root);
        assert!(
            linked
                .refusals
                .iter()
                .any(|item| item.code == RefusalCode::SourceIsLink)
        );
    }
    fixture.close().unwrap();
}

#[test]
fn cpython_preview_refuses_ancestor_swap_to_symlinked_moved_directory() {
    let fixture = Fixture::new().unwrap();
    let root = scope(&fixture);
    let package = root.join("pkg");
    fs::create_dir_all(package.join("__pycache__")).unwrap();
    fs::write(package.join("module.py"), b"print('x')\n").unwrap();
    fs::write(
        package.join("__pycache__/module.cpython-39.pyc"),
        vec![0x33; 64],
    )
    .unwrap();
    let report = scan::scan(
        std::slice::from_ref(&root),
        &ScanLimits::default(),
        &Cancellation::default(),
        |_| {},
    )
    .unwrap();
    let outside = fixture.path().join("outside-sentinel");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("keep.txt"), b"outside must stay untouched").unwrap();
    let moved = outside.join("moved-pkg");
    fs::rename(&package, &moved).unwrap();
    std::os::unix::fs::symlink(&moved, &package).unwrap();
    let result = rules::preview(
        report,
        rules::CPYTHON_SOURCE_BACKED_PYC_RULE_ID,
        &Cancellation::default(),
    )
    .unwrap();
    assert!(result.candidates.is_empty());
    assert!(
        result
            .refusals
            .iter()
            .any(|item| item.code == RefusalCode::IdentityChanged)
    );
    assert_eq!(
        fs::read(outside.join("keep.txt")).unwrap(),
        b"outside must stay untouched"
    );
    fixture.close().unwrap();
}
