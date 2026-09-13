// SPDX-License-Identifier: MPL-2.0

use super::*;
use crate::scan::{ScanCode, ScanIssue, ScanMetrics, ScanStatus, ScanTaskId, ScanTotals};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[cfg(not(windows))]
fn root() -> PathBuf {
    PathBuf::from("/rules-fixture")
}

#[cfg(windows)]
fn root() -> PathBuf {
    PathBuf::from("C:/rules-fixture")
}

fn path(relative: &str) -> PathBuf {
    if relative.is_empty() {
        root()
    } else {
        root().join(relative)
    }
}

fn identity(id: u64) -> FileIdentity {
    #[cfg(not(windows))]
    {
        FileIdentity::Unix {
            device: 7,
            inode: id,
        }
    }
    #[cfg(windows)]
    {
        let mut file_id = [0_u8; 16];
        file_id[0..8].copy_from_slice(&id.to_le_bytes());
        FileIdentity::Windows {
            volume_serial: 11,
            file_id,
        }
    }
}

fn directory(id: u64, relative: &str) -> ScanEntry {
    ScanEntry {
        id,
        path: path(relative),
        kind: ResourceKind::Directory,
        identity: identity(id),
        logical_bytes: None,
        allocated_bytes: None,
        dataless: false,
        counted: false,
        depth: usize::MAX,
    }
}

fn file(id: u64, relative: &str, bytes: Option<u64>) -> ScanEntry {
    ScanEntry {
        id,
        path: path(relative),
        kind: ResourceKind::File,
        identity: identity(id),
        logical_bytes: bytes,
        allocated_bytes: bytes,
        dataless: false,
        counted: true,
        depth: usize::MAX,
    }
}

fn link(id: u64, relative: &str) -> ScanEntry {
    ScanEntry {
        id,
        path: path(relative),
        kind: ResourceKind::Link,
        identity: identity(id),
        logical_bytes: None,
        allocated_bytes: None,
        dataless: false,
        counted: false,
        depth: usize::MAX,
    }
}

fn report(entries: Vec<ScanEntry>) -> ScanReport {
    ScanReport {
        task_id: ScanTaskId::synthetic(1),
        roots: vec![path("")],
        status: ScanStatus::Complete,
        complete: true,
        entries,
        issues: Vec::new(),
        issues_omitted: 0,
        totals: ScanTotals::default(),
        metrics: ScanMetrics::default(),
    }
}

struct FakeEvidence {
    uid: Option<u32>,
    facts: HashMap<PathBuf, Result<NativeFacts, NativeInspectError>>,
}

impl NativeEvidence for FakeEvidence {
    fn current_uid(&self) -> Option<u32> {
        self.uid
    }

    fn inspect_with_ancestry(
        &self,
        root: &Path,
        _root_identity: FileIdentity,
        relative_path: &Path,
        _ancestor_identities: &[(PathBuf, FileIdentity)],
        _cancellation: &Cancellation,
    ) -> Result<NativeFacts, NativeInspectError> {
        let full_path = root.join(relative_path);
        self.facts
            .get(&full_path)
            .copied()
            .unwrap_or(Err(NativeInspectError::Unsupported))
    }
}

fn preview_with(report: ScanReport, provider: &dyn NativeEvidence) -> RulePreview {
    let tree = ScanTree::build(report, &Cancellation::default()).unwrap();
    preview_with_provider(&tree, &Cancellation::default(), provider)
}

#[test]
fn parser_accepts_cpython_name_opt_dotted_and_unicode() {
    let parsed = parse_cpython_name(std::ffi::OsStr::new("mod.cpython-313.pyc")).unwrap();
    assert_eq!(parsed.module_basename, "mod");
    assert_eq!(parsed.cache_tag, "cpython-313");
    assert_eq!(parsed.optimization, None);
    let parsed =
        parse_cpython_name(std::ffi::OsStr::new("pkg.mod.cpython-311.opt-A3.pyc")).unwrap();
    assert_eq!(parsed.module_basename, "pkg.mod");
    assert_eq!(parsed.optimization, Some("A3".into()));
    let parsed = parse_cpython_name(std::ffi::OsStr::new("模块.cpython-312.pyc")).unwrap();
    assert_eq!(parsed.module_basename, "模块");
}

#[test]
fn parser_refuses_non_cpython_and_malformed_tags() {
    for name in [
        "mod.pyc",
        "mod.cpython-31.pyc",
        "mod.cpython-311.opt-!.pyc",
        "mod.pypy-311.pyc",
        ".cpython-311.pyc",
        "mod.cpython-311.pyo",
    ] {
        assert!(
            parse_cpython_name(std::ffi::OsStr::new(name)).is_none(),
            "{name}"
        );
    }
    #[cfg(unix)]
    {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let invalid = OsString::from_vec(b"mod.cpython-311.\xff.pyc".to_vec());
        assert!(parse_cpython_name(&invalid).is_none());
    }
}

#[test]
fn preview_returns_manual_review_candidate_when_evidence_is_consistent() {
    let target = file(4, "pkg/__pycache__/module.cpython-311.pyc", Some(218));
    let source = file(5, "pkg/module.py", Some(11));
    let preview = preview_with(
        report(vec![
            directory(1, ""),
            directory(2, "pkg"),
            directory(3, "pkg/__pycache__"),
            target.clone(),
            source.clone(),
        ]),
        &FakeEvidence {
            uid: Some(1000),
            facts: HashMap::from([
                (
                    target.path.clone(),
                    Ok(NativeFacts {
                        identity: target.identity,
                        kind: ResourceKind::File,
                        nlink: Some(1),
                        uid: Some(1000),
                        dataless: false,
                    }),
                ),
                (
                    source.path.clone(),
                    Ok(NativeFacts {
                        identity: source.identity,
                        kind: ResourceKind::File,
                        nlink: Some(1),
                        uid: Some(1000),
                        dataless: false,
                    }),
                ),
            ]),
        },
    );
    assert_eq!(preview.candidates.len(), 1);
    assert_eq!(preview.candidates[0].action, RuleAction::ManualReview);
    assert_eq!(preview.matched_bytes_known, 218);
    assert_eq!(preview.matched_bytes_unknown_files, 0);
    assert!(!preview.effects_performed);
    assert!(preview.refusals.is_empty());
}

#[test]
fn preview_refuses_missing_source_and_non_pycache_layout() {
    let target = file(4, "pkg/__pycache__/module.cpython-311.pyc", Some(218));
    let wrong = file(5, "pkg/module.cpython-311.pyc", Some(218));
    let preview = preview_with(
        report(vec![
            directory(1, ""),
            directory(2, "pkg"),
            directory(3, "pkg/__pycache__"),
            target.clone(),
            wrong.clone(),
        ]),
        &FakeEvidence {
            uid: Some(1000),
            facts: HashMap::new(),
        },
    );
    assert!(preview.candidates.is_empty());
    assert!(
        preview
            .refusals
            .iter()
            .any(|item| item.code == RefusalCode::SourceMissing
                && item.path == Some(target.path.clone()))
    );
    assert!(
        preview
            .refusals
            .iter()
            .any(|item| item.code == RefusalCode::NotPycacheChild
                && item.path == Some(wrong.path.clone()))
    );
}

#[test]
fn preview_refuses_source_links_hardlinks_and_identity_drift() {
    let mut target = file(4, "pkg/__pycache__/module.cpython-311.pyc", Some(218));
    let source_link = link(5, "pkg/module.py");
    target.counted = false;
    let first = preview_with(
        report(vec![
            directory(1, ""),
            directory(2, "pkg"),
            directory(3, "pkg/__pycache__"),
            target.clone(),
            source_link.clone(),
        ]),
        &FakeEvidence {
            uid: Some(1000),
            facts: HashMap::new(),
        },
    );
    assert!(
        first
            .refusals
            .iter()
            .any(|item| item.code == RefusalCode::SourceIsLink)
    );
    let source = file(6, "pkg/module.py", Some(11));
    let second = preview_with(
        report(vec![
            directory(1, ""),
            directory(2, "pkg"),
            directory(3, "pkg/__pycache__"),
            target.clone(),
            source.clone(),
        ]),
        &FakeEvidence {
            uid: Some(1000),
            facts: HashMap::new(),
        },
    );
    assert!(
        second
            .refusals
            .iter()
            .any(|item| item.code == RefusalCode::DuplicateOrHardlinkAmbiguous)
    );
    let third = preview_with(
        report(vec![
            directory(1, ""),
            directory(2, "pkg"),
            directory(3, "pkg/__pycache__"),
            file(7, "pkg/__pycache__/module.cpython-311.pyc", Some(1)),
            source.clone(),
        ]),
        &FakeEvidence {
            uid: Some(1000),
            facts: HashMap::from([(
                path("pkg/__pycache__/module.cpython-311.pyc"),
                Ok(NativeFacts {
                    identity: identity(999),
                    kind: ResourceKind::File,
                    nlink: Some(1),
                    uid: Some(1000),
                    dataless: false,
                }),
            )]),
        },
    );
    assert!(
        third
            .refusals
            .iter()
            .any(|item| item.code == RefusalCode::UnsupportedRulePlatform
                || item.code == RefusalCode::IdentityChanged)
    );
}

#[test]
fn preview_refuses_owner_unknown_or_mismatch_and_cross_root_source() {
    let target = file(4, "pkg/__pycache__/module.cpython-311.pyc", Some(218));
    let source = file(5, "pkg/module.py", Some(11));
    let mut report = report(vec![
        directory(2, "pkg"),
        directory(3, "pkg/__pycache__"),
        target.clone(),
        source.clone(),
    ]);
    report.roots = vec![path("pkg"), path("pkg/__pycache__")];
    let preview = preview_with(
        report,
        &FakeEvidence {
            uid: None,
            facts: HashMap::from([
                (
                    target.path.clone(),
                    Ok(NativeFacts {
                        identity: target.identity,
                        kind: ResourceKind::File,
                        nlink: Some(1),
                        uid: None,
                        dataless: false,
                    }),
                ),
                (
                    source.path.clone(),
                    Ok(NativeFacts {
                        identity: source.identity,
                        kind: ResourceKind::File,
                        nlink: Some(1),
                        uid: None,
                        dataless: false,
                    }),
                ),
            ]),
        },
    );
    assert!(
        preview
            .refusals
            .iter()
            .any(|item| item.code == RefusalCode::SourceOutsideRoot)
    );
}

#[test]
fn preview_cancellation_after_scan_phase_sets_cancelled_status_and_zero_bytes() {
    let cancellation = Cancellation::default();
    cancellation.cancel();
    let result = preview(
        report(vec![
            directory(1, ""),
            directory(2, "pkg"),
            directory(3, "pkg/__pycache__"),
            file(4, "pkg/__pycache__/module.cpython-311.pyc", Some(218)),
            file(5, "pkg/module.py", Some(11)),
        ]),
        CPYTHON_SOURCE_BACKED_PYC_RULE_ID,
        &cancellation,
    )
    .unwrap();
    assert_eq!(result.status, "cancelled");
    assert!(!result.complete);
    assert!(result.candidates.is_empty());
    assert_eq!(result.matched_bytes_known, 0);
    assert_eq!(result.matched_bytes_unknown_files, 0);
    assert!(
        result
            .refusals
            .iter()
            .any(|refusal| refusal.code == RefusalCode::Cancelled)
    );
}

#[test]
fn preview_cancellation_during_rule_phase_sets_cancelled_status() {
    struct CancellingEvidence {
        uid: Option<u32>,
        cancellation: Cancellation,
    }
    impl NativeEvidence for CancellingEvidence {
        fn current_uid(&self) -> Option<u32> {
            self.uid
        }

        fn inspect_with_ancestry(
            &self,
            root: &Path,
            _root_identity: FileIdentity,
            relative_path: &Path,
            _ancestor_identities: &[(PathBuf, FileIdentity)],
            _cancellation: &Cancellation,
        ) -> Result<NativeFacts, NativeInspectError> {
            self.cancellation.cancel();
            let full_path = root.join(relative_path);
            let inode = if full_path.ends_with("module.py") {
                5
            } else {
                4
            };
            Ok(NativeFacts {
                identity: identity(inode),
                kind: ResourceKind::File,
                nlink: Some(1),
                uid: self.uid,
                dataless: false,
            })
        }
    }
    let report = report(vec![
        directory(1, ""),
        directory(2, "pkg"),
        directory(3, "pkg/__pycache__"),
        file(4, "pkg/__pycache__/module.cpython-311.pyc", Some(218)),
        file(5, "pkg/module.py", Some(11)),
        file(6, "pkg/not_cache.pyc", Some(12)),
    ]);
    let tree = ScanTree::build(report, &Cancellation::default()).unwrap();
    let cancellation = Cancellation::default();
    let preview = preview_with_provider(
        &tree,
        &cancellation,
        &CancellingEvidence {
            uid: Some(1000),
            cancellation: cancellation.clone(),
        },
    );
    assert_eq!(preview.status, "cancelled");
    assert!(!preview.complete);
    assert!(preview.candidates.is_empty());
    assert_eq!(preview.matched_bytes_known, 0);
    assert!(
        preview
            .refusals
            .iter()
            .any(|r| r.code == RefusalCode::Cancelled)
    );
}

#[test]
fn preview_cancellation_after_successful_target_probe_clears_candidates_and_stops() {
    struct CancelAfterProbeEvidence {
        uid: Option<u32>,
        cancellation: Cancellation,
        cancel_on_call: usize,
        calls: Cell<usize>,
        probes: RefCell<Vec<PathBuf>>,
    }
    impl NativeEvidence for CancelAfterProbeEvidence {
        fn current_uid(&self) -> Option<u32> {
            self.uid
        }

        fn inspect_with_ancestry(
            &self,
            root: &Path,
            _root_identity: FileIdentity,
            relative_path: &Path,
            _ancestor_identities: &[(PathBuf, FileIdentity)],
            _cancellation: &Cancellation,
        ) -> Result<NativeFacts, NativeInspectError> {
            let full_path = root.join(relative_path);
            self.probes.borrow_mut().push(full_path.clone());
            let call = self.calls.get() + 1;
            self.calls.set(call);
            if call == self.cancel_on_call {
                self.cancellation.cancel();
            }
            let inode = if full_path.ends_with("module1.cpython-311.pyc") {
                4
            } else if full_path.ends_with("module1.py") {
                5
            } else if full_path.ends_with("module2.cpython-311.pyc") {
                6
            } else if full_path.ends_with("module2.py") {
                7
            } else if full_path.ends_with("module3.cpython-311.pyc") {
                8
            } else if full_path.ends_with("module3.py") {
                9
            } else {
                return Err(NativeInspectError::Unsupported);
            };
            Ok(NativeFacts {
                identity: identity(inode),
                kind: ResourceKind::File,
                nlink: Some(1),
                uid: self.uid,
                dataless: false,
            })
        }
    }

    let report = report(vec![
        directory(1, ""),
        directory(2, "pkg"),
        directory(3, "pkg/__pycache__"),
        file(4, "pkg/__pycache__/module1.cpython-311.pyc", Some(200)),
        file(5, "pkg/module1.py", Some(10)),
        file(6, "pkg/__pycache__/module2.cpython-311.pyc", Some(201)),
        file(7, "pkg/module2.py", Some(10)),
        file(8, "pkg/__pycache__/module3.cpython-311.pyc", Some(202)),
        file(9, "pkg/module3.py", Some(10)),
    ]);
    let tree = ScanTree::build(report, &Cancellation::default()).unwrap();
    let cancellation = Cancellation::default();
    let provider = CancelAfterProbeEvidence {
        uid: Some(1000),
        cancellation: cancellation.clone(),
        cancel_on_call: 3,
        calls: Cell::new(0),
        probes: RefCell::new(Vec::new()),
    };

    let preview = preview_with_provider(&tree, &cancellation, &provider);
    assert_eq!(preview.status, "cancelled");
    assert!(!preview.complete);
    assert!(preview.candidates.is_empty());
    assert_eq!(preview.matched_bytes_known, 0);
    assert_eq!(preview.matched_bytes_unknown_files, 0);
    assert!(
        preview
            .refusals
            .iter()
            .any(|r| r.code == RefusalCode::Cancelled)
    );
    assert_eq!(
        provider.probes.borrow().len(),
        3,
        "must stop probing after cancellation is observed"
    );
}

#[test]
fn preview_cancellation_after_successful_source_probe_clears_candidates_and_stops() {
    struct CancelAfterProbeEvidence {
        uid: Option<u32>,
        cancellation: Cancellation,
        cancel_on_call: usize,
        calls: Cell<usize>,
        probes: RefCell<Vec<PathBuf>>,
    }
    impl NativeEvidence for CancelAfterProbeEvidence {
        fn current_uid(&self) -> Option<u32> {
            self.uid
        }

        fn inspect_with_ancestry(
            &self,
            root: &Path,
            _root_identity: FileIdentity,
            relative_path: &Path,
            _ancestor_identities: &[(PathBuf, FileIdentity)],
            _cancellation: &Cancellation,
        ) -> Result<NativeFacts, NativeInspectError> {
            let full_path = root.join(relative_path);
            self.probes.borrow_mut().push(full_path.clone());
            let call = self.calls.get() + 1;
            self.calls.set(call);
            if call == self.cancel_on_call {
                self.cancellation.cancel();
            }
            let inode = if full_path.ends_with("module1.cpython-311.pyc") {
                4
            } else if full_path.ends_with("module1.py") {
                5
            } else if full_path.ends_with("module2.cpython-311.pyc") {
                6
            } else if full_path.ends_with("module2.py") {
                7
            } else if full_path.ends_with("module3.cpython-311.pyc") {
                8
            } else if full_path.ends_with("module3.py") {
                9
            } else {
                return Err(NativeInspectError::Unsupported);
            };
            Ok(NativeFacts {
                identity: identity(inode),
                kind: ResourceKind::File,
                nlink: Some(1),
                uid: self.uid,
                dataless: false,
            })
        }
    }

    let report = report(vec![
        directory(1, ""),
        directory(2, "pkg"),
        directory(3, "pkg/__pycache__"),
        file(4, "pkg/__pycache__/module1.cpython-311.pyc", Some(200)),
        file(5, "pkg/module1.py", Some(10)),
        file(6, "pkg/__pycache__/module2.cpython-311.pyc", Some(201)),
        file(7, "pkg/module2.py", Some(10)),
        file(8, "pkg/__pycache__/module3.cpython-311.pyc", Some(202)),
        file(9, "pkg/module3.py", Some(10)),
    ]);
    let tree = ScanTree::build(report, &Cancellation::default()).unwrap();
    let cancellation = Cancellation::default();
    let provider = CancelAfterProbeEvidence {
        uid: Some(1000),
        cancellation: cancellation.clone(),
        cancel_on_call: 4,
        calls: Cell::new(0),
        probes: RefCell::new(Vec::new()),
    };

    let preview = preview_with_provider(&tree, &cancellation, &provider);
    assert_eq!(preview.status, "cancelled");
    assert!(!preview.complete);
    assert!(preview.candidates.is_empty());
    assert_eq!(preview.matched_bytes_known, 0);
    assert_eq!(preview.matched_bytes_unknown_files, 0);
    assert!(
        preview
            .refusals
            .iter()
            .any(|r| r.code == RefusalCode::Cancelled)
    );
    assert_eq!(
        provider.probes.borrow().len(),
        4,
        "must stop probing after cancellation is observed"
    );
}

#[test]
fn preview_refuses_policy_failure_and_dataless_transitions() {
    let target = file(4, "pkg/__pycache__/module.cpython-311.pyc", Some(218));
    let source = file(5, "pkg/module.py", Some(11));
    let base = || {
        report(vec![
            directory(1, ""),
            directory(2, "pkg"),
            directory(3, "pkg/__pycache__"),
            target.clone(),
            source.clone(),
        ])
    };
    let policy_failure = preview_with(
        base(),
        &FakeEvidence {
            uid: Some(1000),
            facts: HashMap::from([(target.path.clone(), Err(NativeInspectError::PolicyFailure))]),
        },
    );
    assert!(policy_failure.candidates.is_empty());
    assert!(
        policy_failure
            .refusals
            .iter()
            .any(|item| item.code == RefusalCode::NativePolicyFailure)
    );
    let target_dataless = preview_with(
        base(),
        &FakeEvidence {
            uid: Some(1000),
            facts: HashMap::from([
                (
                    target.path.clone(),
                    Ok(NativeFacts {
                        identity: target.identity,
                        kind: ResourceKind::File,
                        nlink: Some(1),
                        uid: Some(1000),
                        dataless: true,
                    }),
                ),
                (
                    source.path.clone(),
                    Ok(NativeFacts {
                        identity: source.identity,
                        kind: ResourceKind::File,
                        nlink: Some(1),
                        uid: Some(1000),
                        dataless: false,
                    }),
                ),
            ]),
        },
    );
    assert!(target_dataless.candidates.is_empty());
    assert!(
        target_dataless
            .refusals
            .iter()
            .any(|item| item.code == RefusalCode::CandidateDatalessOrCloud)
    );
    let source_dataless = preview_with(
        base(),
        &FakeEvidence {
            uid: Some(1000),
            facts: HashMap::from([
                (
                    target.path.clone(),
                    Ok(NativeFacts {
                        identity: target.identity,
                        kind: ResourceKind::File,
                        nlink: Some(1),
                        uid: Some(1000),
                        dataless: false,
                    }),
                ),
                (
                    source.path.clone(),
                    Ok(NativeFacts {
                        identity: source.identity,
                        kind: ResourceKind::File,
                        nlink: Some(1),
                        uid: Some(1000),
                        dataless: true,
                    }),
                ),
            ]),
        },
    );
    assert!(source_dataless.candidates.is_empty());
    assert!(
        source_dataless
            .refusals
            .iter()
            .any(|item| item.code == RefusalCode::SourceDatalessOrCloud)
    );
}

#[test]
fn preview_emits_incomplete_and_compatibility_state() {
    let mut report = report(vec![directory(1, "")]);
    report.complete = false;
    report.status = ScanStatus::Partial;
    report.issues_omitted = 2;
    report.issues.push(ScanIssue {
        path: Some(path("pkg")),
        code: ScanCode::EntryLimit,
        message: "synthetic".into(),
        os_code: None,
    });
    let preview = preview_with(
        report,
        &FakeEvidence {
            uid: Some(1),
            facts: HashMap::new(),
        },
    );
    assert_eq!(preview.status, "partial");
    assert_eq!(preview.issues_omitted, 2);
    assert_eq!(preview.issues.len(), 1);
    assert_eq!(preview.issues[0].code, ScanCode::EntryLimit);
    assert!(
        preview
            .refusals
            .iter()
            .any(|item| item.code == RefusalCode::ScanIncomplete)
    );
    assert!(preview.compatible_with_current_ruleset());
    let mut stale = preview.clone();
    stale.ruleset_revision += 1;
    assert!(!stale.compatible_with_current_ruleset());
}

#[test]
fn preview_rejects_unknown_rule_id() {
    assert!(matches!(
        preview(
            report(vec![directory(1, "")]),
            "invalid",
            &Cancellation::default()
        ),
        Err(PreviewError::InvalidRuleId)
    ));
}

#[test]
fn explicit_selection_derives_source_from_cpython_target() {
    let target = path("pkg/__pycache__/module.cpython-311.opt-1.pyc");
    let selection = explicit_selection_for_target(&target).expect("valid explicit CPython target");
    assert_eq!(selection.target_path, target);
    assert_eq!(selection.source_path, path("pkg/module.py"));
    assert_eq!(selection.cache_tag, "cpython-311");
    assert_eq!(selection.optimization_tag.as_deref(), Some("1"));
    assert!(explicit_selection_for_target(&path("pkg/module.pyc")).is_none());
}

#[test]
fn cpython_rule_catalog_includes_explicit_native_trash_action() {
    let rule = builtin_rules()
        .iter()
        .find(|rule| rule.id == CPYTHON_SOURCE_BACKED_PYC_RULE_ID)
        .expect("builtin cpython rule");
    assert_eq!(rule.version, CPYTHON_SOURCE_BACKED_PYC_RULE_VERSION);
    assert_eq!(rule.ruleset_revision, BUILTIN_RULESET_REVISION);
    assert!(rule.actions.contains(&RuleAction::ManualReview));
    assert!(rule.actions.contains(&RuleAction::ExplicitNativeTrash));
}
