// SPDX-License-Identifier: MPL-2.0

use super::*;

#[test]
fn default_limits_are_valid() {
    ScanLimits::default().validate().unwrap();
}

#[derive(Clone)]
struct Item {
    name: OsString,
    metadata: Result<Metadata, ScanError>,
}

#[derive(Clone)]
struct Directory {
    metadata: Metadata,
    items: Vec<Item>,
    unchanged: bool,
    open_error: Option<ScanError>,
    read_error: Option<ScanError>,
}

type Hook = Arc<dyn Fn(&Path, usize) + Send + Sync>;

struct Tree {
    directories: HashMap<PathBuf, Directory>,
    opened: Mutex<Vec<PathBuf>>,
    checked: Mutex<Vec<PathBuf>>,
    hook: Option<Hook>,
    fail_enter: bool,
    fail_restore: bool,
    panic_on_read: bool,
    fail_spawn_at: Option<usize>,
    policies_entered: AtomicUsize,
    policies_restored: Arc<AtomicUsize>,
    closed: AtomicUsize,
}

struct FakeBackend(Arc<Tree>);
struct FakeCursor {
    tree: Arc<Tree>,
    path: PathBuf,
    position: usize,
}
struct FakePolicy {
    fail: bool,
    restored: Arc<AtomicUsize>,
}

impl ThreadPolicy for FakePolicy {
    fn restore(self) -> Result<(), ScanError> {
        self.restored.fetch_add(1, Ordering::AcqRel);
        if self.fail {
            Err(ScanError::new(
                ScanCode::PolicyFailure,
                "injected restore failure",
            ))
        } else {
            Ok(())
        }
    }
}

impl Backend for FakeBackend {
    type Directory = FakeCursor;
    type Policy = FakePolicy;
    fn enter_thread(&self) -> Result<FakePolicy, ScanError> {
        self.0.policies_entered.fetch_add(1, Ordering::AcqRel);
        if self.0.fail_enter {
            Err(ScanError::new(
                ScanCode::PolicyFailure,
                "injected setup failure",
            ))
        } else {
            Ok(FakePolicy {
                fail: self.0.fail_restore,
                restored: Arc::clone(&self.0.policies_restored),
            })
        }
    }
    fn open_root(&self, path: &Path) -> Result<FakeCursor, ScanError> {
        open(&self.0, path)
    }

    fn spawn_worker<'scope, 'env: 'scope, F>(
        &self,
        scope: &'scope std::thread::Scope<'scope, 'env>,
        index: usize,
        action: F,
    ) -> std::io::Result<std::thread::ScopedJoinHandle<'scope, Result<(), ScanError>>>
    where
        F: FnOnce() -> Result<(), ScanError> + Send + 'scope,
    {
        if self.0.fail_spawn_at == Some(index) {
            Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "injected thread creation failure",
            ))
        } else {
            std::thread::Builder::new().spawn_scoped(scope, action)
        }
    }
}

impl Drop for FakeCursor {
    fn drop(&mut self) {
        self.tree.closed.fetch_add(1, Ordering::AcqRel);
    }
}

fn open(tree: &Arc<Tree>, path: &Path) -> Result<FakeCursor, ScanError> {
    let node = tree
        .directories
        .get(path)
        .ok_or_else(|| ScanError::new(ScanCode::NotFound, "missing fake directory"))?;
    if let Some(error) = &node.open_error {
        return Err(error.clone());
    }
    tree.opened.lock().unwrap().push(path.to_path_buf());
    Ok(FakeCursor {
        tree: Arc::clone(tree),
        path: path.to_path_buf(),
        position: 0,
    })
}

impl Cursor for FakeCursor {
    fn metadata(&self) -> Metadata {
        self.tree.directories[&self.path].metadata.clone()
    }
    #[cfg(target_os = "macos")]
    fn bare_repository(&self) -> Result<bool, ScanError> {
        assert!(
            self.tree.opened.lock().unwrap().contains(&self.path),
            "Git probes require an admitted handle"
        );
        let dir = &self.tree.directories[&self.path];
        Ok([
            ("HEAD", ResourceKind::File),
            ("objects", ResourceKind::Directory),
            ("refs", ResourceKind::Directory),
        ]
        .iter()
        .all(|(name, kind)| {
            dir.items.iter().any(|item| {
                item.name == *name && item.metadata.as_ref().is_ok_and(|m| m.kind == *kind)
            })
        }))
    }

    fn binds_project_artifact(&self, name: &std::ffi::OsStr) -> Result<bool, ScanError> {
        Ok(crate::purge_preview::ProjectMarker::ALL
            .iter()
            .any(|marker| {
                marker
                    .artifacts()
                    .iter()
                    .any(|candidate| name == *candidate)
                    && self.tree.directories[&self.path].items.iter().any(|item| {
                        item.name == marker.file_name()
                            && item
                                .metadata
                                .as_ref()
                                .is_ok_and(|m| m.kind == ResourceKind::File && !m.dataless)
                    })
            }))
    }

    fn next_entry(&mut self) -> Option<Result<DirItem, ScanError>> {
        assert!(!self.tree.panic_on_read, "injected worker panic");
        if let Some(hook) = &self.tree.hook {
            hook(&self.path, self.position);
        }
        let directory = &self.tree.directories[&self.path];
        if self.position == 0
            && let Some(error) = &directory.read_error
        {
            self.position += 1;
            return Some(Err(error.clone()));
        }
        let item = directory.items.get(self.position)?.clone();
        self.position += 1;
        Some(Ok(DirItem {
            name: item.name,
            metadata: item.metadata,
        }))
    }
    fn open_child(&self, item: &DirItem) -> Result<Self, ScanError> {
        open(&self.tree, &self.path.join(&item.name))
    }
    fn unchanged(&self) -> Result<bool, ScanError> {
        self.tree.checked.lock().unwrap().push(self.path.clone());
        Ok(self.tree.directories[&self.path].unchanged)
    }
}

fn root() -> PathBuf {
    #[cfg(windows)]
    {
        PathBuf::from(r"C:\scan-fixture")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/scan-fixture")
    }
}

fn metadata(inode: u64, kind: ResourceKind, bytes: Option<u64>) -> Metadata {
    Metadata {
        private_bytes: None,
        identity: FileIdentity::Unix { device: 1, inode },
        kind,
        link_count: Some(1),
        logical_bytes: bytes,
        allocated_bytes: bytes,
        modified_unix_ms: None,
        dataless: false,
    }
}

fn directory(inode: u64) -> Directory {
    Directory {
        metadata: metadata(inode, ResourceKind::Directory, None),
        items: Vec::new(),
        unchanged: true,
        open_error: None,
        read_error: None,
    }
}

fn tree() -> Tree {
    Tree {
        directories: HashMap::from([(root(), directory(1))]),
        opened: Mutex::new(Vec::new()),
        checked: Mutex::new(Vec::new()),
        hook: None,
        fail_enter: false,
        fail_restore: false,
        panic_on_read: false,
        fail_spawn_at: None,
        policies_entered: AtomicUsize::new(0),
        policies_restored: Arc::new(AtomicUsize::new(0)),
        closed: AtomicUsize::new(0),
    }
}

fn add_file(tree: &mut Tree, parent: &Path, name: &str, inode: u64, bytes: Option<u64>) {
    tree.directories.get_mut(parent).unwrap().items.push(Item {
        name: name.into(),
        metadata: Ok(metadata(inode, ResourceKind::File, bytes)),
    });
}

fn add_directory(tree: &mut Tree, parent: &Path, name: &str, inode: u64) -> PathBuf {
    let child = parent.join(name);
    tree.directories.get_mut(parent).unwrap().items.push(Item {
        name: name.into(),
        metadata: Ok(metadata(inode, ResourceKind::Directory, None)),
    });
    tree.directories.insert(child.clone(), directory(inode));
    child
}

fn execute(tree: Tree, limits: &ScanLimits) -> ScanReport {
    let backend = FakeBackend(Arc::new(tree));
    run(
        &backend,
        vec![root()],
        RunOptions {
            limits,
            cancellation: &Cancellation::default(),
            task_id: ScanTaskId::new().unwrap(),
            traversal_policy: TraversalPolicy::Default,
            started: Instant::now(),
        },
        |_| {},
    )
    .unwrap()
}

#[test]
fn reparse_refusal_after_directory_observation_is_a_gap_even_with_unchanged_parent() {
    let mut tree = tree();
    add_file(&mut tree, &root(), "readable", 2, Some(7));
    let child = add_directory(&mut tree, &root(), "changed", 3);
    tree.directories.get_mut(&child).unwrap().open_error = Some(ScanError::new(
        ScanCode::LinkSkipped,
        "injected reparse refusal",
    ));
    assert!(tree.directories[&root()].unchanged);
    let backend = FakeBackend(Arc::new(tree));
    let report = run(
        &backend,
        vec![root()],
        RunOptions {
            limits: &ScanLimits::default(),
            cancellation: &Cancellation::default(),
            task_id: ScanTaskId::new().unwrap(),
            traversal_policy: TraversalPolicy::Default,
            started: Instant::now(),
        },
        |_| {},
    )
    .unwrap();
    assert_eq!(report.status, ScanStatus::Partial);
    assert!(!report.complete);
    assert_eq!(report.totals.logical_bytes_known, 7);
    assert!(
        report.issues.iter().any(
            |issue| issue.code == ScanCode::ChangedEntry && issue.path.as_ref() == Some(&child)
        )
    );
    assert_eq!(backend.0.opened.lock().unwrap().as_slice(), &[root()]);
    assert_eq!(backend.0.closed.load(Ordering::Acquire), 1);
}

#[test]
fn normalization_preserves_distinct_explicit_roots_for_admission() {
    let limits = ScanLimits::default();
    let other = root().with_file_name("scan-fixture-other");
    assert_eq!(
        normalize_roots(
            &[root().join("nested"), other.clone(), root(), root()],
            &limits
        )
        .unwrap(),
        [root(), root().join("nested"), other]
    );
    for invalid in [
        Vec::new(),
        vec![PathBuf::from("relative")],
        vec![root().join("../escape")],
    ] {
        assert_eq!(
            normalize_roots(&invalid, &limits).unwrap_err().code,
            ScanCode::InvalidRoot
        );
    }
    let limits = ScanLimits {
        queue_capacity: 1,
        ..limits
    };
    assert_eq!(
        normalize_roots(&[root(), root().with_file_name("other")], &limits)
            .unwrap_err()
            .code,
        ScanCode::InvalidLimits
    );
    assert_eq!(
        normalize_roots(&[root().join("x".repeat(65_537))], &ScanLimits::default())
            .unwrap_err()
            .code,
        ScanCode::InvalidRoot
    );
}

#[test]
fn limits_reject_zero_and_out_of_range_budgets() {
    let invalid = [
        ScanLimits {
            workers: 0,
            ..ScanLimits::default()
        },
        ScanLimits {
            workers: 33,
            ..ScanLimits::default()
        },
        ScanLimits {
            queue_capacity: 0,
            ..ScanLimits::default()
        },
        ScanLimits {
            event_capacity: 0,
            ..ScanLimits::default()
        },
        ScanLimits {
            max_open_dirs: 1,
            ..ScanLimits::default()
        },
        ScanLimits {
            max_depth: 0,
            ..ScanLimits::default()
        },
        ScanLimits {
            max_entries: 0,
            ..ScanLimits::default()
        },
        ScanLimits {
            max_path_bytes: 0,
            ..ScanLimits::default()
        },
        ScanLimits {
            max_issues: 0,
            ..ScanLimits::default()
        },
        ScanLimits {
            time_budget: Duration::ZERO,
            ..ScanLimits::default()
        },
        ScanLimits {
            progress_every: 0,
            ..ScanLimits::default()
        },
    ];
    for limits in invalid {
        assert_eq!(limits.validate().unwrap_err().code, ScanCode::InvalidLimits);
    }
}

#[test]
fn unknown_sizes_are_not_fabricated_zero_and_hard_links_count_once() {
    let mut tree = tree();
    add_file(&mut tree, &root(), "unknown", 2, None);
    add_file(&mut tree, &root(), "known", 3, Some(42));
    add_file(&mut tree, &root(), "alias", 3, Some(42));
    let report = execute(tree, &ScanLimits::default());
    assert_eq!(report.status, ScanStatus::Complete);
    assert_eq!(report.totals.regular_files, 3);
    assert_eq!(report.totals.unique_files, 2);
    assert_eq!(report.totals.duplicate_files, 1);
    assert_eq!(report.totals.logical_bytes_known, 42);
    assert_eq!(report.totals.logical_bytes_unknown_files, 1);
    assert_eq!(
        report.entries.iter().filter(|entry| entry.counted).count(),
        2
    );
}

#[test]
fn byte_overflow_does_not_partially_commit_an_entry() {
    let mut tree = tree();
    add_file(&mut tree, &root(), "maximum", 2, Some(u64::MAX));
    add_file(&mut tree, &root(), "extra", 3, Some(1));
    let report = execute(
        tree,
        &ScanLimits {
            workers: 1,
            ..ScanLimits::default()
        },
    );
    assert_eq!(report.status, ScanStatus::Partial);
    assert_eq!(report.totals.unique_files, 1);
    assert_eq!(report.totals.regular_files, 1);
    assert_eq!(report.totals.logical_bytes_known, u64::MAX);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.code == ScanCode::Overflow)
    );
}

#[test]
fn links_cloud_directories_and_mounts_are_not_opened() {
    let mut tree = tree();
    let cloud = add_directory(&mut tree, &root(), "cloud", 2);
    let mount = add_directory(&mut tree, &root(), "mount", 3);
    let root_node = tree.directories.get_mut(&root()).unwrap();
    root_node.items[0].metadata.as_mut().unwrap().dataless = true;
    root_node.items[1].metadata.as_mut().unwrap().identity = FileIdentity::Unix {
        device: 2,
        inode: 3,
    };
    root_node.items.push(Item {
        name: "link".into(),
        metadata: Ok(metadata(4, ResourceKind::Link, None)),
    });
    let backend = FakeBackend(Arc::new(tree));
    let report = run(
        &backend,
        vec![root()],
        RunOptions {
            limits: &ScanLimits::default(),
            cancellation: &Cancellation::default(),
            task_id: ScanTaskId::new().unwrap(),
            traversal_policy: TraversalPolicy::Default,
            started: Instant::now(),
        },
        |_| {},
    )
    .unwrap();
    assert_eq!(report.status, ScanStatus::Partial);
    let opened = backend.0.opened.lock().unwrap();
    assert!(!opened.contains(&cloud) && !opened.contains(&mount));
    for code in [
        ScanCode::CloudDirectorySkipped,
        ScanCode::MountBoundary,
        ScanCode::LinkSkipped,
    ] {
        assert!(report.issues.iter().any(|issue| issue.code == code));
    }
}

#[test]
fn unavailable_metadata_and_directory_changes_remain_visible() {
    for code in [ScanCode::PermissionDenied, ScanCode::NotFound, ScanCode::Io] {
        let mut tree = tree();
        tree.directories.get_mut(&root()).unwrap().items.push(Item {
            name: "unknown".into(),
            metadata: Err(ScanError::new(code, "injected metadata failure")),
        });
        add_file(&mut tree, &root(), "known", 2, Some(5));
        let report = execute(tree, &ScanLimits::default());
        assert_eq!(report.status, ScanStatus::Partial);
        assert_eq!(report.totals.logical_bytes_known, 5);
        assert_eq!(report.issues[0].code, code);
    }
    let mut tree = tree();
    tree.directories.get_mut(&root()).unwrap().unchanged = false;
    let report = execute(tree, &ScanLimits::default());
    assert_eq!(report.status, ScanStatus::Partial);
    assert_eq!(report.issues[0].code, ScanCode::ChangedEntry);
}

#[test]
fn root_failures_and_read_errors_are_not_empty_success() {
    let mut tree = tree();
    tree.directories.get_mut(&root()).unwrap().open_error =
        Some(ScanError::new(ScanCode::PermissionDenied, "denied"));
    let report = execute(tree, &ScanLimits::default());
    assert_eq!(report.status, ScanStatus::Failed);
    assert!(!report.complete);
    let mut tree = self::tree();
    tree.directories.get_mut(&root()).unwrap().read_error =
        Some(ScanError::new(ScanCode::Io, "read error"));
    let report = execute(tree, &ScanLimits::default());
    assert_eq!(report.status, ScanStatus::Partial);
    assert_eq!(report.issues[0].code, ScanCode::Io);
}

#[test]
fn replacement_and_duplicate_directory_identities_are_not_traversed_twice() {
    let mut tree = tree();
    let child = add_directory(&mut tree, &root(), "changed", 2);
    tree.directories.get_mut(&child).unwrap().metadata.identity = FileIdentity::Unix {
        device: 1,
        inode: 99,
    };
    let report = execute(tree, &ScanLimits::default());
    assert_eq!(report.status, ScanStatus::Partial);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.code == ScanCode::ChangedEntry)
    );
    let mut tree = self::tree();
    add_directory(&mut tree, &root(), "same", 1);
    let report = execute(tree, &ScanLimits::default());
    assert_eq!(report.status, ScanStatus::Complete);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.code == ScanCode::DuplicateDirectory)
    );
}

#[test]
fn bounded_queue_full_fallback_finishes_a_wide_tree() {
    let mut tree = tree();
    for i in 0..200 {
        let child = add_directory(&mut tree, &root(), &format!("dir-{i}"), i * 2 + 2);
        add_file(&mut tree, &child, "file", i * 2 + 3, Some(1));
    }
    let limits = ScanLimits {
        workers: 2,
        queue_capacity: 1,
        event_capacity: 2,
        max_open_dirs: 16,
        ..ScanLimits::default()
    };
    let report = execute(tree, &limits);
    assert_eq!(report.status, ScanStatus::Complete, "{:?}", report.issues);
    assert_eq!(report.totals.unique_files, 200);
    assert!(report.metrics.peak_workers <= 2);
    assert!(report.metrics.peak_queued_dirs <= 1);
    assert!(report.metrics.peak_pending_events <= 2);
    assert!(report.metrics.peak_open_dirs <= 16);
}

#[test]
fn handle_and_depth_budgets_report_omitted_subtrees() {
    let mut tree = tree();
    add_directory(&mut tree, &root(), "queued", 2);
    let nested = add_directory(&mut tree, &root(), "inline", 3);
    add_directory(&mut tree, &nested, "too-deep", 4);
    let limits = ScanLimits {
        workers: 1,
        queue_capacity: 1,
        max_open_dirs: 3,
        ..ScanLimits::default()
    };
    let report = execute(tree, &limits);
    assert_eq!(report.status, ScanStatus::Partial);
    assert_eq!(report.metrics.peak_open_dirs, 3);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.code == ScanCode::OpenHandleLimit)
    );

    let mut tree = self::tree();
    let child = add_directory(&mut tree, &root(), "child", 2);
    add_directory(&mut tree, &child, "grandchild", 3);
    let report = execute(
        tree,
        &ScanLimits {
            max_depth: 1,
            ..ScanLimits::default()
        },
    );
    assert_eq!(report.status, ScanStatus::Partial);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.code == ScanCode::DepthLimit)
    );
}

#[test]
fn result_path_and_issue_budgets_are_enforced() {
    for limits in [
        ScanLimits {
            max_entries: 2,
            ..ScanLimits::default()
        },
        ScanLimits {
            max_path_bytes: root().as_os_str().len() + 2,
            ..ScanLimits::default()
        },
    ] {
        let mut tree = tree();
        for i in 0..30 {
            add_file(&mut tree, &root(), &format!("f{i}"), i + 2, Some(1));
        }
        let report = execute(tree, &limits);
        assert_eq!(report.status, ScanStatus::Partial);
        assert!(report.entries.len() <= limits.max_entries);
        assert!(report.metrics.retained_path_bytes <= limits.max_path_bytes);
        assert!(
            report
                .issues
                .iter()
                .any(|issue| matches!(issue.code, ScanCode::EntryLimit | ScanCode::PathBytesLimit))
        );
    }
    let mut tree = tree();
    for i in 0..20 {
        tree.directories.get_mut(&root()).unwrap().items.push(Item {
            name: format!("bad-{i}").into(),
            metadata: Err(ScanError::new(ScanCode::Io, "injected")),
        });
    }
    let report = execute(
        tree,
        &ScanLimits {
            max_issues: 2,
            ..ScanLimits::default()
        },
    );
    assert_eq!(report.status, ScanStatus::Partial);
    assert_eq!(report.issues.len(), 2);
    assert_eq!(report.issues_omitted, 18);
}

#[test]
fn cancellation_and_expired_budget_stop_without_new_scope_discovery() {
    let cancel = Cancellation::default();
    cancel.cancel();
    let backend = FakeBackend(Arc::new(tree()));
    let report = run(
        &backend,
        vec![root()],
        RunOptions {
            limits: &ScanLimits::default(),
            cancellation: &cancel,
            task_id: ScanTaskId::new().unwrap(),
            traversal_policy: TraversalPolicy::Default,
            started: Instant::now(),
        },
        |_| {},
    )
    .unwrap();
    assert_eq!(report.status, ScanStatus::Cancelled);
    assert!(backend.0.opened.lock().unwrap().is_empty());
    let report = run(
        &backend,
        vec![root()],
        RunOptions {
            limits: &ScanLimits {
                time_budget: Duration::from_secs(1),
                ..ScanLimits::default()
            },
            cancellation: &Cancellation::default(),
            task_id: ScanTaskId::new().unwrap(),
            traversal_policy: TraversalPolicy::Default,
            started: Instant::now() - Duration::from_secs(2),
        },
        |_| {},
    )
    .unwrap();
    assert_eq!(report.status, ScanStatus::Partial);
    assert_eq!(report.issues[0].code, ScanCode::DurationLimit);
    assert!(backend.0.opened.lock().unwrap().is_empty());
}

#[test]
fn cancellation_in_probe_prevents_child_open_and_progress_ids_are_scoped() {
    let mut tree = tree();
    add_directory(&mut tree, &root(), "child", 2);
    let cancel = Cancellation::default();
    let signal = cancel.clone();
    tree.hook = Some(Arc::new(move |_, _| signal.cancel()));
    let backend = FakeBackend(Arc::new(tree));
    let mut ids = Vec::new();
    let report = run(
        &backend,
        vec![root()],
        RunOptions {
            limits: &ScanLimits::default(),
            cancellation: &cancel,
            task_id: ScanTaskId::new().unwrap(),
            traversal_policy: TraversalPolicy::Default,
            started: Instant::now(),
        },
        |event| ids.push(event.task_id),
    )
    .unwrap();
    assert_eq!(report.status, ScanStatus::Cancelled);
    assert_eq!(backend.0.opened.lock().unwrap().as_slice(), [root()]);
    assert!(ids.iter().all(|id| *id == report.task_id));
    assert_ne!(report.task_id, ScanTaskId::new().unwrap());
}

#[test]
fn rejected_explicit_roots_are_gaps_even_for_normally_non_gap_codes() {
    let mut tree = tree();
    tree.directories.get_mut(&root()).unwrap().open_error = Some(ScanError::new(
        ScanCode::LinkSkipped,
        "root traverses a symlink",
    ));
    let accepted = root().with_file_name("accepted");
    tree.directories.insert(accepted.clone(), directory(2));
    add_file(&mut tree, &accepted, "data", 3, Some(4));
    let backend = FakeBackend(Arc::new(tree));
    let report = run(
        &backend,
        vec![root(), accepted],
        RunOptions {
            limits: &ScanLimits::default(),
            cancellation: &Cancellation::default(),
            task_id: ScanTaskId::new().unwrap(),
            traversal_policy: TraversalPolicy::Default,
            started: Instant::now(),
        },
        |_| {},
    )
    .unwrap();
    assert_eq!(report.status, ScanStatus::Partial);
    assert!(!report.complete);
    assert_eq!(report.totals.logical_bytes_known, 4);
    assert_eq!(report.issues[0].code, ScanCode::LinkSkipped);
}

#[test]
fn thread_creation_failure_stops_and_joins_workers_before_returning_an_error() {
    for fail_at in [0, 1] {
        let mut tree = tree();
        tree.fail_spawn_at = Some(fail_at);
        let backend = FakeBackend(Arc::new(tree));
        let result = run(
            &backend,
            vec![root()],
            RunOptions {
                limits: &ScanLimits::default(),
                cancellation: &Cancellation::default(),
                task_id: ScanTaskId::new().unwrap(),
                traversal_policy: TraversalPolicy::Default,
                started: Instant::now(),
            },
            |_| panic!("no progress should be emitted after worker startup failure"),
        );
        let error = result.unwrap_err();
        assert_eq!(error.code, ScanCode::WorkerStartFailed);
        assert!(error.message.contains("injected thread creation failure"));
        assert_eq!(backend.0.policies_entered.load(Ordering::Acquire), fail_at);
        assert_eq!(backend.0.policies_restored.load(Ordering::Acquire), fail_at);
        assert_eq!(
            backend.0.closed.load(Ordering::Acquire),
            backend.0.opened.lock().unwrap().len()
        );
    }
}

#[test]
fn worker_setup_restore_and_panic_failures_surface_without_hanging() {
    for mode in 0..3 {
        let mut tree = tree();
        tree.fail_enter = mode == 0;
        tree.fail_restore = mode == 1;
        tree.panic_on_read = mode == 2;
        let report = execute(tree, &ScanLimits::default());
        assert_eq!(report.status, ScanStatus::Partial);
        assert!(!report.complete);
        let expected = if mode == 2 {
            ScanCode::WorkerPanic
        } else {
            ScanCode::PolicyFailure
        };
        assert!(
            report.issues.iter().any(|issue| issue.code == expected),
            "{:?}",
            report.issues
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn cache_stream_does_not_retain_single_link_files_or_follow_links() {
    let mut fake = tree();
    for n in 0..100_001 {
        add_file(&mut fake, &root(), &format!("file-{n}"), n + 2, Some(3));
    }
    fake.directories.get_mut(&root()).unwrap().items.push(Item {
        name: "external-link".into(),
        metadata: Ok(metadata(200_000, ResourceKind::Link, None)),
    });
    let backend = FakeBackend(Arc::new(fake));
    let limits = ScanLimits {
        max_entries: 2,
        ..ScanLimits::default()
    };
    let result = crate::scan::cache::summarize(
        &backend,
        &root(),
        metadata(1, ResourceKind::Directory, None).identity,
        &limits,
        &Cancellation::default(),
        |_, _, _| {},
    )
    .unwrap();
    assert!(result.complete);
    assert_eq!(result.files, 100_001);
    assert_eq!(result.logical, Some(300_003));
    assert_eq!(result.links, 1);
    assert_eq!(*backend.0.opened.lock().unwrap(), vec![root()]);
}

#[cfg(target_os = "macos")]
#[test]
fn cache_stream_deduplicates_hardlinks_and_bounds_identity_memory() {
    let mut fake = tree();
    for (name, id) in [("a", 2), ("b", 2), ("c", 3)] {
        let mut meta = metadata(id, ResourceKind::File, Some(7));
        meta.link_count = Some(2);
        fake.directories.get_mut(&root()).unwrap().items.push(Item {
            name: name.into(),
            metadata: Ok(meta),
        });
    }
    let backend = FakeBackend(Arc::new(fake));
    let limits = ScanLimits {
        max_entries: 1,
        ..ScanLimits::default()
    };
    let result = crate::scan::cache::summarize(
        &backend,
        &root(),
        metadata(1, ResourceKind::Directory, None).identity,
        &limits,
        &Cancellation::default(),
        |_, _, _| {},
    )
    .unwrap();
    assert!(!result.complete);
    assert_eq!(result.logical, Some(7));
    assert_eq!(result.files, 1);
    assert!(
        result
            .issues
            .iter()
            .any(|issue| issue.code == ScanCode::EntryLimit)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn cache_stream_keeps_permission_gaps_and_cancellation_incomplete() {
    let mut fake = tree();
    let child = add_directory(&mut fake, &root(), "denied", 2);
    fake.directories.get_mut(&child).unwrap().open_error =
        Some(ScanError::new(ScanCode::PermissionDenied, "denied"));
    let backend = FakeBackend(Arc::new(fake));
    let result = crate::scan::cache::summarize(
        &backend,
        &root(),
        metadata(1, ResourceKind::Directory, None).identity,
        &ScanLimits::default(),
        &Cancellation::default(),
        |_, _, _| {},
    )
    .unwrap();
    assert!(!result.complete);
    assert!(
        result
            .issues
            .iter()
            .any(|issue| issue.code == ScanCode::PermissionDenied)
    );
    let cancellation = Cancellation::default();
    cancellation.cancel();
    let result = crate::scan::cache::summarize(
        &backend,
        &root(),
        metadata(1, ResourceKind::Directory, None).identity,
        &ScanLimits::default(),
        &cancellation,
        |_, _, _| {},
    )
    .unwrap();
    assert!(result.cancelled && !result.complete);
    assert_eq!(
        backend.0.policies_entered.load(Ordering::Acquire),
        backend.0.policies_restored.load(Ordering::Acquire)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn cache_stream_rejects_changed_root_and_changed_directory() {
    let mut fake = tree();
    fake.directories.get_mut(&root()).unwrap().unchanged = false;
    let backend = FakeBackend(Arc::new(fake));
    assert!(
        crate::scan::cache::summarize(
            &backend,
            &root(),
            metadata(999, ResourceKind::Directory, None).identity,
            &ScanLimits::default(),
            &Cancellation::default(),
            |_, _, _| {}
        )
        .is_err()
    );
    let result = crate::scan::cache::summarize(
        &backend,
        &root(),
        metadata(1, ResourceKind::Directory, None).identity,
        &ScanLimits::default(),
        &Cancellation::default(),
        |_, _, _| {},
    )
    .unwrap();
    assert!(!result.complete);
    assert!(
        result
            .issues
            .iter()
            .any(|issue| issue.code == ScanCode::ChangedEntry)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn cache_workers_share_hardlink_identity_and_unknown_size_accounting() {
    let mut fake = tree();
    for (name, inode) in [("left", 2), ("right", 3)] {
        let child = add_directory(&mut fake, &root(), name, inode);
        let mut shared = metadata(4, ResourceKind::File, Some(7));
        shared.link_count = Some(2);
        fake.directories.get_mut(&child).unwrap().items.push(Item {
            name: "shared".into(),
            metadata: Ok(shared),
        });
        add_file(&mut fake, &child, "own", inode + 10, Some(3));
    }
    let unknown = root().join("right");
    add_file(&mut fake, &unknown, "unknown", 20, None);
    let backend = FakeBackend(Arc::new(fake));
    let result = crate::scan::cache::summarize(
        &backend,
        &root(),
        metadata(1, ResourceKind::Directory, None).identity,
        &ScanLimits::default(),
        &Cancellation::default(),
        |_, _, _| {},
    )
    .unwrap();
    assert!(result.complete);
    assert_eq!(result.files, 4);
    assert_eq!(result.entries, 7);
    assert_eq!(result.logical, None);
    assert_eq!(result.allocated, None);
    assert_eq!(
        backend.0.opened.lock().unwrap().len(),
        backend.0.closed.load(Ordering::Acquire)
    );
    assert_eq!(
        backend.0.policies_entered.load(Ordering::Acquire),
        backend.0.policies_restored.load(Ordering::Acquire)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn project_subtree_workers_preserve_shared_identity_git_and_entry_budget() {
    for workers in [1, 4] {
        for max_entries in [3, 100] {
            let mut fake = tree();
            for (name, inode) in [("left", 2), ("right", 3)] {
                let child = add_directory(&mut fake, &root(), name, inode);
                let mut shared = metadata(4, ResourceKind::File, Some(7));
                shared.link_count = Some(2);
                fake.directories.get_mut(&child).unwrap().items.push(Item {
                    name: "shared".into(),
                    metadata: Ok(shared),
                });
                add_file(&mut fake, &child, "own", inode + 10, Some(3));
            }
            let git = add_directory(&mut fake, &root().join("left"), ".git", 30);
            add_file(&mut fake, &git, "history", 31, Some(1000));
            let backend = FakeBackend(Arc::new(fake));
            let budget = crate::scan::cache::ProjectSizeBudget {
                visited: AtomicUsize::new(0),
                max_entries,
                deadline: Instant::now() + Duration::from_secs(10),
            };
            let result = crate::scan::cache::summarize_with_project_budget(
                &backend,
                &root(),
                metadata(1, ResourceKind::Directory, None).identity,
                &ScanLimits { workers, ..ScanLimits::default() },
                Some(&budget),
                &Cancellation::default(),
                |_, _, _| {},
            ).unwrap();
            assert!(!result.complete);
            assert!(!backend.0.opened.lock().unwrap().contains(&git));
            if max_entries == 100 {
                assert_eq!(result.files, 3);
                assert_eq!(result.logical, Some(13));
                assert_eq!(result.vcs_metadata, 1);
                assert_eq!(budget.visited.load(Ordering::Acquire), 7);
            } else {
                assert_eq!(budget.visited.load(Ordering::Acquire), max_entries);
                assert!(result.issues.iter().any(|i| i.code == ScanCode::EntryLimit));
            }
            assert_eq!(backend.0.opened.lock().unwrap().len(), backend.0.closed.load(Ordering::Acquire));
            let entered = backend.0.policies_entered.load(Ordering::Acquire);
            assert!(entered <= workers);
            assert_eq!(entered, backend.0.policies_restored.load(Ordering::Acquire));
        }
    }
}

#[cfg(target_os = "macos")]
#[test]
fn cache_worker_start_failure_and_child_panic_return_without_stranding_queue() {
    for fail_spawn in [true, false] {
        let mut fake = tree();
        for n in 0..10 {
            add_directory(&mut fake, &root(), &format!("child-{n}"), n + 2);
        }
        if fail_spawn {
            fake.fail_spawn_at = Some(1);
        } else {
            fake.hook = Some(Arc::new(|path, _| {
                assert_eq!(path, root(), "injected child worker panic");
            }));
        }
        let backend = FakeBackend(Arc::new(fake));
        let result = crate::scan::cache::summarize(
            &backend,
            &root(),
            metadata(1, ResourceKind::Directory, None).identity,
            &ScanLimits::default(),
            &Cancellation::default(),
            |_, _, _| {},
        );
        assert_eq!(
            result.err().unwrap().code,
            if fail_spawn {
                ScanCode::WorkerStartFailed
            } else {
                ScanCode::WorkerPanic
            }
        );
        assert_eq!(
            backend.0.opened.lock().unwrap().len(),
            backend.0.closed.load(Ordering::Acquire)
        );
        if fail_spawn {
            assert_eq!(
                backend.0.policies_entered.load(Ordering::Acquire),
                backend.0.policies_restored.load(Ordering::Acquire)
            );
        }
    }
}

#[test]
fn project_scan_excludes_git_metadata_without_a_coverage_gap() {
    let mut tree = tree();
    let git = add_directory(&mut tree, &root(), ".git", 2);
    add_directory(&mut tree, &git, "objects", 3);
    let linked = add_directory(&mut tree, &root(), "linked", 4);
    add_file(&mut tree, &linked, ".git", 5, Some(40));
    add_file(&mut tree, &root(), "Cargo.toml", 6, Some(20));
    let backend = FakeBackend(Arc::new(tree));
    let limits = ScanLimits::default();
    let report = run_with_policy(
        &backend,
        vec![root()],
        RunOptions {
            limits: &limits,
            cancellation: &Cancellation::default(),
            task_id: ScanTaskId::new().unwrap(),
            traversal_policy: TraversalPolicy::ProjectDiscovery,
            started: Instant::now(),
        },
        |_| {},
    )
    .unwrap();
    assert!(report.complete);
    assert!(report.issues.is_empty());
    assert_eq!(report.vcs_metadata.len(), 2);
    assert!(!backend.0.opened.lock().unwrap().contains(&git));
    assert!(
        report
            .entries
            .iter()
            .all(|e| !crate::project_git::is_metadata_path(&e.path))
    );
    assert!(report.entries.iter().any(|e| e.path == root()));
}

#[test]
fn explicit_git_root_is_excluded_before_any_open() {
    let backend = FakeBackend(Arc::new(tree()));
    let limits = ScanLimits::default();
    let path = root().join(".git/objects");
    let report = run_with_policy(
        &backend,
        vec![path.clone()],
        RunOptions {
            limits: &limits,
            cancellation: &Cancellation::default(),
            task_id: ScanTaskId::new().unwrap(),
            traversal_policy: TraversalPolicy::ProjectDiscovery,
            started: Instant::now(),
        },
        |_| {},
    )
    .unwrap();
    assert!(report.complete);
    assert!(report.issues.is_empty());
    assert_eq!(report.vcs_metadata, vec![path]);
    assert!(backend.0.opened.lock().unwrap().is_empty());
}

#[test]
fn project_git_probes_do_not_open_foreign_mounts() {
    let mut tree = tree();
    let foreign = add_directory(&mut tree, &root(), "foreign", 2);
    let metadata = tree.directories.get_mut(&root()).unwrap().items[0]
        .metadata
        .as_mut()
        .unwrap();
    metadata.identity = FileIdentity::Unix {
        device: 2,
        inode: 2,
    };
    let backend = FakeBackend(Arc::new(tree));
    let limits = ScanLimits::default();
    let report = run_with_policy(
        &backend,
        vec![root()],
        RunOptions {
            limits: &limits,
            cancellation: &Cancellation::default(),
            task_id: ScanTaskId::new().unwrap(),
            traversal_policy: TraversalPolicy::ProjectDiscovery,
            started: Instant::now(),
        },
        |_| {},
    )
    .unwrap();
    assert!(!report.complete);
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.code == ScanCode::MountBoundary)
    );
    assert!(!backend.0.opened.lock().unwrap().contains(&foreign));
}

#[test]
fn project_discovery_prunes_artifacts_even_when_marker_is_listed_later() {
    let mut tree = tree();
    let target = add_directory(&mut tree, &root(), "target", 2);
    for i in 0..200 {
        add_file(&mut tree, &target, &format!("object-{i}"), 100 + i, Some(8));
    }
    add_file(&mut tree, &root(), "Cargo.toml", 3, Some(20));
    let later = add_directory(&mut tree, &root(), "later", 4);
    let modules = add_directory(&mut tree, &later, "node_modules", 5);
    add_file(&mut tree, &later, "package.json", 6, Some(20));
    let backend = FakeBackend(Arc::new(tree));
    let limits = ScanLimits {
        max_entries: 8,
        ..Default::default()
    };
    let report = run_with_policy(
        &backend,
        vec![root()],
        RunOptions {
            limits: &limits,
            cancellation: &Cancellation::default(),
            task_id: ScanTaskId::new().unwrap(),
            traversal_policy: TraversalPolicy::ProjectDiscovery,
            started: Instant::now(),
        },
        |_| {},
    )
    .unwrap();
    assert!(report.complete);
    assert_eq!(report.entries.len(), 6);
    let opened = backend.0.opened.lock().unwrap();
    assert!(!opened.contains(&target));
    assert!(!opened.contains(&modules));
    assert!(report.entries.iter().any(|e| e.path == modules));
}

#[cfg(target_os = "macos")]
#[test]
fn cache_worker_ceiling_preserves_full_totals_hardlinks_and_policy_restore() {
    for requested in [1, 8, 32] {
        let mut fake = tree();
        for i in 0..16 {
            let child = add_directory(&mut fake, &root(), &format!("child-{i}"), i + 2);
            let mut shared = metadata(100, ResourceKind::File, Some(7));
            shared.link_count = Some(16);
            fake.directories.get_mut(&child).unwrap().items.push(Item {
                name: "shared".into(), metadata: Ok(shared),
            });
            add_file(&mut fake, &child, "own", i + 200, Some(3));
        }
        let backend = FakeBackend(Arc::new(fake));
        let limits = ScanLimits { workers: requested, ..ScanLimits::default() };
        let result = crate::scan::cache::summarize(&backend, &root(),
            metadata(1, ResourceKind::Directory, None).identity, &limits,
            &Cancellation::default(), |_, _, _| {}).unwrap();
        assert!(result.complete);
        assert_eq!(result.entries, 48);
        assert_eq!(result.files, 17);
        assert_eq!(result.logical, Some(55));
        assert_eq!(backend.0.opened.lock().unwrap().len(), 17);
        assert_eq!(backend.0.closed.load(Ordering::Acquire), 17);
        assert_eq!(backend.0.policies_entered.load(Ordering::Acquire), requested.min(8) + 1);
        assert_eq!(backend.0.policies_entered.load(Ordering::Acquire), backend.0.policies_restored.load(Ordering::Acquire));
    }
}

#[cfg(target_os = "macos")]
#[test]
fn cache_lazy_paths_preserve_byte_limits_and_error_paths() {
    use std::os::unix::ffi::OsStringExt;
    for scan_root in [PathBuf::from("/"), root(), PathBuf::from("/scan-fixture/")] {
        // Non-UTF8 names must use native bytes, not a lossy display length.
        let name = OsString::from_vec(vec![b'f', 0xff, b'x']);
        let full = scan_root.join(&name);
        for allowance in [full.as_os_str().len() - 1, full.as_os_str().len()] {
            let mut fake = tree();
            fake.directories.clear();
            let mut dir = directory(1);
            dir.items.push(Item { name: name.clone(), metadata: Ok(metadata(2, ResourceKind::File, Some(7))) });
            fake.directories.insert(scan_root.clone(), dir);
            let backend = FakeBackend(Arc::new(fake));
            let limits = ScanLimits { max_path_bytes: allowance, ..ScanLimits::default() };
            let result = crate::scan::cache::summarize(&backend, &scan_root,
                metadata(1, ResourceKind::Directory, None).identity, &limits,
                &Cancellation::default(), |_, _, _| {}).unwrap();
            if allowance < full.as_os_str().len() {
                assert!(!result.complete);
                assert_eq!(result.files, 0);
                assert!(result.issues.iter().any(|issue| issue.code == ScanCode::PathBytesLimit && issue.path.as_deref() == Some(scan_root.as_path())));
            } else {
                assert!(result.complete);
                assert_eq!(result.logical, Some(7));
                assert_eq!(result.files, 1);
            }
        }
        let mut fake = tree();
        fake.directories.clear();
        let mut dir = directory(1);
        dir.items.push(Item { name: name.clone(), metadata: Err(ScanError::new(ScanCode::Io, "denied")) });
        fake.directories.insert(scan_root.clone(), dir);
        let backend = FakeBackend(Arc::new(fake));
        let result = crate::scan::cache::summarize(&backend, &scan_root,
            metadata(1, ResourceKind::Directory, None).identity, &ScanLimits::default(),
            &Cancellation::default(), |_, _, _| {}).unwrap();
        assert!(!result.complete);
        assert!(result.issues.iter().any(|issue| issue.code == ScanCode::Io && issue.path.as_deref() == Some(full.as_path())));
    }
}

#[cfg(target_os = "macos")]
#[test]
fn cache_lending_preserves_wrapper_totals_and_ancestor_change_checks() {
    for changed in [false, true] {
        let mut fake = tree();
        let version = add_directory(&mut fake, &root(), "version", 2);
        let links = add_directory(&mut fake, &version, "links", 3);
        let files = add_directory(&mut fake, &version, "files", 4);
        add_file(&mut fake, &version, "index", 5, Some(11));
        for (side, parent) in [&links, &files].into_iter().enumerate() {
            for i in 0..16 {
                let child = add_directory(&mut fake, parent, &format!("bucket-{i}"), 100 + side as u64 * 100 + i);
                let mut linked = metadata(10, ResourceKind::File, Some(7));
                linked.link_count = Some(32);
                fake.directories.get_mut(&child).unwrap().items.push(Item { name: "shared".into(), metadata: Ok(linked) });
                add_file(&mut fake, &child, "own", 1000 + side as u64 * 100 + i, Some(3));
            }
        }
        fake.directories.get_mut(&version).unwrap().unchanged = !changed;
        let backend = FakeBackend(Arc::new(fake));
        let result = crate::scan::cache::summarize(&backend, &root(),
            metadata(1, ResourceKind::Directory, None).identity, &ScanLimits::default(),
            &Cancellation::default(), |_, _, _| {}).unwrap();
        assert_eq!(result.complete, !changed);
        assert_eq!(result.entries, 100); // 35 directories, index and 64 bucket entries.
        assert_eq!(result.files, 34); // shared identity once, index and 32 own files.
        assert_eq!(result.logical, Some(114));
        let checks = backend.0.checked.lock().unwrap();
        // Every directory is checked exactly once, including ancestors that
        // may have delegated descendants. Completion ordering is covered by
        // the deterministic scheduler checks in cache::parallel.
        assert_eq!(checks.len(), 36);
        assert_eq!(checks.iter().collect::<HashSet<_>>().len(), 36);
        if changed { assert!(result.issues.iter().any(|i| i.code == ScanCode::ChangedEntry && i.path.as_deref() == Some(version.as_path()))); }
        assert_eq!(backend.0.opened.lock().unwrap().len(), backend.0.closed.load(Ordering::Acquire));
        assert_eq!(backend.0.policies_entered.load(Ordering::Acquire), backend.0.policies_restored.load(Ordering::Acquire));
    }
}

#[cfg(target_os = "macos")]
#[test]
fn cache_lending_keeps_deep_wrappers_complete_and_resource_limited() {
    for max_open_dirs in [8, 32] {
        let mut fake = tree();
        let mut parent = root();
        for i in 0..12 { parent = add_directory(&mut fake, &parent, "wrapper", i + 2); }
        add_file(&mut fake, &parent, "payload", 100, Some(9));
        let backend = FakeBackend(Arc::new(fake));
        let limits = ScanLimits { workers: 2, max_open_dirs, ..ScanLimits::default() };
        let result = crate::scan::cache::summarize(&backend, &root(),
            metadata(1, ResourceKind::Directory, None).identity, &limits,
            &Cancellation::default(), |_, _, _| {}).unwrap();
        if max_open_dirs == 32 {
            assert!(result.complete);
            assert_eq!(result.entries, 13);
            assert_eq!(result.logical, Some(9));
            assert_eq!(backend.0.checked.lock().unwrap().len(), 13);
        } else {
            assert!(!result.complete);
            assert!(result.issues.iter().any(|i| i.code == ScanCode::OpenHandleLimit));
        }
        assert_eq!(backend.0.opened.lock().unwrap().len(), backend.0.closed.load(Ordering::Acquire));
    }
}

#[cfg(target_os = "macos")]
#[test]
fn cache_lending_cancellation_in_wrapper_releases_all_handles() {
    let mut fake = tree();
    let version = add_directory(&mut fake, &root(), "version", 2);
    for i in 0..16 { add_directory(&mut fake, &version, &format!("bucket-{i}"), i + 3); }
    let cancellation = Cancellation::default();
    let token = cancellation.clone();
    fake.hook = Some(Arc::new(move |path, index| {
        if path == version && index == 3 { token.cancel(); }
    }));
    let backend = FakeBackend(Arc::new(fake));
    let result = crate::scan::cache::summarize(&backend, &root(),
        metadata(1, ResourceKind::Directory, None).identity, &ScanLimits::default(),
        &cancellation, |_, _, _| {}).unwrap();
    assert!(result.cancelled && !result.complete);
    assert!(result.issues.iter().any(|i| i.code == ScanCode::Cancelled));
    assert_eq!(backend.0.opened.lock().unwrap().len(), backend.0.closed.load(Ordering::Acquire));
    assert_eq!(backend.0.policies_entered.load(Ordering::Acquire), backend.0.policies_restored.load(Ordering::Acquire));
}
