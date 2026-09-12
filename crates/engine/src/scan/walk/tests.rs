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
        identity: FileIdentity::Unix { device: 1, inode },
        kind,
        logical_bytes: bytes,
        allocated_bytes: bytes,
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
        limits,
        &Cancellation::default(),
        ScanTaskId::new().unwrap(),
        Instant::now(),
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
        &ScanLimits::default(),
        &Cancellation::default(),
        ScanTaskId::new().unwrap(),
        Instant::now(),
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
        &ScanLimits::default(),
        &Cancellation::default(),
        ScanTaskId::new().unwrap(),
        Instant::now(),
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
        &ScanLimits::default(),
        &cancel,
        ScanTaskId::new().unwrap(),
        Instant::now(),
        |_| {},
    )
    .unwrap();
    assert_eq!(report.status, ScanStatus::Cancelled);
    assert!(backend.0.opened.lock().unwrap().is_empty());
    let report = run(
        &backend,
        vec![root()],
        &ScanLimits {
            time_budget: Duration::from_secs(1),
            ..ScanLimits::default()
        },
        &Cancellation::default(),
        ScanTaskId::new().unwrap(),
        Instant::now() - Duration::from_secs(2),
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
        &ScanLimits::default(),
        &cancel,
        ScanTaskId::new().unwrap(),
        Instant::now(),
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
        &ScanLimits::default(),
        &Cancellation::default(),
        ScanTaskId::new().unwrap(),
        Instant::now(),
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
            &ScanLimits::default(),
            &Cancellation::default(),
            ScanTaskId::new().unwrap(),
            Instant::now(),
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
