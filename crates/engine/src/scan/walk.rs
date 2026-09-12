// SPDX-License-Identifier: MPL-2.0

use super::*;
use crate::model::valid_absolute_path;
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::OsString;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::Instant;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Metadata {
    pub identity: FileIdentity,
    pub kind: ResourceKind,
    pub logical_bytes: Option<u64>,
    pub allocated_bytes: Option<u64>,
    pub dataless: bool,
}

pub(super) struct DirItem {
    pub name: OsString,
    pub metadata: Result<Metadata, ScanError>,
}

pub(super) trait Cursor: Send {
    fn metadata(&self) -> Metadata;
    fn next_entry(&mut self) -> Option<Result<DirItem, ScanError>>;
    fn open_child(&self, item: &DirItem) -> Result<Self, ScanError>
    where
        Self: Sized;
    fn unchanged(&self) -> Result<bool, ScanError>;
}

pub(super) trait ThreadPolicy {
    fn restore(self) -> Result<(), ScanError>;
}

pub(super) trait Backend: Sync {
    type Directory: Cursor;
    type Policy: ThreadPolicy;
    fn enter_thread(&self) -> Result<Self::Policy, ScanError>;
    fn open_root(&self, path: &Path) -> Result<Self::Directory, ScanError>;

    fn spawn_worker<'scope, 'env: 'scope, F>(
        &self,
        scope: &'scope std::thread::Scope<'scope, 'env>,
        index: usize,
        action: F,
    ) -> std::io::Result<std::thread::ScopedJoinHandle<'scope, Result<(), ScanError>>>
    where
        F: FnOnce() -> Result<(), ScanError> + Send + 'scope,
    {
        std::thread::Builder::new()
            .name(format!("sayaka-scan-{index}"))
            .spawn_scoped(scope, action)
    }
}

pub(super) fn normalize_roots(
    roots: &[PathBuf],
    limits: &ScanLimits,
) -> Result<Vec<PathBuf>, ScanError> {
    if roots.is_empty() || roots.len() > 64 {
        return Err(ScanError::new(
            ScanCode::InvalidRoot,
            "provide between 1 and 64 explicit directory roots",
        ));
    }
    let mut bytes = 0usize;
    for root in roots {
        if !valid_absolute_path(root) || root.parent().is_none() {
            return Err(ScanError::new(
                ScanCode::InvalidRoot,
                "roots must be non-root absolute paths without parent traversal or NUL",
            ));
        }
        if root.as_os_str().len() > limits.max_path_bytes.min(65_536) {
            return Err(ScanError::new(
                ScanCode::InvalidRoot,
                "root exceeds the per-path byte budget",
            ));
        }
        bytes = bytes
            .checked_add(root.as_os_str().len())
            .ok_or_else(|| ScanError::new(ScanCode::InvalidRoot, "root path size overflow"))?;
    }
    if bytes > limits.max_path_bytes {
        return Err(ScanError::new(
            ScanCode::InvalidRoot,
            "root paths exceed the path-byte budget",
        ));
    }
    // A lexical descendant may be missing, unreadable or a symlink. Retain it
    // for independent admission; traversal deduplication happens by identity.
    let mut normalized = roots.to_vec();
    normalized.sort();
    normalized.dedup();
    if normalized.len() > limits.queue_capacity {
        return Err(ScanError::new(
            ScanCode::InvalidLimits,
            "directory queue must accommodate the explicit roots",
        ));
    }
    Ok(normalized)
}

#[derive(Default)]
struct Counters {
    open: AtomicUsize,
    peak_open: AtomicUsize,
    pending_events: AtomicUsize,
    peak_events: AtomicUsize,
    peak_queued: AtomicUsize,
    peak_workers: AtomicUsize,
}

struct Permit(Arc<Counters>);
impl Drop for Permit {
    fn drop(&mut self) {
        self.0.open.fetch_sub(1, Ordering::AcqRel);
    }
}

fn reserve(counters: &Arc<Counters>, limit: usize) -> Option<Permit> {
    counters
        .open
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            (n < limit).then_some(n + 1)
        })
        .ok()
        .map(|old| {
            counters.peak_open.fetch_max(old + 1, Ordering::AcqRel);
            Permit(Arc::clone(counters))
        })
}

struct Frame<D> {
    directory: D,
    // Drop the directory descriptor before releasing its counted slot.
    _permit: Permit,
    path: PathBuf,
    depth: usize,
}

struct Queue<D> {
    jobs: VecDeque<Frame<D>>,
    active: usize,
    finished: bool,
}

struct Shared<D> {
    queue: Mutex<Queue<D>>,
    changed: Condvar,
    visited: Mutex<HashSet<FileIdentity>>,
    stop: AtomicBool,
    timed_out: AtomicBool,
    counters: Arc<Counters>,
}

impl<D> Shared<D> {
    fn stop(&self) {
        self.stop.store(true, Ordering::Release);
        self.changed.notify_all();
    }

    fn should_stop(&self, cancellation: &Cancellation, started: Instant, limit: Duration) -> bool {
        if cancellation.is_cancelled() {
            self.stop();
        }
        if started.elapsed() >= limit {
            self.timed_out.store(true, Ordering::Release);
            self.stop();
        }
        self.stop.load(Ordering::Acquire)
    }
}

struct Active<'a, D>(&'a Shared<D>);
impl<D> Drop for Active<'_, D> {
    fn drop(&mut self) {
        let mut queue = self.0.queue.lock().expect("scan queue poisoned");
        queue.active -= 1;
        if queue.active == 0 && queue.jobs.is_empty() {
            queue.finished = true;
        }
        self.0.changed.notify_all();
    }
}

struct StopOnDrop<'a, D>(&'a Shared<D>);
impl<D> Drop for StopOnDrop<'_, D> {
    fn drop(&mut self) {
        self.0.stop();
    }
}

enum Event {
    Entry {
        path: PathBuf,
        metadata: Metadata,
        depth: usize,
    },
    Issue {
        path: Option<PathBuf>,
        error: ScanError,
    },
}

fn send<D>(
    sender: &mpsc::SyncSender<Event>,
    mut event: Event,
    shared: &Shared<D>,
    limits: &ScanLimits,
    cancellation: &Cancellation,
    started: Instant,
) -> bool {
    loop {
        if shared.should_stop(cancellation, started, limits.time_budget) {
            return false;
        }
        let slot =
            shared
                .counters
                .pending_events
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                    (n < limits.event_capacity).then_some(n + 1)
                });
        if let Ok(old) = slot {
            shared
                .counters
                .peak_events
                .fetch_max(old + 1, Ordering::AcqRel);
            match sender.try_send(event) {
                Ok(()) => return true,
                Err(mpsc::TrySendError::Full(returned)) => {
                    event = returned;
                }
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    shared
                        .counters
                        .pending_events
                        .fetch_sub(1, Ordering::AcqRel);
                    shared.stop();
                    return false;
                }
            }
            shared
                .counters
                .pending_events
                .fetch_sub(1, Ordering::AcqRel);
        }
        std::thread::park_timeout(Duration::from_millis(1));
    }
}

fn issue_event(path: Option<PathBuf>, code: ScanCode, message: &str) -> Event {
    Event::Issue {
        path,
        error: ScanError::new(code, message),
    }
}

fn next_job<'a, D>(
    shared: &'a Shared<D>,
    cancellation: &Cancellation,
    started: Instant,
    limits: &ScanLimits,
) -> Option<(Frame<D>, Active<'a, D>)> {
    let mut queue = shared.queue.lock().expect("scan queue poisoned");
    loop {
        if shared.should_stop(cancellation, started, limits.time_budget) || queue.finished {
            return None;
        }
        if let Some(job) = queue.jobs.pop_front() {
            queue.active += 1;
            shared
                .counters
                .peak_workers
                .fetch_max(queue.active, Ordering::AcqRel);
            return Some((job, Active(shared)));
        }
        if queue.active == 0 {
            queue.finished = true;
            shared.changed.notify_all();
            return None;
        }
        queue = shared
            .changed
            .wait_timeout(queue, Duration::from_millis(10))
            .expect("scan queue poisoned")
            .0;
    }
}

fn worker<B: Backend>(
    backend: &B,
    shared: &Shared<B::Directory>,
    sender: mpsc::SyncSender<Event>,
    limits: &ScanLimits,
    cancellation: &Cancellation,
    started: Instant,
) -> Result<(), ScanError> {
    let policy = backend.enter_thread()?;
    while let Some((job, _active)) = next_job(shared, cancellation, started, limits) {
        let mut stack = vec![job];
        while !stack.is_empty() && !shared.should_stop(cancellation, started, limits.time_budget) {
            let frame = stack.last_mut().expect("nonempty scan stack");
            let item = match frame.directory.next_entry() {
                Some(Ok(item)) => item,
                Some(Err(error)) => {
                    send(
                        &sender,
                        Event::Issue {
                            path: Some(frame.path.clone()),
                            error,
                        },
                        shared,
                        limits,
                        cancellation,
                        started,
                    );
                    stack.pop();
                    continue;
                }
                None => {
                    let result = frame.directory.unchanged();
                    let path = frame.path.clone();
                    stack.pop();
                    let event = match result {
                        Ok(true) => None,
                        Ok(false) => Some(issue_event(
                            Some(path),
                            ScanCode::ChangedEntry,
                            "directory changed during enumeration",
                        )),
                        Err(error) => Some(Event::Issue {
                            path: Some(path),
                            error,
                        }),
                    };
                    if let Some(event) = event {
                        send(&sender, event, shared, limits, cancellation, started);
                    }
                    continue;
                }
            };
            if Path::new(&item.name).components().count() != 1
                || !matches!(
                    Path::new(&item.name).components().next(),
                    Some(std::path::Component::Normal(_))
                )
            {
                send(
                    &sender,
                    issue_event(
                        Some(frame.path.clone()),
                        ScanCode::Internal,
                        "invalid directory entry name",
                    ),
                    shared,
                    limits,
                    cancellation,
                    started,
                );
                continue;
            }
            let path = frame.path.join(&item.name);
            if path.as_os_str().len() > limits.max_path_bytes.min(65_536) {
                send(
                    &sender,
                    issue_event(
                        Some(frame.path.clone()),
                        ScanCode::PathBytesLimit,
                        "entry path exceeds the per-path budget",
                    ),
                    shared,
                    limits,
                    cancellation,
                    started,
                );
                continue;
            }
            let metadata = match &item.metadata {
                Ok(metadata) => metadata,
                Err(error) => {
                    send(
                        &sender,
                        Event::Issue {
                            path: Some(path),
                            error: error.clone(),
                        },
                        shared,
                        limits,
                        cancellation,
                        started,
                    );
                    continue;
                }
            };
            if device(metadata.identity) != device(frame.directory.metadata().identity) {
                send(
                    &sender,
                    issue_event(
                        Some(path),
                        ScanCode::MountBoundary,
                        "mount boundaries are not traversed",
                    ),
                    shared,
                    limits,
                    cancellation,
                    started,
                );
                continue;
            }
            let depth = frame.depth + 1;
            if !send(
                &sender,
                Event::Entry {
                    path: path.clone(),
                    metadata: metadata.clone(),
                    depth,
                },
                shared,
                limits,
                cancellation,
                started,
            ) {
                break;
            }
            if metadata.kind == ResourceKind::Link {
                send(
                    &sender,
                    issue_event(
                        Some(path),
                        ScanCode::LinkSkipped,
                        "symbolic links are not followed",
                    ),
                    shared,
                    limits,
                    cancellation,
                    started,
                );
                continue;
            }
            if metadata.kind != ResourceKind::Directory {
                continue;
            }
            if metadata.dataless {
                send(
                    &sender,
                    issue_event(
                        Some(path),
                        ScanCode::CloudDirectorySkipped,
                        "dataless directories are not materialized",
                    ),
                    shared,
                    limits,
                    cancellation,
                    started,
                );
                continue;
            }
            if shared
                .visited
                .lock()
                .expect("scan identity set poisoned")
                .contains(&metadata.identity)
            {
                send(
                    &sender,
                    issue_event(
                        Some(path),
                        ScanCode::DuplicateDirectory,
                        "directory identity is already scheduled",
                    ),
                    shared,
                    limits,
                    cancellation,
                    started,
                );
                continue;
            }
            if depth > limits.max_depth {
                send(
                    &sender,
                    issue_event(
                        Some(path),
                        ScanCode::DepthLimit,
                        "directory depth budget reached",
                    ),
                    shared,
                    limits,
                    cancellation,
                    started,
                );
                continue;
            }
            let Some(permit) = reserve(&shared.counters, limits.max_open_dirs) else {
                send(
                    &sender,
                    issue_event(
                        Some(path),
                        ScanCode::OpenHandleLimit,
                        "directory handle budget reached",
                    ),
                    shared,
                    limits,
                    cancellation,
                    started,
                );
                continue;
            };
            if shared.should_stop(cancellation, started, limits.time_budget) {
                break;
            }
            let directory = match frame.directory.open_child(&item) {
                Ok(directory) => directory,
                Err(mut error) => {
                    if error.code == ScanCode::LinkSkipped {
                        error.code = ScanCode::ChangedEntry;
                        error.message =
                            "observed directory became a link or reparse path before opening"
                                .into();
                    }
                    send(
                        &sender,
                        Event::Issue {
                            path: Some(path),
                            error,
                        },
                        shared,
                        limits,
                        cancellation,
                        started,
                    );
                    continue;
                }
            };
            if directory.metadata().identity != metadata.identity {
                send(
                    &sender,
                    issue_event(
                        Some(path),
                        ScanCode::ChangedEntry,
                        "directory was replaced before opening",
                    ),
                    shared,
                    limits,
                    cancellation,
                    started,
                );
                continue;
            }
            let fresh = {
                let mut visited = shared.visited.lock().expect("scan identity set poisoned");
                if visited.len() >= limits.max_entries {
                    None
                } else {
                    Some(visited.insert(metadata.identity))
                }
            };
            match fresh {
                Some(false) => {
                    send(
                        &sender,
                        issue_event(
                            Some(path),
                            ScanCode::DuplicateDirectory,
                            "directory identity was already visited",
                        ),
                        shared,
                        limits,
                        cancellation,
                        started,
                    );
                    continue;
                }
                None => {
                    send(
                        &sender,
                        issue_event(
                            Some(path),
                            ScanCode::EntryLimit,
                            "directory identity budget reached",
                        ),
                        shared,
                        limits,
                        cancellation,
                        started,
                    );
                    continue;
                }
                Some(true) => {}
            }
            let child = Frame {
                directory,
                _permit: permit,
                path,
                depth,
            };
            let local = {
                let mut queue = shared.queue.lock().expect("scan queue poisoned");
                if queue.jobs.len() < limits.queue_capacity {
                    queue.jobs.push_back(child);
                    shared
                        .counters
                        .peak_queued
                        .fetch_max(queue.jobs.len(), Ordering::AcqRel);
                    shared.changed.notify_one();
                    None
                } else {
                    Some(child)
                }
            };
            // Inline depth-first fallback avoids producer deadlock when every
            // worker encounters a full queue. Open handles still have a hard cap.
            if let Some(child) = local {
                stack.push(child);
            }
        }
    }
    policy.restore()
}

fn device(identity: FileIdentity) -> u64 {
    match identity {
        FileIdentity::Unix { device, .. } => device,
        FileIdentity::Windows { volume_serial, .. } => volume_serial,
    }
}

fn milliseconds(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn add_issue(
    report: &mut ScanReport,
    limits: &ScanLimits,
    path: Option<PathBuf>,
    error: ScanError,
) {
    if error.code.is_gap() {
        report.complete = false;
    }
    if report.issues.len() < limits.max_issues {
        report.issues.push(ScanIssue {
            path,
            code: error.code,
            message: error.message,
            os_code: error.os_code,
        });
    } else {
        report.issues_omitted += 1;
    }
}

#[derive(Default)]
struct SeenEntries {
    files: HashMap<FileIdentity, (Option<u64>, Option<u64>)>,
    directories: HashSet<FileIdentity>,
}

fn record_entry(
    report: &mut ScanReport,
    identities: &mut SeenEntries,
    path: PathBuf,
    metadata: Metadata,
    depth: usize,
    limits: &ScanLimits,
) -> Result<bool, ScanError> {
    if metadata.kind == ResourceKind::Directory
        && identities.directories.contains(&metadata.identity)
    {
        return Ok(false);
    }
    if report.entries.len() >= limits.max_entries {
        return Err(ScanError::new(
            ScanCode::EntryLimit,
            "retained entry budget reached",
        ));
    }
    let path_bytes = report
        .metrics
        .retained_path_bytes
        .checked_add(path.as_os_str().len())
        .ok_or_else(|| ScanError::new(ScanCode::PathBytesLimit, "path-byte accounting overflow"))?;
    if path_bytes > limits.max_path_bytes {
        return Err(ScanError::new(
            ScanCode::PathBytesLimit,
            "retained path-byte budget reached",
        ));
    }
    let mut counted = false;
    let mut totals = report.totals.clone();
    match metadata.kind {
        ResourceKind::File => {
            totals.regular_files += 1;
            match identities.files.entry(metadata.identity) {
                std::collections::hash_map::Entry::Occupied(previous) => {
                    totals.duplicate_files += 1;
                    if *previous.get() != (metadata.logical_bytes, metadata.allocated_bytes) {
                        add_issue(
                            report,
                            limits,
                            Some(path.clone()),
                            ScanError::new(
                                ScanCode::ChangedEntry,
                                "hard-linked file metadata changed during traversal",
                            ),
                        );
                    }
                }
                std::collections::hash_map::Entry::Vacant(slot) => {
                    let logical = totals
                        .logical_bytes_known
                        .checked_add(metadata.logical_bytes.unwrap_or(0));
                    let allocated = totals
                        .allocated_bytes_known
                        .checked_add(metadata.allocated_bytes.unwrap_or(0));
                    let (Some(logical), Some(allocated)) = (logical, allocated) else {
                        return Err(ScanError::new(ScanCode::Overflow, "byte subtotal overflow"));
                    };
                    slot.insert((metadata.logical_bytes, metadata.allocated_bytes));
                    totals.unique_files += 1;
                    totals.logical_bytes_known = logical;
                    totals.allocated_bytes_known = allocated;
                    totals.logical_bytes_unknown_files +=
                        u64::from(metadata.logical_bytes.is_none());
                    totals.allocated_bytes_unknown_files +=
                        u64::from(metadata.allocated_bytes.is_none());
                    counted = true;
                }
            }
        }
        ResourceKind::Directory => {
            totals.directories += 1;
            identities.directories.insert(metadata.identity);
        }
        ResourceKind::Link => totals.links += 1,
        ResourceKind::Other => totals.other += 1,
    }
    report.totals = totals;
    report.metrics.retained_path_bytes = path_bytes;
    report.entries.push(ScanEntry {
        id: report.entries.len() as u64 + 1,
        path,
        kind: metadata.kind,
        identity: metadata.identity,
        logical_bytes: metadata.logical_bytes,
        allocated_bytes: metadata.allocated_bytes,
        dataless: metadata.dataless,
        counted,
        depth,
    });
    Ok(true)
}

pub(super) fn run<B: Backend>(
    backend: &B,
    roots: Vec<PathBuf>,
    limits: &ScanLimits,
    cancellation: &Cancellation,
    task_id: ScanTaskId,
    started: Instant,
    mut progress: impl FnMut(&ScanProgress),
) -> Result<ScanReport, ScanError> {
    let counters = Arc::new(Counters::default());
    let mut report = ScanReport {
        task_id,
        roots,
        status: ScanStatus::Complete,
        complete: true,
        entries: Vec::new(),
        issues: Vec::new(),
        issues_omitted: 0,
        totals: ScanTotals::default(),
        metrics: ScanMetrics::default(),
    };
    let shared = Shared {
        queue: Mutex::new(Queue {
            jobs: VecDeque::new(),
            active: 0,
            finished: false,
        }),
        changed: Condvar::new(),
        visited: Mutex::new(HashSet::new()),
        stop: AtomicBool::new(false),
        timed_out: AtomicBool::new(false),
        counters: Arc::clone(&counters),
    };
    let mut identities = SeenEntries::default();
    for path in report.roots.clone() {
        if shared.should_stop(cancellation, started, limits.time_budget) {
            break;
        }
        let Some(permit) = reserve(&counters, limits.max_open_dirs) else {
            add_issue(
                &mut report,
                limits,
                Some(path),
                ScanError::new(
                    ScanCode::OpenHandleLimit,
                    "root directory handle budget reached",
                ),
            );
            continue;
        };
        let directory = match backend.open_root(&path) {
            Ok(directory) => directory,
            Err(error) => {
                // A rejected explicit root is a coverage gap even when the
                // same code denotes an intentional skip inside another root.
                report.complete = false;
                add_issue(&mut report, limits, Some(path), error);
                continue;
            }
        };
        let metadata = directory.metadata();
        if metadata.dataless {
            add_issue(
                &mut report,
                limits,
                Some(path),
                ScanError::new(
                    ScanCode::CloudDirectorySkipped,
                    "dataless roots are not materialized",
                ),
            );
            continue;
        }
        if !shared
            .visited
            .lock()
            .expect("scan identity set poisoned")
            .insert(metadata.identity)
        {
            add_issue(
                &mut report,
                limits,
                Some(path),
                ScanError::new(
                    ScanCode::DuplicateRoot,
                    "root identity was already admitted",
                ),
            );
            continue;
        }
        if let Err(error) = record_entry(
            &mut report,
            &mut identities,
            path.clone(),
            metadata,
            0,
            limits,
        ) {
            add_issue(&mut report, limits, Some(path), error);
            shared.stop();
            break;
        }
        report.metrics.accepted_roots += 1;
        shared
            .queue
            .lock()
            .expect("scan queue poisoned")
            .jobs
            .push_back(Frame {
                directory,
                _permit: permit,
                path,
                depth: 0,
            });
    }
    counters.peak_queued.store(
        shared.queue.lock().expect("scan queue poisoned").jobs.len(),
        Ordering::Release,
    );
    let (sender, receiver) = mpsc::sync_channel(limits.event_capacity);
    let mut emitted = false;
    let mut last_progress_entries = report.entries.len();
    let mut last_progress_at = Instant::now();
    let mut spawn_error = None;
    let should_spawn = !shared
        .queue
        .lock()
        .expect("scan queue poisoned")
        .jobs
        .is_empty()
        && !shared.stop.load(Ordering::Acquire);
    std::thread::scope(|threads| {
        let _stop_on_drop = StopOnDrop(&shared);
        let mut handles = Vec::new();
        for index in 0..if should_spawn { limits.workers } else { 0 } {
            let sender = sender.clone();
            let shared = &shared;
            match backend.spawn_worker(threads, index, move || {
                worker(backend, shared, sender, limits, cancellation, started)
            }) {
                Ok(handle) => handles.push(handle),
                Err(error) => {
                    spawn_error = Some(ScanError {
                        code: ScanCode::WorkerStartFailed,
                        message: format!("could not start scan worker {index}: {error}"),
                        os_code: error.raw_os_error(),
                    });
                    shared.stop();
                    break;
                }
            }
        }
        drop(sender);
        if !report.entries.is_empty() && spawn_error.is_none() {
            progress(&progress_state(&report, started));
            emitted = true;
        }
        loop {
            shared.should_stop(cancellation, started, limits.time_budget);
            match receiver.recv_timeout(Duration::from_millis(10)) {
                Ok(event) => {
                    counters.pending_events.fetch_sub(1, Ordering::AcqRel);
                    match event {
                        Event::Entry {
                            path,
                            metadata,
                            depth,
                        } => {
                            if !shared.stop.load(Ordering::Acquire) {
                                match record_entry(
                                    &mut report,
                                    &mut identities,
                                    path,
                                    metadata,
                                    depth,
                                    limits,
                                ) {
                                    Err(error) => {
                                        add_issue(&mut report, limits, None, error);
                                        shared.stop();
                                    }
                                    Ok(true) if report.metrics.first_result_ms.is_none() => {
                                        report.metrics.first_result_ms =
                                            Some(milliseconds(started.elapsed()));
                                    }
                                    Ok(_) => {}
                                }
                            }
                        }
                        Event::Issue { path, error } => add_issue(&mut report, limits, path, error),
                    }
                    if spawn_error.is_none()
                        && (!emitted
                            || report.entries.len().saturating_sub(last_progress_entries)
                                >= limits.progress_every
                            || last_progress_at.elapsed() >= Duration::from_millis(100))
                    {
                        progress(&progress_state(&report, started));
                        emitted = true;
                        last_progress_entries = report.entries.len();
                        last_progress_at = Instant::now();
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        for handle in handles {
            match handle.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => add_issue(&mut report, limits, None, error),
                Err(_) => add_issue(
                    &mut report,
                    limits,
                    None,
                    ScanError::new(ScanCode::WorkerPanic, "scan worker panicked"),
                ),
            }
        }
    });
    // No queued handles may survive the returned result.
    shared
        .queue
        .lock()
        .expect("scan queue poisoned")
        .jobs
        .clear();
    if let Some(mut error) = spawn_error {
        for issue in report
            .issues
            .iter()
            .filter(|issue| matches!(issue.code, ScanCode::PolicyFailure | ScanCode::WorkerPanic))
        {
            error
                .message
                .push_str(&format!("; {}: {}", issue.code.as_str(), issue.message));
        }
        debug_assert_eq!(counters.open.load(Ordering::Acquire), 0);
        return Err(error);
    }
    if cancellation.is_cancelled() {
        add_issue(
            &mut report,
            limits,
            None,
            ScanError::new(
                ScanCode::Cancelled,
                "scan cancelled; no further work scheduled",
            ),
        );
        report.status = ScanStatus::Cancelled;
    } else if shared.timed_out.load(Ordering::Acquire) {
        add_issue(
            &mut report,
            limits,
            None,
            ScanError::new(
                ScanCode::DurationLimit,
                "scan traversal time budget reached",
            ),
        );
        report.status = ScanStatus::Partial;
    } else if report.metrics.accepted_roots == 0 {
        report.complete = false;
        report.status = ScanStatus::Failed;
    } else if !report.complete {
        report.status = ScanStatus::Partial;
    }
    report.entries.sort_by(|a, b| a.path.cmp(&b.path));
    report.metrics.elapsed_ms = milliseconds(started.elapsed());
    if report.complete && report.metrics.first_result_ms.is_none() {
        report.metrics.first_result_ms = Some(report.metrics.elapsed_ms);
    }
    report.metrics.peak_workers = counters.peak_workers.load(Ordering::Acquire);
    report.metrics.peak_queued_dirs = counters.peak_queued.load(Ordering::Acquire);
    report.metrics.peak_open_dirs = counters.peak_open.load(Ordering::Acquire);
    report.metrics.peak_pending_events = counters.peak_events.load(Ordering::Acquire);
    debug_assert_eq!(counters.open.load(Ordering::Acquire), 0);
    Ok(report)
}

fn progress_state(report: &ScanReport, started: Instant) -> ScanProgress {
    ScanProgress {
        task_id: report.task_id,
        entries: report.entries.len(),
        unique_files: report.totals.unique_files,
        logical_bytes_known: report.totals.logical_bytes_known,
        issues: report.issues.len() + report.issues_omitted,
        elapsed_ms: milliseconds(started.elapsed()),
    }
}

#[cfg(test)]
mod tests;
