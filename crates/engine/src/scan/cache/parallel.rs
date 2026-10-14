// SPDX-License-Identifier: MPL-2.0

//! Parallelize independent children of a cache root; each worker keeps a
//! streaming DFS, lending subtrees to idle peers with bounded retained ancestors.
//! All lending ancestors stay open until every worker finishes, so change checks
//! cover their descendants. No per-file records are queued.
// Workers must never acquire stderr: a CLI caller can hold it while joining.
// At most one summary and one resource record per worker, emitted by the caller.
#[cfg(debug_assertions)]
#[derive(Default)]
struct ThreadRecords(Mutex<Vec<String>>);
#[cfg(debug_assertions)]
impl Drop for ThreadRecords {
    fn drop(&mut self) {
        use std::io::Write;
        let records = self.0.get_mut().unwrap_or_else(|e| e.into_inner());
        for record in records {
            let _ = writeln!(std::io::stderr().lock(), "[SayakaSizing] {record}");
        }
    }
}

// Per-thread intervals distinguish CPU work from off-CPU time without adding a
// resource syscall to every directory/file operation. Off-CPU includes queue,
// scheduling and I/O waits; it is deliberately not labelled disk time.
#[cfg(all(debug_assertions, target_os = "macos"))]
struct ThreadTiming<'a> {
    root: &'a Path,
    role: &'static str,
    index: usize,
    started: Instant,
    cpu: Option<u64>,
    records: &'a ThreadRecords,
}
#[cfg(all(debug_assertions, target_os = "macos"))]
impl<'a> ThreadTiming<'a> {
    fn new(root: &'a Path, role: &'static str, index: usize, records: &'a ThreadRecords) -> Self {
        Self { root, role, index, records, started: Instant::now(),
            cpu: sayaka_platform_macos::process_resources::thread_cpu_ns().ok() }
    }
}
#[cfg(all(debug_assertions, target_os = "macos"))]
impl Drop for ThreadTiming<'_> {
    fn drop(&mut self) {
        let cpu = sayaka_platform_macos::process_resources::thread_cpu_ns().ok()
            .zip(self.cpu).and_then(|(end, start)| end.checked_sub(start));
        let wall = self.started.elapsed().as_nanos();
        let record = match cpu {
            Some(cpu) => format!(
                "event=thread_resources path={:?} role={} index={} wall_us={} cpu_us={} off_cpu_us={} cpu_unit=us",
                self.root, self.role, self.index, wall / 1000, cpu / 1000, wall.saturating_sub(u128::from(cpu)) / 1000),
            None => format!(
                "event=thread_resources path={:?} role={} index={} wall_us={} cpu_status=unavailable",
                self.root, self.role, self.index, wall / 1000),
        };
        lock(&self.records.0).push(record);
    }
}


use super::*;
use crate::scan::walk::{Backend, Cursor, ThreadPolicy};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Instant;

fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    value.lock().unwrap_or_else(|error| error.into_inner())
}

#[derive(Default)]
struct Resources {
    open: usize,
    paths: usize,
    peak_open: usize,
}
struct Permit {
    resources: Arc<Mutex<Resources>>,
    bytes: usize,
}
impl Drop for Permit {
    fn drop(&mut self) {
        let mut resources = lock(&self.resources);
        resources.open -= 1;
        resources.paths -= self.bytes;
    }
}
struct Frame<D> {
    directory: D,
    // Release the descriptor before its counted permit.
    _permit: Permit,
    path: PathBuf,
    depth: usize,
    deferred_check: bool,
}
// A lending ancestor must outlive all dispatched descendants even if a
// cursor panics or accounting returns early through `?`.
struct WalkStack<'a, 'b, D> {
    shared: &'a Shared<'b, D>,
    frames: Vec<Frame<D>>,
}
impl<D> std::ops::Deref for WalkStack<'_, '_, D> {
    type Target = Vec<Frame<D>>;
    fn deref(&self) -> &Self::Target { &self.frames }
}
impl<D> std::ops::DerefMut for WalkStack<'_, '_, D> {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.frames }
}
impl<D> Drop for WalkStack<'_, '_, D> {
    fn drop(&mut self) {
        if self.frames.iter().any(|frame| frame.deferred_check) {
            let mut retained = lock(&self.shared.deferred);
            for frame in self.frames.drain(..) {
                if frame.deferred_check { retained.push(frame); }
            }
        }
    }
}
struct Queue<D> {
    jobs: VecDeque<Frame<D>>,
    producer_done: bool,
    active: usize,
    waiting: usize,
    deferred_slots: usize,
}
type Sizes = (Option<u64>, Option<u64>, Option<u64>);
struct Shared<'a, D> {
    #[cfg(debug_assertions)]
    thread_records: ThreadRecords,
    root: &'a Path,
    expected: FileIdentity,
    limits: &'a ScanLimits,
    cancellation: &'a Cancellation,
    started: Instant,
    project_budget: Option<&'a ProjectSizeBudget>,
    stopped: AtomicBool,
    queue: Mutex<Queue<D>>,
    wake: Condvar,
    resources: Arc<Mutex<Resources>>,
    directories: Mutex<HashSet<FileIdentity>>,
    linked_files: Mutex<HashMap<FileIdentity, Sizes>>,
    deferred: Mutex<Vec<Frame<D>>>,
    totals: Mutex<Summary>,
}
impl<D> Shared<'_, D> {
    fn issue(&self, path: &Path, error: ScanError) {
        lock(&self.totals).issue(path, error, self.limits);
    }
    fn stop(&self) {
        // Serialize with a waiter's condition check to avoid a lost wakeup.
        let _queue = lock(&self.queue);
        self.stopped.store(true, Ordering::Release);
        self.wake.notify_all();
    }
    fn interrupted(&self) -> bool {
        if self.stopped.load(Ordering::Acquire) {
            return true;
        }
        let cancelled = self.cancellation.is_cancelled();
        if cancelled
            || self.started.elapsed() >= self.limits.time_budget
            || self
                .project_budget
                .is_some_and(|b| Instant::now() >= b.deadline)
        {
            let _queue = lock(&self.queue);
            if !self.stopped.swap(true, Ordering::AcqRel) {
                let mut totals = lock(&self.totals);
                totals.cancelled = cancelled;
                totals.issue(
                    self.root,
                    ScanError::new(
                        if cancelled {
                            ScanCode::Cancelled
                        } else {
                            ScanCode::DurationLimit
                        },
                        if cancelled {
                            "cache scan cancelled"
                        } else {
                            "cache scan time budget reached"
                        },
                    ),
                    self.limits,
                );
            }
            self.wake.notify_all();
            return true;
        }
        false
    }
    fn reserve(&self, path: &Path) -> Result<Permit, ScanError> {
        let bytes = path.as_os_str().len();
        let mut resources = lock(&self.resources);
        if resources.open >= self.limits.max_open_dirs {
            return Err(ScanError::new(
                ScanCode::OpenHandleLimit,
                "cache open-directory budget reached",
            ));
        }
        if resources.paths.saturating_add(bytes) > self.limits.max_path_bytes {
            return Err(ScanError::new(
                ScanCode::PathBytesLimit,
                "cache retained-path budget reached",
            ));
        }
        resources.open += 1;
        resources.peak_open = resources.peak_open.max(resources.open);
        resources.paths += bytes;
        Ok(Permit {
            resources: Arc::clone(&self.resources),
            bytes,
        })
    }
    fn flush(&self, local: &mut Summary) -> Result<(), ScanError> {
        let mut totals = lock(&self.totals);
        totals.entries = totals
            .entries
            .checked_add(local.entries)
            .ok_or_else(overflow)?;
        totals.files = totals.files.checked_add(local.files).ok_or_else(overflow)?;
        totals.links = totals.links.checked_add(local.links).ok_or_else(overflow)?;
        totals.logical = sum(totals.logical, local.logical)?;
        totals.allocated = sum(totals.allocated, local.allocated)?;
        totals.private = totals.private.and_then(|a| local.private.and_then(|b| a.checked_add(b)));
        *local = empty_totals();
        Ok(())
    }
    fn report(&self, progress: &mut impl FnMut(usize, u64, u64)) {
        let snapshot = {
            let totals = lock(&self.totals);
            (totals.entries, totals.files, totals.logical.unwrap_or(0))
        };
        progress(snapshot.0, snapshot.1, snapshot.2);
    }
    fn submit(&self, frame: Frame<D>, progress: &mut impl FnMut(usize, u64, u64)) {
        let ceiling = if self.project_budget.is_some() { 4 } else { 8 };
        let capacity = self.limits.queue_capacity.min(self.limits.workers.min(ceiling));
        let mut queue = lock(&self.queue);
        while queue.jobs.len() >= capacity && !self.stopped.load(Ordering::Acquire) {
            queue = self
                .wake
                .wait_timeout(queue, Duration::from_millis(50))
                .unwrap_or_else(|error| error.into_inner())
                .0;
            drop(queue);
            self.report(progress);
            self.interrupted();
            queue = lock(&self.queue);
        }
        if !self.stopped.load(Ordering::Acquire) {
            queue.jobs.push_back(frame);
            self.wake.notify_all();
        }
    }
    fn lend(&self, child: Frame<D>, ancestors: &mut [Frame<D>]) -> Option<Frame<D>> {
        // Never wait while owning worker work: a full queue simply keeps DFS
        // local. Projects retain their separately budgeted outer scheduler.
        if self.project_budget.is_some() { return Some(child); }
        let mut queue = lock(&self.queue);
        let needed = ancestors.iter().filter(|f| !f.deferred_check).count();
        // At most one eighth of the existing descriptor budget, capped at
        // two ancestors per default worker. No extra resource allowance.
        if queue.waiting == 0 || queue.jobs.len() >= self.limits.queue_capacity.min(self.limits.workers.min(8))
            || queue.deferred_slots + needed > self.limits.max_open_dirs.saturating_div(8).min(16) || self.stopped.load(Ordering::Acquire) {
            return Some(child);
        }
        queue.deferred_slots += needed;
        for frame in ancestors { frame.deferred_check = true; }
        queue.jobs.push_back(child);
        self.wake.notify_all();
        None
    }
    fn job_finished(&self) {
        let mut queue = lock(&self.queue);
        queue.active -= 1;
        self.wake.notify_all();
    }
    fn take(&self) -> Option<Frame<D>> {
        let mut queue = lock(&self.queue);
        loop {
            if self.stopped.load(Ordering::Acquire) {
                return None;
            }
            if let Some(frame) = queue.jobs.pop_front() {
                queue.active += 1;
                self.wake.notify_all();
                return Some(frame);
            }
            if queue.producer_done && queue.active == 0 {
                return None;
            }
            queue.waiting += 1;
            queue = self
                .wake
                .wait(queue)
                .unwrap_or_else(|error| error.into_inner());
            queue.waiting -= 1;
        }
    }
}
// A failed worker or unwinding producer must wake every queue waiter before
// scoped threads are joined. Otherwise a panic can strand the whole preview.
struct StopOnFailure<'a, 'b, D> {
    shared: &'a Shared<'b, D>,
    success: bool,
}
impl<D> Drop for StopOnFailure<'_, '_, D> {
    fn drop(&mut self) {
        if !self.success {
            self.shared.stop();
        }
    }
}

// Wake the coordinator after policy restoration, including during unwinding.
// Joining still owns worker completion; this only avoids a polling tail.
struct WorkerFinished(std::sync::mpsc::Sender<()>);
impl Drop for WorkerFinished {
    fn drop(&mut self) {
        let _ = self.0.send(());
    }
}

pub(in crate::scan) fn summarize<B: Backend>(
    backend: &B,
    root: &Path,
    expected: FileIdentity,
    limits: &ScanLimits,
    cancellation: &Cancellation,
    progress: impl FnMut(usize, u64, u64),
) -> Result<Summary, ScanError> {
    summarize_with_project_budget(
        backend,
        root,
        expected,
        limits,
        None,
        cancellation,
        progress,
    )
}

pub(in crate::scan) fn summarize_with_project_budget<B: Backend>(
    backend: &B,
    root: &Path,
    expected: FileIdentity,
    limits: &ScanLimits,
    project_budget: Option<&ProjectSizeBudget>,
    cancellation: &Cancellation,
    mut progress: impl FnMut(usize, u64, u64),
) -> Result<Summary, ScanError> {
    limits.validate()?;
    let policy = backend.enter_thread()?;
    let result = (|| {
        let shared = Shared {
            #[cfg(debug_assertions)]
            thread_records: ThreadRecords::default(),
            root,
            expected,
            limits,
            cancellation,
            started: Instant::now(),
            project_budget,
            stopped: AtomicBool::new(false),
            queue: Mutex::new(Queue {
                jobs: VecDeque::new(),
                producer_done: false,
                active: 0,
                waiting: 0,
                deferred_slots: 0,
            }),
            wake: Condvar::new(),
            resources: Arc::new(Mutex::new(Resources::default())),
            directories: Mutex::new(HashSet::from([expected])),
            linked_files: Mutex::new(HashMap::new()),
            deferred: Mutex::new(Vec::new()),
            totals: Mutex::new(empty_totals()),
        };
        let permit = shared.reserve(root)?;
        let directory = backend.open_root(root)?;
        let metadata = directory.metadata();
        if metadata.identity != expected
            || metadata.kind != ResourceKind::Directory
            || metadata.dataless
        {
            return Err(ScanError::new(
                ScanCode::ChangedEntry,
                "cache root changed or is dataless",
            ));
        }
        if project_budget.is_some()
            && (crate::project_git::is_metadata_path(root) || directory.bare_repository()?)
        {
            let mut totals = empty_totals();
            totals.complete = false;
            totals.vcs_metadata = 1;
            return Ok(totals);
        }
        let frame = Frame {
            directory,
            _permit: permit,
            path: root.to_owned(),
            depth: 1,
            deferred_check: false,
        };
        if project_budget.is_some() && limits.workers == 1 {
            // With no spare project slot, retain the single streaming DFS.
            #[cfg(all(debug_assertions, target_os = "macos"))]
            let _resources = ThreadTiming::new(root, "single", 0, &shared.thread_records);
            walk(&shared, frame, false, &mut progress)?;
        } else {
            std::thread::scope(|scope| -> Result<(), ScanError> {
                let mut producer_guard = StopOnFailure {
                    shared: &shared,
                    success: false,
                };
                let mut workers = Vec::new();
                let mut failure = None;
                let (finished, completions) = std::sync::mpsc::channel();
                // A project producer already owns one global sizing slot;
                // remaining slots are lent by the outer artifact scheduler.
                let worker_count = if project_budget.is_some() {
                    limits.workers.saturating_sub(1)
                } else {
                    limits.workers.min(8)
                };
                for index in 0..worker_count {
                    let shared = &shared;
                    let finished = finished.clone();
                    match backend.spawn_worker(scope, index, move || {
                        let _finished = WorkerFinished(finished);
                        let mut guard = StopOnFailure {
                            shared,
                            success: false,
                        };
                        let policy = backend.enter_thread()?;
                        #[cfg(all(debug_assertions, target_os = "macos"))]
                        let _resources = ThreadTiming::new(shared.root, "worker", index, &shared.thread_records);
                        let result = (|| {
                            #[cfg(debug_assertions)]
                            let (mut jobs, mut active_us, mut slowest_us, mut slowest_path) = (0usize, 0u128, 0u128, PathBuf::new());
                            while let Some(frame) = shared.take() {
                                #[cfg(debug_assertions)]
                                let (job_started, job_path) = (Instant::now(), frame.path.clone());
                                walk(shared, frame, false, &mut |_, _, _| {})?;
                                shared.job_finished();
                                #[cfg(debug_assertions)]
                                {
                                    jobs += 1;
                                    let elapsed = job_started.elapsed().as_micros();
                                    active_us += elapsed;
                                    if elapsed > slowest_us { slowest_us = elapsed; slowest_path = job_path; }
                                }
                            }
                            #[cfg(debug_assertions)]
                            if jobs != 0 {
                                lock(&shared.thread_records.0).push(format!("event=worker path={:?} index={index} jobs={jobs} active_us={active_us} slowest_job_us={slowest_us} slowest_path={slowest_path:?}", shared.root));
                            }
                            Ok(())
                        })();
                        let restored = policy.restore();
                        let result = restored.and(result);
                        guard.success = result.is_ok();
                        result
                    }) {
                        Ok(worker) => workers.push(worker),
                        Err(error) => {
                            failure = Some(ScanError::new(
                                ScanCode::WorkerStartFailed,
                                error.to_string(),
                            ));
                            shared.stop();
                            break;
                        }
                    }
                }
                let retained_root = if failure.is_none() {
                    #[cfg(all(debug_assertions, target_os = "macos"))]
                    let _resources = ThreadTiming::new(root, "producer", 0, &shared.thread_records);
                    match walk(&shared, frame, true, &mut progress) {
                        Ok(root) => root,
                        Err(error) => {
                            failure = Some(error);
                            shared.stop();
                            None
                        }
                    }
                } else {
                    None
                };
                {
                    let mut queue = lock(&shared.queue);
                    queue.producer_done = true;
                    shared.wake.notify_all();
                }
                drop(finished);
                for _ in 0..workers.len() {
                    loop {
                        shared.interrupted();
                        shared.report(&mut progress);
                        match completions.recv_timeout(Duration::from_millis(50)) {
                            Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                        }
                    }
                }
                for worker in workers {
                    let result = worker.join().unwrap_or_else(|_| {
                        Err(ScanError::new(
                            ScanCode::WorkerPanic,
                            "cache worker panicked",
                        ))
                    });
                    if let Err(error) = result {
                        failure.get_or_insert(error);
                    }
                }
                // All dynamically lent descendants are finished before any
                // lending ancestor's final check or descriptor release.
                for frame in lock(&shared.deferred).drain(..) {
                    check_unchanged(&shared, &frame);
                }
                if let Some(frame) = retained_root {
                    check_unchanged(&shared, &frame);
                }
                producer_guard.success = true;
                failure.map_or(Ok(()), Err)
            })?;
        }
        shared.interrupted();
        shared.report(&mut progress);
        #[cfg(debug_assertions)]
        {
            let totals = lock(&shared.totals);
            eprintln!("[SayakaSizing] event=summary path={root:?} wall_us={} entries={} files={} links={} directory_identities={} peak_open={} workers_limit={} deferred_ancestors={} complete={} cancelled={} issues={}",
                shared.started.elapsed().as_micros(), totals.entries, totals.files, totals.links,
                lock(&shared.directories).len(), lock(&shared.resources).peak_open, limits.workers, lock(&shared.queue).deferred_slots,
                totals.complete, totals.cancelled, totals.issues.len() + totals.omitted);
        }
        Ok(shared
            .totals
            .into_inner()
            .unwrap_or_else(|error| error.into_inner()))
    })();
    policy.restore().and(result)
}

fn check_unchanged<D: Cursor>(shared: &Shared<'_, D>, frame: &Frame<D>) {
    match frame.directory.unchanged() {
        Ok(true) => {}
        Ok(false) => shared.issue(
            &frame.path,
            ScanError::new(
                ScanCode::ChangedEntry,
                "directory changed during cache scan",
            ),
        ),
        Err(error) => shared.issue(&frame.path, error),
    }
}

fn walk<D: Cursor>(
    shared: &Shared<'_, D>,
    frame: Frame<D>,
    producer: bool,
    progress: &mut impl FnMut(usize, u64, u64),
) -> Result<Option<Frame<D>>, ScanError> {
    let mut stack = WalkStack { shared, frames: vec![frame] };
    let mut local = empty_totals();
    while !stack.is_empty() && !shared.interrupted() {
        let frame = stack.last_mut().expect("nonempty stack");
        let item = match frame.directory.next_entry() {
            None => {
                if producer {
                    shared.flush(&mut local)?;
                    return Ok(stack.pop());
                }
                finish_frame(shared, stack.pop().expect("finished frame"));
                continue;
            }
            Some(Err(error)) => {
                shared.issue(&frame.path, error);
                let frame = stack.pop().expect("failed frame");
                if frame.deferred_check { lock(&shared.deferred).push(frame); }
                continue;
            }
            Some(Ok(item)) => item,
        };
        if Path::new(&item.name).components().count() != 1
            || !matches!(
                Path::new(&item.name).components().next(),
                Some(std::path::Component::Normal(_))
            )
        {
            shared.issue(
                &frame.path,
                ScanError::new(ScanCode::Internal, "invalid cache entry name"),
            );
            continue;
        }
        // Ordinary file accounting needs a full path only on failure. Check
        // the identical joined byte length before allocating that path.
        let joined_bytes = frame.path.as_os_str().len()
            .saturating_add(usize::from(!frame.path.as_os_str().as_encoded_bytes().ends_with(b"/")))
            .saturating_add(item.name.len());
        if joined_bytes > shared.limits.max_path_bytes.min(65_536) {
            shared.issue(
                &frame.path,
                ScanError::new(ScanCode::PathBytesLimit, "cache path budget reached"),
            );
            continue;
        }
        let cached_path = std::cell::OnceCell::new();
        let path = || cached_path.get_or_init(|| frame.path.join(&item.name));
        if shared.project_budget.is_some_and(|budget| !budget.admit()) {
            shared.issue(
                path(),
                ScanError::new(
                    ScanCode::EntryLimit,
                    "shared project sizing entry budget reached",
                ),
            );
            shared.stop();
            break;
        }
        if shared.project_budget.is_some() && crate::project_git::is_metadata_path(path()) {
            let mut totals = lock(&shared.totals);
            totals.vcs_metadata += 1;
            totals.complete = false;
            continue;
        }
        local.entries = local.entries.checked_add(1).ok_or_else(overflow)?;
        if local.entries >= shared.limits.progress_every {
            shared.flush(&mut local)?;
            if producer || shared.project_budget.is_some() {
                shared.report(progress);
            }
        }
        let metadata = match &item.metadata {
            Ok(metadata) => metadata,
            Err(error) => {
                shared.issue(path(), error.clone());
                continue;
            }
        };
        if device(metadata.identity) != device(shared.expected) {
            shared.issue(
                path(),
                ScanError::new(
                    ScanCode::MountBoundary,
                    "cache mount boundary not traversed",
                ),
            );
            continue;
        }
        if metadata.dataless {
            shared.issue(
                path(),
                ScanError::new(
                    ScanCode::CloudDirectorySkipped,
                    "dataless cache contents not materialized",
                ),
            );
            continue;
        }
        match metadata.kind {
            ResourceKind::Link => local.links = local.links.checked_add(1).ok_or_else(overflow)?,
            ResourceKind::File => {
                let sizes = (metadata.logical_bytes, metadata.allocated_bytes, metadata.private_bytes);
                if metadata.link_count != Some(1) {
                    let mut files = lock(&shared.linked_files);
                    if let Some(previous) = files.get(&metadata.identity) {
                        if previous != &sizes {
                            shared.issue(
                                path(),
                                ScanError::new(
                                    ScanCode::ChangedEntry,
                                    "hard-linked cache file changed",
                                ),
                            );
                        }
                        continue;
                    }
                    if files.len() >= shared.limits.max_entries {
                        shared.issue(
                            path(),
                            ScanError::new(
                                ScanCode::EntryLimit,
                                "cache hard-link identity budget reached",
                            ),
                        );
                        shared.stop();
                        break;
                    }
                    files.insert(metadata.identity, sizes);
                }
                local.files = local.files.checked_add(1).ok_or_else(overflow)?;
                local.logical = sum(local.logical, sizes.0)?;
                local.allocated = sum(local.allocated, sizes.1)?;
                local.private = local.private.and_then(|a| sizes.2.and_then(|b| a.checked_add(b)));
            }
            ResourceKind::Directory => {
                {
                    let mut directories = lock(&shared.directories);
                    if directories.contains(&metadata.identity) {
                        shared.issue(
                            path(),
                            ScanError::new(
                                ScanCode::ChangedEntry,
                                "duplicate cache directory identity",
                            ),
                        );
                        continue;
                    }
                    if directories.len() >= shared.limits.max_entries {
                        shared.issue(
                            path(),
                            ScanError::new(
                                ScanCode::EntryLimit,
                                "cache directory identity budget reached",
                            ),
                        );
                        shared.stop();
                        break;
                    }
                    directories.insert(metadata.identity);
                }
                if frame.depth >= shared.limits.max_depth {
                    shared.issue(
                        path(),
                        ScanError::new(ScanCode::DepthLimit, "cache depth budget reached"),
                    );
                    continue;
                }
                let permit = match shared.reserve(path()) {
                    Ok(permit) => permit,
                    Err(error) => {
                        shared.issue(path(), error);
                        continue;
                    }
                };
                let directory = match frame.directory.open_child(&item) {
                    Ok(directory) => directory,
                    Err(mut error) => {
                        if error.code == ScanCode::LinkSkipped {
                            error.code = ScanCode::ChangedEntry;
                        }
                        shared.issue(path(), error);
                        continue;
                    }
                };
                let opened = directory.metadata();
                if opened.identity != metadata.identity
                    || opened.kind != ResourceKind::Directory
                    || opened.dataless
                {
                    shared.issue(
                        path(),
                        ScanError::new(
                            ScanCode::ChangedEntry,
                            "cache directory replaced before opening",
                        ),
                    );
                    continue;
                }
                if shared.project_budget.is_some() {
                    match directory.bare_repository() {
                        Ok(true) => {
                            let mut totals = lock(&shared.totals);
                            totals.vcs_metadata += 1;
                            totals.complete = false;
                            continue;
                        }
                        Ok(false) => {}
                        Err(error) => {
                            shared.issue(path(), error);
                            continue;
                        }
                    }
                }
                // Directory admission above already constructed this path;
                // transfer it to the child without a second allocation.
                let child_path = cached_path.into_inner().expect("admitted directory path");
                let child = Frame {
                    directory,
                    _permit: permit,
                    path: child_path,
                    depth: frame.depth + 1,
                    deferred_check: false,
                };
                if producer {
                    shared.flush(&mut local)?;
                    shared.submit(child, progress);
                } else if let Some(child) = shared.lend(child, &mut stack) {
                    stack.push(child);
                }
            }
            _ => shared.issue(
                path(),
                ScanError::new(ScanCode::Io, "unsupported cache entry kind"),
            ),
        }
    }
    // The guard also retains lending ancestors on cancellation, fatal
    // accounting errors and unwinding, not just on the normal EOF path.
    drop(stack);
    shared.flush(&mut local)?;
    Ok(None)
}
fn finish_frame<D: Cursor>(shared: &Shared<'_, D>, frame: Frame<D>) {
    if frame.deferred_check { lock(&shared.deferred).push(frame); }
    else { check_unchanged(shared, &frame); }
}
fn empty_totals() -> Summary {
    Summary {
        complete: true,
        private: Some(0),
        logical: Some(0),
        allocated: Some(0),
        ..Default::default()
    }
}
fn overflow() -> ScanError {
    ScanError::new(ScanCode::Overflow, "cache total overflow")
}
fn sum(left: Option<u64>, right: Option<u64>) -> Result<Option<u64>, ScanError> {
    match (left, right) {
        (Some(a), Some(b)) => a.checked_add(b).map(Some).ok_or_else(overflow),
        _ => Ok(None),
    }
}
fn device(identity: FileIdentity) -> u64 {
    match identity {
        FileIdentity::Unix { device, .. } => device,
        FileIdentity::Windows { volume_serial, .. } => volume_serial,
    }
}

#[cfg(test)]
mod scheduling_tests {
    use super::*;

    fn shared<'a, D>(limits: &'a ScanLimits, cancellation: &'a Cancellation) -> Shared<'a, D> {
        Shared {
            #[cfg(debug_assertions)]
            thread_records: ThreadRecords::default(),
            root: Path::new("/cache"), expected: FileIdentity::Unix { device: 1, inode: 1 },
            limits, cancellation, started: Instant::now(), project_budget: None,
            stopped: AtomicBool::new(false),
            queue: Mutex::new(Queue { jobs: VecDeque::new(), producer_done: true, active: 1, waiting: 0, deferred_slots: 0 }),
            wake: Condvar::new(), resources: Arc::new(Mutex::new(Resources::default())),
            directories: Mutex::new(HashSet::new()), linked_files: Mutex::new(HashMap::new()),
            deferred: Mutex::new(Vec::new()), totals: Mutex::new(empty_totals()),
        }
    }
    fn frame(shared: &Shared<'_, ()>, name: &str) -> Frame<()> {
        let path = shared.root.join(name);
        Frame { directory: (), _permit: shared.reserve(&path).unwrap(), path, depth: 1, deferred_check: false }
    }

    #[test]
    fn lending_requires_idle_capacity_and_reserves_every_ancestor_once() {
        let limits = ScanLimits::default();
        let cancellation = Cancellation::default();
        let shared = shared(&limits, &cancellation);
        let mut ancestors = vec![frame(&shared, "version"), frame(&shared, "version/files")];
        assert!(shared.lend(frame(&shared, "local"), &mut ancestors).is_some());
        assert!(ancestors.iter().all(|f| !f.deferred_check));
        lock(&shared.queue).waiting = 1;
        assert!(shared.lend(frame(&shared, "lent"), &mut ancestors).is_none());
        assert!(ancestors.iter().all(|f| f.deferred_check));
        assert_eq!(lock(&shared.queue).deferred_slots, 2);
        assert!(shared.lend(frame(&shared, "also-lent"), &mut ancestors).is_none());
        assert_eq!(lock(&shared.queue).deferred_slots, 2);
        lock(&shared.queue).deferred_slots = 16;
        let mut other = vec![frame(&shared, "other")];
        assert!(shared.lend(frame(&shared, "over-cap"), &mut other).is_some());
        assert!(!other[0].deferred_check);
        lock(&shared.queue).jobs.clear();
        drop(ancestors);
        drop(other);
        assert_eq!(lock(&shared.resources).open, 0);
    }

    #[test]
    fn idle_worker_waits_for_active_lender_after_root_producer_finishes() {
        let limits = ScanLimits::default();
        let cancellation = Cancellation::default();
        let shared = shared::<()>(&limits, &cancellation);
        std::thread::scope(|scope| {
            let waiter = scope.spawn(|| shared.take());
            let until = Instant::now() + Duration::from_secs(2);
            while lock(&shared.queue).waiting == 0 && Instant::now() < until {
                std::thread::yield_now();
            }
            let waiting = lock(&shared.queue).waiting == 1;
            if !waiting { shared.stop(); }
            // Always release the waiter before assertions, even on failure.
            shared.job_finished();
            assert!(waiter.join().unwrap().is_none());
            assert!(waiting, "root EOF must not retire workers while a lender is active");
            assert_eq!(lock(&shared.queue).active, 0);
        });
    }

    #[test]
    fn lending_keeps_projects_and_full_queues_local() {
        let limits = ScanLimits { queue_capacity: 1, ..ScanLimits::default() };
        let cancellation = Cancellation::default();
        let mut shared = shared(&limits, &cancellation);
        lock(&shared.queue).waiting = 1;
        let mut ancestors = vec![frame(&shared, "parent")];
        lock(&shared.queue).jobs.push_back(frame(&shared, "queued"));
        assert!(shared.lend(frame(&shared, "full"), &mut ancestors).is_some());
        lock(&shared.queue).jobs.clear();
        let budget = ProjectSizeBudget { visited: std::sync::atomic::AtomicUsize::new(0), max_entries: 100, deadline: Instant::now() + Duration::from_secs(1) };
        shared.project_budget = Some(&budget);
        assert!(shared.lend(frame(&shared, "project"), &mut ancestors).is_some());
        assert!(!ancestors[0].deferred_check);
    }

    struct AbnormalCursor {
        child: bool,
        position: usize,
        panic: bool,
        events: Arc<Mutex<Vec<&'static str>>>,
    }
    impl Drop for AbnormalCursor {
        fn drop(&mut self) { lock(&self.events).push(if self.child { "child closed" } else { "parent closed" }); }
    }
    fn metadata(inode: u64, kind: ResourceKind, size: Option<u64>) -> crate::scan::walk::Metadata {
        crate::scan::walk::Metadata {
            identity: FileIdentity::Unix { device: 1, inode }, kind,
            logical_bytes: size, allocated_bytes: size, private_bytes: size,
            link_count: Some(1), modified_unix_ms: None, dataless: false,
        }
    }
    impl Cursor for AbnormalCursor {
        fn metadata(&self) -> crate::scan::walk::Metadata {
            metadata(if self.child { 2 } else { 1 }, ResourceKind::Directory, None)
        }
        fn next_entry(&mut self) -> Option<Result<crate::scan::walk::DirItem, ScanError>> {
            if self.child { return None; }
            let position = self.position;
            self.position += 1;
            let (name, value) = match position {
                0 => ("child", metadata(2, ResourceKind::Directory, None)),
                1 => {
                    assert!(!self.panic, "injected cursor panic after lending");
                    ("large", metadata(3, ResourceKind::File, Some(u64::MAX)))
                }
                2 => ("overflow", metadata(4, ResourceKind::File, Some(1))),
                _ => return None,
            };
            Some(Ok(crate::scan::walk::DirItem { name: name.into(), metadata: Ok(value) }))
        }
        fn open_child(&self, _: &crate::scan::walk::DirItem) -> Result<Self, ScanError> {
            Ok(Self { child: true, position: 0, panic: false, events: Arc::clone(&self.events) })
        }
        fn unchanged(&self) -> Result<bool, ScanError> {
            lock(&self.events).push(if self.child { "child checked" } else { "parent checked" });
            Ok(true)
        }
    }
    #[test]
    fn fatal_accounting_and_cursor_panic_retain_lenders_until_descendants_finish() {
        for panic in [false, true] {
            let limits = ScanLimits::default();
            let cancellation = Cancellation::default();
            let shared = shared::<AbnormalCursor>(&limits, &cancellation);
            lock(&shared.queue).waiting = 1;
            let events = Arc::new(Mutex::new(Vec::new()));
            let parent = Frame {
                directory: AbnormalCursor { child: false, position: 0, panic, events: Arc::clone(&events) },
                _permit: shared.reserve(shared.root).unwrap(), path: shared.root.to_owned(), depth: 1, deferred_check: false,
            };
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| walk(&shared, parent, false, &mut |_, _, _| {})));
            if panic { assert!(result.is_err()); }
            else { assert!(matches!(result, Ok(Err(ScanError { code: ScanCode::Overflow, .. })))); }
            assert_eq!(lock(&shared.queue).jobs.len(), 1, "a child really was lent");
            assert_eq!(lock(&shared.deferred).len(), 1);
            assert!(lock(&events).is_empty(), "parent must not close or check while child remains outstanding");
            let child = lock(&shared.queue).jobs.pop_front().unwrap();
            walk(&shared, child, false, &mut |_, _, _| {}).unwrap();
            for frame in lock(&shared.deferred).drain(..) { check_unchanged(&shared, &frame); }
            assert_eq!(*lock(&events), ["child checked", "child closed", "parent checked", "parent closed"]);
            assert_eq!(lock(&shared.resources).open, 0);
        }
    }

}
