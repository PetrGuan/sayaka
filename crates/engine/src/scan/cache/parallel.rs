// SPDX-License-Identifier: MPL-2.0

//! Parallelize independent children of a cache root; each worker keeps a
//! streaming DFS. The root stays open until all children finish, so its change
//! check still covers the entire measurement. No per-file records are queued.
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
}
struct Queue<D> {
    jobs: VecDeque<Frame<D>>,
    producer_done: bool,
}
type Sizes = (Option<u64>, Option<u64>);
struct Shared<'a, D> {
    root: &'a Path,
    expected: FileIdentity,
    limits: &'a ScanLimits,
    cancellation: &'a Cancellation,
    started: Instant,
    stopped: AtomicBool,
    queue: Mutex<Queue<D>>,
    wake: Condvar,
    resources: Arc<Mutex<Resources>>,
    directories: Mutex<HashSet<FileIdentity>>,
    linked_files: Mutex<HashMap<FileIdentity, Sizes>>,
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
        if cancelled || self.started.elapsed() >= self.limits.time_budget {
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
        let capacity = self.limits.queue_capacity.min(self.limits.workers.min(4));
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
    fn take(&self) -> Option<Frame<D>> {
        let mut queue = lock(&self.queue);
        loop {
            if self.stopped.load(Ordering::Acquire) {
                return None;
            }
            if let Some(frame) = queue.jobs.pop_front() {
                self.wake.notify_all();
                return Some(frame);
            }
            if queue.producer_done {
                return None;
            }
            queue = self
                .wake
                .wait(queue)
                .unwrap_or_else(|error| error.into_inner());
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

pub(in crate::scan) fn summarize<B: Backend>(
    backend: &B,
    root: &Path,
    expected: FileIdentity,
    limits: &ScanLimits,
    cancellation: &Cancellation,
    mut progress: impl FnMut(usize, u64, u64),
) -> Result<Summary, ScanError> {
    limits.validate()?;
    let policy = backend.enter_thread()?;
    let result = (|| {
        let shared = Shared {
            root,
            expected,
            limits,
            cancellation,
            started: Instant::now(),
            stopped: AtomicBool::new(false),
            queue: Mutex::new(Queue {
                jobs: VecDeque::new(),
                producer_done: false,
            }),
            wake: Condvar::new(),
            resources: Arc::new(Mutex::new(Resources::default())),
            directories: Mutex::new(HashSet::from([expected])),
            linked_files: Mutex::new(HashMap::new()),
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
        let frame = Frame {
            directory,
            _permit: permit,
            path: root.to_owned(),
            depth: 1,
        };
        std::thread::scope(|scope| -> Result<(), ScanError> {
            let mut producer_guard = StopOnFailure {
                shared: &shared,
                success: false,
            };
            let mut workers = Vec::new();
            let mut failure = None;
            for index in 0..limits.workers.min(4) {
                let shared = &shared;
                match backend.spawn_worker(scope, index, move || {
                    let mut guard = StopOnFailure {
                        shared,
                        success: false,
                    };
                    let policy = backend.enter_thread()?;
                    let result = (|| {
                        while let Some(frame) = shared.take() {
                            walk(shared, frame, false, &mut |_, _, _| {})?;
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
            while workers.iter().any(|worker| !worker.is_finished()) {
                shared.interrupted();
                shared.report(&mut progress);
                std::thread::sleep(Duration::from_millis(50));
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
            if let Some(frame) = retained_root {
                check_unchanged(&shared, &frame);
            }
            producer_guard.success = true;
            failure.map_or(Ok(()), Err)
        })?;
        shared.interrupted();
        shared.report(&mut progress);
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
    let mut stack = vec![frame];
    let mut local = empty_totals();
    while !stack.is_empty() && !shared.interrupted() {
        let frame = stack.last_mut().expect("nonempty stack");
        let item = match frame.directory.next_entry() {
            None => {
                if producer {
                    shared.flush(&mut local)?;
                    return Ok(stack.pop());
                }
                check_unchanged(shared, frame);
                stack.pop();
                continue;
            }
            Some(Err(error)) => {
                shared.issue(&frame.path, error);
                stack.pop();
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
        let path = frame.path.join(&item.name);
        if path.as_os_str().len() > shared.limits.max_path_bytes.min(65_536) {
            shared.issue(
                &frame.path,
                ScanError::new(ScanCode::PathBytesLimit, "cache path budget reached"),
            );
            continue;
        }
        local.entries = local.entries.checked_add(1).ok_or_else(overflow)?;
        if local.entries >= shared.limits.progress_every {
            shared.flush(&mut local)?;
            if producer {
                shared.report(progress);
            }
        }
        let metadata = match &item.metadata {
            Ok(metadata) => metadata,
            Err(error) => {
                shared.issue(&path, error.clone());
                continue;
            }
        };
        if device(metadata.identity) != device(shared.expected) {
            shared.issue(
                &path,
                ScanError::new(
                    ScanCode::MountBoundary,
                    "cache mount boundary not traversed",
                ),
            );
            continue;
        }
        if metadata.dataless {
            shared.issue(
                &path,
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
                let sizes = (metadata.logical_bytes, metadata.allocated_bytes);
                if metadata.link_count != Some(1) {
                    let mut files = lock(&shared.linked_files);
                    if let Some(previous) = files.get(&metadata.identity) {
                        if previous != &sizes {
                            shared.issue(
                                &path,
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
                            &path,
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
            }
            ResourceKind::Directory => {
                {
                    let mut directories = lock(&shared.directories);
                    if directories.contains(&metadata.identity) {
                        shared.issue(
                            &path,
                            ScanError::new(
                                ScanCode::ChangedEntry,
                                "duplicate cache directory identity",
                            ),
                        );
                        continue;
                    }
                    if directories.len() >= shared.limits.max_entries {
                        shared.issue(
                            &path,
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
                        &path,
                        ScanError::new(ScanCode::DepthLimit, "cache depth budget reached"),
                    );
                    continue;
                }
                let permit = match shared.reserve(&path) {
                    Ok(permit) => permit,
                    Err(error) => {
                        shared.issue(&path, error);
                        continue;
                    }
                };
                let directory = match frame.directory.open_child(&item) {
                    Ok(directory) => directory,
                    Err(mut error) => {
                        if error.code == ScanCode::LinkSkipped {
                            error.code = ScanCode::ChangedEntry;
                        }
                        shared.issue(&path, error);
                        continue;
                    }
                };
                let opened = directory.metadata();
                if opened.identity != metadata.identity
                    || opened.kind != ResourceKind::Directory
                    || opened.dataless
                {
                    shared.issue(
                        &path,
                        ScanError::new(
                            ScanCode::ChangedEntry,
                            "cache directory replaced before opening",
                        ),
                    );
                    continue;
                }
                let child = Frame {
                    directory,
                    _permit: permit,
                    path,
                    depth: frame.depth + 1,
                };
                if producer {
                    shared.flush(&mut local)?;
                    shared.submit(child, progress);
                } else {
                    stack.push(child);
                }
            }
            _ => shared.issue(
                &path,
                ScanError::new(ScanCode::Io, "unsupported cache entry kind"),
            ),
        }
    }
    shared.flush(&mut local)?;
    Ok(None)
}
fn empty_totals() -> Summary {
    Summary {
        complete: true,
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
