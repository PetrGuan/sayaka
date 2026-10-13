// SPDX-License-Identifier: MPL-2.0
//! Preview-only bounded waiting for synchronous native ownership observations.
//! A native call cannot be forcibly interrupted. At most two read-only workers
//! may outlive a wait; their late results are discarded and no execution uses them.
use std::{
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, atomic::{AtomicBool, AtomicUsize, Ordering}, mpsc, OnceLock},
    time::{Duration, Instant},
};

static ACTIVE: OnceLock<Arc<AtomicUsize>> = OnceLock::new();
const CAPACITY: usize = 2;
const OWNER_BUDGET: Duration = Duration::from_secs(5);
const POLL: Duration = Duration::from_millis(25);
const LOG_LIMIT: usize = 256;
const SLOW_LOG_LIMIT: usize = 32;

struct Slot(Arc<AtomicUsize>);
impl Slot {
    fn reserve(active: Arc<AtomicUsize>) -> Option<Self> {
        active.fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |n| (n < CAPACITY).then_some(n + 1)).ok().map(|_| Self(active))
    }
}
impl Drop for Slot {
    fn drop(&mut self) { self.0.fetch_sub(1, Ordering::AcqRel); }
}

#[derive(Clone)]
struct Stage {
    operation: &'static str,
    path: PathBuf,
    started: Instant,
}
#[derive(Clone)]
pub(crate) struct Control {
    pub deadline: Instant,
    stopped: Arc<AtomicBool>,
    stage: Arc<Mutex<Stage>>,
    logs: Arc<AtomicUsize>,
    started: Instant,
}
impl Control {
    pub fn new(deadline: Instant, path: &Path, logs: Arc<AtomicUsize>) -> Self {
        let started = Instant::now();
        Self { deadline, stopped: Arc::new(AtomicBool::new(false)),
            stage: Arc::new(Mutex::new(Stage { operation: "queued", path: path.to_owned(), started })),
            logs, started }
    }
    pub fn check(&self) -> io::Result<()> {
        if self.stopped.load(Ordering::Acquire) { return Err(self.failure("cancelled")); }
        if Instant::now() >= self.deadline { return Err(self.failure("deadline")); }
        Ok(())
    }
    pub fn run<T>(&self, operation: &'static str, path: &Path, action: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
        self.check()?;
        let started = Instant::now();
        *self.stage.lock().map_err(|_| io::Error::other("owner diagnostic state unavailable"))? =
            Stage { operation, path: path.to_owned(), started };
        self.log("begin", operation, path, 0);
        let result = action();
        self.log("end", operation, path, started.elapsed().as_micros());
        self.check()?; // A completed but late observation is never accepted.
        result.map_err(|e| io::Error::new(e.kind(), format!(
            "copies_unknown: operation={operation} path={path:?} operation_us={}: {e}", started.elapsed().as_micros())))
    }
    fn log(&self, event: &str, operation: &str, path: &Path, operation_us: u128) {
        // Reserve a bounded tail for slow completed operations even after early
        // owners exhaust routine detail. Both limits share one classification counter.
        let limit = if event == "end" && operation_us >= 50_000 { LOG_LIMIT + SLOW_LOG_LIMIT } else { LOG_LIMIT };
        if self.logs.fetch_update(Ordering::Relaxed, Ordering::Relaxed,
            |n| (n < limit).then_some(n + 1)).is_ok() {
            super::diagnostics::debug_line(format_args!(
                "event=owner_{event} operation={operation} path={path:?} operation_us={operation_us} elapsed_us={} remaining_ms={}",
                self.started.elapsed().as_micros(), self.deadline.saturating_duration_since(Instant::now()).as_millis()));
        }
    }
    fn failure(&self, reason: &str) -> io::Error {
        let detail = match self.stage.lock() {
            Ok(s) => format!("operation={} path={:?} operation_us={}", s.operation, s.path, s.started.elapsed().as_micros()),
            Err(_) => "operation=unknown".into(),
        };
        io::Error::other(format!("copies_unknown: {reason} {detail} elapsed_us={}", self.started.elapsed().as_micros()))
    }
}
struct Stop(Control);
impl Drop for Stop {
    fn drop(&mut self) { self.0.stopped.store(true, Ordering::Release); }
}

/// Outer error is caller cancellation/progress failure; inner error protects only
/// this candidate. No unbounded queue, joins, stale reuse, or cleanup capabilities.
pub(crate) fn observe<T: Send + 'static>(
    path: &Path, deadline: Instant, logs: Arc<AtomicUsize>,
    mut progress: impl FnMut() -> Result<(), String>,
    action: impl FnOnce(&Control) -> Result<T, String> + Send + 'static,
) -> Result<Result<T, String>, String> {
    progress()?;
    let control = Control::new(deadline.min(Instant::now() + OWNER_BUDGET), path, logs);
    if let Err(e) = control.check() { return Ok(Err(e.to_string())); }
    let Some(slot) = Slot::reserve(Arc::clone(ACTIVE.get_or_init(|| Arc::new(AtomicUsize::new(0))))) else { return Ok(Err(control.failure("observation_busy").to_string())); };
    let _stop = Stop(control.clone());
    let worker_control = control.clone();
    let (sender, receiver) = mpsc::sync_channel(1);
    let worker = std::thread::Builder::new().name("sayaka-owner-observation".into()).spawn(move || {
        let _slot = slot;
        let result = (|| {
            worker_control.check().map_err(|e| e.to_string())?;
            // I/O policy is thread-local: never rely on the scan worker's guard.
            let policy = sayaka_platform_macos::ReadOnlyPolicy::enter().map_err(|e| e.to_string())?;
            let result = action(&worker_control);
            let restored = policy.restore().map_err(|e| e.to_string());
            worker_control.check().map_err(|e| e.to_string())?;
            restored?;
            result
        })();
        let _ = sender.send(result); // capacity one; abandoned receiver drops it
    });
    if let Err(e) = worker { return Ok(Err(format!("owner worker unavailable: {e}"))); }
    loop {
        progress()?;
        if let Err(e) = control.check() {
            super::diagnostics::debug_line(format_args!("event=owner_timeout {e}"));
            return Ok(Err(e.to_string()));
        }
        let wait = POLL.min(control.deadline.saturating_duration_since(Instant::now()));
        match receiver.recv_timeout(wait) {
            Ok(result) => {
                progress()?;
                if let Err(e) = control.check() { return Ok(Err(e.to_string())); }
                if result.is_err() || control.started.elapsed() >= Duration::from_millis(50) {
                    super::diagnostics::debug_line(format_args!("event=owner_outcome path={path:?} elapsed_us={} result={:?}",
                        control.started.elapsed().as_micros(), result.as_ref().map(|_| "observed")));
                }
                return Ok(result);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {},
            Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(Err("owner worker failed; ownership unknown".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capacity_is_retained_until_worker_slot_drops() {
        let active = Arc::new(AtomicUsize::new(0));
        let first = Slot::reserve(active.clone()).unwrap();
        let second = Slot::reserve(active.clone()).unwrap();
        assert!(Slot::reserve(active.clone()).is_none());
        drop(first);
        let replacement = Slot::reserve(active.clone()).unwrap();
        assert!(Slot::reserve(active.clone()).is_none());
        drop(second);
        drop(replacement);
        assert_eq!(active.load(Ordering::Acquire), 0);
    }
    #[test]
    fn expired_budget_never_runs_observation() {
        let called = Arc::new(AtomicBool::new(false));
        let copy = called.clone();
        let result = observe(Path::new("/example.app"), Instant::now(), Arc::new(AtomicUsize::new(0)),
            || Ok(()), move |_| { copy.store(true, Ordering::Relaxed); Ok(()) }).unwrap();
        assert!(result.unwrap_err().contains("deadline"));
        assert!(!called.load(Ordering::Relaxed));
    }
    #[test]
    fn caller_cancellation_is_not_a_candidate_error() {
        let result = observe(Path::new("/example.app"), Instant::now() + OWNER_BUDGET,
            Arc::new(AtomicUsize::new(0)), || Err("classification cancelled".into()), |_| Ok(()));
        assert_eq!(result.unwrap_err(), "classification cancelled");
    }
    #[test]
    fn late_success_is_not_accepted() {
        let control = Control::new(Instant::now() + Duration::from_millis(10), Path::new("/example.app"), Arc::new(AtomicUsize::new(0)));
        let result = control.run("registry", Path::new("/example.app"), || {
            std::thread::sleep(Duration::from_millis(20));
            Ok(())
        });
        assert!(result.unwrap_err().to_string().contains("deadline"));
    }
    #[test]
    fn operation_cancelled_before_return_is_rejected() {
        let control = Control::new(Instant::now() + OWNER_BUDGET, Path::new("/example.app"), Arc::new(AtomicUsize::new(0)));
        let result = control.run("registry", Path::new("/example.app"), || {
            control.stopped.store(true, Ordering::Release);
            Ok(vec![PathBuf::from("/example.app")])
        });
        let error = result.unwrap_err().to_string();
        assert!(error.contains("cancelled"));
        assert!(error.contains("operation=registry"));
    }
}
