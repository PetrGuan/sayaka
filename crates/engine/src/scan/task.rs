// SPDX-License-Identifier: MPL-2.0

//! Owned read-only scan worker with one coalesced progress slot.

use super::{ScanCode, ScanError, ScanLimits, ScanProgress, ScanReport, ScanStatus};
use crate::model::{Cancellation, valid_absolute_path};
use crate::readonly_task::ReadOnlyTask;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanTaskState {
    Running,
    Complete,
    Partial,
    Cancelled,
    Failed,
}

#[derive(Clone, Debug)]
pub struct ScanTaskSnapshot {
    pub state: ScanTaskState,
    pub cancellation_requested: bool,
    pub progress_sequence: u64,
    pub progress: Option<ScanProgress>,
}

pub struct ScanTask {
    inner: ReadOnlyTask<ScanReport, ScanProgress>,
}

impl ScanTask {
    pub fn start(roots: Vec<PathBuf>, limits: ScanLimits) -> Result<Self, ScanError> {
        validate_roots(&roots, &limits)?;
        Self::spawn(move |cancel, progress| super::scan(&roots, &limits, cancel, progress))
    }

    fn spawn(
        operation: impl FnOnce(
            &Cancellation,
            &mut dyn FnMut(&ScanProgress),
        ) -> Result<ScanReport, ScanError>
        + Send
        + 'static,
    ) -> Result<Self, ScanError> {
        Ok(Self {
            inner: ReadOnlyTask::spawn("sayaka-host-scan", operation)?,
        })
    }

    pub fn cancel(&self) {
        self.inner.cancel();
    }

    pub fn is_finished(&self) -> bool {
        self.inner.is_finished()
    }

    pub fn poll(&mut self) -> Result<ScanTaskSnapshot, ScanError> {
        let slot = self.inner.poll()?;
        let state = match self.inner.outcome() {
            None => ScanTaskState::Running,
            Some(Err(_)) => ScanTaskState::Failed,
            Some(Ok(report)) => match report.status {
                ScanStatus::Complete => ScanTaskState::Complete,
                ScanStatus::Partial => ScanTaskState::Partial,
                ScanStatus::Cancelled => ScanTaskState::Cancelled,
                ScanStatus::Failed => ScanTaskState::Failed,
            },
        };
        Ok(ScanTaskSnapshot {
            state,
            cancellation_requested: slot.cancellation_requested,
            progress_sequence: slot.progress_sequence,
            progress: slot.progress,
        })
    }

    /// None until the owned worker has exited; polling never joins active work.
    pub fn result(&mut self) -> Option<&Result<ScanReport, ScanError>> {
        self.inner.result()
    }
}

pub(crate) fn validate_roots(roots: &[PathBuf], limits: &ScanLimits) -> Result<(), ScanError> {
    limits.validate()?;
    if roots.is_empty()
        || roots.len() > 64
        || roots.iter().any(|root| {
            !valid_absolute_path(root)
                || root.parent().is_none()
                || root.as_os_str().len() > limits.max_path_bytes.min(65_536)
        })
    {
        return Err(ScanError::new(
            ScanCode::InvalidRoot,
            "provide 1..64 non-root absolute scan paths without traversal or NUL",
        ));
    }
    let bytes = roots
        .iter()
        .try_fold(0usize, |sum, path| sum.checked_add(path.as_os_str().len()));
    if bytes.is_none_or(|bytes| bytes > limits.max_path_bytes) {
        return Err(ScanError::new(
            ScanCode::InvalidRoot,
            "scan roots exceed path budget",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::{ScanMetrics, ScanTaskId, ScanTotals};
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    fn report(status: ScanStatus) -> ScanReport {
        ScanReport {
            task_id: ScanTaskId::synthetic(1),
            roots: vec![],
            status,
            complete: status == ScanStatus::Complete,
            entries: vec![],
            issues: vec![],
            issues_omitted: 0,
            totals: ScanTotals::default(),
            metrics: ScanMetrics::default(),
        }
    }

    fn finish(task: &mut ScanTask) -> ScanTaskSnapshot {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let value = task.poll().unwrap();
            if value.state != ScanTaskState::Running {
                return value;
            }
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
    }

    #[test]
    fn coalesces_progress_and_preserves_terminal_result() {
        let mut task = ScanTask::spawn(|_, progress| {
            for entries in 1..=100 {
                progress(&ScanProgress {
                    task_id: ScanTaskId::synthetic(1),
                    entries,
                    unique_files: entries as u64,
                    logical_bytes_known: entries as u64,
                    issues: 0,
                    elapsed_ms: entries as u64,
                });
            }
            Ok(report(ScanStatus::Partial))
        })
        .unwrap();
        let snapshot = finish(&mut task);
        assert_eq!(snapshot.state, ScanTaskState::Partial);
        assert_eq!(snapshot.progress_sequence, 100);
        assert_eq!(snapshot.progress.unwrap().entries, 100);
        task.cancel();
        assert_eq!(task.poll().unwrap().state, ScanTaskState::Partial);
        assert_eq!(
            task.result().unwrap().as_ref().unwrap().status,
            ScanStatus::Partial
        );
    }

    #[test]
    fn cancellation_and_pending_result_are_explicit() {
        let (ready, received) = mpsc::channel();
        let mut task = ScanTask::spawn(move |cancel, _| {
            ready.send(()).unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            while !cancel.is_cancelled() {
                assert!(Instant::now() < deadline);
                thread::yield_now();
            }
            Ok(report(ScanStatus::Cancelled))
        })
        .unwrap();
        received.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(task.poll().unwrap().state, ScanTaskState::Running);
        assert!(task.result().is_none());
        task.cancel();
        assert_eq!(finish(&mut task).state, ScanTaskState::Cancelled);
    }

    #[test]
    fn failure_and_worker_panic_remain_terminal_errors() {
        let mut error =
            ScanTask::spawn(|_, _| Err(ScanError::new(ScanCode::Internal, "injected"))).unwrap();
        assert_eq!(finish(&mut error).state, ScanTaskState::Failed);
        assert_eq!(
            error.result().unwrap().as_ref().unwrap_err().message,
            "injected"
        );
        let mut panic = ScanTask::spawn(|_, _| panic!("owned injected panic")).unwrap();
        assert_eq!(finish(&mut panic).state, ScanTaskState::Failed);
        assert_eq!(
            panic.result().unwrap().as_ref().unwrap_err().code,
            ScanCode::WorkerPanic
        );
    }

    #[test]
    fn drop_cancels_and_joins_owned_work() {
        let (done, receiver) = mpsc::channel();
        let task = ScanTask::spawn(move |cancel, _| {
            let deadline = Instant::now() + Duration::from_secs(5);
            while !cancel.is_cancelled() {
                assert!(Instant::now() < deadline);
                thread::yield_now();
            }
            done.send(()).unwrap();
            Ok(report(ScanStatus::Cancelled))
        })
        .unwrap();
        drop(task);
        receiver.recv_timeout(Duration::from_secs(1)).unwrap();
    }

    #[test]
    fn invalid_inputs_fail_before_spawning() {
        for roots in [
            vec![],
            vec![PathBuf::from("relative")],
            vec![PathBuf::from("/a/../b")],
        ] {
            assert!(ScanTask::start(roots, ScanLimits::default()).is_err());
        }
    }
}
