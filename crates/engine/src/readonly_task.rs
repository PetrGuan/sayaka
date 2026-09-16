// SPDX-License-Identifier: MPL-2.0

use crate::model::Cancellation;
use crate::scan::{ScanCode, ScanError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

pub(crate) struct TaskSnapshot<P> {
    pub cancellation_requested: bool,
    pub progress_sequence: u64,
    pub progress: Option<P>,
}

struct ProgressSlot<P> {
    sequence: u64,
    progress: Option<P>,
}

pub(crate) struct ReadOnlyTask<T, P> {
    cancellation: Cancellation,
    progress: Arc<Mutex<ProgressSlot<P>>>,
    worker: Option<JoinHandle<Result<T, ScanError>>>,
    outcome: Option<Result<T, ScanError>>,
}

impl<T: Send + 'static, P: Clone + Send + 'static> ReadOnlyTask<T, P> {
    pub fn spawn(
        name: &str,
        operation: impl FnOnce(&Cancellation, &mut dyn FnMut(&P)) -> Result<T, ScanError>
        + Send
        + 'static,
    ) -> Result<Self, ScanError> {
        let cancellation = Cancellation::default();
        let cancel = cancellation.clone();
        let progress = Arc::new(Mutex::new(ProgressSlot {
            sequence: 0,
            progress: None,
        }));
        let slot = Arc::clone(&progress);
        let worker = thread::Builder::new()
            .name(name.into())
            .spawn(move || {
                let mut progress_error = None;
                let result = operation(&cancel, &mut |update| match slot.lock() {
                    Ok(mut slot) => {
                        if let Some(sequence) = slot.sequence.checked_add(1) {
                            slot.sequence = sequence;
                            slot.progress = Some(update.clone());
                        } else {
                            progress_error =
                                Some(internal("read-only task progress sequence exhausted"));
                            cancel.cancel();
                        }
                    }
                    Err(_) => {
                        progress_error = Some(internal("read-only task progress state poisoned"));
                        cancel.cancel();
                    }
                });
                if let Some(error) = progress_error {
                    Err(error)
                } else {
                    result
                }
            })
            .map_err(|error| ScanError::new(ScanCode::WorkerStartFailed, error.to_string()))?;
        Ok(Self {
            cancellation,
            progress,
            worker: Some(worker),
            outcome: None,
        })
    }

    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    pub fn is_finished(&self) -> bool {
        self.worker.as_ref().is_none_or(JoinHandle::is_finished)
    }

    fn collect_finished(&mut self) {
        if self.is_finished()
            && let Some(worker) = self.worker.take()
        {
            self.outcome = Some(worker.join().unwrap_or_else(|_| {
                Err(ScanError::new(
                    ScanCode::WorkerPanic,
                    "owned read-only worker panicked",
                ))
            }));
        }
    }

    pub fn poll(&mut self) -> Result<TaskSnapshot<P>, ScanError> {
        self.collect_finished();
        let slot = self
            .progress
            .lock()
            .map_err(|_| internal("read-only task progress state poisoned"))?;
        Ok(TaskSnapshot {
            cancellation_requested: self.cancellation.is_cancelled(),
            progress_sequence: slot.sequence,
            progress: slot.progress.clone(),
        })
    }

    pub fn result(&mut self) -> Option<&Result<T, ScanError>> {
        self.collect_finished();
        self.outcome.as_ref()
    }

    pub fn outcome(&self) -> Option<&Result<T, ScanError>> {
        self.outcome.as_ref()
    }
}

impl<T, P> Drop for ReadOnlyTask<T, P> {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(worker) = self.worker.take() {
            match worker.join() {
                Ok(Ok(_)) => {}
                Ok(Err(error)) if error.code == ScanCode::Cancelled => {}
                Ok(Err(error)) => eprintln!("read-only task cleanup: {error}"),
                Err(_) => eprintln!("read-only task worker panicked during cleanup"),
            }
        }
    }
}

fn internal(message: &str) -> ScanError {
    ScanError::new(ScanCode::Internal, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    #[test]
    fn progress_exhaustion_cancels_and_reports_an_error() {
        let (go, wait) = mpsc::channel();
        let mut task = ReadOnlyTask::spawn("owned-sequence-test", move |cancel, update| {
            wait.recv_timeout(Duration::from_secs(5)).unwrap();
            update(&1u64);
            assert!(cancel.is_cancelled());
            Ok(())
        })
        .unwrap();
        task.progress.lock().unwrap().sequence = u64::MAX;
        assert!(task.result().is_none());
        task.progress.lock().unwrap().progress = Some(0);
        go.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !task.is_finished() {
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
        assert_eq!(
            task.result().unwrap().as_ref().unwrap_err().code,
            ScanCode::Internal
        );
        assert!(task.poll().unwrap().cancellation_requested);
    }
}
