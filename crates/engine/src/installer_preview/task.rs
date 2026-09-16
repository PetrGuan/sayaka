// SPDX-License-Identifier: MPL-2.0

use super::*;
use crate::readonly_task::ReadOnlyTask;
use crate::scan::task::{ScanTaskState, validate_roots};
use crate::scan::{self, ScanCode, ScanError, ScanLimits};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallerTaskKind {
    Discovery,
    Selection,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallerPhase {
    Scanning,
    Inspecting,
    CheckingSelection,
}

#[derive(Clone, Debug)]
pub struct InstallerProgress {
    pub phase: InstallerPhase,
    pub observed_entries: u64,
    pub total_candidates: u64,
    pub inspected_candidates: u64,
    pub elapsed_ms: u64,
}

pub enum InstallerTaskResult {
    Discovery(Arc<InstallerPreview>),
    Selection(InstallerSelectionPreview),
}

pub struct InstallerTaskSnapshot {
    pub kind: InstallerTaskKind,
    pub state: ScanTaskState,
    pub cancellation_requested: bool,
    pub progress_sequence: u64,
    pub progress: Option<InstallerProgress>,
}

pub struct InstallerTask {
    kind: InstallerTaskKind,
    inner: ReadOnlyTask<InstallerTaskResult, InstallerProgress>,
}

impl InstallerTask {
    pub fn start(root: PathBuf) -> Result<Self, ScanError> {
        if !cfg!(target_os = "macos") {
            return Err(ScanError::new(
                ScanCode::UnsupportedPlatform,
                "native installer inspection is macOS-only",
            ));
        }
        let limits = ScanLimits::default();
        validate_roots(std::slice::from_ref(&root), &limits)?;
        Ok(Self {
            kind: InstallerTaskKind::Discovery,
            inner: ReadOnlyTask::spawn("sayaka-host-installers", move |cancel, progress| {
                let started = Instant::now();
                progress(&InstallerProgress {
                    phase: InstallerPhase::Scanning,
                    observed_entries: 0,
                    total_candidates: 0,
                    inspected_candidates: 0,
                    elapsed_ms: 0,
                });
                let report = scan::scan(&[root], &limits, cancel, |update| {
                    progress(&InstallerProgress {
                        phase: InstallerPhase::Scanning,
                        observed_entries: update.entries as u64,
                        total_candidates: 0,
                        inspected_candidates: 0,
                        elapsed_ms: elapsed_ms(started.elapsed()),
                    });
                })?;
                let entries = report.entries.len() as u64;
                let remaining = INSTALLER_TOTAL_BUDGET.saturating_sub(started.elapsed());
                let preview = preview_installers_with_progress(
                    report,
                    &InstallerPreviewOptions::default(),
                    cancel,
                    remaining,
                    |update| {
                        progress(&InstallerProgress {
                            phase: InstallerPhase::Inspecting,
                            observed_entries: entries,
                            total_candidates: update.total_candidates as u64,
                            inspected_candidates: update.inspected_candidates as u64,
                            elapsed_ms: elapsed_ms(started.elapsed()),
                        });
                    },
                );
                Ok(InstallerTaskResult::Discovery(Arc::new(preview)))
            })?,
        })
    }

    pub fn start_selection(
        discovery: Arc<InstallerPreview>,
        indices: Vec<usize>,
    ) -> Result<Self, ScanError> {
        if !cfg!(target_os = "macos") {
            return Err(ScanError::new(
                ScanCode::UnsupportedPlatform,
                "native installer checks are macOS-only",
            ));
        }
        super::selection::validate_selection(&discovery, &indices)?;
        Ok(Self {
            kind: InstallerTaskKind::Selection,
            inner: ReadOnlyTask::spawn(
                "sayaka-host-installer-selection",
                move |cancel, progress| {
                    let started = Instant::now();
                    let mut update = InstallerProgress {
                        phase: InstallerPhase::CheckingSelection,
                        observed_entries: 0,
                        total_candidates: indices.len() as u64,
                        inspected_candidates: 0,
                        elapsed_ms: 0,
                    };
                    progress(&update);
                    let result = preview_selection(&discovery, &indices, cancel)?;
                    if result.status == SelectionCheckStatus::Checked {
                        update.inspected_candidates = indices.len() as u64;
                    }
                    update.elapsed_ms = elapsed_ms(started.elapsed());
                    progress(&update);
                    Ok(InstallerTaskResult::Selection(result))
                },
            )?,
        })
    }

    pub fn kind(&self) -> InstallerTaskKind {
        self.kind
    }
    pub fn cancel(&self) {
        self.inner.cancel();
    }
    pub fn is_finished(&self) -> bool {
        self.inner.is_finished()
    }
    pub fn result(&mut self) -> Option<&Result<InstallerTaskResult, ScanError>> {
        self.inner.result()
    }

    pub fn poll(&mut self) -> Result<InstallerTaskSnapshot, ScanError> {
        let snapshot = self.inner.poll()?;
        let state = match self.inner.outcome() {
            None => ScanTaskState::Running,
            Some(Err(error)) if error.code == ScanCode::Cancelled => ScanTaskState::Cancelled,
            Some(Err(_)) => ScanTaskState::Failed,
            Some(Ok(InstallerTaskResult::Discovery(preview))) => match preview.status {
                InstallerStatus::Complete => ScanTaskState::Complete,
                InstallerStatus::Partial => ScanTaskState::Partial,
                InstallerStatus::Cancelled => ScanTaskState::Cancelled,
                InstallerStatus::Failed => ScanTaskState::Failed,
            },
            Some(Ok(InstallerTaskResult::Selection(preview))) => match preview.status {
                SelectionCheckStatus::Checked => ScanTaskState::Complete,
                SelectionCheckStatus::Refused => ScanTaskState::Partial,
                SelectionCheckStatus::Cancelled => ScanTaskState::Cancelled,
                SelectionCheckStatus::Failed => ScanTaskState::Failed,
            },
        };
        Ok(InstallerTaskSnapshot {
            kind: self.kind,
            state,
            cancellation_requested: snapshot.cancellation_requested,
            progress_sequence: snapshot.progress_sequence,
            progress: snapshot.progress,
        })
    }
}
