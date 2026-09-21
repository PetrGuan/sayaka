// SPDX-License-Identifier: MPL-2.0

use super::*;
use crate::scan::{ScanCode, ScanError};
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionCheckStatus {
    Checked,
    Refused,
    Cancelled,
    Failed,
}

#[derive(Clone, Debug)]
pub struct SelectedInstaller {
    pub candidate_id: u64,
    pub path: PathBuf,
    pub logical_bytes: Option<u64>,
    pub allocated_bytes: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SelectionCheckIssue {
    pub candidate_id: Option<u64>,
    pub code: &'static str,
    pub message: String,
    pub os_code: Option<i32>,
}

#[derive(Clone, Debug)]
pub struct InstallerSelectionPreview {
    pub scan_task_id: String,
    pub status: SelectionCheckStatus,
    pub selected: Vec<SelectedInstaller>,
    pub bytes: InstallerBytes,
    pub issues: Vec<SelectionCheckIssue>,
}

pub(crate) fn validate_selection(
    discovery: &InstallerPreview,
    indices: &[usize],
) -> Result<(), ScanError> {
    let unique: HashSet<_> = indices.iter().copied().collect();
    if indices.is_empty()
        || indices.len() > 32
        || unique.len() != indices.len()
        || indices
            .iter()
            .any(|&index| index >= discovery.candidates.len())
    {
        return Err(ScanError::new(
            ScanCode::InvalidRoot,
            "select 1..32 unique candidates from this discovery",
        ));
    }
    Ok(())
}

/// Rechecks explicit discovery candidates using the same native admission as
/// the CLI. Returns observations only; no Plan, Approval or session survives.
pub fn preview_selection(
    discovery: &InstallerPreview,
    indices: &[usize],
    cancellation: &Cancellation,
) -> Result<InstallerSelectionPreview, ScanError> {
    validate_selection(discovery, indices)?;
    let mut result = InstallerSelectionPreview {
        scan_task_id: discovery.scan_task_id.clone(),
        status: SelectionCheckStatus::Refused,
        selected: Vec::with_capacity(indices.len()),
        bytes: InstallerBytes::default(),
        issues: Vec::new(),
    };
    let mut identities = HashSet::new();
    for &index in indices {
        let candidate = &discovery.candidates[index];
        result.selected.push(SelectedInstaller {
            candidate_id: index as u64 + 1,
            path: candidate.path.clone(),
            logical_bytes: candidate.logical_bytes,
            allocated_bytes: candidate.allocated_bytes,
        });
        if identities.insert(candidate.identity) {
            add_bytes(
                &mut result.bytes.matched_logical_bytes,
                &mut result.bytes.matched_logical_unknown_files,
                candidate.logical_bytes,
            )?;
            add_bytes(
                &mut result.bytes.matched_allocated_bytes,
                &mut result.bytes.matched_allocated_unknown_files,
                candidate.allocated_bytes,
            )?;
        }
    }
    if cancellation.is_cancelled() {
        result.status = SelectionCheckStatus::Cancelled;
        result.issue(None, "cancelled", "selection check cancelled");
        return Ok(result);
    }
    if !discovery.selection_ready() {
        result.issue(
            None,
            "discovery_not_ready",
            "complete unchanged discovery is required",
        );
        return Ok(result);
    }
    for &index in indices {
        let candidate = &discovery.candidates[index];
        if !candidate.selectable() {
            let reason = if candidate.format.status != FormatStatus::Recognized {
                "format_not_recognized"
            } else if candidate.owner_scope != OwnerScope::CurrentUser {
                "owner_not_current_user"
            } else {
                "inspection_not_eligible"
            };
            result.issue(
                Some(index as u64 + 1),
                reason,
                "candidate lacks eligible current-user single-link inspection evidence",
            );
        }
    }
    if !result.issues.is_empty() {
        return Ok(result);
    }
    let paths: Vec<_> = result
        .selected
        .iter()
        .map(|item| item.path.clone())
        .collect();
    match crate::execute::InstallerSession::prepare(discovery, &paths, cancellation) {
        Ok(session) => {
            for issue in session.issues() {
                let id = result
                    .selected
                    .iter()
                    .find(|item| crate::journal::NativePath::from_path(&item.path) == issue.path)
                    .map(|item| item.candidate_id);
                result.issue_with_os_code(
                    id,
                    "native_inspection_failed",
                    &issue.message,
                    issue.os_code,
                );
            }
            for refusal in session.refusals() {
                let id = result
                    .selected
                    .iter()
                    .find(|item| crate::journal::NativePath::from_path(&item.path) == refusal.path)
                    .map(|item| item.candidate_id);
                result.issue(id, "native_policy_refused", &refusal.reason);
            }
            if session.ready() {
                result.status = SelectionCheckStatus::Checked;
            } else if result.issues.is_empty() {
                result.issue(
                    None,
                    "native_batch_refused",
                    "the full selected batch was not admitted",
                );
            }
        }
        Err(error) => {
            let code = if error.kind() == std::io::ErrorKind::Interrupted {
                result.status = SelectionCheckStatus::Cancelled;
                "cancelled"
            } else if matches!(
                error.kind(),
                std::io::ErrorKind::PermissionDenied
                    | std::io::ErrorKind::InvalidInput
                    | std::io::ErrorKind::NotFound
                    | std::io::ErrorKind::Unsupported
            ) {
                "native_revalidation_failed"
            } else {
                result.status = SelectionCheckStatus::Failed;
                "native_check_failed"
            };
            result.issue_with_os_code(None, code, &error.to_string(), error.raw_os_error());
        }
    }
    if cancellation.is_cancelled() {
        result.status = SelectionCheckStatus::Cancelled;
        result.issue(
            None,
            "cancelled",
            "selection check cancelled; no action was performed",
        );
    }
    Ok(result)
}

fn add_bytes(known: &mut u64, unknown: &mut u64, value: Option<u64>) -> Result<(), ScanError> {
    let (total, increment) = match value {
        Some(value) => (known, value),
        None => (unknown, 1),
    };
    *total = total.checked_add(increment).ok_or_else(|| {
        ScanError::new(ScanCode::Overflow, "selected installer byte total overflow")
    })?;
    Ok(())
}

impl InstallerSelectionPreview {
    fn issue(&mut self, candidate_id: Option<u64>, code: &'static str, message: &str) {
        self.issue_with_os_code(candidate_id, code, message, None);
    }

    fn issue_with_os_code(
        &mut self,
        candidate_id: Option<u64>,
        code: &'static str,
        message: &str,
        os_code: Option<i32>,
    ) {
        self.issues.push(SelectionCheckIssue {
            candidate_id,
            code,
            message: message.into(),
            os_code,
        });
    }
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;

    #[test]
    fn selection_wire_preserves_native_code_and_policy_absence() {
        let mut preview = InstallerSelectionPreview {
            scan_task_id: "diagnostic-fixture".into(),
            status: SelectionCheckStatus::Refused,
            selected: Vec::new(),
            bytes: InstallerBytes::default(),
            issues: Vec::new(),
        };
        let error = std::io::Error::from_raw_os_error(1);
        preview.issue_with_os_code(
            Some(1),
            "native_inspection_failed",
            &error.to_string(),
            error.raw_os_error(),
        );
        preview.issue(None, "native_policy_refused", "protection_unknown");
        let wire = crate::installer_preview::wire::selection_json(&preview);
        assert_eq!(wire["issues"][0]["os_code"], 1);
        assert!(wire["issues"][1]["os_code"].is_null());
        assert_eq!(wire["status"], "refused");
        assert_eq!(wire["effects_performed"], false);
        assert_eq!(wire["execution_authority"], false);
    }
}
