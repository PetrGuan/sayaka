// SPDX-License-Identifier: MPL-2.0

//! Administrator-approved uninstall of a root-owned app bundle directly in
//! `/Applications`, performed by Finder (SayakaCleaner#323).
//!
//! The ordinary user cannot move such a bundle, and `NSWorkspace` refuses
//! without prompting. Finder's delete shows the system administrator prompt,
//! so the app asks Finder to move the bundle. The core owns everything else:
//! admission, revalidation right before the hand-off, a durable journal
//! intent under `system_delegated_trash_v1`, and verification of the outcome
//! by observation. Finder's own report is never trusted on its own. Nothing
//! is permanently deleted. See docs/UNINSTALL_EXECUTION.md.

use crate::journal::ItemState;

/// What the app reports Finder said. Advisory only: the outcome is decided
/// by observing the original path and the user's Trash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DelegateStatus {
    /// Finder reported success.
    Reported,
    /// The user cancelled or administrator authorization was denied.
    Cancelled,
    /// Any other error, or no answer.
    Error,
}

impl DelegateStatus {
    pub fn from_code(code: i32) -> Option<Self> {
        match code {
            0 => Some(Self::Reported),
            1 => Some(Self::Cancelled),
            2 => Some(Self::Error),
            _ => None,
        }
    }
}

/// Classifies a delegated move from observation. `original_present` is
/// whether the original path still names the captured bundle (`None` when
/// that could not be observed); `in_trash` is whether the same bundle was
/// found in the user's Trash.
pub fn classify(
    original_present: Option<bool>,
    in_trash: bool,
    status: DelegateStatus,
) -> (ItemState, &'static str) {
    match (original_present, in_trash) {
        (Some(true), false) => (
            ItemState::Failed,
            match status {
                DelegateStatus::Cancelled => "cancelled_by_user",
                DelegateStatus::Error => "delegate_error",
                DelegateStatus::Reported => "not_moved_despite_reported_success",
            },
        ),
        (Some(false), true) => (ItemState::Succeeded, "moved_to_trash_by_finder"),
        _ => (ItemState::Unknown, "delegated_outcome_unverified"),
    }
}

#[cfg(target_os = "macos")]
pub use native::{DelegatedMove, admin_evidence, begin};
#[cfg(target_os = "macos")]
pub use sayaka_platform_macos::AdminBundleEvidence;

#[cfg(target_os = "macos")]
mod native {
    use super::{DelegateStatus, classify};
    use crate::app_uninstall::{self, UninstallPreview};
    use crate::execute::ExecutionReport;
    use crate::journal::{
        self, DelegationRecord, ItemRecord, ItemState, NativePath, Publication, Record, Store,
    };
    use sayaka_platform_macos::AdminBundleEvidence;
    use sha2::{Digest, Sha256};
    use std::path::{Path, PathBuf};

    /// Administrator-path evidence for a preview that has no refusals and
    /// whose bundle is root-owned and admissible. `None` otherwise; the
    /// preview's own identity must match the captured one.
    pub fn admin_evidence(preview: &UninstallPreview) -> Option<AdminBundleEvidence> {
        if !preview.refusals.is_empty() {
            return None;
        }
        let identity = preview.identity.as_ref()?;
        let evidence = AdminBundleEvidence::capture(&preview.bundle_path).ok()?;
        (evidence.device == identity.device && evidence.inode == identity.inode).then_some(evidence)
    }

    fn plan_digest(bundle: &Path, evidence: &AdminBundleEvidence) -> String {
        let mut hasher = Sha256::new();
        let path = bundle.as_os_str().as_encoded_bytes();
        hasher.update((path.len() as u64).to_le_bytes());
        hasher.update(path);
        for value in [
            evidence.device,
            evidence.inode,
            evidence.manifest_device,
            evidence.manifest_inode,
        ] {
            hasher.update(value.to_le_bytes());
        }
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// A delegated move whose durable intent is written. The app now asks
    /// Finder to move the bundle, then calls [`DelegatedMove::finish`].
    /// Dropping it without finishing leaves the intent `started`, which the
    /// journal reads back as unknown and never retries.
    pub struct DelegatedMove {
        bundle: PathBuf,
        evidence: AdminBundleEvidence,
        store: Store,
        report: ExecutionReport,
    }

    /// Re-observes the bundle right before the hand-off and writes the
    /// durable intent. Any change since `captured` refuses with a message;
    /// nothing has been written then.
    pub fn begin(
        bundle: &Path,
        captured: &AdminBundleEvidence,
        store: Store,
    ) -> Result<DelegatedMove, String> {
        let fresh = AdminBundleEvidence::capture(bundle).map_err(|error| error.to_string())?;
        if (
            fresh.device,
            fresh.inode,
            fresh.manifest_device,
            fresh.manifest_inode,
        ) != (
            captured.device,
            captured.inode,
            captured.manifest_device,
            captured.manifest_inode,
        ) {
            return Err("the app changed since it was previewed".into());
        }
        let preview = app_uninstall::preview_bundle_uninstall(bundle);
        if let Some(refusal) = preview.refusals.first() {
            return Err(refusal.message.clone());
        }
        let now = journal::now_ms().map_err(|error| error.to_string())?;
        let scope = bundle.parent().unwrap_or(Path::new("/"));
        let record = Record {
            schema_version: journal::DELEGATED_SCHEMA_VERSION,
            plan_schema_version: journal::DELEGATED_PLAN_SCHEMA_VERSION,
            engine_version: journal::DELEGATED_ENGINE_VERSION,
            rules_version: journal::DELEGATED_RULES_VERSION,
            operation_id: store.new_id().map_err(|error| error.to_string())?,
            contract: journal::DELEGATED_CONTRACT.into(),
            scope: NativePath::from_path(scope),
            clean_policy: None,
            tool_operation: None,
            delegation: Some(DelegationRecord {
                schema_version: 1,
                performer: journal::DELEGATED_PERFORMER.into(),
                plan_digest: plan_digest(bundle, &fresh),
                manifest_device: fresh.manifest_device,
                manifest_inode: fresh.manifest_inode,
            }),
            created_unix_ms: now,
            items: vec![ItemRecord {
                path: NativePath::from_path(bundle),
                device: fresh.device,
                inode: fresh.inode,
                logical_bytes: fresh.logical_bytes,
                // Durable intent: once written, an interruption reads as unknown.
                state: ItemState::Started,
                reason: Some("awaiting_finder_after_administrator_approval".into()),
                destination: None,
                rule_binding: None,
                recovery_evidence: None,
                updated_unix_ms: now,
            }],
        };
        store
            .publish(&record, true)
            .and_then(Publication::require_clean)
            .map_err(|error| {
                format!("journal unavailable; nothing was handed to Finder: {error}")
            })?;
        Ok(DelegatedMove {
            bundle: bundle.to_path_buf(),
            evidence: fresh,
            store,
            report: ExecutionReport {
                record,
                journal_error: None,
            },
        })
    }

    impl DelegatedMove {
        /// Verifies the outcome by observation and records it.
        pub fn finish(mut self, status: DelegateStatus) -> ExecutionReport {
            let present = self.evidence.is_present_at(&self.bundle).ok();
            let destination = if present == Some(false) {
                self.evidence.find_in_user_trash().ok().flatten()
            } else {
                None
            };
            let (state, reason) = classify(present, destination.is_some(), status);
            let item = &mut self.report.record.items[0];
            item.state = state.clone();
            item.reason = Some(reason.into());
            item.destination = (state == ItemState::Succeeded)
                .then(|| destination.as_deref().map(NativePath::from_path))
                .flatten();
            item.updated_unix_ms = journal::now_ms().unwrap_or(item.updated_unix_ms);
            if let Err(error) = self
                .store
                .publish(&self.report.record, false)
                .and_then(Publication::require_clean)
            {
                self.report.journal_error = Some(error.to_string());
            }
            self.report
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_is_decided_by_observation() {
        for status in [
            DelegateStatus::Reported,
            DelegateStatus::Cancelled,
            DelegateStatus::Error,
        ] {
            assert_eq!(classify(Some(false), true, status).0, ItemState::Succeeded);
            assert_eq!(classify(Some(true), false, status).0, ItemState::Failed);
            assert_eq!(classify(Some(false), false, status).0, ItemState::Unknown);
            assert_eq!(classify(None, false, status).0, ItemState::Unknown);
            assert_eq!(classify(Some(true), true, status).0, ItemState::Unknown);
        }
        assert_eq!(
            classify(Some(true), false, DelegateStatus::Cancelled).1,
            "cancelled_by_user"
        );
        assert_eq!(DelegateStatus::from_code(3), None);
    }
}
