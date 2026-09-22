// SPDX-License-Identifier: MPL-2.0

//! Read-only saved-state preview (T10 Class B `saved_state_cleanup`).
//!
//! Enumerates `*.savedState` bundles directly under the fixed per-user
//! `~/Library/Saved Application State` location with per-item eligibility
//! states. It performs no effects: no Trash, no deletion, no signals.
//! Contract: docs/SAVED_STATE_CLEANUP.md.

use crate::model::ResourceKind;
use crate::scan::index::{Metric, ScanTree};
use crate::scan::{ScanIssue, ScanStatus};
use std::io;
use std::path::{Path, PathBuf};

pub use sayaka_platform_macos::saved_state_location as default_location;

/// Running PIDs of the application owning one bundle identifier, via the
/// official unprivileged AppKit query; an error never means "not running".
pub fn running_owner_pids(bundle_id: &str) -> io::Result<Vec<u32>> {
    sayaka_platform_macos::running_pids_with_bundle_identifier(bundle_id)
}
use std::time::{SystemTime, UNIX_EPOCH};

pub const SAVED_STATE_SCHEMA_VERSION: u32 = 1;
pub const SAVED_STATE_KIND: &str = "sayaka.saved_state_preview";
pub const DEFAULT_OLDER_THAN_DAYS: u32 = 30;
pub const MAX_OLDER_THAN_DAYS: u32 = 3650;
/// Bound on listed candidates; overflow is counted, never silently merged.
pub const MAX_LISTED: usize = 256;
const DAY_MS: u128 = 86_400_000;

#[derive(Clone, Copy, Debug)]
pub struct SavedStateOptions {
    pub older_than_days: u32,
}

impl Default for SavedStateOptions {
    fn default() -> Self {
        Self {
            older_than_days: DEFAULT_OLDER_THAN_DAYS,
        }
    }
}

impl SavedStateOptions {
    pub fn validate(self) -> Result<(), String> {
        if (1..=MAX_OLDER_THAN_DAYS).contains(&self.older_than_days) {
            Ok(())
        } else {
            Err(format!(
                "older-than days must be in 1..={MAX_OLDER_THAN_DAYS}, got {}",
                self.older_than_days
            ))
        }
    }
}

/// Per-item preview state; only `Eligible` items are ever selectable by a
/// future execution slice. Unknowns fail closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SavedStateEligibility {
    Eligible,
    TooRecent,
    Running,
    NotAttributable,
    Unknown,
}

impl SavedStateEligibility {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Eligible => "eligible",
            Self::TooRecent => "too_recent",
            Self::Running => "running",
            Self::NotAttributable => "not_attributable",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug)]
pub struct SavedStateCandidate {
    pub name: String,
    /// Derived from the directory naming convention; never proof of
    /// installed-app or team identity (contract disclosure).
    pub bundle_id: Option<String>,
    pub eligibility: SavedStateEligibility,
    pub reason: Option<&'static str>,
    pub running_pids: Option<Vec<u32>>,
    pub logical_bytes: Option<u64>,
    pub allocated_bytes: Option<u64>,
    pub complete: bool,
    /// Observed directory mtime; an observation, not proof of disuse.
    pub modified_unix_ms: Option<i64>,
    pub age_days: Option<u64>,
}

#[derive(Clone, Debug, Default)]
pub struct SavedStateCounts {
    pub eligible: usize,
    pub too_recent: usize,
    pub running: usize,
    pub not_attributable: usize,
    pub unknown: usize,
    /// Direct children whose names do not end `.savedState`; invisible.
    pub ignored: usize,
    pub listed_omitted: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SavedStateStatus {
    Complete,
    Partial,
    /// The fixed location does not exist or holds no candidates; a
    /// distinct state, never an error disguised as success.
    Unnecessary,
    Cancelled,
    Failed,
}

impl SavedStateStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::Unnecessary => "unnecessary",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Debug)]
pub struct SavedStatePreview {
    pub schema_version: u32,
    pub kind: &'static str,
    pub platform: &'static str,
    pub status: SavedStateStatus,
    pub complete: bool,
    pub effects_performed: bool,
    pub location: PathBuf,
    pub effective_cutoff_days: u32,
    /// The computed cutoff moment; an adjustable day value never hides the
    /// fixed rule it replaced.
    pub cutoff_unix_ms: Option<i64>,
    pub candidates: Vec<SavedStateCandidate>,
    pub counts: SavedStateCounts,
    pub scan_issues: Vec<ScanIssue>,
    pub scan_issues_omitted: usize,
}

/// The bundle-identifier prefix of a `.savedState` directory name, when the
/// name follows the reverse-DNS naming convention. Anything else is not a
/// candidate identifier (never guessed).
pub fn bundle_id_from_name(name: &str) -> Option<&str> {
    let prefix = name.strip_suffix(".savedState")?;
    if valid_bundle_id_shape(prefix) {
        Some(prefix)
    } else {
        None
    }
}

fn valid_bundle_id_shape(id: &str) -> bool {
    let mut labels = 0usize;
    for label in id.split('.') {
        labels += 1;
        if label.is_empty()
            || label.len() > 63
            || !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return false;
        }
    }
    labels >= 2
}

/// Builds the read-only saved-state preview from one finished scan of the
/// fixed location. `now` and `running` are injected so eligibility is
/// deterministic in fixtures; `running` must fail closed on any query
/// problem (the caller maps the error to `not_attributable`).
pub fn saved_state_preview(
    index: &ScanTree,
    location: &Path,
    options: &SavedStateOptions,
    now: SystemTime,
    running: &mut dyn FnMut(&str) -> io::Result<Vec<u32>>,
) -> Result<SavedStatePreview, String> {
    options.validate()?;
    let now_ms = now
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    let cutoff_unix_ms =
        i64::try_from(now_ms.saturating_sub(u128::from(options.older_than_days) * DAY_MS)).ok();
    let mut candidates = Vec::new();
    let mut counts = SavedStateCounts::default();
    for &root in index.roots() {
        let Some(children) = index.children(root) else {
            continue;
        };
        for &child in children {
            let Some(entry) = index.entry(child) else {
                continue;
            };
            let Some(name) = entry.path.file_name().and_then(|name| name.to_str()) else {
                counts.ignored += 1;
                continue;
            };
            if !name.ends_with(".savedState") {
                counts.ignored += 1;
                continue;
            }
            if candidates.len() >= MAX_LISTED {
                counts.listed_omitted += 1;
                continue;
            }
            let modified_unix_ms = mtime_unix_ms(&entry.path);
            let (eligibility, mut reason, bundle_id, running_pids) = classify(
                entry,
                name,
                modified_unix_ms,
                now_ms,
                options.older_than_days,
                running,
            );
            if eligibility == SavedStateEligibility::Unknown && reason.is_none() {
                reason = Some("observation incomplete");
            }
            match eligibility {
                SavedStateEligibility::Eligible => counts.eligible += 1,
                SavedStateEligibility::TooRecent => counts.too_recent += 1,
                SavedStateEligibility::Running => counts.running += 1,
                SavedStateEligibility::NotAttributable => counts.not_attributable += 1,
                SavedStateEligibility::Unknown => counts.unknown += 1,
            }
            candidates.push(SavedStateCandidate {
                name: name.to_string(),
                bundle_id,
                eligibility,
                reason,
                running_pids,
                logical_bytes: index.size(child, Metric::Logical),
                allocated_bytes: index.size(child, Metric::Allocated),
                complete: index.summary(child).is_some_and(|summary| summary.complete),
                modified_unix_ms,
                age_days: age_days_ms(modified_unix_ms, now_ms),
            });
        }
    }
    candidates.sort_by(|left, right| left.name.cmp(&right.name));
    let report = index.report();
    let mut status = match report.status {
        ScanStatus::Complete => SavedStateStatus::Complete,
        ScanStatus::Partial => SavedStateStatus::Partial,
        ScanStatus::Cancelled => SavedStateStatus::Cancelled,
        ScanStatus::Failed => SavedStateStatus::Failed,
    };
    if status == SavedStateStatus::Complete && counts.eligible == 0 {
        // Nothing selectable is a distinct, honest state — not an error,
        // not a claim that the location was empty.
        status = SavedStateStatus::Unnecessary;
    }
    let _ = location;
    Ok(SavedStatePreview {
        schema_version: SAVED_STATE_SCHEMA_VERSION,
        kind: SAVED_STATE_KIND,
        platform: if cfg!(target_os = "macos") {
            "macos"
        } else {
            "unsupported"
        },
        status,
        complete: matches!(
            status,
            SavedStateStatus::Complete | SavedStateStatus::Unnecessary
        ),
        effects_performed: false,
        location: location.to_path_buf(),
        effective_cutoff_days: options.older_than_days,
        cutoff_unix_ms,
        candidates,
        counts,
        scan_issues: report.issues.clone(),
        scan_issues_omitted: report.issues_omitted,
    })
}

/// The directory mtime from a no-follow metadata read; an observation,
/// not proof of disuse. Unavailable stays unavailable.
fn mtime_unix_ms(path: &Path) -> Option<i64> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    let modified = metadata.modified().ok()?;
    let duration = modified.duration_since(UNIX_EPOCH).ok()?;
    i64::try_from(duration.as_millis()).ok()
}

fn age_days_ms(modified_unix_ms: Option<i64>, now_ms: u128) -> Option<u64> {
    let mtime_ms = u128::try_from(modified_unix_ms?).ok()?;
    u64::try_from(now_ms.saturating_sub(mtime_ms) / DAY_MS).ok()
}

/// Classifies one `.savedState` direct child. Order: malformed shape →
/// running observation → age. Every unclear state fails closed.
fn classify(
    entry: &crate::scan::ScanEntry,
    name: &str,
    modified_unix_ms: Option<i64>,
    now_ms: u128,
    older_than_days: u32,
    running: &mut dyn FnMut(&str) -> io::Result<Vec<u32>>,
) -> (
    SavedStateEligibility,
    Option<&'static str>,
    Option<String>,
    Option<Vec<u32>>,
) {
    if entry.dataless {
        return (
            SavedStateEligibility::NotAttributable,
            Some("cloud placeholder; never hydrated"),
            None,
            None,
        );
    }
    if entry.kind == ResourceKind::Link {
        return (
            SavedStateEligibility::NotAttributable,
            Some("link; never followed"),
            None,
            None,
        );
    }
    if entry.kind != ResourceKind::Directory {
        return (
            SavedStateEligibility::NotAttributable,
            Some("not a directory"),
            None,
            None,
        );
    }
    let Some(bundle_id) = bundle_id_from_name(name) else {
        return (
            SavedStateEligibility::NotAttributable,
            Some("directory name carries no bundle identifier"),
            None,
            None,
        );
    };
    let bundle_id = bundle_id.to_string();
    let pids = match running(&bundle_id) {
        Ok(pids) => pids,
        Err(_) => {
            return (
                SavedStateEligibility::NotAttributable,
                Some("running observation unavailable"),
                Some(bundle_id),
                None,
            );
        }
    };
    if !pids.is_empty() {
        return (
            SavedStateEligibility::Running,
            None,
            Some(bundle_id),
            Some(pids),
        );
    }
    let Some(age) = age_days_ms(modified_unix_ms, now_ms) else {
        return (
            SavedStateEligibility::Unknown,
            Some("modification time unavailable"),
            Some(bundle_id),
            None,
        );
    };
    if age >= u64::from(older_than_days) {
        (SavedStateEligibility::Eligible, None, Some(bundle_id), None)
    } else {
        (
            SavedStateEligibility::TooRecent,
            None,
            Some(bundle_id),
            None,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_id_shape_follows_the_naming_convention() {
        assert_eq!(
            bundle_id_from_name("com.example.demo.savedState"),
            Some("com.example.demo")
        );
        assert_eq!(
            bundle_id_from_name("dev.team-app.more.savedState"),
            Some("dev.team-app.more")
        );
        assert_eq!(bundle_id_from_name("plain.savedState"), None);
        assert_eq!(bundle_id_from_name(".savedState"), None);
        assert_eq!(bundle_id_from_name("has space.app.savedState"), None);
        assert_eq!(bundle_id_from_name("com.example.app"), None);
        assert_eq!(bundle_id_from_name("trailing..savedState"), None);
    }
}
