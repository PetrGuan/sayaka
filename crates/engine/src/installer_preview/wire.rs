// SPDX-License-Identifier: MPL-2.0

//! Shared installer observation JSON. Private inspection witnesses and executable
//! plans are never serialized.

use super::*;
use serde_json::{Value, json};

pub fn family(value: FormatFamily) -> &'static str {
    match value {
        FormatFamily::UdifDmg => "udif_dmg",
        FormatFamily::FlatPkgXar => "flat_pkg_xar",
        FormatFamily::Xar => "xar",
        FormatFamily::Unknown => "unknown",
    }
}

pub fn status(value: FormatStatus) -> &'static str {
    match value {
        FormatStatus::Recognized => "recognized",
        FormatStatus::Unsupported => "unsupported",
        FormatStatus::Corrupt => "corrupt",
        FormatStatus::Changed => "changed",
        FormatStatus::PermissionDenied => "permission_denied",
        FormatStatus::Partial => "partial",
        FormatStatus::Cancelled => "cancelled",
        FormatStatus::Unknown => "unknown",
    }
}

pub fn owner_scope(value: OwnerScope) -> &'static str {
    match value {
        OwnerScope::CurrentUser => "current_user",
        OwnerScope::OtherUser => "other_user",
        OwnerScope::Unknown => "unknown",
    }
}

pub fn native_path(path: &Path) -> Value {
    // This serializer contains only strings and fixed string keys.
    serde_json::to_value(crate::scan::wire::NativePath(path)).expect("native path JSON value")
}

pub fn candidate_json(candidate: &InstallerCandidate) -> Value {
    json!({
        "path": native_path(&candidate.path),
        "identity": candidate.identity,
        "owner_scope": owner_scope(candidate.owner_scope),
        "logical_bytes": candidate.logical_bytes,
        "allocated_bytes": candidate.allocated_bytes,
        "counted": candidate.counted,
        "name_kind": match candidate.name_kind { CandidateNameKind::Dmg => "dmg", CandidateNameKind::Pkg => "pkg" },
        "format": {
            "family": family(candidate.format.family),
            "status": status(candidate.format.status),
            "detection_level": candidate.format.detection_level,
            "evidence": candidate.format.evidence,
            "limitations": candidate.format.limitations,
        },
        "provenance": { "where_froms": "not_read", "quarantine": "not_read" },
    })
}

pub fn bytes_json(bytes: &InstallerBytes) -> Value {
    json!({
        "matched_logical_bytes": bytes.matched_logical_bytes,
        "matched_logical_unknown_files": bytes.matched_logical_unknown_files,
        "matched_allocated_bytes": bytes.matched_allocated_bytes,
        "matched_allocated_unknown_files": bytes.matched_allocated_unknown_files,
        "matched_sizes_are_reclaimable": false,
    })
}

pub fn preview_json(preview: &InstallerPreview) -> Value {
    json!({
        "schema_version": INSTALLER_PREVIEW_SCHEMA_VERSION,
        "kind": INSTALLER_KIND,
        "platform": preview.platform,
        "status": preview.status.as_str(),
        "complete": preview.complete,
        "effects_performed": preview.effects_performed,
        "root": native_path(&preview.root),
        "filters": {
            "text": preview.filter,
            "excludes": preview.excludes.iter().map(|path| native_path(path)).collect::<Vec<_>>(),
        },
        "scan_task_id": preview.scan_task_id,
        "counts": {
            "scan_entries": preview.counts.scan_entries,
            "named_candidates": preview.counts.named_candidates,
            "inspected_candidates": preview.counts.inspected_candidates,
            "recognized": preview.counts.recognized,
            "unsupported": preview.counts.unsupported,
            "corrupt": preview.counts.corrupt,
            "changed": preview.counts.changed,
            "permission_denied": preview.counts.permission_denied,
            "aliases": preview.counts.aliases,
            "scan_issues": preview.counts.scan_issues,
            "probe_issues": preview.counts.probe_issues,
        },
        "bytes": bytes_json(&preview.bytes),
        "candidates": preview.candidates.iter().map(candidate_json).collect::<Vec<_>>(),
        "scan_issues": preview.scan_issues.iter().map(|issue| json!({
            "path": issue.path.as_deref().map(native_path),
            "code": issue.code.as_str(),
            "message": issue.message,
            "os_code": issue.os_code,
        })).collect::<Vec<_>>(),
        "issues": preview.issues.iter().map(|issue| json!({
            "path": issue.path.as_deref().map(native_path),
            "code": issue.code.as_str(),
            "message": issue.message,
            "os_code": issue.os_code,
        })).collect::<Vec<_>>(),
        "issues_omitted": preview.issues_omitted,
        "metrics": {
            "elapsed_ms": preview.metrics.elapsed_ms,
            "probe_elapsed_ms": preview.metrics.probe_elapsed_ms,
            "candidate_io_bytes": preview.metrics.candidate_io_bytes,
            "expanded_bytes": preview.metrics.expanded_bytes,
            "retained_xml_name_bytes": preview.metrics.retained_name_bytes,
        },
    })
}

pub fn selection_json(preview: &InstallerSelectionPreview) -> Value {
    json!({
        "schema_version": 1,
        "kind": "installer_selection_preview",
        "scan_task_id": preview.scan_task_id,
        "status": preview.status,
        "batch_checks_passed": preview.status == SelectionCheckStatus::Checked,
        "effects_performed": false,
        "execution_authority": false,
        "snapshot_only": true,
        "measurement_source": "discovery",
        "selected": preview.selected.iter().map(|item| json!({
            "candidate_id": item.candidate_id.to_string(),
            "path": native_path(&item.path),
            "logical_bytes": item.logical_bytes,
            "allocated_bytes": item.allocated_bytes,
        })).collect::<Vec<_>>(),
        "bytes": bytes_json(&preview.bytes),
        "issues": preview.issues.iter().map(|issue| json!({
            "candidate_id": issue.candidate_id.map(|id| id.to_string()),
            "code": issue.code,
            "message": issue.message,
        })).collect::<Vec<_>>(),
    })
}
