// SPDX-License-Identifier: MPL-2.0

//! Review-only projection of possible app cache remnants in an explicit Caches scan.

use crate::app_inventory::{AppInventory, StringState};
use crate::model::ResourceKind;
use crate::scan::ScanReport;
use serde::Serialize;
use std::path::{Component, Path};

const MAX_ROWS: usize = 256;

#[derive(Debug, Serialize)]
pub struct OrphanCachePreview {
    pub schema_version: u32,
    pub kind: &'static str,
    pub inventory_complete_in_selected_roots: bool,
    pub library_scan_complete: bool,
    pub globally_complete: bool,
    pub effects_performed: bool,
    pub truncated: bool,
    pub inventory_roots: Vec<String>,
    pub library_roots: Vec<String>,
    pub candidates: Vec<OrphanCacheCandidate>,
}

#[derive(Debug, Serialize)]
pub struct OrphanCacheCandidate {
    pub path: String,
    pub bundle_id_hint: String,
    pub disposition: &'static str,
    pub matching_app_count: usize,
    pub matching_app_paths: Vec<String>,
    pub evidence: Vec<&'static str>,
    pub uncertainty: Vec<&'static str>,
    pub selected: bool,
    pub authorized_action: Option<&'static str>,
}

/// No result authorizes deletion. An inventory marked complete covers only its
/// explicit roots; an app copy elsewhere can still own the cache.
pub fn project_orphan_caches(
    inventory: &AppInventory,
    library_scan: &ScanReport,
) -> OrphanCachePreview {
    let mut candidates = Vec::new();
    let mut truncated = false;
    for entry in &library_scan.entries {
        if entry.kind != ResourceKind::Directory || entry.dataless {
            continue;
        }
        let Some((root, bundle_id)) = library_scan
            .roots
            .iter()
            .find_map(|root| cache_bundle_id(&entry.path, root).map(|id| (root, id)))
        else {
            continue;
        };
        if candidates.len() == MAX_ROWS || entry.path.as_os_str().len() > 1024 {
            truncated = true;
            if candidates.len() == MAX_ROWS {
                break;
            }
            continue;
        }
        let matching_app_count = inventory
            .apps
            .iter()
            .filter(|app| {
                app.bundle_id.state == StringState::Present
                    && app.bundle_id.value.as_deref() == Some(bundle_id)
            })
            .count();
        let matching_app_paths = inventory
            .apps
            .iter()
            .filter_map(|app| {
                (app.bundle_id.state == StringState::Present
                    && app.bundle_id.value.as_deref() == Some(bundle_id)
                    && app.bundle_path.as_os_str().len() <= 1024)
                    .then(|| app.bundle_path.display().to_string())
            })
            .take(8)
            .collect::<Vec<_>>();
        let protected_family =
            bundle_id.starts_with("group.") || bundle_id.starts_with("com.apple.");
        let disposition = if protected_family {
            "protected_shared_or_system"
        } else if matching_app_count == 0 {
            "possible_orphan_review_only"
        } else {
            "installed_app_observed"
        };
        let mut uncertainty = vec!["app_inventory_covers_explicit_roots_only"];
        if !inventory.complete {
            uncertainty.push("app_inventory_incomplete");
        }
        if !library_scan.complete {
            uncertainty.push("library_scan_incomplete");
        }
        if protected_family {
            uncertainty.push("shared_or_system_identifier");
        }
        if matching_app_count > matching_app_paths.len() {
            uncertainty.push("matching_app_paths_truncated");
        }
        candidates.push(OrphanCacheCandidate {
            path: root.join(bundle_id).display().to_string(),
            bundle_id_hint: bundle_id.to_string(),
            disposition,
            matching_app_count,
            matching_app_paths,
            evidence: vec![
                "exact_cache_directory_name",
                "observed_app_bundle_identifiers",
            ],
            uncertainty,
            selected: false,
            authorized_action: None,
        });
    }
    candidates.sort_by(|a, b| a.path.cmp(&b.path));
    OrphanCachePreview {
        schema_version: 1,
        kind: "orphan_app_cache_preview",
        inventory_complete_in_selected_roots: inventory.complete,
        library_scan_complete: library_scan.complete,
        globally_complete: false,
        effects_performed: false,
        truncated,
        inventory_roots: inventory
            .roots
            .iter()
            .map(|p| p.display().to_string())
            .collect(),
        library_roots: library_scan
            .roots
            .iter()
            .map(|p| p.display().to_string())
            .collect(),
        candidates,
    }
}

fn cache_bundle_id<'a>(path: &'a Path, root: &Path) -> Option<&'a str> {
    if root.file_name()? != "Caches" || root.parent()?.file_name()? != "Library" {
        return None;
    }
    let mut parts = path.strip_prefix(root).ok()?.components();
    let Component::Normal(name) = parts.next()? else {
        return None;
    };
    if parts.next().is_some() {
        return None;
    }
    let bundle_id = name.to_str()?;
    let mut labels = bundle_id.split('.');
    if labels.clone().count() < 3
        || labels.any(|label| {
            label.is_empty()
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return None;
    }
    Some(bundle_id)
}
