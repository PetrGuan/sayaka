// SPDX-License-Identifier: MPL-2.0

//! Read-only macOS app-related data attribution preview.

use crate::app_inventory::{
    AppInventory, AppInventoryStatus, AppIssue, AppKind, AppRecord, PathStatus, StringState,
};
use crate::model::{Cancellation, FileIdentity, valid_absolute_path};
use crate::scan::{ScanError, ScanIssue};
use std::collections::{BTreeMap, BTreeSet};
#[cfg(target_os = "macos")]
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

pub const APP_RELATED_KIND: &str = "app_related_data_preview";
pub const APP_RELATED_SCHEMA_VERSION: u32 = 1;
pub const APP_RELATED_PROBE_BUDGET_CAP: Duration = Duration::from_secs(5);

const MAX_LIBRARY_ROOTS: usize = 8;
const MAX_APP_ROOTS: usize = 64;
const MAX_GENERIC_APP_COPIES: usize = 32;
const MAX_CANDIDATES: usize = 256;
const MAX_ISSUES: usize = 256;
const MAX_PATH_BYTES: usize = 1024 * 1024;

const APPLE_FS_URL: &str = "https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/MacOSXDirectories/MacOSXDirectories.html";
const CHROMIUM_URL: &str =
    "https://chromium.googlesource.com/chromium/src/+/HEAD/docs/user_data_dir.md";
const MOZILLA_URL: &str = "https://firefox-source-docs.mozilla.org/toolkit/profile/index.html";
const APPLE_BUNDLE_URL: &str = "https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/BundleTypes/BundleTypes.html";

const CHROMIUM_DIR_ALLOWLIST: &[&str] = &[
    "Google/Chrome",
    "Google/Chrome Beta",
    "Google/Chrome Dev",
    "Google/Chrome Canary",
    "Google/Chrome for Testing",
    "Chromium",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppRelatedStatus {
    Complete,
    Partial,
    Cancelled,
    Failed,
}

impl AppRelatedStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
        }
    }

    pub const fn exit_code(self) -> u8 {
        match self {
            Self::Complete => 0,
            Self::Partial => 3,
            Self::Cancelled => 130,
            Self::Failed => 1,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AppRelatedIssue {
    pub path: Option<PathBuf>,
    pub code: &'static str,
    pub message: String,
    pub os_code: Option<i32>,
}

#[derive(Clone, Debug, Default)]
pub struct AppRelatedCounts {
    pub inventoried_apps: usize,
    pub matched_app_copies: usize,
    pub candidate_paths: usize,
    pub present_candidates: usize,
    pub missing_candidates: usize,
    pub shared_candidates: usize,
    pub protected_candidates: usize,
    pub issues: usize,
    pub issues_omitted: usize,
}

#[derive(Clone, Debug, Default)]
pub struct AppRelatedMetrics {
    pub elapsed_ms: u64,
    pub inventory_elapsed_ms: u64,
    pub candidate_probe_elapsed_ms: u64,
    pub candidate_probe_count: usize,
}

#[derive(Clone, Debug)]
pub struct AppCopySummary {
    pub app_copy_id: String,
    pub bundle_path: PathBuf,
    pub observed_roots: Vec<PathBuf>,
    pub bundle_identity: FileIdentity,
    pub display_name: String,
    pub bundle_id: Option<String>,
    pub short_version: Option<String>,
    pub build_version: Option<String>,
    pub executable_path_status: &'static str,
    pub match_rules: Vec<&'static str>,
    pub copy_state: &'static str,
}

#[derive(Clone, Debug)]
pub struct RelatedEvidence {
    pub kind: &'static str,
    pub value: String,
    pub app_copy_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct RelatedDataCandidate {
    pub candidate_id: String,
    pub path: PathBuf,
    pub relative_library_path: String,
    pub source_rule_id: &'static str,
    pub source_urls: Vec<&'static str>,
    pub role: &'static str,
    pub path_state: &'static str,
    pub ownership_certainty: &'static str,
    pub ownership_statement: String,
    pub evidence: Vec<RelatedEvidence>,
    pub matched_app_copy_ids: Vec<String>,
    pub protection_reasons: Vec<&'static str>,
    pub preview_disposition: &'static str,
    pub deletable: bool,
    pub authorized_action: Option<&'static str>,
}

#[derive(Clone, Debug)]
pub struct AppRelatedPreview {
    pub schema_version: u32,
    pub kind: &'static str,
    pub platform: &'static str,
    pub status: AppRelatedStatus,
    pub complete: bool,
    pub effects_performed: bool,
    pub app_roots: Vec<PathBuf>,
    pub library_roots: Vec<PathBuf>,
    pub filter: String,
    pub scan_task_id: Option<String>,
    pub inventory_status: &'static str,
    pub inventory_complete: bool,
    pub counts: AppRelatedCounts,
    pub app_copies: Vec<AppCopySummary>,
    pub candidates: Vec<RelatedDataCandidate>,
    pub scan_issues: Vec<ScanIssue>,
    pub issues: Vec<AppRelatedIssue>,
    pub metrics: AppRelatedMetrics,
}

pub fn preview_app_related_data(
    inventory: AppInventory,
    app_roots: Vec<PathBuf>,
    library_roots: Vec<PathBuf>,
    filter: String,
    cancellation: &Cancellation,
    probe_budget: Duration,
) -> AppRelatedPreview {
    let started = Instant::now();
    let platform = if cfg!(target_os = "macos") {
        "macos"
    } else {
        "unsupported"
    };
    let inventory_status = inventory.status.as_str();
    let mut preview = AppRelatedPreview {
        schema_version: APP_RELATED_SCHEMA_VERSION,
        kind: APP_RELATED_KIND,
        platform,
        status: map_inventory_status(inventory.status),
        complete: matches!(inventory.status, AppInventoryStatus::Complete),
        effects_performed: false,
        app_roots,
        library_roots: library_roots.clone(),
        filter: filter.clone(),
        scan_task_id: Some(inventory.scan_task_id.clone()),
        inventory_status,
        inventory_complete: inventory.complete,
        counts: AppRelatedCounts {
            inventoried_apps: inventory.apps.len(),
            ..AppRelatedCounts::default()
        },
        app_copies: Vec::new(),
        candidates: Vec::new(),
        scan_issues: inventory.scan_issues.clone(),
        issues: Vec::new(),
        metrics: AppRelatedMetrics {
            inventory_elapsed_ms: inventory.metrics.elapsed_ms,
            ..AppRelatedMetrics::default()
        },
    };
    preview.counts.issues_omitted = inventory.issues_omitted;
    merge_inventory_issues(&mut preview, &inventory.issues);

    if !cfg!(target_os = "macos") {
        update_status(&mut preview, AppRelatedStatus::Failed);
        push_issue(
            &mut preview,
            None,
            "unsupported_platform",
            "native app-related probing is unavailable on this platform",
            None,
        );
        finalize_metrics(&mut preview, started, Instant::now());
        return preview;
    }

    if matches!(
        inventory.status,
        AppInventoryStatus::Failed | AppInventoryStatus::Cancelled
    ) {
        push_issue(
            &mut preview,
            None,
            if inventory.status == AppInventoryStatus::Cancelled {
                "cancelled"
            } else {
                "inventory_failed"
            },
            "app inventory did not complete; related-data attribution is unavailable",
            None,
        );
        preview.complete = false;
        finalize_metrics(&mut preview, started, Instant::now());
        return preview;
    }

    if let Err(message) = validate_root_inputs(&preview.app_roots, &library_roots) {
        update_status(&mut preview, AppRelatedStatus::Failed);
        push_issue(&mut preview, None, "invalid_input", message, None);
        finalize_metrics(&mut preview, started, Instant::now());
        return preview;
    }

    let filter_lower = filter.to_ascii_lowercase();
    let probe_started = Instant::now();
    let probe_deadline = probe_started + probe_budget.min(APP_RELATED_PROBE_BUDGET_CAP);
    let prepared_roots =
        prepare_library_roots(library_roots, &mut preview, cancellation, probe_deadline);
    let copy_views = copy_views(&inventory.apps, &inventory.scan_task_id, inventory.complete);
    let rule_matches = rule_matches(&copy_views);
    let filtered_copy_ids = filtered_copy_ids(&copy_views, &filter_lower);
    let generic_copies = rule_matches
        .generic
        .iter()
        .take(MAX_GENERIC_APP_COPIES)
        .copied()
        .collect::<Vec<_>>();
    if rule_matches.generic.len() > MAX_GENERIC_APP_COPIES {
        if !cancellation.is_cancelled() {
            update_status(&mut preview, AppRelatedStatus::Partial);
        }
        push_issue(
            &mut preview,
            None,
            "candidate_limit",
            "generic bundle-id convention app budget reached",
            None,
        );
    }
    let mut path_bytes = 0usize;
    let mut specs = BTreeMap::<(PathBuf, &'static str, String), CandidateSpec>::new();

    for (root_index, root) in prepared_roots.iter().enumerate() {
        if cancellation.is_cancelled() {
            update_status(&mut preview, AppRelatedStatus::Cancelled);
            push_issue(
                &mut preview,
                None,
                "cancelled",
                "app-related probe cancelled",
                None,
            );
            break;
        }
        if Instant::now() >= probe_deadline {
            update_status(&mut preview, AppRelatedStatus::Partial);
            push_issue(
                &mut preview,
                None,
                "duration_limit",
                "app-related probe budget exhausted",
                None,
            );
            break;
        }

        for copy in rule_matches.chromium.iter().copied() {
            let Some(dir) = copy.app.declared_product_dir_name.value.as_deref() else {
                continue;
            };
            if !CHROMIUM_DIR_ALLOWLIST.contains(&dir) {
                continue;
            }
            for (suffix, rule, role) in [
                (
                    format!("Application Support/{dir}"),
                    "org.chromium.default_user_data.macos.v1",
                    "persistent_support_or_profile",
                ),
                (
                    format!("Caches/{dir}"),
                    "org.chromium.default_cache.macos.v1",
                    "cache",
                ),
            ] {
                maybe_add_spec(
                    &mut preview,
                    &mut specs,
                    &mut path_bytes,
                    &copy.app_copy_id,
                    CandidateSpecInput {
                        library_root_index: root_index,
                        path: root.path.join(&suffix),
                        relative_library_path: suffix,
                        source_rule_id: rule,
                        role,
                        ownership_certainty: "app_declared_default_location",
                        evidence: vec![
                            RelatedEvidence {
                                kind: "physical_app_copy_observed",
                                value: copy.app.bundle_path.display().to_string(),
                                app_copy_id: Some(copy.app_copy_id.clone()),
                            },
                            RelatedEvidence {
                                kind: "declared_info_plist_key",
                                value: format!("CrProductDirName={dir}"),
                                app_copy_id: Some(copy.app_copy_id.clone()),
                            },
                            RelatedEvidence {
                                kind: "public_documentation",
                                value: CHROMIUM_URL.to_string(),
                                app_copy_id: None,
                            },
                        ],
                        protection_reasons: vec![
                            "persistent_user_profile_or_support_data",
                            "may_contain_credentials_history_or_preferences",
                            "ownership_not_proven",
                            "running_state_not_checked",
                            "no_uninstall_or_delete_contract",
                        ],
                    },
                );
            }
        }

        if !rule_matches.firefox.is_empty() {
            for (suffix, rule, role) in [
                (
                    "Application Support/Firefox/Profiles".to_string(),
                    "org.mozilla.firefox.default_profiles.macos.v1",
                    "persistent_support_or_profile",
                ),
                (
                    "Caches/Firefox/Profiles".to_string(),
                    "org.mozilla.firefox.default_profile_caches.macos.v1",
                    "cache",
                ),
                (
                    "Application Support/Firefox/ProfileGroups".to_string(),
                    "org.mozilla.firefox.profile_groups.macos.v1",
                    "shared_profile_group",
                ),
            ] {
                let mut evidence = vec![RelatedEvidence {
                    kind: "public_documentation",
                    value: MOZILLA_URL.to_string(),
                    app_copy_id: None,
                }];
                for copy in rule_matches.firefox.iter().copied() {
                    evidence.push(RelatedEvidence {
                        kind: "physical_app_copy_observed",
                        value: copy.app.bundle_path.display().to_string(),
                        app_copy_id: Some(copy.app_copy_id.clone()),
                    });
                }
                maybe_add_spec(
                    &mut preview,
                    &mut specs,
                    &mut path_bytes,
                    "firefox-family",
                    CandidateSpecInput {
                        library_root_index: root_index,
                        path: root.path.join(&suffix),
                        relative_library_path: suffix,
                        source_rule_id: rule,
                        role,
                        ownership_certainty: "public_default_shared_profile_family",
                        evidence,
                        protection_reasons: vec![
                            "persistent_user_profile_or_support_data",
                            "may_contain_credentials_history_or_preferences",
                            "shared_across_profiles_or_app_copies",
                            "ownership_not_proven",
                            "running_state_not_checked",
                            "no_uninstall_or_delete_contract",
                        ],
                    },
                );
                if let Some(spec) = specs.get_mut(&(
                    root.path.join("Application Support/Firefox/Profiles"),
                    "org.mozilla.firefox.default_profiles.macos.v1",
                    "Application Support/Firefox/Profiles".to_string(),
                )) {
                    for copy in rule_matches.firefox.iter().copied() {
                        spec.matched_app_copy_ids.insert(copy.app_copy_id.clone());
                    }
                }
            }
            for rule in [
                "org.mozilla.firefox.default_profiles.macos.v1",
                "org.mozilla.firefox.default_profile_caches.macos.v1",
                "org.mozilla.firefox.profile_groups.macos.v1",
            ] {
                for spec in specs
                    .values_mut()
                    .filter(|spec| spec.source_rule_id == rule)
                {
                    for copy in rule_matches.firefox.iter().copied() {
                        spec.matched_app_copy_ids.insert(copy.app_copy_id.clone());
                    }
                }
            }
        }

        for copy in generic_copies.iter().copied() {
            let Some(bundle_id) = copy.app.bundle_id.value.as_deref() else {
                continue;
            };
            if !valid_bundle_id_component_path(bundle_id) {
                update_status(&mut preview, AppRelatedStatus::Partial);
                push_issue(
                    &mut preview,
                    Some(copy.app.bundle_path.clone()),
                    "invalid_bundle_id_component",
                    "bundle identifier is unsafe for path construction",
                    None,
                );
                continue;
            }
            for (prefix, rule, role, reason) in [
                (
                    "Application Support",
                    "org.apple.library.application_support.bundle_id_convention.v1",
                    "persistent_support_or_profile",
                    "persistent_user_profile_or_support_data",
                ),
                (
                    "Caches",
                    "org.apple.library.caches.bundle_id_convention.v1",
                    "cache",
                    "cache_but_not_authorized_for_cleanup",
                ),
            ] {
                let suffix = format!("{prefix}/{bundle_id}");
                maybe_add_spec(
                    &mut preview,
                    &mut specs,
                    &mut path_bytes,
                    &copy.app_copy_id,
                    CandidateSpecInput {
                        library_root_index: root_index,
                        path: root.path.join(&suffix),
                        relative_library_path: suffix,
                        source_rule_id: rule,
                        role,
                        ownership_certainty: "location_standard_hypothesis",
                        evidence: vec![
                            RelatedEvidence {
                                kind: "physical_app_copy_observed",
                                value: copy.app.bundle_path.display().to_string(),
                                app_copy_id: Some(copy.app_copy_id.clone()),
                            },
                            RelatedEvidence {
                                kind: "public_documentation",
                                value: APPLE_FS_URL.to_string(),
                                app_copy_id: None,
                            },
                            RelatedEvidence {
                                kind: "public_documentation",
                                value: APPLE_BUNDLE_URL.to_string(),
                                app_copy_id: None,
                            },
                        ],
                        protection_reasons: vec![
                            reason,
                            "ownership_not_proven",
                            "running_state_not_checked",
                            "no_uninstall_or_delete_contract",
                        ],
                    },
                );
            }
        }
    }

    let mut kept_specs = Vec::new();
    for (_, spec) in specs {
        if kept_specs.len() >= MAX_CANDIDATES {
            update_status(&mut preview, AppRelatedStatus::Partial);
            push_issue(
                &mut preview,
                None,
                "candidate_limit",
                "candidate limit reached",
                None,
            );
            break;
        }
        kept_specs.push(spec);
    }

    let mut generated_candidates = Vec::with_capacity(kept_specs.len());
    for (index, spec) in kept_specs.iter().enumerate() {
        let root = prepared_roots
            .get(spec.library_root_index)
            .expect("prepared library root index");
        let (state, issue) = probe_candidate_path(
            root,
            &spec.path,
            &spec.relative_library_path,
            cancellation,
            probe_deadline,
        );
        preview.metrics.candidate_probe_count += 1;
        if let Some(issue) = issue {
            let next = match issue.code {
                "cancelled" => AppRelatedStatus::Cancelled,
                "invalid_input" => AppRelatedStatus::Failed,
                _ => AppRelatedStatus::Partial,
            };
            update_status(&mut preview, next);
            push_issue(
                &mut preview,
                issue.path,
                issue.code,
                issue.message,
                issue.os_code,
            );
        }
        let mut reasons = spec.protection_reasons.clone();
        if spec.matched_app_copy_ids.len() > 1 {
            reasons.push("multiple_physical_app_copies");
        }
        if !preview.inventory_complete {
            reasons.push("inventory_or_probe_partial");
        }
        reasons.sort_unstable();
        reasons.dedup();
        let candidate = RelatedDataCandidate {
            candidate_id: format!("{}:{}", spec.source_rule_id, index + 1),
            path: spec.path.clone(),
            relative_library_path: spec.relative_library_path.clone(),
            source_rule_id: spec.source_rule_id,
            source_urls: source_urls(spec.source_rule_id),
            role: spec.role,
            path_state: state,
            ownership_certainty: if preview.inventory_complete {
                spec.ownership_certainty
            } else {
                "unattributed_due_to_partial_inventory"
            },
            ownership_statement: ownership_statement(
                spec.source_rule_id,
                spec.ownership_certainty,
                &spec.relative_library_path,
            ),
            evidence: spec.evidence.clone(),
            matched_app_copy_ids: spec.matched_app_copy_ids.iter().cloned().collect(),
            protection_reasons: reasons,
            preview_disposition: "protect_for_manual_review",
            deletable: false,
            authorized_action: None,
        };
        match state {
            "present_directory" | "present_file" | "present_other" => {
                preview.counts.present_candidates += 1
            }
            "missing" => preview.counts.missing_candidates += 1,
            _ => {}
        }
        generated_candidates.push(candidate);
    }

    let display_candidates = generated_candidates
        .into_iter()
        .filter(|candidate| candidate_matches_filter(candidate, &filter_lower, &filtered_copy_ids))
        .collect::<Vec<_>>();

    preview.candidates = display_candidates;
    preview.counts.candidate_paths = preview.candidates.len();
    preview.counts.present_candidates = preview
        .candidates
        .iter()
        .filter(|candidate| {
            matches!(
                candidate.path_state,
                "present_directory" | "present_file" | "present_other"
            )
        })
        .count();
    preview.counts.missing_candidates = preview
        .candidates
        .iter()
        .filter(|candidate| candidate.path_state == "missing")
        .count();
    preview.counts.protected_candidates = preview.candidates.len();
    preview.counts.shared_candidates = preview
        .candidates
        .iter()
        .filter(|candidate| candidate.matched_app_copy_ids.len() > 1)
        .count();

    let shown_candidate_ids = preview
        .candidates
        .iter()
        .filter(|candidate| {
            filter_lower.is_empty()
                || candidate
                    .relative_library_path
                    .to_ascii_lowercase()
                    .contains(&filter_lower)
                || candidate
                    .matched_app_copy_ids
                    .iter()
                    .any(|id| filtered_copy_ids.contains(id))
        })
        .flat_map(|candidate| candidate.matched_app_copy_ids.iter().cloned())
        .collect::<BTreeSet<_>>();

    preview.app_copies = copy_views
        .iter()
        .filter(|copy| {
            filter_lower.is_empty()
                || filtered_copy_ids.contains(&copy.app_copy_id)
                || shown_candidate_ids.contains(&copy.app_copy_id)
        })
        .map(|copy| AppCopySummary {
            app_copy_id: copy.app_copy_id.clone(),
            bundle_path: copy.app.bundle_path.clone(),
            observed_roots: copy.app.observed_roots.clone(),
            bundle_identity: copy.app.bundle_identity,
            display_name: copy.app.display_name.clone(),
            bundle_id: copy.app.bundle_id.value.clone(),
            short_version: copy.app.short_version.value.clone(),
            build_version: copy.app.build_version.value.clone(),
            executable_path_status: copy.app.executable.path_status.as_str(),
            match_rules: copy.match_rules.clone(),
            copy_state: copy.copy_state,
        })
        .collect();

    preview.counts.matched_app_copies = preview
        .app_copies
        .iter()
        .filter(|copy| !copy.match_rules.is_empty())
        .count();

    preview.counts.issues = preview.issues.len();
    preview.complete = matches!(preview.status, AppRelatedStatus::Complete);
    finalize_metrics(&mut preview, started, probe_started);
    preview
}

fn candidate_matches_filter(
    candidate: &RelatedDataCandidate,
    filter_lower: &str,
    filtered_copy_ids: &BTreeSet<String>,
) -> bool {
    if filter_lower.is_empty() {
        return true;
    }
    candidate
        .relative_library_path
        .to_ascii_lowercase()
        .contains(filter_lower)
        || candidate
            .matched_app_copy_ids
            .iter()
            .any(|id| filtered_copy_ids.contains(id))
}

#[derive(Clone)]
struct CopyView<'a> {
    app_copy_id: String,
    app: &'a AppRecord,
    match_rules: Vec<&'static str>,
    copy_state: &'static str,
}

fn copy_views<'a>(
    apps: &'a [AppRecord],
    scan_task_id: &str,
    inventory_complete: bool,
) -> Vec<CopyView<'a>> {
    let mut by_declared = BTreeMap::<String, usize>::new();
    for app in apps {
        if let Some(dir) = app.declared_product_dir_name.value.as_deref()
            && CHROMIUM_DIR_ALLOWLIST.contains(&dir)
        {
            *by_declared.entry(dir.to_string()).or_default() += 1;
        }
    }
    apps.iter()
        .enumerate()
        .map(|(index, app)| {
            let mut rules = Vec::new();
            if is_chromium(app) {
                rules.push("org.chromium.default_user_data.macos.v1");
                rules.push("org.chromium.default_cache.macos.v1");
            } else if is_firefox(app) {
                rules.push("org.mozilla.firefox.default_profiles.macos.v1");
                rules.push("org.mozilla.firefox.default_profile_caches.macos.v1");
                rules.push("org.mozilla.firefox.profile_groups.macos.v1");
            } else if app.bundle_id.state == StringState::Present {
                rules.push("org.apple.library.application_support.bundle_id_convention.v1");
                rules.push("org.apple.library.caches.bundle_id_convention.v1");
            }
            let state = if !inventory_complete {
                "inventory_partial_unknown"
            } else if !rules.iter().any(|rule| rule.starts_with("org.chromium")) {
                "single_observed_copy"
            } else if app
                .declared_product_dir_name
                .value
                .as_deref()
                .is_some_and(|dir| by_declared.get(dir).copied().unwrap_or(0) > 1)
            {
                "multiple_physical_copies_same_declared_product"
            } else {
                "single_observed_copy"
            };
            CopyView {
                app_copy_id: format!("{scan_task_id}:{index}"),
                app,
                match_rules: rules,
                copy_state: state,
            }
        })
        .collect()
}

struct RuleMatch<'a> {
    chromium: Vec<&'a CopyView<'a>>,
    firefox: Vec<&'a CopyView<'a>>,
    generic: Vec<&'a CopyView<'a>>,
}

fn rule_matches<'a>(copies: &'a [CopyView<'a>]) -> RuleMatch<'a> {
    let mut chromium = Vec::new();
    let mut firefox = Vec::new();
    let mut generic = Vec::new();
    for copy in copies {
        if is_chromium(copy.app) {
            chromium.push(copy);
        } else if is_firefox(copy.app) {
            firefox.push(copy);
        } else if copy.app.bundle_id.state == StringState::Present {
            generic.push(copy);
        }
    }
    generic.sort_by_key(|copy| copy.app.bundle_path.clone());
    RuleMatch {
        chromium,
        firefox,
        generic,
    }
}

fn filtered_copy_ids(copies: &[CopyView<'_>], filter_lower: &str) -> BTreeSet<String> {
    copies
        .iter()
        .filter(|copy| {
            filter_lower.is_empty()
                || copy
                    .app
                    .display_name
                    .to_ascii_lowercase()
                    .contains(filter_lower)
                || copy
                    .app
                    .bundle_path
                    .to_string_lossy()
                    .to_ascii_lowercase()
                    .contains(filter_lower)
                || copy
                    .app
                    .bundle_id
                    .value
                    .as_deref()
                    .is_some_and(|id| id.to_ascii_lowercase().contains(filter_lower))
        })
        .map(|copy| copy.app_copy_id.clone())
        .collect()
}

fn is_chromium(app: &AppRecord) -> bool {
    app.app_kind == AppKind::App
        && app.package_type.value.as_deref() == Some("APPL")
        && !matches!(app.executable.path_status, PathStatus::InvalidDeclaredPath)
        && app
            .declared_product_dir_name
            .value
            .as_deref()
            .is_some_and(|dir| CHROMIUM_DIR_ALLOWLIST.contains(&dir))
}

fn is_firefox(app: &AppRecord) -> bool {
    app.app_kind == AppKind::App
        && (app
            .bundle_id
            .value
            .as_deref()
            .is_some_and(|id| id.eq_ignore_ascii_case("org.mozilla.firefox"))
            || app.display_name.to_ascii_lowercase().contains("firefox"))
}

fn map_inventory_status(status: AppInventoryStatus) -> AppRelatedStatus {
    match status {
        AppInventoryStatus::Complete => AppRelatedStatus::Complete,
        AppInventoryStatus::Partial => AppRelatedStatus::Partial,
        AppInventoryStatus::Cancelled => AppRelatedStatus::Cancelled,
        AppInventoryStatus::Failed => AppRelatedStatus::Failed,
    }
}

fn validate_root_inputs(app_roots: &[PathBuf], library_roots: &[PathBuf]) -> Result<(), String> {
    if app_roots.is_empty() || app_roots.len() > MAX_APP_ROOTS {
        return Err("provide between 1 and 64 app roots".into());
    }
    if library_roots.is_empty() || library_roots.len() > MAX_LIBRARY_ROOTS {
        return Err("provide between 1 and 8 library roots".into());
    }
    for root in app_roots {
        if !valid_absolute_path(root) || root.parent().is_none() {
            return Err("roots must be non-root absolute paths without parent traversal".into());
        }
        if root.as_os_str().as_encoded_bytes().len() > 65_536 {
            return Err("root path exceeds 65,536 bytes".into());
        }
    }
    for root in library_roots {
        if !valid_absolute_path(root) || root.parent().is_none() {
            return Err("roots must be non-root absolute paths without parent traversal".into());
        }
        if root.as_os_str().as_encoded_bytes().len() > 65_536 {
            return Err("root path exceeds 65,536 bytes".into());
        }
        if root.file_name().is_none_or(|leaf| leaf != "Library") {
            return Err("library roots must use an explicit Library leaf directory".into());
        }
    }
    Ok(())
}

struct LibraryRoot {
    path: PathBuf,
    #[cfg(target_os = "macos")]
    native: NativeLibraryRoot,
}

#[cfg(target_os = "macos")]
struct NativeLibraryRoot {
    fd: rustix::fd::OwnedFd,
    identity: FileIdentity,
    device: u64,
}

fn prepare_library_roots(
    roots: Vec<PathBuf>,
    preview: &mut AppRelatedPreview,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Vec<LibraryRoot> {
    let mut selected = Vec::<LibraryRoot>::new();
    let mut ordered = roots;
    ordered.sort_by_key(|path| path.as_os_str().len());
    for root in ordered {
        if cancellation.is_cancelled() {
            update_status(preview, AppRelatedStatus::Cancelled);
            push_issue(
                preview,
                Some(root),
                "cancelled",
                "library root validation cancelled",
                None,
            );
            break;
        }
        if Instant::now() >= deadline {
            update_status(preview, AppRelatedStatus::Partial);
            push_issue(
                preview,
                Some(root),
                "duration_limit",
                "library root validation interrupted",
                None,
            );
            break;
        }
        if selected
            .iter()
            .any(|existing| root.starts_with(&existing.path) || existing.path.starts_with(&root))
        {
            update_status(preview, AppRelatedStatus::Partial);
            push_issue(
                preview,
                Some(root),
                "coalesced_library_root",
                "library root overlaps another explicit root and was coalesced",
                None,
            );
            continue;
        }
        match open_library_root(&root) {
            Ok(native) => selected.push(LibraryRoot {
                path: root,
                #[cfg(target_os = "macos")]
                native,
            }),
            Err(issue) => {
                let status = match issue.code {
                    "cancelled" => AppRelatedStatus::Cancelled,
                    "invalid_input" => AppRelatedStatus::Failed,
                    _ => AppRelatedStatus::Partial,
                };
                update_status(preview, status);
                push_issue(
                    preview,
                    issue.path,
                    issue.code,
                    issue.message,
                    issue.os_code,
                );
            }
        }
    }
    preview.library_roots = selected.iter().map(|root| root.path.clone()).collect();
    selected
}

#[derive(Clone)]
struct CandidateSpec {
    library_root_index: usize,
    path: PathBuf,
    relative_library_path: String,
    source_rule_id: &'static str,
    role: &'static str,
    ownership_certainty: &'static str,
    evidence: Vec<RelatedEvidence>,
    matched_app_copy_ids: BTreeSet<String>,
    protection_reasons: Vec<&'static str>,
}

struct CandidateSpecInput {
    library_root_index: usize,
    path: PathBuf,
    relative_library_path: String,
    source_rule_id: &'static str,
    role: &'static str,
    ownership_certainty: &'static str,
    evidence: Vec<RelatedEvidence>,
    protection_reasons: Vec<&'static str>,
}

fn maybe_add_spec(
    preview: &mut AppRelatedPreview,
    specs: &mut BTreeMap<(PathBuf, &'static str, String), CandidateSpec>,
    path_bytes: &mut usize,
    app_copy_id: &str,
    input: CandidateSpecInput,
) {
    let CandidateSpecInput {
        library_root_index,
        path,
        relative_library_path,
        source_rule_id,
        role,
        ownership_certainty,
        evidence,
        protection_reasons,
    } = input;
    let key = (path.clone(), source_rule_id, relative_library_path.clone());
    let is_new = !specs.contains_key(&key);
    if is_new {
        let next = path
            .as_os_str()
            .as_encoded_bytes()
            .len()
            .saturating_add(*path_bytes);
        if next > MAX_PATH_BYTES {
            update_status(preview, AppRelatedStatus::Partial);
            push_issue(
                preview,
                Some(path),
                "path_bytes_limit",
                "candidate path budget exceeded",
                None,
            );
            return;
        }
        *path_bytes = next;
    }
    let spec = specs.entry(key).or_insert_with(|| CandidateSpec {
        library_root_index,
        path,
        relative_library_path,
        source_rule_id,
        role,
        ownership_certainty,
        evidence: Vec::new(),
        matched_app_copy_ids: BTreeSet::new(),
        protection_reasons: protection_reasons.clone(),
    });
    if app_copy_id != "firefox-family" {
        spec.matched_app_copy_ids.insert(app_copy_id.to_string());
    }
    for item in evidence {
        let duplicate = spec.evidence.iter().any(|existing| {
            existing.kind == item.kind
                && existing.value == item.value
                && existing.app_copy_id == item.app_copy_id
        });
        if !duplicate {
            spec.evidence.push(item);
        }
    }
}

fn source_urls(rule_id: &str) -> Vec<&'static str> {
    if rule_id.starts_with("org.chromium") {
        vec![CHROMIUM_URL]
    } else if rule_id.starts_with("org.mozilla") {
        vec![MOZILLA_URL]
    } else {
        vec![APPLE_FS_URL, APPLE_BUNDLE_URL]
    }
}

fn ownership_statement(rule_id: &str, certainty: &str, relative_path: &str) -> String {
    if rule_id.starts_with("org.chromium") {
        format!(
            "{relative_path} matches Chromium-documented default location and app declaration; this is not proof of active profile usage."
        )
    } else if rule_id.starts_with("org.mozilla") {
        format!(
            "{relative_path} is a Firefox-family shared default profile location; it is not attributed to a single app copy."
        )
    } else {
        format!(
            "{relative_path} follows Apple Library conventions ({certainty}); ownership remains a hypothesis only."
        )
    }
}

fn valid_bundle_id_component_path(bundle_id: &str) -> bool {
    if bundle_id.is_empty()
        || bundle_id.starts_with('.')
        || bundle_id.ends_with('.')
        || bundle_id.contains('/')
        || bundle_id.contains('\\')
        || bundle_id.contains('\0')
    {
        return false;
    }
    for component in bundle_id.split('.') {
        if component.is_empty() || component == "." || component == ".." {
            return false;
        }
        if !component
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return false;
        }
    }
    true
}

fn update_status(preview: &mut AppRelatedPreview, next: AppRelatedStatus) {
    preview.status = match (preview.status, next) {
        (AppRelatedStatus::Failed, _) => AppRelatedStatus::Failed,
        (AppRelatedStatus::Cancelled, AppRelatedStatus::Failed) => AppRelatedStatus::Failed,
        (AppRelatedStatus::Cancelled, _) => AppRelatedStatus::Cancelled,
        (_, AppRelatedStatus::Failed) => AppRelatedStatus::Failed,
        (_, AppRelatedStatus::Cancelled) => AppRelatedStatus::Cancelled,
        (AppRelatedStatus::Complete, AppRelatedStatus::Partial) => AppRelatedStatus::Partial,
        (status, AppRelatedStatus::Complete) => status,
        (_, AppRelatedStatus::Partial) => AppRelatedStatus::Partial,
    };
    preview.complete = matches!(preview.status, AppRelatedStatus::Complete);
}

fn merge_inventory_issues(preview: &mut AppRelatedPreview, issues: &[AppIssue]) {
    for issue in issues {
        push_issue(
            preview,
            issue.path.clone(),
            issue.code.as_str(),
            issue.message.clone(),
            issue.os_code,
        );
    }
}

fn push_issue(
    preview: &mut AppRelatedPreview,
    path: Option<PathBuf>,
    code: &'static str,
    message: impl Into<String>,
    os_code: Option<i32>,
) {
    if preview.issues.len() < MAX_ISSUES {
        preview.issues.push(AppRelatedIssue {
            path,
            code,
            message: message.into(),
            os_code,
        });
    } else {
        preview.counts.issues_omitted += 1;
    }
}

fn finalize_metrics(preview: &mut AppRelatedPreview, started: Instant, probe_started: Instant) {
    preview.metrics.elapsed_ms = elapsed_ms(started.elapsed());
    preview.metrics.candidate_probe_elapsed_ms = elapsed_ms(probe_started.elapsed());
    preview.counts.issues = preview.issues.len();
}

fn elapsed_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn probe_candidate_path(
    root: &LibraryRoot,
    path: &Path,
    relative_library_path: &str,
    cancellation: &Cancellation,
    deadline: Instant,
) -> (&'static str, Option<AppRelatedIssue>) {
    if cancellation.is_cancelled() {
        return (
            "probe_failed",
            Some(AppRelatedIssue {
                path: Some(path.to_path_buf()),
                code: "cancelled",
                message: "probe cancelled".into(),
                os_code: None,
            }),
        );
    }
    if Instant::now() >= deadline {
        return (
            "probe_failed",
            Some(AppRelatedIssue {
                path: Some(path.to_path_buf()),
                code: "duration_limit",
                message: "probe budget exhausted".into(),
                os_code: None,
            }),
        );
    }
    #[cfg(target_os = "macos")]
    {
        probe_candidate_path_macos(root, path, relative_library_path)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (root, path, relative_library_path, cancellation, deadline);
        ("probe_failed", None)
    }
}

#[cfg(target_os = "macos")]
type OpenedLibraryRoot = NativeLibraryRoot;

#[cfg(not(target_os = "macos"))]
type OpenedLibraryRoot = ();

fn open_library_root(path: &Path) -> Result<OpenedLibraryRoot, AppRelatedIssue> {
    #[cfg(target_os = "macos")]
    {
        open_library_root_macos(path)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(AppRelatedIssue {
            path: Some(path.to_path_buf()),
            code: "unsupported_platform",
            message: "native app-related probing is unavailable on this platform".into(),
            os_code: None,
        })
    }
}

#[cfg(target_os = "macos")]
fn open_library_root_macos(path: &Path) -> Result<NativeLibraryRoot, AppRelatedIssue> {
    use rustix::fs::{self, Mode};
    let policy = match sayaka_platform_macos::ReadOnlyPolicy::enter() {
        Ok(policy) => policy,
        Err(error) => {
            return Err(AppRelatedIssue {
                path: Some(path.to_path_buf()),
                code: "policy_failure",
                message: format!("read-only policy setup failed: {error}"),
                os_code: error.raw_os_error(),
            });
        }
    };
    let opened = (|| {
        let fd = fs::open(path, directory_flags(), Mode::empty())
            .map_err(|error| issue_for_errno(path, error, "open library root", true))?;
        crate::scan::validate_local_internal_volume_fd(&fd)
            .map_err(|error| issue_from_scan_error(path, "validate library root volume", error))?;
        let stat = fs::fstat(&fd)
            .map_err(|error| issue_for_errno(path, error, "stat library root", true))?;
        if stat.st_mode & libc::S_IFMT != libc::S_IFDIR || is_dataless(&stat) {
            return Err(AppRelatedIssue {
                path: Some(path.to_path_buf()),
                code: "invalid_root",
                message: "library root must be an existing materialized directory".into(),
                os_code: None,
            });
        }
        let identity = stat_identity(&stat);
        let device = stat_device(&stat);
        Ok(NativeLibraryRoot {
            fd,
            identity,
            device,
        })
    })();
    finalize_policy_result(path, "library root validation", opened, policy.restore())
}

#[cfg(target_os = "macos")]
fn probe_candidate_path_macos(
    root: &LibraryRoot,
    path: &Path,
    relative_library_path: &str,
) -> (&'static str, Option<AppRelatedIssue>) {
    use rustix::fs::{self, AtFlags, Mode};
    use rustix::io::dup;

    let policy = match sayaka_platform_macos::ReadOnlyPolicy::enter() {
        Ok(policy) => policy,
        Err(error) => {
            return (
                "probe_failed",
                Some(AppRelatedIssue {
                    path: Some(path.to_path_buf()),
                    code: "policy_failure",
                    message: format!("read-only policy setup failed: {error}"),
                    os_code: error.raw_os_error(),
                }),
            );
        }
    };

    let probed = (|| {
        let components =
            relative_components(relative_library_path).ok_or_else(|| AppRelatedIssue {
                path: Some(path.to_path_buf()),
                code: "invalid_input",
                message: "invalid candidate relative path component".into(),
                os_code: None,
            })?;
        verify_root_mapping(root)?;
        let mut current = dup(&root.native.fd).map_err(|error| AppRelatedIssue {
            path: Some(path.to_path_buf()),
            code: "probe_failed",
            message: format!("duplicate root handle failed: {error}"),
            os_code: Some(error.raw_os_error()),
        })?;
        if components.is_empty() {
            return Ok(("present_directory", None));
        }
        for (index, name) in components.iter().enumerate() {
            let leaf = index + 1 == components.len();
            let stat = match fs::statat(&current, *name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) => stat,
                Err(error) => {
                    let state = map_probe_errno(error, leaf);
                    let issue = issue_for_probe_error(path, error, "stat candidate");
                    return Ok((state, issue));
                }
            };
            if stat.st_mode & libc::S_IFMT == libc::S_IFLNK {
                return Ok(("not_followed_symlink", None));
            }
            if is_dataless(&stat) {
                return Ok((
                    "probe_failed",
                    Some(AppRelatedIssue {
                        path: Some(path.to_path_buf()),
                        code: "cloud_or_dataless",
                        message: "candidate is cloud/dataless and was not materialized".into(),
                        os_code: None,
                    }),
                ));
            }
            if stat_device(&stat) != root.native.device {
                return Ok(("probe_failed", Some(descendant_device_issue(path))));
            }
            if !leaf {
                if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
                    return Ok((
                        "probe_failed",
                        Some(AppRelatedIssue {
                            path: Some(path.to_path_buf()),
                            code: "probe_failed",
                            message: "intermediate candidate path is not a directory".into(),
                            os_code: None,
                        }),
                    ));
                }
                #[cfg(all(test, target_os = "macos"))]
                run_intermediate_open_fault_hook();
                current = match fs::openat(&current, *name, directory_flags(), Mode::empty()) {
                    Ok(fd) => fd,
                    Err(error) => {
                        let state = map_probe_errno(error, false);
                        let issue = issue_for_probe_error(path, error, "open intermediate path");
                        return Ok((state, issue));
                    }
                };
                if let Err(validation) = validate_opened_intermediate(path, root, &stat, &current) {
                    return Ok(("probe_failed", Some(validation)));
                }
                continue;
            }
            let state = match stat.st_mode & libc::S_IFMT {
                libc::S_IFDIR => "present_directory",
                libc::S_IFREG => "present_file",
                _ => "present_other",
            };
            verify_root_mapping(root)?;
            return Ok((state, None));
        }
        Ok(("missing", None))
    })();

    let (mut state, mut issue) = match probed {
        Ok(outcome) => outcome,
        Err(issue) => ("probe_failed", Some(issue)),
    };
    if let Err(root_issue) = verify_root_mapping(root) {
        state = "probe_failed";
        issue = Some(match issue {
            Some(primary) => AppRelatedIssue {
                path: root_issue.path,
                code: root_issue.code,
                message: format!(
                    "{}; prior {}: {}",
                    root_issue.message, primary.code, primary.message
                ),
                os_code: root_issue.os_code.or(primary.os_code),
            },
            None => root_issue,
        });
    }
    finalize_policy_outcome(path, state, issue, policy.restore())
}

#[cfg(target_os = "macos")]
fn verify_root_mapping(root: &LibraryRoot) -> Result<(), AppRelatedIssue> {
    use rustix::fs::{self, Mode};
    let reopened = fs::open(&root.path, directory_flags(), Mode::empty())
        .map_err(|error| issue_for_errno(&root.path, error, "reopen library root", true))?;
    crate::scan::validate_local_internal_volume_fd(&reopened)
        .map_err(|error| issue_from_scan_error(&root.path, "revalidate root volume", error))?;
    let stat = fs::fstat(&reopened)
        .map_err(|error| issue_for_errno(&root.path, error, "restat library root", true))?;
    let observed_identity = stat_identity(&stat);
    let observed_device = stat_device(&stat);
    if let Err(message) = validate_root_observation(
        root.native.identity,
        root.native.device,
        observed_identity,
        observed_device,
        stat.st_mode & libc::S_IFMT == libc::S_IFDIR,
        is_dataless(&stat),
    ) {
        return Err(AppRelatedIssue {
            path: Some(root.path.clone()),
            code: "changed_root_identity",
            message: message.into(),
            os_code: None,
        });
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn relative_components(relative_library_path: &str) -> Option<Vec<&OsStr>> {
    let path = Path::new(relative_library_path);
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => components.push(name),
            _ => return None,
        }
    }
    Some(components)
}

#[cfg(target_os = "macos")]
fn stat_identity(stat: &rustix::fs::Stat) -> FileIdentity {
    FileIdentity::Unix {
        device: stat_device(stat),
        inode: stat.st_ino,
    }
}

#[cfg(target_os = "macos")]
fn stat_device(stat: &rustix::fs::Stat) -> u64 {
    u64::from(stat.st_dev.cast_unsigned())
}

#[cfg(target_os = "macos")]
fn is_dataless(stat: &rustix::fs::Stat) -> bool {
    stat.st_flags & 0x4000_0000 != 0
}

#[cfg(target_os = "macos")]
fn directory_flags() -> rustix::fs::OFlags {
    rustix::fs::OFlags::RDONLY
        | rustix::fs::OFlags::DIRECTORY
        | rustix::fs::OFlags::CLOEXEC
        | rustix::fs::OFlags::NONBLOCK
        | rustix::fs::OFlags::from_bits_retain(0x2000_0000)
}

fn issue_from_scan_error(path: &Path, context: &str, error: ScanError) -> AppRelatedIssue {
    AppRelatedIssue {
        path: Some(path.to_path_buf()),
        code: error.code.as_str(),
        message: format!("{context}: {}", error.message),
        os_code: error.os_code,
    }
}

fn finalize_policy_result<T>(
    path: &Path,
    phase: &str,
    primary: Result<T, AppRelatedIssue>,
    restored: Result<(), std::io::Error>,
) -> Result<T, AppRelatedIssue> {
    match (primary, restored) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(issue), Ok(())) => Err(issue),
        (Ok(_), Err(error)) => Err(AppRelatedIssue {
            path: Some(path.to_path_buf()),
            code: "policy_failure",
            message: format!("read-only policy restore failed after {phase}: {error}"),
            os_code: error.raw_os_error(),
        }),
        (Err(issue), Err(error)) => Err(AppRelatedIssue {
            path: issue.path.or_else(|| Some(path.to_path_buf())),
            code: "policy_failure",
            message: format!(
                "read-only policy restore failed after {phase}: {error}; prior {}: {}",
                issue.code, issue.message
            ),
            os_code: error.raw_os_error().or(issue.os_code),
        }),
    }
}

fn finalize_policy_outcome(
    path: &Path,
    state: &'static str,
    issue: Option<AppRelatedIssue>,
    restored: Result<(), std::io::Error>,
) -> (&'static str, Option<AppRelatedIssue>) {
    match restored {
        Ok(()) => (state, issue),
        Err(error) => {
            let policy_failure = AppRelatedIssue {
                path: issue
                    .as_ref()
                    .and_then(|value| value.path.clone())
                    .or_else(|| Some(path.to_path_buf())),
                code: "policy_failure",
                message: issue.as_ref().map_or_else(
                    || format!("read-only policy restore failed after {state}: {error}"),
                    |primary| {
                        format!(
                            "read-only policy restore failed after {state}: {error}; prior {}: {}",
                            primary.code, primary.message
                        )
                    },
                ),
                os_code: error
                    .raw_os_error()
                    .or_else(|| issue.as_ref().and_then(|value| value.os_code)),
            };
            ("probe_failed", Some(policy_failure))
        }
    }
}

fn descendant_device_issue(path: &Path) -> AppRelatedIssue {
    AppRelatedIssue {
        path: Some(path.to_path_buf()),
        code: "mount_boundary",
        message: "candidate crossed mount boundary below validated Library root".into(),
        os_code: None,
    }
}

#[cfg(target_os = "macos")]
enum IntermediateOpenError {
    Dataless,
    NotDirectory,
    MountBoundary,
    MappingChanged,
}

#[cfg(target_os = "macos")]
struct IntermediateObservation {
    identity: FileIdentity,
    device: u64,
    kind: libc::mode_t,
    dataless: bool,
}

#[cfg(target_os = "macos")]
fn validate_opened_intermediate_observation(
    prior: IntermediateObservation,
    opened: IntermediateObservation,
    root_device: u64,
) -> Result<(), IntermediateOpenError> {
    if opened.dataless {
        return Err(IntermediateOpenError::Dataless);
    }
    if opened.kind != libc::S_IFDIR {
        return Err(IntermediateOpenError::NotDirectory);
    }
    if opened.device != root_device {
        return Err(IntermediateOpenError::MountBoundary);
    }
    if prior.identity != opened.identity
        || prior.device != opened.device
        || prior.kind != opened.kind
    {
        return Err(IntermediateOpenError::MappingChanged);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn validate_opened_intermediate(
    path: &Path,
    root: &LibraryRoot,
    prior_stat: &rustix::fs::Stat,
    opened: &rustix::fd::OwnedFd,
) -> Result<(), AppRelatedIssue> {
    let stat = rustix::fs::fstat(opened)
        .map_err(|error| issue_for_errno(path, error, "stat opened intermediate path", false))?;
    match validate_opened_intermediate_observation(
        IntermediateObservation {
            identity: stat_identity(prior_stat),
            device: stat_device(prior_stat),
            kind: prior_stat.st_mode & libc::S_IFMT,
            dataless: is_dataless(prior_stat),
        },
        IntermediateObservation {
            identity: stat_identity(&stat),
            device: stat_device(&stat),
            kind: stat.st_mode & libc::S_IFMT,
            dataless: is_dataless(&stat),
        },
        root.native.device,
    ) {
        Ok(()) => Ok(()),
        Err(IntermediateOpenError::Dataless) => Err(AppRelatedIssue {
            path: Some(path.to_path_buf()),
            code: "cloud_or_dataless",
            message: "candidate is cloud/dataless and was not materialized".into(),
            os_code: None,
        }),
        Err(IntermediateOpenError::NotDirectory) => Err(AppRelatedIssue {
            path: Some(path.to_path_buf()),
            code: "probe_failed",
            message: "opened intermediate candidate path is not a directory".into(),
            os_code: None,
        }),
        Err(IntermediateOpenError::MountBoundary) => Err(descendant_device_issue(path)),
        Err(IntermediateOpenError::MappingChanged) => Err(AppRelatedIssue {
            path: Some(path.to_path_buf()),
            code: "probe_failed",
            message: "intermediate candidate mapping changed before open; refresh required".into(),
            os_code: None,
        }),
    }
}

#[cfg(all(test, target_os = "macos"))]
type IntermediateOpenHook = Box<dyn FnMut() + Send>;

#[cfg(all(test, target_os = "macos"))]
static INTERMEDIATE_OPEN_HOOK: std::sync::OnceLock<std::sync::Mutex<Option<IntermediateOpenHook>>> =
    std::sync::OnceLock::new();

fn validate_root_observation(
    expected_identity: FileIdentity,
    expected_device: u64,
    observed_identity: FileIdentity,
    observed_device: u64,
    is_directory: bool,
    dataless: bool,
) -> Result<(), &'static str> {
    if observed_identity != expected_identity || observed_device != expected_device {
        return Err("validated library root identity changed; refresh required");
    }
    if !is_directory || dataless {
        return Err("validated library root is no longer a materialized directory");
    }
    Ok(())
}

#[cfg(all(test, target_os = "macos"))]
fn run_intermediate_open_fault_hook() {
    if let Some(hook) = INTERMEDIATE_OPEN_HOOK
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .expect("hook lock")
        .as_mut()
    {
        hook();
    }
}

#[cfg(all(test, target_os = "macos"))]
fn install_intermediate_open_fault_hook(hook: impl FnMut() + Send + 'static) -> impl Drop {
    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            let mut slot = INTERMEDIATE_OPEN_HOOK
                .get_or_init(|| std::sync::Mutex::new(None))
                .lock()
                .expect("hook lock");
            *slot = None;
        }
    }
    let mut slot = INTERMEDIATE_OPEN_HOOK
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .expect("hook lock");
    *slot = Some(Box::new(hook));
    Guard
}

#[cfg(target_os = "macos")]
fn map_probe_errno(error: rustix::io::Errno, leaf: bool) -> &'static str {
    let io = std::io::Error::from_raw_os_error(error.raw_os_error());
    if io.kind() == std::io::ErrorKind::NotFound {
        return "missing";
    }
    if error == rustix::io::Errno::LOOP {
        return "not_followed_symlink";
    }
    if io.kind() == std::io::ErrorKind::PermissionDenied {
        return "permission_denied";
    }
    if leaf {
        "probe_failed"
    } else {
        "not_followed_symlink"
    }
}

#[cfg(target_os = "macos")]
fn issue_for_probe_error(
    path: &Path,
    error: rustix::io::Errno,
    context: &str,
) -> Option<AppRelatedIssue> {
    let io = std::io::Error::from_raw_os_error(error.raw_os_error());
    if io.kind() == std::io::ErrorKind::NotFound || error == rustix::io::Errno::LOOP {
        return None;
    }

    let code = if io.kind() == std::io::ErrorKind::PermissionDenied {
        "permission_denied"
    } else {
        "probe_failed"
    };
    Some(AppRelatedIssue {
        path: Some(path.to_path_buf()),
        code,
        message: format!("{context}: {io}"),
        os_code: io.raw_os_error(),
    })
}

#[cfg(target_os = "macos")]
fn issue_for_errno(
    path: &Path,
    error: rustix::io::Errno,
    context: &str,
    _leaf: bool,
) -> AppRelatedIssue {
    issue_for_probe_error(path, error, context).unwrap_or_else(|| AppRelatedIssue {
        path: Some(path.to_path_buf()),
        code: if error == rustix::io::Errno::LOOP {
            "not_followed_symlink"
        } else {
            "probe_failed"
        },
        message: format!(
            "{context}: {}",
            std::io::Error::from_raw_os_error(error.raw_os_error())
        ),
        os_code: Some(error.raw_os_error()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_inventory::{
        AppInventoryMetrics, AppIssueCode, ExecutableMetadata, NameSource, PlistFormat,
        RunningObservation, StringField,
    };
    use crate::scan::ScanTaskId;
    use std::fs;
    use std::process;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    const TEST_PROBE_BUDGET: Duration = Duration::from_secs(5);

    fn app(
        path: &str,
        bundle_id: Option<&str>,
        cr_dir: Option<&str>,
        display: &str,
        app_kind: AppKind,
    ) -> AppRecord {
        let field = |value: Option<&str>| StringField {
            state: if value.is_some() {
                StringState::Present
            } else {
                StringState::Missing
            },
            value: value.map(str::to_string),
        };
        AppRecord {
            bundle_path: PathBuf::from(path),
            observed_roots: vec![PathBuf::from("/Applications")],
            bundle_identity: FileIdentity::Unix {
                device: 1,
                inode: 1,
            },
            app_kind,
            parser_format: PlistFormat::Xml,
            display_name: display.to_string(),
            display_name_source: NameSource::BundleDisplayName,
            localized: false,
            bundle_id: field(bundle_id),
            short_version: field(Some("1.0")),
            build_version: field(Some("1")),
            package_type: field(Some("APPL")),
            declared_product_dir_name: field(cr_dir),
            executable: ExecutableMetadata {
                state: StringState::Present,
                declared_value: Some("Run".into()),
                path_status: PathStatus::PresentFile,
            },
            running: RunningObservation::NotChecked,
        }
    }

    fn preview_diagnostics(preview: &AppRelatedPreview) -> String {
        let issues = preview
            .issues
            .iter()
            .map(|issue| format!("{}:{}", issue.code, issue.message))
            .collect::<Vec<_>>();
        let candidates = preview
            .candidates
            .iter()
            .map(|candidate| {
                format!(
                    "{} [{}] ({})",
                    candidate.relative_library_path, candidate.source_rule_id, candidate.path_state
                )
            })
            .collect::<Vec<_>>();
        format!(
            "status={} complete={} issues={issues:?} candidates={candidates:?}",
            preview.status.as_str(),
            preview.complete
        )
    }

    fn assert_no_duration_limit_issue(preview: &AppRelatedPreview) {
        assert!(
            !preview
                .issues
                .iter()
                .any(|issue| issue.code == "duration_limit"),
            "unexpected duration limit in fixture test: {}",
            preview_diagnostics(preview)
        );
    }

    fn inventory(apps: Vec<AppRecord>) -> AppInventory {
        AppInventory {
            schema_version: 1,
            kind: "app_inventory",
            platform: "macos",
            status: AppInventoryStatus::Complete,
            complete: true,
            effects_performed: false,
            roots: vec![PathBuf::from("/Applications")],
            filter: String::new(),
            excludes: Vec::new(),
            scan_task_id: ScanTaskId::synthetic(1).to_string(),
            counts: Default::default(),
            apps,
            scan_issues: Vec::new(),
            issues: Vec::new(),
            issues_omitted: 0,
            metrics: AppInventoryMetrics::default(),
        }
    }

    fn inventory_with_status(
        apps: Vec<AppRecord>,
        status: AppInventoryStatus,
        complete: bool,
    ) -> AppInventory {
        let mut inv = inventory(apps);
        inv.status = status;
        inv.complete = complete;
        inv
    }

    fn inventory_with_inventory_issues(
        apps: Vec<AppRecord>,
        issues: Vec<crate::app_inventory::AppIssue>,
        issues_omitted: usize,
    ) -> AppInventory {
        let mut inv = inventory(apps);
        inv.status = AppInventoryStatus::Partial;
        inv.complete = false;
        inv.issues = issues;
        inv.issues_omitted = issues_omitted;
        inv
    }

    struct TestLibraryRoot {
        root: PathBuf,
        library: PathBuf,
    }

    impl TestLibraryRoot {
        fn library_path(&self) -> PathBuf {
            self.library.clone()
        }

        fn root_path(&self) -> &Path {
            &self.root
        }
    }

    impl Drop for TestLibraryRoot {
        fn drop(&mut self) {
            if let Err(error) = fs::remove_dir_all(&self.root)
                && self.root.exists()
            {
                eprintln!("app-related test fixture cleanup failed: {error}");
                if !std::thread::panicking() {
                    panic!("app-related test fixture cleanup failed");
                }
            }
        }
    }

    #[test]
    fn chromium_requires_allowlisted_declared_product_dir() {
        let root = test_library_root("chromium");
        let inv = inventory(vec![
            app(
                "/Applications/Chrome.app",
                Some("com.google.Chrome"),
                Some("Google/Chrome"),
                "Google Chrome",
                AppKind::App,
            ),
            app(
                "/Applications/NameOnly.app",
                Some("com.google.Chrome"),
                None,
                "Google Chrome",
                AppKind::App,
            ),
        ]);
        let preview = preview_app_related_data(
            inv,
            vec![PathBuf::from("/Applications")],
            vec![root.library_path()],
            String::new(),
            &Cancellation::default(),
            TEST_PROBE_BUDGET,
        );
        assert_no_duration_limit_issue(&preview);
        assert!(
            preview
                .candidates
                .iter()
                .any(|candidate| candidate.source_rule_id.starts_with("org.chromium")),
            "{}",
            preview_diagnostics(&preview)
        );
        let name_only_id = preview
            .app_copies
            .iter()
            .find(|copy| copy.bundle_path.ends_with("NameOnly.app"))
            .map(|copy| copy.app_copy_id.clone())
            .expect("name-only copy id");
        assert!(
            preview
                .candidates
                .iter()
                .filter(|candidate| candidate.source_rule_id.starts_with("org.chromium"))
                .all(|candidate| !candidate.matched_app_copy_ids.contains(&name_only_id)),
            "{}",
            preview_diagnostics(&preview)
        );
    }

    #[test]
    fn generic_bundle_candidates_are_hypothesis_and_never_deletable() {
        let root = test_library_root("generic");
        let inv = inventory(vec![app(
            "/Applications/Demo.app",
            Some("com.example.demo"),
            None,
            "Demo",
            AppKind::App,
        )]);
        let preview = preview_app_related_data(
            inv,
            vec![PathBuf::from("/Applications")],
            vec![root.library_path()],
            String::new(),
            &Cancellation::default(),
            TEST_PROBE_BUDGET,
        );
        assert_no_duration_limit_issue(&preview);
        for candidate in preview
            .candidates
            .iter()
            .filter(|candidate| candidate.source_rule_id.starts_with("org.apple.library"))
        {
            assert_eq!(
                candidate.ownership_certainty,
                "location_standard_hypothesis"
            );
            assert!(!candidate.deletable);
            assert!(candidate.authorized_action.is_none());
        }
    }

    #[test]
    fn bundle_id_validation_rejects_traversal_segments() {
        assert!(valid_bundle_id_component_path("com.example.demo"));
        assert!(!valid_bundle_id_component_path("../demo"));
        assert!(!valid_bundle_id_component_path("com.example/demo"));
        assert!(!valid_bundle_id_component_path("com..example"));
    }

    #[test]
    fn filter_narrows_candidates_and_counts_but_keeps_referenced_copies() {
        let root = test_library_root("filter");
        let inv = inventory(vec![
            app(
                "/Applications/Google Chrome.app",
                Some("com.google.Chrome"),
                Some("Google/Chrome"),
                "Google Chrome",
                AppKind::App,
            ),
            app(
                "/Applications/Demo.app",
                Some("com.example.demo"),
                None,
                "Demo",
                AppKind::App,
            ),
        ]);
        let preview = preview_app_related_data(
            inv,
            vec![PathBuf::from("/Applications")],
            vec![root.library_path()],
            "Chrome".into(),
            &Cancellation::default(),
            TEST_PROBE_BUDGET,
        );
        assert_no_duration_limit_issue(&preview);
        assert!(
            preview
                .candidates
                .iter()
                .all(|candidate| !candidate.relative_library_path.contains("com.example.demo"))
        );
        assert!(
            preview
                .candidates
                .iter()
                .any(|candidate| candidate.relative_library_path
                    == "Application Support/Google/Chrome"),
            "{}",
            preview_diagnostics(&preview)
        );
        assert_eq!(preview.counts.candidate_paths, preview.candidates.len());
        assert_eq!(
            preview.counts.protected_candidates,
            preview.candidates.len()
        );
        assert!(
            preview
                .app_copies
                .iter()
                .all(|copy| copy.bundle_path.ends_with("Google Chrome.app"))
        );
    }

    #[test]
    fn partial_inventory_forces_unattributed_certainty_and_partial_reason() {
        let root = test_library_root("inventory-partial");
        let inv = inventory_with_status(
            vec![app(
                "/Applications/Google Chrome.app",
                Some("com.google.Chrome"),
                Some("Google/Chrome"),
                "Google Chrome",
                AppKind::App,
            )],
            AppInventoryStatus::Partial,
            false,
        );
        let preview = preview_app_related_data(
            inv,
            vec![PathBuf::from("/Applications")],
            vec![root.library_path()],
            String::new(),
            &Cancellation::default(),
            TEST_PROBE_BUDGET,
        );
        assert_no_duration_limit_issue(&preview);
        assert_eq!(preview.status, AppRelatedStatus::Partial);
        assert!(!preview.complete);
        assert!(preview.candidates.iter().all(|candidate| {
            candidate.ownership_certainty == "unattributed_due_to_partial_inventory"
                && candidate
                    .protection_reasons
                    .contains(&"inventory_or_probe_partial")
        }));
        assert!(!preview.app_copies.is_empty());
        assert!(
            preview
                .app_copies
                .iter()
                .all(|copy| copy.copy_state == "inventory_partial_unknown")
        );
    }

    #[test]
    fn duplicate_physical_chrome_copies_share_candidates() {
        let root = test_library_root("duplicate-chrome");
        let inv = inventory(vec![
            app(
                "/Applications/Google Chrome.app",
                Some("com.google.Chrome"),
                Some("Google/Chrome"),
                "Google Chrome",
                AppKind::App,
            ),
            app(
                "/Applications/Google Chrome Canary.app",
                Some("com.google.Chrome"),
                Some("Google/Chrome"),
                "Google Chrome Canary",
                AppKind::App,
            ),
        ]);
        let preview = preview_app_related_data(
            inv,
            vec![PathBuf::from("/Applications")],
            vec![root.library_path()],
            String::new(),
            &Cancellation::default(),
            TEST_PROBE_BUDGET,
        );
        assert_no_duration_limit_issue(&preview);
        let profile = preview
            .candidates
            .iter()
            .find(|candidate| {
                candidate.relative_library_path == "Application Support/Google/Chrome"
            })
            .unwrap_or_else(|| panic!("{}", preview_diagnostics(&preview)));
        assert_eq!(profile.matched_app_copy_ids.len(), 2);
        assert!(
            profile
                .protection_reasons
                .contains(&"multiple_physical_app_copies")
        );
        assert_eq!(preview.counts.shared_candidates, 2);
    }

    #[test]
    fn duplicate_firefox_copies_remain_shared_family_candidates() {
        let root = test_library_root("duplicate-firefox");
        let inv = inventory(vec![
            app(
                "/Applications/Firefox.app",
                Some("org.mozilla.firefox"),
                None,
                "Firefox",
                AppKind::App,
            ),
            app(
                "/Applications/Firefox Developer Edition.app",
                Some("org.mozilla.firefox"),
                None,
                "Firefox Developer Edition",
                AppKind::App,
            ),
        ]);
        let preview = preview_app_related_data(
            inv,
            vec![PathBuf::from("/Applications")],
            vec![root.library_path()],
            String::new(),
            &Cancellation::default(),
            TEST_PROBE_BUDGET,
        );
        assert_no_duration_limit_issue(&preview);
        let profiles = preview
            .candidates
            .iter()
            .find(|candidate| {
                candidate.source_rule_id == "org.mozilla.firefox.default_profiles.macos.v1"
            })
            .unwrap_or_else(|| panic!("{}", preview_diagnostics(&preview)));
        assert_eq!(profiles.matched_app_copy_ids.len(), 2);
        assert!(
            profiles
                .protection_reasons
                .contains(&"shared_across_profiles_or_app_copies")
        );
    }

    #[test]
    fn candidate_limit_marks_partial_with_explicit_issue() {
        let root_base = test_library_root("candidate-limit");
        let mut libraries = Vec::new();
        for idx in 0..MAX_LIBRARY_ROOTS {
            let library = root_base.root_path().join(format!("root-{idx}/Library"));
            fs::create_dir_all(&library).expect("create library root");
            libraries.push(library);
        }
        let apps = (0..MAX_GENERIC_APP_COPIES)
            .map(|idx| {
                app(
                    &format!("/Applications/Demo{idx}.app"),
                    Some(&format!("com.example.demo{idx}")),
                    None,
                    &format!("Demo{idx}"),
                    AppKind::App,
                )
            })
            .collect::<Vec<_>>();
        let preview = preview_app_related_data(
            inventory(apps),
            vec![PathBuf::from("/Applications")],
            libraries,
            String::new(),
            &Cancellation::default(),
            Duration::from_secs(5),
        );
        assert_eq!(preview.status, AppRelatedStatus::Partial);
        assert!(
            preview
                .issues
                .iter()
                .any(|issue| issue.code == "candidate_limit")
        );
        assert_eq!(preview.counts.candidate_paths, MAX_CANDIDATES);
    }

    #[test]
    fn path_budget_limit_is_reported() {
        let mut preview = AppRelatedPreview {
            schema_version: APP_RELATED_SCHEMA_VERSION,
            kind: APP_RELATED_KIND,
            platform: "macos",
            status: AppRelatedStatus::Complete,
            complete: true,
            effects_performed: false,
            app_roots: vec![PathBuf::from("/Applications")],
            library_roots: vec![PathBuf::from("/Users/test/Library")],
            filter: String::new(),
            scan_task_id: Some("unit".into()),
            inventory_status: "complete",
            inventory_complete: true,
            counts: AppRelatedCounts::default(),
            app_copies: Vec::new(),
            candidates: Vec::new(),
            scan_issues: Vec::new(),
            issues: Vec::new(),
            metrics: AppRelatedMetrics::default(),
        };
        let mut specs = BTreeMap::new();
        let mut bytes = MAX_PATH_BYTES;
        maybe_add_spec(
            &mut preview,
            &mut specs,
            &mut bytes,
            "unit-copy",
            CandidateSpecInput {
                library_root_index: 0,
                path: PathBuf::from("/Users/test/Library/Application Support/com.example.demo"),
                relative_library_path: "Application Support/com.example.demo".into(),
                source_rule_id: "org.apple.library.application_support.bundle_id_convention.v1",
                role: "persistent_support_or_profile",
                ownership_certainty: "location_standard_hypothesis",
                evidence: Vec::new(),
                protection_reasons: vec!["ownership_not_proven"],
            },
        );
        assert!(specs.is_empty());
        assert!(
            preview
                .issues
                .iter()
                .any(|issue| issue.code == "path_bytes_limit")
        );
    }

    #[test]
    fn issues_budget_tracks_omitted_items() {
        let mut preview = AppRelatedPreview {
            schema_version: APP_RELATED_SCHEMA_VERSION,
            kind: APP_RELATED_KIND,
            platform: "macos",
            status: AppRelatedStatus::Complete,
            complete: true,
            effects_performed: false,
            app_roots: Vec::new(),
            library_roots: Vec::new(),
            filter: String::new(),
            scan_task_id: None,
            inventory_status: "complete",
            inventory_complete: true,
            counts: AppRelatedCounts::default(),
            app_copies: Vec::new(),
            candidates: Vec::new(),
            scan_issues: Vec::new(),
            issues: Vec::new(),
            metrics: AppRelatedMetrics::default(),
        };
        for index in 0..(MAX_ISSUES + 7) {
            push_issue(
                &mut preview,
                None,
                "probe_failed",
                format!("issue {index}"),
                None,
            );
        }
        assert_eq!(preview.issues.len(), MAX_ISSUES);
        assert_eq!(preview.counts.issues_omitted, 7);
    }

    #[test]
    fn inventory_issues_and_upstream_omitted_are_preserved() {
        let root = test_library_root("inventory-issues");
        let inventory_issues = vec![crate::app_inventory::AppIssue {
            path: Some(PathBuf::from("/Applications/Bad.app/Contents/Info.plist")),
            code: AppIssueCode::MalformedPlist,
            message: "malformed plist fixture".into(),
            os_code: None,
        }];
        let preview = preview_app_related_data(
            inventory_with_inventory_issues(
                vec![app(
                    "/Applications/Bad.app",
                    Some("com.example.bad"),
                    None,
                    "Bad",
                    AppKind::App,
                )],
                inventory_issues,
                3,
            ),
            vec![PathBuf::from("/Applications")],
            vec![root.library_path()],
            String::new(),
            &Cancellation::default(),
            TEST_PROBE_BUDGET,
        );
        assert!(
            preview
                .issues
                .iter()
                .any(|issue| issue.code == "malformed_plist")
        );
        assert_eq!(preview.counts.issues_omitted, 3);
    }

    #[test]
    fn upstream_issue_overflow_accounting_is_exact() {
        let mut issues = Vec::new();
        for idx in 0..MAX_ISSUES {
            issues.push(crate::app_inventory::AppIssue {
                path: None,
                code: AppIssueCode::MalformedPlist,
                message: format!("malformed-{idx}"),
                os_code: None,
            });
        }
        let preview = preview_app_related_data(
            inventory_with_inventory_issues(
                vec![app(
                    "/Applications/Bad.app",
                    Some("com.example.bad"),
                    None,
                    "Bad",
                    AppKind::App,
                )],
                issues,
                2,
            ),
            vec![PathBuf::from("/Applications")],
            vec![PathBuf::from("/Users/test/home")],
            String::new(),
            &Cancellation::default(),
            TEST_PROBE_BUDGET,
        );
        assert_eq!(preview.issues.len(), MAX_ISSUES);
        assert_eq!(preview.counts.issues_omitted, 3);
        assert!(
            preview
                .issues
                .iter()
                .any(|issue| issue.code == "malformed_plist")
        );
    }

    #[test]
    fn pre_cancelled_generic_limit_stays_cancelled() {
        let root = test_library_root("cancelled-generic-limit");
        let apps = (0..(MAX_GENERIC_APP_COPIES + 1))
            .map(|idx| {
                app(
                    &format!("/Applications/Demo{idx}.app"),
                    Some(&format!("com.example.demo{idx}")),
                    None,
                    &format!("Demo{idx}"),
                    AppKind::App,
                )
            })
            .collect::<Vec<_>>();
        let cancellation = Cancellation::default();
        cancellation.cancel();
        let preview = preview_app_related_data(
            inventory(apps),
            vec![PathBuf::from("/Applications")],
            vec![root.library_path()],
            String::new(),
            &cancellation,
            TEST_PROBE_BUDGET,
        );
        assert_eq!(preview.status, AppRelatedStatus::Cancelled);
        assert_eq!(preview.status.exit_code(), 130);
    }

    #[test]
    fn policy_restore_failure_overrides_successful_probe_state() {
        let (state, issue) = finalize_policy_outcome(
            Path::new("/Users/test/Library/Caches/example"),
            "missing",
            None,
            Err(std::io::Error::from_raw_os_error(libc::EIO)),
        );
        assert_eq!(state, "probe_failed");
        let issue = issue.expect("policy restore issue");
        assert_eq!(issue.code, "policy_failure");
        assert!(issue.message.contains("after missing"));
    }

    #[test]
    fn policy_restore_failure_retains_primary_context() {
        let (state, issue) = finalize_policy_outcome(
            Path::new("/Users/test/Library/Caches/example"),
            "probe_failed",
            Some(AppRelatedIssue {
                path: None,
                code: "permission_denied",
                message: "stat candidate: permission denied".into(),
                os_code: Some(libc::EACCES),
            }),
            Err(std::io::Error::from_raw_os_error(libc::EPERM)),
        );
        assert_eq!(state, "probe_failed");
        let issue = issue.expect("policy restore issue");
        assert_eq!(issue.code, "policy_failure");
        assert!(issue.message.contains("prior permission_denied"));
    }

    #[test]
    fn root_observation_detects_identity_or_device_changes() {
        let expected = FileIdentity::Unix {
            device: 10,
            inode: 22,
        };
        assert!(validate_root_observation(expected, 10, expected, 10, true, false).is_ok());
        assert!(validate_root_observation(expected, 10, expected, 11, true, false).is_err());
        assert!(
            validate_root_observation(
                expected,
                10,
                FileIdentity::Unix {
                    device: 10,
                    inode: 23
                },
                10,
                true,
                false,
            )
            .is_err()
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn opened_intermediate_validation_checks_dataless_kind_device_and_mapping() {
        let prior = FileIdentity::Unix {
            device: 10,
            inode: 20,
        };
        assert!(
            validate_opened_intermediate_observation(
                IntermediateObservation {
                    identity: prior,
                    device: 10,
                    kind: libc::S_IFDIR,
                    dataless: false,
                },
                IntermediateObservation {
                    identity: prior,
                    device: 10,
                    kind: libc::S_IFDIR,
                    dataless: false,
                },
                10
            )
            .is_ok()
        );
        assert!(matches!(
            validate_opened_intermediate_observation(
                IntermediateObservation {
                    identity: prior,
                    device: 10,
                    kind: libc::S_IFDIR,
                    dataless: false,
                },
                IntermediateObservation {
                    identity: prior,
                    device: 10,
                    kind: libc::S_IFDIR,
                    dataless: true,
                },
                10
            ),
            Err(IntermediateOpenError::Dataless)
        ));
        assert!(matches!(
            validate_opened_intermediate_observation(
                IntermediateObservation {
                    identity: prior,
                    device: 10,
                    kind: libc::S_IFDIR,
                    dataless: false,
                },
                IntermediateObservation {
                    identity: prior,
                    device: 10,
                    kind: libc::S_IFREG,
                    dataless: false,
                },
                10
            ),
            Err(IntermediateOpenError::NotDirectory)
        ));
        assert!(matches!(
            validate_opened_intermediate_observation(
                IntermediateObservation {
                    identity: prior,
                    device: 10,
                    kind: libc::S_IFDIR,
                    dataless: false,
                },
                IntermediateObservation {
                    identity: prior,
                    device: 11,
                    kind: libc::S_IFDIR,
                    dataless: false,
                },
                10
            ),
            Err(IntermediateOpenError::MountBoundary)
        ));
        assert!(matches!(
            validate_opened_intermediate_observation(
                IntermediateObservation {
                    identity: prior,
                    device: 10,
                    kind: libc::S_IFDIR,
                    dataless: false,
                },
                IntermediateObservation {
                    identity: FileIdentity::Unix {
                        device: 10,
                        inode: 21,
                    },
                    device: 10,
                    kind: libc::S_IFDIR,
                    dataless: false,
                },
                10
            ),
            Err(IntermediateOpenError::MappingChanged)
        ));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn replacing_intermediate_between_stat_and_open_fails_before_next_lookup() {
        let root = test_library_root("intermediate-replace");
        let application_support = root.root_path().join("Library/Application Support");
        fs::create_dir_all(&application_support).expect("create application support");
        let replacement = application_support.clone();
        let mut replaced = false;
        let _hook = install_intermediate_open_fault_hook(move || {
            if replaced {
                return;
            }
            replaced = true;
            fs::remove_dir_all(&replacement).expect("remove original intermediate");
            fs::create_dir(&replacement).expect("create replacement intermediate");
        });
        let preview = preview_app_related_data(
            inventory(vec![app(
                "/Applications/Demo.app",
                Some("com.example.demo"),
                None,
                "Demo",
                AppKind::App,
            )]),
            vec![PathBuf::from("/Applications")],
            vec![root.library_path()],
            String::new(),
            &Cancellation::default(),
            TEST_PROBE_BUDGET,
        );
        assert_no_duration_limit_issue(&preview);
        let candidate = preview
            .candidates
            .iter()
            .find(|candidate| {
                candidate.relative_library_path == "Application Support/com.example.demo"
            })
            .unwrap_or_else(|| panic!("{}", preview_diagnostics(&preview)));
        assert_eq!(candidate.path_state, "probe_failed");
        assert!(preview.issues.iter().any(|issue| {
            issue
                .path
                .as_ref()
                .is_some_and(|path| path == &candidate.path)
                && issue.code == "probe_failed"
                && issue
                    .message
                    .contains("intermediate candidate mapping changed before open")
        }));
        assert!(!preview.issues.iter().any(|issue| {
            issue
                .path
                .as_ref()
                .is_some_and(|path| path == &candidate.path)
                && issue.message.contains("stat candidate")
        }));
    }

    #[test]
    fn cancellation_marks_result_cancelled() {
        let root = test_library_root("cancelled");
        let cancellation = Cancellation::default();
        cancellation.cancel();
        let preview = preview_app_related_data(
            inventory(vec![app(
                "/Applications/Demo.app",
                Some("com.example.demo"),
                None,
                "Demo",
                AppKind::App,
            )]),
            vec![PathBuf::from("/Applications")],
            vec![root.library_path()],
            String::new(),
            &cancellation,
            TEST_PROBE_BUDGET,
        );
        assert_eq!(preview.status, AppRelatedStatus::Cancelled);
        assert!(!preview.complete);
        assert!(preview.issues.iter().any(|issue| issue.code == "cancelled"));
    }

    #[test]
    fn overlapping_library_roots_are_coalesced() {
        let root = test_library_root("overlap");
        let nested = root.library_path().join("Nested/Library");
        fs::create_dir_all(&nested).expect("create nested root");
        let preview = preview_app_related_data(
            inventory(vec![app(
                "/Applications/Demo.app",
                Some("com.example.demo"),
                None,
                "Demo",
                AppKind::App,
            )]),
            vec![PathBuf::from("/Applications")],
            vec![root.library_path(), nested.clone()],
            String::new(),
            &Cancellation::default(),
            TEST_PROBE_BUDGET,
        );
        assert_no_duration_limit_issue(&preview);
        assert_eq!(preview.library_roots.len(), 1);
        assert!(
            preview
                .issues
                .iter()
                .any(|issue| issue.code == "coalesced_library_root"),
            "{}",
            preview_diagnostics(&preview)
        );
    }

    #[test]
    fn invalid_library_root_leaf_is_rejected() {
        let inv = inventory(vec![app(
            "/Applications/Demo.app",
            Some("com.example.demo"),
            None,
            "Demo",
            AppKind::App,
        )]);
        let preview = preview_app_related_data(
            inv,
            vec![PathBuf::from("/Applications")],
            vec![PathBuf::from("/Users/test/home")],
            String::new(),
            &Cancellation::default(),
            TEST_PROBE_BUDGET,
        );
        assert_eq!(preview.status, AppRelatedStatus::Failed);
        assert!(
            preview
                .issues
                .iter()
                .any(|issue| issue.code == "invalid_input")
        );
    }

    fn test_library_root(label: &str) -> TestLibraryRoot {
        static UNIQUE: AtomicU64 = AtomicU64::new(0);
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("repo root");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let sequence = UNIQUE.fetch_add(1, Ordering::Relaxed);
        let target = repo_root.join("target");
        fs::create_dir_all(&target).expect("create test target");
        let root = target.join(format!(
            "app-related-unit-{label}-{}-{now}-{sequence}",
            process::id()
        ));
        fs::create_dir(&root).expect("create unique test root");
        let library = root.join("Library");
        fs::create_dir_all(&library).expect("create test root");
        TestLibraryRoot { root, library }
    }
}
