// SPDX-License-Identifier: MPL-2.0

use crate::{human, output};
use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use sayaka_engine::app_inventory::{
    APP_INVENTORY_TOTAL_BUDGET, AppInventoryLimits, AppInventoryMetadataReadMode,
    AppInventoryOptions, inventory_apps,
};
use sayaka_engine::app_related::{
    APP_RELATED_KIND, APP_RELATED_SCHEMA_VERSION, AppRelatedPreview, AppRelatedStatus,
    preview_app_related_data,
};
use sayaka_engine::model::Cancellation;
use sayaka_engine::scan::{ScanCode, ScanError, display_path};
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub fn command() -> Command {
    let defaults = sayaka_engine::scan::ScanLimits::default();
    let mut command = Command::new("apps-related")
        .about("Read-only macOS app-related data attribution preview")
        .arg(
            Arg::new("app-roots")
                .long("app-root")
                .required(true)
                .action(ArgAction::Append)
                .num_args(1)
                .value_name("ROOT")
                .help("Explicit app inventory roots (repeatable)")
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("library-roots")
                .long("library-root")
                .required(true)
                .action(ArgAction::Append)
                .num_args(1)
                .value_name("ROOT")
                .help("Explicit Library roots for related-data candidates (repeatable)")
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("filter")
                .long("filter")
                .value_name("TEXT")
                .help("Display narrowing only; does not grant additional permissions"),
        )
        .arg(
            Arg::new("json")
                .long("json")
                .action(ArgAction::SetTrue)
                .help("Write one versioned JSON report to stdout"),
        )
        .arg(
            Arg::new("progress")
                .long("progress")
                .action(ArgAction::SetTrue)
                .help("Show app inventory scan progress on stderr (NDJSON with --json)"),
        );
    for (name, description, default) in [
        ("workers", "Directory workers, 1-32", defaults.workers),
        (
            "queue-capacity",
            "Maximum queued directories",
            defaults.queue_capacity,
        ),
        (
            "max-open-dirs",
            "Directory handle slots; at least workers + 2",
            defaults.max_open_dirs,
        ),
        (
            "max-depth",
            "Directory descent depth below each root",
            defaults.max_depth,
        ),
        (
            "max-entries",
            "Maximum retained entries; reaching it returns partial results",
            defaults.max_entries,
        ),
        (
            "max-path-bytes",
            "Memory budget for retained native paths, in bytes",
            defaults.max_path_bytes,
        ),
    ] {
        command = command.arg(
            Arg::new(name)
                .long(name)
                .value_name("N")
                .help(format!("{description} [default: {default}]"))
                .value_parser(value_parser!(usize)),
        );
    }
    command.arg(
        Arg::new("timeout-ms")
            .long("timeout-ms")
            .value_name("MS")
            .help(format!(
                "Scan+metadata budget in milliseconds (always capped at {})",
                APP_INVENTORY_TOTAL_BUDGET.as_millis()
            ))
            .value_parser(value_parser!(u64)),
    )
}

pub fn run(args: &ArgMatches) -> io::Result<u8> {
    let json = args.get_flag("json");
    let stdout_terminal = io::stdout().is_terminal();
    let stderr_terminal = io::stderr().is_terminal();
    let dumb = std::env::var_os("TERM").is_some_and(|term| term == "dumb");
    let no_color = std::env::var_os("NO_COLOR").is_some();
    let disabled = std::env::var_os("CLICOLOR").is_some_and(|value| value == "0");
    let style = |terminal| human::Style {
        color: human::colors_allowed(terminal && cfg!(unix), no_color, dumb, disabled),
    };
    let stdout_style = style(stdout_terminal);
    let stderr_style = style(stderr_terminal);
    let show_progress =
        args.get_flag("progress") || (!json && stdout_terminal && stderr_terminal && !dumb);
    let mut progress = human::Progress::default();
    let mut stderr = io::stderr().lock();
    let mut stdout = io::stdout().lock();
    let mut progress_error = None;
    let started = Instant::now();
    let result: Result<AppRelatedPreview, ScanError> = (|| {
        let app_roots = normalize_roots(
            args.get_many::<PathBuf>("app-roots")
                .ok_or_else(|| {
                    ScanError::new(ScanCode::InvalidRoot, "at least one --app-root is required")
                })?
                .collect(),
            64,
            "--app-root",
        )?;
        let library_roots = normalize_roots(
            args.get_many::<PathBuf>("library-roots")
                .ok_or_else(|| {
                    ScanError::new(
                        ScanCode::InvalidRoot,
                        "at least one --library-root is required",
                    )
                })?
                .collect(),
            8,
            "--library-root",
        )?;
        validate_library_roots(&library_roots)?;
        let filter = args
            .get_one::<String>("filter")
            .cloned()
            .unwrap_or_default();
        let mut limits = crate::limits(args);
        if limits.time_budget > APP_INVENTORY_TOTAL_BUDGET {
            limits.time_budget = APP_INVENTORY_TOTAL_BUDGET;
        }
        limits.validate()?;
        let cancellation = Cancellation::default();
        let signal = cancellation.clone();
        ctrlc::set_handler(move || signal.cancel()).map_err(|error| {
            ScanError::new(
                ScanCode::Internal,
                format!("cannot install interrupt handler: {error}"),
            )
        })?;
        let report = sayaka_engine::scan::scan_prune_app_bundles(
            &app_roots,
            &limits,
            &cancellation,
            |event| {
                if show_progress && progress_error.is_none() {
                    let written = if json {
                        output::progress(&mut stderr, event)
                    } else {
                        progress.update(&mut stderr, event, stderr_style)
                    };
                    if let Err(error) = written {
                        cancellation.cancel();
                        progress_error = Some(error);
                    }
                }
            },
        )?;
        let remaining_for_inventory = limits
            .time_budget
            .checked_sub(started.elapsed())
            .unwrap_or(Duration::ZERO);
        let inventory = inventory_apps(
            report,
            &AppInventoryOptions {
                filter: String::new(),
                excludes: vec![],
                limits: AppInventoryLimits::default(),
                metadata_read_mode: AppInventoryMetadataReadMode::AppRelated,
                running_attribution: false,
            },
            &cancellation,
            remaining_for_inventory,
        );
        let remaining_for_related = limits
            .time_budget
            .checked_sub(started.elapsed())
            .unwrap_or(Duration::ZERO);
        Ok(preview_app_related_data(
            inventory,
            app_roots,
            library_roots,
            filter,
            &cancellation,
            remaining_for_related,
        ))
    })();

    if let Some(error) = progress_error {
        if json {
            write_fatal_json(
                &mut stdout,
                ScanError::new(ScanCode::Io, format!("progress output failed: {error}")),
            )?;
        }
        return Err(error);
    }

    match result {
        Ok(preview) => {
            if json {
                write_json(&mut stdout, &preview)?;
            } else {
                write_human(&mut stdout, &preview, stdout_style)?;
            }
            stdout.flush()?;
            stderr.flush()?;
            Ok(preview.status.exit_code())
        }
        Err(error) => {
            if json {
                write_fatal_json(&mut stdout, error.clone())?;
            } else {
                human::fatal(&mut stderr, &error, stderr_style)?;
            }
            Ok(
                if matches!(error.code, ScanCode::InvalidRoot | ScanCode::InvalidLimits) {
                    2
                } else {
                    1
                },
            )
        }
    }
}

fn normalize_roots(
    roots: Vec<&PathBuf>,
    max: usize,
    flag: &str,
) -> Result<Vec<PathBuf>, ScanError> {
    let mut resolved = Vec::with_capacity(roots.len());
    for root in roots {
        if root
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err(ScanError::new(
                ScanCode::InvalidRoot,
                format!("{flag} parent traversal is not accepted"),
            ));
        }
        resolved.push(
            std::path::absolute(root)
                .map_err(|error| ScanError::new(ScanCode::InvalidRoot, error.to_string()))?,
        );
    }
    if resolved.is_empty() || resolved.len() > max {
        return Err(ScanError::new(
            ScanCode::InvalidRoot,
            format!("provide between 1 and {max} values for {flag}"),
        ));
    }
    Ok(resolved)
}

fn validate_library_roots(roots: &[PathBuf]) -> Result<(), ScanError> {
    for root in roots {
        if root.file_name().is_none_or(|leaf| leaf != "Library") {
            return Err(ScanError::new(
                ScanCode::InvalidRoot,
                "--library-root must point to an explicit Library directory",
            ));
        }
    }
    Ok(())
}

fn write_human(
    out: &mut impl Write,
    preview: &AppRelatedPreview,
    _style: human::Style,
) -> io::Result<()> {
    writeln!(out, "kind: {}", preview.kind)?;
    writeln!(out, "status: {}", preview.status.as_str())?;
    writeln!(out, "complete: {}", preview.complete)?;
    writeln!(out, "platform: {}", preview.platform)?;
    writeln!(out, "effects_performed: false")?;
    writeln!(
        out,
        "candidate data locations: {}",
        preview.candidates.len()
    )?;
    for candidate in &preview.candidates {
        writeln!(
            out,
            "\n{} [{}]\n  path: {}\n  observed: {}\n  protection: {}",
            candidate.source_rule_id,
            candidate.ownership_certainty,
            display_path(&candidate.path),
            candidate.path_state,
            candidate
                .protection_reasons
                .iter()
                .map(|reason| human_protection_reason(reason))
                .collect::<Vec<_>>()
                .join(", ")
        )?;
    }
    if !preview.scan_issues.is_empty() {
        writeln!(out, "\nscan issues:")?;
        for issue in &preview.scan_issues {
            if let Some(path) = &issue.path {
                writeln!(
                    out,
                    "  - {} {} {}",
                    issue.code.as_str(),
                    display_path(path),
                    escape_human_text(&issue.message)
                )?;
            } else {
                writeln!(
                    out,
                    "  - {} {}",
                    issue.code.as_str(),
                    escape_human_text(&issue.message)
                )?;
            }
        }
    }
    if !preview.issues.is_empty() {
        writeln!(out, "\nissues:")?;
        for issue in &preview.issues {
            if let Some(path) = &issue.path {
                writeln!(
                    out,
                    "  - {} {} {}",
                    issue.code,
                    display_path(path),
                    escape_human_text(&issue.message)
                )?;
            } else {
                writeln!(
                    out,
                    "  - {} {}",
                    issue.code,
                    escape_human_text(&issue.message)
                )?;
            }
        }
    }
    if preview.counts.issues_omitted > 0 {
        writeln!(
            out,
            "issues omitted due to limits: {}",
            preview.counts.issues_omitted
        )?;
    }

    fn escape_human_text(text: &str) -> String {
        text.escape_debug().to_string()
    }
    Ok(())
}

fn human_protection_reason(reason: &str) -> &'static str {
    match reason {
        "persistent_user_profile_or_support_data" => "persistent profile/support data",
        "may_contain_credentials_history_or_preferences" => {
            "may contain credentials/history/preferences"
        }
        "shared_across_profiles_or_app_copies" => "shared across profiles or app copies",
        "cache_but_not_authorized_for_cleanup" => "cache path without cleanup authorization",
        "ownership_not_proven" => "ownership not proven",
        "inventory_or_probe_partial" => "inventory/probe partial",
        "multiple_physical_app_copies" => "multiple physical app copies",
        "running_state_not_checked" => "running state not checked",
        "no_uninstall_or_delete_contract" => "no uninstall/removal contract",
        _ => "protected for manual review",
    }
}

fn write_native_path(path: &Path) -> serde_json::Value {
    use std::fmt::Write;
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let mut raw = String::new();
        for byte in path.as_os_str().as_bytes() {
            write!(raw, "{byte:02x}").expect("write string");
        }
        serde_json::json!({
            "display": display_path(path),
            "encoding": "unix_bytes_hex",
            "raw": raw,
        })
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let mut raw = String::new();
        for unit in path.as_os_str().encode_wide() {
            write!(raw, "{unit:04x}").expect("write string");
        }
        serde_json::json!({
            "display": display_path(path),
            "encoding": "windows_utf16_hex",
            "raw": raw,
        })
    }
}

fn write_json(out: &mut impl Write, preview: &AppRelatedPreview) -> io::Result<()> {
    let value = serde_json::json!({
        "schema_version": APP_RELATED_SCHEMA_VERSION,
        "kind": APP_RELATED_KIND,
        "platform": preview.platform,
        "status": preview.status.as_str(),
        "complete": preview.complete,
        "effects_performed": false,
        "app_roots": preview.app_roots.iter().map(|path| write_native_path(path)).collect::<Vec<_>>(),
        "library_roots": preview.library_roots.iter().map(|path| write_native_path(path)).collect::<Vec<_>>(),
        "filter": preview.filter,
        "scan_task_id": preview.scan_task_id,
        "inventory_status": preview.inventory_status,
        "inventory_complete": preview.inventory_complete,
        "counts": {
            "inventoried_apps": preview.counts.inventoried_apps,
            "matched_app_copies": preview.counts.matched_app_copies,
            "candidate_paths": preview.counts.candidate_paths,
            "present_candidates": preview.counts.present_candidates,
            "missing_candidates": preview.counts.missing_candidates,
            "shared_candidates": preview.counts.shared_candidates,
            "protected_candidates": preview.counts.protected_candidates,
            "issues": preview.counts.issues,
            "issues_omitted": preview.counts.issues_omitted,
        },
        "app_copies": preview.app_copies.iter().map(|copy| serde_json::json!({
            "app_copy_id": copy.app_copy_id,
            "bundle_path": write_native_path(&copy.bundle_path),
            "observed_roots": copy.observed_roots.iter().map(|path| write_native_path(path)).collect::<Vec<_>>(),
            "bundle_identity": copy.bundle_identity,
            "display_name": copy.display_name,
            "bundle_id": copy.bundle_id,
            "short_version": copy.short_version,
            "build_version": copy.build_version,
            "executable": {
                "path_status": copy.executable_path_status,
            },
            "match_rules": copy.match_rules,
            "copy_state": copy.copy_state,
        })).collect::<Vec<_>>(),
        "candidates": preview.candidates.iter().map(|candidate| serde_json::json!({
            "candidate_id": candidate.candidate_id,
            "path": write_native_path(&candidate.path),
            "relative_library_path": candidate.relative_library_path,
            "source_rule_id": candidate.source_rule_id,
            "source_urls": candidate.source_urls,
            "role": candidate.role,
            "path_state": candidate.path_state,
            "ownership_certainty": candidate.ownership_certainty,
            "ownership_statement": candidate.ownership_statement,
            "evidence": candidate.evidence.iter().map(|item| serde_json::json!({
                "kind": item.kind,
                "value": item.value,
                "app_copy_id": item.app_copy_id,
            })).collect::<Vec<_>>(),
            "matched_app_copy_ids": candidate.matched_app_copy_ids,
            "protection_reasons": candidate.protection_reasons,
            "preview_disposition": candidate.preview_disposition,
            "deletable": candidate.deletable,
            "authorized_action": candidate.authorized_action,
        })).collect::<Vec<_>>(),
        "scan_issues": preview.scan_issues.iter().map(|issue| serde_json::json!({
            "path": issue.path.as_deref().map(write_native_path),
            "code": issue.code.as_str(),
            "message": issue.message,
            "os_code": issue.os_code,
        })).collect::<Vec<_>>(),
        "issues": preview.issues.iter().map(|issue| serde_json::json!({
            "path": issue.path.as_deref().map(write_native_path),
            "code": issue.code,
            "message": issue.message,
            "os_code": issue.os_code,
        })).collect::<Vec<_>>(),
        "metrics": {
            "elapsed_ms": preview.metrics.elapsed_ms,
            "inventory_elapsed_ms": preview.metrics.inventory_elapsed_ms,
            "candidate_probe_elapsed_ms": preview.metrics.candidate_probe_elapsed_ms,
            "candidate_probe_count": preview.metrics.candidate_probe_count,
        },
    });
    serde_json::to_writer(&mut *out, &value)?;
    out.write_all(b"\n")?;
    Ok(())
}

fn write_fatal_json(out: &mut impl Write, error: ScanError) -> io::Result<()> {
    let value = serde_json::json!({
        "schema_version": APP_RELATED_SCHEMA_VERSION,
        "kind": APP_RELATED_KIND,
        "platform": if cfg!(target_os = "macos") { "macos" } else { "unsupported" },
        "status": AppRelatedStatus::Failed.as_str(),
        "complete": false,
        "effects_performed": false,
        "app_roots": [],
        "library_roots": [],
        "filter": "",
        "scan_task_id": serde_json::Value::Null,
        "inventory_status": "failed",
        "inventory_complete": false,
        "counts": {
            "inventoried_apps": 0,
            "matched_app_copies": 0,
            "candidate_paths": 0,
            "present_candidates": 0,
            "missing_candidates": 0,
            "shared_candidates": 0,
            "protected_candidates": 0,
            "issues": 1,
            "issues_omitted": 0,
        },
        "app_copies": [],
        "candidates": [],
        "scan_issues": [],
        "issues": [{
            "path": serde_json::Value::Null,
            "code": error.code.as_str(),
            "message": error.message,
            "os_code": error.os_code,
        }],
        "metrics": serde_json::Value::Null,
    });
    serde_json::to_writer(&mut *out, &value)?;
    out.write_all(b"\n")?;
    Ok(())
}
