// SPDX-License-Identifier: MPL-2.0

use crate::{human, output};
use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use sayaka_engine::app_inventory::{
    APP_INVENTORY_KIND, APP_INVENTORY_SCHEMA_VERSION, APP_INVENTORY_TOTAL_BUDGET, AppInventory,
    AppInventoryLimits, AppInventoryMetadataReadMode, AppInventoryOptions, RunningObservation,
    StringField, StringState, inventory_apps,
};
use sayaka_engine::model::Cancellation;
use sayaka_engine::scan::{ScanCode, ScanError, display_path};
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub fn command() -> Command {
    let defaults = sayaka_engine::scan::ScanLimits::default();
    let mut command = Command::new("apps")
        .about("Read-only macOS app inventory for explicit roots")
        .arg(
            Arg::new("roots")
                .value_name("ROOT")
                .required(true)
                .num_args(1..)
                .help("Existing explicit directories to scan; no implicit HOME/cwd defaults")
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("filter")
                .long("filter")
                .value_name("TEXT")
                .help("Display narrowing only; does not grant additional permissions"),
        )
        .arg(
            Arg::new("exclude")
                .long("exclude")
                .value_name("PATH")
                .action(ArgAction::Append)
                .value_parser(value_parser!(PathBuf))
                .help("Explicit path exclusion (repeatable)"),
        )
        .arg(
            Arg::new("json")
                .long("json")
                .action(ArgAction::SetTrue)
                .help("Write one versioned JSON report to stdout"),
        )
        .arg(
            Arg::new("running")
                .long("running")
                .action(ArgAction::SetTrue)
                .help("Opt-in read-only attribution of running processes by exact executable path"),
        )
        .arg(
            Arg::new("progress")
                .long("progress")
                .action(ArgAction::SetTrue)
                .help("Show scan progress on stderr (NDJSON with --json)"),
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
    let result: Result<AppInventory, ScanError> = (|| {
        let roots = normalize_roots(
            args.get_many::<PathBuf>("roots")
                .ok_or_else(|| {
                    ScanError::new(ScanCode::InvalidRoot, "at least one root is required")
                })?
                .collect(),
        )?;
        let excludes = normalize_excludes(
            &roots,
            args.get_many::<PathBuf>("exclude")
                .into_iter()
                .flatten()
                .collect(),
        )?;
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
        let report =
            sayaka_engine::scan::scan_prune_app_bundles(&roots, &limits, &cancellation, |event| {
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
            })?;

        let remaining = limits
            .time_budget
            .checked_sub(started.elapsed())
            .unwrap_or(Duration::ZERO);
        Ok(inventory_apps(
            report,
            &AppInventoryOptions {
                filter,
                excludes,
                limits: AppInventoryLimits::default(),
                metadata_read_mode: AppInventoryMetadataReadMode::Baseline,
                running_attribution: args.get_flag("running"),
            },
            &cancellation,
            remaining,
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
        Ok(inventory) => {
            if json {
                write_inventory_json(&mut stdout, &inventory)?;
            } else {
                write_inventory_human(&mut stdout, &inventory, stdout_style)?;
                stdout.flush()?;
                if !inventory.scan_issues.is_empty() {
                    writeln!(
                        stderr,
                        "Scan issues retained: {}",
                        inventory.scan_issues.len()
                    )?;
                }
            }
            stdout.flush()?;
            stderr.flush()?;
            Ok(inventory.status.exit_code())
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

fn normalize_roots(roots: Vec<&PathBuf>) -> Result<Vec<PathBuf>, ScanError> {
    let mut resolved = Vec::with_capacity(roots.len());
    for root in roots {
        if root
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err(ScanError::new(
                ScanCode::InvalidRoot,
                "parent traversal is not accepted",
            ));
        }
        resolved.push(
            std::path::absolute(root)
                .map_err(|error| ScanError::new(ScanCode::InvalidRoot, error.to_string()))?,
        );
    }
    if resolved.is_empty() || resolved.len() > 64 {
        return Err(ScanError::new(
            ScanCode::InvalidRoot,
            "provide between 1 and 64 explicit roots",
        ));
    }
    Ok(resolved)
}

fn normalize_excludes(
    roots: &[PathBuf],
    excludes: Vec<&PathBuf>,
) -> Result<Vec<PathBuf>, ScanError> {
    let mut resolved = Vec::new();
    for exclude in excludes {
        if exclude
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err(ScanError::new(
                ScanCode::InvalidRoot,
                "exclude parent traversal is not accepted",
            ));
        }
        let absolute = std::path::absolute(exclude)
            .map_err(|error| ScanError::new(ScanCode::InvalidRoot, error.to_string()))?;
        let overlaps_any_root = roots
            .iter()
            .any(|root| root.starts_with(&absolute) || absolute.starts_with(root));
        if !overlaps_any_root {
            return Err(ScanError::new(
                ScanCode::InvalidRoot,
                "exclude must overlap at least one explicit root",
            ));
        }
        resolved.push(absolute);
    }
    Ok(resolved)
}

fn write_inventory_human(
    out: &mut impl Write,
    inventory: &AppInventory,
    _style: human::Style,
) -> io::Result<()> {
    writeln!(out, "kind: {}", inventory.kind)?;
    writeln!(out, "status: {}", inventory.status.as_str())?;
    writeln!(out, "complete: {}", inventory.complete)?;
    writeln!(out, "platform: {}", inventory.platform)?;
    writeln!(out, "effects_performed: false")?;
    writeln!(out, "roots: {}", inventory.roots.len())?;
    for root in &inventory.roots {
        writeln!(out, "  - {}", display_path(root))?;
    }
    writeln!(out, "apps:")?;
    for app in &inventory.apps {
        writeln!(
            out,
            "  - {} [{}] id={} version={} build={} path={}",
            app.display_name,
            app.app_kind.as_str(),
            field_value(&app.bundle_id),
            field_value(&app.short_version),
            field_value(&app.build_version),
            display_path(&app.bundle_path)
        )?;
        match &app.running {
            RunningObservation::NotChecked => {}
            RunningObservation::Running(pids) => {
                writeln!(out, "    running: yes (pids: {pids:?})")?;
            }
            RunningObservation::NotRunning => {
                writeln!(out, "    running: no matching process observed")?;
            }
            RunningObservation::NotAttributable(reason) => {
                writeln!(out, "    running: not attributable ({reason})")?;
            }
            RunningObservation::Unknown => {
                writeln!(out, "    running: unknown (process enumeration failed)")?;
            }
        }
    }
    if !inventory.issues.is_empty() {
        writeln!(out, "issues:")?;
        for issue in &inventory.issues {
            if let Some(path) = &issue.path {
                writeln!(
                    out,
                    "  - {} {} {}",
                    issue.code.as_str(),
                    display_path(path),
                    issue.message
                )?;
            } else {
                writeln!(out, "  - {} {}", issue.code.as_str(), issue.message)?;
            }
        }
    }
    Ok(())
}

fn field_value(field: &StringField) -> String {
    match field.state {
        StringState::Present => field.value.clone().unwrap_or_default(),
        _ => format!("({})", field.state.as_str()),
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

fn write_string_field(field: &StringField) -> serde_json::Value {
    serde_json::json!({
        "state": field.state.as_str(),
        "value": field.value,
    })
}

fn write_inventory_json(out: &mut impl Write, inventory: &AppInventory) -> io::Result<()> {
    let value = serde_json::json!({
        "schema_version": APP_INVENTORY_SCHEMA_VERSION,
        "kind": APP_INVENTORY_KIND,
        "platform": inventory.platform,
        "status": inventory.status.as_str(),
        "complete": inventory.complete,
        "effects_performed": false,
        "roots": inventory.roots.iter().map(|path| write_native_path(path)).collect::<Vec<_>>(),
        "filter": inventory.filter,
        "excludes": inventory.excludes.iter().map(|path| write_native_path(path)).collect::<Vec<_>>(),
        "scan_task_id": inventory.scan_task_id,
        "counts": {
            "scan_entries": inventory.counts.scan_entries,
            "scan_issues": inventory.counts.scan_issues,
            "named_candidates": inventory.counts.named_candidates,
            "inspected_candidates": inventory.counts.inspected_candidates,
            "recognized_apps": inventory.counts.recognized_apps,
            "unknown": inventory.counts.unknown,
            "non_app": inventory.counts.non_app,
            "duplicates_by_identity": inventory.counts.duplicate_identities,
            "metadata_issues": inventory.counts.metadata_issues,
        },
        "apps": inventory.apps.iter().map(|app| serde_json::json!({
            "bundle_path": write_native_path(&app.bundle_path),
            "observed_roots": app.observed_roots.iter().map(|path| write_native_path(path)).collect::<Vec<_>>(),
            "bundle_identity": app.bundle_identity,
            "app_kind": app.app_kind.as_str(),
            "parser_format": app.parser_format.as_str(),
            "display_name": {
                "value": app.display_name,
                "source": app.display_name_source.as_str(),
                "localized": app.localized,
            },
            "bundle_id": write_string_field(&app.bundle_id),
            "short_version": write_string_field(&app.short_version),
            "build_version": write_string_field(&app.build_version),
            "package_type": write_string_field(&app.package_type),
            "executable": {
                "state": app.executable.state.as_str(),
                "declared_value": app.executable.declared_value,
                "path_status": app.executable.path_status.as_str(),
            },
            "running": {
                "state": app.running.as_str(),
                "pids": match &app.running {
                    RunningObservation::Running(pids) => serde_json::json!(pids),
                    _ => serde_json::Value::Null,
                },
                "reason": match &app.running {
                    RunningObservation::NotAttributable(reason) => serde_json::json!(reason),
                    _ => serde_json::Value::Null,
                },
            },
            "trust": {
                "signature": "not_read",
                "app_store_receipt": "not_read",
                "quarantine": "not_read",
            },
        })).collect::<Vec<_>>(),
        "scan_issues": inventory.scan_issues.iter().map(|issue| serde_json::json!({
            "path": issue.path.as_deref().map(write_native_path),
            "code": issue.code.as_str(),
            "message": issue.message,
            "os_code": issue.os_code,
        })).collect::<Vec<_>>(),
        "issues": inventory.issues.iter().map(|issue| serde_json::json!({
            "path": issue.path.as_deref().map(write_native_path),
            "code": issue.code.as_str(),
            "message": issue.message,
            "os_code": issue.os_code,
        })).collect::<Vec<_>>(),
        "issues_omitted": inventory.issues_omitted,
        "metrics": {
            "elapsed_ms": inventory.metrics.elapsed_ms,
            "probe_elapsed_ms": inventory.metrics.probe_elapsed_ms,
            "plist_read_bytes": inventory.metrics.plist_read_bytes,
            "retained_metadata_string_bytes": inventory.metrics.retained_metadata_string_bytes,
        }
    });
    serde_json::to_writer(&mut *out, &value)?;
    out.write_all(b"\n")?;
    Ok(())
}

fn write_fatal_json(out: &mut impl Write, error: ScanError) -> io::Result<()> {
    let value = serde_json::json!({
        "schema_version": APP_INVENTORY_SCHEMA_VERSION,
        "kind": APP_INVENTORY_KIND,
        "platform": if cfg!(target_os = "macos") { "macos" } else { "unsupported" },
        "status": "failed",
        "complete": false,
        "effects_performed": false,
        "roots": [],
        "filter": "",
        "excludes": [],
        "scan_task_id": serde_json::Value::Null,
        "counts": {
            "scan_entries": 0,
            "scan_issues": 0,
            "named_candidates": 0,
            "inspected_candidates": 0,
            "recognized_apps": 0,
            "unknown": 0,
            "non_app": 0,
            "duplicates_by_identity": 0,
            "metadata_issues": 0,
        },
        "apps": [],
        "scan_issues": [],
        "issues": [{
            "path": serde_json::Value::Null,
            "code": error.code.as_str(),
            "message": error.message,
            "os_code": error.os_code,
        }],
        "issues_omitted": 0,
        "metrics": serde_json::Value::Null,
    });
    serde_json::to_writer(&mut *out, &value)?;
    out.write_all(b"\n")?;
    Ok(())
}
