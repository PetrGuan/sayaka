// SPDX-License-Identifier: MPL-2.0

use crate::{human, output};
use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use sayaka_engine::installer_preview::{
    CandidateNameKind, FormatFamily, FormatStatus, INSTALLER_KIND,
    INSTALLER_PREVIEW_SCHEMA_VERSION, INSTALLER_TOTAL_BUDGET, InstallerIssueCode,
    InstallerPreviewLimits, InstallerPreviewOptions, InstallerStatus, OwnerScope,
    preview_installers,
};
use sayaka_engine::model::Cancellation;
use sayaka_engine::scan::{ScanCode, ScanError, display_path};
use std::fmt::Write as _;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub fn command() -> Command {
    let defaults = sayaka_engine::scan::ScanLimits::default();
    let mut command = Command::new("installer")
        .about("Read-only installer-format discovery for one explicit root")
        .arg(
            Arg::new("root")
                .value_name("ROOT")
                .required(true)
                .help("Existing directory to scan; no implicit HOME/cwd defaults")
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
                .help("Write one versioned JSON preview to stdout"),
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
            "Directory descent depth below root",
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
                "Scan budget in milliseconds (installer scan+probe always capped at {})",
                INSTALLER_TOTAL_BUDGET.as_millis()
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
    let result: Result<sayaka_engine::installer_preview::InstallerPreview, ScanError> = (|| {
        let root = normalize_root(
            args.get_one::<PathBuf>("root")
                .ok_or_else(|| ScanError::new(ScanCode::InvalidRoot, "root is required"))?,
        )?;
        let excludes = normalize_excludes(
            &root,
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
        if limits.time_budget > INSTALLER_TOTAL_BUDGET {
            limits.time_budget = INSTALLER_TOTAL_BUDGET;
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
        let report = sayaka_engine::scan::scan(
            std::slice::from_ref(&root),
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
        let remaining = INSTALLER_TOTAL_BUDGET
            .checked_sub(started.elapsed())
            .unwrap_or(Duration::ZERO);
        Ok(preview_installers(
            report,
            &InstallerPreviewOptions {
                filter,
                excludes,
                limits: InstallerPreviewLimits::default(),
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
        Ok(preview) => {
            if json {
                write_preview_json(&mut stdout, &preview)?;
            } else {
                write_preview_human(&mut stdout, &preview, stdout_style)?;
                stdout.flush()?;
                if !preview.scan_issues.is_empty() {
                    writeln!(
                        stderr,
                        "Scan issues retained: {}",
                        preview.scan_issues.len()
                    )?;
                }
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

fn normalize_root(root: &Path) -> Result<PathBuf, ScanError> {
    if root
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(ScanError::new(
            ScanCode::InvalidRoot,
            "parent traversal is not accepted",
        ));
    }
    std::path::absolute(root)
        .map_err(|error| ScanError::new(ScanCode::InvalidRoot, error.to_string()))
}

fn normalize_excludes(root: &Path, excludes: Vec<&PathBuf>) -> Result<Vec<PathBuf>, ScanError> {
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
        if !(root.starts_with(&absolute) || absolute.starts_with(root)) {
            return Err(ScanError::new(
                ScanCode::InvalidRoot,
                "exclude must overlap the explicit root",
            ));
        }
        resolved.push(absolute);
    }
    Ok(resolved)
}

fn write_preview_human(
    out: &mut impl Write,
    preview: &sayaka_engine::installer_preview::InstallerPreview,
    _style: human::Style,
) -> io::Result<()> {
    let heading = match preview.status {
        InstallerStatus::Complete => "Installer preview complete",
        InstallerStatus::Partial => "Installer preview partial",
        InstallerStatus::Cancelled => "Installer preview cancelled",
        InstallerStatus::Failed => "Installer preview failed",
    };
    writeln!(out, "\nSayaka / Installer preview")?;
    writeln!(out, "----------------------------------------------")?;
    writeln!(out, "  {heading}")?;
    writeln!(out, "  Root         {}", display_path(&preview.root))?;
    writeln!(
        out,
        "  Candidates   {}",
        preview.counts.inspected_candidates
    )?;
    writeln!(
        out,
        "  Logical      {}",
        human::size(preview.bytes.matched_logical_bytes)
    )?;
    writeln!(
        out,
        "  Allocated    {}",
        human::size(preview.bytes.matched_allocated_bytes)
    )?;
    for item in &preview.candidates {
        let name = match item.name_kind {
            CandidateNameKind::Dmg => "dmg",
            CandidateNameKind::Pkg => "pkg",
        };
        writeln!(out, "\n  [{}] {}", name, display_path(&item.path))?;
        writeln!(
            out,
            "     {} / {}",
            family(item.format.family),
            status(item.format.status)
        )?;
        writeln!(out, "     detection: {}", item.format.detection_level)?;
    }
    if !preview.issues.is_empty() {
        writeln!(out, "\n  Issues:")?;
        for issue in preview.issues.iter().take(8) {
            writeln!(out, "    - {} {}", issue.code.as_str(), issue.message)?;
        }
    }
    writeln!(
        out,
        "\n  Notes: structural hints only; no mount/install/signature/provenance assessment."
    )?;
    Ok(())
}

fn family(value: FormatFamily) -> &'static str {
    match value {
        FormatFamily::UdifDmg => "udif_dmg",
        FormatFamily::FlatPkgXar => "flat_pkg_xar",
        FormatFamily::Xar => "xar",
        FormatFamily::Unknown => "unknown",
    }
}

fn status(value: FormatStatus) -> &'static str {
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

fn owner_scope(value: OwnerScope) -> &'static str {
    match value {
        OwnerScope::CurrentUser => "current_user",
        OwnerScope::OtherUser => "other_user",
        OwnerScope::Unknown => "unknown",
    }
}

fn write_native_path(path: &Path) -> serde_json::Value {
    let mut raw = String::new();
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        for byte in path.as_os_str().as_bytes() {
            write!(&mut raw, "{byte:02x}").expect("hex write");
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
        for unit in path.as_os_str().encode_wide() {
            write!(&mut raw, "{unit:04x}").expect("hex write");
        }
        serde_json::json!({
            "display": display_path(path),
            "encoding": "windows_utf16_hex",
            "raw": raw,
        })
    }
}

fn write_preview_json(
    out: &mut impl Write,
    preview: &sayaka_engine::installer_preview::InstallerPreview,
) -> io::Result<()> {
    let value = serde_json::json!({
        "schema_version": INSTALLER_PREVIEW_SCHEMA_VERSION,
        "kind": INSTALLER_KIND,
        "platform": preview.platform,
        "status": preview.status.as_str(),
        "complete": preview.complete,
        "effects_performed": preview.effects_performed,
        "root": write_native_path(&preview.root),
        "filters": {
            "text": preview.filter,
            "excludes": preview.excludes.iter().map(|path| write_native_path(path)).collect::<Vec<_>>(),
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
        "bytes": {
            "matched_logical_bytes": preview.bytes.matched_logical_bytes,
            "matched_logical_unknown_files": preview.bytes.matched_logical_unknown_files,
            "matched_allocated_bytes": preview.bytes.matched_allocated_bytes,
            "matched_allocated_unknown_files": preview.bytes.matched_allocated_unknown_files,
            "matched_sizes_are_reclaimable": false,
        },
        "candidates": preview.candidates.iter().map(|candidate| serde_json::json!({
            "path": write_native_path(&candidate.path),
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
        })).collect::<Vec<_>>(),
        "scan_issues": preview.scan_issues.iter().map(|issue| serde_json::json!({
            "path": issue.path.as_deref().map(write_native_path),
            "code": issue.code.as_str(),
            "message": issue.message,
            "os_code": issue.os_code,
        })).collect::<Vec<_>>(),
        "issues": preview.issues.iter().map(|issue| serde_json::json!({
            "path": issue.path.as_deref().map(write_native_path),
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
    });
    serde_json::to_writer(&mut *out, &value)?;
    writeln!(out)?;
    out.flush()
}

fn write_fatal_json(out: &mut impl Write, error: ScanError) -> io::Result<()> {
    let value = serde_json::json!({
        "schema_version": INSTALLER_PREVIEW_SCHEMA_VERSION,
        "kind": INSTALLER_KIND,
        "platform": if cfg!(target_os = "macos") { "macos" } else if cfg!(windows) { "windows" } else { "unsupported" },
        "status": "failed",
        "complete": false,
        "effects_performed": false,
        "root": null,
        "filters": { "text": "", "excludes": [] },
        "scan_task_id": null,
        "counts": null,
        "bytes": null,
        "candidates": [],
        "scan_issues": [],
        "issues": [{
            "path": null,
            "code": match error.code {
                ScanCode::InvalidRoot | ScanCode::InvalidLimits => InstallerIssueCode::InvalidInput.as_str(),
                ScanCode::Cancelled => InstallerIssueCode::Cancelled.as_str(),
                _ => InstallerIssueCode::Internal.as_str(),
            },
            "message": error.message,
            "os_code": error.os_code,
        }],
        "issues_omitted": 0,
        "metrics": null,
    });
    serde_json::to_writer(&mut *out, &value)?;
    writeln!(out)?;
    out.flush()
}
