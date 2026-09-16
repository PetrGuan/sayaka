// SPDX-License-Identifier: MPL-2.0

use crate::{human, output, trash};
use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use sayaka_engine::installer_preview::wire::{
    family, native_path as write_native_path, preview_json, status,
};
use sayaka_engine::installer_preview::{
    CandidateNameKind, INSTALLER_KIND, INSTALLER_PREVIEW_SCHEMA_VERSION,
};
use sayaka_engine::installer_preview::{
    INSTALLER_TOTAL_BUDGET, InstallerIssueCode, InstallerPreviewLimits, InstallerPreviewOptions,
    InstallerStatus, preview_installers,
};
use sayaka_engine::model::Cancellation;
use sayaka_engine::scan::{ScanCode, ScanError, display_path};
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub fn command() -> Command {
    let defaults = sayaka_engine::scan::ScanLimits::default();
    let mut command = Command::new("installer")
        .about("Preview installer files; Trash requires explicit selection and terminal confirmation")
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
                .conflicts_with("execute")
                .help("Write one versioned JSON preview to stdout"),
        )
        .arg(
            Arg::new("select").long("select").value_name("PATH")
                .action(ArgAction::Append).value_parser(value_parser!(PathBuf))
                .help("Select recognized current-user installer paths from this preview (max 32)"),
        )
        .arg(
            Arg::new("execute").long("execute").action(ArgAction::SetTrue)
                .help("Select files and confirm the exact sealed Trash plan in an interactive terminal"),
        )
        .arg(
            Arg::new("state-dir").long("state-dir").value_name("DIR")
                .value_parser(value_parser!(PathBuf)).help("Private journal directory; created only after confirmation"),
        )
        .after_help("Default is read-only. Only complete previews of recognized ordinary single-link DMG/PKG files can enter approval.\nNo signature/disposability assessment, mounts, installs, permanent deletion or elevation.\nA replacement after the final check can still move a different file; Trash does not measure freed space or guarantee restoration.")
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
    let execute = args.get_flag("execute");
    if execute
        && !(io::stdin().is_terminal() && io::stdout().is_terminal() && io::stderr().is_terminal())
    {
        return trash::render_error(
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--execute requires an interactive terminal on stdin/stdout/stderr",
            )),
            json,
            "installer",
        );
    }
    let selected = args
        .get_many::<PathBuf>("select")
        .map(|paths| {
            let paths = paths
                .map(|path| {
                    normalize_root(path)
                        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
                })
                .collect::<io::Result<Vec<_>>>()?;
            let unique: std::collections::BTreeSet<_> = paths.iter().collect();
            if paths.is_empty()
                || paths.len() > trash::MAX_SELECTIONS
                || unique.len() != paths.len()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "select between 1 and 32 unique installer paths",
                ));
            }
            Ok(paths)
        })
        .transpose();
    let selected = match selected {
        Ok(paths) => paths,
        Err(error) => return trash::render_error(Err(error), json, "installer"),
    };
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
    let cancellation = Cancellation::default();
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
            if execute || selected.is_some() {
                // Release the output locks before shared terminal/plan rendering.
                drop(stdout);
                drop(stderr);
                return trash::render_error(
                    run_selection(args, &preview, selected, &cancellation, stdout_style),
                    json,
                    "installer",
                );
            }
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

fn write_preview_json(
    out: &mut impl Write,
    preview: &sayaka_engine::installer_preview::InstallerPreview,
) -> io::Result<()> {
    serde_json::to_writer(&mut *out, &preview_json(preview))?;
    writeln!(out)?;
    out.flush()
}

fn run_selection(
    args: &ArgMatches,
    preview: &sayaka_engine::installer_preview::InstallerPreview,
    selected: Option<Vec<PathBuf>>,
    cancellation: &Cancellation,
    style: human::Style,
) -> io::Result<u8> {
    let json = args.get_flag("json");
    let execute = args.get_flag("execute");
    if !preview.selection_ready() || cancellation.is_cancelled() {
        if json {
            trash::print_json_value(&serde_json::json!({
                "schema_version": 1, "kind": "installer_trash_preview",
                "status": "refused", "discovery": preview_json(preview),
                "reason": "complete unchanged discovery is required", "effects_performed": false,
            }))?;
        } else {
            write_preview_human(&mut io::stdout().lock(), preview, style)?;
            writeln!(
                io::stderr().lock(),
                "Installer selection refused: discovery is incomplete or cancelled."
            )?;
        }
        return Ok(if cancellation.is_cancelled() {
            130
        } else {
            match preview.status {
                InstallerStatus::Cancelled => 130,
                InstallerStatus::Failed => 1,
                _ => 3,
            }
        });
    }
    let candidates: Vec<_> = preview
        .candidates
        .iter()
        .filter(|candidate| candidate.selectable())
        .collect();
    if !json {
        write_preview_human(&mut io::stdout().lock(), preview, style)?;
        writeln!(
            io::stdout().lock(),
            "\nOnly recognized current-user single-link files may be selected; native admission may still refuse them.\nFormat hints do not prove trust, disposability, or that a file is not in use."
        )?;
    }
    let selected = match selected {
        Some(paths) => paths,
        None if candidates.is_empty() => {
            writeln!(
                io::stderr().lock(),
                "No recognized current-user installer files can be selected."
            )?;
            return Ok(3);
        }
        None => {
            let mut out = io::stdout().lock();
            writeln!(
                out,
                "Select candidate numbers (comma/range, max 32); blank cancels:"
            )?;
            for (index, candidate) in candidates.iter().enumerate() {
                writeln!(out, "{:>3}. {}", index + 1, display_path(&candidate.path))?;
            }
            out.flush()?;
            write!(io::stderr().lock(), "Selection: ")?;
            io::stderr().flush()?;
            let input = read_terminal_line(cancellation, 256)?;
            let answer = read_selection_line(&mut input.as_bytes())?;
            trash::parse_selection_input(answer.trim(), candidates.len())?
                .into_iter()
                .map(|index| candidates[index - 1].path.clone())
                .collect()
        }
    };
    if selected.is_empty() || cancellation.is_cancelled() {
        writeln!(
            io::stderr().lock(),
            "Cancelled; no files selected or moved."
        )?;
        return Ok(130);
    }
    let mut session =
        sayaka_engine::execute::InstallerSession::prepare(preview, &selected, cancellation)?;
    let refusals = session.refusals();
    if json {
        trash::print_json_value(&serde_json::json!({
            "schema_version": 1, "kind": "installer_trash_preview",
            "status": if session.ready() { "ready_for_confirmation" } else { "refused" },
            "discovery": preview_json(preview),
            "requested": selected.iter().map(|path| write_native_path(path)).collect::<Vec<_>>(),
            "plan": trash::plan_preview_json(session.preview(), &refusals, session.issues())?,
            "effects_performed": false,
        }))?;
    } else {
        writeln!(
            io::stdout().lock(),
            "\nExecution plan (sealed before approval):"
        )?;
        trash::show_plan_preview(session.preview())?;
        for refusal in refusals {
            writeln!(
                io::stdout().lock(),
                "  Refused: {} ({})",
                refusal.path.display,
                refusal.reason
            )?;
        }
        for issue in session.issues() {
            writeln!(
                io::stderr().lock(),
                "Refused {}: {:?}",
                issue.path.display,
                issue.message
            )?;
        }
    }
    if !session.ready() {
        if !json {
            writeln!(
                io::stderr().lock(),
                "Installer batch refused; no subset will be executed."
            )?;
        }
        return Ok(3);
    }
    if !execute {
        return Ok(0);
    }
    let expected = format!("trash {}", session.preview().items().len());
    write!(
        io::stderr().lock(),
        "\nType {expected:?} to move exactly these files, or press Enter to cancel: "
    )?;
    io::stderr().flush()?;
    let answer = read_terminal_line(cancellation, 128)?;
    if !trash::confirmed(&answer, &expected) || cancellation.is_cancelled() {
        writeln!(io::stderr().lock(), "Cancelled; no files moved.")?;
        return Ok(130);
    }
    let approval = session.approve()?;
    let store = sayaka_engine::journal::Store::open(&trash::state_directory(args)?, true)?;
    let report = session.execute(&approval, cancellation, &store)?;
    trash::print_execution_report(&report)?;
    Ok(report.exit_code())
}

fn read_selection_line(input: &mut impl BufRead) -> io::Result<String> {
    let mut answer = String::new();
    input.take(256).read_line(&mut answer)?;
    if !answer.is_empty() && !answer.ends_with('\n') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "selection line is incomplete or exceeds 255 bytes",
        ));
    }
    Ok(answer)
}

fn read_terminal_line(cancellation: &Cancellation, limit: usize) -> io::Result<String> {
    #[cfg(unix)]
    {
        use nix::errno::Errno;
        use nix::sys::select::{FdSet, select};
        use nix::sys::time::{TimeVal, TimeValLike};
        use std::os::fd::AsFd;

        let input = io::stdin().lock();
        let fd = input.as_fd();
        let mut bytes = Vec::new();
        while bytes.len() < limit {
            if cancellation.is_cancelled() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "cancelled while waiting for terminal input",
                ));
            }
            let mut ready = FdSet::new();
            ready.insert(fd);
            let mut timeout = TimeVal::milliseconds(50);
            match select(None, Some(&mut ready), None, None, Some(&mut timeout)) {
                Ok(0) | Err(Errno::EINTR) => continue,
                Ok(_) => {}
                Err(error) => return Err(error.into()),
            }
            // No buffered read-ahead: a pasted next line stays available to the
            // next prompt's readiness check. The terminal remains in cooked mode.
            let mut byte = [0];
            match nix::unistd::read(fd, &mut byte) {
                Ok(0) => break,
                Ok(_) => {
                    bytes.push(byte[0]);
                    if byte[0] == b'\n' {
                        break;
                    }
                }
                Err(Errno::EINTR) => continue,
                Err(error) => return Err(error.into()),
            }
        }
        String::from_utf8(bytes).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "terminal input is not valid UTF-8",
            )
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (cancellation, limit);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "installer terminal approval requires macOS",
        ))
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installer_selection_input_requires_a_complete_bounded_line() {
        assert_eq!(
            read_selection_line(&mut &b"1,3-4\n"[..]).unwrap(),
            "1,3-4\n"
        );
        assert_eq!(read_selection_line(&mut &b"\n"[..]).unwrap(), "\n");
        assert_eq!(read_selection_line(&mut &b""[..]).unwrap(), "");
        assert!(read_selection_line(&mut &b"1,2"[..]).is_err());
        let overlong = format!("{}\ntrash 1\n", "1,".repeat(129));
        assert!(read_selection_line(&mut overlong.as_bytes()).is_err());
    }
}
