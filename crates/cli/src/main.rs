// SPDX-License-Identifier: MPL-2.0

mod browser;
mod clean;
mod completions;
mod history;
mod human;
mod lifecycle;
mod output;
mod rules;
mod status;
mod terminal;
mod trash;

use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use sayaka_engine::model::Cancellation;
use sayaka_engine::scan::{self, ScanCode, ScanError, ScanLimits, ScanStatus};
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

fn command() -> Command {
    let defaults = ScanLimits::default();
    let mut scan = Command::new("scan")
        .about("Read-only macOS scan; logical bytes are not reclaimable capacity")
        .arg(
            Arg::new("roots")
                .value_name("ROOT")
                .required(true)
                .num_args(1..)
                .help("Existing directory to scan; use . for the current directory")
                .value_parser(value_parser!(PathBuf)),
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
                .help("Show progress on stderr (NDJSON only with --json)"),
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
        scan = scan.arg(
            Arg::new(name)
                .long(name)
                .value_name("N")
                .help(format!("{description} [default: {default}]"))
                .value_parser(value_parser!(usize)),
        );
    }
    scan = scan.arg(
        Arg::new("timeout-ms")
            .long("timeout-ms")
            .value_name("MS")
            .help(format!(
                "Cooperative scan time budget in milliseconds [default: {}]",
                defaults.time_budget.as_millis()
            ))
            .value_parser(value_parser!(u64)),
    );
    Command::new("sayaka")
        .bin_name("sayaka")
        .version(env!("CARGO_PKG_VERSION"))
        .about("An open-source local maintenance engine and CLI")
        .after_help("Examples:\n  sayaka scan .          Readable read-only report\n  sayaka scan . --json   Machine-readable report\n  sayaka rules list      Built-in read-only rule catalog\n  sayaka rules preview . --rule org.python.cpython.pep3147.source_backed_pyc\n  sayaka rules trash . --rule org.python.cpython.pep3147.source_backed_pyc --select ./pkg/__pycache__/m.cpython-311.pyc\n  sayaka clean .         Clean preview for source-backed __pycache__ .pyc\n  sayaka trash --scope . ./file.txt   Preview one explicit file\n\nScanning and previews never modify targets. Trash requires --execute and terminal confirmation.")
        .arg_required_else_help(true)
        .subcommand(scan)
        .subcommand(trash::command())
        .subcommand(trash::receipt_command())
        .subcommand(browser::command())
        .subcommand(status::command())
        .subcommand(history::command())
        .subcommand(rules::command())
        .subcommand(clean::command())
        .subcommand(completions::command())
        .subcommand(lifecycle::install_command())
        .subcommand(lifecycle::update_command())
        .subcommand(lifecycle::recover_command())
        .subcommand(lifecycle::remove_command())
}

pub(crate) fn limits(args: &ArgMatches) -> ScanLimits {
    let mut limits = ScanLimits::default();
    for (name, destination) in [
        ("workers", &mut limits.workers),
        ("queue-capacity", &mut limits.queue_capacity),
        ("max-open-dirs", &mut limits.max_open_dirs),
        ("max-depth", &mut limits.max_depth),
        ("max-entries", &mut limits.max_entries),
        ("max-path-bytes", &mut limits.max_path_bytes),
    ] {
        if let Some(value) = args.get_one::<usize>(name) {
            *destination = *value;
        }
    }
    if let Some(value) = args.get_one::<u64>("timeout-ms") {
        limits.time_budget = Duration::from_millis(*value);
    }
    limits
}

fn run_scan(args: &ArgMatches) -> io::Result<u8> {
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
    let mut readable_progress = human::Progress::default();
    let limits = limits(args);
    let cancellation = Cancellation::default();
    let mut stderr = io::stderr().lock();
    let mut stdout = io::stdout().lock();
    let mut progress_error = None;
    let result = (|| {
        limits.validate()?;
        let roots = args
            .get_many::<PathBuf>("roots")
            .ok_or_else(|| ScanError::new(ScanCode::InvalidRoot, "at least one root is required"))?
            .map(|root| {
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
            })
            .collect::<Result<Vec<_>, _>>()?;
        let signal_cancellation = cancellation.clone();
        ctrlc::set_handler(move || signal_cancellation.cancel()).map_err(|error| {
            ScanError::new(
                ScanCode::Internal,
                format!("cannot install interrupt handler: {error}"),
            )
        })?;
        scan::scan(&roots, &limits, &cancellation, |progress| {
            if show_progress && progress_error.is_none() {
                let written = if json {
                    output::progress(&mut stderr, progress)
                } else {
                    readable_progress.update(&mut stderr, progress, stderr_style)
                };
                if let Err(error) = written {
                    cancellation.cancel();
                    progress_error = Some(error);
                }
            }
        })
    })();
    if let Some(error) = progress_error {
        let fatal = ScanError::new(ScanCode::Io, format!("progress output failed: {error}"));
        if json {
            output::fatal(&mut stdout, &fatal)?;
        }
        return Err(error);
    }
    match result {
        Ok(report) => {
            if json {
                output::report(&mut stdout, &report)?;
            } else if report.status == ScanStatus::Failed {
                human::report(&mut stderr, &report, stderr_style)?;
                human::notes(&mut stderr, &report, stderr_style)?;
                human::footer(&mut stderr)?;
            } else {
                human::report(&mut stdout, &report, stdout_style)?;
                stdout.flush()?;
                human::notes(&mut stderr, &report, stderr_style)?;
                stderr.flush()?;
                human::footer(&mut stdout)?;
            }
            stdout.flush()?;
            stderr.flush()?;
            Ok(report.status.exit_code())
        }
        Err(error) => {
            if json {
                output::fatal(&mut stdout, &error)?;
            } else {
                human::fatal(&mut stderr, &error, stderr_style)?;
            }
            stdout.flush()?;
            stderr.flush()?;
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

fn run() -> io::Result<u8> {
    let args = match command().try_get_matches() {
        Ok(args) => args,
        Err(error) => {
            let code = error.exit_code() as u8;
            if error.use_stderr() {
                write!(io::stderr().lock(), "{}", human::parser_error(error))?;
            } else {
                write!(io::stdout().lock(), "{error}")?;
            }
            return Ok(code);
        }
    };
    match args.subcommand() {
        Some(("scan", args)) => run_scan(args),
        Some(("trash", args)) => trash::run(args),
        Some(("receipt", args)) => trash::receipt(args),
        Some(("browse" | "analyze", args)) => browser::run(args),
        Some(("status", args)) => status::run(args),
        Some(("history", args)) => history::run(args),
        Some(("rules", args)) => rules::run(args),
        Some(("clean", args)) => clean::run(args),
        Some(("completions", args)) => completions::run(args),
        Some(("install", args)) => lifecycle::run(args, "install"),
        Some(("update", args)) => lifecycle::run(args, "update"),
        Some(("recover", args)) => lifecycle::run(args, "recover"),
        Some(("remove", args)) => lifecycle::run(args, "remove"),
        _ => Ok(2),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "output error: {:?}", error.to_string());
            ExitCode::FAILURE
        }
    }
}
