// SPDX-License-Identifier: MPL-2.0

mod apps;
mod apps_related;
mod browser;
mod clean;
mod completions;
mod history;
mod human;
mod installer;
mod lifecycle;
mod menu;
mod output;
mod rules;
mod status;
mod terminal;
mod trash;

use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use sayaka_engine::model::Cancellation;
use sayaka_engine::scan::{self, ScanCode, ScanError, ScanLimits, ScanStatus};
use serde::Serialize;
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

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
        )
        .arg(
            Arg::new("profile-scan-stderr")
                .long("profile-scan-stderr")
                .action(ArgAction::SetTrue)
                .requires("json")
                .help("Diagnostic: write one scan phase profile JSON line to stderr (--json only)"),
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
        .after_help("Examples:\n  sayaka scan .          Readable read-only report\n  sayaka scan . --json   Machine-readable report\n  sayaka menu            Guided terminal entry for browse/rule previews/approval\n  sayaka installer .     Read-only installer discovery\n  sayaka installer . --json\n  sayaka apps .          Read-only macOS app inventory\n  sayaka apps . --json\n  sayaka apps-related --app-root /Applications --library-root \"$HOME/Library\"\n  sayaka apps-related --app-root /Applications --library-root \"$HOME/Library\" --json\n  sayaka rules list      Built-in read-only rule catalog\n  sayaka rules preview . --rule org.python.cpython.pep3147.source_backed_pyc\n  sayaka rules preview . --rule org.openjdk.javac.source_backed_class\n  sayaka rules trash . --rule org.python.cpython.pep3147.source_backed_pyc --select ./pkg/__pycache__/m.cpython-311.pyc\n  sayaka rules trash . --rule org.openjdk.javac.source_backed_class --select ./Foo.class\n  sayaka clean .         Clean preview for CPython source-backed __pycache__ .pyc\n  sayaka clean . --rule org.openjdk.javac.source_backed_class\n  sayaka trash --scope . ./file.txt   Preview one explicit file\n\nScanning and previews never modify targets. Trash requires --execute and terminal confirmation.")
        .arg_required_else_help(true)
        .subcommand(scan)
        .subcommand(apps::command())
        .subcommand(apps_related::command())
        .subcommand(trash::command())
        .subcommand(trash::receipt_command())
        .subcommand(browser::command())
        .subcommand(status::command())
        .subcommand(history::command())
        .subcommand(installer::command())
        .subcommand(menu::command())
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

#[derive(Serialize)]
struct ScanProfileRecord<'a> {
    schema_version: u8,
    #[serde(rename = "type")]
    record_type: &'static str,
    status: &'a str,
    main_to_dispatch_ms: Option<f64>,
    setup_ms: Option<f64>,
    scan_ms: Option<f64>,
    json_encode_write_flush_ms: Option<f64>,
    stdout_json_bytes: Option<usize>,
    engine_elapsed_ms: Option<u64>,
    output_error: Option<&'a str>,
}

fn as_ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

fn emit_scan_profile(stderr: &mut impl Write, record: &ScanProfileRecord<'_>) -> io::Result<()> {
    serde_json::to_writer(&mut *stderr, record).map_err(io::Error::other)?;
    stderr.write_all(b"\n")?;
    stderr.flush()
}

fn run_scan(args: &ArgMatches, run_start: Instant) -> io::Result<u8> {
    let dispatch_start = Instant::now();
    let json = args.get_flag("json");
    let profile_scan = args.get_flag("profile-scan-stderr");
    if profile_scan && !json {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--profile-scan-stderr requires --json",
        ));
    }
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
    let main_to_dispatch_ms = profile_scan.then(|| as_ms(dispatch_start.duration_since(run_start)));
    let setup_start = dispatch_start;
    let mut setup_ms = None;
    let mut scan_ms = None;
    let mut json_encode_write_flush_ms = None;
    let mut stdout_json_bytes = None;
    let mut output_error: Option<String> = None;
    let mut progress_error = None;
    let result: Result<scan::ScanReport, ScanError> = (|| {
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
        if profile_scan {
            setup_ms = Some(as_ms(setup_start.elapsed()));
        }
        let scan_start = profile_scan.then(Instant::now);
        let report = scan::scan(&roots, &limits, &cancellation, |progress| {
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
        });
        scan_ms = scan_start.map(|start| as_ms(start.elapsed()));
        report
    })();
    if profile_scan && setup_ms.is_none() {
        setup_ms = Some(as_ms(setup_start.elapsed()));
    }
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
                if profile_scan {
                    let output_start = Instant::now();
                    let counted = output::report_with_count(&mut stdout, &report);
                    match counted {
                        Ok(bytes) => {
                            stdout.flush()?;
                            json_encode_write_flush_ms = Some(as_ms(output_start.elapsed()));
                            stdout_json_bytes = Some(bytes);
                        }
                        Err(error) => {
                            output_error = Some(format!("{:?}", error.kind()));
                            if profile_scan {
                                let profile = ScanProfileRecord {
                                    schema_version: 1,
                                    record_type: "scan_profile",
                                    status: "failed",
                                    main_to_dispatch_ms,
                                    setup_ms,
                                    scan_ms,
                                    json_encode_write_flush_ms,
                                    stdout_json_bytes,
                                    engine_elapsed_ms: Some(report.metrics.elapsed_ms),
                                    output_error: output_error.as_deref(),
                                };
                                if let Err(profile_error) = emit_scan_profile(&mut stderr, &profile)
                                {
                                    return Err(io::Error::new(
                                        error.kind(),
                                        format!(
                                            "{error}; profile output also failed: {profile_error}"
                                        ),
                                    ));
                                }
                            }
                            return Err(error);
                        }
                    }
                } else {
                    output::report(&mut stdout, &report)?;
                }
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
            if profile_scan {
                let profile = ScanProfileRecord {
                    schema_version: 1,
                    record_type: "scan_profile",
                    status: report.status.as_str(),
                    main_to_dispatch_ms,
                    setup_ms,
                    scan_ms,
                    json_encode_write_flush_ms,
                    stdout_json_bytes,
                    engine_elapsed_ms: Some(report.metrics.elapsed_ms),
                    output_error: output_error.as_deref(),
                };
                emit_scan_profile(&mut stderr, &profile)?;
            }
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
            if profile_scan {
                let profile = ScanProfileRecord {
                    schema_version: 1,
                    record_type: "scan_profile",
                    status: "failed",
                    main_to_dispatch_ms,
                    setup_ms,
                    scan_ms,
                    json_encode_write_flush_ms,
                    stdout_json_bytes,
                    engine_elapsed_ms: None,
                    output_error: Some(error.code.as_str()),
                };
                emit_scan_profile(&mut stderr, &profile)?;
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

fn run() -> io::Result<u8> {
    let run_start = Instant::now();
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
        Some(("scan", args)) => run_scan(args, run_start),
        Some(("apps", args)) => apps::run(args),
        Some(("apps-related", args)) => apps_related::run(args),
        Some(("trash", args)) => trash::run(args),
        Some(("receipt", args)) => trash::receipt(args),
        Some(("browse" | "analyze", args)) => browser::run(args),
        Some(("status", args)) => status::run(args),
        Some(("history", args)) => history::run(args),
        Some(("installer", args)) => installer::run(args),
        Some(("menu", args)) => menu::run(args),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_record_serializes_expected_shape() {
        let record = ScanProfileRecord {
            schema_version: 1,
            record_type: "scan_profile",
            status: "complete",
            main_to_dispatch_ms: Some(1.25),
            setup_ms: Some(0.5),
            scan_ms: Some(9.0),
            json_encode_write_flush_ms: Some(2.0),
            stdout_json_bytes: Some(1234),
            engine_elapsed_ms: Some(8),
            output_error: None,
        };
        let mut buffer = Vec::new();
        emit_scan_profile(&mut buffer, &record).expect("emit profile");
        let value: serde_json::Value = serde_json::from_slice(&buffer).expect("json");
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["type"], "scan_profile");
        assert_eq!(value["stdout_json_bytes"], 1234);
        assert!(value["output_error"].is_null());
    }
}
