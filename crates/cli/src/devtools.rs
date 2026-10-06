// SPDX-License-Identifier: MPL-2.0

//! `sayaka devtools simulators`: permanent simulator erase/delete through
//! Apple's `simctl` (docs/SIMULATOR_CLEANUP.md, slice 1a).

use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use std::io::{self, Write};
use std::path::PathBuf;

pub fn command() -> Command {
    Command::new("devtools")
        .about("Developer tool data owned by Apple tools (macOS)")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("simulators")
                .about("Preview simulator devices, or PERMANENTLY erase/delete explicitly selected ones")
                .arg(
                    Arg::new("operation")
                        .long("operation")
                        .value_name("KIND")
                        .required(true)
                        .value_parser(["erase", "delete"])
                        .help("erase: wipe a device's apps and data, keep the device; delete: remove the device"),
                )
                .arg(
                    Arg::new("json")
                        .long("json")
                        .action(ArgAction::SetTrue)
                        .help("Write one versioned JSON preview to stdout"),
                )
                .arg(
                    Arg::new("execute")
                        .long("execute")
                        .action(ArgAction::SetTrue)
                        .help("Run the operation on the --only devices after typed confirmation (120-second approval)"),
                )
                .arg(
                    Arg::new("only")
                        .long("only")
                        .value_name("UDID")
                        .action(ArgAction::Append)
                        .help("Device UDID from this invocation's preview (repeatable, 1..32; a pair needs both)"),
                )
                .arg(
                    Arg::new("state-dir")
                        .long("state-dir")
                        .value_name("DIR")
                        .value_parser(value_parser!(PathBuf))
                        .help("Private journal directory for the durable intent/outcome record"),
                ),
        )
        .after_help(
            "Default is a read-only preview. Erase and delete are PERMANENT: nothing moves to Trash and\nnothing can be restored. Quit Xcode, Simulator and test runs first; only shut-down devices are\noffered. Sizes are CoreSimulator estimates, not guaranteed freed space.",
        )
}

pub fn run(args: &ArgMatches) -> io::Result<u8> {
    let Some(("simulators", args)) = args.subcommand() else {
        return Ok(2);
    };
    match imp::run(args) {
        Ok(code) => Ok(code),
        Err(error) => {
            writeln!(
                io::stderr().lock(),
                "devtools simulators failed: {:?}",
                error.to_string()
            )?;
            Ok(if error.kind() == io::ErrorKind::InvalidInput {
                2
            } else {
                1
            })
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::*;

    pub(super) fn run(_: &ArgMatches) -> io::Result<u8> {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "simulator cleanup is macOS only",
        ))
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    use sayaka_engine::devtools::session::{
        ExecuteRequest, MacHost, SessionError, SimulatorSession,
    };
    use sayaka_engine::devtools::{Candidate, Operation};
    use sayaka_engine::model::Cancellation;
    use std::io::{BufRead, IsTerminal, Read};

    fn invalid(message: impl Into<String>) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, message.into())
    }

    fn session_error(error: SessionError) -> io::Error {
        let kind = match error {
            SessionError::InvalidRequest { .. } => io::ErrorKind::InvalidInput,
            _ => io::ErrorKind::Other,
        };
        io::Error::new(kind, error.to_string())
    }

    fn size(bytes: Option<u64>) -> String {
        match bytes {
            Some(bytes) if bytes >= 1_000_000_000 => format!("~{:.1} GB", bytes as f64 / 1e9),
            Some(bytes) => format!("~{} MB", bytes.div_ceil(1_000_000)),
            None => "size unknown".into(),
        }
    }

    fn runtime(identifier: &str) -> &str {
        identifier
            .strip_prefix("com.apple.CoreSimulator.SimRuntime.")
            .unwrap_or(identifier)
    }

    fn describe(candidate: &Candidate) -> String {
        let device = &candidate.device;
        let mut line = format!(
            "{}  {}  {}  {}  {}",
            device.udid,
            device.name,
            runtime(&device.runtime_identifier),
            device.state,
            size(device.data_path_size)
        );
        if !device.is_available {
            line.push_str("  unavailable");
        }
        if let Some(partner) = &candidate.paired_with {
            line.push_str(&format!("  paired with {partner}"));
        }
        line
    }

    pub(super) fn run(args: &ArgMatches) -> io::Result<u8> {
        let operation = match args.get_one::<String>("operation").map(String::as_str) {
            Some("erase") => Operation::Erase,
            _ => Operation::Delete,
        };
        let json = args.get_flag("json");
        let execute = args.get_flag("execute");
        let only: Vec<String> = args
            .get_many::<String>("only")
            .into_iter()
            .flatten()
            .map(|udid| udid.to_ascii_uppercase())
            .collect();
        if execute {
            if json {
                return Err(invalid(
                    "--json applies to the read-only preview; --execute prints a journaled report",
                ));
            }
            if !(io::stdin().is_terminal()
                && io::stdout().is_terminal()
                && io::stderr().is_terminal())
            {
                return Err(invalid(
                    "--execute requires an interactive terminal; piped approval is not accepted",
                ));
            }
            if only.is_empty() {
                return Err(invalid(
                    "--execute without --only selects nothing and is refused",
                ));
            }
        } else if !only.is_empty() {
            return Err(invalid("--only requires --execute"));
        }
        let cancellation = Cancellation::default();
        let signal = cancellation.clone();
        // Ctrl-C skips batches not yet started; a running simctl call finishes.
        ctrlc::set_handler(move || signal.cancel()).map_err(io::Error::other)?;
        let host = MacHost::new().map_err(session_error)?;
        let mut session =
            SimulatorSession::prepare(host, operation, &cancellation).map_err(session_error)?;
        let preview = session.preview();
        if json {
            let mut out = io::stdout().lock();
            serde_json::to_writer(&mut out, preview)?;
            writeln!(out)?;
            return Ok(0);
        }
        {
            let mut out = io::stdout().lock();
            writeln!(
                out,
                "Simulator {} preview (PERMANENT, not Trash; nothing is selected)",
                operation.verb()
            )?;
            for candidate in &preview.candidates {
                let refusals = if candidate.eligible() {
                    String::new()
                } else {
                    format!(
                        "  refused: {}",
                        serde_json::to_string(&candidate.refusals).unwrap_or_default()
                    )
                };
                writeln!(out, "  {}{refusals}", describe(candidate))?;
            }
            if !preview.developer_activity.is_empty() {
                writeln!(
                    out,
                    "Developer tools are running; execution is refused until they quit:"
                )?;
                for path in &preview.developer_activity {
                    writeln!(out, "  {path}")?;
                }
            }
            writeln!(
                out,
                "Sizes are CoreSimulator estimates of the data directory; freed space is not guaranteed."
            )?;
        }
        if !execute {
            return Ok(0);
        }
        let selected: Vec<&Candidate> = only
            .iter()
            .filter_map(|udid| preview.candidates.iter().find(|c| &c.device.udid == udid))
            .collect();
        let count = only.len();
        let expected = operation.approval_phrase(count);
        let request = ExecuteRequest {
            plan_digest: preview.plan_digest.clone(),
            items: only.clone(),
            approval_token: expected.clone(),
        };
        session.check_approval(&request).map_err(session_error)?;
        {
            let mut err = io::stderr().lock();
            writeln!(
                err,
                "\nThese {count} simulators will be PERMANENTLY {}d. Nothing moves to Trash; this cannot be undone:",
                operation.verb()
            )?;
            for candidate in &selected {
                writeln!(err, "  - {}", describe(candidate))?;
            }
            writeln!(
                err,
                "Lost: {}",
                match operation {
                    Operation::Erase =>
                        "every app, its data and settings on each device; the devices remain",
                    Operation::Delete => "each device with all of its apps, data and settings",
                }
            )?;
            write!(
                err,
                "Type {expected:?} to continue, or press Enter to cancel: "
            )?;
            err.flush()?;
        }
        let mut answer = String::new();
        io::stdin().lock().take(128).read_line(&mut answer)?;
        if !crate::trash::confirmed(&answer, &expected) || cancellation.is_cancelled() {
            writeln!(io::stderr().lock(), "Cancelled; nothing changed.")?;
            return Ok(130);
        }
        let state_dir = crate::trash::state_directory(args)?;
        let report = session
            .execute(&request, &cancellation, &state_dir)
            .map_err(session_error)?;
        let mut out = io::stdout().lock();
        writeln!(out, "\nOperation {}", report.record.operation_id)?;
        let devices = report
            .record
            .tool_operation
            .as_ref()
            .map(|operation| operation.devices.as_slice())
            .unwrap_or_default();
        for (item, device) in report.record.items.iter().zip(devices) {
            writeln!(
                out,
                "{:?}  {} ({}){}",
                item.state,
                device.name,
                device.udid,
                item.reason
                    .as_ref()
                    .map(|reason| format!(": {reason}"))
                    .unwrap_or_default()
            )?;
        }
        if let Some(error) = &report.journal_error {
            writeln!(out, "Journal error: {error}")?;
        }
        writeln!(
            out,
            "Permanent: nothing was moved to Trash. Unknown items are reconciled by a fresh preview, never retried."
        )?;
        Ok(report.exit_code())
    }
}
