// SPDX-License-Identifier: MPL-2.0
//! Shared read-only diagnostic CLI. No alternate subprocess executor.
use clap::{Arg, ArgAction, ArgMatches, Command};
use sayaka_engine::readonly_diagnostics::{self, Id};
use std::io::{self, Write};
const IDS: [(&str, Id); 10] = [
    ("disk", Id::Disk),
    ("login-items", Id::LoginItems),
    ("network", Id::Network),
    ("home-permissions", Id::HomePermissions),
    ("spotlight", Id::Spotlight),
    ("spotlight-exclusions", Id::SpotlightExclusions),
    ("network-dsstore", Id::NetworkDsstore),
    ("legacy-overrides", Id::LegacyOverrides),
    ("sudo-touch-id", Id::SudoTouchId),
    ("periodic-availability", Id::PeriodicAvailability),
];
pub fn command() -> Command {
    let mut command = Command::new("diagnose")
        .about("Read-only observations; never repair or change settings")
        .subcommand_required(true)
        .arg_required_else_help(true);
    for (name, _) in IDS {
        let mut sub =
            Command::new(name).arg(Arg::new("json").long("json").action(ArgAction::SetTrue));
        if name == "disk" {
            sub =
                sub.arg(Arg::new("volume").long("volume").value_parser(["/"]).help(
                    "Compatibility selector: boot volume only; other volumes are not accepted",
                ));
        }
        if name == "network" {
            sub=sub.about("Reads routes/resolvers and resolves www.apple.com via the system DNS service (no HTTP)");
        }
        command = command.subcommand(sub);
    }
    command.after_help("JSON now uses the shared diagnostic schema 1 (id/status/facts/source/complete).\nDisk verifies / only; Spotlight enumerates local mounted volumes. Tool deadlines are fixed.\nDetails are local and may contain private paths/addresses. No helper or sudo is used.")
}
pub fn run(args: &ArgMatches) -> io::Result<u8> {
    let Some((name, args)) = args.subcommand() else {
        return Ok(2);
    };
    let Some((_, id)) = IDS.iter().find(|(n, _)| *n == name) else {
        return Ok(2);
    };
    let signals = crate::terminal::Signals::new()?;
    let report = readonly_diagnostics::run_cancellable(*id, &|| {
        signals.interrupted() || signals.terminated()
    });
    let mut out = io::stdout().lock();
    if args.get_flag("json") {
        serde_json::to_writer(&mut out, &report).map_err(io::Error::other)?;
        writeln!(out)?;
    } else {
        writeln!(
            out,
            "{}: {} (complete: {})",
            report.id, report.status, report.complete
        )?;
        writeln!(
            out,
            "source: {}\nobserved_unix_ms: {}\neffects_performed: false",
            report.source, report.observed_unix_ms
        )?;
        for fact in &report.facts {
            writeln!(out, "{}: {} [{}]", fact.name, fact.value, fact.status)?;
        }
    }
    Ok(signals
        .exit_code()
        .unwrap_or(if report.complete && report.status == "ok" {
            0
        } else {
            3
        }))
}
