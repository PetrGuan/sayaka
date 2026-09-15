// SPDX-License-Identifier: MPL-2.0

use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use sayaka_engine::execute::TrashSession;
use sayaka_engine::journal::{self, NativePath, Store};
use sayaka_engine::model::{Cancellation, Plan, ReasonCode, Scope};
use serde_json::json;
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

pub(crate) const MAX_SELECTIONS: usize = sayaka_engine::journal::MAX_ITEMS;

pub fn command() -> Command {
    Command::new("trash")
        .about("Preview explicit files for native Trash; no change without --execute and terminal confirmation")
        .arg(Arg::new("files").value_name("FILE").num_args(1..).required(true).value_parser(value_parser!(PathBuf)))
        .arg(Arg::new("scope").long("scope").value_name("DIR").required(true).value_parser(value_parser!(PathBuf))
            .help("Existing physical directory containing every selected file"))
        .arg(Arg::new("exclude").long("exclude").value_name("PATH").action(ArgAction::Append).value_parser(value_parser!(PathBuf)))
        .arg(Arg::new("execute").long("execute").action(ArgAction::SetTrue)
            .help("Show the exact plan and require typed terminal confirmation (120-second expiry)"))
        .arg(json_arg().conflicts_with("execute"))
        .arg(state_arg())
        .after_help("Only ordinary single-link files on supported local macOS volumes. No permanent deletion or elevation.\nA replacement after the final check can still cause a different file to be moved.\nTrash does not free disk space or guarantee restoration. Do not use on files being modified by other apps.")
}

pub fn receipt_command() -> Command {
    Command::new("receipt")
        .about("Read local operation records; interrupted work is Unknown and is never retried")
        .arg(state_arg())
        .arg(json_arg())
}

fn state_arg() -> Arg {
    Arg::new("state-dir")
        .long("state-dir")
        .value_name("DIR")
        .value_parser(value_parser!(PathBuf))
        .help("Private local journal directory (default: ~/Library/Application Support/Sayaka)")
}

fn json_arg() -> Arg {
    Arg::new("json")
        .long("json")
        .action(ArgAction::SetTrue)
        .help("Write versioned JSON to stdout")
}

fn absolute(path: &Path) -> io::Result<PathBuf> {
    if path
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "'..' path traversal is not accepted",
        ));
    }
    std::path::absolute(path)
}

pub(crate) fn state_directory(args: &ArgMatches) -> io::Result<PathBuf> {
    match args.get_one::<PathBuf>("state-dir") {
        Some(path) => absolute(path),
        None => journal::default_directory(),
    }
}

pub fn run(args: &ArgMatches) -> io::Result<u8> {
    let result = run_inner(args);
    render_error(result, args.get_flag("json"), "trash")
}

fn run_inner(args: &ArgMatches) -> io::Result<u8> {
    let execute = args.get_flag("execute");
    if execute
        && !(io::stdin().is_terminal() && io::stdout().is_terminal() && io::stderr().is_terminal())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--execute requires an interactive terminal; piped approval is not accepted",
        ));
    }
    let scope = args
        .get_one::<PathBuf>("scope")
        .ok_or_else(|| io::Error::other("scope is missing"))?;
    let files = args
        .get_many::<PathBuf>("files")
        .ok_or_else(|| io::Error::other("files are missing"))?
        .map(|path| absolute(path))
        .collect::<io::Result<Vec<_>>>()?;
    let excluded = args
        .get_many::<PathBuf>("exclude")
        .into_iter()
        .flatten()
        .map(|path| absolute(path))
        .collect::<io::Result<Vec<_>>>()?;
    let scope = Scope::new(absolute(scope)?, vec![])
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let cancellation = Cancellation::default();
    let mut session = TrashSession::prepare(scope, &files, &excluded, &cancellation)?;
    let plan = session.preview().clone();
    let rejected = plan
        .rejected()
        .iter()
        .filter(|item| item.code != ReasonCode::Excluded)
        .count();
    if args.get_flag("json") {
        print_json_value(&plan_preview_json(
            &plan,
            &session.refusals(),
            session.issues(),
        )?)?;
    } else {
        show_plan_preview(&plan)?;
        for item in session.refusals() {
            writeln!(
                io::stdout().lock(),
                "  Not selected: {} ({})",
                item.path.display,
                item.reason
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
    if !execute {
        return Ok(if rejected > 0 || plan.items().is_empty() {
            3
        } else {
            0
        });
    }
    if plan.items().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no eligible files; nothing can be approved",
        ));
    }
    let expected = format!("trash {}", plan.items().len());
    write!(
        io::stderr().lock(),
        "\nType {expected:?} to move exactly these files, or press Enter to cancel: "
    )?;
    io::stderr().flush()?;
    let mut answer = String::new();
    io::stdin().lock().take(128).read_line(&mut answer)?;
    if !confirmed(&answer, &expected) {
        writeln!(io::stderr().lock(), "Cancelled; no files moved.")?;
        return Ok(130);
    }
    let signal = cancellation.clone();
    ctrlc::set_handler(move || signal.cancel()).map_err(io::Error::other)?;
    let approval = session
        .approve(&plan)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let store = Store::open(&state_directory(args)?, true)?;
    let report = session.execute(&plan, &approval, &cancellation, &store)?;
    print_execution_report(&report)?;
    let code = report.exit_code();
    Ok(if code == 0 && rejected > 0 { 3 } else { code })
}

pub(crate) fn plan_preview_json(
    plan: &Plan,
    refusals: &[sayaka_engine::execute::SelectionRefusal],
    issues: &[sayaka_engine::execute::SelectionIssue],
) -> io::Result<serde_json::Value> {
    let timestamp = |time: std::time::SystemTime| -> io::Result<u64> {
        let millis = time
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_millis();
        u64::try_from(millis).map_err(io::Error::other)
    };
    Ok(json!({
        "schema_version": 1, "kind": "trash_preview",
        "plan_schema_version": plan.schema_version(),
        "execution_contract": plan.execution_contract().as_str(),
        "warning": plan.execution_contract().warning(),
        "scope": NativePath::from_path(plan.scope()),
        "created_unix_ms": timestamp(plan.created_at())?,
        "expires_unix_ms": timestamp(plan.expires_at())?,
        "items": plan.items().iter().map(|item| json!({
            "path": NativePath::from_path(item.observation().path()),
            "action": "revalidated_move_to_trash",
            "logical_bytes": item.observation().snapshot().logical_bytes,
            "identity": item.observation().snapshot().identity,
        })).collect::<Vec<_>>(),
        "rejected": refusals,
        "selection_issues": issues,
        "effects_performed": false,
    }))
}

pub(crate) fn parse_selection_input(
    answer: &str,
    candidate_count: usize,
) -> io::Result<std::collections::BTreeSet<usize>> {
    let mut indices = std::collections::BTreeSet::new();
    for part in answer
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        let (start, end) = match part.split_once('-') {
            Some((from, to)) => (
                from.parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "invalid numeric range")
                })?,
                to.parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "invalid numeric range")
                })?,
            ),
            None => {
                let index = part.parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "invalid selection number")
                })?;
                (index, index)
            }
        };
        if start == 0 || start > end || end > candidate_count {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "selection index out of bounds",
            ));
        }
        for index in start..=end {
            indices.insert(index);
            if indices.len() > MAX_SELECTIONS {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "selection exceeds 32 items",
                ));
            }
        }
    }
    Ok(indices)
}

pub(crate) fn print_execution_report(
    report: &sayaka_engine::execute::ExecutionReport,
) -> io::Result<()> {
    writeln!(
        io::stdout().lock(),
        "\nOperation {}",
        report.record.operation_id
    )?;
    for item in &report.record.items {
        writeln!(
            io::stdout().lock(),
            "{:?}  {}{}",
            item.state,
            item.path.display,
            item.reason
                .as_ref()
                .map(|reason| format!(": {reason:?}"))
                .unwrap_or_default()
        )?;
        if let Some(destination) = &item.destination {
            writeln!(
                io::stdout().lock(),
                "  Recorded destination (not a restore guarantee): {}",
                destination.display
            )?;
        }
        if let Some(binding) = &item.rule_binding {
            writeln!(
                io::stdout().lock(),
                "  Rule: {} v{} (ruleset r{}, digest {})",
                binding.rule_id,
                binding.rule_version,
                binding.ruleset_revision,
                binding.semantics_digest
            )?;
        }
        if let Some(evidence) = &item.recovery_evidence {
            show_recovery_evidence(&mut io::stdout().lock(), evidence)?;
        }
    }
    writeln!(
        io::stdout().lock(),
        "Verified moved files' approved logical size: {}; freed space is not measured.",
        report
            .record
            .handled_bytes()
            .map(crate::human::size)
            .unwrap_or_else(|| "unknown (size overflow)".into())
    )?;
    if let Some(error) = &report.journal_error {
        writeln!(
            io::stderr().lock(),
            "Journal failure; no further operations were started: {error:?}"
        )?;
    }
    Ok(())
}

pub(crate) fn confirmed(answer: &str, expected: &str) -> bool {
    answer
        .strip_suffix('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        == Some(expected)
}

fn show_recovery_evidence(
    out: &mut impl Write,
    evidence: &journal::RecoveryEvidence,
) -> io::Result<()> {
    writeln!(
        out,
        "  Recovery observations only; no automatic retry or restoration:"
    )?;
    writeln!(
        out,
        "    Approved identity: {}:{}",
        evidence.approved.device, evidence.approved.inode
    )?;
    if let Some(path) = &evidence.returned_destination {
        writeln!(out, "    Unverified OS destination: {}", path.display)?;
    }
    if let Some(path) = &evidence.held_source_path {
        writeln!(
            out,
            "    Held-descriptor path observation: {}",
            path.display
        )?;
    }
    for error in &evidence.observation_errors {
        writeln!(out, "    Observation unavailable: {error:?}")?;
    }
    Ok(())
}

pub(crate) fn show_plan_preview(plan: &Plan) -> io::Result<()> {
    let mut out = io::stdout().lock();
    writeln!(
        out,
        "Trash preview: {} eligible, {} excluded/refused",
        plan.items().len(),
        plan.rejected().len()
    )?;
    writeln!(out, "Scope: {:?}", plan.scope().as_os_str())?;
    for item in plan.items() {
        writeln!(
            out,
            "  {}  ({} logical size)",
            item.observation().display_path(),
            item.observation()
                .snapshot()
                .logical_bytes
                .map(crate::human::size)
                .unwrap_or_else(|| "unknown".into())
        )?;
    }
    writeln!(out, "\n{}", plan.execution_contract().warning())?;
    writeln!(
        out,
        "Preview only until explicitly confirmed; no automatic retry or permanent-delete fallback."
    )?;
    out.flush()
}

pub fn receipt(args: &ArgMatches) -> io::Result<u8> {
    let result = (|| {
        let store = Store::open(&state_directory(args)?, false)?;
        let snapshot = store.records()?;
        if args.get_flag("json") {
            print_json_value(
                &json!({ "schema_version": 1, "kind": "receipts", "journal": snapshot }),
            )?;
        } else {
            let mut out = io::stdout().lock();
            if snapshot.records.is_empty() {
                writeln!(out, "No committed operation records.")?;
            }
            for record in &snapshot.records {
                write_record(&mut out, record)?;
            }
            for pending in &snapshot.uncommitted_snapshots {
                writeln!(
                    out,
                    "Uncommitted snapshot {pending:?}: preserved for inspection; never replayed."
                )?;
            }
        }
        Ok(if snapshot.uncommitted_snapshots.is_empty() {
            0
        } else {
            3
        })
    })();
    render_error(result, args.get_flag("json"), "receipt")
}

pub(crate) fn write_record(out: &mut impl Write, record: &journal::Record) -> io::Result<()> {
    writeln!(
        out,
        "Operation {} ({})",
        record.operation_id, record.contract
    )?;
    for item in &record.items {
        writeln!(
            out,
            "  {:?} {}  {:?}",
            item.state, item.path.display, item.reason
        )?;
        if let Some(binding) = &item.rule_binding {
            writeln!(
                out,
                "    rule={} v{} ruleset_r{} digest={}",
                binding.rule_id,
                binding.rule_version,
                binding.ruleset_revision,
                binding.semantics_digest
            )?;
        }
        if let Some(evidence) = &item.recovery_evidence {
            show_recovery_evidence(out, evidence)?;
        }
    }
    Ok(())
}

pub(crate) fn print_json_value(value: &serde_json::Value) -> io::Result<()> {
    let mut out = io::stdout().lock();
    serde_json::to_writer(&mut out, value)?;
    writeln!(out)?;
    out.flush()
}

pub(crate) fn render_error(
    result: io::Result<u8>,
    json_output: bool,
    kind: &str,
) -> io::Result<u8> {
    match result {
        Ok(code) => Ok(code),
        Err(error) => {
            let code = match error.kind() {
                io::ErrorKind::InvalidInput => 2,
                io::ErrorKind::Interrupted => 130,
                _ => 1,
            };
            if json_output {
                print_json_value(&json!({
                    "schema_version": 1, "kind": kind, "status": "failed",
                    "error": { "code": format!("{:?}", error.kind()), "message": error.to_string() }
                }))?;
            } else {
                writeln!(
                    io::stderr().lock(),
                    "{kind} failed: {:?}",
                    error.to_string()
                )?;
            }
            Ok(code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn approval_requires_exact_phrase_and_line_ending() {
        assert!(confirmed("trash 2\n", "trash 2"));
        assert!(confirmed("trash 2\r\n", "trash 2"));
        for answer in [
            "yes\n",
            "trash 3\n",
            " trash 2\n",
            "trash 2",
            "trash 2\nextra",
        ] {
            assert!(!confirmed(answer, "trash 2"));
        }
    }
    #[test]
    fn traversal_is_rejected_before_absolute_normalization() {
        assert!(absolute(Path::new("a/../b")).is_err());
    }

    #[test]
    fn numeric_selection_is_bounded_before_expanding_large_ranges() {
        assert_eq!(
            parse_selection_input("1,3-4,3", 4)
                .unwrap()
                .into_iter()
                .collect::<Vec<_>>(),
            vec![1, 3, 4]
        );
        assert!(parse_selection_input("", 4).unwrap().is_empty());
        assert_eq!(parse_selection_input("1-32", 32).unwrap().len(), 32);
        for input in ["0", "5", "4-2", "1-x"] {
            assert!(parse_selection_input(input, 4).is_err());
        }
        assert!(parse_selection_input(&format!("1-{}", usize::MAX), usize::MAX).is_err());
    }
}
