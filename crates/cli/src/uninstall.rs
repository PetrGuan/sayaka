// SPDX-License-Identifier: MPL-2.0

use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use sayaka_engine::app_inventory::RunningObservation;
use sayaka_engine::app_uninstall::{self, CopiesStatus, UninstallPreview, UninstallRefusal};
use sayaka_engine::execute::BundleUninstallSession;
use sayaka_engine::journal::Store;
use sayaka_engine::model::{Cancellation, ReasonCode, Scope};
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::path::PathBuf;
use std::time::Duration;

const SCHEMA_VERSION: u32 = 1;
const KIND: &str = "sayaka.app_uninstall_preview";
const COPIES_SCAN_BUDGET_SEC: u64 = 60;

pub fn command() -> Command {
    Command::new("uninstall")
        .about("Preview or uninstall one explicit .app bundle to the user Trash")
        .arg(
            Arg::new("bundle")
                .long("bundle")
                .value_name("PATH")
                .required(true)
                .value_parser(value_parser!(PathBuf))
                .help("Explicit .app bundle directory; links are never followed"),
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
                .help("Move the bundle to Trash after typed confirmation (120-second approval)"),
        )
        .arg(
            Arg::new("state-dir")
                .long("state-dir")
                .value_name("DIR")
                .value_parser(value_parser!(PathBuf))
                .help("Private M3 journal directory for the durable intent/outcome record"),
        )
        .arg(
            Arg::new("copies-root")
                .long("copies-root")
                .value_name("ROOT")
                .action(ArgAction::Append)
                .value_parser(value_parser!(PathBuf))
                .help("Repeatable root searched for coexisting copies of the same bundle ID (read-only evidence; copies are never targets)"),
        )
        .after_help(
            "Default is a read-only preview. --execute requires an interactive terminal and moves\nexactly the named bundle to the user Trash (recovery: Finder 'Put Back'; no programmatic\nrestore). Related data, preferences, caches and other copies are never touched. A running\nbundle is refused at preview, approval and immediately before the native call.\n--copies-root only observes coexisting copies; it never selects them for any effect.",
        )
}

pub fn run(args: &ArgMatches) -> io::Result<u8> {
    let result = run_inner(args);
    match result {
        Ok(code) => Ok(code),
        Err(error) => {
            writeln!(
                io::stderr().lock(),
                "uninstall failed: {:?}",
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
    let bundle = std::path::absolute(
        args.get_one::<PathBuf>("bundle")
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "--bundle is required"))?,
    )?;
    let mut preview = app_uninstall::preview_bundle_uninstall(&bundle);
    let copies_roots: Vec<PathBuf> = args
        .get_many::<PathBuf>("copies-root")
        .into_iter()
        .flatten()
        .cloned()
        .collect();
    if !copies_roots.is_empty() {
        // Read-only evidence; the preview phase installs no signal handler,
        // so Ctrl-C keeps its default behavior, same as the base preview.
        preview.copies = app_uninstall::observe_copies(
            &preview,
            &copies_roots,
            &Cancellation::default(),
            Duration::from_secs(COPIES_SCAN_BUDGET_SEC),
        );
    }
    if args.get_flag("json") {
        write_json(&mut io::stdout().lock(), &preview)?;
    } else {
        write_human(&mut io::stdout().lock(), &preview)?;
    }
    if !preview.refusals.is_empty() {
        return Ok(3);
    }
    if !execute {
        return Ok(0);
    }
    let scope = Scope::new(
        bundle
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "bundle has no parent"))?
            .to_path_buf(),
        vec![],
    )
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let cancellation = Cancellation::default();
    let mut session = BundleUninstallSession::prepare(scope, &bundle, &cancellation)?;
    let plan = session.preview().clone();
    for refusal in session.refusals() {
        if refusal.reason != ReasonCode::Excluded.as_str() {
            writeln!(
                io::stdout().lock(),
                "  Not eligible: {} ({})",
                refusal.path.display,
                refusal.reason
            )?;
        }
    }
    for issue in session.issues() {
        writeln!(
            io::stderr().lock(),
            "Refused {}: {:?}",
            issue.path.display,
            issue.message
        )?;
    }
    if plan.items().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bundle is not eligible; nothing can be approved",
        ));
    }
    let name = bundle
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bundle name is not UTF-8"))?;
    let expected = format!("uninstall {name}");
    write!(
        io::stderr().lock(),
        "\nType {expected:?} to move exactly this bundle to Trash, or press Enter to cancel: "
    )?;
    io::stderr().flush()?;
    let mut answer = String::new();
    io::stdin().lock().take(128).read_line(&mut answer)?;
    if !crate::trash::confirmed(&answer, &expected) {
        writeln!(io::stderr().lock(), "Cancelled; nothing moved.")?;
        return Ok(130);
    }
    let signal = cancellation.clone();
    ctrlc::set_handler(move || signal.cancel()).map_err(io::Error::other)?;
    let approval = session
        .approve(&plan)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let store = Store::open(&crate::trash::state_directory(args)?, true)?;
    let report = session.execute(&plan, &approval, &cancellation, &store)?;
    crate::trash::print_execution_report(&report)?;
    writeln!(
        io::stdout().lock(),
        "Recovery: Finder 'Put Back' from Trash; no programmatic restore. Related data untouched."
    )?;
    Ok(report.exit_code())
}

fn running_json(observation: &RunningObservation) -> serde_json::Value {
    serde_json::json!({
        "state": observation.as_str(),
        "pids": match observation {
            RunningObservation::Running(pids) => serde_json::json!(pids),
            _ => serde_json::Value::Null,
        },
        "reason": match observation {
            RunningObservation::NotAttributable(reason) => serde_json::json!(reason),
            _ => serde_json::Value::Null,
        },
    })
}

fn copies_json(preview: &UninstallPreview) -> serde_json::Value {
    let copies = &preview.copies;
    serde_json::json!({
        "state": copies.status.as_str(),
        "reason": copies.reason,
        "target_bundle_id": copies.target_bundle_id,
        "scan_budget_sec": copies.scan_budget_sec,
        "inventory_budget_sec": copies.inventory_budget_sec,
        "requested_roots": copies.requested_roots.iter().map(|root| crate::apps::write_native_path(root)).collect::<Vec<_>>(),
        "copies": copies.copies.iter().map(|copy| serde_json::json!({
            "bundle_path": crate::apps::write_native_path(&copy.bundle_path),
            "observed_roots": copy.observed_roots.iter().map(|root| crate::apps::write_native_path(root)).collect::<Vec<_>>(),
            "running": running_json(&copy.running),
        })).collect::<Vec<_>>(),
        "note": copies.note,
    })
}

fn refusal_json(refusal: &UninstallRefusal) -> serde_json::Value {
    serde_json::json!({
        "code": refusal.code.as_str(),
        "message": refusal.message,
        "os_code": refusal.os_code,
    })
}

fn write_json(out: &mut impl Write, preview: &UninstallPreview) -> io::Result<()> {
    let identity = preview.identity.as_ref();
    let value = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "bundle_path": crate::apps::write_native_path(&preview.bundle_path),
        "display_name": preview.display_name,
        "effects_performed": false,
        "execution": preview.execution,
        "can_execute": preview.can_execute(),
        "identity": identity.map(|identity| serde_json::json!({
            "device": identity.device,
            "inode": identity.inode,
            "logical_bytes": identity.logical_bytes,
        })),
        "executables_observed": preview.executables_observed,
        "running": running_json(&preview.running),
        "copies": copies_json(preview),
        "vendor_uninstaller": preview.vendor_uninstaller.map(|vendor| serde_json::json!({
            "name": vendor.name,
            "instruction": vendor.instruction,
            "source_url": vendor.source_url,
            "may_remove_user_data": vendor.may_remove_user_data,
            "authorization": vendor.authorization,
            "restart": vendor.restart,
            "execution": "guidance_only",
        })),
        "protections": preview.protections,
        "recovery": preview.recovery,
        "refusals": preview.refusals.iter().map(refusal_json).collect::<Vec<_>>(),
    });
    serde_json::to_writer(&mut *out, &value).map_err(|error| {
        io::Error::new(
            error.io_error_kind().unwrap_or(io::ErrorKind::InvalidData),
            error,
        )
    })?;
    out.write_all(b"\n")?;
    out.flush()
}

fn write_human(out: &mut impl Write, preview: &UninstallPreview) -> io::Result<()> {
    writeln!(out, "kind: {KIND}")?;
    writeln!(
        out,
        "bundle: {}",
        sayaka_engine::scan::display_path(&preview.bundle_path)
    )?;
    writeln!(out, "display_name: {}", preview.display_name)?;
    writeln!(out, "effects_performed: false")?;
    writeln!(
        out,
        "execution: {} (a clean preview is not approval)",
        preview.execution
    )?;
    if let Some(identity) = &preview.identity {
        writeln!(
            out,
            "identity: device={} inode={} bytes={}",
            identity.device, identity.inode, identity.logical_bytes
        )?;
    }
    if let Some(count) = preview.executables_observed {
        writeln!(out, "executables_observed: {count}")?;
    }
    match &preview.running {
        RunningObservation::Running(pids) => writeln!(out, "running: yes (pids: {pids:?})")?,
        RunningObservation::NotRunning => writeln!(out, "running: no matching process observed")?,
        RunningObservation::NotAttributable(reason) => {
            writeln!(out, "running: not attributable ({reason})")?
        }
        RunningObservation::Unknown => {
            writeln!(out, "running: unknown (process enumeration failed)")?
        }
        RunningObservation::NotChecked => writeln!(out, "running: not checked")?,
    }
    if preview.copies.status != CopiesStatus::NotChecked {
        writeln!(out, "copies: {}", preview.copies.status.as_str())?;
        if let Some(reason) = preview.copies.reason {
            writeln!(out, "copies_reason: {reason}")?;
        }
        if let Some(id) = &preview.copies.target_bundle_id {
            writeln!(out, "target_bundle_id: {id}")?;
        }
        for copy in &preview.copies.copies {
            writeln!(
                out,
                "  - {} (running: {})",
                sayaka_engine::scan::display_path(&copy.bundle_path),
                copy.running.as_str()
            )?;
        }
        writeln!(out, "  note: {}", preview.copies.note)?;
    }
    if let Some(vendor) = preview.vendor_uninstaller {
        writeln!(out, "vendor_uninstaller: {} (guidance only)", vendor.name)?;
        writeln!(out, "  {}", vendor.instruction)?;
        writeln!(out, "  source: {}", vendor.source_url)?;
        writeln!(out, "  authorization: {}", vendor.authorization)?;
        writeln!(out, "  restart: {}", vendor.restart)?;
    }
    writeln!(out, "protections:")?;
    for protection in &preview.protections {
        writeln!(out, "  - {protection}")?;
    }
    writeln!(out, "recovery: {}", preview.recovery)?;
    if !preview.refusals.is_empty() {
        writeln!(out, "refusals:")?;
        for refusal in &preview.refusals {
            writeln!(out, "  - {} {}", refusal.code.as_str(), refusal.message)?;
        }
    }
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn json_preview_has_explicit_states_and_no_effects() {
        let root = tempfile::tempdir().expect("tempdir");
        let bundle = root.path().join("Fixture.app");
        let macos = bundle.join("Contents").join("MacOS");
        fs::create_dir_all(&macos).expect("tree");
        fs::write(bundle.join("Contents").join("Info.plist"), b"<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>com.example.fixture</string><key>CFBundleExecutable</key><string>Run</string></dict></plist>").expect("plist");
        fs::write(macos.join("Run"), b"inert").expect("exe");
        let preview = app_uninstall::preview_bundle_uninstall(&bundle);
        let mut out = Vec::new();
        write_json(&mut out, &preview).expect("json");
        let value: serde_json::Value = serde_json::from_slice(&out).expect("parse");
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["kind"], KIND);
        assert_eq!(value["effects_performed"], false);
        assert_eq!(value["can_execute"], false);
        assert_eq!(value["execution"], app_uninstall::EXECUTION_DEFERRED);
        assert_eq!(value["running"]["state"], "not_running");
        assert_eq!(value["copies"]["state"], "not_checked");
        assert!(value["vendor_uninstaller"].is_null());
        assert!(
            value["copies"]["note"]
                .as_str()
                .unwrap()
                .contains("evidence only")
        );
        assert!(value["refusals"].as_array().expect("refusals").is_empty());
        assert!(value["identity"]["inode"].is_u64());
    }
}
