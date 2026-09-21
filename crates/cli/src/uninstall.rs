// SPDX-License-Identifier: MPL-2.0

use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use sayaka_engine::app_inventory::RunningObservation;
use sayaka_engine::app_uninstall::{self, UninstallPreview, UninstallRefusal};
use std::io::{self, Write};
use std::path::PathBuf;

const SCHEMA_VERSION: u32 = 1;
const KIND: &str = "sayaka.app_uninstall_preview";

pub fn command() -> Command {
    Command::new("uninstall")
        .about("Preview uninstalling one explicit .app bundle; execution is deferred to a separate contract")
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
        .after_help(
            "Read-only preview only. No Trash, deletion, signals or approval surface in this slice.\nExecution remains deferred to a separately reviewed contract; a clean preview is not approval.",
        )
}

pub fn run(args: &ArgMatches) -> io::Result<u8> {
    let bundle = args
        .get_one::<PathBuf>("bundle")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "--bundle is required"))?;
    let preview = app_uninstall::preview_bundle_uninstall(bundle);
    if args.get_flag("json") {
        write_json(&mut io::stdout().lock(), &preview)?;
    } else {
        write_human(&mut io::stdout().lock(), &preview)?;
    }
    Ok(if preview.refusals.is_empty() { 0 } else { 3 })
}

fn running_json(preview: &UninstallPreview) -> serde_json::Value {
    serde_json::json!({
        "state": preview.running.as_str(),
        "pids": match &preview.running {
            RunningObservation::Running(pids) => serde_json::json!(pids),
            _ => serde_json::Value::Null,
        },
        "reason": match &preview.running {
            RunningObservation::NotAttributable(reason) => serde_json::json!(reason),
            _ => serde_json::Value::Null,
        },
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
        "running": running_json(preview),
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
        fs::write(bundle.join("Contents").join("Info.plist"), b"plist").expect("plist");
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
        assert!(value["refusals"].as_array().expect("refusals").is_empty());
        assert!(value["identity"]["inode"].is_u64());
    }
}
