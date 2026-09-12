// SPDX-License-Identifier: MPL-2.0

use crate::terminal::Signals;
use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use sayaka_engine::installation::{InstallPlan, Outcome, OutcomeState, Preview, RemovePlan};
use sayaka_engine::model::Cancellation;
use serde::Serialize;
use std::io::{self, Write};
use std::path::PathBuf;
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub fn install_command() -> Command {
    command(
        "install",
        "Preview a dedicated local installation of this on-disk executable",
    )
}
pub fn remove_command() -> Command {
    command(
        "remove",
        "Preview removal of a verified Sayaka installation; history is preserved",
    )
}

fn command(name: &'static str, about: &'static str) -> Command {
    Command::new(name).about(about)
        .arg(Arg::new("prefix").long("prefix").value_name("DIR").value_parser(value_parser!(PathBuf))
            .help("Dedicated physical prefix (default: ~/.local/share/sayaka); parent must exist"))
        .arg(Arg::new("execute").long("execute").action(ArgAction::SetTrue).help("Explicitly apply this owned-prefix operation"))
        .arg(Arg::new("json").long("json").action(ArgAction::SetTrue))
        .after_help("No downloads, overwrite/update fallback, privilege escalation, PATH/shellrc edits or history deletion.\nOnly a private dedicated installation is supported. Unknown, modified or extra files cause refusal.")
}

pub fn run(args: &ArgMatches, install: bool) -> io::Result<u8> {
    let result = run_inner(args, install);
    match result {
        Ok(code) => Ok(code),
        Err(error) => {
            if args.get_flag("json") && error.kind() != io::ErrorKind::BrokenPipe {
                json(
                    &serde_json::json!({"schema_version":1,"kind":"installation","status":"failed",
                    "error":{"code":format!("{:?}",error.kind()),"message":error.to_string()}}),
                )?;
            }
            writeln!(
                io::stderr().lock(),
                "local lifecycle operation failed: {:?}",
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

fn run_inner(args: &ArgMatches, install: bool) -> io::Result<u8> {
    let prefix = match args.get_one::<PathBuf>("prefix") {
        Some(path) => path.clone(),
        None => {
            let home = std::env::var_os("HOME")
                .filter(|home| !home.is_empty())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "HOME is unavailable; supply --prefix",
                    )
                })?;
            let home = PathBuf::from(home);
            if !home.is_absolute() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "HOME must be absolute",
                ));
            }
            home.join(".local/share/sayaka")
        }
    };
    if prefix
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "'..' prefix traversal is not accepted",
        ));
    }
    let prefix = std::path::absolute(prefix)?;
    let apply = args.get_flag("execute");
    let json_output = args.get_flag("json");
    if install {
        let plan = InstallPlan::prepare(
            &prefix,
            &std::env::current_exe()?,
            env!("CARGO_PKG_VERSION"),
        )?;
        if !apply || !json_output {
            preview(plan.preview(), json_output)?;
        }
        if apply {
            execute(move |cancel| plan.execute(cancel), json_output)
        } else {
            Ok(0)
        }
    } else {
        let plan = RemovePlan::prepare(&prefix)?;
        if !apply || !json_output {
            preview(plan.preview(), json_output)?;
        }
        if apply {
            execute(move |cancel| plan.execute(cancel), json_output)
        } else {
            Ok(0)
        }
    }
}

fn preview(plan: &Preview, machine: bool) -> io::Result<()> {
    if machine {
        #[derive(Serialize)]
        struct Envelope<'a> {
            schema_version: u32,
            kind: &'static str,
            effects_performed: bool,
            plan: &'a Preview,
        }
        return json(&Envelope {
            schema_version: 1,
            kind: "installation_preview",
            effects_performed: false,
            plan,
        });
    }
    let mut out = io::stdout().lock();
    writeln!(out, "{:?} preview: {}", plan.action, plan.prefix.display)?;
    writeln!(out, "Executable: {}", plan.executable.display)?;
    writeln!(
        out,
        "Version {:?}, {} bytes, SHA-256 {}",
        plan.version, plan.executable_bytes, plan.sha256
    )?;
    if plan.already_installed {
        writeln!(
            out,
            "The installed image is already verified; no replacement is needed."
        )?;
    }
    writeln!(
        out,
        "Preview only without --execute. Operation history and shell configuration stay untouched."
    )?;
    out.flush()
}

struct OwnedOperation {
    cancel: Cancellation,
    handle: Option<JoinHandle<io::Result<Outcome>>>,
}
impl Drop for OwnedOperation {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            self.cancel.cancel();
            match handle.join() {
                Ok(Ok(outcome)) => {
                    if let Err(error) = show_outcome(&outcome) {
                        eprintln!("lifecycle outcome output failed: {error}");
                    }
                }
                Ok(Err(error)) => eprintln!("lifecycle cleanup failed: {:?}", error.to_string()),
                Err(_) => eprintln!("lifecycle worker panicked; inspect the dedicated prefix"),
            }
        }
    }
}

fn execute(
    operation: impl FnOnce(&Cancellation) -> io::Result<Outcome> + Send + 'static,
    machine: bool,
) -> io::Result<u8> {
    let signals = Signals::new()?;
    let cancel = Cancellation::default();
    let worker_cancel = cancel.clone();
    let handle = thread::Builder::new()
        .name("sayaka-local-install".into())
        .spawn(move || operation(&worker_cancel))?;
    let mut owned = OwnedOperation {
        cancel,
        handle: Some(handle),
    };
    while !owned.handle.as_ref().is_none_or(JoinHandle::is_finished) {
        if signals.exit_code().is_some() {
            owned.cancel.cancel();
        }
        thread::sleep(Duration::from_millis(10));
    }
    let outcome = owned
        .handle
        .take()
        .ok_or_else(|| io::Error::other("lifecycle worker missing"))?
        .join()
        .map_err(|_| {
            io::Error::other("lifecycle worker panicked; inspect the dedicated prefix")
        })??;
    let code = outcome.exit_code();
    if machine {
        #[derive(Serialize)]
        struct Envelope<'a> {
            schema_version: u32,
            kind: &'static str,
            outcome: &'a Outcome,
        }
        json(&Envelope {
            schema_version: 1,
            kind: "installation_result",
            outcome: &outcome,
        })?;
    } else {
        show_outcome(&outcome)?;
    }
    Ok(signals.exit_code().unwrap_or(code))
}

fn show_outcome(outcome: &Outcome) -> io::Result<()> {
    let mut out = io::stdout().lock();
    writeln!(
        out,
        "{:?}: {}",
        outcome.status, outcome.preview.prefix.display
    )?;
    writeln!(
        out,
        "Known regular-file logical bytes: {}; allocated bytes: {}",
        outcome
            .logical_bytes
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".into()),
        outcome
            .allocated_bytes
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".into())
    )?;
    for path in &outcome.recovery_paths {
        writeln!(
            out,
            "Exact recovery location (inspect before any action): {}",
            path.display
        )?;
    }
    if let Some(error) = &outcome.error {
        writeln!(out, "Incomplete operation: {error:?}")?;
    }
    writeln!(
        out,
        "No PATH/startup-file changes; operation history was not removed."
    )?;
    if matches!(
        outcome.status,
        OutcomeState::Installed | OutcomeState::AlreadyInstalled
    ) {
        writeln!(out, "Add the verified bin directory to PATH manually.")?;
        writeln!(out, "Generate completion with sayaka completions SHELL.")?;
    }
    out.flush()
}

fn json(value: &impl Serialize) -> io::Result<()> {
    let mut out = io::stdout().lock();
    serde_json::to_writer(&mut out, value).map_err(|error| {
        io::Error::new(
            error.io_error_kind().unwrap_or(io::ErrorKind::InvalidData),
            error,
        )
    })?;
    writeln!(out)?;
    out.flush()
}
