// SPDX-License-Identifier: MPL-2.0
use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use std::{
    io::{self, IsTerminal, Write},
    path::PathBuf,
};
pub fn command() -> Command {
    Command::new("orphans")
        .about("Review exact application leftovers with tiered evidence")
        .arg(
            Arg::new("related")
                .long("related")
                .required(true)
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("execute")
                .long("execute")
                .action(ArgAction::SetTrue)
                .conflicts_with("json"),
        )
        .arg(Arg::new("json").long("json").action(ArgAction::SetTrue))
        .arg(
            Arg::new("app-root")
                .long("app-root")
                .action(ArgAction::Append)
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("policy-dir")
                .long("policy-dir")
                .required(true)
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("state-dir")
                .long("state-dir")
                .value_parser(value_parser!(PathBuf)),
        )
}
#[cfg(target_os = "macos")]
pub fn run(args: &ArgMatches) -> io::Result<u8> {
    use sayaka_engine::{model::Cancellation, orphan_execution::OrphanSession};
    let execute = args.get_flag("execute");
    if execute && (!io::stdin().is_terminal() || !io::stdout().is_terminal()) {
        return Err(io::Error::other(
            "orphan approval requires an interactive terminal",
        ));
    }
    let extra: Vec<_> = args
        .get_many::<PathBuf>("app-root")
        .map(|v| v.cloned().collect())
        .unwrap_or_default();
    let session = OrphanSession::prepare(
        &extra,
        args.get_one::<PathBuf>("policy-dir").unwrap(),
        Cancellation::default(),
    )?;
    println!("{}", serde_json::to_string_pretty(session.preview())?);
    if !execute {
        return Ok(0);
    }
    if !session
        .preview()
        .candidates
        .iter()
        .any(|c| c.execution_supported)
    {
        return Err(io::Error::other(
            "no executable candidates; native acceptance may be pending",
        ));
    }
    print!("Select item IDs (space separated, maximum 32): ");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    let ids: Vec<String> = line.split_whitespace().map(str::to_owned).collect();
    println!("Selected paths and consequences:");
    for id in &ids {
        let row = session
            .preview()
            .candidates
            .iter()
            .find(|c| c.binding.item_id == *id)
            .ok_or_else(|| io::Error::other("unknown item ID"))?;
        println!("{} — {}", row.binding.path.display, row.binding.consequence);
    }
    print!("Type exactly 'trash {} leftovers': ", ids.len());
    io::stdout().flush()?;
    let mut token = String::new();
    io::stdin().read_line(&mut token)?;
    let digest = session.preview().plan_digest.clone();
    let default = session.default_state_directory();
    let state = args.get_one::<PathBuf>("state-dir").unwrap_or(&default);
    let result = session
        .begin(&ids, &digest, token.trim_end_matches(['\r', '\n']), state)?
        .execute();
    println!("{}", serde_json::to_string_pretty(&result.record)?);
    if let Some(error) = &result.journal_error {
        eprintln!("Journal error: {error}");
    }
    Ok(result.exit_code())
}
#[cfg(not(target_os = "macos"))]
pub fn run(_: &ArgMatches) -> io::Result<u8> {
    Err(io::Error::other("orphan execution requires macOS"))
}
