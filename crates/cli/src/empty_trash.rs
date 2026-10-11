// SPDX-License-Identifier: MPL-2.0
use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use std::{io, path::PathBuf};
pub fn command() -> Command {
    Command::new("empty-trash")
        .about("Read-only known-subset evidence; never empties Trash or sends Finder events")
        .arg(
            Arg::new("journal-root")
                .long("journal-root")
                .action(ArgAction::Append)
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("schema")
                .long("schema")
                .required(true)
                .action(ArgAction::Append)
                .value_parser(value_parser!(u32)),
        )
        .arg(Arg::new("json").long("json").action(ArgAction::SetTrue))
}
#[cfg(target_os = "macos")]
pub fn run(a: &ArgMatches) -> io::Result<u8> {
    use sayaka_engine::{
        empty_trash::{EmptyTrashSession, SourceInput},
        journal::NativePath,
    };
    let schemas: Vec<_> = a.get_many::<u32>("schema").unwrap().copied().collect();
    let sources = a
        .get_many::<PathBuf>("journal-root")
        .into_iter()
        .flatten()
        .map(|p| SourceInput {
            path: NativePath::from_path(p),
            schemas: schemas.clone(),
        })
        .collect();
    let s = EmptyTrashSession::prepare(sources, None)?;
    println!("{}", serde_json::to_string_pretty(s.preview())?);
    Ok(0)
}
#[cfg(not(target_os = "macos"))]
pub fn run(_: &ArgMatches) -> io::Result<u8> {
    Err(io::Error::other("empty Trash observations require macOS"))
}
