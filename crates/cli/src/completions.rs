// SPDX-License-Identifier: MPL-2.0

use clap::{Arg, ArgMatches, Command, value_parser};
use clap_complete::Shell;
use std::io::{self, Write};

pub fn command() -> Command {
    Command::new("completions")
        .about("Print a completion script for manual Shell configuration")
        .arg(
            Arg::new("shell")
                .required(true)
                .value_parser(value_parser!(Shell)),
        )
        .after_help(
            "Writes only stdout. Does not source scripts, edit startup files, or modify PATH.",
        )
}

pub fn run(args: &ArgMatches) -> io::Result<u8> {
    let shell = *args
        .get_one::<Shell>("shell")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "shell is required"))?;
    let bytes = generate(shell)?;
    let mut out = io::stdout().lock();
    out.write_all(&bytes)?;
    out.flush()?;
    Ok(0)
}

fn generate(shell: Shell) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    // Generate into memory: clap_complete's infallible writer interface must
    // not panic on a user's broken stdout pipe.
    clap_complete::generate(shell, &mut crate::command(), "sayaka", &mut output);
    if output.len() > 1024 * 1024 {
        return Err(io::Error::other(
            "completion output exceeds its byte budget",
        ));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scripts_follow_the_actual_command_tree() {
        for shell in [
            Shell::Bash,
            Shell::Zsh,
            Shell::Fish,
            Shell::PowerShell,
            Shell::Elvish,
        ] {
            let output = String::from_utf8(generate(shell).unwrap()).unwrap();
            for name in [
                "scan",
                "browse",
                "menu",
                "trash",
                "receipt",
                "status",
                "history",
                "rules",
                "completions",
                "install",
                "update",
                "recover",
                "remove",
            ] {
                assert!(output.contains(name), "{shell}: {name}");
            }
        }
    }
}
