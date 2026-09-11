// SPDX-License-Identifier: MPL-2.0

use clap::Command;

fn main() {
    Command::new("sayaka")
        .version(env!("CARGO_PKG_VERSION"))
        .about("An open-source local maintenance engine and CLI")
        .after_help("Initial scaffold only. Scanning and maintenance commands are not implemented.")
        .arg_required_else_help(true)
        .get_matches();
}
