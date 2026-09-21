// SPDX-License-Identifier: MPL-2.0

//! Raycast/Alfred terminal launcher generation with owned-artifact cleanup.
//!
//! Generated scripts only ask the chosen supported terminal to open a window
//! running `sayaka menu`. They never edit Raycast/Alfred configuration, shell
//! startup files or PATH. Installed artifacts live in one dedicated directory
//! with a SHA-256 ownership manifest; removal deletes exactly the verified
//! owned files and refuses unknown or modified content.

use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const MANIFEST_NAME: &str = ".sayaka-launchers.json";
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_SCRIPT_BYTES: usize = 64 * 1024;

pub fn command() -> Command {
    let terminal = Arg::new("terminal")
        .long("terminal")
        .value_name("TERMINAL")
        .value_parser(["terminal-app", "iterm2"])
        .default_value("terminal-app")
        .help("Terminal used to open the Sayaka window");
    let bin = Arg::new("bin")
        .long("bin")
        .value_name("PATH")
        .value_parser(value_parser!(PathBuf))
        .help("Sayaka executable to launch [default: this running executable]");
    let dir = Arg::new("dir")
        .long("dir")
        .value_name("DIR")
        .required(true)
        .value_parser(value_parser!(PathBuf))
        .help("Dedicated launcher directory (created on install)");
    let execute = Arg::new("execute")
        .long("execute")
        .action(ArgAction::SetTrue)
        .help("Explicitly apply this owned-directory operation");
    let json = Arg::new("json").long("json").action(ArgAction::SetTrue);
    Command::new("launchers")
        .about("Generate or manage Raycast/Alfred terminal launcher scripts")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("print")
                .about("Print one launcher script to stdout without writing files")
                .arg(
                    Arg::new("flavor")
                        .value_name("FLAVOR")
                        .required(true)
                        .value_parser(["raycast", "alfred"]),
                )
                .arg(terminal.clone())
                .arg(bin.clone())
                .after_help(
                    "Writes only stdout. Does not install artifacts or edit any configuration.",
                ),
        )
        .subcommand(
            Command::new("install")
                .about("Preview installing owned launcher scripts into a dedicated directory")
                .arg(dir.clone())
                .arg(terminal)
                .arg(bin)
                .arg(execute.clone())
                .arg(json.clone())
                .after_help(
                    "Writes both Raycast and Alfred scripts plus a SHA-256 ownership manifest.\nThe directory must be absent, empty, or already owned by this tool. Unknown or modified files cause refusal.\nNo Raycast/Alfred configuration, PATH or startup file is changed.",
                ),
        )
        .subcommand(
            Command::new("remove")
                .about("Preview removing exactly the verified owned launcher artifacts")
                .arg(dir)
                .arg(execute)
                .arg(json)
                .after_help(
                    "Deletes only manifest-listed files whose bytes still match their recorded SHA-256.\nModified, missing or unknown files cause refusal; the directory is removed only when left empty.",
                ),
        )
}

pub fn run(args: &ArgMatches) -> io::Result<u8> {
    let (result, json_on_error) = match args.subcommand() {
        Some(("print", args)) => (print(args), false),
        Some(("install", args)) => (install(args), args.get_flag("json")),
        Some(("remove", args)) => (remove(args), args.get_flag("json")),
        _ => (Ok(2), false),
    };
    match result {
        Ok(code) => Ok(code),
        Err(error) => {
            if json_on_error && error.kind() != io::ErrorKind::BrokenPipe {
                json(&serde_json::json!({
                    "schema_version": 1,
                    "kind": "launchers_result",
                    "status": "failed",
                    "error": {
                        "code": format!("{:?}", error.kind()),
                        "message": error.to_string(),
                    },
                }))?;
            }
            writeln!(
                io::stderr().lock(),
                "launcher operation failed: {:?}",
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Flavor {
    Raycast,
    Alfred,
}

impl Flavor {
    fn parse(value: &str) -> io::Result<Self> {
        match value {
            "raycast" => Ok(Self::Raycast),
            "alfred" => Ok(Self::Alfred),
            _ => Err(invalid(format!("unsupported launcher flavor {value:?}"))),
        }
    }

    fn file_name(self) -> &'static str {
        match self {
            Self::Raycast => "sayaka-raycast.sh",
            Self::Alfred => "sayaka-alfred.sh",
        }
    }
}

#[derive(Clone, Copy)]
enum Terminal {
    TerminalApp,
    Iterm2,
}

impl Terminal {
    fn parse(value: &str) -> io::Result<Self> {
        match value {
            "terminal-app" => Ok(Self::TerminalApp),
            "iterm2" => Ok(Self::Iterm2),
            _ => Err(invalid(format!("unsupported terminal {value:?}"))),
        }
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn shell_single_quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

fn applescript_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

fn osascript_arguments(terminal: Terminal, command_line: &str) -> Vec<String> {
    let application = match terminal {
        Terminal::TerminalApp => "Terminal",
        Terminal::Iterm2 => "iTerm2",
    };
    let action = match terminal {
        Terminal::TerminalApp => format!("do script {}", applescript_string(command_line)),
        Terminal::Iterm2 => format!(
            "create window with default profile command {}",
            applescript_string(command_line)
        ),
    };
    vec![
        format!("tell application \"{application}\""),
        "activate".to_string(),
        action,
        "end tell".to_string(),
    ]
}

fn script(flavor: Flavor, terminal: Terminal, command_line: &str) -> io::Result<Vec<u8>> {
    let mut text = String::from(
        "#!/bin/sh\n# Sayaka terminal launcher. Generated artifact owned by `sayaka launchers`;\n# edits are detected and refused by `sayaka launchers remove`.\n",
    );
    match flavor {
        Flavor::Raycast => text.push_str(
            "# Required parameters:\n# @raycast.schemaVersion 1\n# @raycast.title Sayaka Menu\n# @raycast.mode silent\n# Optional parameters:\n# @raycast.packageName Sayaka\n",
        ),
        Flavor::Alfred => text.push_str(
            "# Alfred: connect a Keyword input to a Run Script action (Language /bin/sh)\n# containing this script, or point the action at this installed file.\n",
        ),
    }
    text.push_str("set -eu\n/usr/bin/osascript");
    for argument in osascript_arguments(terminal, command_line) {
        text.push_str(" \\\n  -e ");
        text.push_str(&shell_single_quote(&argument));
    }
    text.push('\n');
    let bytes = text.into_bytes();
    if bytes.len() > MAX_SCRIPT_BYTES {
        return Err(io::Error::other("launcher script exceeds its byte budget"));
    }
    Ok(bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
struct OwnedFile {
    name: String,
    bytes: u64,
    sha256: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
struct Manifest {
    schema_version: u32,
    kind: String,
    files: Vec<OwnedFile>,
}

impl Manifest {
    fn validate(&self) -> io::Result<()> {
        if self.schema_version != 1
            || self.kind != "sayaka_launchers"
            || self.files.is_empty()
            || self.files.len() > 16
        {
            return Err(invalid(
                "unsupported or malformed launcher ownership manifest",
            ));
        }
        for file in &self.files {
            let name = Path::new(&file.name);
            if file.name.is_empty()
                || file.name.contains('/')
                || name.file_name().is_none_or(|n| n != file.name.as_str())
                || file.sha256.len() != 64
                || !file.sha256.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err(invalid(
                    "unsupported or malformed launcher ownership manifest",
                ));
            }
        }
        let mut unique = std::collections::HashSet::with_capacity(self.files.len());
        if !self
            .files
            .iter()
            .all(|file| unique.insert(file.name.as_str()))
        {
            return Err(invalid(
                "launcher ownership manifest lists a file more than once",
            ));
        }
        Ok(())
    }
}

struct PlannedFile {
    name: &'static str,
    bytes: Vec<u8>,
    sha256: String,
}

fn planned_files(terminal: Terminal, command_line: &str) -> io::Result<Vec<PlannedFile>> {
    [Flavor::Raycast, Flavor::Alfred]
        .into_iter()
        .map(|flavor| {
            let bytes = script(flavor, terminal, command_line)?;
            let sha256 = sha256_hex(&bytes);
            Ok(PlannedFile {
                name: flavor.file_name(),
                bytes,
                sha256,
            })
        })
        .collect()
}

fn command_line(bin: Option<&PathBuf>) -> io::Result<String> {
    let path = match bin {
        Some(path) => path.clone(),
        None => std::env::current_exe()?,
    };
    if path
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(invalid("'..' executable path traversal is not accepted"));
    }
    let path = std::path::absolute(&path)?;
    if bin.is_some() && !path.is_file() {
        return Err(invalid(format!(
            "executable {} is not an existing regular file",
            path.display()
        )));
    }
    let text = path.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "executable path is not valid UTF-8 and cannot be scripted",
        )
    })?;
    if text.chars().any(char::is_control) {
        return Err(invalid(
            "executable path contains control characters and cannot be scripted",
        ));
    }
    Ok(format!("{} menu", shell_single_quote(text)))
}

fn checked_dir(value: &PathBuf) -> io::Result<PathBuf> {
    if value
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(invalid("'..' directory traversal is not accepted"));
    }
    std::path::absolute(value)
}

fn read_manifest(dir: &Path) -> io::Result<Manifest> {
    let path = dir.join(MANIFEST_NAME);
    let metadata = fs::symlink_metadata(&path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("cannot inspect {}: {error}", path.display()),
        )
    })?;
    if !metadata.is_file() || metadata.len() > MAX_MANIFEST_BYTES {
        return Err(invalid(
            "launcher ownership manifest is missing, not a regular file, or too large",
        ));
    }
    let bytes = fs::read(&path)?;
    let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("launcher ownership manifest is not valid JSON: {error}"),
        )
    })?;
    manifest.validate()?;
    Ok(manifest)
}

fn verify_owned(dir: &Path, manifest: &Manifest) -> io::Result<()> {
    for file in &manifest.files {
        let path = dir.join(&file.name);
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("owned launcher {} is missing: {error}", path.display()),
            )
        })?;
        if !metadata.is_file() || metadata.len() != file.bytes {
            return Err(invalid(format!(
                "owned launcher {} changed; refusing to touch it",
                path.display()
            )));
        }
        let bytes = fs::read(&path)?;
        if sha256_hex(&bytes) != file.sha256 {
            return Err(invalid(format!(
                "owned launcher {} changed; refusing to touch it",
                path.display()
            )));
        }
    }
    Ok(())
}

fn dir_entries(dir: &Path) -> io::Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "launcher directory contains a non-UTF-8 entry",
            )
        })?;
        names.push(name.to_string());
    }
    names.sort();
    Ok(names)
}

enum DirState {
    Absent,
    Empty,
    Owned(Manifest),
}

fn dir_state(dir: &Path) -> io::Result<DirState> {
    match fs::symlink_metadata(dir) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(DirState::Absent),
        Err(error) => return Err(error),
        Ok(metadata) if !metadata.is_dir() => {
            return Err(invalid(format!(
                "{} exists and is not a directory",
                dir.display()
            )));
        }
        Ok(_) => {}
    }
    let entries = dir_entries(dir)?;
    if entries.is_empty() {
        return Ok(DirState::Empty);
    }
    if !entries.iter().any(|name| name == MANIFEST_NAME) {
        return Err(invalid(format!(
            "{} contains files not owned by this tool; refusing to touch it",
            dir.display()
        )));
    }
    let manifest = read_manifest(dir)?;
    let mut expected: Vec<&str> = manifest.files.iter().map(|f| f.name.as_str()).collect();
    expected.push(MANIFEST_NAME);
    expected.sort_unstable();
    if entries != expected {
        return Err(invalid(format!(
            "{} contains files not owned by this tool; refusing to touch it",
            dir.display()
        )));
    }
    Ok(DirState::Owned(manifest))
}

fn print(args: &ArgMatches) -> io::Result<u8> {
    let flavor = Flavor::parse(
        args.get_one::<String>("flavor")
            .map(String::as_str)
            .unwrap_or_default(),
    )?;
    let terminal = Terminal::parse(
        args.get_one::<String>("terminal")
            .map(String::as_str)
            .unwrap_or_default(),
    )?;
    let bytes = script(
        flavor,
        terminal,
        &command_line(args.get_one::<PathBuf>("bin"))?,
    )?;
    let mut out = io::stdout().lock();
    out.write_all(&bytes)?;
    out.flush()?;
    Ok(0)
}

#[derive(Serialize)]
struct PlannedOutput<'a> {
    name: &'a str,
    bytes: usize,
    sha256: &'a str,
}

fn install(args: &ArgMatches) -> io::Result<u8> {
    let dir = checked_dir(
        args.get_one::<PathBuf>("dir")
            .ok_or_else(|| invalid("--dir is required"))?,
    )?;
    let terminal = Terminal::parse(
        args.get_one::<String>("terminal")
            .map(String::as_str)
            .unwrap_or_default(),
    )?;
    let files = planned_files(terminal, &command_line(args.get_one::<PathBuf>("bin"))?)?;
    let state = dir_state(&dir)?;
    let replacing = match &state {
        DirState::Absent | DirState::Empty => false,
        DirState::Owned(manifest) => {
            verify_owned(&dir, manifest)?;
            true
        }
    };
    let apply = args.get_flag("execute");
    let outputs: Vec<PlannedOutput<'_>> = files
        .iter()
        .map(|file| PlannedOutput {
            name: file.name,
            bytes: file.bytes.len(),
            sha256: &file.sha256,
        })
        .collect();
    if !apply || !args.get_flag("json") {
        if args.get_flag("json") {
            json(&serde_json::json!({
                "schema_version": 1,
                "kind": "launchers_preview",
                "action": "install",
                "effects_performed": false,
                "dir": dir.display().to_string(),
                "replacing_owned_installation": replacing,
                "files": outputs,
            }))?;
        } else {
            let mut out = io::stdout().lock();
            writeln!(out, "Launchers install preview: {}", dir.display())?;
            if replacing {
                writeln!(out, "Replacing the verified owned launcher artifacts.")?;
            }
            for file in &outputs {
                writeln!(
                    out,
                    "Write {} ({} bytes, SHA-256 {})",
                    file.name, file.bytes, file.sha256
                )?;
            }
            writeln!(
                out,
                "Preview only without --execute. No Raycast/Alfred configuration, PATH or startup file is changed."
            )?;
            out.flush()?;
        }
    }
    if !apply {
        return Ok(0);
    }
    // Re-validate the dedicated directory state immediately before effects;
    // refuse if it changed since the checks above.
    match dir_state(&dir)? {
        DirState::Absent | DirState::Empty => {}
        DirState::Owned(manifest) => verify_owned(&dir, &manifest)?,
    }
    fs::create_dir_all(&dir)?;
    let manifest = Manifest {
        schema_version: 1,
        kind: "sayaka_launchers".to_string(),
        files: files
            .iter()
            .map(|file| OwnedFile {
                name: file.name.to_string(),
                bytes: file.bytes.len() as u64,
                sha256: file.sha256.clone(),
            })
            .collect(),
    };
    for file in &files {
        write_atomic(&dir.join(file.name), &file.bytes, true)?;
    }
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).map_err(io::Error::other)?;
    write_atomic(&dir.join(MANIFEST_NAME), &manifest_bytes, false)?;
    if args.get_flag("json") {
        json(&serde_json::json!({
            "schema_version": 1,
            "kind": "launchers_result",
            "action": "install",
            "status": "installed",
            "dir": dir.display().to_string(),
            "files": outputs,
        }))?;
    } else {
        let mut out = io::stdout().lock();
        writeln!(out, "Installed launcher artifacts: {}", dir.display())?;
        writeln!(
            out,
            "Point Raycast Script Commands or an Alfred Run Script action at this directory manually."
        )?;
        out.flush()?;
    }
    Ok(0)
}

fn write_atomic(path: &Path, bytes: &[u8], executable: bool) -> io::Result<()> {
    let tmp = path.with_extension("sayaka-tmp");
    let result = (|| -> io::Result<()> {
        {
            let mut file = fs::File::create(&tmp)?;
            file.write_all(bytes)?;
            file.sync_all()?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = if executable { 0o755 } else { 0o644 };
            fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
        }
        fs::rename(&tmp, path)
    })();
    result.map_err(|error| {
        let cleaned = fs::remove_file(&tmp).is_ok();
        io::Error::new(
            error.kind(),
            format!(
                "{error} (temporary file {} {})",
                tmp.display(),
                if cleaned {
                    "cleaned up"
                } else {
                    "could not be removed; delete it manually"
                }
            ),
        )
    })
}

fn remove(args: &ArgMatches) -> io::Result<u8> {
    let dir = checked_dir(
        args.get_one::<PathBuf>("dir")
            .ok_or_else(|| invalid("--dir is required"))?,
    )?;
    // The directory inventory must exactly match the verified ownership
    // manifest; any unknown entry refuses the whole operation.
    let manifest = match dir_state(&dir)? {
        DirState::Owned(manifest) => manifest,
        DirState::Absent => {
            return Err(invalid(format!("{} does not exist", dir.display())));
        }
        DirState::Empty => {
            return Err(invalid(format!(
                "{} contains no owned launcher artifacts",
                dir.display()
            )));
        }
    };
    verify_owned(&dir, &manifest)?;
    let apply = args.get_flag("execute");
    let names: Vec<&str> = manifest
        .files
        .iter()
        .map(|file| file.name.as_str())
        .collect();
    if !apply || !args.get_flag("json") {
        if args.get_flag("json") {
            json(&serde_json::json!({
                "schema_version": 1,
                "kind": "launchers_preview",
                "action": "remove",
                "effects_performed": false,
                "dir": dir.display().to_string(),
                "files": names,
            }))?;
        } else {
            let mut out = io::stdout().lock();
            writeln!(out, "Launchers remove preview: {}", dir.display())?;
            for name in &names {
                writeln!(out, "Delete owned artifact {name}")?;
            }
            writeln!(
                out,
                "Preview only without --execute. Raycast/Alfred configuration stays untouched."
            )?;
            out.flush()?;
        }
    }
    if !apply {
        return Ok(0);
    }
    // Re-check the exact inventory and each owned hash immediately before
    // deletion; refuse to delete anything that changed since the preview.
    match dir_state(&dir)? {
        DirState::Owned(current) => verify_owned(&dir, &current)?,
        _ => {
            return Err(invalid(format!(
                "{} changed during removal; refusing to touch it",
                dir.display()
            )));
        }
    }
    for name in &names {
        fs::remove_file(dir.join(name))?;
    }
    fs::remove_file(dir.join(MANIFEST_NAME))?;
    let dir_removed = fs::remove_dir(&dir).is_ok();
    if args.get_flag("json") {
        json(&serde_json::json!({
            "schema_version": 1,
            "kind": "launchers_result",
            "action": "remove",
            "status": "removed",
            "dir": dir.display().to_string(),
            "files": names,
            "dir_removed": dir_removed,
        }))?;
    } else {
        let mut out = io::stdout().lock();
        writeln!(out, "Removed owned launcher artifacts: {}", dir.display())?;
        if !dir_removed {
            writeln!(
                out,
                "Directory could not be removed; inspect and remove it manually."
            )?;
        }
        out.flush()?;
    }
    Ok(0)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_single_quote_escapes_quotes() {
        assert_eq!(shell_single_quote("plain"), "'plain'");
        assert_eq!(shell_single_quote("a'b"), "'a'\\''b'");
        assert_eq!(
            shell_single_quote("/tmp/has space/sayaka"),
            "'/tmp/has space/sayaka'"
        );
    }

    #[test]
    fn applescript_string_escapes_backslash_and_quote() {
        assert_eq!(applescript_string("a\\b\"c"), "\"a\\\\b\\\"c\"");
    }

    #[test]
    fn raycast_script_carries_metadata_and_command() {
        let bytes = script(Flavor::Raycast, Terminal::TerminalApp, "'/opt/sayaka' menu").unwrap();
        let text = String::from_utf8(bytes).unwrap();
        for needle in [
            "@raycast.schemaVersion 1",
            "@raycast.title Sayaka Menu",
            "@raycast.mode silent",
            "tell application \"Terminal\"",
            "do script \"",
            "'/opt/sayaka' menu",
        ] {
            assert!(text.contains(needle), "{needle}");
        }
        assert!(!text.contains("create window with default profile"));
    }

    #[test]
    fn iterm2_script_uses_iterm_vocabulary_without_raycast_metadata() {
        let bytes = script(Flavor::Alfred, Terminal::Iterm2, "'/opt/sayaka' menu").unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("tell application \"iTerm2\""));
        assert!(text.contains("create window with default profile command"));
        assert!(!text.contains("@raycast"));
    }

    #[test]
    fn tricky_paths_are_escaped_at_both_layers() {
        let bytes = script(
            Flavor::Raycast,
            Terminal::TerminalApp,
            &command_line(Some(&PathBuf::from("/tmp/has space/it's sayaka"))).unwrap(),
        )
        .unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("it'\\''s sayaka"));
    }

    #[test]
    fn manifest_roundtrip_and_validation() {
        let manifest = Manifest {
            schema_version: 1,
            kind: "sayaka_launchers".into(),
            files: vec![OwnedFile {
                name: "sayaka-raycast.sh".into(),
                bytes: 3,
                sha256: sha256_hex(b"abc"),
            }],
        };
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let parsed: Manifest = serde_json::from_slice(&bytes).unwrap();
        parsed.validate().unwrap();
        assert_eq!(parsed, manifest);
        let mut bad = manifest.clone();
        bad.files[0].name = "../escape".into();
        assert!(bad.validate().is_err());
        let mut duplicate = manifest.clone();
        duplicate.files.push(duplicate.files[0].clone());
        assert!(duplicate.validate().is_err());
        let mut wrong_kind = manifest;
        wrong_kind.kind = "other".into();
        assert!(wrong_kind.validate().is_err());
    }

    #[test]
    fn install_then_remove_roundtrip_in_tempdir() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("launchers");
        let files = planned_files(Terminal::TerminalApp, "'/bin/echo' menu").unwrap();
        assert!(matches!(dir_state(&dir).unwrap(), DirState::Absent));
        fs::create_dir_all(&dir).unwrap();
        assert!(matches!(dir_state(&dir).unwrap(), DirState::Empty));
        for file in &files {
            write_atomic(&dir.join(file.name), &file.bytes, true).unwrap();
        }
        let manifest = Manifest {
            schema_version: 1,
            kind: "sayaka_launchers".into(),
            files: files
                .iter()
                .map(|f| OwnedFile {
                    name: f.name.into(),
                    bytes: f.bytes.len() as u64,
                    sha256: f.sha256.clone(),
                })
                .collect(),
        };
        write_atomic(
            &dir.join(MANIFEST_NAME),
            &serde_json::to_vec_pretty(&manifest).unwrap(),
            false,
        )
        .unwrap();
        match dir_state(&dir).unwrap() {
            DirState::Owned(found) => {
                verify_owned(&dir, &found).unwrap();
                assert_eq!(found, manifest);
            }
            _ => panic!("expected owned directory"),
        }
        for name in ["sayaka-raycast.sh", "sayaka-alfred.sh", MANIFEST_NAME] {
            fs::remove_file(dir.join(name)).unwrap();
        }
        fs::remove_dir(&dir).unwrap();
        assert!(matches!(dir_state(&dir).unwrap(), DirState::Absent));
    }

    #[test]
    fn install_refuses_directory_with_unknown_files() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("launchers");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("stranger.txt"), b"not ours").unwrap();
        assert!(matches!(dir_state(&dir), Err(e) if e.kind() == io::ErrorKind::InvalidInput));
    }

    #[test]
    fn remove_refuses_owned_directory_with_extra_entries() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("launchers");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("sayaka-raycast.sh"), b"original").unwrap();
        let manifest = Manifest {
            schema_version: 1,
            kind: "sayaka_launchers".into(),
            files: vec![OwnedFile {
                name: "sayaka-raycast.sh".into(),
                bytes: 8,
                sha256: sha256_hex(b"original"),
            }],
        };
        fs::write(
            dir.join(MANIFEST_NAME),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        assert!(matches!(dir_state(&dir), Ok(DirState::Owned(_))));
        fs::write(dir.join("user-note.txt"), b"mine").unwrap();
        assert!(matches!(dir_state(&dir), Err(e) if e.kind() == io::ErrorKind::InvalidInput));
    }

    #[test]
    fn remove_refuses_modified_owned_file() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("launchers");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("sayaka-raycast.sh"), b"original").unwrap();
        let manifest = Manifest {
            schema_version: 1,
            kind: "sayaka_launchers".into(),
            files: vec![OwnedFile {
                name: "sayaka-raycast.sh".into(),
                bytes: 8,
                sha256: sha256_hex(b"original"),
            }],
        };
        fs::write(
            dir.join(MANIFEST_NAME),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        fs::write(dir.join("sayaka-raycast.sh"), b"modified").unwrap();
        assert!(matches!(dir_state(&dir), Ok(DirState::Owned(_))));
        assert!(verify_owned(&dir, &manifest).is_err());
    }

    #[test]
    fn non_utf8_or_missing_bin_is_refused() {
        assert!(command_line(Some(&PathBuf::from("/definitely/not/here"))).is_err());
        assert!(command_line(Some(&PathBuf::from("../relative"))).is_err());
    }

    #[test]
    fn control_characters_in_bin_path_are_refused() {
        let root = tempfile::tempdir().unwrap();
        let newline = root.path().join("line\nbreak");
        fs::write(&newline, b"x").unwrap();
        assert!(matches!(
            command_line(Some(&newline)),
            Err(e) if e.kind() == io::ErrorKind::InvalidInput
        ));
    }
}
