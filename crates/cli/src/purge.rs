// SPDX-License-Identifier: MPL-2.0

use crate::{human, output};
use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use sayaka_engine::model::Cancellation;
use sayaka_engine::purge_preview::{
    self, DEFAULT_STALE_DAYS, MAX_STALE_DAYS, PurgeOptions, PurgePreview,
};
use sayaka_engine::scan::index::ScanTree;
use sayaka_engine::scan::{self, ScanCode, ScanError};
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::time::SystemTime;

pub fn command() -> Command {
    Command::new("purge")
        .about("Read-only preview of rebuildable project artifacts grouped by project")
        .arg(
            Arg::new("roots")
                .value_name("ROOT")
                .required(true)
                .num_args(1..)
                .help("Existing explicit directories to scan; no implicit HOME/cwd defaults")
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("stale-days")
                .long("stale-days")
                .value_name("DAYS")
                .help(format!(
                    "Artifact mtime staleness cutoff in days [default: {DEFAULT_STALE_DAYS}, max: {MAX_STALE_DAYS}]"
                ))
                .value_parser(value_parser!(u32)),
        )
        .arg(
            Arg::new("json")
                .long("json")
                .action(ArgAction::SetTrue)
                .help("Write one versioned JSON preview to stdout"),
        )
        .arg(
            Arg::new("progress")
                .long("progress")
                .action(ArgAction::SetTrue)
                .help("Show scan progress on stderr (NDJSON with --json)"),
        )
        .after_help(
            "Preview only: no directory effects exist in this slice. A name match alone never qualifies;\nevery artifact is bound to its project marker (rebuild evidence). mtime is an observation, not proof of disuse.",
        )
}

pub fn run(args: &ArgMatches) -> io::Result<u8> {
    let json = args.get_flag("json");
    let stderr_terminal = io::stderr().is_terminal();
    let dumb = std::env::var_os("TERM").is_some_and(|term| term == "dumb");
    let show_progress = args.get_flag("progress")
        || (!json && io::stdout().is_terminal() && stderr_terminal && !dumb);
    let style = human::Style {
        color: human::colors_allowed(
            stderr_terminal && cfg!(unix),
            std::env::var_os("NO_COLOR").is_some(),
            dumb,
            std::env::var_os("CLICOLOR").is_some_and(|value| value == "0"),
        ),
    };
    let mut progress = human::Progress::default();
    let mut progress_error = None;
    let result: Result<PurgePreview, ScanError> = (|| {
        let stale_days = args
            .get_one::<u32>("stale-days")
            .copied()
            .unwrap_or(DEFAULT_STALE_DAYS);
        let options = PurgeOptions { stale_days };
        options
            .validate()
            .map_err(|message| ScanError::new(ScanCode::InvalidLimits, message))?;
        let roots = args
            .get_many::<PathBuf>("roots")
            .ok_or_else(|| ScanError::new(ScanCode::InvalidRoot, "at least one root is required"))?
            .map(|root| {
                if root
                    .components()
                    .any(|part| matches!(part, std::path::Component::ParentDir))
                {
                    return Err(ScanError::new(
                        ScanCode::InvalidRoot,
                        "parent traversal is not accepted",
                    ));
                }
                std::path::absolute(root)
                    .map_err(|error| ScanError::new(ScanCode::InvalidRoot, error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let limits = sayaka_engine::scan::ScanLimits::default();
        limits
            .validate()
            .map_err(|error| ScanError::new(error.code, error.message))?;
        let cancellation = Cancellation::default();
        let signal = cancellation.clone();
        ctrlc::set_handler(move || signal.cancel()).map_err(|error| {
            ScanError::new(
                ScanCode::Internal,
                format!("cannot install interrupt handler: {error}"),
            )
        })?;
        let report = scan::scan(&roots, &limits, &cancellation, |event| {
            if show_progress && progress_error.is_none() {
                let written = if json {
                    output::progress(&mut io::stderr().lock(), event)
                } else {
                    progress.update(&mut io::stderr().lock(), event, style)
                };
                if let Err(error) = written {
                    cancellation.cancel();
                    progress_error = Some(error);
                }
            }
        })?;
        let index = ScanTree::build(report, &cancellation)?;
        purge_preview::purge_preview(&index, &options, SystemTime::now())
            .map_err(|message| ScanError::new(ScanCode::InvalidLimits, message))
    })();

    if let Some(error) = progress_error {
        if json {
            write_fatal_json(
                &mut io::stdout().lock(),
                ScanError::new(ScanCode::Io, format!("progress output failed: {error}")),
            )?;
        }
        return Err(error);
    }
    match result {
        Ok(preview) => {
            if json {
                write_json(&mut io::stdout().lock(), &preview)?;
            } else {
                write_human(&mut io::stdout().lock(), &preview)?;
            }
            Ok(match preview.status {
                purge_preview::PurgeStatus::Complete => 0,
                purge_preview::PurgeStatus::Partial => 3,
                purge_preview::PurgeStatus::Cancelled => 130,
                purge_preview::PurgeStatus::Failed => 1,
            })
        }
        Err(error) => {
            if json {
                write_fatal_json(&mut io::stdout().lock(), error.clone())?;
            } else {
                human::fatal(&mut io::stderr().lock(), &error, style)?;
            }
            Ok(
                if matches!(error.code, ScanCode::InvalidRoot | ScanCode::InvalidLimits) {
                    2
                } else {
                    1
                },
            )
        }
    }
}

fn write_fatal_json(out: &mut impl Write, error: ScanError) -> io::Result<()> {
    let value = serde_json::json!({
        "schema_version": purge_preview::PURGE_SCHEMA_VERSION,
        "kind": purge_preview::PURGE_KIND,
        "platform": if cfg!(target_os = "macos") { "macos" } else { "unsupported" },
        "status": "failed",
        "complete": false,
        "effects_performed": false,
        "roots": [],
        "stale_days": serde_json::Value::Null,
        "projects": [],
        "counts": {
            "projects": 0,
            "artifacts": 0,
            "stale_artifacts": 0,
            "excluded": 0,
        },
        "issues": [{
            "code": error.code.as_str(),
            "message": error.message,
            "os_code": error.os_code,
        }],
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

fn write_json(out: &mut impl Write, preview: &PurgePreview) -> io::Result<()> {
    let value = serde_json::json!({
        "schema_version": preview.schema_version,
        "kind": preview.kind,
        "platform": preview.platform,
        "status": preview.status.as_str(),
        "complete": preview.complete,
        "effects_performed": false,
        "roots": preview.roots.iter().map(|path| crate::apps::write_native_path(path)).collect::<Vec<_>>(),
        "stale_days": preview.stale_days,
        "projects": preview.projects.iter().map(|project| serde_json::json!({
            "root": crate::apps::write_native_path(&project.root),
            "markers": project.markers.iter().map(|marker| marker.as_str()).collect::<Vec<_>>(),
            "artifacts": project.artifacts.iter().map(|artifact| serde_json::json!({
                "path": crate::apps::write_native_path(&artifact.path),
                "name": artifact.name,
                "markers": artifact.markers.iter().map(|marker| marker.as_str()).collect::<Vec<_>>(),
                "logical_bytes": artifact.logical_bytes,
                "allocated_bytes": artifact.allocated_bytes,
                "complete": artifact.complete,
                "modified_unix_ms": artifact.modified_unix_ms,
                "stale": artifact.stale,
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "counts": {
            "projects": preview.counts.projects,
            "artifacts": preview.counts.artifacts,
            "stale_artifacts": preview.counts.stale_artifacts,
            "excluded": preview.counts.excluded,
        },
        "scan_issues": preview.scan_issues.iter().map(|issue| serde_json::json!({
            "path": issue.path.as_deref().map(crate::apps::write_native_path),
            "code": issue.code.as_str(),
            "message": issue.message,
            "os_code": issue.os_code,
        })).collect::<Vec<_>>(),
        "scan_issues_omitted": preview.scan_issues_omitted,
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

fn write_human(out: &mut impl Write, preview: &PurgePreview) -> io::Result<()> {
    writeln!(out, "kind: {}", preview.kind)?;
    writeln!(out, "status: {}", preview.status.as_str())?;
    writeln!(out, "complete: {}", preview.complete)?;
    writeln!(out, "effects_performed: false")?;
    writeln!(out, "stale_days: {}", preview.stale_days)?;
    writeln!(out, "projects:")?;
    for project in &preview.projects {
        let markers = project
            .markers
            .iter()
            .map(|marker| marker.as_str())
            .collect::<Vec<_>>()
            .join(",");
        writeln!(
            out,
            "  - {} [{}]",
            sayaka_engine::scan::display_path(&project.root),
            markers
        )?;
        for artifact in &project.artifacts {
            let size = artifact
                .logical_bytes
                .map(crate::human::size)
                .unwrap_or_else(|| "unknown".into());
            let stale = match artifact.stale {
                Some(true) => "stale",
                Some(false) => "fresh",
                None => "unknown-age",
            };
            let coverage = if artifact.complete {
                ""
            } else {
                ", partial coverage"
            };
            writeln!(out, "    - {} ({size}, {stale}{coverage})", artifact.name)?;
        }
    }
    if preview.counts.excluded > 0 {
        writeln!(
            out,
            "excluded (nested inside another artifact or dataless): {}",
            preview.counts.excluded
        )?;
    }
    writeln!(
        out,
        "Preview only; no directory effects exist in this slice."
    )?;
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn json_preview_groups_artifacts_with_explicit_states() {
        let root = tempfile::tempdir().expect("tempdir");
        let project = root.path().join("app");
        fs::create_dir_all(project.join("target")).expect("tree");
        fs::write(project.join("Cargo.toml"), b"[package]").expect("marker");
        fs::write(project.join("target").join("bin"), b"x").expect("bin");
        let cancellation = Cancellation::default();
        let report = scan::scan(
            &[root.path().to_path_buf()],
            &sayaka_engine::scan::ScanLimits::default(),
            &cancellation,
            |_| {},
        )
        .expect("scan");
        let index = ScanTree::build(report, &cancellation).expect("index");
        let preview =
            purge_preview::purge_preview(&index, &PurgeOptions::default(), SystemTime::now())
                .expect("preview");
        let mut out = Vec::new();
        write_json(&mut out, &preview).expect("json");
        let value: serde_json::Value = serde_json::from_slice(&out).expect("parse");
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["kind"], purge_preview::PURGE_KIND);
        assert_eq!(value["effects_performed"], false);
        assert_eq!(value["counts"]["projects"], 1);
        assert_eq!(value["projects"][0]["markers"][0], "cargo");
        assert_eq!(value["projects"][0]["artifacts"][0]["name"], "target");
        assert_eq!(value["projects"][0]["artifacts"][0]["stale"], false);
        assert!(value["projects"][0]["artifacts"][0]["logical_bytes"].is_u64());
    }

    #[test]
    fn fatal_json_keeps_the_purge_envelope_shape() {
        let mut out = Vec::new();
        write_fatal_json(
            &mut out,
            ScanError::new(ScanCode::InvalidRoot, "test refusal"),
        )
        .expect("fatal json");
        let value: serde_json::Value = serde_json::from_slice(&out).expect("parse");
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["kind"], purge_preview::PURGE_KIND);
        assert_eq!(value["status"], "failed");
        assert_eq!(value["effects_performed"], false);
        assert!(value["projects"].as_array().expect("projects").is_empty());
        assert_eq!(value["issues"][0]["code"], "invalid_root");
        assert_eq!(value["issues"][0]["message"], "test refusal");
    }
}
