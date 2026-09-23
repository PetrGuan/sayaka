// SPDX-License-Identifier: MPL-2.0

use crate::{human, output};
use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use sayaka_engine::execute::PurgeSession;
use sayaka_engine::journal::Store;
use sayaka_engine::model::Cancellation;
use sayaka_engine::purge_preview::{
    self, DEFAULT_STALE_DAYS, MAX_STALE_DAYS, PurgeOptions, PurgePreview, PurgeProfile,
};
use sayaka_engine::scan::index::ScanTree;
use sayaka_engine::scan::{self, ScanCode, ScanError};
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::path::PathBuf;
use std::time::SystemTime;

pub fn command() -> Command {
    Command::new("purge")
        .about("Preview rebuildable project artifacts, or Trash the explicitly selected ones")
        .arg(
            Arg::new("profile")
                .long("profile")
                .value_name("PROFILE")
                .default_value("projects")
                .value_parser(["projects", "developer-caches"])
                .help("Preview profile: marker-bound project artifacts or known developer cache locations"),
        )
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
        .arg(
            Arg::new("execute")
                .long("execute")
                .action(ArgAction::SetTrue)
                .help("Move the --only-selected artifacts to Trash after typed confirmation (120-second approval)"),
        )
        .arg(
            Arg::new("only")
                .long("only")
                .value_name("PATH")
                .action(ArgAction::Append)
                .value_parser(value_parser!(PathBuf))
                .help("Artifact directory from this invocation's preview selected for execution (repeatable, 1..32)"),
        )
        .arg(
            Arg::new("state-dir")
                .long("state-dir")
                .value_name("DIR")
                .value_parser(value_parser!(PathBuf))
                .help("Private M3 journal directory for the durable intent/outcome record"),
        )
        .after_help(
            "Default is a read-only preview. --execute requires an interactive terminal and explicit\n--only selections from this invocation's preview (no select-all, no staleness rule); each\nartifact moves to Trash as one container (recovery: Finder 'Put Back' plus rebuild from the\nretained marker; markers are never targets). A running build tool is not detected; displayed\nbytes are observations, not reclaimed space.",
        )
}

pub fn run(args: &ArgMatches) -> io::Result<u8> {
    match run_inner(args) {
        Ok(code) => Ok(code),
        Err(error) => {
            writeln!(io::stderr().lock(), "purge failed: {:?}", error.to_string())?;
            Ok(if error.kind() == io::ErrorKind::InvalidInput {
                2
            } else {
                1
            })
        }
    }
}

fn run_inner(args: &ArgMatches) -> io::Result<u8> {
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
    let execute = args.get_flag("execute");
    let only: Vec<PathBuf> = args
        .get_many::<PathBuf>("only")
        .into_iter()
        .flatten()
        .cloned()
        .collect();
    if execute {
        if json {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--json applies to the read-only preview; --execute prints a journaled execution report instead",
            ));
        }
        if !(io::stdin().is_terminal() && io::stdout().is_terminal() && io::stderr().is_terminal())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--execute requires an interactive terminal; piped approval is not accepted",
            ));
        }
        if only.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--execute without --only selects nothing and is refused",
            ));
        }
    } else if !only.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--only only applies together with --execute",
        ));
    }
    let cancellation = Cancellation::default();
    let signal = cancellation.clone();
    ctrlc::set_handler(move || signal.cancel()).map_err(io::Error::other)?;
    let scan_cancellation = cancellation.clone();
    let requested_profile = match args
        .get_one::<String>("profile")
        .map(String::as_str)
        .unwrap_or("projects")
    {
        "projects" => PurgeProfile::Projects,
        "developer-caches" => PurgeProfile::DeveloperCaches,
        _ => unreachable!("clap value_parser enforces profile values"),
    };
    let result: Result<PurgePreview, ScanError> = (|| {
        let stale_days = args
            .get_one::<u32>("stale-days")
            .copied()
            .unwrap_or(DEFAULT_STALE_DAYS);
        let profile = requested_profile;
        if execute && profile != PurgeProfile::Projects {
            return Err(ScanError::new(
                ScanCode::InvalidLimits,
                "--execute is unsupported for --profile developer-caches; this profile is preview-only until a non-project cache revalidation contract exists",
            ));
        }
        let options = PurgeOptions {
            stale_days,
            profile,
        };
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
        let cancellation = scan_cancellation;
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
                requested_profile,
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
            if execute {
                return run_execution(args, &preview, &only, &cancellation);
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
                write_fatal_json(&mut io::stdout().lock(), requested_profile, error.clone())?;
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

fn run_execution(
    args: &ArgMatches,
    preview: &PurgePreview,
    only: &[PathBuf],
    cancellation: &Cancellation,
) -> io::Result<u8> {
    if preview.status != purge_preview::PurgeStatus::Complete {
        // A partial scan may have missed a containing artifact; the nesting
        // exclusion is only trustworthy on complete coverage.
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "--execute requires a complete preview; status is {}",
                preview.status.as_str()
            ),
        ));
    }
    let selections = purge_preview::resolve_selections_by_paths(preview, only)
        .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message))?;
    let mut session = PurgeSession::prepare(&selections, cancellation)?;
    for issue in session.issues() {
        writeln!(
            io::stderr().lock(),
            "candidate issue: {}: {}",
            issue.path.display,
            issue.message
        )?;
    }
    let refusals = session.refusals();
    if !refusals.is_empty() {
        let mut err = io::stderr().lock();
        writeln!(err, "refusals (nothing moved):")?;
        for refusal in &refusals {
            writeln!(err, "  - {}: {}", refusal.path.display, refusal.reason)?;
        }
        return Ok(3);
    }
    let count = selections.len();
    let expected = format!("purge {count} artifacts");
    write!(
        io::stderr().lock(),
        "\nType {expected:?} to move exactly these {count} artifact directories to Trash, or press Enter to cancel: "
    )?;
    io::stderr().flush()?;
    let mut answer = String::new();
    io::stdin().lock().take(128).read_line(&mut answer)?;
    if !crate::trash::confirmed(&answer, &expected) || cancellation.is_cancelled() {
        writeln!(io::stderr().lock(), "Cancelled; nothing moved.")?;
        return Ok(130);
    }
    let plan = session.preview().clone();
    let approval = session
        .approve(&plan)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let store = Store::open(&crate::trash::state_directory(args)?, true)?;
    let report = session.execute(&plan, &approval, cancellation, &store)?;
    crate::trash::print_execution_report(&report)?;
    writeln!(
        io::stdout().lock(),
        "Recovery: Finder 'Put Back' per item, plus rebuild from the retained marker (markers untouched)."
    )?;
    writeln!(
        io::stdout().lock(),
        "Displayed bytes were observations, not reclaimed space; a running build tool was not detected."
    )?;
    Ok(report.exit_code())
}

fn write_fatal_json(
    out: &mut impl Write,
    profile: PurgeProfile,
    error: ScanError,
) -> io::Result<()> {
    let unsupported_operations = purge_preview::profile_unsupported_operations(profile);
    let value = serde_json::json!({
        "schema_version": purge_preview::PURGE_SCHEMA_VERSION,
        "kind": purge_preview::PURGE_KIND,
        "platform": if cfg!(target_os = "macos") { "macos" } else { "unsupported" },
        "status": "failed",
        "complete": false,
        "effects_performed": false,
        "profile": profile.as_str(),
        "roots": [],
        "stale_days": serde_json::Value::Null,
        "projects": [],
        "developer_caches": [],
        "unsupported_operations": unsupported_operations.iter().map(|operation| serde_json::json!({
            "tool": operation.tool,
            "operation": operation.operation,
            "reason": operation.reason,
        })).collect::<Vec<_>>(),
        "counts": {
            "projects": 0,
            "artifacts": 0,
            "stale_artifacts": 0,
            "excluded": 0,
            "developer_caches": 0,
            "unsupported_operations": unsupported_operations.len(),
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
        "profile": preview.profile.as_str(),
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
        "developer_caches": preview.developer_caches.iter().map(|cache| serde_json::json!({
            "tool": cache.tool,
            "rule_id": cache.rule_id,
            "rule_version": cache.rule_version,
            "ruleset_revision": cache.ruleset_revision,
            "title": cache.title,
            "path": crate::apps::write_native_path(&cache.path),
            "location": cache.location,
            "location_kind": cache.location_kind,
            "kind": cache.kind,
            "rebuildability_note": cache.rebuildability_note,
            "user_product": cache.user_product,
            "cleanup_supported": cache.cleanup_supported,
            "unsupported_reason": cache.unsupported_reason,
            "sizes": {
                "logical": cache.logical_bytes,
                "allocated": cache.allocated_bytes,
            },
            "complete": cache.complete,
            "modified_unix_ms": cache.modified_unix_ms,
            "activity": cache.activity.as_str(),
            "evidence": cache.evidence.iter().map(|source| serde_json::json!({
                "title": source.title,
                "url": source.url,
                "reviewed_utc": source.reviewed_utc,
                "license_note": source.license_note,
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "unsupported_operations": preview.unsupported_operations.iter().map(|operation| serde_json::json!({
            "tool": operation.tool,
            "operation": operation.operation,
            "reason": operation.reason,
        })).collect::<Vec<_>>(),
        "counts": {
            "projects": preview.counts.projects,
            "artifacts": preview.counts.artifacts,
            "stale_artifacts": preview.counts.stale_artifacts,
            "excluded": preview.counts.excluded,
            "developer_caches": preview.counts.developer_caches,
            "unsupported_operations": preview.counts.unsupported_operations,
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
    writeln!(out, "profile: {}", preview.profile.as_str())?;
    writeln!(out, "stale_days: {}", preview.stale_days)?;
    if preview.profile == PurgeProfile::DeveloperCaches {
        writeln!(out, "developer caches:")?;
        for cache in &preview.developer_caches {
            let size = cache
                .logical_bytes
                .map(crate::human::size)
                .unwrap_or_else(|| "unknown".into());
            writeln!(
                out,
                "  - {} [{}] ({size}, activity: {}, cleanup_supported: {})",
                sayaka_engine::scan::display_path(&cache.path),
                cache.tool,
                cache.activity.as_str(),
                cache.cleanup_supported
            )?;
            writeln!(out, "    rule: {}", cache.rule_id)?;
            writeln!(out, "    note: {}", cache.rebuildability_note)?;
        }
        writeln!(out, "unsupported in-app operations:")?;
        for operation in preview.unsupported_operations {
            writeln!(
                out,
                "  - {} {}: {}",
                operation.tool, operation.operation, operation.reason
            )?;
        }
        return out.flush();
    }
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
        "Preview observations only; effects require --execute with explicit --only selections."
    )?;
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn preview_with_artifacts(root: &std::path::Path) -> PurgePreview {
        let project = root.join("app");
        PurgePreview {
            schema_version: 1,
            kind: purge_preview::PURGE_KIND,
            platform: "macos",
            status: purge_preview::PurgeStatus::Complete,
            complete: true,
            effects_performed: false,
            profile: purge_preview::PurgeProfile::Projects,
            roots: vec![root.to_path_buf()],
            stale_days: 30,
            projects: vec![purge_preview::PurgeProject {
                root: project.clone(),
                markers: vec![purge_preview::ProjectMarker::CargoToml],
                artifacts: vec![
                    purge_preview::PurgeArtifact {
                        path: project.join("target"),
                        name: "target".into(),
                        markers: vec![purge_preview::ProjectMarker::CargoToml],
                        logical_bytes: Some(10),
                        allocated_bytes: Some(10),
                        complete: true,
                        modified_unix_ms: Some(0),
                        stale: Some(false),
                    },
                    purge_preview::PurgeArtifact {
                        path: project.join("dist"),
                        name: "dist".into(),
                        markers: vec![purge_preview::ProjectMarker::CargoToml],
                        logical_bytes: None,
                        allocated_bytes: None,
                        complete: false,
                        modified_unix_ms: None,
                        stale: None,
                    },
                ],
            }],
            developer_caches: vec![],
            unsupported_operations: purge_preview::profile_unsupported_operations(
                purge_preview::PurgeProfile::Projects,
            ),
            counts: purge_preview::PurgeCounts::default(),
            scan_issues: vec![],
            scan_issues_omitted: 0,
        }
    }

    #[test]
    fn only_resolution_matches_artifacts_and_builds_marker_paths() {
        let root = tempfile::tempdir().expect("tempdir");
        let preview = preview_with_artifacts(root.path());
        let selections =
            purge_preview::resolve_selections_by_paths(&preview, &[root.path().join("app/target")])
                .expect("selections");
        assert_eq!(selections.len(), 1);
        assert_eq!(selections[0].artifact, root.path().join("app/target"));
        assert_eq!(selections[0].project_root, root.path().join("app"));
        assert_eq!(
            selections[0].markers,
            vec![root.path().join("app/Cargo.toml")]
        );
    }

    #[test]
    fn only_resolution_rejects_unknown_duplicate_and_traversal() {
        let root = tempfile::tempdir().expect("tempdir");
        let preview = preview_with_artifacts(root.path());
        assert!(
            purge_preview::resolve_selections_by_paths(&preview, &[root.path().join("app/other")])
                .is_err()
        );
        assert!(
            purge_preview::resolve_selections_by_paths(
                &preview,
                &[
                    root.path().join("app/target"),
                    root.path().join("app/target")
                ],
            )
            .is_err()
        );
        assert!(
            purge_preview::resolve_selections_by_paths(
                &preview,
                &[std::path::PathBuf::from("app/../app/target")]
            )
            .is_err()
        );
    }

    #[test]
    fn invalid_execution_arguments_exit_2_before_any_scan() {
        for argv in [
            vec!["sayaka", "purge", ".", "--execute"],
            vec!["sayaka", "purge", ".", "--only", "/tmp/x"],
            vec![
                "sayaka",
                "purge",
                ".",
                "--execute",
                "--json",
                "--only",
                "/tmp/x",
            ],
        ] {
            let matches = command().try_get_matches_from(argv).expect("matches");
            assert_eq!(run(&matches).expect("run"), 2);
        }
    }

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
        assert_eq!(value["profile"], "projects");
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
            PurgeProfile::DeveloperCaches,
            ScanError::new(ScanCode::InvalidRoot, "test refusal"),
        )
        .expect("fatal json");
        let value: serde_json::Value = serde_json::from_slice(&out).expect("parse");
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["kind"], purge_preview::PURGE_KIND);
        assert_eq!(value["status"], "failed");
        assert_eq!(value["effects_performed"], false);
        assert_eq!(value["profile"], "developer_caches");
        assert!(value["projects"].as_array().expect("projects").is_empty());
        assert_eq!(value["issues"][0]["code"], "invalid_root");
        assert_eq!(value["issues"][0]["message"], "test refusal");
    }
}
