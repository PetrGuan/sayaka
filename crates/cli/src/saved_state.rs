// SPDX-License-Identifier: MPL-2.0

use crate::{human, output};
use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use sayaka_engine::model::Cancellation;
use sayaka_engine::saved_state::{
    self, DEFAULT_OLDER_THAN_DAYS, MAX_OLDER_THAN_DAYS, SavedStateCandidate, SavedStateEligibility,
    SavedStateOptions, SavedStatePreview, SavedStateStatus,
};
use sayaka_engine::scan;
use sayaka_engine::scan::index::ScanTree;
use std::io::{self, IsTerminal, Write};
use std::time::SystemTime;

pub fn command() -> Command {
    Command::new("saved-states")
        .about("Read-only preview of application saved states by cleanup eligibility (T10)")
        .arg(
            Arg::new("older-than-days")
                .long("older-than-days")
                .value_name("DAYS")
                .help(format!(
                    "Age cutoff in days [default: {DEFAULT_OLDER_THAN_DAYS}, max: {MAX_OLDER_THAN_DAYS}]"
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
            "Preview only in this slice: no selection and no effects. Saved states are window/resume\nstate, not documents; age is an observation, not proof of disuse; a running owner is never\ntouched. The location is the fixed per-user Saved Application State directory, resolved\nfrom the native account record. Bundle identifiers come from the directory naming\nconvention, not from installed-app identity.",
        )
}

pub fn run(args: &ArgMatches) -> io::Result<u8> {
    match run_inner(args) {
        Ok(code) => Ok(code),
        Err(error) => {
            writeln!(
                io::stderr().lock(),
                "saved-states failed: {:?}",
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
    let json = args.get_flag("json");
    let options = SavedStateOptions {
        older_than_days: args
            .get_one::<u32>("older-than-days")
            .copied()
            .unwrap_or(DEFAULT_OLDER_THAN_DAYS),
    };
    options
        .validate()
        .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message))?;
    let now = SystemTime::now();
    if cfg!(not(target_os = "macos")) {
        // The operation is unavailable off macOS, never a silent skip.
        let preview = unsupported_platform_preview(
            std::path::PathBuf::new(),
            args.get_one::<u32>("older-than-days")
                .copied()
                .unwrap_or(DEFAULT_OLDER_THAN_DAYS),
            now,
        );
        return print_preview(&preview, json);
    }
    let location = saved_state::default_location()?;
    let cutoff_unix_ms = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|duration| {
            i64::try_from(
                duration
                    .as_millis()
                    .saturating_sub(u128::from(options.older_than_days) * 86_400_000),
            )
            .ok()
        });
    if !location.is_dir() {
        // The absent location is an explicit unnecessary state, never an
        // error disguised as success.
        let preview = SavedStatePreview {
            schema_version: saved_state::SAVED_STATE_SCHEMA_VERSION,
            kind: saved_state::SAVED_STATE_KIND,
            platform: if cfg!(target_os = "macos") {
                "macos"
            } else {
                "unsupported"
            },
            status: SavedStateStatus::Unnecessary,
            complete: true,
            effects_performed: false,
            location,
            effective_cutoff_days: options.older_than_days,
            cutoff_unix_ms,
            candidates: Vec::new(),
            counts: Default::default(),
            scan_issues: Vec::new(),
            scan_issues_omitted: 0,
        };
        return print_preview(&preview, json);
    }
    // Applicability per contract: the location must be a real directory
    // owned by the current user; anything else fails closed.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::symlink_metadata(&location)?;
        let owned = metadata.uid() == rustix::process::getuid().as_raw();
        if !metadata.is_dir() || !owned {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the saved-state location must be a directory owned by the current user",
            ));
        }
    }
    let json_mode = json;
    let stderr_terminal = io::stderr().is_terminal();
    let dumb = std::env::var_os("TERM").is_some_and(|term| term == "dumb");
    let show_progress = args.get_flag("progress")
        || (!json_mode && io::stdout().is_terminal() && stderr_terminal && !dumb);
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
    let limits = sayaka_engine::scan::ScanLimits::default();
    limits
        .validate()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.message))?;
    let cancellation = Cancellation::default();
    let signal = cancellation.clone();
    ctrlc::set_handler(move || signal.cancel()).map_err(io::Error::other)?;
    let report = scan::scan(
        std::slice::from_ref(&location),
        &limits,
        &cancellation,
        |event| {
            if show_progress && progress_error.is_none() {
                let written = if json_mode {
                    output::progress(&mut io::stderr().lock(), event)
                } else {
                    progress.update(&mut io::stderr().lock(), event, style)
                };
                if let Err(error) = written {
                    cancellation.cancel();
                    progress_error = Some(error);
                }
            }
        },
    )
    .map_err(|error| io::Error::other(error.to_string()))?;
    let index = ScanTree::build(report, &cancellation)
        .map_err(|error| io::Error::other(format!("cannot index the saved-state scan: {error}")))?;
    let preview = saved_state::saved_state_preview(
        &index,
        &location,
        &options,
        now,
        &mut saved_state::running_owner_pids,
    )
    .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message))?;
    if let Some(error) = progress_error {
        return Err(error);
    }
    print_preview(&preview, json_mode)
}

fn unsupported_platform_preview(
    location: std::path::PathBuf,
    days: u32,
    now: SystemTime,
) -> SavedStatePreview {
    SavedStatePreview {
        schema_version: saved_state::SAVED_STATE_SCHEMA_VERSION,
        kind: saved_state::SAVED_STATE_KIND,
        platform: "unsupported",
        status: SavedStateStatus::UnsupportedPlatform,
        complete: false,
        effects_performed: false,
        location,
        effective_cutoff_days: days,
        cutoff_unix_ms: now
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()
            .and_then(|duration| {
                i64::try_from(
                    duration
                        .as_millis()
                        .saturating_sub(u128::from(days) * 86_400_000),
                )
                .ok()
            }),
        candidates: Vec::new(),
        counts: Default::default(),
        scan_issues: Vec::new(),
        scan_issues_omitted: 0,
    }
}

fn print_preview(preview: &SavedStatePreview, json: bool) -> io::Result<u8> {
    if json {
        write_json(&mut io::stdout().lock(), preview)?;
    } else {
        write_human(&mut io::stdout().lock(), preview)?;
    }
    Ok(match preview.status {
        SavedStateStatus::Complete | SavedStateStatus::Unnecessary => 0,
        SavedStateStatus::Partial => 3,
        SavedStateStatus::Cancelled => 130,
        SavedStateStatus::Failed | SavedStateStatus::UnsupportedPlatform => 1,
    })
}

fn candidate_json(candidate: &SavedStateCandidate) -> serde_json::Value {
    serde_json::json!({
        "name": candidate.name,
        "bundle_id": candidate.bundle_id,
        "eligibility": candidate.eligibility.as_str(),
        "reason": candidate.reason,
        "running_pids": candidate.running_pids,
        "logical_bytes": candidate.logical_bytes,
        "allocated_bytes": candidate.allocated_bytes,
        "complete": candidate.complete,
        "modified_unix_ms": candidate.modified_unix_ms,
        "age_days": candidate.age_days,
    })
}

fn write_json(out: &mut impl Write, preview: &SavedStatePreview) -> io::Result<()> {
    let value = serde_json::json!({
        "schema_version": preview.schema_version,
        "kind": preview.kind,
        "platform": preview.platform,
        "status": preview.status.as_str(),
        "complete": preview.complete,
        "effects_performed": false,
        "location": crate::apps::write_native_path(&preview.location),
        "effective_cutoff_days": preview.effective_cutoff_days,
        "cutoff_unix_ms": preview.cutoff_unix_ms,
        "candidates": preview.candidates.iter().map(candidate_json).collect::<Vec<_>>(),
        "counts": {
            "eligible": preview.counts.eligible,
            "too_recent": preview.counts.too_recent,
            "running": preview.counts.running,
            "not_attributable": preview.counts.not_attributable,
            "unknown": preview.counts.unknown,
            "ignored": preview.counts.ignored,
            "listed_omitted": preview.counts.listed_omitted,
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

fn write_human(out: &mut impl Write, preview: &SavedStatePreview) -> io::Result<()> {
    writeln!(out, "kind: {}", preview.kind)?;
    writeln!(
        out,
        "location: {}",
        sayaka_engine::scan::display_path(&preview.location)
    )?;
    writeln!(out, "status: {}", preview.status.as_str())?;
    writeln!(out, "effects_performed: false")?;
    let cutoff = preview
        .cutoff_unix_ms
        .map(|ms| format!("before unix_ms {ms}"))
        .unwrap_or_else(|| "uncomputed".into());
    writeln!(
        out,
        "cutoff: {} days ({cutoff})",
        preview.effective_cutoff_days
    )?;
    if preview.status == SavedStateStatus::Unnecessary && preview.candidates.is_empty() {
        writeln!(
            out,
            "unnecessary: the fixed location does not exist or holds no candidates"
        )?;
    }
    for (state, label) in [
        (SavedStateEligibility::Eligible, "eligible"),
        (SavedStateEligibility::TooRecent, "too_recent"),
        (SavedStateEligibility::Running, "running"),
        (SavedStateEligibility::NotAttributable, "not_attributable"),
        (SavedStateEligibility::Unknown, "unknown"),
    ] {
        let group: Vec<&SavedStateCandidate> = preview
            .candidates
            .iter()
            .filter(|candidate| candidate.eligibility == state)
            .collect();
        if group.is_empty() {
            continue;
        }
        writeln!(out, "{label}:")?;
        for candidate in group {
            let size = candidate
                .logical_bytes
                .map(crate::human::size)
                .unwrap_or_else(|| "unknown".into());
            let age = candidate
                .age_days
                .map(|days| format!("{days} days"))
                .unwrap_or_else(|| "unknown age".into());
            let detail = match candidate.eligibility {
                SavedStateEligibility::Running => format!(
                    "owner running (pids: {:?})",
                    candidate.running_pids.as_deref().unwrap_or(&[])
                ),
                SavedStateEligibility::NotAttributable | SavedStateEligibility::Unknown => {
                    candidate.reason.unwrap_or("no reason recorded").to_string()
                }
                _ => String::new(),
            };
            let coverage = if candidate.complete {
                ""
            } else {
                ", partial coverage"
            };
            let detail = if detail.is_empty() {
                detail
            } else {
                format!(", {detail}")
            };
            writeln!(
                out,
                "  - {} ({size}, {age}{coverage}{detail})",
                candidate.name
            )?;
        }
    }
    if preview.counts.ignored > 0 {
        writeln!(
            out,
            "ignored (not .savedState children): {}",
            preview.counts.ignored
        )?;
    }
    if preview.counts.listed_omitted > 0 {
        writeln!(
            out,
            "listed_omitted (beyond {}): {}",
            saved_state::MAX_LISTED,
            preview.counts.listed_omitted
        )?;
    }
    writeln!(
        out,
        "Preview only; saved states are window/resume state, and no selection exists in this slice."
    )?;
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_preview_envelope_carries_explicit_states() {
        let preview = SavedStatePreview {
            schema_version: 1,
            kind: saved_state::SAVED_STATE_KIND,
            platform: "macos",
            status: SavedStateStatus::Unnecessary,
            complete: true,
            effects_performed: false,
            location: std::path::PathBuf::from("/fixture/Library/Saved Application State"),
            effective_cutoff_days: 30,
            cutoff_unix_ms: Some(1_000_000),
            candidates: vec![SavedStateCandidate {
                name: "dev.example.app.savedState".into(),
                bundle_id: Some("dev.example.app".into()),
                eligibility: SavedStateEligibility::Running,
                reason: None,
                running_pids: Some(vec![42]),
                logical_bytes: Some(10),
                allocated_bytes: Some(10),
                complete: true,
                modified_unix_ms: Some(999_000),
                age_days: Some(0),
            }],
            counts: Default::default(),
            scan_issues: vec![],
            scan_issues_omitted: 0,
        };
        let mut out = Vec::new();
        write_json(&mut out, &preview).expect("json");
        let value: serde_json::Value = serde_json::from_slice(&out).expect("parse");
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["kind"], saved_state::SAVED_STATE_KIND);
        assert_eq!(value["status"], "unnecessary");
        assert_eq!(value["effects_performed"], false);
        assert_eq!(value["effective_cutoff_days"], 30);
        assert_eq!(
            value["candidates"][0]["eligibility"], "running",
            "per-item states must stay explicit"
        );
        assert_eq!(value["candidates"][0]["running_pids"][0], 42);
    }
}
