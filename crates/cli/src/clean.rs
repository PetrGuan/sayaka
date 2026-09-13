// SPDX-License-Identifier: MPL-2.0

use crate::trash;
use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use sayaka_engine::clean_policy::{self, PolicyFileState};
use sayaka_engine::execute::CleanSession;
use sayaka_engine::model::{Cancellation, Scope};
use sayaka_engine::rules;
use sayaka_engine::scan::{self, ScanCode, ScanError, ScanLimits, ScanStatus, display_path};
use serde_json::json;
use std::collections::BTreeSet;
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

const MAX_SELECTIONS: usize = 32;

pub fn command() -> Command {
    Command::new("clean")
        .about(
            "Discover CPython source-backed .pyc candidates and clean them with explicit approval",
        )
        .arg(
            Arg::new("root")
                .value_name("ROOT")
                .required(false)
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("filter")
                .long("filter")
                .value_name("TEXT")
                .help("Display filter only; does not change exclusion policy"),
        )
        .arg(
            Arg::new("select")
                .long("select")
                .value_name("PATH")
                .action(ArgAction::Append)
                .value_parser(value_parser!(PathBuf))
                .help("Explicit candidate target paths from this preview (repeatable, max 32)"),
        )
        .arg(
            Arg::new("execute")
                .long("execute")
                .action(ArgAction::SetTrue)
                .help("Require interactive TTY selection/confirmation and execute"),
        )
        .arg(
            Arg::new("json")
                .long("json")
                .action(ArgAction::SetTrue)
                .conflicts_with("execute"),
        )
        .arg(
            Arg::new("config-dir")
                .long("config-dir")
                .value_name("DIR")
                .value_parser(value_parser!(PathBuf))
                .help("Clean exclusions policy directory"),
        )
        .arg(
            Arg::new("state-dir")
                .long("state-dir")
                .value_name("DIR")
                .value_parser(value_parser!(PathBuf)),
        )
        .subcommand(exclusions_command())
}

fn exclusions_command() -> Command {
    Command::new("exclusions")
        .about("Manage persistent clean exclusions")
        .subcommand_required(true)
        .subcommand(
            Command::new("list")
                .arg(
                    Arg::new("root")
                        .required(true)
                        .value_parser(value_parser!(PathBuf)),
                )
                .arg(
                    Arg::new("config-dir")
                        .long("config-dir")
                        .value_name("DIR")
                        .value_parser(value_parser!(PathBuf)),
                )
                .arg(Arg::new("json").long("json").action(ArgAction::SetTrue)),
        )
        .subcommand(
            Command::new("add")
                .arg(
                    Arg::new("root")
                        .required(true)
                        .value_parser(value_parser!(PathBuf)),
                )
                .arg(
                    Arg::new("paths")
                        .required(true)
                        .num_args(1..)
                        .value_parser(value_parser!(PathBuf)),
                )
                .arg(
                    Arg::new("config-dir")
                        .long("config-dir")
                        .value_name("DIR")
                        .value_parser(value_parser!(PathBuf)),
                ),
        )
        .subcommand(
            Command::new("remove")
                .arg(
                    Arg::new("root")
                        .required(true)
                        .value_parser(value_parser!(PathBuf)),
                )
                .arg(
                    Arg::new("paths")
                        .required(true)
                        .num_args(1..)
                        .value_parser(value_parser!(PathBuf)),
                )
                .arg(
                    Arg::new("config-dir")
                        .long("config-dir")
                        .value_name("DIR")
                        .value_parser(value_parser!(PathBuf)),
                ),
        )
        .subcommand(
            Command::new("remove-root")
                .arg(
                    Arg::new("root")
                        .required(true)
                        .value_parser(value_parser!(PathBuf)),
                )
                .arg(
                    Arg::new("config-dir")
                        .long("config-dir")
                        .value_name("DIR")
                        .value_parser(value_parser!(PathBuf)),
                ),
        )
}

pub fn run(args: &ArgMatches) -> io::Result<u8> {
    if let Some(("exclusions", nested)) = args.subcommand() {
        return trash::render_error(
            run_exclusions(nested),
            exclusions_json_output(nested),
            "clean exclusions",
        );
    }
    trash::render_error(run_clean(args), args.get_flag("json"), "clean")
}

fn exclusions_json_output(args: &ArgMatches) -> bool {
    matches!(args.subcommand(), Some(("list", sub)) if sub.get_flag("json"))
}

fn run_clean(args: &ArgMatches) -> io::Result<u8> {
    let execute = args.get_flag("execute");
    if execute
        && !(io::stdin().is_terminal() && io::stdout().is_terminal() && io::stderr().is_terminal())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--execute requires an interactive terminal on stdin/stdout/stderr",
        ));
    }
    let config_dir = args.get_one::<PathBuf>("config-dir").map(PathBuf::as_path);
    let config = clean_policy::resolve_config_path(config_dir)?;
    let root = normalize_root(
        args.get_one::<PathBuf>("root")
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "root is required"))?,
    )?;
    let cancellation = Cancellation::default();
    let limits = ScanLimits::default();
    let report = scan::scan(std::slice::from_ref(&root), &limits, &cancellation, |_| {})
        .map_err(|error| io::Error::other(error.to_string()))?;
    let preview = rules::preview(
        report,
        rules::CPYTHON_SOURCE_BACKED_PYC_RULE_ID,
        &cancellation,
    )
    .map_err(map_preview_error)?;
    let policy = clean_policy::snapshot_for_root(&config, &root)?;
    let filter = args
        .get_one::<String>("filter")
        .cloned()
        .unwrap_or_default();
    let mut candidates: Vec<_> = preview
        .candidates
        .iter()
        .filter(|candidate| {
            filter.is_empty() || path_matches_filter(&candidate.target_path, &filter)
        })
        .collect();
    candidates.sort_by(|left, right| left.target_path.cmp(&right.target_path));
    let missing_attention = !policy.missing_attention_entries.is_empty();
    let selected = explicit_or_interactive_selection(args, execute, &candidates)?;
    let selected_set: BTreeSet<_> = selected.iter().map(|path| path.as_path()).collect();
    let persisted_excluded = candidates
        .iter()
        .filter(|candidate| {
            policy
                .effective_exclusions
                .iter()
                .any(|exclude| overlaps(&candidate.target_path, exclude))
        })
        .count();
    let selected_excluded = selected
        .iter()
        .filter(|path| {
            policy
                .effective_exclusions
                .iter()
                .any(|exclude| overlaps(path, exclude))
        })
        .count();
    let eligible_selected: Vec<_> = selected
        .iter()
        .filter(|path| {
            !policy
                .effective_exclusions
                .iter()
                .any(|exclude| overlaps(path, exclude))
        })
        .cloned()
        .collect();
    let refused = selected_excluded + usize::from(missing_attention);
    let matched = candidates
        .iter()
        .filter_map(|candidate| candidate.matched_logical_bytes)
        .sum::<u64>();
    if args.get_flag("json") {
        let value = json!({
            "schema_version": 1,
            "kind": "clean_preview",
            "status": if preview.status == ScanStatus::Cancelled.as_str() { "cancelled" } else { "preview" },
            "root": display_path(&root),
            "policy_file_state": json_policy_state(&policy.file_state),
            "missing_attention_entries": policy
                .missing_attention_entries
                .iter()
                .map(|path| display_path(path))
                .collect::<Vec<_>>(),
            "counts": {
                "discovered": preview.candidates.len(),
                "filtered": candidates.len(),
                "selected": selected.len(),
                "eligible": candidates.len().saturating_sub(persisted_excluded),
                "persisted_excluded": persisted_excluded,
                "refused": refused,
                "succeeded": 0,
                "failed": 0,
                "unknown": 0,
                "skipped": preview.refusals.len(),
            },
            "bytes": {
                "matched_logical_bytes": matched,
                "handled_logical_bytes": 0u64,
            },
            "items": candidates.iter().map(|candidate| {
                json!({
                    "target": display_path(&candidate.target_path),
                    "source": display_path(&candidate.source_path),
                    "selected": selected_set.contains(candidate.target_path.as_path()),
                    "eligible": !policy
                        .effective_exclusions
                        .iter()
                        .any(|exclude| overlaps(&candidate.target_path, exclude)),
                })
            }).collect::<Vec<_>>(),
            "effects_performed": false,
        });
        trash::print_json_value(&value)?;
        return Ok(exit_for_preview(&preview, missing_attention));
    }
    print_preview_human(
        &root,
        &policy,
        &candidates,
        &selected_set,
        &eligible_selected,
    )?;
    if !execute {
        return Ok(exit_for_preview(&preview, missing_attention));
    }
    if missing_attention {
        writeln!(
            io::stderr().lock(),
            "Execution refused: exclusions need attention before native effects."
        )?;
        return Ok(3);
    }
    if selected.is_empty() {
        writeln!(io::stderr().lock(), "Cancelled; no files selected.")?;
        return Ok(130);
    }
    if selected_excluded > 0 {
        writeln!(
            io::stderr().lock(),
            "Execution refused: selected files include persisted exclusions."
        )?;
        return Ok(3);
    }
    if eligible_selected.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no eligible files selected",
        ));
    }
    let scope = Scope::new(root.clone(), vec![])
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let mut session = CleanSession::prepare_rule_selection(
        scope,
        &preview.candidates,
        &eligible_selected,
        config.clone(),
        policy.clone(),
        &cancellation,
    )?;
    writeln!(
        io::stdout().lock(),
        "\nExecution plan (sealed before approval):"
    )?;
    trash::show_plan_preview(session.preview())?;
    let expected = format!("trash {}", eligible_selected.len());
    write!(
        io::stderr().lock(),
        "\nType {expected:?} to move exactly these files, or press Enter to cancel: "
    )?;
    io::stderr().flush()?;
    let mut answer = String::new();
    io::stdin().lock().take(128).read_line(&mut answer)?;
    if !trash::confirmed(&answer, &expected) {
        writeln!(io::stderr().lock(), "Cancelled; no files moved.")?;
        return Ok(130);
    }
    let approval = session.approve()?;
    let state_dir = crate::trash::state_directory(args)?;
    let store = sayaka_engine::journal::Store::open(&state_dir, true)?;
    let report = session.execute(&approval, &cancellation, &store)?;
    trash::print_execution_report(&report)?;
    let base = report.exit_code();
    Ok(if base == 0 && refused > 0 { 3 } else { base })
}

fn explicit_or_interactive_selection(
    args: &ArgMatches,
    execute: bool,
    candidates: &[&sayaka_engine::rules::RuleCandidate],
) -> io::Result<Vec<PathBuf>> {
    if let Some(explicit) = args.get_many::<PathBuf>("select") {
        let selected: Vec<PathBuf> = explicit
            .map(std::path::absolute)
            .collect::<io::Result<Vec<_>>>()?;
        if selected.is_empty() || selected.len() > MAX_SELECTIONS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "select between 1 and 32 explicit targets",
            ));
        }
        let valid: BTreeSet<_> = candidates
            .iter()
            .map(|candidate| candidate.target_path.as_path())
            .collect();
        for path in &selected {
            if !valid.contains(path.as_path()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "selected path is not a current candidate: {}",
                        display_path(path)
                    ),
                ));
            }
        }
        return Ok(selected);
    }
    if !execute {
        return Ok(Vec::new());
    }
    choose_interactively(candidates)
}

fn choose_interactively(
    candidates: &[&sayaka_engine::rules::RuleCandidate],
) -> io::Result<Vec<PathBuf>> {
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = io::stdout().lock();
    writeln!(
        out,
        "Select candidate numbers (comma/range, max 32). Example: 1,3-4"
    )?;
    for (index, candidate) in candidates.iter().enumerate() {
        writeln!(
            out,
            "{:>3}. {} <= {}",
            index + 1,
            display_path(&candidate.target_path),
            display_path(&candidate.source_path),
        )?;
    }
    out.flush()?;
    write!(io::stderr().lock(), "Selection: ")?;
    io::stderr().flush()?;
    let mut answer = String::new();
    io::stdin().lock().take(256).read_line(&mut answer)?;
    let indices = parse_selection_input(answer.trim(), candidates.len())?;
    if indices.is_empty() {
        return Ok(Vec::new());
    }
    Ok(indices
        .into_iter()
        .map(|index| candidates[index - 1].target_path.clone())
        .collect())
}

fn parse_selection_input(answer: &str, candidate_count: usize) -> io::Result<BTreeSet<usize>> {
    if answer.is_empty() {
        return Ok(BTreeSet::new());
    }
    let mut indices = BTreeSet::new();
    for part in answer
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        if let Some((from, to)) = part.split_once('-') {
            let start = from.parse::<usize>().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid numeric range")
            })?;
            let end = to.parse::<usize>().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid numeric range")
            })?;
            if start == 0 || end == 0 || start > end || end > candidate_count {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "selection index out of bounds",
                ));
            }
            for index in start..=end {
                indices.insert(index);
            }
        } else {
            let index = part.parse::<usize>().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid selection number")
            })?;
            if index == 0 || index > candidate_count {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "selection index out of bounds",
                ));
            }
            indices.insert(index);
        }
    }
    if indices.len() > MAX_SELECTIONS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "selection exceeds 32 items",
        ));
    }
    Ok(indices)
}

fn run_exclusions(args: &ArgMatches) -> io::Result<u8> {
    match args.subcommand() {
        Some(("list", sub)) => {
            let config = clean_policy::resolve_config_path(
                sub.get_one::<PathBuf>("config-dir").map(PathBuf::as_path),
            )?;
            let root = sub
                .get_one::<PathBuf>("root")
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "root is required"))?;
            let (snapshot, entries) = clean_policy::list_root_entries(&config, root)?;
            if sub.get_flag("json") {
                let value = json!({
                    "schema_version": 1,
                    "kind": "clean_exclusions",
                    "root": display_path(root),
                    "policy_file_state": json_policy_state(&snapshot.file_state),
                    "entries": entries.iter().map(|entry| json!({
                        "relative_path": display_path(&entry.relative_path),
                        "missing_attention": entry.missing_attention,
                    })).collect::<Vec<_>>(),
                });
                trash::print_json_value(&value)?;
            } else {
                writeln!(io::stdout().lock(), "Root: {}", display_path(root))?;
                writeln!(io::stdout().lock(), "Policy: {:?}", snapshot.file_state)?;
                if entries.is_empty() {
                    writeln!(io::stdout().lock(), "No exclusions.")?;
                } else {
                    for entry in entries {
                        writeln!(
                            io::stdout().lock(),
                            "  {}{}",
                            display_path(&entry.relative_path),
                            if entry.missing_attention {
                                " (needs_attention)"
                            } else {
                                ""
                            }
                        )?;
                    }
                }
            }
            Ok(0)
        }
        Some(("add", sub)) => {
            let config = clean_policy::resolve_config_path(
                sub.get_one::<PathBuf>("config-dir").map(PathBuf::as_path),
            )?;
            let root = sub
                .get_one::<PathBuf>("root")
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "root is required"))?;
            let paths = sub
                .get_many::<PathBuf>("paths")
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "paths are required"))?
                .cloned()
                .collect::<Vec<_>>();
            clean_policy::add_entries(&config, root, &paths)?;
            writeln!(io::stdout().lock(), "Added {} exclusion(s).", paths.len())?;
            Ok(0)
        }
        Some(("remove", sub)) => {
            let config = clean_policy::resolve_config_path(
                sub.get_one::<PathBuf>("config-dir").map(PathBuf::as_path),
            )?;
            let root = sub
                .get_one::<PathBuf>("root")
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "root is required"))?;
            let paths = sub
                .get_many::<PathBuf>("paths")
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "paths are required"))?
                .cloned()
                .collect::<Vec<_>>();
            let removed = clean_policy::remove_entries(&config, root, &paths)?;
            writeln!(io::stdout().lock(), "Removed {removed} exclusion(s).")?;
            Ok(0)
        }
        Some(("remove-root", sub)) => {
            let config = clean_policy::resolve_config_path(
                sub.get_one::<PathBuf>("config-dir").map(PathBuf::as_path),
            )?;
            let root = sub
                .get_one::<PathBuf>("root")
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "root is required"))?;
            let removed = clean_policy::remove_root(&config, root)?;
            writeln!(
                io::stdout().lock(),
                "{}",
                if removed {
                    "Root record removed."
                } else {
                    "No matching root record."
                }
            )?;
            Ok(0)
        }
        _ => Ok(2),
    }
}

fn print_preview_human(
    root: &Path,
    policy: &clean_policy::PolicySnapshot,
    candidates: &[&sayaka_engine::rules::RuleCandidate],
    selected_set: &BTreeSet<&Path>,
    eligible: &[PathBuf],
) -> io::Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out, "Clean preview root: {}", display_path(root))?;
    writeln!(out, "Candidates: {}", candidates.len())?;
    for candidate in candidates {
        writeln!(
            out,
            "  {}{} <= {}",
            if selected_set.contains(candidate.target_path.as_path()) {
                if eligible.iter().any(|item| item == &candidate.target_path) {
                    "[selected] "
                } else {
                    "[excluded] "
                }
            } else {
                ""
            },
            display_path(&candidate.target_path),
            display_path(&candidate.source_path)
        )?;
    }
    writeln!(out, "Policy: {:?}", policy.file_state)?;
    if !policy.effective_exclusions.is_empty() {
        writeln!(out, "Persistent exclusions:")?;
        for entry in &policy.effective_exclusions {
            writeln!(out, "  {}", display_path(entry))?;
        }
    }
    if !policy.missing_attention_entries.is_empty() {
        writeln!(out, "Missing exclusions (needs attention, blocks execute):")?;
        for entry in &policy.missing_attention_entries {
            writeln!(out, "  {}", display_path(entry))?;
        }
    }
    out.flush()
}

fn json_policy_state(state: &PolicyFileState) -> serde_json::Value {
    match state {
        PolicyFileState::Absent {
            expected_path,
            nearest_existing_parent,
            nearest_existing_parent_identity,
        } => json!({
            "state": "absent",
            "expected_path": display_path(expected_path),
            "nearest_existing_parent": nearest_existing_parent
                .as_ref()
                .map(|path| display_path(path)),
            "nearest_existing_parent_identity": nearest_existing_parent_identity.as_ref().map(|id| json!({"device": id.device, "inode": id.inode})),
        }),
        PolicyFileState::Present {
            path,
            identity,
            length,
            modified_unix_ms,
            sha256,
        } => json!({
            "state": "present",
            "path": display_path(path),
            "identity": {"device": identity.device, "inode": identity.inode},
            "length": length,
            "modified_unix_ms": modified_unix_ms,
            "sha256": sha256,
        }),
    }
}

fn path_matches_filter(path: &Path, filter: &str) -> bool {
    let text = display_path(path).to_lowercase();
    text.contains(&filter.to_lowercase())
}

fn overlaps(path: &Path, exclusion: &Path) -> bool {
    path.starts_with(exclusion) || exclusion.starts_with(path)
}

fn normalize_root(path: &Path) -> io::Result<PathBuf> {
    if path
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "parent traversal is not accepted",
        ));
    }
    let absolute = std::path::absolute(path)?;
    if !absolute.is_absolute()
        || absolute.parent().is_none()
        || absolute.as_os_str().as_encoded_bytes().contains(&0)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "roots must be non-root absolute paths without parent traversal or NUL",
        ));
    }
    if !absolute.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "root must be an existing directory",
        ));
    }
    Ok(absolute)
}

fn map_preview_error(error: sayaka_engine::rules::PreviewError) -> io::Error {
    match error {
        sayaka_engine::rules::PreviewError::InvalidRuleId => {
            io::Error::new(io::ErrorKind::InvalidInput, "unknown clean rule ID")
        }
        sayaka_engine::rules::PreviewError::Scan(ScanError { code, message, .. }) => {
            let kind = if matches!(code, ScanCode::InvalidRoot | ScanCode::InvalidLimits) {
                io::ErrorKind::InvalidInput
            } else {
                io::ErrorKind::Other
            };
            io::Error::new(kind, message)
        }
    }
}

fn exit_for_preview(preview: &sayaka_engine::rules::RulePreview, missing_attention: bool) -> u8 {
    if preview.status == ScanStatus::Cancelled.as_str() {
        130
    } else if !preview.complete || missing_attention {
        3
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::parse_selection_input;

    #[test]
    fn chooser_empty_input_is_cancel_and_bounded() {
        assert!(parse_selection_input("", 4).unwrap().is_empty());
        assert!(parse_selection_input("1-33", 40).is_err());
        assert!(parse_selection_input("0", 4).is_err());
    }
}
