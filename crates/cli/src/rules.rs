// SPDX-License-Identifier: MPL-2.0

use crate::human;
use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use sayaka_engine::model::Cancellation;
use sayaka_engine::rules::{self, PreviewError, RuleAction, RulePreview};
use sayaka_engine::scan::{self, ScanCode, ScanError, ScanLimits, display_path};
use serde::Serialize;
use serde::ser::SerializeStruct;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

pub fn command() -> Command {
    let defaults = ScanLimits::default();
    let mut preview = Command::new("preview")
        .about("Read-only rule discovery preview for one explicit root")
        .arg(
            Arg::new("root")
                .value_name("ROOT")
                .required(true)
                .help("Existing directory to scan; use . for the current directory")
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("rule")
                .long("rule")
                .value_name("RULE_ID")
                .required(true)
                .help("Rule ID from `sayaka rules list`"),
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
        );
    for (name, description, default) in [
        ("workers", "Directory workers, 1-32", defaults.workers),
        (
            "queue-capacity",
            "Maximum queued directories",
            defaults.queue_capacity,
        ),
        (
            "max-open-dirs",
            "Directory handle slots; at least workers + 2",
            defaults.max_open_dirs,
        ),
        (
            "max-depth",
            "Directory descent depth below each root",
            defaults.max_depth,
        ),
        (
            "max-entries",
            "Maximum retained entries; reaching it returns partial results",
            defaults.max_entries,
        ),
        (
            "max-path-bytes",
            "Memory budget for retained native paths, in bytes",
            defaults.max_path_bytes,
        ),
    ] {
        preview = preview.arg(
            Arg::new(name)
                .long(name)
                .value_name("N")
                .help(format!("{description} [default: {default}]"))
                .value_parser(value_parser!(usize)),
        );
    }
    preview = preview.arg(
        Arg::new("timeout-ms")
            .long("timeout-ms")
            .value_name("MS")
            .help(format!(
                "Cooperative scan time budget in milliseconds [default: {}]",
                defaults.time_budget.as_millis()
            ))
            .value_parser(value_parser!(u64)),
    );
    Command::new("rules")
        .about("Built-in evidence-backed rules")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("list")
                .about("List built-in rules and evidence metadata")
                .arg(
                    Arg::new("json")
                        .long("json")
                        .action(ArgAction::SetTrue)
                        .help("Write one versioned JSON catalog to stdout"),
                ),
        )
        .subcommand(preview)
}

pub fn run(args: &ArgMatches) -> io::Result<u8> {
    match args.subcommand() {
        Some(("list", args)) => run_list(args),
        Some(("preview", args)) => run_preview(args),
        _ => Ok(2),
    }
}

fn run_list(args: &ArgMatches) -> io::Result<u8> {
    if args.get_flag("json") {
        #[derive(Serialize)]
        struct Catalog<'a> {
            schema_version: u32,
            kind: &'static str,
            ruleset_schema_version: u32,
            ruleset_revision: u32,
            rules: &'a [sayaka_engine::rules::RuleDefinition],
        }
        write_json(&Catalog {
            schema_version: 1,
            kind: "rule_catalog",
            ruleset_schema_version: rules::RULESET_SCHEMA_VERSION,
            ruleset_revision: rules::BUILTIN_RULESET_REVISION,
            rules: rules::builtin_rules(),
        })?;
        return Ok(0);
    }
    let mut out = io::stdout().lock();
    writeln!(out, "Built-in rules:")?;
    for rule in rules::builtin_rules() {
        writeln!(out, "  {} v{}", rule.id, rule.version)?;
        writeln!(out, "    {}", rule.title)?;
        writeln!(
            out,
            "    Actions: {}",
            rule.actions
                .iter()
                .map(action_label)
                .collect::<Vec<_>>()
                .join(", ")
        )?;
    }
    out.flush()?;
    Ok(0)
}

fn run_preview(args: &ArgMatches) -> io::Result<u8> {
    let json = args.get_flag("json");
    let stdout_terminal = io::stdout().is_terminal();
    let stderr_terminal = io::stderr().is_terminal();
    let dumb = std::env::var_os("TERM").is_some_and(|term| term == "dumb");
    let no_color = std::env::var_os("NO_COLOR").is_some();
    let disabled = std::env::var_os("CLICOLOR").is_some_and(|value| value == "0");
    let style = |terminal| human::Style {
        color: human::colors_allowed(terminal && cfg!(unix), no_color, dumb, disabled),
    };
    let stderr_style = style(stderr_terminal);
    let show_progress =
        args.get_flag("progress") || (!json && stdout_terminal && stderr_terminal && !dumb);
    let mut readable_progress = human::Progress::default();
    let limits = crate::limits(args);
    let cancellation = Cancellation::default();
    let mut stderr = io::stderr().lock();
    let mut stdout = io::stdout().lock();
    let mut progress_error = None;
    let result = (|| {
        let rule_id = args
            .get_one::<String>("rule")
            .ok_or_else(|| ScanError::new(ScanCode::InvalidRoot, "rule is required"))?;
        if !rules::is_builtin_rule(rule_id) {
            return Err(ScanError::new(
                ScanCode::InvalidRoot,
                "unknown rule ID; use `sayaka rules list`",
            ));
        }
        let root = normalize_root(
            args.get_one::<PathBuf>("root")
                .ok_or_else(|| ScanError::new(ScanCode::InvalidRoot, "root is required"))?,
        )?;
        limits.validate()?;
        let signal_cancellation = cancellation.clone();
        ctrlc::set_handler(move || signal_cancellation.cancel()).map_err(|error| {
            ScanError::new(
                ScanCode::Internal,
                format!("cannot install interrupt handler: {error}"),
            )
        })?;
        let report = scan::scan(&[root], &limits, &cancellation, |progress| {
            if show_progress && progress_error.is_none() {
                let written = if json {
                    crate::output::progress(&mut stderr, progress)
                } else {
                    readable_progress.update(&mut stderr, progress, stderr_style)
                };
                if let Err(error) = written {
                    cancellation.cancel();
                    progress_error = Some(error);
                }
            }
        })?;
        rules::preview(report, rule_id, &cancellation).map_err(|error| match error {
            PreviewError::InvalidRuleId => ScanError::new(
                ScanCode::InvalidRoot,
                "unknown rule ID; use `sayaka rules list`",
            ),
            PreviewError::Scan(error) => error,
        })
    })();
    if let Some(error) = progress_error {
        let fatal = ScanError::new(ScanCode::Io, format!("progress output failed: {error}"));
        if json {
            write_preview_fatal(&fatal)?;
        }
        return Err(error);
    }
    match result {
        Ok(preview) => {
            if json {
                write_preview_json(&preview)?;
            } else {
                write_preview_human(&preview)?;
            }
            stdout.flush()?;
            stderr.flush()?;
            Ok(match preview.status {
                "cancelled" => 130,
                _ if !preview.complete
                    || !preview.refusals.is_empty()
                    || preview.candidates.is_empty() =>
                {
                    3
                }
                _ => 0,
            })
        }
        Err(error) => {
            let invalid = matches!(error.code, ScanCode::InvalidRoot | ScanCode::InvalidLimits);
            if json {
                write_preview_fatal(&error)?;
            } else {
                human::fatal(&mut stderr, &error, stderr_style)?;
            }
            Ok(if invalid { 2 } else { 1 })
        }
    }
}

fn action_label(action: &RuleAction) -> &'static str {
    match action {
        RuleAction::PreviewOnly => "preview_only",
        RuleAction::ManualReview => "manual_review",
    }
}

fn write_preview_human(preview: &RulePreview) -> io::Result<()> {
    let mut out = io::stdout().lock();
    writeln!(
        out,
        "Rule preview {} v{} (ruleset r{}):",
        preview.rule_id, preview.rule_version, preview.ruleset_revision
    )?;
    writeln!(
        out,
        "  {} candidate(s), {} refusal(s), matched bytes {} known + {} unknown files",
        preview.candidates.len(),
        preview.refusals.len(),
        preview.matched_bytes_known,
        preview.matched_bytes_unknown_files
    )?;
    for candidate in &preview.candidates {
        writeln!(
            out,
            "  candidate: {} <= {} ({})",
            display_path(&candidate.target_path),
            display_path(&candidate.source_path),
            action_label(&candidate.action)
        )?;
    }
    if !preview.issues.is_empty() {
        writeln!(out, "  scan issues:")?;
        for issue in &preview.issues {
            if let Some(path) = issue.path.as_deref() {
                writeln!(
                    out,
                    "    {} [{}] {}{}",
                    display_path(path),
                    issue.code.as_str(),
                    issue.message,
                    issue
                        .os_code
                        .map(|code| format!(" (os_code={code})"))
                        .unwrap_or_default()
                )?;
            } else {
                writeln!(
                    out,
                    "    [{}] {}{}",
                    issue.code.as_str(),
                    issue.message,
                    issue
                        .os_code
                        .map(|code| format!(" (os_code={code})"))
                        .unwrap_or_default()
                )?;
            }
        }
    }
    if preview.issues_omitted > 0 {
        writeln!(out, "  scan issues omitted: {}", preview.issues_omitted)?;
    }
    for refusal in &preview.refusals {
        if let Some(path) = &refusal.path {
            writeln!(
                out,
                "  refusal: {} [{}] {}",
                display_path(path),
                serde_json::to_string(&refusal.code).unwrap_or_else(|_| "\"unknown\"".into()),
                refusal.message
            )?;
        } else {
            writeln!(
                out,
                "  refusal: [{}] {}",
                serde_json::to_string(&refusal.code).unwrap_or_else(|_| "\"unknown\"".into()),
                refusal.message
            )?;
        }
    }
    out.flush()
}

struct NativePath<'a>(&'a Path);

impl Serialize for NativePath<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use std::fmt::Write;
        let mut raw = String::new();
        #[cfg(unix)]
        let encoding = {
            use std::os::unix::ffi::OsStrExt;
            for byte in self.0.as_os_str().as_bytes() {
                write!(raw, "{byte:02x}").map_err(serde::ser::Error::custom)?;
            }
            "unix_bytes_hex"
        };
        #[cfg(windows)]
        let encoding = {
            use std::os::windows::ffi::OsStrExt;
            for unit in self.0.as_os_str().encode_wide() {
                write!(raw, "{unit:04x}").map_err(serde::ser::Error::custom)?;
            }
            "windows_utf16_hex"
        };
        let mut value = serializer.serialize_struct("Path", 3)?;
        value.serialize_field("display", &display_path(self.0))?;
        value.serialize_field("encoding", encoding)?;
        value.serialize_field("raw", &raw)?;
        value.end()
    }
}

#[derive(Serialize)]
struct JsonCandidate<'a> {
    rule_id: &'static str,
    rule_version: u32,
    ruleset_revision: u32,
    action: &'static str,
    target_entry_id: u64,
    source_entry_id: u64,
    target_path: NativePath<'a>,
    source_path: NativePath<'a>,
    target_identity: sayaka_engine::model::FileIdentity,
    source_identity: sayaka_engine::model::FileIdentity,
    matched_logical_bytes: Option<u64>,
    observed_cache_tag: &'a str,
    observed_optimization_tag: Option<&'a str>,
}

#[derive(Serialize)]
struct JsonRefusal<'a> {
    rule_id: &'static str,
    rule_version: u32,
    ruleset_revision: u32,
    code: rules::RefusalCode,
    path: Option<NativePath<'a>>,
    message: &'a str,
}

#[derive(Serialize)]
struct JsonIssue<'a> {
    path: Option<NativePath<'a>>,
    code: &'a str,
    message: &'a str,
    os_code: Option<i32>,
}

fn write_preview_json(preview: &RulePreview) -> io::Result<()> {
    #[derive(Serialize)]
    struct JsonPreview<'a> {
        schema_version: u32,
        kind: &'static str,
        ruleset_schema_version: u32,
        ruleset_revision: u32,
        rule_id: &'static str,
        rule_version: u32,
        scan_task_id: &'a str,
        status: &'a str,
        complete: bool,
        roots: Vec<NativePath<'a>>,
        issues: Vec<JsonIssue<'a>>,
        issues_omitted: usize,
        candidates: Vec<JsonCandidate<'a>>,
        refusals: Vec<JsonRefusal<'a>>,
        matched_bytes_known: u64,
        matched_bytes_unknown_files: u64,
        effects_performed: bool,
    }
    let roots = preview.roots.iter().map(|path| NativePath(path)).collect();
    let candidates = preview
        .candidates
        .iter()
        .map(|candidate| JsonCandidate {
            rule_id: candidate.rule_id,
            rule_version: candidate.rule_version,
            ruleset_revision: candidate.ruleset_revision,
            action: action_label(&candidate.action),
            target_entry_id: candidate.target_entry_id,
            source_entry_id: candidate.source_entry_id,
            target_path: NativePath(&candidate.target_path),
            source_path: NativePath(&candidate.source_path),
            target_identity: candidate.target_identity,
            source_identity: candidate.source_identity,
            matched_logical_bytes: candidate.matched_logical_bytes,
            observed_cache_tag: &candidate.observed_cache_tag,
            observed_optimization_tag: candidate.observed_optimization_tag.as_deref(),
        })
        .collect();
    let issues = preview
        .issues
        .iter()
        .map(|issue| JsonIssue {
            path: issue.path.as_deref().map(NativePath),
            code: issue.code.as_str(),
            message: &issue.message,
            os_code: issue.os_code,
        })
        .collect();
    let refusals = preview
        .refusals
        .iter()
        .map(|refusal| JsonRefusal {
            rule_id: refusal.rule_id,
            rule_version: refusal.rule_version,
            ruleset_revision: refusal.ruleset_revision,
            code: refusal.code,
            path: refusal.path.as_deref().map(NativePath),
            message: &refusal.message,
        })
        .collect();
    write_json(&JsonPreview {
        schema_version: preview.schema_version,
        kind: preview.kind,
        ruleset_schema_version: preview.ruleset_schema_version,
        ruleset_revision: preview.ruleset_revision,
        rule_id: preview.rule_id,
        rule_version: preview.rule_version,
        scan_task_id: &preview.scan_task_id,
        status: preview.status,
        complete: preview.complete,
        roots,
        issues,
        issues_omitted: preview.issues_omitted,
        candidates,
        refusals,
        matched_bytes_known: preview.matched_bytes_known,
        matched_bytes_unknown_files: preview.matched_bytes_unknown_files,
        effects_performed: preview.effects_performed,
    })
}

fn write_preview_fatal(error: &ScanError) -> io::Result<()> {
    #[derive(Serialize)]
    struct Fatal<'a> {
        schema_version: u32,
        kind: &'static str,
        status: &'static str,
        complete: bool,
        issues: [Issue<'a>; 1],
    }
    #[derive(Serialize)]
    struct Issue<'a> {
        code: &'a str,
        message: &'a str,
        os_code: Option<i32>,
    }
    write_json(&Fatal {
        schema_version: 1,
        kind: "rule_preview",
        status: "failed",
        complete: false,
        issues: [Issue {
            code: error.code.as_str(),
            message: &error.message,
            os_code: error.os_code,
        }],
    })
}

fn write_json(value: &impl Serialize) -> io::Result<()> {
    let mut out = io::stdout().lock();
    serde_json::to_writer(&mut out, value)?;
    writeln!(out)?;
    out.flush()
}

fn absolute(path: &Path) -> io::Result<PathBuf> {
    std::path::absolute(path)
}

fn normalize_root(path: &Path) -> Result<PathBuf, ScanError> {
    if path
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(ScanError::new(
            ScanCode::InvalidRoot,
            "parent traversal is not accepted",
        ));
    }
    let absolute =
        absolute(path).map_err(|error| ScanError::new(ScanCode::InvalidRoot, error.to_string()))?;
    if !absolute.is_absolute()
        || absolute.parent().is_none()
        || absolute.as_os_str().as_encoded_bytes().contains(&0)
    {
        return Err(ScanError::new(
            ScanCode::InvalidRoot,
            "roots must be non-root absolute paths without parent traversal or NUL",
        ));
    }
    Ok(absolute)
}
