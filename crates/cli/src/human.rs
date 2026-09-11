// SPDX-License-Identifier: MPL-2.0

use sayaka_engine::model::ResourceKind;
use sayaka_engine::scan::{
    ScanCode, ScanEntry, ScanError, ScanIssue, ScanProgress, ScanReport, ScanStatus, ScanTotals,
};
use std::fmt;
use std::io::{self, Write};
use std::path::Path;

/// Escape argument values, not clap's generated line breaks and usage layout.
pub fn parser_error(mut error: clap::Error) -> String {
    use clap::error::{ContextKind, ContextValue, ErrorKind};
    let missing_root = error.kind() == ErrorKind::MissingRequiredArgument;
    let escaped: Vec<_> = error
        .context()
        .filter_map(|(kind, value)| {
            if kind == ContextKind::Usage {
                return None;
            }
            let value = match value {
                ContextValue::String(value) => ContextValue::String(escape_argument(value)),
                ContextValue::Strings(values) => ContextValue::Strings(
                    values.iter().map(|value| escape_argument(value)).collect(),
                ),
                ContextValue::StyledStr(value) => {
                    ContextValue::StyledStr(escape_argument(&value.to_string()).into())
                }
                ContextValue::StyledStrs(values) => ContextValue::StyledStrs(
                    values
                        .iter()
                        .map(|value| escape_argument(&value.to_string()).into())
                        .collect(),
                ),
                _ => return None,
            };
            Some((kind, value))
        })
        .collect();
    for (kind, value) in escaped {
        error.insert(kind, value);
    }
    let mut message = error.to_string();
    if missing_root {
        message.push_str(
            "\nChoose a directory to scan. The final '.' means the current directory.\n\
             \n  cargo run --quiet -p sayaka-cli -- scan .\n\
             \nWith the installed CLI: sayaka scan .\n",
        );
    }
    message
}

fn escape_argument(value: &str) -> String {
    let mut escaped = String::new();
    for ch in value.chars() {
        match ch {
            '\'' | '"' | '\\' => escaped.push(ch),
            _ => escaped.extend(ch.escape_debug()),
        }
    }
    escaped
}

const TOP_FILES: usize = 8;
const MAX_NOTES: usize = 6;

#[derive(Clone, Copy, Default)]
pub struct Style {
    pub color: bool,
}

impl Style {
    fn paint(self, text: &str, code: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_owned()
        }
    }
}

pub fn colors_allowed(terminal: bool, no_color: bool, dumb: bool, disabled: bool) -> bool {
    terminal && !no_color && !dumb && !disabled
}

fn count(value: impl fmt::Display) -> String {
    let digits = value.to_string();
    let mut result = String::new();
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            result.push(',');
        }
        result.push(ch);
    }
    result
}

pub(crate) fn size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut unit = 0;
    let mut divisor = 1u128;
    while unit + 1 < UNITS.len() && u128::from(bytes) >= divisor * 1024 {
        divisor *= 1024;
        unit += 1;
    }
    let mut tenths = (u128::from(bytes) * 10 + divisor / 2) / divisor;
    if tenths >= 10240 && unit + 1 < UNITS.len() {
        divisor *= 1024;
        unit += 1;
        tenths = (u128::from(bytes) * 10 + divisor / 2) / divisor;
    }
    format!("{}.{:01} {}", tenths / 10, tenths % 10, UNITS[unit])
}

fn duration(ms: u64) -> String {
    if ms < 1000 {
        format!("{ms} ms")
    } else if ms < 60_000 {
        format!("{}.{:02} s", ms / 1000, (ms % 1000) / 10)
    } else {
        format!("{} min {} s", ms / 60_000, (ms % 60_000) / 1000)
    }
}

fn path_label(path: &Path) -> String {
    let escaped = sayaka_engine::scan::display_path(path);
    let text = escaped
        .strip_prefix('"')
        .and_then(|text| text.strip_suffix('"'))
        .unwrap_or(&escaped);
    let length = text.chars().count();
    if length > 96 {
        format!("...{}", text.chars().skip(length - 93).collect::<String>())
    } else {
        text.to_owned()
    }
}

fn heading(writer: &mut impl Write, status: &str, color: &str, style: Style) -> io::Result<()> {
    writeln!(writer, "\n{}", style.paint("Sayaka / Storage scan", "1;36"))?;
    writeln!(writer, "------------------------------------------------")?;
    writeln!(writer, "  {}\n", style.paint(status, color))
}

pub fn report(writer: &mut impl Write, report: &ScanReport, style: Style) -> io::Result<()> {
    let (status, color) = match report.status {
        ScanStatus::Complete => ("Scan complete", "1;32"),
        ScanStatus::Partial => ("Partial scan - some items were not read", "1;33"),
        ScanStatus::Cancelled => ("Scan cancelled - showing results so far", "1;33"),
        ScanStatus::Failed => ("Could not scan", "1;31"),
    };
    heading(writer, status, color, style)?;
    if report.status == ScanStatus::Failed {
        return Ok(());
    }
    for root in report.roots.iter().take(MAX_NOTES) {
        writeln!(writer, "  Folder  {}", path_label(root))?;
    }
    if report.roots.len() > MAX_NOTES {
        writeln!(
            writer,
            "          + {} more roots (see --json)",
            report.roots.len() - MAX_NOTES
        )?;
    }
    writeln!(writer)?;
    measurements(writer, &report.totals, !report.complete, style)?;
    writeln!(
        writer,
        "  Time        {}\n",
        duration(report.metrics.elapsed_ms)
    )?;

    let largest = largest_files(&report.entries);
    if largest.is_empty() {
        let message = if report.complete && report.totals.unique_files == 0 {
            "No regular files found within the scan policy."
        } else {
            "No files with a known size are available to rank."
        };
        writeln!(writer, "  {message}")?;
    } else {
        writeln!(writer, "  {}", style.paint("Largest files", "1"))?;
        writeln!(writer, "  Logical size; bars compare the listed files.\n")?;
        let maximum = largest[0].0;
        for (index, (bytes, entry)) in largest.iter().enumerate() {
            let bytes = *bytes;
            let filled = if maximum == 0 {
                0
            } else {
                (u128::from(bytes) * 12 / u128::from(maximum)) as usize
            };
            let bar = format!("{}{}", "#".repeat(filled), ".".repeat(12 - filled));
            let path = if report.roots.len() == 1 {
                entry
                    .path
                    .strip_prefix(&report.roots[0])
                    .unwrap_or(&entry.path)
            } else {
                &entry.path
            };
            writeln!(
                writer,
                "  {}. {:>10}  [{}]",
                index + 1,
                size(bytes),
                style.paint(&bar, "36")
            )?;
            writeln!(writer, "     {}", path_label(path))?;
        }
    }
    writeln!(writer)
}

fn measurements(
    writer: &mut impl Write,
    totals: &ScanTotals,
    partial: bool,
    style: Style,
) -> io::Result<()> {
    if partial {
        writeln!(
            writer,
            "  {} (not the complete folder total)",
            style.paint("Observed so far", "1;33")
        )?;
    }
    measurement(
        writer,
        "File data",
        totals.logical_bytes_known,
        totals.logical_bytes_unknown_files,
        style,
    )?;
    measurement(
        writer,
        "Allocated",
        totals.allocated_bytes_known,
        totals.allocated_bytes_unknown_files,
        style,
    )?;
    writeln!(
        writer,
        "  Files       {} unique",
        count(totals.unique_files)
    )?;
    writeln!(writer, "  Folders     {}", count(totals.directories))?;
    if totals.duplicate_files > 0 {
        writeln!(
            writer,
            "  Hard links  {} additional names; bytes counted once",
            count(totals.duplicate_files)
        )?;
    }
    Ok(())
}

fn measurement(
    writer: &mut impl Write,
    label: &str,
    known: u64,
    unknown: u64,
    style: Style,
) -> io::Result<()> {
    let value = if unknown > 0 && known == 0 {
        "Unknown".to_owned()
    } else {
        size(known)
    };
    write!(writer, "  {label:<12}{}", style.paint(&value, "1"))?;
    if unknown > 0 {
        write!(
            writer,
            "  (known subtotal; {} unmeasured files)",
            count(unknown)
        )?;
    }
    writeln!(writer)
}

fn largest_files(entries: &[ScanEntry]) -> Vec<(u64, &ScanEntry)> {
    let mut top = Vec::with_capacity(TOP_FILES + 1);
    for entry in entries
        .iter()
        .filter(|entry| entry.kind == ResourceKind::File && entry.counted)
    {
        let Some(bytes) = entry.logical_bytes else {
            continue;
        };
        let position = top.partition_point(|current: &(u64, &ScanEntry)| {
            current.0 > bytes || (current.0 == bytes && current.1.path <= entry.path)
        });
        if position < TOP_FILES {
            top.insert(position, (bytes, entry));
            top.truncate(TOP_FILES);
        }
    }
    top
}

fn explanation(code: ScanCode) -> (&'static str, &'static str) {
    match code {
        ScanCode::NotFound => (
            "Path not found",
            "Choose an existing directory. Try: sayaka scan .",
        ),
        ScanCode::InvalidRoot => (
            "Invalid directory",
            "Choose an existing directory, without '..' or a filesystem root.",
        ),
        ScanCode::PermissionDenied => (
            "Access denied",
            "Check the folder's permissions and macOS privacy access.",
        ),
        ScanCode::LinkSkipped => (
            "Symbolic link skipped",
            "Links are not followed. For a scan root, use its physical directory path.",
        ),
        ScanCode::UnsupportedPlatform => (
            "Scanning is unavailable on this platform",
            "Native scanning currently requires macOS.",
        ),
        ScanCode::UnsupportedVolume => (
            "Volume not supported",
            "This version scans local internal volumes only.",
        ),
        ScanCode::VolumeUnknown => (
            "Could not identify the volume safely",
            "The volume was left unscanned rather than guessed to be safe.",
        ),
        ScanCode::CloudDirectorySkipped => (
            "Cloud folder left unscanned",
            "The scan will not download cloud-only contents.",
        ),
        ScanCode::MountBoundary => (
            "Another volume was skipped",
            "The scan does not cross volume boundaries.",
        ),
        ScanCode::InvalidLimits => (
            "Invalid scan limits",
            "Remove custom limits and try again, or run: sayaka scan --help",
        ),
        ScanCode::DepthLimit => (
            "Folder depth limit reached",
            "Use --max-depth with a larger value to include deeper folders.",
        ),
        ScanCode::OpenHandleLimit => (
            "Open-folder limit reached",
            "Scan a smaller folder or adjust --max-open-dirs.",
        ),
        ScanCode::EntryLimit => (
            "Result limit reached",
            "Scan a smaller folder or increase --max-entries.",
        ),
        ScanCode::PathBytesLimit => (
            "Path memory limit reached",
            "Scan a smaller folder or adjust --max-path-bytes.",
        ),
        ScanCode::DurationLimit => (
            "Time limit reached",
            "Use a larger --timeout-ms value or choose a smaller folder.",
        ),
        ScanCode::Cancelled => (
            "Stopped at your request",
            "The results shown are incomplete. Nothing was deleted.",
        ),
        ScanCode::ChangedEntry => (
            "An item changed during the scan",
            "Run the scan again when the folder is less active.",
        ),
        ScanCode::DuplicateRoot | ScanCode::DuplicateDirectory => (
            "Already covered by this scan",
            "The same directory is not scanned twice.",
        ),
        ScanCode::PolicyFailure => (
            "macOS scan protection unavailable",
            "Safety checks were not weakened; review the diagnostic below.",
        ),
        ScanCode::WorkerStartFailed => (
            "Could not start a scan worker",
            "Try again with fewer workers: --workers 1",
        ),
        ScanCode::WorkerPanic | ScanCode::Internal => (
            "An internal scan error occurred",
            "The scan could not finish reliably. Keep the diagnostic when reporting the problem.",
        ),
        ScanCode::Overflow => (
            "Measurement is too large to represent",
            "This result is incomplete; no wrapped or guessed total is shown.",
        ),
        ScanCode::Io => (
            "Could not read an item",
            "Check the diagnostic below and try an accessible folder.",
        ),
    }
}

fn issue(writer: &mut impl Write, issue: &ScanIssue, style: Style) -> io::Result<()> {
    let (title, hint) = explanation(issue.code);
    writeln!(writer, "  {}", style.paint(title, "1;33"))?;
    if let Some(path) = &issue.path {
        writeln!(writer, "    {}", path_label(path))?;
    }
    writeln!(writer, "    {hint}")?;
    if matches!(
        issue.code,
        ScanCode::Io
            | ScanCode::PolicyFailure
            | ScanCode::Internal
            | ScanCode::WorkerStartFailed
            | ScanCode::WorkerPanic
    ) {
        writeln!(writer, "    Details: {}", issue.message.escape_debug())?;
    }
    writeln!(writer)
}

pub fn notes(writer: &mut impl Write, report: &ScanReport, style: Style) -> io::Result<()> {
    if report.issues.is_empty() && report.issues_omitted == 0 {
        return Ok(());
    }
    if report.status != ScanStatus::Failed {
        writeln!(writer, "  {}\n", style.paint("Scan notes", "1;33"))?;
    }
    for note in report.issues.iter().take(MAX_NOTES) {
        issue(writer, note, style)?;
    }
    let remaining = report.issues.len().saturating_sub(MAX_NOTES) + report.issues_omitted;
    if remaining > 0 {
        writeln!(
            writer,
            "  {} more notes. Use --json for the full available report.\n",
            count(remaining)
        )?;
    }
    Ok(())
}

pub fn fatal(writer: &mut impl Write, error: &ScanError, style: Style) -> io::Result<()> {
    heading(writer, "Could not scan", "1;31", style)?;
    issue(
        writer,
        &ScanIssue {
            path: None,
            code: error.code,
            message: error.message.clone(),
            os_code: error.os_code,
        },
        style,
    )?;
    footer(writer)
}

pub fn footer(writer: &mut impl Write) -> io::Result<()> {
    writeln!(writer, "  Read-only scan. Nothing was deleted.")?;
    writeln!(writer, "  File sizes are not space you can safely free.\n")
}

#[derive(Default)]
pub struct Progress {
    last_ms: Option<u64>,
}

impl Progress {
    pub fn update(
        &mut self,
        writer: &mut impl Write,
        event: &ScanProgress,
        style: Style,
    ) -> io::Result<()> {
        if self
            .last_ms
            .is_some_and(|last| event.elapsed_ms.saturating_sub(last) < 500)
        {
            return Ok(());
        }
        self.last_ms = Some(event.elapsed_ms);
        if event.unique_files == 0 {
            writeln!(
                writer,
                "  {}  Press Ctrl+C to cancel.",
                style.paint("Scanning...", "36")
            )?;
        } else {
            writeln!(
                writer,
                "  {}  {} files  |  {} known  |  {}",
                style.paint("Scanning", "36"),
                count(event.unique_files),
                size(event.logical_bytes_known),
                duration(event.elapsed_ms)
            )?;
        }
        writer.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_layout_stays_multiline_but_untrusted_values_are_escaped() {
        for argument in ["--bad\nFAKE\x1b[2J", "--bad\tvalue"] {
            let error = clap::Command::new("sayaka")
                .try_get_matches_from(["sayaka", argument])
                .unwrap_err();
            let text = parser_error(error);
            assert!(text.contains("\n\nUsage:"));
            assert!(!text.contains('\x1b'));
            assert!(!text.contains('\t'));
            assert!(!text.lines().any(|line| line.starts_with("FAKE")));
        }
        let error = clap::Command::new("sayaka")
            .arg(
                clap::Arg::new("workers")
                    .long("workers")
                    .value_parser(clap::value_parser!(usize)),
            )
            .try_get_matches_from(["sayaka", "--workers", "bad\nFAKE\x1b[2J"])
            .unwrap_err();
        let text = parser_error(error);
        assert!(text.contains("\\nFAKE"));
        assert!(!text.contains('\x1b'));
        assert!(text.contains("\n\nFor more information"));
    }

    #[test]
    fn byte_units_are_readable_and_do_not_overflow() {
        for (bytes, expected) in [
            (0, "0 B"),
            (1023, "1023 B"),
            (1024, "1.0 KiB"),
            (1536, "1.5 KiB"),
            (1_048_575, "1.0 MiB"),
            (1_073_741_824, "1.0 GiB"),
            (u64::MAX, "16.0 EiB"),
        ] {
            assert_eq!(size(bytes), expected);
        }
        assert_eq!(count(1234567), "1,234,567");
    }

    #[test]
    fn color_is_only_used_when_terminal_and_preferences_allow_it() {
        assert!(colors_allowed(true, false, false, false));
        for arguments in [
            (false, false, false, false),
            (true, true, false, false),
            (true, false, true, false),
            (true, false, false, true),
        ] {
            assert!(!colors_allowed(
                arguments.0,
                arguments.1,
                arguments.2,
                arguments.3
            ));
        }
    }

    #[test]
    fn unknown_and_partial_measurements_are_not_presented_as_complete_zero() {
        let totals = ScanTotals {
            unique_files: 2,
            logical_bytes_known: 1024,
            logical_bytes_unknown_files: 1,
            allocated_bytes_unknown_files: 2,
            ..ScanTotals::default()
        };
        let mut bytes = Vec::new();
        measurements(&mut bytes, &totals, true, Style::default()).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("Observed so far"));
        assert!(text.contains("1.0 KiB"));
        assert!(text.contains("Unknown"));
        assert!(text.contains("2 unmeasured files"));
        assert!(!text.contains("Allocated   0 B"));
    }

    #[test]
    fn missing_paths_explain_the_problem_instead_of_showing_zero_results() {
        let mut bytes = Vec::new();
        fatal(
            &mut bytes,
            &ScanError::new(ScanCode::NotFound, "No such file"),
            Style::default(),
        )
        .unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("Path not found"));
        assert!(text.contains("sayaka scan ."));
        assert!(!text.contains("0 B"));
        assert!(!text.contains('\x1b'));
    }

    #[test]
    fn displayed_paths_escape_controls_and_preserve_plain_readability() {
        assert_eq!(path_label(Path::new("/folder/file")), "/folder/file");
        let escaped = path_label(Path::new("/folder/line\n\x1b[2J"));
        assert!(!escaped.chars().any(char::is_control));
        assert!(escaped.contains("\\n"));
        assert!(path_label(Path::new(&"x".repeat(200))).starts_with("..."));
    }

    #[test]
    fn rankings_are_bounded_and_do_not_count_aliases_or_unknown_sizes() {
        use sayaka_engine::model::FileIdentity;
        let mut entries: Vec<_> = (0..20)
            .map(|id| ScanEntry {
                id,
                path: format!("file-{id:02}").into(),
                kind: ResourceKind::File,
                identity: FileIdentity::Unix {
                    device: 1,
                    inode: id,
                },
                logical_bytes: Some(id),
                allocated_bytes: Some(id),
                dataless: false,
                counted: true,
                depth: 1,
            })
            .collect();
        entries[19].counted = false;
        entries[18].logical_bytes = None;
        let ranked = largest_files(&entries);
        assert_eq!(ranked.len(), TOP_FILES);
        assert_eq!(ranked[0].0, 17);
        assert_eq!(ranked.last().unwrap().0, 10);
    }
}
