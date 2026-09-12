// SPDX-License-Identifier: MPL-2.0

use super::model::{App, Metric, Screen, kind};
use sayaka_engine::scan;
use std::io;
use unicode_width::UnicodeWidthChar;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Style {
    Normal,
    Header,
    Muted,
    Selected,
    Warning,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    pub text: String,
    pub style: Style,
}

const HELP: &[&str] = &[
    "BROWSE / SELECT",
    "Up/Down or j/k: move. Enter/Right: enter directory. Left/Backspace: parent.",
    "Space: select an ordinary file (maximum 32). Directories cannot be trashed.",
    "x: toggle file/directory exclusion. v: selected-file view. /: edit name filter.",
    "s: size/name ordering. a: logical/allocated measurements. r: explicit refresh.",
    "i: scan issues. m: menu. ?: help. q: quit. Ctrl-C: cancel and quit.",
    "",
    "EXPLICIT ACTIONS",
    "t: prepare an exact native Trash plan from the frozen selected observations.",
    "Review all preview lines, then type trash N and Enter. Esc cancels the plan.",
    "No automatic retry, directory removal, permanent-delete fallback or elevation.",
    "A final pathname replacement race remains; Trash is not guaranteed restoration.",
    "o: reveal observed entry in Finder. p: acknowledge and request Quick Look.",
    "External viewers read contents; installed providers are outside scanner policy.",
    "Esc cancels owned work. In-flight native I/O may need time to return.",
    "",
    "MEASUREMENTS",
    "Directory sizes count each file identity once within that directory subtree.",
    "A hardlink in two siblings counts in both; sibling totals are not additive.",
    "* means incomplete coverage. +? means some file measurements are unknown.",
    "Unknown is not zero. Sizes are observations, never guaranteed reclaimed bytes.",
    "Scanning is a bounded snapshot, not live monitoring. Refresh clears selection.",
    "After any execution, the old snapshot is stale and cannot authorize more actions.",
];

pub fn frame(app: &mut App, width: u16, height: u16) -> io::Result<Vec<Line>> {
    let mut lines = vec![
        Line {
            text: String::new(),
            style: Style::Normal
        };
        usize::from(height)
    ];
    let mut put = |row: usize, text: String, style| {
        if let Some(line) = lines.get_mut(row) {
            *line = Line {
                text: clip(&text, usize::from(width)),
                style,
            };
        }
    };
    if width < 20 || height < 8 {
        put(0, "Sayaka: resize terminal".into(), Style::Warning);
        put(1, "q quits; no action here".into(), Style::Muted);
        app.review_allowed = false;
        app.external_allowed = false;
        return Ok(lines);
    }
    app.viewport = usize::from(height).saturating_sub(8).max(1);
    app.review_allowed = width >= 60 && height >= 14;
    put(
        0,
        format!(
            "Sayaka  /  {:?}{}",
            app.screen,
            if app.stale { "  [STALE]" } else { "" }
        ),
        Style::Header,
    );
    put(
        1,
        "m Menu   / Filter   Space Select   x Exclude   t Plan   ? Help   q Quit".into(),
        Style::Muted,
    );
    put(2, app.status.clone(), Style::Warning);
    let footer = usize::from(height) - 2;
    put(
        footer,
        "* incomplete; +? unknown; subtree hardlinks overlap. No reclaimed-size promise.".into(),
        Style::Muted,
    );
    put(
        footer + 1,
        if app.filtering {
            format!("Filter> {}  [Enter accepts, Esc clears]", app.filter)
        } else {
            format!(
                "Selected {} / 32 | Exclusions {} / 32 | {:?} / {:?}",
                app.selected.len(),
                app.excluded.len(),
                app.sort,
                app.metric
            )
        },
        Style::Header,
    );
    match app.screen {
        Screen::Browse | Screen::Selected => {
            let path = app
                .directory
                .and_then(|id| app.data.as_ref()?.tree.entry(id))
                .map(|entry| &entry.path)
                .unwrap_or(&app.root);
            let location = path
                .strip_prefix(&app.root)
                .ok()
                .map(|relative| {
                    if relative.as_os_str().is_empty() {
                        "ROOT".into()
                    } else {
                        format!("ROOT / {}", scan::display_path(relative))
                    }
                })
                .unwrap_or_else(|| scan::display_path(path));
            put(
                3,
                format!(
                    "{}{}",
                    location,
                    if app.filter.is_empty() {
                        String::new()
                    } else {
                        format!("  filter={:?}", app.filter)
                    }
                ),
                Style::Normal,
            );
            put(
                4,
                format!(
                    "      {:>14}  TYPE  NAME  ({} observed)",
                    "SIZE",
                    match app.metric {
                        Metric::Logical => "logical",
                        Metric::Allocated => "allocated",
                    }
                ),
                Style::Muted,
            );
            if app.rows.is_empty() {
                let text = if app.data.is_none() {
                    "Scanning / indexing; results are not ready. Esc cancels."
                } else if !app.filter.is_empty() {
                    "No observed entries match this filter."
                } else if app.screen == Screen::Selected {
                    "No files selected. Space selects a file in Browse."
                } else if app
                    .data
                    .as_ref()
                    .is_some_and(|data| data.tree.report().complete)
                {
                    "No observed entries in this directory."
                } else {
                    "No observed entries; coverage is incomplete or the scope is unavailable."
                };
                put(6, text.into(), Style::Muted);
            }
            if app.cursor < app.offset {
                app.offset = app.cursor;
            }
            if app.cursor >= app.offset + app.viewport {
                app.offset = app.cursor + 1 - app.viewport;
            }
            for (row, id) in app
                .rows
                .iter()
                .skip(app.offset)
                .take(app.viewport)
                .enumerate()
            {
                let data = app
                    .data
                    .as_ref()
                    .ok_or_else(|| io::Error::other("rows without scan data"))?;
                let entry = data.entry(*id)?;
                let selected = if app.selected.contains(id) { '+' } else { ' ' };
                let excluded = if app.is_excluded(*id) { 'x' } else { ' ' };
                let cursor = if app.offset + row == app.cursor {
                    '>'
                } else {
                    ' '
                };
                let name = format!(
                    "{:?}",
                    entry.path.file_name().unwrap_or(entry.path.as_os_str())
                );
                put(
                    5 + row,
                    format!(
                        "{cursor}{selected}{excluded} {:>14}  {:>4}  {name}",
                        data.measure(*id, app.metric),
                        kind(entry.kind)
                    ),
                    if cursor == '>' {
                        Style::Selected
                    } else {
                        Style::Normal
                    },
                );
            }
            if let Some(id) = app.rows.get(app.cursor)
                && let Some(entry) = app.data.as_ref().and_then(|data| data.tree.entry(*id))
            {
                put(
                    usize::from(height) - 3,
                    format!(
                        "Focus: {}  [o reveal / p preview]",
                        scan::display_path(&entry.path)
                    ),
                    Style::Muted,
                );
            }
        }
        Screen::Menu => {
            for (index, label) in [
                "Browse disk",
                "Selected files",
                "Refresh snapshot (clears selections)",
                "Help and safety",
                "Quit",
            ]
            .into_iter()
            .enumerate()
            {
                put(
                    4 + index,
                    format!(
                        "{} {label}",
                        if app.menu_cursor == index { ">" } else { " " }
                    ),
                    if app.menu_cursor == index {
                        Style::Selected
                    } else {
                        Style::Normal
                    },
                );
            }
        }
        Screen::Help | Screen::Notice => {
            let source: Vec<String> = if app.screen == Screen::Help {
                HELP.iter().map(|line| (*line).into()).collect()
            } else {
                app.notice.clone()
            };
            let wrapped: Vec<_> = source
                .iter()
                .flat_map(|line| wrap(line, usize::from(width)))
                .collect();
            app.notice_scroll = app
                .notice_scroll
                .min(wrapped.len().saturating_sub(app.viewport));
            for (row, line) in wrapped
                .into_iter()
                .skip(app.notice_scroll)
                .take(app.viewport)
                .enumerate()
            {
                put(4 + row, line, Style::Normal);
            }
            put(
                usize::from(height) - 3,
                "Up/Down or PgUp/PgDn scroll; Esc returns; q quits.".into(),
                Style::Muted,
            );
        }
        Screen::Preview => {
            let preview = app
                .preview
                .as_mut()
                .ok_or_else(|| io::Error::other("preview screen has no plan"))?;
            if !app.review_allowed {
                put(
                    5,
                    "Resize to at least 60 columns x 14 rows to review and confirm.".into(),
                    Style::Warning,
                );
            } else {
                if preview.width != width {
                    preview.wrapped = preview
                        .lines
                        .iter()
                        .flat_map(|line| wrap(line, usize::from(width)))
                        .collect();
                    preview.width = width;
                    preview.scroll = 0;
                    preview.seen_through = 0;
                    preview.input.clear();
                }
                let end = (preview.scroll + app.viewport).min(preview.wrapped.len());
                if preview.scroll <= preview.seen_through {
                    preview.seen_through = preview.seen_through.max(end);
                }
                for (row, line) in preview
                    .wrapped
                    .iter()
                    .skip(preview.scroll)
                    .take(app.viewport)
                    .enumerate()
                {
                    put(4 + row, line.clone(), Style::Normal);
                }
                put(
                    usize::from(height) - 3,
                    format!(
                        "Reviewed {}/{} lines; PgDn continues; Esc cancels.",
                        preview.seen_through,
                        preview.wrapped.len()
                    ),
                    Style::Muted,
                );
                put(
                    footer + 1,
                    if preview.plan.items().is_empty() {
                        "No eligible files. Esc cancels; execution is unavailable.".into()
                    } else {
                        format!(
                            "Type trash {} then Enter > {}",
                            preview.plan.items().len(),
                            preview.input
                        )
                    },
                    Style::Warning,
                );
            }
        }
        Screen::ExternalPrompt => {
            let (_, entry) = app.viewer_entries()?;
            let text = [
                format!("Quick Look: {}", scan::display_path(&entry.path)),
                "Quick Look opens contents using system preview providers.".into(),
                "No engine-enforced no-hydration or provider-isolation guarantee.".into(),
                "Known placeholders and changed observations are refused.".into(),
                "Enter explicitly requests preview; Esc returns without opening.".into(),
            ];
            let wrapped: Vec<_> = text
                .iter()
                .flat_map(|line| wrap(line, usize::from(width)))
                .collect();
            app.external_allowed = wrapped.len() <= app.viewport && width >= 60;
            for (row, line) in wrapped.into_iter().take(app.viewport).enumerate() {
                put(4 + row, line, Style::Warning);
            }
            if !app.external_allowed {
                put(
                    footer + 1,
                    "Resize to read all acknowledgement lines before Enter.".into(),
                    Style::Warning,
                );
            }
        }
        Screen::Executing => {
            put(
                5,
                "Owned operation in progress. Esc cancels subsequent work; q exits safely.".into(),
                Style::Normal,
            );
            put(
                6,
                "An in-flight native call may finish. Results are not discarded or replayed."
                    .into(),
                Style::Muted,
            );
        }
    }
    Ok(lines)
}

fn safe(text: &str) -> String {
    let mut result = String::new();
    for ch in text.chars() {
        if ch.is_control()
            || matches!(ch, '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{206f}')
        {
            result.extend(ch.escape_debug());
        } else {
            result.push(ch);
        }
    }
    result
}

pub fn clip(text: &str, width: usize) -> String {
    let text = safe(text);
    let mut output = String::new();
    let mut columns = 0;
    for ch in text.chars() {
        let size = ch.width().unwrap_or(0);
        if columns + size > width {
            let reserved = width.min(3);
            while columns > width.saturating_sub(reserved) {
                let Some(previous) = output.pop() else {
                    break;
                };
                columns = columns.saturating_sub(previous.width().unwrap_or(0));
            }
            output.push_str(&".".repeat(reserved));
            return output;
        }
        output.push(ch);
        columns += size;
    }
    output
}

fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(2);
    let mut result = Vec::new();
    let mut line = String::new();
    let mut columns = 0;
    for ch in safe(text).chars() {
        let size = ch.width().unwrap_or(0);
        if columns + size > width {
            result.push(std::mem::take(&mut line));
            columns = 0;
        }
        line.push(ch);
        columns += size;
    }
    result.push(line);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use unicode_width::UnicodeWidthStr;
    #[test]
    fn terminal_text_never_contains_injected_controls_or_exceeds_width() {
        let text = "abc\x1b[2J\t\r\n\u{202e}\u{4e2d}\u{6587}";
        for width in 1..40 {
            let clipped = clip(text, width);
            assert!(!clipped.chars().any(char::is_control));
            assert!(!clipped.contains('\u{202e}'));
            assert!(clipped.width() <= width);
            for line in wrap(text, width.max(2)) {
                assert!(line.width() <= width.max(2));
            }
        }
    }
    #[test]
    fn a_tiny_terminal_cannot_confirm_a_plan() {
        let mut app = App::new("/fixture".into());
        let rows = frame(&mut app, 12, 3).unwrap();
        assert_eq!(rows.len(), 3);
        assert!(!app.review_allowed);
    }
}
