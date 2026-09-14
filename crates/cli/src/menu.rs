// SPDX-License-Identifier: MPL-2.0

use crate::terminal::{Line, Signals, Style, Terminal};
use clap::{Arg, ArgMatches, Command, value_parser};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal;
#[cfg(unix)]
use rustix::process::{Pid, Signal, kill_process};
use sayaka_engine::rules::{
    CPYTHON_SOURCE_BACKED_PYC_RULE_ID, JAVAC_SOURCE_BACKED_CLASS_RULE_ID, RuleDefinition,
    builtin_rules,
};
use std::ffi::OsString;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command as ProcessCommand, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use unicode_width::UnicodeWidthChar;

const MIN_WIDTH: u16 = 60;
const MIN_HEIGHT: u16 = 14;
const MAX_PATH_INPUT_BYTES: usize = 65_536;
const CHILD_POLL: Duration = Duration::from_millis(25);
const CHILD_TERM_GRACE: Duration = Duration::from_secs(2);
const POST_CHILD_POLL: Duration = Duration::from_millis(25);

pub fn command() -> Command {
    Command::new("menu")
        .about("Compact terminal menu for explicit browse and rule-driven clean flows")
        .arg(
            Arg::new("state-dir")
                .long("state-dir")
                .value_name("DIR")
                .value_parser(value_parser!(PathBuf))
                .help("Private M3 state directory forwarded only to browse/clean approval flows"),
        )
        .after_help(
            "Requires interactive stdin/stdout/stderr and TERM!=dumb. The menu never scans\n\
             implicitly: choose an action, review limitations, then type an explicit root path.",
        )
}

pub fn run(args: &ArgMatches) -> io::Result<u8> {
    if !interactive_terminal_ready() {
        writeln!(
            io::stderr().lock(),
            "menu requires interactive stdin/stdout/stderr with TERM != dumb; use direct commands instead."
        )?;
        return Ok(2);
    }
    let state_dir = args.get_one::<PathBuf>("state-dir").cloned();
    let mut app = App::new(action_catalog()?, state_dir);
    let signals = Signals::new()?;
    let mut terminal = Terminal::enter()?;
    let mut result = run_loop(&mut app, &signals, &mut terminal);
    if let Some(code) = signals.exit_code() {
        result = Ok(code);
    }
    let restored = terminal.restore();
    restored?;
    result
}

fn interactive_terminal_ready() -> bool {
    io::stdin().is_terminal()
        && io::stdout().is_terminal()
        && io::stderr().is_terminal()
        && std::env::var_os("TERM").is_none_or(|term| term != "dumb")
}

fn run_loop(app: &mut App, signals: &Signals, terminal: &mut Terminal) -> io::Result<u8> {
    let mut last_draw = Instant::now() - Duration::from_secs(1);
    loop {
        if let Some(code) = signals.exit_code() {
            return Ok(code);
        }
        if last_draw.elapsed() >= Duration::from_millis(60) || app.dirty {
            let (width, height) = crossterm::terminal::size()?;
            app.last_size = (width.min(240), height.min(80));
            let frame = app.frame();
            terminal.draw(&frame, app.last_size.0, app.last_size.1)?;
            app.dirty = false;
            last_draw = Instant::now();
        }
        if !event::poll(Duration::from_millis(20))? {
            continue;
        }
        let event = event::read()?;
        match event {
            Event::Resize(_, _) => {
                terminal.invalidate();
                app.dirty = true;
            }
            Event::Key(key) if matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) => {
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                    return Ok(130);
                }
                match app.on_key(key.code, key.modifiers)? {
                    Outcome::None => {}
                    Outcome::Quit => return Ok(0),
                    Outcome::Run(plan) => {
                        let mut repeat = true;
                        while repeat {
                            repeat = false;
                            let restored = terminal.restore();
                            if let Err(error) = restored {
                                return Err(io::Error::other(format!(
                                    "terminal restore before child dispatch failed: {error}"
                                )));
                            }
                            let child_outcome = dispatch(&plan, signals)?;
                            if let Some(code) = signals.exit_code() {
                                return Ok(code);
                            }
                            match post_child_prompt(&plan.label, &child_outcome, signals)? {
                                AfterChild::Back => {
                                    app.screen = Screen::Root;
                                }
                                AfterChild::Repeat => repeat = true,
                                AfterChild::Quit => return Ok(0),
                                AfterChild::Exit(code) => return Ok(code),
                            }
                            *terminal = Terminal::enter()?;
                            terminal.invalidate();
                            app.status = child_outcome.summary();
                            app.dirty = true;
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuleMode {
    Preview,
    Approval,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ActionKind {
    Browse,
    PythonRule,
    JavaRule,
    InstallerPreview,
    AppsInventory,
}

#[derive(Clone, Debug)]
struct Action {
    kind: ActionKind,
    label: &'static str,
    summary: &'static str,
    enabled: bool,
    disabled_reason: Option<&'static str>,
    approval_enabled: bool,
    approval_disabled_reason: Option<&'static str>,
    details: Vec<String>,
}

#[derive(Clone, Debug)]
struct DispatchPlan {
    label: String,
    program: PathBuf,
    args: Vec<OsString>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Screen {
    Root,
    ActionInfo {
        index: usize,
        scroll: usize,
    },
    PathPrompt {
        index: usize,
        input: String,
    },
    RuleMode {
        index: usize,
        root: PathBuf,
        choice: usize,
    },
    Help {
        scroll: usize,
    },
}

#[derive(Clone, Debug)]
enum Outcome {
    None,
    Quit,
    Run(DispatchPlan),
}

#[derive(Debug)]
struct App {
    actions: Vec<Action>,
    screen: Screen,
    selected: usize,
    status: String,
    dirty: bool,
    state_dir: Option<PathBuf>,
    last_size: (u16, u16),
}

impl App {
    fn new(actions: Vec<Action>, state_dir: Option<PathBuf>) -> Self {
        Self {
            actions,
            screen: Screen::Root,
            selected: 0,
            status: "Choose an action. Nothing scans until you enter an explicit root.".into(),
            dirty: true,
            state_dir,
            last_size: (80, 24),
        }
    }

    fn narrow(&self) -> bool {
        self.last_size.0 < MIN_WIDTH || self.last_size.1 < MIN_HEIGHT
    }

    fn on_key(&mut self, code: KeyCode, modifiers: KeyModifiers) -> io::Result<Outcome> {
        if self.narrow() {
            return self.on_key_narrow(code);
        }
        let outcome = match self.screen.clone() {
            Screen::Root => self.key_root(code),
            Screen::ActionInfo { index, scroll } => self.key_action_info(code, index, scroll),
            Screen::PathPrompt { index, input } => {
                self.key_path_prompt(code, modifiers, index, input)
            }
            Screen::RuleMode {
                index,
                root,
                choice,
            } => self.key_rule_mode(code, index, root, choice),
            Screen::Help { scroll } => self.key_help(code, scroll),
        }?;
        self.dirty = true;
        Ok(outcome)
    }

    fn on_key_narrow(&mut self, code: KeyCode) -> io::Result<Outcome> {
        let outcome = match self.screen.clone() {
            Screen::Root => match code {
                KeyCode::Char('q') | KeyCode::Esc => Outcome::Quit,
                KeyCode::Char('?') | KeyCode::Char('h') => {
                    self.screen = Screen::Help { scroll: 0 };
                    self.status = "Narrow terminal: only help and quit are available.".into();
                    Outcome::None
                }
                _ => {
                    self.status =
                        "Terminal is too small (minimum 60x14). Resize to dispatch actions.".into();
                    Outcome::None
                }
            },
            Screen::ActionInfo { .. } | Screen::PathPrompt { .. } | Screen::RuleMode { .. } => {
                match code {
                    KeyCode::Esc | KeyCode::Left | KeyCode::Backspace => {
                        self.screen = Screen::Root;
                        self.status = "Returned to root menu.".into();
                    }
                    _ => {
                        self.status = "Terminal is too small; only back/quit is allowed.".into();
                    }
                }
                Outcome::None
            }
            Screen::Help { scroll } => self.key_help(code, scroll)?,
        };
        self.dirty = true;
        Ok(outcome)
    }

    fn key_root(&mut self, code: KeyCode) -> io::Result<Outcome> {
        match code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected = self.selected.saturating_sub(1);
                Ok(Outcome::None)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.selected + 1 < self.actions.len() {
                    self.selected += 1;
                }
                Ok(Outcome::None)
            }
            KeyCode::Char('?') | KeyCode::Char('h') => {
                self.screen = Screen::Help { scroll: 0 };
                Ok(Outcome::None)
            }
            KeyCode::Char('q') | KeyCode::Esc => Ok(Outcome::Quit),
            KeyCode::Enter | KeyCode::Right => {
                self.screen = Screen::ActionInfo {
                    index: self.selected,
                    scroll: 0,
                };
                Ok(Outcome::None)
            }
            KeyCode::Char(digit @ '1'..='9') => {
                let index = usize::from((digit as u8) - b'1');
                if index < self.actions.len() {
                    self.selected = index;
                    self.screen = Screen::ActionInfo { index, scroll: 0 };
                }
                Ok(Outcome::None)
            }
            _ => Ok(Outcome::None),
        }
    }

    fn key_action_info(
        &mut self,
        code: KeyCode,
        index: usize,
        mut scroll: usize,
    ) -> io::Result<Outcome> {
        let action = self
            .actions
            .get(index)
            .ok_or_else(|| io::Error::other("action index out of range"))?;
        let max_scroll = action.details.len().saturating_sub(1);
        match code {
            KeyCode::Esc | KeyCode::Left | KeyCode::Backspace => {
                self.screen = Screen::Root;
                Ok(Outcome::None)
            }
            KeyCode::Up | KeyCode::Char('k') => {
                scroll = scroll.saturating_sub(1);
                self.screen = Screen::ActionInfo { index, scroll };
                Ok(Outcome::None)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                scroll = (scroll + 1).min(max_scroll);
                self.screen = Screen::ActionInfo { index, scroll };
                Ok(Outcome::None)
            }
            KeyCode::PageUp => {
                scroll = scroll.saturating_sub(6);
                self.screen = Screen::ActionInfo { index, scroll };
                Ok(Outcome::None)
            }
            KeyCode::PageDown => {
                scroll = (scroll + 6).min(max_scroll);
                self.screen = Screen::ActionInfo { index, scroll };
                Ok(Outcome::None)
            }
            KeyCode::Enter | KeyCode::Right => {
                if !action.enabled {
                    self.status = action
                        .disabled_reason
                        .unwrap_or("This action is disabled on this host.")
                        .to_string();
                    return Ok(Outcome::None);
                }
                self.screen = Screen::PathPrompt {
                    index,
                    input: String::new(),
                };
                self.status = "Type an explicit root path and press Enter. Esc cancels.".into();
                Ok(Outcome::None)
            }
            _ => {
                self.screen = Screen::ActionInfo { index, scroll };
                Ok(Outcome::None)
            }
        }
    }

    fn key_path_prompt(
        &mut self,
        code: KeyCode,
        modifiers: KeyModifiers,
        index: usize,
        mut input: String,
    ) -> io::Result<Outcome> {
        match code {
            KeyCode::Esc | KeyCode::Left => {
                self.screen = Screen::ActionInfo { index, scroll: 0 };
                self.status = "Path entry cancelled.".into();
                Ok(Outcome::None)
            }
            KeyCode::Backspace => {
                input.pop();
                self.screen = Screen::PathPrompt { index, input };
                Ok(Outcome::None)
            }
            KeyCode::Char('u') if modifiers.contains(KeyModifiers::CONTROL) => {
                input.clear();
                self.screen = Screen::PathPrompt { index, input };
                Ok(Outcome::None)
            }
            KeyCode::Enter => {
                let root = match parse_explicit_root(&input) {
                    Ok(root) => root,
                    Err(error) => {
                        self.status = format!("Invalid root: {error}");
                        self.screen = Screen::PathPrompt { index, input };
                        return Ok(Outcome::None);
                    }
                };
                let action = self
                    .actions
                    .get(index)
                    .ok_or_else(|| io::Error::other("action index out of range"))?;
                match action.kind {
                    ActionKind::PythonRule | ActionKind::JavaRule => {
                        self.screen = Screen::RuleMode {
                            index,
                            root,
                            choice: 0,
                        };
                        self.status =
                            "Choose preview or existing approval flow. No cleanup is preselected."
                                .into();
                        Ok(Outcome::None)
                    }
                    _ => build_dispatch_plan(
                        action.kind,
                        root,
                        None,
                        self.state_dir.as_deref(),
                        current_exe_path()?,
                    )
                    .map(Outcome::Run),
                }
            }
            KeyCode::Char(ch) if !modifiers.contains(KeyModifiers::CONTROL) => {
                if ch.is_control() {
                    self.status = "Control characters are not accepted in menu path input.".into();
                    self.screen = Screen::PathPrompt { index, input };
                    return Ok(Outcome::None);
                }
                let mut append = [0u8; 4];
                let bytes = ch.encode_utf8(&mut append).as_bytes();
                if input.len() + bytes.len() > MAX_PATH_INPUT_BYTES {
                    self.status = format!(
                        "Path input is limited to {} UTF-8 bytes.",
                        MAX_PATH_INPUT_BYTES
                    );
                    self.screen = Screen::PathPrompt { index, input };
                    return Ok(Outcome::None);
                }
                input.push(ch);
                self.screen = Screen::PathPrompt { index, input };
                Ok(Outcome::None)
            }
            _ => {
                self.screen = Screen::PathPrompt { index, input };
                Ok(Outcome::None)
            }
        }
    }

    fn key_rule_mode(
        &mut self,
        code: KeyCode,
        index: usize,
        root: PathBuf,
        mut choice: usize,
    ) -> io::Result<Outcome> {
        match code {
            KeyCode::Up | KeyCode::Char('k') => {
                choice = choice.saturating_sub(1);
                self.screen = Screen::RuleMode {
                    index,
                    root,
                    choice,
                };
                Ok(Outcome::None)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if choice < 2 {
                    choice += 1;
                }
                self.screen = Screen::RuleMode {
                    index,
                    root,
                    choice,
                };
                Ok(Outcome::None)
            }
            KeyCode::Esc | KeyCode::Left | KeyCode::Backspace => {
                self.screen = Screen::PathPrompt {
                    index,
                    input: root.display().to_string(),
                };
                self.status = "Rule mode cancelled.".into();
                Ok(Outcome::None)
            }
            KeyCode::Enter | KeyCode::Right => {
                if choice == 2 {
                    self.screen = Screen::PathPrompt {
                        index,
                        input: root.display().to_string(),
                    };
                    return Ok(Outcome::None);
                }
                let mode = if choice == 0 {
                    RuleMode::Preview
                } else {
                    RuleMode::Approval
                };
                let action = self
                    .actions
                    .get(index)
                    .ok_or_else(|| io::Error::other("action index out of range"))?;
                if matches!(mode, RuleMode::Approval) && !action.approval_enabled {
                    self.status = action
                        .approval_disabled_reason
                        .unwrap_or("Rule approval is not available on this host.")
                        .to_string();
                    self.screen = Screen::RuleMode {
                        index,
                        root,
                        choice,
                    };
                    return Ok(Outcome::None);
                }
                build_dispatch_plan(
                    action.kind,
                    root,
                    Some(mode),
                    self.state_dir.as_deref(),
                    current_exe_path()?,
                )
                .map(Outcome::Run)
            }
            _ => {
                self.screen = Screen::RuleMode {
                    index,
                    root,
                    choice,
                };
                Ok(Outcome::None)
            }
        }
    }

    fn key_help(&mut self, code: KeyCode, mut scroll: usize) -> io::Result<Outcome> {
        let max = help_lines().len().saturating_sub(1);
        match code {
            KeyCode::Up | KeyCode::Char('k') => scroll = scroll.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => scroll = (scroll + 1).min(max),
            KeyCode::PageUp => scroll = scroll.saturating_sub(8),
            KeyCode::PageDown => scroll = (scroll + 8).min(max),
            KeyCode::Esc | KeyCode::Left | KeyCode::Backspace | KeyCode::Char('q') => {
                self.screen = Screen::Root;
                return Ok(Outcome::None);
            }
            _ => {}
        }
        self.screen = Screen::Help { scroll };
        Ok(Outcome::None)
    }

    fn frame(&self) -> Vec<Line> {
        let mut lines = Vec::new();
        lines.push(Line {
            text: "Sayaka menu  /  explicit maintenance entry (macOS-first)".into(),
            style: Style::Header,
        });
        if self.narrow() {
            lines.push(Line {
                text: format!(
                    "Terminal too small: {}x{} (minimum {}x{}).",
                    self.last_size.0, self.last_size.1, MIN_WIDTH, MIN_HEIGHT
                ),
                style: Style::Warning,
            });
        }
        match &self.screen {
            Screen::Root => {
                lines.push(Line {
                    text: "Choose action (Enter):".into(),
                    style: Style::Muted,
                });
                for (index, action) in self.actions.iter().enumerate() {
                    let marker = if index == self.selected { ">" } else { " " };
                    let state = if action.enabled {
                        ""
                    } else {
                        " (disabled on this host)"
                    };
                    lines.push(Line {
                        text: format!("{marker} {}. {}{state}", index + 1, action.label),
                        style: if index == self.selected {
                            Style::Selected
                        } else {
                            Style::Normal
                        },
                    });
                }
                lines.push(Line {
                    text: "Keys: ↑/↓ or j/k, Enter details, ? help, q quit".into(),
                    style: Style::Muted,
                });
            }
            Screen::ActionInfo { index, scroll } => {
                if let Some(action) = self.actions.get(*index) {
                    let lines_before = lines.len();
                    lines.push(Line {
                        text: action.label.to_string(),
                        style: Style::Header,
                    });
                    lines.push(Line {
                        text: action.summary.to_string(),
                        style: Style::Normal,
                    });
                    if !action.enabled {
                        lines.push(Line {
                            text: action
                                .disabled_reason
                                .unwrap_or("Disabled on this host.")
                                .to_string(),
                            style: Style::Warning,
                        });
                    }
                    let reserved = 3usize;
                    let fixed = lines.len().saturating_sub(lines_before);
                    let available = self
                        .last_size
                        .1
                        .saturating_sub((lines_before + fixed + reserved) as u16)
                        as usize;
                    for detail in action.details.iter().skip(*scroll).take(available.max(1)) {
                        lines.push(Line {
                            text: format!("• {detail}"),
                            style: Style::Muted,
                        });
                    }
                    if !action.details.is_empty() {
                        let shown_end = (*scroll + available.max(1)).min(action.details.len());
                        lines.push(Line {
                            text: format!(
                                "Details {}-{} of {} (j/k or PgUp/PgDn to scroll)",
                                (*scroll + 1).min(action.details.len()),
                                shown_end,
                                action.details.len()
                            ),
                            style: Style::Muted,
                        });
                    }
                    lines.push(Line {
                        text: "Enter: continue to explicit root path; Esc: back".into(),
                        style: Style::Muted,
                    });
                }
            }
            Screen::PathPrompt { index, input } => {
                let title = self
                    .actions
                    .get(*index)
                    .map(|action| action.label)
                    .unwrap_or("Action");
                lines.push(Line {
                    text: format!("{title} / explicit root"),
                    style: Style::Header,
                });
                lines.push(Line {
                    text: "Type one UTF-8 path. No HOME defaults, no shell expansion, no autoscan."
                        .into(),
                    style: Style::Muted,
                });
                lines.push(Line {
                    text: format!("ROOT: {}", clip_display(input, self.last_size.0 as usize)),
                    style: Style::Selected,
                });
                lines.push(Line {
                    text: format!("{} / {} bytes", input.len(), MAX_PATH_INPUT_BYTES),
                    style: Style::Muted,
                });
                lines.push(Line {
                    text: "Enter: continue; Ctrl-U: clear; Backspace: delete; Esc: back".into(),
                    style: Style::Muted,
                });
            }
            Screen::RuleMode { index, choice, .. } => {
                let approval_enabled = self
                    .actions
                    .get(*index)
                    .is_some_and(|action| action.approval_enabled);
                lines.push(Line {
                    text: "Choose rule action mode".into(),
                    style: Style::Header,
                });
                for (index, option) in [
                    "Preview candidates (read-only rules preview)",
                    "Enter existing approval flow (clean --execute)",
                    "Back",
                ]
                .iter()
                .enumerate()
                {
                    let disabled_approval = index == 1 && !approval_enabled;
                    lines.push(Line {
                        text: if disabled_approval {
                            format!(
                                "{} {} (disabled)",
                                if *choice == index { ">" } else { " " },
                                option
                            )
                        } else {
                            format!("{} {}", if *choice == index { ">" } else { " " }, option)
                        },
                        style: if *choice == index {
                            Style::Selected
                        } else {
                            Style::Normal
                        },
                    });
                }
                if let Some(action) = self.actions.get(*index)
                    && !action.approval_enabled
                {
                    lines.push(Line {
                        text: action
                            .approval_disabled_reason
                            .unwrap_or("Rule approval is unavailable on this host.")
                            .to_string(),
                        style: Style::Warning,
                    });
                }
                lines.push(Line {
                    text: "No preselected targets. Approval remains exact child confirmation."
                        .into(),
                    style: Style::Muted,
                });
            }
            Screen::Help { scroll } => {
                lines.push(Line {
                    text: "Menu help".into(),
                    style: Style::Header,
                });
                let help = help_lines();
                let usable = self.last_size.1.saturating_sub(4) as usize;
                for line in help.iter().skip(*scroll).take(usable.max(1)) {
                    lines.push(Line {
                        text: clip_display(line, self.last_size.0 as usize),
                        style: Style::Normal,
                    });
                }
                lines.push(Line {
                    text: "Esc/q back; arrows or j/k scroll".into(),
                    style: Style::Muted,
                });
            }
        }
        lines.push(Line {
            text: clip_display(&self.status, self.last_size.0 as usize),
            style: Style::Warning,
        });
        clip_frame_width(
            trim_frame(lines, self.last_size.1 as usize),
            self.last_size.0 as usize,
        )
    }
}

fn clip_frame_width(lines: Vec<Line>, width: usize) -> Vec<Line> {
    lines
        .into_iter()
        .map(|line| Line {
            text: clip_display(&line.text, width),
            style: line.style,
        })
        .collect()
}

fn trim_frame(mut lines: Vec<Line>, height: usize) -> Vec<Line> {
    if height == 0 {
        return Vec::new();
    }
    if lines.len() > height {
        lines.truncate(height);
    }
    lines
}

fn help_lines() -> Vec<String> {
    vec![
        "Actions: browse, Python/Java rule previews, approval-flow entry, installer preview, app inventory.".into(),
        "Every action requires a typed root path. Empty/default roots are rejected.".into(),
        "Rule mode separates read-only preview from clean --execute approval flow.".into(),
        "No --yes and no preselected --select targets are passed by menu dispatch.".into(),
        "The clean child keeps existing candidate choice, exclusions, sealed plan, and exact phrase confirmation.".into(),
        "Paths are UTF-8 only in menu input; for raw non-UTF-8 bytes use direct CLI arguments.".into(),
        "Control characters are rejected in menu path input.".into(),
        "If this terminal is too small (<60x14), dispatch is blocked until resize.".into(),
        "apps-related remains direct CLI only in this batch:".into(),
        "  sayaka apps-related --app-root /Applications --library-root \"$HOME/Library\"".into(),
    ]
}

fn clip_display(text: &str, max_columns: usize) -> String {
    if max_columns == 0 {
        return String::new();
    }
    let mut output = String::new();
    let mut used = 0usize;
    let mut clipped = false;
    for ch in text.chars() {
        if ch.is_control() {
            for escaped in ch.escape_default() {
                if used + 1 > max_columns {
                    clipped = true;
                    break;
                }
                output.push(escaped);
                used += 1;
            }
            if clipped {
                break;
            }
            continue;
        }
        let width = UnicodeWidthChar::width(ch).unwrap_or(0);
        if used + width > max_columns {
            clipped = true;
            break;
        }
        output.push(ch);
        used += width;
    }
    if clipped && used < max_columns {
        output.push('…');
    }
    output
}

fn parse_explicit_root(input: &str) -> io::Result<PathBuf> {
    if input.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "root path is required; no default root is used",
        ));
    }
    if input.len() > MAX_PATH_INPUT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("root path exceeds {MAX_PATH_INPUT_BYTES} UTF-8 bytes"),
        ));
    }
    if input.chars().any(char::is_control) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "root path contains control characters",
        ));
    }
    let path = PathBuf::from(input);
    if path
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "'..' traversal is not accepted",
        ));
    }
    std::path::absolute(path)
}

fn current_exe_path() -> io::Result<PathBuf> {
    std::env::current_exe().map_err(|error| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("cannot resolve current executable: {error}"),
        )
    })
}

fn action_catalog() -> io::Result<Vec<Action>> {
    let python = builtin_rule(CPYTHON_SOURCE_BACKED_PYC_RULE_ID)?;
    let java = builtin_rule(JAVAC_SOURCE_BACKED_CLASS_RULE_ID)?;
    Ok(vec![
        Action {
            kind: ActionKind::Browse,
            label: "Browse disk snapshot",
            summary: "Read-only terminal browser with explicit scope.",
            enabled: cfg!(target_os = "macos"),
            disabled_reason: (!cfg!(target_os = "macos"))
                .then_some("Browse menu dispatch is currently accepted on macOS only."),
            approval_enabled: false,
            approval_disabled_reason: None,
            details: vec![
                "No implicit root; type one path first.".into(),
                "Native preview/confirmation semantics remain unchanged in the child command."
                    .into(),
            ],
        },
        rule_action(
            ActionKind::PythonRule,
            "Python cache clean rule",
            python,
            cfg!(target_os = "macos") || cfg!(windows),
            cfg!(target_os = "macos"),
        ),
        rule_action(
            ActionKind::JavaRule,
            "Java class clean rule",
            java,
            cfg!(target_os = "macos") || cfg!(windows),
            cfg!(target_os = "macos"),
        ),
        Action {
            kind: ActionKind::InstallerPreview,
            label: "Installer preview",
            summary: "Read-only installer-format discovery.",
            enabled: cfg!(target_os = "macos"),
            disabled_reason: (!cfg!(target_os = "macos"))
                .then_some("Installer preview acceptance is currently macOS-only."),
            approval_enabled: false,
            approval_disabled_reason: None,
            details: vec![
                "Preview-only; no mounts, installs, or deletions.".into(),
                "Type an explicit root; no defaults.".into(),
            ],
        },
        Action {
            kind: ActionKind::AppsInventory,
            label: "Apps inventory preview",
            summary: "Read-only app inventory metadata preview.",
            enabled: cfg!(target_os = "macos"),
            disabled_reason: (!cfg!(target_os = "macos"))
                .then_some("Apps inventory acceptance is currently macOS-only."),
            approval_enabled: false,
            approval_disabled_reason: None,
            details: vec![
                "Preview-only; no launch/uninstall actions.".into(),
                "apps-related remains direct CLI in this batch.".into(),
            ],
        },
    ])
}

fn builtin_rule(id: &str) -> io::Result<&'static RuleDefinition> {
    builtin_rules()
        .iter()
        .find(|rule| rule.id == id)
        .ok_or_else(|| io::Error::other(format!("required builtin rule {id} is missing")))
}

fn rule_action(
    kind: ActionKind,
    label: &'static str,
    rule: &RuleDefinition,
    enabled: bool,
    approval_enabled: bool,
) -> Action {
    Action {
        kind,
        label,
        summary: rule.title,
        enabled,
        disabled_reason: (!enabled).then_some(
            "Rule preview is unavailable on this host. Use `sayaka rules preview` where supported.",
        ),
        approval_enabled,
        approval_disabled_reason: (!approval_enabled).then_some(
            "Rule approval/execute is macOS-only in this slice; preview remains read-only.",
        ),
        details: vec![
            format!("Rule ID: {} (v{})", rule.id, rule.version),
            format!("Targets: {}", rule.targets.join("; ")),
            format!("Non-targets: {}", rule.non_targets.join("; ")),
            format!("Prerequisites: {}", rule.prerequisites.join("; ")),
            format!("Rebuild cost: {}", rule.rebuild_cost),
            format!("Recovery cost: {}", rule.recovery_cost),
            format!("Concurrency: {}", rule.concurrency),
            format!("Failure: {}", rule.failure),
        ],
    }
}

fn build_dispatch_plan(
    kind: ActionKind,
    root: PathBuf,
    mode: Option<RuleMode>,
    state_dir: Option<&Path>,
    program: PathBuf,
) -> io::Result<DispatchPlan> {
    let mut args = Vec::<OsString>::new();
    let label = match kind {
        ActionKind::Browse => {
            args.push("browse".into());
            if let Some(state_dir) = state_dir {
                args.push("--state-dir".into());
                args.push(state_dir.as_os_str().to_os_string());
            }
            args.push("--".into());
            args.push(root.as_os_str().to_os_string());
            "browse".into()
        }
        ActionKind::InstallerPreview => {
            args.push("installer".into());
            args.push("--".into());
            args.push(root.as_os_str().to_os_string());
            "installer preview".into()
        }
        ActionKind::AppsInventory => {
            args.push("apps".into());
            args.push("--".into());
            args.push(root.as_os_str().to_os_string());
            "apps inventory preview".into()
        }
        ActionKind::PythonRule | ActionKind::JavaRule => {
            let rule = if matches!(kind, ActionKind::PythonRule) {
                CPYTHON_SOURCE_BACKED_PYC_RULE_ID
            } else {
                JAVAC_SOURCE_BACKED_CLASS_RULE_ID
            };
            match mode.ok_or_else(|| io::Error::other("missing rule mode"))? {
                RuleMode::Preview => {
                    args.push("rules".into());
                    args.push("preview".into());
                    args.push("--rule".into());
                    args.push(rule.into());
                    args.push("--".into());
                    args.push(root.as_os_str().to_os_string());
                    format!("{rule} preview")
                }
                RuleMode::Approval => {
                    if !cfg!(target_os = "macos") {
                        return Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "rule approval dispatch is macOS-only in this slice",
                        ));
                    }
                    args.push("clean".into());
                    args.push("--rule".into());
                    args.push(rule.into());
                    args.push("--execute".into());
                    if let Some(state_dir) = state_dir {
                        args.push("--state-dir".into());
                        args.push(state_dir.as_os_str().to_os_string());
                    }
                    args.push("--".into());
                    args.push(root.as_os_str().to_os_string());
                    format!("{rule} approval")
                }
            }
        }
    };
    Ok(DispatchPlan {
        label,
        program,
        args,
    })
}

#[derive(Debug)]
struct OwnedChild {
    child: Child,
    reaped: bool,
}

impl OwnedChild {
    fn spawn(program: &Path, args: &[OsString]) -> io::Result<Self> {
        let child = ProcessCommand::new(program)
            .args(args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()?;
        Ok(Self {
            child,
            reaped: false,
        })
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        let result = self.child.try_wait()?;
        if result.is_some() {
            self.reaped = true;
        }
        Ok(result)
    }

    #[cfg(unix)]
    fn signal(&self, signal: Signal) -> io::Result<()> {
        let pid = Pid::from_raw(self.child.id() as i32)
            .ok_or_else(|| io::Error::other("child PID does not fit platform PID type"))?;
        match kill_process(pid, signal) {
            Ok(()) => Ok(()),
            Err(errno) if errno == rustix::io::Errno::SRCH => Ok(()),
            Err(errno) => Err(io::Error::from_raw_os_error(errno.raw_os_error())),
        }
    }

    fn kill(&mut self) -> io::Result<()> {
        self.child.kill()
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        match self.child.try_wait() {
            Ok(Some(_)) => self.reaped = true,
            Ok(None) => {
                if let Err(error) = self.child.kill() {
                    eprintln!(
                        "could not request owned child stop {}: {error}",
                        self.child.id()
                    );
                }
                if let Err(error) = self.child.wait() {
                    eprintln!("could not reap owned child {}: {error}", self.child.id());
                }
                self.reaped = true;
            }
            Err(error) => eprintln!(
                "could not poll owned child {}; status unknown: {error}",
                self.child.id()
            ),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ChildOutcome {
    SpawnFailed(String),
    Completed { status: ExitStatus, forwarded: bool },
}

impl ChildOutcome {
    fn summary(&self) -> String {
        match self {
            ChildOutcome::SpawnFailed(error) => format!("Child spawn failed: {error}"),
            ChildOutcome::Completed { status, forwarded } => {
                let base = format!("Child exited: {}", format_exit_status(*status));
                if *forwarded {
                    format!("{base} (signal forwarded by parent)")
                } else {
                    base
                }
            }
        }
    }
}

fn dispatch(plan: &DispatchPlan, signals: &Signals) -> io::Result<ChildOutcome> {
    let mut child = match OwnedChild::spawn(&plan.program, &plan.args) {
        Ok(child) => child,
        Err(error) => return Ok(ChildOutcome::SpawnFailed(error.to_string())),
    };
    let (status, forwarded) = wait_for_owned_child(&mut child, || SignalState {
        interrupted: signals.interrupted(),
        terminated: signals.terminated(),
    })?;
    Ok(ChildOutcome::Completed { status, forwarded })
}

#[derive(Clone, Copy, Debug, Default)]
struct SignalState {
    interrupted: bool,
    terminated: bool,
}

fn wait_for_owned_child(
    child: &mut OwnedChild,
    mut signal_state: impl FnMut() -> SignalState,
) -> io::Result<(ExitStatus, bool)> {
    let mut forwarded = false;
    let mut interrupt_sent_at = None::<Instant>;
    let mut terminate_sent_at = None::<Instant>;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok((status, forwarded));
        }
        let state = signal_state();
        #[cfg(unix)]
        {
            if state.interrupted && interrupt_sent_at.is_none() {
                child.signal(Signal::INT)?;
                forwarded = true;
                interrupt_sent_at = Some(Instant::now());
            }
            if (state.terminated
                || interrupt_sent_at.is_some_and(|sent| sent.elapsed() >= CHILD_TERM_GRACE))
                && terminate_sent_at.is_none()
            {
                child.signal(Signal::TERM)?;
                forwarded = true;
                terminate_sent_at = Some(Instant::now());
            }
            if terminate_sent_at.is_some_and(|sent| sent.elapsed() >= CHILD_TERM_GRACE) {
                force_kill_owned_child(child)?;
            }
        }
        #[cfg(not(unix))]
        {
            if state.interrupted || state.terminated {
                force_kill_owned_child(child)?;
                forwarded = true;
            }
        }
        thread::sleep(CHILD_POLL);
    }
}

fn force_kill_owned_child(child: &mut OwnedChild) -> io::Result<()> {
    match child.kill() {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::InvalidInput
            ) =>
        {
            if child.try_wait()?.is_some() {
                Ok(())
            } else {
                Err(error)
            }
        }
        Err(error) => Err(error),
    }
}

fn post_child_prompt(
    label: &str,
    outcome: &ChildOutcome,
    signals: &Signals,
) -> io::Result<AfterChild> {
    let mut out = io::stdout().lock();
    writeln!(out)?;
    writeln!(out, "=== sayaka menu child outcome ===")?;
    writeln!(out, "Action: {label}")?;
    writeln!(out, "{}", outcome.summary())?;
    writeln!(
        out,
        "Press Enter to return, r to repeat, q to quit. Ctrl-C exits."
    )?;
    out.flush()?;
    let _raw = RawModeGuard::enter()?;
    loop {
        if let Some(code) = signals.exit_code() {
            return Ok(AfterChild::Exit(code));
        }
        if event::poll(POST_CHILD_POLL)? {
            let event = event::read()?;
            if let Event::Key(key) = event {
                if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
                    continue;
                }
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                    return Ok(AfterChild::Exit(130));
                }
                return Ok(match key.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') => AfterChild::Quit,
                    KeyCode::Char('r') | KeyCode::Char('R') => AfterChild::Repeat,
                    KeyCode::Enter => AfterChild::Back,
                    _ => AfterChild::Back,
                });
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AfterChild {
    Back,
    Repeat,
    Quit,
    Exit(u8),
}

struct RawModeGuard;

impl RawModeGuard {
    fn enter() -> io::Result<Self> {
        terminal::enable_raw_mode()?;
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
    }
}

fn format_exit_status(status: ExitStatus) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(code) = status.code() {
            return format!("code {code}");
        }
        if let Some(signal) = status.signal() {
            return format!("signal {signal}");
        }
        "unknown process status".into()
    }
    #[cfg(not(unix))]
    {
        status
            .code()
            .map(|code| format!("code {code}"))
            .unwrap_or_else(|| "unknown process status".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    #[cfg(unix)]
    use std::io::BufRead;
    #[cfg(unix)]
    use std::os::unix::process::ExitStatusExt;
    #[cfg(unix)]
    use std::process::{Command as ProcessCommand, Stdio};
    #[cfg(unix)]
    use std::sync::mpsc;
    #[cfg(unix)]
    use std::thread;
    use unicode_width::UnicodeWidthStr;

    #[test]
    fn catalog_uses_builtin_rules_for_python_and_java() {
        let actions = action_catalog().unwrap();
        let python = actions
            .iter()
            .find(|action| action.kind == ActionKind::PythonRule)
            .unwrap();
        assert!(
            python
                .details
                .iter()
                .any(|detail| detail.contains(CPYTHON_SOURCE_BACKED_PYC_RULE_ID))
        );
        let java = actions
            .iter()
            .find(|action| action.kind == ActionKind::JavaRule)
            .unwrap();
        assert!(
            java.details
                .iter()
                .any(|detail| detail.contains(JAVAC_SOURCE_BACKED_CLASS_RULE_ID))
        );
    }

    #[test]
    fn parse_explicit_root_rejects_empty_control_and_parent_traversal() {
        assert!(parse_explicit_root("").is_err());
        assert!(parse_explicit_root("a\nb").is_err());
        assert!(parse_explicit_root("../x").is_err());
    }

    #[test]
    fn parse_explicit_root_accepts_exact_max_utf8_bytes() {
        let text = "a".repeat(MAX_PATH_INPUT_BYTES);
        assert!(parse_explicit_root(&text).is_ok());
        let over = format!("{text}b");
        assert!(parse_explicit_root(&over).is_err());
    }

    #[test]
    fn dispatch_argv_uses_double_dash_and_existing_execute_flow() {
        let root = PathBuf::from("-leading-path");
        let plan = build_dispatch_plan(
            ActionKind::PythonRule,
            root.clone(),
            Some(RuleMode::Preview),
            None,
            PathBuf::from("/bin/sayaka"),
        )
        .unwrap();
        assert_eq!(
            plan.args,
            vec![
                OsString::from("rules"),
                OsString::from("preview"),
                OsString::from("--rule"),
                OsString::from(CPYTHON_SOURCE_BACKED_PYC_RULE_ID),
                OsString::from("--"),
                root.as_os_str().to_os_string(),
            ]
        );
        let plan = build_dispatch_plan(
            ActionKind::JavaRule,
            PathBuf::from("."),
            Some(RuleMode::Approval),
            Some(Path::new("state")),
            PathBuf::from("/bin/sayaka"),
        )
        .unwrap();
        let args: Vec<_> = plan
            .args
            .iter()
            .map(OsString::as_os_str)
            .collect::<Vec<&OsStr>>();
        assert_eq!(args[0], OsStr::new("clean"));
        assert!(args.contains(&OsStr::new("--execute")));
        assert!(args.contains(&OsStr::new("--state-dir")));
        assert!(args.contains(&OsStr::new("--")));
        assert!(!args.contains(&OsStr::new("--yes")));
        assert!(!args.contains(&OsStr::new("--select")));
    }

    #[test]
    fn path_prompt_editing_obeys_utf8_limit_and_backspace() {
        let mut app = App::new(action_catalog().unwrap(), None);
        app.screen = Screen::PathPrompt {
            index: 0,
            input: String::new(),
        };
        app.on_key(KeyCode::Char('中'), KeyModifiers::NONE).unwrap();
        app.on_key(KeyCode::Backspace, KeyModifiers::NONE).unwrap();
        if let Screen::PathPrompt { input, .. } = &app.screen {
            assert!(input.is_empty());
        } else {
            panic!("expected path prompt");
        }
    }

    #[test]
    fn spawn_failure_is_reported_without_success_masking() {
        let plan = DispatchPlan {
            label: "broken".into(),
            program: PathBuf::from("/definitely/missing/sayaka"),
            args: vec!["scan".into()],
        };
        let signals = Signals::new().unwrap();
        let outcome = dispatch(&plan, &signals).unwrap();
        assert!(matches!(outcome, ChildOutcome::SpawnFailed(_)));
    }

    #[test]
    fn clip_display_respects_control_escape_and_unicode_width() {
        let text = "A\u{1b}e\u{301}中B";
        let clipped = clip_display(text, 6);
        assert!(!clipped.chars().any(char::is_control));
        assert!(UnicodeWidthStr::width(clipped.as_str()) <= 6);
        assert!(clipped.contains('\\'));
    }

    #[test]
    fn action_info_frame_clips_all_lines_and_keeps_navigation_in_60x14() {
        let mut app = App::new(action_catalog().unwrap(), None);
        app.last_size = (60, 14);
        app.screen = Screen::ActionInfo {
            index: 1,
            scroll: 0,
        };
        let frame = app.frame();
        assert!(
            frame
                .iter()
                .all(|line| UnicodeWidthStr::width(line.text.as_str()) <= 60)
        );
        assert!(
            frame
                .iter()
                .all(|line| !line.text.chars().any(char::is_control))
        );
        assert!(
            frame
                .iter()
                .any(|line| line.text.contains("Enter: continue to explicit root path"))
        );
        assert!(
            frame
                .iter()
                .any(|line| line.text.contains("Details") && line.text.contains("scroll"))
        );
    }

    #[test]
    #[cfg(unix)]
    fn interrupted_wait_escalates_to_term_then_forced_kill() {
        let script = r#"import signal,time
signal.signal(signal.SIGINT, signal.SIG_IGN)
signal.signal(signal.SIGTERM, signal.SIG_IGN)
print("READY", flush=True)
while True:
    time.sleep(0.1)
"#;
        let mut process = ProcessCommand::new("/usr/bin/python3")
            .arg("-c")
            .arg(script)
            .env_clear()
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn ignoring-signal child");
        let stdout = process.stdout.take().expect("child stdout");
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let mut line = String::new();
            let mut reader = std::io::BufReader::new(stdout);
            let result = reader.read_line(&mut line).map(|_| line);
            let _ = ready_tx.send(result);
        });
        let ready = ready_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("ready handshake timeout")
            .expect("ready handshake read failure");
        assert_eq!(ready.trim_end(), "READY");
        let mut child = OwnedChild {
            child: process,
            reaped: false,
        };
        let started = Instant::now();
        let (status, forwarded) = wait_for_owned_child(&mut child, || SignalState {
            interrupted: true,
            terminated: false,
        })
        .expect("wait helper result");
        assert!(forwarded);
        assert_eq!(status.signal(), Some(signal_hook::consts::SIGKILL));
        assert!(
            started.elapsed() < Duration::from_secs(8),
            "forced kill should remain bounded"
        );
    }
}
