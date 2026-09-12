// SPDX-License-Identifier: MPL-2.0

mod jobs;
mod model;
mod render;
mod terminal;
#[cfg(all(test, target_os = "macos"))]
mod tests;

use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use jobs::{ActionResult, Job, Viewer};
use model::{App, BrowserData, Screen};
use sayaka_engine::model::Cancellation;
use sayaka_engine::scan::{self, ScanLimits};
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub fn command() -> Command {
    Command::new("browse")
        .visible_alias("analyze")
        .about("Browse an explicitly selected disk scope; directories are read-only")
        .arg(Arg::new("root").value_name("ROOT").required(true).value_parser(value_parser!(PathBuf)))
        .arg(Arg::new("plain").long("plain").action(ArgAction::SetTrue)
            .help("Read-only plain directory report (automatic for pipes or TERM=dumb)"))
        .arg(Arg::new("state-dir").long("state-dir").value_name("DIR").value_parser(value_parser!(PathBuf))
            .help("Private M3 journal directory; used only after explicit confirmation"))
        .after_help("Keys: arrows/Enter browse, Space select file, x exclude, / filter, s sort, a size metric,\nv selected, t exact Trash plan, o reveal, p Quick Look, r refresh, m menu, ? help, q quit.\nScanning is bounded and read-only. Nothing is trashed without a separate exact-plan confirmation.")
}

pub fn run(args: &ArgMatches) -> io::Result<u8> {
    let result = (|| {
        let root = args
            .get_one::<PathBuf>("root")
            .ok_or_else(|| io::Error::other("missing root"))?;
        let root = physical_input(root)?;
        let state = args
            .get_one::<PathBuf>("state-dir")
            .map(|path| physical_input(path))
            .transpose()?;
        if args.get_flag("plain")
            || !io::stdin().is_terminal()
            || !io::stdout().is_terminal()
            || std::env::var_os("TERM").is_some_and(|term| term == "dumb")
        {
            return plain(&root);
        }
        match std::panic::catch_unwind(move || interactive(root, state)) {
            Ok(result) => result,
            Err(payload) => {
                let detail = payload
                    .downcast_ref::<String>()
                    .map(String::as_str)
                    .or_else(|| payload.downcast_ref::<&str>().copied())
                    .unwrap_or("non-string panic payload");
                Err(io::Error::other(format!(
                    "browser panicked: {detail}; inspect receipt for any in-flight operation"
                )))
            }
        }
    })();
    match result {
        Ok(code) => Ok(code),
        Err(error) => {
            writeln!(
                io::stderr().lock(),
                "browse failed: {:?}",
                error.to_string()
            )?;
            Ok(match error.kind() {
                io::ErrorKind::InvalidInput => 2,
                io::ErrorKind::Interrupted => 130,
                _ => 1,
            })
        }
    }
}

fn physical_input(path: &Path) -> io::Result<PathBuf> {
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

fn scan_error(error: scan::ScanError) -> io::Error {
    io::Error::new(
        if matches!(
            error.code,
            scan::ScanCode::InvalidRoot | scan::ScanCode::InvalidLimits
        ) {
            io::ErrorKind::InvalidInput
        } else if error.code == scan::ScanCode::Cancelled {
            io::ErrorKind::Interrupted
        } else {
            io::ErrorKind::Other
        },
        error,
    )
}

fn plain(root: &Path) -> io::Result<u8> {
    let cancellation = Cancellation::default();
    let signals = terminal::Signals::new()?;
    let report = scan::scan(
        &[root.to_owned()],
        &ScanLimits::default(),
        &cancellation,
        |_| {
            if signals.exit_code().is_some() {
                cancellation.cancel();
            }
        },
    )
    .map_err(scan_error)?;
    if let Some(code) = signals.exit_code() {
        writeln!(
            io::stderr().lock(),
            "Browsing cancelled before directory summaries were ready."
        )?;
        return Ok(code);
    }
    let code = report.status.exit_code();
    let data = BrowserData::build(report, &cancellation)?;
    if let Some(code) = signals.exit_code() {
        return Ok(code);
    }
    let mut out = io::stdout().lock();
    writeln!(out, "Sayaka disk browser - read-only snapshot")?;
    writeln!(out, "Scope: {}", scan::display_path(root))?;
    writeln!(out, "Status: {}", data.tree.report().status.as_str())?;
    writeln!(
        out,
        "Observed regular entries: {}",
        data.tree.report().totals.regular_files
    )?;
    writeln!(out, "Index elapsed: {} ms", data.index_elapsed_ms)?;
    if let Some(root_id) = data.tree.roots().first() {
        let summary = data
            .tree
            .summary(*root_id)
            .ok_or_else(|| io::Error::other("root directory summary missing"))?;
        writeln!(out, "Root unique files: {}", summary.unique_files)?;
        writeln!(
            out,
            "Root logical subtotal: {} bytes; unknown files: {}; complete: {}",
            summary.logical_bytes_known, summary.logical_bytes_unknown_files, summary.complete
        )?;
        writeln!(
            out,
            "Observed logical size (subtrees independently deduplicated):"
        )?;
        for id in data
            .children(*root_id, model::Sort::Size, model::Metric::Logical)
            .iter()
            .take(100)
        {
            let entry = data.entry(*id)?;
            writeln!(
                out,
                "{:>14}  (known_bytes={})  {:>4}  {}",
                data.measure(*id, model::Metric::Logical),
                data.size(*id, model::Metric::Logical)
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "?".into()),
                model::kind(entry.kind),
                scan::display_path(&entry.path)
            )?;
        }
        let count = data
            .children(*root_id, model::Sort::Size, model::Metric::Logical)
            .len();
        if count > 100 {
            writeln!(
                out,
                "{} additional entries; use an interactive terminal to browse.",
                count - 100
            )?;
        }
    } else {
        writeln!(
            out,
            "The requested scope is unavailable; this is not an empty-directory result."
        )?;
    }
    for issue in &data.tree.report().issues {
        writeln!(
            io::stderr().lock(),
            "{}: {:?} ({:?})",
            issue.code.as_str(),
            issue.message,
            issue.path
        )?;
    }
    writeln!(
        out,
        "* incomplete coverage; +? unknown measurements. These are not reclaimable bytes."
    )?;
    out.flush()?;
    Ok(signals.exit_code().unwrap_or(code))
}

fn interactive(root: PathBuf, state: Option<PathBuf>) -> io::Result<u8> {
    let signals = terminal::Signals::new()?;
    // On unwind, terminal restoration must precede the job's cancel/join.
    let mut job = None;
    let mut term = terminal::Terminal::enter()?;
    let mut app = App::new(root.clone());
    let _ = job.replace(Job::scan(app.generation, root)?);
    let mut result = run_loop(&mut app, &mut job, state, &signals, &mut term);
    if let Some(active) = job.as_mut() {
        active.cancel();
    }
    if let Some(code) = signals.exit_code() {
        result = Ok(code);
    }
    // Restore the user's terminal before waiting for potentially blocking OS I/O.
    let restored = term.restore();
    if let Some(mut active) = job.take() {
        active.cancel();
        if !active.is_finished() {
            writeln!(
                io::stderr().lock(),
                "Stopping owned browser work; waiting for in-flight I/O."
            )?;
        }
        match active.finish() {
            Ok(jobs::ResultValue::Action(ActionResult::Executed(report))) => {
                super::trash::print_execution_report(&report)?;
                if report.exit_code() == 1 {
                    result = Ok(1);
                }
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    restored?;
    result
}

fn run_loop(
    app: &mut App,
    job: &mut Option<Job>,
    state: Option<PathBuf>,
    signals: &terminal::Signals,
    term: &mut terminal::Terminal,
) -> io::Result<u8> {
    let mut last_draw = Instant::now() - Duration::from_secs(1);
    loop {
        if let Some(code) = signals.exit_code().or(app.exit) {
            if let Some(active) = job.as_mut() {
                active.cancel();
            }
            return Ok(code);
        }
        if let Some(active) = job.as_mut() {
            if let Some(progress) = active.progress()? {
                app.status = format!(
                    "Scanning: {} entries, {} unique files, {} observed",
                    progress.entries,
                    progress.unique_files,
                    crate::human::size(progress.logical_bytes_known)
                );
            }
            if let Some(plan) = active.take_plan()? {
                app.accept_plan(active.generation(), plan);
            }
            if active.is_finished() {
                let active = job
                    .take()
                    .ok_or_else(|| io::Error::other("missing completed job"))?;
                let generation = active.generation();
                let result = active.finish();
                app.busy = false;
                if app.refresh_pending {
                    app.refresh_pending = false;
                    app.start_scan()?;
                    *job = Some(Job::scan(app.generation, app.root.clone())?);
                } else {
                    match result {
                        Ok(jobs::ResultValue::Scan(data)) => app.accept_scan(generation, *data)?,
                        Ok(jobs::ResultValue::Action(ActionResult::Cancelled)) => {
                            app.screen = Screen::Browse;
                            app.preview = None;
                            app.status = "Plan cancelled; no new action authorized.".into();
                        }
                        Ok(jobs::ResultValue::Action(ActionResult::Executed(report))) => {
                            app.accept_execution(*report)
                        }
                        Ok(jobs::ResultValue::Viewer(message)) => {
                            app.screen = Screen::Browse;
                            app.status = message;
                        }
                        Err(error) => {
                            app.fail(error);
                        }
                    }
                }
                term.invalidate();
            }
        }
        if last_draw.elapsed() >= Duration::from_millis(40) || app.dirty {
            let (width, height) = crossterm::terminal::size()?;
            let frame = render::frame(app, width.min(240), height.min(80))?;
            term.draw(&frame, width.min(240), height.min(80))?;
            app.dirty = false;
            last_draw = Instant::now();
        }
        if !event::poll(Duration::from_millis(20))? {
            continue;
        }
        let event = event::read()?;
        match event {
            Event::Resize(_, _) => {
                app.reset_preview_layout();
                term.invalidate();
                app.dirty = true;
            }
            Event::Key(key) if matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) => {
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                    if let Some(active) = job.as_mut() {
                        active.cancel();
                    }
                    return Ok(130);
                }
                let command = app.key(key.code, key.modifiers)?;
                match command {
                    model::Command::None => {}
                    model::Command::Quit => {
                        if let Some(active) = job.as_mut() {
                            active.cancel();
                        }
                        return Ok(if job.is_some() { 130 } else { app.result_code });
                    }
                    model::Command::Refresh => {
                        if let Some(active) = job.as_mut() {
                            active.cancel();
                            app.refresh_pending = true;
                            app.status = "Cancelling the old job before refresh.".into();
                        } else {
                            app.start_scan()?;
                            *job = Some(Job::scan(app.generation, app.root.clone())?);
                        }
                    }
                    model::Command::Prepare => {
                        let selection = app.frozen_selection()?;
                        let exclusions = app.excluded_paths()?;
                        *job = Some(Job::prepare(
                            app.generation,
                            app.root_entry()?,
                            selection,
                            exclusions,
                            state.clone(),
                        )?);
                        app.busy = true;
                        app.status = "Preparing the exact native plan; no effects yet.".into();
                    }
                    model::Command::Confirm => {
                        let plan = app
                            .preview
                            .as_ref()
                            .ok_or_else(|| io::Error::other("preview is missing"))?;
                        job.as_mut()
                            .ok_or_else(|| io::Error::other("preview worker is missing"))?
                            .confirm(app.generation, plan.plan.id())?;
                        app.screen = Screen::Executing;
                        app.status =
                            "Executing the approved plan; Esc cancels subsequent items.".into();
                    }
                    model::Command::Cancel => {
                        if let Some(active) = job.as_mut() {
                            active.cancel();
                            if app.screen == Screen::Preview {
                                app.screen = Screen::Executing;
                            }
                            app.status = "Cancellation requested; waiting for owned work.".into();
                        }
                    }
                    model::Command::View(viewer) => {
                        let (scope, entry) = app.viewer_entries()?;
                        *job = Some(Job::viewer(app.generation, scope, entry, viewer)?);
                        app.busy = true;
                        app.status = match viewer {
                            Viewer::Reveal => "Opening Finder...",
                            Viewer::Preview => "Quick Look active; Esc stops the owned helper.",
                        }
                        .into();
                        app.screen = Screen::Executing;
                    }
                }
                app.dirty = true;
            }
            _ => {}
        }
    }
}
