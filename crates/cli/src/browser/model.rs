// SPDX-License-Identifier: MPL-2.0

use super::jobs::{PlanDisplay, Viewer};
use crossterm::event::{KeyCode, KeyModifiers};
use sayaka_engine::execute::ExecutionReport;
use sayaka_engine::journal;
use sayaka_engine::model::{Cancellation, ResourceKind};
use sayaka_engine::scan::{self, ScanEntry, ScanReport, index::ScanTree};
use std::collections::{BTreeSet, HashMap};
use std::io;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sort {
    Size,
    Name,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Metric {
    Logical,
    Allocated,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Screen {
    Browse,
    Selected,
    Menu,
    Help,
    Preview,
    ExternalPrompt,
    Executing,
    Notice,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    None,
    Quit,
    Refresh,
    Prepare,
    Confirm,
    Cancel,
    View(Viewer),
}

pub struct BrowserData {
    pub tree: ScanTree,
    pub index_elapsed_ms: u64,
    orders: HashMap<u64, [Vec<u64>; 3]>,
}

impl BrowserData {
    pub fn build(report: ScanReport, cancellation: &Cancellation) -> io::Result<Self> {
        let started = std::time::Instant::now();
        let tree = ScanTree::build(report, cancellation).map_err(super::scan_error)?;
        let mut result = Self {
            tree,
            orders: HashMap::new(),
            index_elapsed_ms: 0,
        };
        for entry in &result.tree.report().entries {
            if cancellation.is_cancelled() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "browser indexing cancelled",
                ));
            }
            if entry.kind != ResourceKind::Directory {
                continue;
            }
            let children = result
                .tree
                .children(entry.id)
                .ok_or_else(|| io::Error::other("directory has no index"))?;
            let mut order = [children.to_vec(), children.to_vec(), children.to_vec()];
            for (index, metric) in [(1, Metric::Logical), (2, Metric::Allocated)] {
                order[index].sort_by(|a, b| {
                    result
                        .size(*b, metric)
                        .cmp(&result.size(*a, metric))
                        .then_with(|| {
                            result
                                .tree
                                .entry(*a)
                                .map(|entry| &entry.path)
                                .cmp(&result.tree.entry(*b).map(|entry| &entry.path))
                        })
                });
            }
            order[0].sort_by(|a, b| {
                result
                    .tree
                    .entry(*a)
                    .map(|entry| &entry.path)
                    .cmp(&result.tree.entry(*b).map(|entry| &entry.path))
            });
            result.orders.insert(entry.id, order);
        }
        result.index_elapsed_ms =
            u64::try_from(started.elapsed().as_millis()).map_err(io::Error::other)?;
        Ok(result)
    }
    pub fn entry(&self, id: u64) -> io::Result<&ScanEntry> {
        self.tree
            .entry(id)
            .ok_or_else(|| io::Error::other("unknown browser resource"))
    }
    pub fn children(&self, id: u64, sort: Sort, metric: Metric) -> &[u64] {
        let index = match (sort, metric) {
            (Sort::Name, _) => 0,
            (_, Metric::Logical) => 1,
            (_, Metric::Allocated) => 2,
        };
        self.orders
            .get(&id)
            .map(|order| order[index].as_slice())
            .unwrap_or(&[])
    }
    pub fn size(&self, id: u64, metric: Metric) -> Option<u64> {
        let entry = self.tree.entry(id)?;
        if entry.kind == ResourceKind::Directory {
            let summary = self.tree.summary(id)?;
            let (bytes, unknown) = match metric {
                Metric::Logical => (
                    summary.logical_bytes_known,
                    summary.logical_bytes_unknown_files,
                ),
                Metric::Allocated => (
                    summary.allocated_bytes_known,
                    summary.allocated_bytes_unknown_files,
                ),
            };
            if (bytes == 0 && unknown > 0) || (!summary.complete && summary.unique_files == 0) {
                None
            } else {
                Some(bytes)
            }
        } else if entry.kind == ResourceKind::File {
            match metric {
                Metric::Logical => entry.logical_bytes,
                Metric::Allocated => entry.allocated_bytes,
            }
        } else {
            None
        }
    }
    pub fn measure(&self, id: u64, metric: Metric) -> String {
        if self.tree.entry(id).is_some_and(|entry| {
            !matches!(entry.kind, ResourceKind::File | ResourceKind::Directory)
        }) {
            return "--".into();
        }
        let Some(size) = self.size(id, metric) else {
            return "unknown".into();
        };
        let mut text = crate::human::size(size);
        if let Some(summary) = self.tree.summary(id) {
            let unknown = match metric {
                Metric::Logical => summary.logical_bytes_unknown_files,
                Metric::Allocated => summary.allocated_bytes_unknown_files,
            };
            if unknown > 0 {
                text.push_str("+?");
            }
            if !summary.complete {
                text.push('*');
            }
        }
        text
    }
}

pub struct Preview {
    pub plan: sayaka_engine::model::Plan,
    pub lines: Vec<String>,
    pub wrapped: Vec<String>,
    pub width: u16,
    pub scroll: usize,
    pub seen_through: usize,
    pub input: String,
}

pub struct App {
    pub root: PathBuf,
    pub generation: u64,
    pub data: Option<BrowserData>,
    pub directory: Option<u64>,
    pub rows: Vec<u64>,
    pub cursor: usize,
    pub offset: usize,
    pub selected: BTreeSet<u64>,
    pub excluded: BTreeSet<u64>,
    pub screen: Screen,
    pub sort: Sort,
    pub metric: Metric,
    pub filter: String,
    pub filtering: bool,
    pub status: String,
    pub busy: bool,
    pub dirty: bool,
    pub stale: bool,
    pub refresh_pending: bool,
    pub preview: Option<Preview>,
    pub notice: Vec<String>,
    pub notice_scroll: usize,
    pub menu_cursor: usize,
    pub viewport: usize,
    pub review_allowed: bool,
    pub external_allowed: bool,
    pub result_code: u8,
    pub action_code: Option<u8>,
    pub exit: Option<u8>,
}

impl App {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            generation: 1,
            data: None,
            directory: None,
            rows: Vec::new(),
            cursor: 0,
            offset: 0,
            selected: BTreeSet::new(),
            excluded: BTreeSet::new(),
            screen: Screen::Browse,
            sort: Sort::Size,
            metric: Metric::Logical,
            filter: String::new(),
            filtering: false,
            status: "Scanning selected scope; no file contents are read.".into(),
            busy: true,
            dirty: true,
            stale: false,
            refresh_pending: false,
            preview: None,
            notice: Vec::new(),
            notice_scroll: 0,
            menu_cursor: 0,
            viewport: 10,
            review_allowed: false,
            external_allowed: false,
            result_code: 0,
            action_code: None,
            exit: None,
        }
    }
    pub fn start_scan(&mut self) -> io::Result<()> {
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| io::Error::other("browser generation exhausted"))?;
        self.selected.clear();
        self.excluded.clear();
        self.preview = None;
        self.data = None;
        self.rows.clear();
        self.directory = None;
        self.cursor = 0;
        self.offset = 0;
        self.filter.clear();
        self.filtering = false;
        self.screen = Screen::Browse;
        self.busy = true;
        self.stale = false;
        self.dirty = true;
        self.status = "Scanning a fresh generation; selections cleared.".into();
        Ok(())
    }
    pub fn accept_scan(&mut self, generation: u64, data: BrowserData) -> io::Result<()> {
        if generation != self.generation {
            return Ok(());
        }
        self.result_code = self
            .action_code
            .unwrap_or(data.tree.report().status.exit_code());
        self.directory = data.tree.roots().first().copied();
        self.status = format!(
            "{} snapshot: {} entries; r refresh, i scan issues. Not live data.",
            data.tree.report().status.as_str(),
            data.tree.report().entries.len()
        );
        self.data = Some(data);
        self.busy = false;
        self.dirty = true;
        self.rebuild_rows()
    }
    pub fn accept_plan(&mut self, generation: u64, display: PlanDisplay) {
        if generation != self.generation {
            return;
        }
        let mut lines = vec![
            format!("Scope: {}", scan::display_path(display.plan.scope())),
            format!(
                "{} eligible files; {} exclusions/refusals.",
                display.plan.items().len(),
                display.plan.rejected().len()
            ),
            display.plan.execution_contract().warning().into(),
            "Only these exact eligible files may be moved; no directory deletion.".into(),
            "No automatic retry or guaranteed recovery. This plan expires after 120 seconds."
                .into(),
        ];
        for item in display.plan.items() {
            lines.push(format!(
                "MOVE {} ({} logical bytes)",
                item.observation().display_path(),
                item.observation()
                    .snapshot()
                    .logical_bytes
                    .map(|bytes| bytes.to_string())
                    .unwrap_or_else(|| "unknown".into())
            ));
        }
        for refusal in display.refusals {
            lines.push(format!("SKIP {}: {}", refusal.path.display, refusal.reason));
        }
        for issue in display.issues {
            lines.push(format!(
                "DETAIL {}: {:?}",
                issue.path.display, issue.message
            ));
        }
        self.preview = Some(Preview {
            plan: display.plan,
            lines,
            wrapped: Vec::new(),
            width: 0,
            scroll: 0,
            seen_through: 0,
            input: String::new(),
        });
        self.screen = Screen::Preview;
        self.dirty = true;
        self.status = "Review every line, then type the exact confirmation. Esc cancels.".into();
    }
    pub fn accept_execution(&mut self, report: ExecutionReport) {
        let code = report.exit_code();
        if code != 0 {
            self.action_code = Some(if self.action_code == Some(1) { 1 } else { code });
        }
        self.result_code = self.action_code.unwrap_or(code);
        self.notice = vec![format!("Operation {}", report.record.operation_id)];
        for item in report.record.items {
            self.notice.push(format!(
                "{:?} {}: {:?}",
                item.state, item.path.display, item.reason
            ));
            if let Some(path) = item.destination {
                self.notice.push(format!(
                    "Recorded destination, not a restore guarantee: {}",
                    path.display
                ));
            }
            if let Some(evidence) = item.recovery_evidence {
                if let Some(path) = evidence.returned_destination {
                    self.notice
                        .push(format!("UNVERIFIED OS destination: {}", path.display));
                }
                if let Some(path) = evidence.held_source_path {
                    self.notice
                        .push(format!("Held-object path observation: {}", path.display));
                }
                for error in evidence.observation_errors {
                    self.notice
                        .push(format!("Observation unavailable: {error:?}"));
                }
            }
        }
        if let Some(error) = report.journal_error {
            self.notice
                .push(format!("Journal failure; no subsequent action: {error:?}"));
        }
        self.notice.push(
            "No automatic retry or restoration. Use receipt to inspect durable evidence.".into(),
        );
        self.notice
            .push("This browser snapshot is now stale. Press r after closing this report.".into());
        self.screen = Screen::Notice;
        self.notice_scroll = 0;
        self.stale = true;
        self.selected.clear();
        self.preview = None;
        self.status = "Operation finished. Snapshot stale; refresh explicitly.".into();
    }
    pub fn fail(&mut self, error: io::Error) {
        if self.screen == Screen::Executing && self.preview.is_some() {
            self.action_code = Some(1);
        }
        self.stale = self.data.is_some();
        self.notice = vec![
            format!("Browser operation failed: {:?}", error.to_string()),
            "No success is assumed. Existing operation records can be inspected with receipt."
                .into(),
        ];
        self.notice_scroll = 0;
        self.screen = Screen::Notice;
        self.preview = None;
        self.result_code = if error.kind() == io::ErrorKind::InvalidInput {
            2
        } else {
            1
        };
        self.status = "Operation failed; Esc returns to browser.".into();
        self.dirty = true;
    }
    pub fn reset_preview_layout(&mut self) {
        if let Some(preview) = &mut self.preview {
            preview.width = 0;
            preview.scroll = 0;
            preview.seen_through = 0;
            preview.input.clear();
        }
    }
    pub fn rebuild_rows(&mut self) -> io::Result<()> {
        let old = self.rows.get(self.cursor).copied();
        self.rows.clear();
        let Some(data) = &self.data else {
            return Ok(());
        };
        if self.screen == Screen::Selected {
            self.rows.extend(self.selected.iter().copied());
            self.rows.sort_by(|a, b| {
                let name = data
                    .tree
                    .entry(*a)
                    .map(|entry| &entry.path)
                    .cmp(&data.tree.entry(*b).map(|entry| &entry.path));
                if self.sort == Sort::Name {
                    name
                } else {
                    data.size(*b, self.metric)
                        .cmp(&data.size(*a, self.metric))
                        .then(name)
                }
            });
        } else if let Some(directory) = self.directory {
            self.rows
                .extend_from_slice(data.children(directory, self.sort, self.metric));
        }
        if !self.filter.is_empty() {
            let query = self.filter.to_lowercase();
            self.rows.retain(|id| {
                data.tree.entry(*id).is_some_and(|entry| {
                    format!(
                        "{:?}",
                        entry.path.file_name().unwrap_or(entry.path.as_os_str())
                    )
                    .to_lowercase()
                    .contains(&query)
                })
            });
        }
        self.cursor = old
            .and_then(|id| self.rows.iter().position(|row| *row == id))
            .unwrap_or(0);
        self.offset = self.offset.min(self.cursor);
        Ok(())
    }
    pub fn frozen_selection(&self) -> io::Result<Vec<ScanEntry>> {
        let data = self
            .data
            .as_ref()
            .ok_or_else(|| io::Error::other("no scan snapshot"))?;
        self.selected
            .iter()
            .map(|id| data.entry(*id).cloned())
            .collect()
    }
    pub fn excluded_paths(&self) -> io::Result<Vec<PathBuf>> {
        let data = self
            .data
            .as_ref()
            .ok_or_else(|| io::Error::other("no scan snapshot"))?;
        self.excluded
            .iter()
            .map(|id| data.entry(*id).map(|entry| entry.path.clone()))
            .collect()
    }
    pub fn root_entry(&self) -> io::Result<ScanEntry> {
        let data = self
            .data
            .as_ref()
            .ok_or_else(|| io::Error::other("no scan snapshot"))?;
        let id = data
            .tree
            .roots()
            .first()
            .ok_or_else(|| io::Error::other("scope is unavailable"))?;
        data.entry(*id).cloned()
    }
    pub fn viewer_entries(&self) -> io::Result<(ScanEntry, ScanEntry)> {
        let id = self
            .rows
            .get(self.cursor)
            .ok_or_else(|| io::Error::other("no entry selected for viewing"))?;
        Ok((
            self.root_entry()?,
            self.data
                .as_ref()
                .ok_or_else(|| io::Error::other("no scan snapshot"))?
                .entry(*id)?
                .clone(),
        ))
    }
    pub fn is_excluded(&self, id: u64) -> bool {
        let Some(data) = &self.data else {
            return false;
        };
        let Some(entry) = data.tree.entry(id) else {
            return false;
        };
        self.excluded.iter().any(|excluded| {
            data.tree
                .entry(*excluded)
                .is_some_and(|excluded| entry.path.starts_with(&excluded.path))
        })
    }

    pub fn key(&mut self, key: KeyCode, modifiers: KeyModifiers) -> io::Result<Command> {
        if self.screen == Screen::Preview {
            let Some(preview) = &mut self.preview else {
                return Err(io::Error::other("missing preview state"));
            };
            match key {
                KeyCode::Esc | KeyCode::Char('q') => return Ok(Command::Cancel),
                KeyCode::Down | KeyCode::PageDown => {
                    preview.scroll = (preview.scroll
                        + if key == KeyCode::Down {
                            1
                        } else {
                            self.viewport
                        })
                    .min(preview.wrapped.len().saturating_sub(1))
                }
                KeyCode::Up | KeyCode::PageUp => {
                    preview.scroll = preview.scroll.saturating_sub(if key == KeyCode::Up {
                        1
                    } else {
                        self.viewport
                    })
                }
                KeyCode::Home => preview.scroll = 0,
                KeyCode::End => {
                    preview.scroll = preview.wrapped.len().saturating_sub(self.viewport)
                }
                KeyCode::Backspace => {
                    preview.input.pop();
                }
                KeyCode::Enter => {
                    if self.review_allowed
                        && !preview.plan.items().is_empty()
                        && preview.seen_through == preview.wrapped.len()
                        && preview.input == format!("trash {}", preview.plan.items().len())
                    {
                        return Ok(Command::Confirm);
                    }
                    self.status =
                        "Review all plan lines and type exactly trash N. Nothing authorized."
                            .into();
                }
                KeyCode::Char(ch)
                    if !modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
                        && !ch.is_control()
                        && preview.input.len() < 48 =>
                {
                    if self.review_allowed && preview.seen_through == preview.wrapped.len() {
                        preview.input.push(ch);
                    } else {
                        self.status = "Use Page Down to review the full plan before typing.".into();
                    }
                }
                _ => {}
            }
            return Ok(Command::None);
        }
        if self.screen == Screen::Executing {
            return Ok(match key {
                KeyCode::Esc => Command::Cancel,
                KeyCode::Char('q') => Command::Quit,
                _ => Command::None,
            });
        }
        if self.screen == Screen::ExternalPrompt {
            return Ok(match key {
                KeyCode::Enter if self.external_allowed => Command::View(Viewer::Preview),
                KeyCode::Enter => {
                    self.status =
                        "Resize to read the complete external-viewer acknowledgement.".into();
                    Command::None
                }
                KeyCode::Esc | KeyCode::Char('q') => {
                    self.screen = Screen::Browse;
                    Command::None
                }
                _ => Command::None,
            });
        }
        if matches!(self.screen, Screen::Help | Screen::Notice) {
            match key {
                KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('b') => {
                    self.screen = Screen::Browse;
                    self.rebuild_rows()?;
                }
                KeyCode::Char('q') => return Ok(Command::Quit),
                KeyCode::Down | KeyCode::PageDown => {
                    self.notice_scroll =
                        self.notice_scroll.saturating_add(if key == KeyCode::Down {
                            1
                        } else {
                            self.viewport
                        })
                }
                KeyCode::Up | KeyCode::PageUp => {
                    self.notice_scroll = self.notice_scroll.saturating_sub(if key == KeyCode::Up {
                        1
                    } else {
                        self.viewport
                    })
                }
                KeyCode::Home => self.notice_scroll = 0,
                _ => {}
            }
            return Ok(Command::None);
        }
        if self.screen == Screen::Menu {
            match key {
                KeyCode::Down | KeyCode::Char('j') => {
                    self.menu_cursor = (self.menu_cursor + 1).min(4)
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.menu_cursor = self.menu_cursor.saturating_sub(1)
                }
                KeyCode::Esc | KeyCode::Char('m') => self.screen = Screen::Browse,
                KeyCode::Char('q') => return Ok(Command::Quit),
                KeyCode::Enter => match self.menu_cursor {
                    0 => {
                        self.screen = Screen::Browse;
                        self.rebuild_rows()?;
                    }
                    1 => {
                        self.screen = Screen::Selected;
                        self.rebuild_rows()?;
                    }
                    2 if !self.busy => return Ok(Command::Refresh),
                    3 => {
                        self.screen = Screen::Help;
                        self.notice_scroll = 0;
                    }
                    4 => return Ok(Command::Quit),
                    _ => self.status = "Cancel the active job first.".into(),
                },
                _ => {}
            }
            return Ok(Command::None);
        }
        if self.filtering {
            match key {
                KeyCode::Esc => {
                    self.filter.clear();
                    self.filtering = false;
                }
                KeyCode::Enter => self.filtering = false,
                KeyCode::Backspace => {
                    self.filter.pop();
                }
                KeyCode::Char('u') if modifiers.contains(KeyModifiers::CONTROL) => {
                    self.filter.clear()
                }
                KeyCode::Char(ch)
                    if !ch.is_control()
                        && !modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    if self.filter.len() + ch.len_utf8() <= 256 {
                        self.filter.push(ch);
                    } else {
                        self.status = "Filter byte limit reached.".into();
                    }
                }
                _ => {}
            }
            self.rebuild_rows()?;
            return Ok(Command::None);
        }
        match key {
            KeyCode::Char('q') => return Ok(Command::Quit),
            KeyCode::Esc if self.busy => return Ok(Command::Cancel),
            KeyCode::Char('?') => {
                self.screen = Screen::Help;
                self.notice_scroll = 0;
            }
            KeyCode::Char('m') => self.screen = Screen::Menu,
            KeyCode::Char('i') => {
                self.notice = self
                    .data
                    .as_ref()
                    .map(|data| {
                        data.tree
                            .report()
                            .issues
                            .iter()
                            .map(|issue| {
                                format!(
                                    "{} {:?}: {:?}",
                                    issue.code.as_str(),
                                    issue.path,
                                    issue.message
                                )
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                if self.notice.is_empty() {
                    self.notice.push("No retained scan issues. Unknown measurements remain separate from coverage.".into());
                }
                self.notice_scroll = 0;
                self.screen = Screen::Notice;
            }
            KeyCode::Char('r') if !self.busy || self.data.is_none() => return Ok(Command::Refresh),
            KeyCode::Char('v') => {
                self.screen = if self.screen == Screen::Selected {
                    Screen::Browse
                } else {
                    Screen::Selected
                };
                self.rebuild_rows()?;
            }
            KeyCode::Char('/') => self.filtering = true,
            KeyCode::Char('s') => {
                self.sort = if self.sort == Sort::Size {
                    Sort::Name
                } else {
                    Sort::Size
                };
                self.rebuild_rows()?;
            }
            KeyCode::Char('a') => {
                self.metric = if self.metric == Metric::Logical {
                    Metric::Allocated
                } else {
                    Metric::Logical
                };
                self.rebuild_rows()?;
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.cursor = (self.cursor + 1).min(self.rows.len().saturating_sub(1))
            }
            KeyCode::Up | KeyCode::Char('k') => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::PageDown => {
                self.cursor = (self.cursor + self.viewport).min(self.rows.len().saturating_sub(1))
            }
            KeyCode::PageUp => self.cursor = self.cursor.saturating_sub(self.viewport),
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = self.rows.len().saturating_sub(1),
            KeyCode::Enter | KeyCode::Right => {
                if let Some(id) = self.rows.get(self.cursor).copied()
                    && self.data.as_ref().is_some_and(|data| {
                        data.tree
                            .entry(id)
                            .is_some_and(|entry| entry.kind == ResourceKind::Directory)
                    })
                {
                    self.directory = Some(id);
                    self.screen = Screen::Browse;
                    self.filter.clear();
                    self.cursor = 0;
                    self.offset = 0;
                    self.rebuild_rows()?;
                }
            }
            KeyCode::Left | KeyCode::Backspace => {
                if let (Some(data), Some(id)) = (&self.data, self.directory)
                    && let Some(parent) = data.tree.parent(id)
                {
                    self.directory = Some(parent);
                    self.screen = Screen::Browse;
                    self.filter.clear();
                    self.cursor = 0;
                    self.offset = 0;
                    self.rebuild_rows()?;
                    if let Some(index) = self.rows.iter().position(|row| *row == id) {
                        self.cursor = index;
                    }
                }
            }
            KeyCode::Char(' ') | KeyCode::Char('x') if !self.busy && !self.stale => {
                if let Some(id) = self.rows.get(self.cursor).copied() {
                    let entry = self
                        .data
                        .as_ref()
                        .ok_or_else(|| io::Error::other("missing scan"))?
                        .entry(id)?;
                    if key == KeyCode::Char(' ') {
                        if entry.kind != ResourceKind::File || entry.dataless {
                            self.status = "Only observed ordinary non-placeholder files can be selected; directories stay read-only.".into();
                        } else if !self.selected.remove(&id) {
                            if self.selected.len() >= journal::MAX_ITEMS {
                                self.status = "Selection limit: 32 files per native plan.".into();
                            } else {
                                self.selected.insert(id);
                            }
                        }
                    } else if !matches!(entry.kind, ResourceKind::Directory | ResourceKind::File)
                        || entry.dataless
                    {
                        self.status =
                            "Links and placeholders are already outside action selection.".into();
                    } else if !self.excluded.remove(&id) {
                        if self.excluded.len() >= journal::MAX_ITEMS {
                            self.status = "Exclusion limit: 32 entries per native plan.".into();
                        } else {
                            self.excluded.insert(id);
                        }
                    }
                    if self.screen == Screen::Selected {
                        self.rebuild_rows()?;
                    }
                }
            }
            KeyCode::Char('t') if !self.busy && !self.stale && !self.selected.is_empty() => {
                return Ok(Command::Prepare);
            }
            KeyCode::Char('o') | KeyCode::Char('p')
                if !self.busy && !self.stale && !self.rows.is_empty() =>
            {
                let (_, entry) = self.viewer_entries()?;
                if entry.dataless
                    || !matches!(entry.kind, ResourceKind::File | ResourceKind::Directory)
                {
                    self.status = "This entry cannot be sent to a viewer.".into();
                } else if key == KeyCode::Char('o') {
                    return Ok(Command::View(Viewer::Reveal));
                } else if entry.kind == ResourceKind::File {
                    self.screen = Screen::ExternalPrompt;
                } else {
                    self.status =
                        "Enter browses directories; Quick Look is limited to explicit files."
                            .into();
                }
            }
            KeyCode::Char('t' | ' ' | 'x' | 'o' | 'p') => {
                self.status = if self.stale {
                    "Snapshot is stale; refresh before selecting or acting.".into()
                } else if self.busy {
                    "Cancel the current job before changing or acting on selection.".into()
                } else {
                    "Select an ordinary file with Space before preparing a plan.".into()
                }
            }
            _ => {}
        }
        Ok(Command::None)
    }
}

pub fn kind(kind: ResourceKind) -> &'static str {
    match kind {
        ResourceKind::Directory => "DIR",
        ResourceKind::File => "FILE",
        ResourceKind::Link => "LINK",
        ResourceKind::Other => "OTHER",
    }
}
