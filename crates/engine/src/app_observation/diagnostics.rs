// SPDX-License-Identifier: MPL-2.0
//! Bounded diagnostics for application discovery. Never used as ownership proof.
use std::{
    collections::BTreeMap,
    io,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[derive(Default)]
struct Operation {
    count: usize,
    total_us: u128,
    max_us: u128,
    slowest: PathBuf,
}
pub(super) struct Diagnostics {
    start: Instant,
    deadline: Instant,
    entry_limit: usize,
    last_log: Instant,
    details: usize,
    operations: BTreeMap<&'static str, Operation>,
    pub entries: usize,
    pub directories: usize,
    pub apps: usize,
    pub queued_paths: usize,
    pub queued_bytes: usize,
    outcome: &'static str,
}
impl Diagnostics {
    pub fn new(deadline: Instant, entry_limit: usize) -> Self {
        let now = Instant::now();
        Self {
            start: now,
            deadline,
            entry_limit,
            last_log: now,
            details: 0,
            operations: BTreeMap::new(),
            entries: 0,
            directories: 0,
            apps: 0,
            queued_paths: 0,
            queued_bytes: 0,
            outcome: "interrupted",
        }
    }
    pub fn run<T>(
        &mut self,
        operation: &'static str,
        path: &Path,
        action: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<T> {
        if self.last_log.elapsed() >= Duration::from_secs(1) {
            self.log("begin", operation, path, 0);
        }
        let start = Instant::now();
        let result = action();
        let us = start.elapsed().as_micros();
        let record = self.operations.entry(operation).or_default();
        record.count += 1;
        record.total_us += us;
        if us > record.max_us {
            record.max_us = us;
            record.slowest = path.to_owned();
        }
        if us >= 50_000 || result.is_err() {
            self.log("end", operation, path, us);
        }
        result.map_err(|e| {
            self.outcome = "operation_failed";
            io::Error::new(e.kind(), format!("copies_unknown: operation={operation} path={path:?} operation_us={us} elapsed_us={} entries={} directories={} apps={}: {e}",
                self.start.elapsed().as_micros(), self.entries, self.directories, self.apps))
        })
    }
    pub fn budget(
        &mut self,
        path: &Path,
        depth: usize,
        remaining: Option<usize>,
    ) -> io::Result<()> {
        let reason = if Instant::now() >= self.deadline {
            Some("deadline")
        } else if depth > 32 {
            Some("depth_limit")
        } else if self.entries > self.entry_limit {
            Some("entry_limit")
        } else if self.queued_paths > 10_000 {
            Some("queue_limit")
        } else if self.queued_bytes > 32 * 1024 * 1024 {
            Some("queued_path_bytes")
        } else if remaining == Some(0) {
            Some("shared_entry_limit")
        } else {
            None
        };
        if let Some(reason) = reason {
            self.outcome = reason;
            return Err(io::Error::other(format!(
                "copies_unknown: budget={reason} path={path:?} elapsed_us={} remaining_ms={} entries={} directories={} apps={} depth={} entry_limit={} depth_limit=32 shared_entries_remaining={remaining:?} queued_paths={} queued_bytes={}",
                self.start.elapsed().as_micros(),
                self.deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis(),
                self.entries,
                self.directories,
                self.apps,
                depth,
                self.entry_limit,
                self.queued_paths,
                self.queued_bytes
            )));
        }
        Ok(())
    }
    pub fn complete(&mut self) {
        self.outcome = "complete";
    }
    fn log(&mut self, event: &str, operation: &str, path: &Path, operation_us: u128) {
        self.last_log = Instant::now();
        if self.details >= 128 {
            return;
        }
        self.details += 1;
        debug_line(format_args!(
            "event={event} operation={operation} path={path:?} operation_us={operation_us} elapsed_us={} remaining_ms={} entries={} directories={} apps={}",
            self.start.elapsed().as_micros(),
            self.deadline
                .saturating_duration_since(Instant::now())
                .as_millis(),
            self.entries,
            self.directories,
            self.apps
        ));
    }
}
impl Drop for Diagnostics {
    fn drop(&mut self) {
        debug_line(format_args!(
            "event=summary outcome={} elapsed_us={} entries={} directories={} apps={}",
            self.outcome,
            self.start.elapsed().as_micros(),
            self.entries,
            self.directories,
            self.apps
        ));
        for (operation, record) in &self.operations {
            debug_line(format_args!(
                "event=operation_summary operation={operation} count={} total_us={} max_us={} slowest_path={:?}",
                record.count, record.total_us, record.max_us, record.slowest
            ));
        }
    }
}
pub(super) fn debug_line(args: std::fmt::Arguments<'_>) {
    #[cfg(debug_assertions)]
    {
        use std::io::Write;
        let _ = writeln!(io::stderr().lock(), "[SayakaInventory] {args}");
    }
    #[cfg(not(debug_assertions))]
    let _ = args;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn distinguishes_budget_causes_and_includes_the_failing_path() {
        let path = Path::new("/fixture/SDK/header.h");
        let mut d = Diagnostics::new(Instant::now(), 100);
        assert!(
            d.budget(path, 0, None)
                .unwrap_err()
                .to_string()
                .contains("budget=deadline")
        );
        d.deadline = Instant::now() + Duration::from_secs(30);
        d.entries = 101;
        let text = d.budget(path, 0, Some(100)).unwrap_err().to_string();
        assert!(text.contains("budget=entry_limit") && text.contains("/fixture/SDK/header.h"));
        d.entries = 0;
        assert!(
            d.budget(path, 0, Some(0))
                .unwrap_err()
                .to_string()
                .contains("budget=shared_entry_limit")
        );
        assert!(
            d.budget(path, 33, None)
                .unwrap_err()
                .to_string()
                .contains("budget=depth_limit")
        );
        d.queued_bytes = 32 * 1024 * 1024 + 1;
        assert!(
            d.budget(path, 0, None)
                .unwrap_err()
                .to_string()
                .contains("budget=queued_path_bytes")
        );
    }
}
