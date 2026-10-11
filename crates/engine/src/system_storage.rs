// SPDX-License-Identifier: MPL-2.0
//! Read-only observations. No values in this module authorize cleanup.
use serde::Serialize;
use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize)]
pub struct Observation<T> {
    pub source: &'static str,
    pub observed_unix_ms: u64,
    pub complete: bool,
    pub value: Option<T>,
    pub issues: Vec<&'static str>,
}
impl<T> Observation<T> {
    pub fn known(source: &'static str, value: T) -> Self {
        Self {
            source,
            observed_unix_ms: now(),
            complete: true,
            value: Some(value),
            issues: vec![],
        }
    }
    pub fn unknown(source: &'static str, reason: &'static str) -> Self {
        Self {
            source,
            observed_unix_ms: now(),
            complete: false,
            value: None,
            issues: vec![reason],
        }
    }
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}
const SNAP: &str = "/usr/bin/tmutil listlocalsnapshots /";
const STATUS: &str = "/usr/bin/tmutil status";
const DEST: &str = "/usr/bin/tmutil destinationinfo";
const CAP: &str = "URLResourceValues /System/Volumes/Data: volumeAvailableCapacityForImportantUsage - volumeAvailableCapacity";

#[derive(Debug, Serialize)]
pub struct Snapshots {
    pub names: Vec<String>,
    pub count: Option<usize>,
}
#[derive(Debug, Serialize)]
pub struct Capacity {
    pub volume: &'static str,
    pub available_bytes: u64,
    pub important_usage_bytes: u64,
    pub estimate_bytes: u64,
}
#[derive(Debug, Serialize)]
pub struct Overview {
    pub schema_version: u32,
    pub kind: &'static str,
    pub effects_performed: bool,
    pub snapshots: Observation<Snapshots>,
    pub backup_running: Observation<bool>,
    pub backup_configured: Observation<bool>,
    pub last_successful_backup: Observation<String>,
    pub reclaimable: Observation<Capacity>,
}
fn lines(bytes: &[u8]) -> Result<Vec<&str>, &'static str> {
    if bytes.len() > 256 * 1024 {
        return Err("output_limit");
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "invalid_utf8")?;
    let rows: Vec<_> = text.lines().collect();
    if rows.len() > 4096 || rows.iter().any(|s| s.len() > 4096) {
        return Err("line_limit");
    }
    Ok(rows)
}
fn valid_snapshot(s: &str) -> bool {
    let Some(s) = s
        .strip_prefix("com.apple.TimeMachine.")
        .and_then(|s| s.strip_suffix(".local"))
    else {
        return false;
    };
    let b = s.as_bytes();
    if b.len() != 17
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'-'
        || b.iter()
            .enumerate()
            .any(|(i, c)| ![4, 7, 10].contains(&i) && !c.is_ascii_digit())
    {
        return false;
    }
    let n = |a, b| s[a..b].parse::<u32>().unwrap_or(9999);
    let y = n(0, 4);
    let m = n(5, 7);
    let d = n(8, 10);
    let days = match m {
        4 | 6 | 9 | 11 => 30,
        2 if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) => 29,
        2 => 28,
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        _ => 0,
    };
    y > 0 && d > 0 && d <= days && n(11, 13) < 24 && n(13, 15) < 60 && n(15, 17) < 60
}
pub fn parse_snapshots(bytes: &[u8]) -> Observation<Snapshots> {
    let rows = match lines(bytes) {
        Ok(v) => v,
        Err(e) => return Observation::unknown(SNAP, e),
    };
    let mut rows = rows.into_iter().filter(|s| !s.trim().is_empty());
    if rows.next() != Some("Snapshots for disk /:") {
        return Observation::unknown(SNAP, "snapshot_header");
    }
    let mut names = BTreeSet::new();
    let mut invalid = false;
    for row in rows {
        if !valid_snapshot(row) || names.len() >= 1024 || !names.insert(row.to_owned()) {
            invalid = true;
        }
    }
    let mut o = Observation::known(
        SNAP,
        Snapshots {
            count: (!invalid).then_some(names.len()),
            names: names.into_iter().collect(),
        },
    );
    if invalid {
        o.complete = false;
        o.issues.push("unrecognized_duplicate_or_excess_snapshot");
    }
    o
}
pub fn parse_status(bytes: &[u8]) -> Observation<bool> {
    let rows = match lines(bytes) {
        Ok(v) => v,
        Err(e) => return Observation::unknown(STATUS, e),
    };
    let rows: Vec<_> = rows
        .into_iter()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if rows.len() < 4
        || rows[0] != "Backup session status:"
        || rows[1] != "{"
        || rows.last() != Some(&"}")
    {
        return Observation::unknown(STATUS, "status_format");
    }
    let mut running = None;
    let mut keys = BTreeSet::new();
    let mut extra = false;
    // Accept only the evidenced flat OpenStep dictionary subset. Nested active
    // progress structures remain unknown until native evidence supports them.
    for row in &rows[2..rows.len() - 1] {
        let Some((key, value)) = row.strip_suffix(';').and_then(|s| s.split_once('=')) else {
            return Observation::unknown(STATUS, "status_format");
        };
        let key = key.trim();
        let value = value.trim();
        if key.is_empty()
            || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || !keys.insert(key)
        {
            return Observation::unknown(STATUS, "status_duplicate_or_key");
        }
        if key == "Running" {
            running = match value {
                "0" => Some(false),
                "1" => Some(true),
                _ => return Observation::unknown(STATUS, "status_running"),
            };
        } else if key == "ClientID" && value == "\"com.apple.backupd\"" {
        } else {
            if value.is_empty() || value.contains(['{', '}', ';', '=']) {
                return Observation::unknown(STATUS, "status_format");
            }
            extra = true;
        }
    }
    let Some(running) = running else {
        return Observation::unknown(STATUS, "status_running_missing");
    };
    let mut o = Observation::known(STATUS, running);
    if extra {
        o.complete = false;
        o.issues.push("unrecognized_status_fields");
    }
    o
}
pub fn parse_destinations(bytes: &[u8]) -> Observation<bool> {
    if let Err(e) = lines(bytes) {
        return Observation::unknown(DEST, e);
    }
    if std::str::from_utf8(bytes).unwrap_or("").trim() == "tmutil: No destinations configured." {
        Observation::known(DEST, false)
    } else {
        Observation::unknown(DEST, "destination_format_not_evidenced")
    }
}
fn unavailable(reason: &'static str) -> Overview {
    Overview {
        schema_version: 1,
        kind: "sayaka.system_storage_overview",
        effects_performed: false,
        snapshots: Observation::unknown(SNAP, reason),
        backup_running: Observation::unknown(STATUS, reason),
        backup_configured: Observation::unknown(DEST, reason),
        last_successful_backup: Observation::unknown(
            "accepted tmutil status/destinationinfo fields",
            "not_observed",
        ),
        reclaimable: Observation::unknown(CAP, reason),
    }
}
#[cfg(target_os = "macos")]
fn collect() -> Overview {
    use sayaka_platform_macos::system_storage::{Query, capacity, query};
    let mut o = unavailable("not_observed");
    o.snapshots = match query(Query::Snapshots) {
        Ok(b) => parse_snapshots(&b),
        Err(e) => Observation::unknown(SNAP, e),
    };
    o.backup_running = match query(Query::Status) {
        Ok(b) => parse_status(&b),
        Err(e) => Observation::unknown(STATUS, e),
    };
    o.backup_configured = match query(Query::Destinations) {
        Ok(b) => parse_destinations(&b),
        Err(e) => Observation::unknown(DEST, e),
    };
    o.reclaimable = match capacity() {
        Ok((free, important)) => match important.checked_sub(free) {
            Some(estimate) => Observation::known(
                CAP,
                Capacity {
                    volume: "/System/Volumes/Data",
                    available_bytes: free,
                    important_usage_bytes: important,
                    estimate_bytes: estimate,
                },
            ),
            None => Observation::unknown(CAP, "capacity_inconsistent"),
        },
        Err(e) => Observation::unknown(CAP, e),
    };
    o
}
/// A single in-flight native worker, including after a caller timeout.
/// OS calls can outlive the deadline; a later call never overlaps that worker.
pub fn overview() -> Overview {
    #[cfg(not(target_os = "macos"))]
    {
        unavailable("unsupported_platform")
    }
    #[cfg(target_os = "macos")]
    {
        use std::sync::atomic::{AtomicBool, Ordering};
        static BUSY: AtomicBool = AtomicBool::new(false);
        if BUSY
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return unavailable("observation_busy");
        }
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("system-storage".into())
            .spawn(move || {
                struct Guard;
                impl Drop for Guard {
                    fn drop(&mut self) {
                        BUSY.store(false, Ordering::Release);
                    }
                }
                let _guard = Guard;
                let value = collect();
                let _ = tx.send(value);
            });
        if worker.is_err() {
            BUSY.store(false, Ordering::Release);
            return unavailable("worker_unavailable");
        }
        rx.recv_timeout(std::time::Duration::from_secs(20))
            .unwrap_or_else(|_| unavailable("observation_timeout"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn snapshot_dates_and_unknowns() {
        assert_eq!(
            parse_snapshots(b"Snapshots for disk /:\n")
                .value
                .unwrap()
                .count,
            Some(0)
        );
        assert!(valid_snapshot(
            "com.apple.TimeMachine.2024-02-29-235959.local"
        ));
        assert!(!valid_snapshot(
            "com.apple.TimeMachine.2025-02-29-235959.local"
        ));
        let o = parse_snapshots(b"Snapshots for disk /:\ncom.apple.os.update-1\n");
        assert!(!o.complete);
        assert_eq!(o.value.unwrap().count, None);
        assert!(parse_snapshots(b"\xff").value.is_none());
    }
    #[test]
    fn backup_fail_closed() {
        assert_eq!(
            parse_status(b"Backup session status:\n{\nRunning = 0;\n}\n").value,
            Some(false)
        );
        assert_eq!(
            parse_status(b"Backup session status:\n{\nRunning = 1;\n}\n").value,
            Some(true)
        );
        assert!(
            parse_status(b"Backup session status:\n{\nRunning = 0;\nRunning = 1;\n}\n")
                .value
                .is_none()
        );
        assert_eq!(
            parse_destinations(b"tmutil: No destinations configured.\n").value,
            Some(false)
        );
        assert!(parse_destinations(b"unexpected").value.is_none());
    }
}
