// SPDX-License-Identifier: MPL-2.0

use sayaka_engine::model::{FileIdentity, ResourceKind};
use sayaka_engine::scan::{
    ScanEntry, ScanError, ScanIssue, ScanMetrics, ScanProgress, ScanReport, ScanTaskId, ScanTotals,
    display_path,
};
use serde::ser::{SerializeSeq, SerializeStruct};
use serde::{Serialize, Serializer};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

struct NativePath<'a>(&'a Path);

impl Serialize for NativePath<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
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

struct Roots<'a>(&'a [PathBuf]);

impl Serialize for Roots<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for path in self.0 {
            sequence.serialize_element(&NativePath(path))?;
        }
        sequence.end()
    }
}

#[derive(Serialize)]
#[serde(tag = "variant", rename_all = "snake_case")]
enum Identity {
    Unix {
        device: u64,
        inode: u64,
    },
    Windows {
        volume_serial: u64,
        file_id: [u8; 16],
    },
}

#[derive(Serialize)]
struct Entry<'a> {
    resource_id: String,
    path: NativePath<'a>,
    kind: &'static str,
    identity: Identity,
    logical_bytes: Option<u64>,
    allocated_bytes: Option<u64>,
    dataless: bool,
    counted: bool,
    depth: usize,
}

struct Entries<'a> {
    task_id: ScanTaskId,
    entries: &'a [ScanEntry],
}

impl Serialize for Entries<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.entries.len()))?;
        for entry in self.entries {
            sequence.serialize_element(&Entry {
                resource_id: format!("{}/{}", self.task_id, entry.id),
                path: NativePath(&entry.path),
                kind: match entry.kind {
                    ResourceKind::File => "file",
                    ResourceKind::Directory => "directory",
                    ResourceKind::Link => "link",
                    ResourceKind::Other => "other",
                },
                identity: match entry.identity {
                    FileIdentity::Unix { device, inode } => Identity::Unix { device, inode },
                    FileIdentity::Windows {
                        volume_serial,
                        file_id,
                    } => Identity::Windows {
                        volume_serial,
                        file_id,
                    },
                },
                logical_bytes: entry.logical_bytes,
                allocated_bytes: entry.allocated_bytes,
                dataless: entry.dataless,
                counted: entry.counted,
                depth: entry.depth,
            })?;
        }
        sequence.end()
    }
}

#[derive(Serialize)]
struct Issue<'a> {
    path: Option<NativePath<'a>>,
    code: &'static str,
    message: &'a str,
    os_code: Option<i32>,
}

struct Issues<'a>(&'a [ScanIssue]);

impl Serialize for Issues<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for issue in self.0 {
            sequence.serialize_element(&Issue {
                path: issue.path.as_deref().map(NativePath),
                code: issue.code.as_str(),
                message: &issue.message,
                os_code: issue.os_code,
            })?;
        }
        sequence.end()
    }
}

struct Totals<'a>(&'a ScanTotals);

impl Serialize for Totals<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let totals = self.0;
        let mut value = serializer.serialize_struct("Totals", 10)?;
        value.serialize_field("regular_files", &totals.regular_files)?;
        value.serialize_field("unique_files", &totals.unique_files)?;
        value.serialize_field("duplicate_files", &totals.duplicate_files)?;
        value.serialize_field("directories", &totals.directories)?;
        value.serialize_field("links", &totals.links)?;
        value.serialize_field("other", &totals.other)?;
        value.serialize_field("logical_bytes_known", &totals.logical_bytes_known)?;
        value.serialize_field(
            "logical_bytes_unknown_files",
            &totals.logical_bytes_unknown_files,
        )?;
        value.serialize_field("allocated_bytes_known", &totals.allocated_bytes_known)?;
        value.serialize_field(
            "allocated_bytes_unknown_files",
            &totals.allocated_bytes_unknown_files,
        )?;
        value.end()
    }
}

struct Metrics<'a>(&'a ScanMetrics);

impl Serialize for Metrics<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let metrics = self.0;
        let mut value = serializer.serialize_struct("Metrics", 8)?;
        value.serialize_field("elapsed_ms", &metrics.elapsed_ms)?;
        value.serialize_field("first_result_ms", &metrics.first_result_ms)?;
        value.serialize_field("peak_workers", &metrics.peak_workers)?;
        value.serialize_field("peak_queued_dirs", &metrics.peak_queued_dirs)?;
        value.serialize_field("peak_open_dirs", &metrics.peak_open_dirs)?;
        value.serialize_field("peak_pending_events", &metrics.peak_pending_events)?;
        value.serialize_field("retained_path_bytes", &metrics.retained_path_bytes)?;
        value.serialize_field("accepted_roots", &metrics.accepted_roots)?;
        value.end()
    }
}

#[derive(Serialize)]
struct Report<'a> {
    schema_version: u8,
    task_id: String,
    status: &'static str,
    complete: bool,
    roots: Roots<'a>,
    entries: Entries<'a>,
    issues: Issues<'a>,
    issues_omitted: usize,
    totals: Totals<'a>,
    metrics: Metrics<'a>,
}

fn line(writer: &mut impl Write, value: &impl Serialize) -> io::Result<()> {
    serde_json::to_writer(&mut *writer, value).map_err(io::Error::other)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

pub fn report(writer: &mut impl Write, report: &ScanReport) -> io::Result<()> {
    line(
        writer,
        &Report {
            schema_version: 1,
            task_id: report.task_id.to_string(),
            status: report.status.as_str(),
            complete: report.complete,
            roots: Roots(&report.roots),
            entries: Entries {
                task_id: report.task_id,
                entries: &report.entries,
            },
            issues: Issues(&report.issues),
            issues_omitted: report.issues_omitted,
            totals: Totals(&report.totals),
            metrics: Metrics(&report.metrics),
        },
    )
}

pub fn fatal(writer: &mut impl Write, error: &ScanError) -> io::Result<()> {
    #[derive(Serialize)]
    struct Fatal<'a> {
        schema_version: u8,
        task_id: Option<&'a str>,
        status: &'static str,
        complete: bool,
        roots: [(); 0],
        entries: [(); 0],
        issues: [Issue<'a>; 1],
        issues_omitted: usize,
        totals: Option<()>,
        metrics: Option<()>,
    }
    line(
        writer,
        &Fatal {
            schema_version: 1,
            task_id: None,
            status: "failed",
            complete: false,
            roots: [],
            entries: [],
            issues: [Issue {
                path: None,
                code: error.code.as_str(),
                message: &error.message,
                os_code: error.os_code,
            }],
            issues_omitted: 0,
            totals: None,
            metrics: None,
        },
    )
}

pub fn progress(writer: &mut impl Write, progress: &ScanProgress) -> io::Result<()> {
    #[derive(Serialize)]
    struct Progress {
        schema_version: u8,
        #[serde(rename = "type")]
        record_type: &'static str,
        task_id: String,
        entries: usize,
        unique_files: u64,
        logical_bytes_known: u64,
        issues: usize,
        elapsed_ms: u64,
    }
    line(
        writer,
        &Progress {
            schema_version: 1,
            record_type: "progress",
            task_id: progress.task_id.to_string(),
            entries: progress.entries,
            unique_files: progress.unique_files,
            logical_bytes_known: progress.logical_bytes_known,
            issues: progress.issues,
            elapsed_ms: progress.elapsed_ms,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use sayaka_engine::scan::ScanCode;

    struct BrokenWriter;

    impl Write for BrokenWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
    }

    #[test]
    fn serialization_propagates_output_failure() {
        let error = ScanError::new(ScanCode::InvalidLimits, "invalid limits");
        assert!(fatal(&mut BrokenWriter, &error).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn synthetic_non_utf8_path_serialization_preserves_bytes() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        // Wire-only coverage: APFS does not support creating this filename.
        let path = PathBuf::from(OsString::from_vec(b"/synthetic/\xff\n\x1b".to_vec()));
        let mut bytes = Vec::new();
        line(&mut bytes, &NativePath(&path)).expect("serialize synthetic path");
        let value: serde_json::Value = serde_json::from_slice(&bytes).expect("path JSON");
        assert_eq!(value["encoding"], "unix_bytes_hex");
        assert_eq!(value["raw"], "2f73796e7468657469632fff0a1b");
        assert!(
            !value["display"]
                .as_str()
                .expect("diagnostic string")
                .chars()
                .any(char::is_control)
        );
    }
}
