// SPDX-License-Identifier: MPL-2.0

//! Cache-only streaming totals. No per-file path/index retention.
#[cfg(target_os = "macos")]
use super::walk::{Backend, Cursor, ThreadPolicy};
use super::*;
#[cfg(target_os = "macos")]
use std::collections::{HashMap, HashSet};
#[cfg(target_os = "macos")]
use std::time::Instant;

#[derive(Default)]
pub(crate) struct Summary {
    pub entries: usize,
    pub files: u64,
    pub logical: Option<u64>,
    pub allocated: Option<u64>,
    pub links: u64,
    pub complete: bool,
    pub cancelled: bool,
    pub issues: Vec<ScanIssue>,
    pub omitted: usize,
}
impl Summary {
    fn issue(&mut self, path: &Path, error: ScanError, limits: &ScanLimits) {
        self.complete = false;
        if self.issues.len() < limits.max_issues {
            self.issues.push(ScanIssue {
                path: Some(path.to_owned()),
                code: error.code,
                message: error.message,
                os_code: error.os_code,
            });
        } else {
            self.omitted += 1;
        }
    }
}

pub(crate) fn scan(
    path: &Path,
    expected: FileIdentity,
    limits: &ScanLimits,
    cancellation: &Cancellation,
    progress: impl FnMut(usize, u64, u64),
) -> Result<Summary, ScanError> {
    limits.validate()?;
    #[cfg(target_os = "macos")]
    {
        super::macos::summarize_cache(path, expected, limits, cancellation, progress)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (path, expected, cancellation, progress);
        Err(ScanError::new(
            ScanCode::UnsupportedPlatform,
            "streaming cache previews are macOS-only",
        ))
    }
}

#[cfg(target_os = "macos")]
pub(super) fn summarize<B: Backend>(
    backend: &B,
    root: &Path,
    expected: FileIdentity,
    limits: &ScanLimits,
    cancellation: &Cancellation,
    mut progress: impl FnMut(usize, u64, u64),
) -> Result<Summary, ScanError> {
    let policy = backend.enter_thread()?;
    let result = (|| {
        let started = Instant::now();
        let mut out = Summary {
            complete: true,
            logical: Some(0),
            allocated: Some(0),
            ..Default::default()
        };
        let directory = backend.open_root(root)?;
        let root_meta = directory.metadata();
        if root_meta.identity != expected
            || root_meta.kind != ResourceKind::Directory
            || root_meta.dataless
        {
            return Err(ScanError::new(
                ScanCode::ChangedEntry,
                "cache root changed or is dataless",
            ));
        }
        let mut stack = vec![(directory, root.to_owned())];
        let mut path_bytes = root.as_os_str().len();
        let mut directories = HashSet::from([expected]);
        // Single-link files need no retained identity. Only multiply-linked (or
        // unknown-link-count) files use the bounded exact deduplication map.
        let mut linked_files = HashMap::new();
        while !stack.is_empty() {
            if cancellation.is_cancelled() {
                out.cancelled = true;
                out.issue(
                    root,
                    ScanError::new(ScanCode::Cancelled, "cache scan cancelled"),
                    limits,
                );
                break;
            }
            if started.elapsed() >= limits.time_budget {
                out.issue(
                    root,
                    ScanError::new(ScanCode::DurationLimit, "cache scan time budget reached"),
                    limits,
                );
                break;
            }
            let depth = stack.len();
            let (directory, parent) = stack.last_mut().expect("nonempty stack");
            let item = match directory.next_entry() {
                None => {
                    match directory.unchanged() {
                        Ok(true) => {}
                        Ok(false) => out.issue(
                            parent,
                            ScanError::new(
                                ScanCode::ChangedEntry,
                                "directory changed during cache scan",
                            ),
                            limits,
                        ),
                        Err(error) => out.issue(parent, error, limits),
                    }
                    path_bytes -= parent.as_os_str().len();
                    stack.pop();
                    continue;
                }
                Some(Err(error)) => {
                    out.issue(parent, error, limits);
                    path_bytes -= parent.as_os_str().len();
                    stack.pop();
                    continue;
                }
                Some(Ok(item)) => item,
            };
            if Path::new(&item.name).components().count() != 1
                || !matches!(
                    Path::new(&item.name).components().next(),
                    Some(std::path::Component::Normal(_))
                )
            {
                out.issue(
                    parent,
                    ScanError::new(ScanCode::Internal, "invalid cache entry name"),
                    limits,
                );
                continue;
            }
            let path = parent.join(&item.name);
            if path.as_os_str().len() > limits.max_path_bytes.min(65_536) {
                out.issue(
                    parent,
                    ScanError::new(ScanCode::PathBytesLimit, "cache path budget reached"),
                    limits,
                );
                continue;
            }
            out.entries = out
                .entries
                .checked_add(1)
                .ok_or_else(|| ScanError::new(ScanCode::Overflow, "cache entry count overflow"))?;
            if out.entries % limits.progress_every == 0 {
                progress(out.entries, out.files, out.logical.unwrap_or(0));
            }
            let metadata = match &item.metadata {
                Ok(value) => value,
                Err(error) => {
                    out.issue(&path, error.clone(), limits);
                    continue;
                }
            };
            if device(metadata.identity) != device(expected) {
                out.issue(
                    &path,
                    ScanError::new(
                        ScanCode::MountBoundary,
                        "cache mount boundary not traversed",
                    ),
                    limits,
                );
                continue;
            }
            if metadata.dataless {
                out.issue(
                    &path,
                    ScanError::new(
                        ScanCode::CloudDirectorySkipped,
                        "dataless cache contents not materialized",
                    ),
                    limits,
                );
                continue;
            }
            match metadata.kind {
                ResourceKind::Link => {
                    out.links += 1;
                } // Never open or count the target.
                ResourceKind::File => {
                    let sizes = (metadata.logical_bytes, metadata.allocated_bytes);
                    if metadata.link_count != Some(1) {
                        if let Some(previous) = linked_files.get(&metadata.identity) {
                            if previous != &sizes {
                                out.issue(
                                    &path,
                                    ScanError::new(
                                        ScanCode::ChangedEntry,
                                        "hard-linked cache file changed",
                                    ),
                                    limits,
                                );
                            }
                            continue;
                        }
                        if linked_files.len() >= limits.max_entries {
                            out.issue(
                                &path,
                                ScanError::new(
                                    ScanCode::EntryLimit,
                                    "cache hard-link identity budget reached",
                                ),
                                limits,
                            );
                            break;
                        }
                        linked_files.insert(metadata.identity, sizes);
                    }
                    out.files += 1;
                    out.logical = sum(out.logical, sizes.0)?;
                    out.allocated = sum(out.allocated, sizes.1)?;
                }
                ResourceKind::Directory => {
                    if directories.contains(&metadata.identity) {
                        out.issue(
                            &path,
                            ScanError::new(
                                ScanCode::ChangedEntry,
                                "duplicate cache directory identity",
                            ),
                            limits,
                        );
                        continue;
                    }
                    if directories.len() >= limits.max_entries {
                        out.issue(
                            &path,
                            ScanError::new(
                                ScanCode::EntryLimit,
                                "cache directory identity budget reached",
                            ),
                            limits,
                        );
                        break;
                    }
                    // Stack depth and open descriptors are bounded separately.
                    if path_bytes.saturating_add(path.as_os_str().len()) > limits.max_path_bytes {
                        out.issue(
                            &path,
                            ScanError::new(
                                ScanCode::PathBytesLimit,
                                "cache stack path budget reached",
                            ),
                            limits,
                        );
                        continue;
                    }
                    if depth >= limits.max_depth || depth >= limits.max_open_dirs {
                        out.issue(
                            &path,
                            ScanError::new(
                                ScanCode::DepthLimit,
                                "cache depth or open-directory budget reached",
                            ),
                            limits,
                        );
                        continue;
                    }
                    let child = match directory.open_child(&item) {
                        Ok(child) => child,
                        Err(mut error) => {
                            if error.code == ScanCode::LinkSkipped {
                                error.code = ScanCode::ChangedEntry;
                            }
                            out.issue(&path, error, limits);
                            continue;
                        }
                    };
                    if child.metadata().identity != metadata.identity || child.metadata().dataless {
                        out.issue(
                            &path,
                            ScanError::new(
                                ScanCode::ChangedEntry,
                                "cache directory replaced before opening",
                            ),
                            limits,
                        );
                        continue;
                    }
                    directories.insert(metadata.identity);
                    path_bytes += path.as_os_str().len();
                    stack.push((child, path));
                }
                _ => out.issue(
                    &path,
                    ScanError::new(ScanCode::Io, "unsupported cache entry kind"),
                    limits,
                ),
            }
        }
        progress(out.entries, out.files, out.logical.unwrap_or(0));
        Ok(out)
    })();
    match policy.restore() {
        Ok(()) => result,
        Err(error) => Err(error),
    }
}

#[cfg(target_os = "macos")]
fn sum(left: Option<u64>, right: Option<u64>) -> Result<Option<u64>, ScanError> {
    match (left, right) {
        (Some(a), Some(b)) => a
            .checked_add(b)
            .map(Some)
            .ok_or_else(|| ScanError::new(ScanCode::Overflow, "cache byte total overflow")),
        _ => Ok(None),
    }
}
#[cfg(target_os = "macos")]
fn device(identity: FileIdentity) -> u64 {
    match identity {
        FileIdentity::Unix { device, .. } => device,
        FileIdentity::Windows { volume_serial, .. } => volume_serial,
    }
}
