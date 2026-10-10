// SPDX-License-Identifier: MPL-2.0

//! Cache-only streaming totals. No per-file path/index retention.
use super::*;
#[cfg(target_os = "macos")]
mod parallel;
#[cfg(target_os = "macos")]
pub(super) use parallel::summarize;

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
