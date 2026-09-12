// SPDX-License-Identifier: MPL-2.0

//! Local, dedicated-prefix lifecycle; never an arbitrary deletion interface.
//!
//! Only macOS is supported. The physical parent must already exist. A private
//! managed prefix must remain quiescent except for cooperating locked operations:
//! descriptor-relative checks are not atomic protection against hostile same-UID
//! namespace tampering. Receipts are local ownership bookkeeping, not signatures.
//! Failed effects retain exact recovery locations, never discover/replay leftovers
//! by name. Footprints cover only the three known regular files, not directory
//! overhead, physical space reclaimed, or external history/user state.
//!
//! Layout: `bin/sayaka` (0700), `ownership-v1.json` and `.lock` (0600), in
//! directories with mode 0700 and no extended ACL. The caller supplies its running
//! program's on-disk executable, which is opened once and copied as local input;
//! this does not establish codesigning or download provenance. Pre-effect errors
//! return `Err`; failures or cancellation after effects return `Incomplete`.
//! An existing verified image is only reported `AlreadyInstalled` by execution
//! after completing file, directory, parent, and final full-sync barriers. Its
//! visibility alone does not prove an earlier publication was durable. Preparing
//! an existing-image preview does not perform these barriers or repair anything.
//! Abrupt process death cannot return an outcome: retained artifacts are not
//! automatically discovered or replayed, and incomplete layouts need inspection.

use crate::{journal::NativePath, model::Cancellation};
use serde::Serialize;
use std::{io, path::Path};

#[cfg(target_os = "macos")]
mod macos;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Action {
    Install,
    Remove,
}

#[derive(Clone, Debug, Serialize)]
pub struct Preview {
    pub action: Action,
    pub prefix: NativePath,
    pub executable: NativePath,
    pub version: String,
    pub sha256: String,
    pub executable_bytes: u64,
    pub already_installed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum OutcomeState {
    Installed,
    AlreadyInstalled,
    Removed,
    Incomplete,
    Cancelled,
}

#[derive(Debug, Serialize)]
pub struct Outcome {
    pub status: OutcomeState,
    pub preview: Preview,
    pub logical_bytes: Option<u64>,
    pub allocated_bytes: Option<u64>,
    /// Exact locations touched by an incomplete operation, possibly now absent.
    /// These are evidence for inspection, not authorization to delete or replay.
    pub recovery_paths: Vec<NativePath>,
    pub error: Option<String>,
}

impl Outcome {
    pub fn exit_code(&self) -> u8 {
        match self.status {
            OutcomeState::Installed | OutcomeState::AlreadyInstalled | OutcomeState::Removed => 0,
            OutcomeState::Incomplete => 1,
            OutcomeState::Cancelled => 130,
        }
    }
}

/// A single-use plan retaining the opened source and, if present, package lock.
pub struct InstallPlan {
    preview: Preview,
    #[cfg(target_os = "macos")]
    inner: macos::Install,
}

impl InstallPlan {
    /// Inspect without creating any files or rewriting permissions.
    pub fn prepare(prefix: &Path, source: &Path, version: &str) -> io::Result<Self> {
        #[cfg(target_os = "macos")]
        {
            let (inner, preview) = macos::Install::prepare(prefix, source, version)?;
            Ok(Self { preview, inner })
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (prefix, source, version);
            Err(unsupported())
        }
    }

    pub fn preview(&self) -> &Preview {
        &self.preview
    }

    pub fn execute(self, cancellation: &Cancellation) -> io::Result<Outcome> {
        #[cfg(target_os = "macos")]
        {
            self.inner.execute(self.preview, cancellation)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = cancellation;
            Err(unsupported())
        }
    }
}

/// A single-use plan holding the verified package's exclusive cooperative lock.
pub struct RemovePlan {
    preview: Preview,
    #[cfg(target_os = "macos")]
    inner: macos::Remove,
}

impl RemovePlan {
    /// Verify the entire fixed inventory; no files are removed by preparation.
    pub fn prepare(prefix: &Path) -> io::Result<Self> {
        #[cfg(target_os = "macos")]
        {
            let (inner, preview) = macos::Remove::prepare(prefix)?;
            Ok(Self { preview, inner })
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = prefix;
            Err(unsupported())
        }
    }

    pub fn preview(&self) -> &Preview {
        &self.preview
    }

    pub fn execute(self, cancellation: &Cancellation) -> io::Result<Outcome> {
        #[cfg(target_os = "macos")]
        {
            self.inner.execute(self.preview, cancellation)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = cancellation;
            Err(unsupported())
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "local dedicated-prefix installation/removal currently requires macOS",
    )
}

#[cfg(all(test, not(target_os = "macos")))]
mod tests {
    use super::*;

    #[test]
    fn installation_is_explicitly_unsupported() {
        assert!(matches!(
            InstallPlan::prepare(Path::new("/unused"), Path::new("/unused"), "1"),
            Err(error) if error.kind() == io::ErrorKind::Unsupported
        ));
        assert!(matches!(
            RemovePlan::prepare(Path::new("/unused")),
            Err(error) if error.kind() == io::ErrorKind::Unsupported
        ));
    }
}
