// SPDX-License-Identifier: MPL-2.0
use crate::system_storage::Observation;
use serde::Serialize;
#[derive(Serialize)]
pub struct Preview {
    pub schema_version: u32,
    pub kind: &'static str,
    pub effects_performed: bool,
    pub candidates: Observation<Vec<Candidate>>,
}
#[derive(Serialize)]
pub struct Candidate {
    pub path: String,
    pub bundle_id: String,
    pub app_version: Option<String>,
    pub target_os_major: Option<u32>,
    pub same_current_os_major: Option<bool>,
    pub identity: Identity,
    pub logical_bytes: Option<u64>,
    pub size_complete: bool,
}
#[derive(Serialize)]
pub struct Identity {
    pub device: u64,
    pub inode: u64,
    pub plist_device: u64,
    pub plist_inode: u64,
    pub plist_sha256: String,
}
const SOURCE: &str = "/Applications direct children, bounded Info.plist and metadata size";
fn candidate_name(s: &str) -> bool {
    s.strip_prefix("Install macOS ")
        .and_then(|s| s.strip_suffix(".app"))
        .is_some_and(|s| !s.is_empty())
}
pub fn preview() -> Preview {
    #[cfg(target_os = "macos")]
    let candidates =
        observe().unwrap_or_else(|_| Observation::unknown(SOURCE, "discovery_unavailable"));
    #[cfg(not(target_os = "macos"))]
    let candidates = Observation::unknown(SOURCE, "unsupported_platform");
    Preview {
        schema_version: 1,
        kind: "sayaka.macos_installer_preview",
        effects_performed: false,
        candidates,
    }
}
#[cfg(target_os = "macos")]
fn observe() -> std::io::Result<Observation<Vec<Candidate>>> {
    let policy = sayaka_platform_macos::ReadOnlyPolicy::enter()?;
    let result = observe_inner();
    let restored = policy.restore();
    restored?;
    result
}
#[cfg(target_os = "macos")]
fn observe_inner() -> std::io::Result<Observation<Vec<Candidate>>> {
    use sayaka_platform_macos::{firmware, orphans};
    use std::{
        os::unix::ffi::OsStrExt,
        path::Path,
        time::{Duration, Instant},
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    let path = Path::new("/Applications");
    let witness = orphans::exact(path)?;
    let volume = sayaka_platform_macos::volume_info(path)?;
    if !volume.local || !volume.internal || volume.removable || volume.ejectable {
        return Err(std::io::Error::other("volume"));
    }
    let root = firmware::directory(path)?;
    use std::os::unix::fs::MetadataExt;
    let m = root.metadata()?;
    if (m.dev(), m.ino()) != witness.identity() {
        return Err(std::io::Error::other("changed"));
    }
    let mut entries = firmware::Entries::new(&root)?;
    let mut list = Vec::new();
    let mut seen = 0;
    let mut remaining = 100_000;
    let mut complete = true;
    while let Some(name) = entries.next_name()? {
        if seen >= 4096 || list.len() >= 32 || Instant::now() >= deadline {
            complete = false;
            break;
        }
        seen += 1;
        let Ok(name_text) = name.to_str() else {
            continue;
        };
        if !candidate_name(name_text) {
            continue;
        }
        let bundle = path.join(std::ffi::OsStr::from_bytes(name.to_bytes()));
        let result = (|| -> std::io::Result<Candidate> {
            let evidence = crate::app_observation::Bundle::capture(&bundle)?;
            if evidence.bundle.identity().0 != witness.identity().0
                || evidence.manifest.identity().0 != witness.identity().0
            {
                return Err(std::io::Error::other("mount"));
            }
            if !evidence
                .id
                .strip_prefix("com.apple.InstallAssistant.")
                .is_some_and(|s| !s.is_empty())
            {
                return Err(std::io::Error::other("identifier_mismatch"));
            }
            let (id, version, digest, dev, ino) =
                crate::app_inventory::read_bundle_metadata_with_digest(&bundle)
                    .map_err(std::io::Error::other)?;
            if id.value.as_deref() != Some(&evidence.id)
                || digest != evidence.digest
                || (dev, ino) != evidence.manifest.identity()
            {
                return Err(std::io::Error::other("changed"));
            }
            let size =
                sayaka_platform_macos::installer_size::size(&bundle, deadline, &mut remaining).ok();
            evidence.revalidate()?;
            Ok(Candidate {
                path: bundle.to_string_lossy().into_owned(),
                bundle_id: evidence.id,
                app_version: version.value,
                target_os_major: None,
                same_current_os_major: None,
                identity: Identity {
                    device: evidence.bundle.identity().0,
                    inode: evidence.bundle.identity().1,
                    plist_device: dev,
                    plist_inode: ino,
                    plist_sha256: digest.iter().map(|b| format!("{b:02x}")).collect(),
                },
                logical_bytes: size.map(|s| s.0),
                size_complete: size.is_some_and(|s| s.1),
            })
        })();
        match result {
            Ok(c) => list.push(c),
            Err(_) => complete = false,
        }
    }
    witness.revalidate()?;
    let after = root.metadata()?;
    complete &= m.mtime() == after.mtime()
        && m.mtime_nsec() == after.mtime_nsec()
        && Instant::now() < deadline;
    let mut out = Observation::known(SOURCE, list);
    out.complete = complete;
    if !complete {
        out.issues.push("partial_or_excluded_candidates");
    }
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn names_are_exact() {
        assert!(candidate_name("Install macOS Tahoe.app"));
        assert!(!candidate_name("Install macOS .app"));
        assert!(!candidate_name("install macOS Tahoe.app"));
        assert!(!candidate_name("Install macOS Tahoe.app.old"));
    }
}
