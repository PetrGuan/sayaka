// SPDX-License-Identifier: MPL-2.0

//! Fail-closed shared Adobe media-cache writer observation, with no effects.
use crate::app_inventory::{self, AppInventoryOptions, PathStatus, StringState};
use crate::model::Cancellation;
use crate::scan::{self, ScanLimits};
use sayaka_platform_macos::related::{self, PathWitness};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const EXACT: &[&str] = &[
    "Adobe Premiere Pro",
    "Adobe Premiere",
    "After Effects",
    "Adobe After Effects",
    "Adobe Media Encoder",
    "aerender",
    "dynamiclinkmanager",
    "dynamiclinkmediaserver",
];
const PREFIXES: &[&str] = &[
    "Adobe Premiere",
    "Adobe After Effects",
    "Adobe Media Encoder",
    "After Effects",
    "dynamiclink",
    "Adobe QT32 Server",
    "AdobeIPCBroker",
];
fn writer_name(name: &str) -> bool {
    EXACT.contains(&name) || PREFIXES.iter().any(|p| name.starts_with(p))
}
fn writer_id(id: &str) -> bool {
    let id = id.to_ascii_lowercase();
    [
        "com.adobe.premiere",
        "com.adobe.aftereffects",
        "com.adobe.adobemediaencoder",
    ]
    .iter()
    .any(|p| id.starts_with(p))
}

fn app_ancestors(path: &Path) -> impl Iterator<Item = &Path> {
    path.ancestors()
        .filter(|p| p.extension().is_some_and(|x| x == "app"))
}

pub(super) fn active_or_unknown(home: &Path) -> bool {
    observe_idle(home).is_err()
}
fn observe_idle(home: &Path) -> Result<(), String> {
    let start = Instant::now();
    let budget = Duration::from_secs(30);
    let paths = related::executable_paths().map_err(|e| e.to_string())?;
    // Renamed bundles and detached helpers still retain their executable names.
    if super::named_process_active_or_unknown::<()>(Ok(paths.clone()), EXACT, PREFIXES) {
        return Err("Adobe shared writer is running".into());
    }
    let mut roots = vec![PathBuf::from("/Applications")];
    let user_root = home.join("Applications");
    match std::fs::symlink_metadata(&user_root) {
        Ok(_) => roots.push(user_root),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.to_string()),
    }
    // Inspect every enclosing bundle, including nested writers/helpers and
    // installations outside ordinary roots. Pruned inventory alone misses these.
    let mut observed = std::collections::HashSet::new();
    for path in &paths {
        for bundle in app_ancestors(path) {
            if !observed.insert(bundle.to_owned()) {
                continue;
            }
            if observed.len() > 256 || start.elapsed() >= budget {
                return Err("running bundle inventory budget exceeded".into());
            }
            let bundle_witness = PathWitness::capture(bundle).map_err(|e| e.to_string())?;
            let manifest = PathWitness::capture(&bundle.join("Contents/Info.plist"))
                .map_err(|e| e.to_string())?;
            let (id, _, device, inode) =
                app_inventory::read_bundle_identifier_with_digest(bundle).map_err(str::to_owned)?;
            bundle_witness.revalidate().map_err(|e| e.to_string())?;
            manifest.revalidate().map_err(|e| e.to_string())?;
            if manifest.identity() != (device, inode) {
                return Err("writer manifest changed".into());
            }
            let id = id
                .value
                .filter(|_| id.state == StringState::Present)
                .ok_or("running bundle identity unknown")?;
            if writer_id(&id) {
                return Err("Adobe bundle writer is running".into());
            }
        }
    }
    roots.sort();
    roots.dedup();
    if roots.len() > 64 {
        return Err("Adobe writer inventory roots exceeded".into());
    }
    let witnesses = roots
        .iter()
        .map(|p| PathWitness::capture(p).map_err(|e| e.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    let limits = ScanLimits {
        max_entries: 10_000,
        time_budget: budget.saturating_sub(start.elapsed()),
        ..ScanLimits::default()
    };
    let cancellation = Cancellation::default();
    let report = scan::scan_prune_app_bundles(&roots, &limits, &cancellation, |_| {})
        .map_err(|e| e.to_string())?;
    let inventory = app_inventory::inventory_apps(
        report,
        &AppInventoryOptions::default(),
        &cancellation,
        budget.saturating_sub(start.elapsed()),
    );
    if !inventory.complete || inventory.counts.unknown != 0 || !inventory.issues.is_empty() {
        return Err("Adobe writer inventory incomplete".into());
    }
    for app in inventory.apps {
        let Some(id) = app
            .bundle_id
            .value
            .filter(|_| app.bundle_id.state == StringState::Present)
        else {
            return Err("writer identity unknown".into());
        };
        if !writer_id(&id) {
            continue;
        }
        if app.executable.path_status != PathStatus::PresentFile
            || !app
                .executable
                .declared_value
                .as_deref()
                .is_some_and(writer_name)
        {
            return Err("unrecognized Adobe writer layout".into());
        }
        if related::bundle_id_running(&id).map_err(|e| e.to_string())?
            || paths.iter().any(|p| p.starts_with(&app.bundle_path))
        {
            return Err("Adobe shared writer is running".into());
        }
    }
    for w in witnesses {
        w.revalidate().map_err(|e| e.to_string())?;
    }
    if start.elapsed() >= budget {
        return Err("Adobe writer inventory timed out".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nested_helpers_and_writers_keep_every_bundle_ancestor() {
        let paths: Vec<_> = app_ancestors(Path::new("/Volumes/Apps/Suite.app/Contents/Adobe.app/Contents/Helpers/Helper.app/Contents/MacOS/unlisted")).collect();
        assert_eq!(paths.len(), 3);
        assert!(paths.contains(&Path::new("/Volumes/Apps/Suite.app/Contents/Adobe.app")));
        assert!(paths.contains(&Path::new("/Volumes/Apps/Suite.app")));
    }
    #[test]
    fn shared_writers_and_detached_helpers_are_denied() {
        for name in [
            "Adobe Premiere Pro",
            "After Effects",
            "Adobe Media Encoder 2026",
            "aerender",
            "dynamiclinkmanager",
            "dynamiclinkmediaserver",
            "Adobe QT32 Server",
            "AdobeIPCBroker",
        ] {
            assert!(writer_name(name), "{name}");
        }
        assert!(!writer_name("TextEdit"));
        for id in [
            "com.adobe.PremierePro.26",
            "com.adobe.AfterEffects",
            "com.adobe.AdobeMediaEncoder",
        ] {
            assert!(writer_id(id));
        }
        assert!(!writer_id("com.example.Premiere"));
        assert!(super::super::named_process_active_or_unknown::<()>(
            Err(()),
            EXACT,
            PREFIXES
        ));
        assert!(super::super::named_process_active_or_unknown::<()>(
            Ok(vec![PathBuf::from(
                "/Applications/Renamed.app/Contents/MacOS/aerender"
            )]),
            EXACT,
            PREFIXES
        ));
        assert!(!super::super::named_process_active_or_unknown::<()>(
            Ok(vec![PathBuf::from("/usr/bin/true")]),
            EXACT,
            PREFIXES
        ));
    }
}
