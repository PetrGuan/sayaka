// SPDX-License-Identifier: MPL-2.0
//! Read-only ownership evidence. A match never grants filesystem cleanup.
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

#[derive(Clone, Debug, Serialize)]
pub struct KnownOwner {
    pub rule: &'static str,
    pub owner: &'static str,
    pub non_target: bool,
    pub title: String,
    pub explanation: String,
    pub action: &'static str,
    pub simulator_udid: Option<String>,
    pub evidence: Vec<String>,
}
#[derive(Default)]
struct Catalog {
    simulators: BTreeMap<String, String>,
    physical: BTreeMap<String, String>,
    runtimes: Vec<(PathBuf, String)>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DeviceFiles {
    /// Unknown never contributes zero to the combined estimate.
    pub bytes: Option<u64>,
}

fn component(path: &Path) -> Option<String> {
    path.components().next().and_then(|c| match c {
        Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
        _ => None,
    })
}
fn normal(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
}
fn match_path(path: &Path, home: &Path, catalog: &Catalog) -> Option<(PathBuf, KnownOwner)> {
    if !normal(path) || !normal(home) {
        return None;
    }
    let make =
        |rule, owner, title: String, explanation: String, action, simulator_udid| KnownOwner {
            rule,
            owner,
            non_target: true,
            title,
            explanation,
            action,
            simulator_udid,
            evidence: vec![
                "Known-owner path table v1; observation only, never a filesystem Trash target"
                    .into(),
            ],
        };
    let devicefs = home.join("Library/Developer/CoreDevice/DeviceFS");
    if let Ok(relative) = path.strip_prefix(&devicefs) {
        let name = component(relative);
        let base = name.as_ref().map_or(devicefs.clone(), |n| devicefs.join(n));
        let id = name
            .as_deref()
            .and_then(|n| n.strip_prefix("device-"))
            .and_then(crate::devtools::canonical_udid);
        let simulator = id.as_ref().and_then(|id| catalog.simulators.get(id));
        let physical = id.as_ref().and_then(|id| catalog.physical.get(id));
        let (title, explanation, action) = if let Some(name) = simulator {
            (
                format!("{name} simulator data"),
                format!(
                    "Data for the {name} simulator. Erase or delete it in the Developer review."
                ),
                "developer_device",
            )
        } else {
            (
                physical.map_or("Xcode-managed device data".into(), |name| {
                    format!("{name} device data")
                }),
                "Device data managed by Xcode. Remove it in Xcode → Devices and Simulators.".into(),
                "xcode",
            )
        };
        let mut owner = make(
            "coredevice_devicefs_v1",
            "CoreDevice",
            title,
            explanation,
            action,
            simulator.and(id.clone()),
        );
        if simulator.is_some() {
            owner
                .evidence
                .push("DeviceFS identifier matched simctl list devices UDID".into());
        }
        if physical.is_some() {
            owner
                .evidence
                .push("DeviceFS identifier matched devicectl CoreDevice identifier".into());
        }
        return Some((base, owner));
    }
    let volumes = Path::new("/Library/Developer/CoreSimulator/Volumes");
    let assets = Path::new("/System/Library/AssetsV2");
    let runtime_base = if let Ok(relative) = path.strip_prefix(volumes) {
        Some(component(relative).map_or(volumes.to_path_buf(), |c| volumes.join(c)))
    } else if let Ok(relative) = path.strip_prefix(assets) {
        component(relative)
            .filter(|n| n.starts_with("com_apple_MobileAsset_") && n.ends_with("SimulatorRuntime"))
            .map(|n| assets.join(n))
    } else {
        None
    };
    if let Some(base) = runtime_base {
        let version = catalog
            .runtimes
            .iter()
            .find(|(p, _)| path.starts_with(p) || p == &base)
            .map(|(_, v)| v.as_str());
        let title = version.map_or("Simulator runtime data".into(), |v| {
            format!("Simulator runtime {v}")
        });
        return Some((
            base,
            make(
                "simulator_runtime_storage_v1",
                "simctl",
                title.clone(),
                format!("{title}. Remove the matching runtime in the Developer review."),
                "developer_runtime",
                None,
            ),
        ));
    }
    for platform in ["iOS", "watchOS", "tvOS", "visionOS", "xrOS"] {
        let support = home.join(format!("Library/Developer/Xcode/{platform} DeviceSupport"));
        if let Ok(relative) = path.strip_prefix(&support) {
            let version = component(relative);
            let base = version
                .as_ref()
                .map_or(support.clone(), |v| support.join(v));
            let os = version.map_or(platform.into(), |v| format!("{platform} {v}"));
            return Some((
                base,
                make(
                    "xcode_device_support_v1",
                    "Xcode",
                    format!("{os} debug symbols"),
                    format!(
                        "Debug symbols for {os}. Xcode recreates them when that device connects. Observation only; these are not a cleanup target."
                    ),
                    "xcode",
                    None,
                ),
            ));
        }
    }
    None
}

/// Pure path classification with no device tools; used at Trash admission too.
#[cfg(target_os = "macos")]
pub fn managed(path: &Path) -> bool {
    sayaka_platform_macos::effective_account_home()
        .ok()
        .is_some_and(|home| match_path(path, &home, &Catalog::default()).is_some())
}
#[cfg(not(target_os = "macos"))]
pub fn managed(_path: &Path) -> bool {
    false
}

#[cfg(target_os = "macos")]
pub(crate) fn annotate(report: &mut crate::scan::ScanReport, cancel: &crate::model::Cancellation) {
    let Ok(home) = sayaka_platform_macos::effective_account_home() else {
        return;
    };
    let mut catalog = Catalog::default();
    let paths = report
        .entries
        .iter()
        .map(|e| e.path.as_path())
        .chain(report.issues.iter().filter_map(|i| i.path.as_deref()));
    let mut devices = false;
    let mut runtimes = false;
    for path in paths {
        if let Some((_, owner)) = match_path(path, &home, &catalog) {
            devices |= owner.rule == "coredevice_devicefs_v1";
            runtimes |= owner.rule == "simulator_runtime_storage_v1";
        }
    }
    if !cancel.is_cancelled() && (devices || runtimes) {
        let observed = sayaka_platform_macos::known_owner::observe(devices, runtimes, &|| {
            cancel.is_cancelled()
        });
        if let Some(bytes) = observed.simulators {
            if let Ok(items) = crate::devtools::parse_devices(&bytes) {
                for item in items {
                    catalog.simulators.insert(item.udid, item.name);
                }
            }
        }
        if let Some(bytes) = observed.physical {
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                if let Some(items) = json.pointer("/result/devices").and_then(|v| v.as_array()) {
                    for item in items.iter().take(1024) {
                        if let (Some(id), Some(name)) = (
                            item.get("identifier")
                                .and_then(|v| v.as_str())
                                .and_then(crate::devtools::canonical_udid),
                            item.pointer("/deviceProperties/name")
                                .or_else(|| item.pointer("/properties/name"))
                                .and_then(|v| v.as_str())
                                .filter(|s| !s.is_empty() && s.len() <= 256),
                        ) {
                            catalog.physical.insert(id, name.into());
                        }
                    }
                }
            }
        }
        if let Some(bytes) = observed.runtimes {
            if let Ok(items) = crate::devtools::runtimes::parse_runtimes(&bytes) {
                catalog.runtimes = items
                    .into_iter()
                    .map(|r| (r.path.into(), r.version))
                    .collect();
            }
        }
    }
    let mut shared = BTreeMap::new();
    for entry in &mut report.entries {
        if let Some((base, owner)) = match_path(&entry.path, &home, &catalog) {
            entry.owner = Some(
                shared
                    .entry(base)
                    .or_insert_with(|| Arc::new(owner))
                    .clone(),
            );
        }
    }
    for issue in &mut report.issues {
        if let Some((_, owner)) = issue
            .path
            .as_ref()
            .and_then(|p| match_path(p, &home, &catalog))
        {
            issue.owner = Some(Arc::new(owner));
        }
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn device_files(
    devices: &[crate::devtools::Device],
    cancel: &crate::model::Cancellation,
) -> BTreeMap<String, DeviceFiles> {
    use std::time::Instant;
    let mut result = BTreeMap::new();
    let Ok(home) = sayaka_platform_macos::effective_account_home() else {
        return result;
    };
    let root = home.join("Library/Developer/CoreDevice/DeviceFS");
    let Ok(_policy) = sayaka_platform_macos::ReadOnlyPolicy::enter() else {
        return result;
    };
    let Ok(root_witness) = sayaka_platform_macos::related::PathWitness::capture(&root) else {
        return result;
    };
    if !root_witness.is_directory() {
        return result;
    }
    let start = Instant::now();
    let Ok(entries) = std::fs::read_dir(&root) else {
        return result;
    };
    for entry in entries.take(256).flatten() {
        if cancel.is_cancelled() {
            break;
        }
        let name = entry.file_name();
        let Some(id) = name
            .to_str()
            .and_then(|n| n.strip_prefix("device-"))
            .and_then(crate::devtools::canonical_udid)
        else {
            continue;
        };
        let Some(device) = devices.iter().find(|d| d.udid == id) else {
            continue;
        };
        // Never add an overlapping path to simctl's own data-path subtotal.
        if entry.path().starts_with(&device.data_path)
            || Path::new(&device.data_path).starts_with(entry.path())
        {
            continue;
        }
        let bytes = crate::related_uninstall::measure_size(&entry.path(), start).ok();
        result.insert(id, DeviceFiles { bytes });
    }
    if root_witness.revalidate().is_err() {
        return BTreeMap::new();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_native_components_and_owner_routes_never_authorize_trash() {
        let home = Path::new("/Users/example");
        let id = "12345678-1234-1234-1234-123456789ABC";
        let mut catalog = Catalog::default();
        catalog.simulators.insert(id.into(), "iPhone Duo".into());
        let (_, o) = match_path(
            &home.join(format!(
                "Library/Developer/CoreDevice/DeviceFS/device-{id}/data/a"
            )),
            home,
            &catalog,
        )
        .unwrap();
        assert_eq!(o.title, "iPhone Duo simulator data");
        assert!(o.non_target);
        assert_eq!(o.action, "developer_device");
        assert!(
            match_path(
                &home.join("Library/Developer/CoreDevice/DeviceFS-backup/file"),
                home,
                &catalog
            )
            .is_none()
        );
        assert!(
            match_path(
                Path::new("/System/Library/AssetsV2/com_apple_MobileAsset_iOSSimulatorRuntime/a"),
                home,
                &catalog
            )
            .unwrap()
            .1
            .non_target
        );
        assert!(
            match_path(
                &home.join("Library/Developer/Xcode/iOS DeviceSupport/18.0/Symbols"),
                home,
                &catalog
            )
            .unwrap()
            .1
            .non_target
        );
    }
}
