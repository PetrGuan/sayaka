// SPDX-License-Identifier: MPL-2.0

//! Advisory simulator classification. Never changes execution eligibility.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SimulatorSuggestion {
    #[serde(flatten)]
    pub kind: SuggestionKind,
    pub evidence: Vec<String>,
    pub rebuildability_note: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SuggestionKind {
    Duplicate { newer_runtime: String },
    Unavailable,
}

/// Preserve an invalid report as unknown, rather than falling back to an older
/// valid date and suggesting an actively used device.
pub(super) fn latest_activity(used: Option<String>, booted: Option<String>) -> Option<String> {
    match (used, booted) {
        (Some(a), Some(b)) => match (runtimes::timestamp(&a), runtimes::timestamp(&b)) {
            (Some(x), Some(y)) => Some(if x >= y { a } else { b }),
            (None, _) => Some(a),
            (_, None) => Some(b),
        },
        (a, b) => a.or(b),
    }
}

fn runtime(value: &str) -> Option<(&'static str, [u32; 4])> {
    let raw = value.strip_prefix("com.apple.CoreSimulator.SimRuntime.")?;
    let (platform, digits) = raw.split_once('-')?;
    let platform = match platform {
        "iOS" => "iOS",
        "watchOS" => "watchOS",
        "tvOS" => "tvOS",
        "xrOS" | "visionOS" => "visionOS",
        _ => return None,
    };
    let mut version = [0; 4];
    let parts = digits.split('-').collect::<Vec<_>>();
    if parts.is_empty() || parts.len() > version.len() {
        return None;
    }
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        version[i] = part.parse().ok()?;
    }
    Some((platform, version))
}

pub fn assess(
    candidates: &mut [Candidate],
    types: &BTreeMap<String, String>,
    operation: Operation,
    now: Option<u64>,
) {
    let observed = candidates.to_vec();
    for candidate in candidates {
        candidate.suggestion = None;
        let device = &candidate.device;
        candidate.custom_name = types
            .get(&device.device_type_identifier)
            .map(|name| name != &device.name);
        // Orphans also respect the no-custom-name/no-pair recommendation rule.
        if operation != Operation::Delete
            || candidate.custom_name != Some(false)
            || !candidate.eligible()
            || candidate.paired_with.is_some()
        {
            continue;
        }
        let mut evidence = vec![
            "device_type_default_name".into(),
            "shutdown_unpaired_non_test_clone".into(),
        ];
        let kind = if !device.is_available {
            evidence.push("simctl_reports_unavailable".into());
            SuggestionKind::Unavailable
        } else {
            let Some(now) = now else {
                continue;
            };
            match device.last_used_at.as_deref() {
                Some(value) => {
                    let Some(time) = runtimes::timestamp(value) else {
                        continue;
                    };
                    if now.saturating_sub(time) < 14 * 86400 {
                        continue;
                    }
                    evidence.push("unused_at_least_14_days".into());
                }
                // simctl omits usage for never-booted devices. Preserve the
                // absence in the UI: this is not a fabricated activity date.
                None => evidence.push("no_boot_or_use_reported".into()),
            }
            let Some((platform, version)) = runtime(&device.runtime_identifier) else {
                continue;
            };
            let newer = observed
                .iter()
                .filter(|other| {
                    other.device.udid != device.udid
                        && other.device.is_available
                        && other.device.device_type_identifier == device.device_type_identifier
                        && !is_test_clone(&other.device.name)
                })
                .filter_map(|other| {
                    let (p, v) = runtime(&other.device.runtime_identifier)?;
                    (p == platform && v > version).then_some((v, &other.device.runtime_identifier))
                })
                .max();
            let Some((_, newer)) = newer else {
                continue;
            };
            evidence.push("available_same_device_type_on_newer_runtime".into());
            SuggestionKind::Duplicate {
                newer_runtime: newer.clone(),
            }
        };
        candidate.suggestion = Some(SimulatorSuggestion {
            kind, evidence,
            rebuildability_note: "Xcode can create another simulator. Apps, data and settings in this device are permanently deleted and are not copied to the newer device.".into(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn item(id: &str, version: &str, name: &str) -> Device {
        Device {
            udid: id.into(),
            name: name.into(),
            runtime_identifier: format!("com.apple.CoreSimulator.SimRuntime.{version}"),
            device_type_identifier: "iphone".into(),
            state: "Shutdown".into(),
            is_available: true,
            data_path: "/fixture".into(),
            data_path_size: None,
            log_path_size: None,
            last_used_at: None,
            availability_error: None,
        }
    }
    fn classify(devices: &[Device], pairs: &[(String, String)]) -> Vec<Candidate> {
        let mut result = candidates(devices, pairs, Operation::Delete);
        assess(
            &mut result,
            &BTreeMap::from([("iphone".into(), "iPhone".into())]),
            Operation::Delete,
            runtimes::timestamp("2026-10-12T00:00:00Z"),
        );
        result
    }
    #[test]
    fn numeric_same_platform_order_and_custom_names() {
        let mut devices = vec![
            item("a", "iOS-9-3", "iPhone"),
            item("b", "iOS-10-0", "iPhone"),
            item("c", "iOS-9-3", "My work"),
        ];
        let result = classify(&devices, &[]);
        assert!(matches!(
            result[0].suggestion.as_ref().unwrap().kind,
            SuggestionKind::Duplicate { .. }
        ));
        assert!(result[1].suggestion.is_none());
        assert_eq!(result[2].custom_name, Some(true));
        assert!(result[2].suggestion.is_none());
        devices[1].runtime_identifier = "com.apple.CoreSimulator.SimRuntime.tvOS-27-0".into();
        assert!(classify(&devices, &[])[0].suggestion.is_none());
    }
    #[test]
    fn recent_future_malformed_paired_and_clone_devices_are_not_suggested() {
        for value in ["2026-10-11T00:00:00Z", "2027-01-01T00:00:00Z", "unknown"] {
            let mut old = item("a", "iOS-26-4", "iPhone");
            old.last_used_at = Some(value.into());
            assert!(
                classify(&[old, item("b", "iOS-27-0", "iPhone")], &[])[0]
                    .suggestion
                    .is_none()
            );
        }
        let devices = [
            item("a", "iOS-26-4", "iPhone"),
            item("b", "iOS-27-0", "iPhone"),
        ];
        assert!(
            classify(&devices, &[("a".into(), "b".into())])[0]
                .suggestion
                .is_none()
        );
        let mut old = devices[0].clone();
        old.state = "Booted".into();
        assert!(
            classify(&[old, devices[1].clone()], &[])[0]
                .suggestion
                .is_none()
        );
        let clone = item("b", "iOS-27-0", "Clone 1 of iPhone");
        assert!(
            classify(&[devices[0].clone(), clone], &[])[0]
                .suggestion
                .is_none()
        );
    }
    #[test]
    fn unknown_names_and_custom_orphans_are_never_suggested() {
        let mut devices = vec![
            item("a", "iOS-26-4", "iPhone"),
            item("b", "iOS-26-4", "Custom"),
        ];
        for d in &mut devices {
            d.is_available = false;
        }
        let mut result = classify(&devices, &[]);
        assert!(matches!(
            result[0].suggestion.as_ref().unwrap().kind,
            SuggestionKind::Unavailable
        ));
        assert!(result[1].suggestion.is_none());
        assess(&mut result, &BTreeMap::new(), Operation::Delete, Some(0));
        assert!(
            result
                .iter()
                .all(|c| c.suggestion.is_none() && c.custom_name.is_none())
        );
    }
    #[test]
    fn latest_activity_keeps_recent_or_invalid_boot_report() {
        let old = "2026-01-01T00:00:00Z";
        let recent = "2026-10-11T00:00:00Z";
        assert_eq!(
            latest_activity(Some(old.into()), Some(recent.into())).as_deref(),
            Some(recent)
        );
        assert_eq!(
            latest_activity(Some(old.into()), Some("unknown".into())).as_deref(),
            Some("unknown")
        );
    }
}
