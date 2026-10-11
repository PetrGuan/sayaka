// SPDX-License-Identifier: MPL-2.0
use crate::system_storage::Observation;
use serde::Serialize;
#[derive(Serialize)]
pub struct Firmware {
    pub schema_version: u32,
    pub kind: &'static str,
    pub effects_performed: bool,
    pub leaves: Vec<Observation<Leaf>>,
}
#[derive(Serialize)]
pub struct Leaf {
    pub present: bool,
    pub file_count: u64,
    pub logical_bytes: u64,
}
const LEAVES: [&str; 3] = [
    "iPhone Software Updates",
    "iPad Software Updates",
    "iPod Software Updates",
];
const SOURCES: [&str; 3] = [
    "native home/Library/iTunes/iPhone Software Updates: direct .ipsw metadata",
    "native home/Library/iTunes/iPad Software Updates: direct .ipsw metadata",
    "native home/Library/iTunes/iPod Software Updates: direct .ipsw metadata",
];
pub fn preview() -> Firmware {
    let leaves = LEAVES
        .into_iter()
        .zip(SOURCES)
        .map(|(_, source)| Observation::unknown(source, "unsupported_platform"))
        .collect();
    let mut output = Firmware {
        schema_version: 1,
        kind: "sayaka.firmware_preview",
        effects_performed: false,
        leaves,
    };
    #[cfg(target_os = "macos")]
    {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        output.leaves = LEAVES
            .into_iter()
            .zip(SOURCES)
            .map(|(leaf, source)| {
                if std::time::Instant::now() >= deadline {
                    return Observation::unknown(source, "budget");
                }
                let result = sayaka_platform_macos::effective_account_home().and_then(|home| {
                    sayaka_platform_macos::firmware::observe(&home, leaf, deadline)
                });
                match result {
                    Ok(v) => {
                        let mut o = Observation::known(
                            source,
                            Leaf {
                                present: v.present,
                                file_count: v.count,
                                logical_bytes: v.bytes,
                            },
                        );
                        o.complete = v.complete;
                        if let Some(i) = v.issue {
                            o.issues.push(i);
                        }
                        o
                    }
                    Err(_) => Observation::unknown(source, "metadata_unavailable_or_budget"),
                }
            })
            .collect();
    }
    output
}
