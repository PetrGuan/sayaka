// SPDX-License-Identifier: MPL-2.0
//! Fixed read-only Apple tool calls for ownership labels, never cleanup authority.
use crate::devtools::{ToolRunner, XcrunRunner};
use std::time::{Duration, Instant};
#[derive(Default)]
pub struct CatalogOutput {
    pub simulators: Option<Vec<u8>>,
    pub physical: Option<Vec<u8>>,
    pub runtimes: Option<Vec<u8>>,
}
pub fn observe(devices: bool, runtimes: bool, cancel: &dyn Fn() -> bool) -> CatalogOutput {
    let mut out = CatalogOutput::default();
    let Ok(runner) = XcrunRunner::new() else {
        return out;
    };
    let deadline = Instant::now() + Duration::from_secs(3);
    let read = |args: &[&str]| {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if cancel() || remaining.is_zero() {
            return None;
        }
        runner
            .run(
                &args.iter().map(|s| (*s).into()).collect::<Vec<_>>(),
                remaining.min(Duration::from_secs(1)),
            )
            .ok()
            .filter(|r| r.success)
            .map(|r| r.stdout)
    };
    if devices {
        out.simulators = read(&["simctl", "list", "devices", "-j"]);
        out.physical = read(&[
            "devicectl",
            "list",
            "devices",
            "--json-output",
            "-",
            "--quiet",
        ]);
    }
    if runtimes {
        out.runtimes = read(&["simctl", "runtime", "list", "-j"]);
    }
    out
}
