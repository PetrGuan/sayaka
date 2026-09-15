// SPDX-License-Identifier: MPL-2.0

use serde::Serialize;

/// Optional aggregate observations, separate from the scan report/authorization.
/// Root records are in admission order (at most 64), and never contain paths.
#[derive(Debug, Default, Serialize)]
pub struct ScanDiagnostics {
    pub caller_policy_enter_ms: Option<f64>,
    pub native_walk_ms: Option<f64>,
    pub caller_policy_restore_ms: Option<f64>,
    pub roots: Vec<RootAdmissionDiagnostics>,
}

#[derive(Debug, Default, Serialize)]
pub struct RootAdmissionDiagnostics {
    pub open_ms: Option<f64>,
    pub volume_ms: Option<f64>,
    pub directory_setup_ms: Option<f64>,
    pub volume_url_ms: Option<f64>,
    pub volume_local_ms: Option<f64>,
    pub volume_internal_ms: Option<f64>,
    pub volume_removable_ms: Option<f64>,
    pub volume_ejectable_ms: Option<f64>,
    pub error_code: Option<&'static str>,
}

/// macOS host-wide mach-absolute nanoseconds; unavailable on other platforms.
pub fn diagnostic_clock_ns() -> std::io::Result<Option<u64>> {
    #[cfg(target_os = "macos")]
    {
        sayaka_platform_macos::diagnostic_monotonic_ns().map(Some)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(None)
    }
}
