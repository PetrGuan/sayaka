// SPDX-License-Identifier: MPL-2.0

//! One-shot, read-only possible-remnant preview for explicit App Store grants.

use super::*;
use sayaka_engine::app_inventory::{
    AppInventoryLimits, AppInventoryMetadataReadMode, AppInventoryOptions, inventory_apps,
};
use sayaka_engine::app_orphans::project_orphan_caches;
use sayaka_engine::model::Cancellation;
use sayaka_engine::scan::{ScanLimits, scan, scan_prune_app_bundles};
use std::path::Component;
use std::time::{Duration, Instant};

const ORPHAN_RESULT_BYTES: usize = 4 * 1024 * 1024;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SayakaOrphanPreviewRequestV1 {
    pub abi_version: u32,
    pub struct_size: u32,
    pub app_root: SayakaPathV1,
    pub caches_root: SayakaPathV1,
    pub reserved: u64,
}

/// Performs two bounded, read-only scans. Call off the UI thread. The result
/// supplies evidence only and cannot be used as an execution selection.
///
/// # Safety
/// Request and path bytes must be readable; output storage must be writable,
/// exactly `ORPHAN_RESULT_BYTES` long and disjoint from all input storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sayaka_orphan_preview_v1(
    request: *const SayakaOrphanPreviewRequestV1,
    buffer: *mut u8,
    capacity: usize,
    required: *mut usize,
) -> i32 {
    boundary(|| {
        // SAFETY: Caller promises valid, non-overlapping storage.
        unsafe { prepare_output(buffer, capacity, required, ORPHAN_RESULT_BYTES)? };
        if capacity != ORPHAN_RESULT_BYTES {
            return Err(INVALID_ARGUMENT);
        }
        pointer(request)?;
        // SAFETY: Caller promises a readable/aligned request.
        let request = unsafe { *request };
        if request.abi_version != ABI_VERSION
            || request.struct_size as usize != size_of::<SayakaOrphanPreviewRequestV1>()
        {
            return Err(UNSUPPORTED_VERSION);
        }
        if request.reserved != 0 {
            return Err(INVALID_ARGUMENT);
        }
        #[cfg(not(target_os = "macos"))]
        return Err(UNSUPPORTED_PLATFORM);
        #[cfg(target_os = "macos")]
        {
            // SAFETY: Caller promises both bounded path byte buffers are readable.
            let app_root = unsafe { decode_path(request.app_root)? };
            let caches_root = unsafe { decode_path(request.caches_root)? };
            if !app_root.is_absolute()
                || app_root.parent().is_none()
                || !caches_root.is_absolute()
                || caches_root.parent().is_none()
                || app_root
                    .components()
                    .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
                || caches_root
                    .components()
                    .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
                || caches_root.file_name().is_none_or(|s| s != "Caches")
                || caches_root
                    .parent()
                    .and_then(|p| p.file_name())
                    .is_none_or(|s| s != "Library")
            {
                return Err(INVALID_ARGUMENT);
            }
            let cancellation = Cancellation::default();
            let started = Instant::now();
            let limits = ScanLimits {
                time_budget: Duration::from_secs(15),
                ..ScanLimits::default()
            };
            let app_report = scan_prune_app_bundles(&[app_root], &limits, &cancellation, |_| {})
                .map_err(|_| QUERY_UNAVAILABLE)?;
            let remaining = Duration::from_secs(30).saturating_sub(started.elapsed());
            let inventory = inventory_apps(
                app_report,
                &AppInventoryOptions {
                    metadata_read_mode: AppInventoryMetadataReadMode::AppRelated,
                    limits: AppInventoryLimits::default(),
                    ..AppInventoryOptions::default()
                },
                &cancellation,
                remaining,
            );
            let cache_limits = ScanLimits {
                max_depth: 1,
                max_entries: 4096,
                time_budget: Duration::from_secs(10),
                ..ScanLimits::default()
            };
            let cache_report = scan(&[caches_root], &cache_limits, &cancellation, |_| {})
                .map_err(|_| QUERY_UNAVAILABLE)?;
            let preview = project_orphan_caches(&inventory, &cache_report);
            let bytes = bounded_json(&preview, ORPHAN_RESULT_BYTES)?;
            // SAFETY: Output was validated above; bytes are privately owned.
            unsafe { copy_output(&bytes, buffer, capacity, required) }
        }
    })
}

#[cfg(test)]
mod tests;
