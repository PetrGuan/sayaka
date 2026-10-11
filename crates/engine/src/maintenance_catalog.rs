// SPDX-License-Identifier: MPL-2.0

//! Versioned, read-only App Store availability contract for user-scope maintenance.
//! This catalog grants no mutation authority and never probes private user data.

pub const JSON_V1: &str = include_str!("../assets/maintenance_catalog_v1.json");

/// Developer ID version; legacy v1 remains byte-compatible.
pub fn json_v2() -> String {
    JSON_V1
        .replace("\"schema_version\": 1", "\"schema_version\": 2")
        .replace("macos_app_store", "macos_developer_id")
}
