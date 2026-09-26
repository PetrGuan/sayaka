// SPDX-License-Identifier: MPL-2.0

//! Versioned, read-only App Store availability contract for user-scope maintenance.
//! This catalog grants no mutation authority and never probes private user data.

pub const JSON_V1: &str = include_str!("../assets/maintenance_catalog_v1.json");
