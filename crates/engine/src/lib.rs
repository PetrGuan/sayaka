// SPDX-License-Identifier: MPL-2.0

//! Shared local maintenance engine for Sayaka.
//!
//! Deterministic in-memory planning, approval and preflight, plus bounded
//! read-only macOS scanning of explicit roots. Planning probes are trusted
//! embedding boundaries, not OS authorization. Explicit native Trash execution
//! uses a separate, versioned revalidation contract with a residual path race.

#![forbid(unsafe_code)]

pub mod admin_uninstall;
pub mod ai_footprint;
pub mod app_inventory;
pub mod app_orphans;
pub mod app_related;
pub mod app_uninstall;
pub mod clean_policy;
pub mod devtools;
pub mod execute;
pub mod history;
pub mod installation;
pub mod installer_preview;
pub mod journal;
pub mod maintenance_catalog;
pub mod model;
pub mod plan;
pub mod project_git;
pub mod project_activity;
pub mod purge_preview;
mod readonly_task;
pub mod receipt;
pub mod rules;
pub mod scan;
pub mod status;
pub mod system_storage;

pub use plan::{Clock, IdSource, Planner, SequentialIds, SystemClock};

#[cfg(target_os = "macos")]
pub mod related_uninstall;

#[cfg(target_os = "macos")]
mod app_observation;

pub mod orphan_journal;

#[cfg(target_os = "macos")]
pub mod orphan_execution;

#[cfg(target_os = "macos")]
pub mod empty_trash;
pub mod empty_trash_journal;

pub mod firmware;

pub mod macos_installers;

pub mod runtime_journal;

pub mod readonly_diagnostics;
