// SPDX-License-Identifier: MPL-2.0

//! Shared local maintenance engine for Sayaka.
//!
//! Deterministic in-memory planning, approval and preflight, plus bounded
//! read-only macOS scanning of explicit roots. Planning probes are trusted
//! embedding boundaries, not OS authorization. Explicit native Trash execution
//! uses a separate, versioned revalidation contract with a residual path race.

#![forbid(unsafe_code)]

pub mod app_inventory;
pub mod app_related;
pub mod app_uninstall;
pub mod clean_policy;
pub mod execute;
pub mod history;
pub mod installation;
pub mod installer_preview;
pub mod journal;
pub mod model;
pub mod plan;
mod readonly_task;
pub mod receipt;
pub mod rules;
pub mod scan;
pub mod status;

pub use plan::{Clock, IdSource, Planner, SequentialIds, SystemClock};
