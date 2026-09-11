// SPDX-License-Identifier: MPL-2.0

//! Shared local maintenance engine for Sayaka.
//!
//! Deterministic in-memory planning, approval and preflight, plus bounded
//! read-only macOS scanning of explicit roots. Planning probes are trusted
//! embedding boundaries, not OS authorization. Explicit native Trash execution
//! uses a separate, versioned revalidation contract with a residual path race.

#![forbid(unsafe_code)]

pub mod execute;
pub mod journal;
pub mod model;
pub mod plan;
pub mod receipt;
pub mod scan;

pub use plan::{Clock, IdSource, Planner, SequentialIds, SystemClock};
