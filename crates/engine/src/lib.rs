// SPDX-License-Identifier: MPL-2.0

//! Shared local maintenance engine for Sayaka.
//!
//! Deterministic, in-memory discovery, planning, approval, and read-only
//! preflight contracts. Probes are trusted embedding boundaries, not an OS
//! authorization mechanism. This crate does not scan or modify the filesystem.

#![forbid(unsafe_code)]

pub mod model;
pub mod plan;
pub mod receipt;

pub use plan::{Clock, IdSource, Planner, SequentialIds, SystemClock};
