// SPDX-License-Identifier: MPL-2.0

#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(windows)]
mod native;
#[cfg(windows)]
pub use native::{Directory, Entry, Error, Metadata};

#[cfg(all(windows, test))]
#[path = "../../engine/tests/support/owned_temp.rs"]
mod owned_temp;
