// SPDX-License-Identifier: MPL-2.0

//! Bounded, read-only native status counters; no rates or health interpretation.

#[derive(Clone, Debug, PartialEq)]
pub struct CpuCounters {
    pub user: u64,
    pub system: u64,
    pub idle: u64,
    pub nice: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MemoryCounters {
    pub physical_bytes: u64,
    pub page_size: u64,
    pub active_bytes: u64,
    pub inactive_bytes: u64,
    pub wired_bytes: u64,
    pub free_bytes: u64,
    pub compressor_bytes: u64,
    pub speculative_bytes: u64,
    pub purgeable_bytes: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct NetworkCounters {
    pub index: u32,
    pub name: String,
    pub up: bool,
    pub received_bytes: u64,
    pub transmitted_bytes: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DiskCounters {
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub available_bytes: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SamplerCounters {
    pub cpu_time_ns: u64,
    pub resident_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessTopSort {
    Cpu,
    Memory,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_unix_sec: u64,
    pub start_unix_usec: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ProcessTopCounters {
    pub identity: ProcessIdentity,
    pub name: String,
    pub resident_bytes: u64,
    pub total_cpu_time_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessTopCollection {
    pub visible_processes: u64,
    pub candidate_cap: usize,
    pub probe_cap: usize,
    pub probed: usize,
    pub denied: usize,
    pub disappeared: usize,
    pub invalid: usize,
    pub truncated: bool,
    pub partial: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ProcessTopSnapshot {
    pub rows: Vec<ProcessTopCounters>,
    pub collection: ProcessTopCollection,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PowerCounters {
    pub on_ac: bool,
    pub battery_percent: Option<f64>,
    pub charging: Option<bool>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ThermalState {
    Nominal,
    Fair,
    Serious,
    Critical,
}

#[cfg(target_os = "macos")]
mod native;
#[cfg(target_os = "macos")]
pub use native::{cpu, disk, memory, network, power, processes, processes_top, sampler, thermal};

#[cfg(not(target_os = "macos"))]
macro_rules! unsupported {
    ($($name:ident -> $value:ty),+ $(,)?) => {$(
        #[doc = "Unavailable outside macOS; returns `ErrorKind::Unsupported`."]
        pub fn $name() -> std::io::Result<$value> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                concat!("macOS ", stringify!($name), " source is unavailable on this platform"),
            ))
        }
    )+};
}

#[cfg(not(target_os = "macos"))]
unsupported! {
    cpu -> CpuCounters,
    memory -> MemoryCounters,
    network -> Vec<NetworkCounters>,
    disk -> DiskCounters,
    sampler -> SamplerCounters,
    processes -> u64,
    processes_top -> ProcessTopSnapshot,
    power -> PowerCounters,
    thermal -> ThermalState,
}

#[cfg(all(test, not(target_os = "macos")))]
mod tests {
    use super::*;

    #[test]
    fn all_sources_are_explicitly_unsupported() {
        let errors = [
            cpu().unwrap_err(),
            memory().unwrap_err(),
            network().unwrap_err(),
            disk().unwrap_err(),
            sampler().unwrap_err(),
            processes().unwrap_err(),
            processes_top(1, ProcessTopSort::Cpu, 1, 1).unwrap_err(),
            power().unwrap_err(),
            thermal().unwrap_err(),
        ];
        assert!(
            errors
                .iter()
                .all(|e| e.kind() == std::io::ErrorKind::Unsupported)
        );
    }
}
