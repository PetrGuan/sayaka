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
pub use native::{cpu, disk, memory, network, power, processes, sampler, thermal};

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
