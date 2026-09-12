// SPDX-License-Identifier: MPL-2.0

use super::*;
use sayaka_platform_macos::status as native;

impl Provider for NativeProvider {
    fn cpu(&mut self) -> io::Result<CpuTicks> {
        native::cpu().map(|value| CpuTicks {
            user: value.user,
            system: value.system,
            idle: value.idle,
            nice: value.nice,
        })
    }
    fn memory(&mut self) -> io::Result<Memory> {
        native::memory().map(|value| Memory {
            physical_bytes: value.physical_bytes,
            page_size: value.page_size,
            active_bytes: value.active_bytes,
            inactive_bytes: value.inactive_bytes,
            wired_bytes: value.wired_bytes,
            free_bytes: value.free_bytes,
            compressor_bytes: value.compressor_bytes,
            speculative_bytes: value.speculative_bytes,
            purgeable_bytes: value.purgeable_bytes,
            working_set_percent: 0.0,
        })
    }
    fn network(&mut self) -> io::Result<Vec<InterfaceCounters>> {
        native::network().map(|entries| {
            entries
                .into_iter()
                .map(|value| InterfaceCounters {
                    index: value.index,
                    name: value.name,
                    up: value.up,
                    received_bytes: value.received_bytes,
                    transmitted_bytes: value.transmitted_bytes,
                })
                .collect()
        })
    }
    fn sampler(&mut self) -> io::Result<ProcessCounters> {
        native::sampler().map(|value| ProcessCounters {
            cpu_time_ns: value.cpu_time_ns,
            resident_bytes: value.resident_bytes,
        })
    }
    fn disk(&mut self) -> io::Result<Disk> {
        native::disk().map(|value| Disk {
            total_bytes: value.total_bytes,
            free_bytes: value.free_bytes,
            available_bytes: value.available_bytes,
        })
    }
    fn processes(&mut self) -> io::Result<u64> {
        native::processes()
    }
    fn processes_top(
        &mut self,
        limit: usize,
        sort: ProcessTopSort,
        probe_cap: usize,
        collection_budget_ms: u64,
    ) -> io::Result<ProcessTopSnapshot> {
        let native_sort = match sort {
            ProcessTopSort::Cpu => native::ProcessTopSort::Cpu,
            ProcessTopSort::Memory => native::ProcessTopSort::Memory,
        };
        native::processes_top(limit, native_sort, probe_cap, collection_budget_ms).map(|snapshot| {
            ProcessTopSnapshot {
                rows: snapshot
                    .rows
                    .into_iter()
                    .map(|row| ProcessTopCounters {
                        identity: ProcessIdentity {
                            pid: row.identity.pid,
                            start_unix_sec: row.identity.start_unix_sec,
                            start_unix_usec: row.identity.start_unix_usec,
                        },
                        name: row.name,
                        resident_bytes: row.resident_bytes,
                        total_cpu_time_ns: row.total_cpu_time_ns,
                    })
                    .collect(),
                collection: ProcessTopCollection {
                    visible_processes: snapshot.collection.visible_processes,
                    candidate_cap: snapshot.collection.candidate_cap,
                    probe_cap: snapshot.collection.probe_cap,
                    probed: snapshot.collection.probed,
                    denied: snapshot.collection.denied,
                    disappeared: snapshot.collection.disappeared,
                    invalid: snapshot.collection.invalid,
                    truncated: snapshot.collection.truncated,
                    partial: snapshot.collection.partial,
                },
            }
        })
    }
    fn power(&mut self) -> io::Result<Power> {
        native::power().map(|value| Power {
            on_ac: value.on_ac,
            battery_percent: value.battery_percent,
            charging: value.charging,
        })
    }
    fn thermal(&mut self) -> io::Result<Thermal> {
        native::thermal().map(|value| match value {
            native::ThermalState::Nominal => Thermal::Nominal,
            native::ThermalState::Fair => Thermal::Fair,
            native::ThermalState::Serious => Thermal::Serious,
            native::ThermalState::Critical => Thermal::Critical,
        })
    }
}
