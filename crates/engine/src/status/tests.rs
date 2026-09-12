// SPDX-License-Identifier: MPL-2.0

use super::*;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

#[derive(Clone)]
struct ManualClock(Rc<Cell<TimePoint>>);
impl Clock for ManualClock {
    fn now(&self) -> TimePoint {
        self.0.get()
    }
}
impl ManualClock {
    fn new() -> Self {
        Self(Rc::new(Cell::new(TimePoint {
            elapsed: Duration::ZERO,
            wall: UNIX_EPOCH + Duration::from_secs(1000),
        })))
    }
    fn advance(&self, seconds: u64) {
        let old = self.now();
        self.0.set(TimePoint {
            elapsed: old.elapsed + Duration::from_secs(seconds),
            wall: old.wall + Duration::from_secs(seconds),
        });
    }
}

struct Fake {
    ticks: CpuTicks,
    interfaces: Vec<InterfaceCounters>,
    cpu_error: bool,
    network_error: bool,
    bad_memory: bool,
    calls: Rc<RefCell<Vec<&'static str>>>,
    slow_calls: Rc<Cell<usize>>,
    top_calls: Rc<Cell<usize>>,
    cancel_after_cpu: Option<Cancellation>,
    top_rows: Vec<ProcessTopCounters>,
    top_collection: ProcessTopCollection,
    top_error: bool,
}

impl Fake {
    fn new() -> Self {
        Self {
            ticks: CpuTicks {
                user: 100,
                system: 100,
                idle: 800,
                nice: 0,
            },
            interfaces: vec![InterfaceCounters {
                index: 1,
                name: "en0".into(),
                up: true,
                received_bytes: 1000,
                transmitted_bytes: 500,
            }],
            cpu_error: false,
            network_error: false,
            bad_memory: false,
            calls: Rc::new(RefCell::new(Vec::new())),
            slow_calls: Rc::new(Cell::new(0)),
            top_calls: Rc::new(Cell::new(0)),
            cancel_after_cpu: None,
            top_rows: vec![ProcessTopCounters {
                identity: ProcessIdentity {
                    pid: 1234,
                    start_unix_sec: 100,
                    start_unix_usec: 1,
                },
                name: "worker".into(),
                resident_bytes: 8192,
                total_cpu_time_ns: 5_000_000,
            }],
            top_collection: ProcessTopCollection {
                visible_processes: 42,
                candidate_cap: 65_536,
                probe_cap: 4096,
                probed: 12,
                denied: 1,
                disappeared: 2,
                invalid: 0,
                truncated: false,
                partial: false,
            },
            top_error: false,
        }
    }
    fn advance_counters(&mut self) {
        self.ticks.user += 20;
        self.ticks.system += 10;
        self.ticks.idle += 70;
        for interface in &mut self.interfaces {
            interface.received_bytes += 1024;
            interface.transmitted_bytes += 512;
        }
        for row in &mut self.top_rows {
            row.total_cpu_time_ns += 100_000_000;
            row.resident_bytes += 128;
        }
    }
}
impl Provider for Fake {
    fn cpu(&mut self) -> io::Result<CpuTicks> {
        self.calls.borrow_mut().push("cpu");
        if let Some(cancel) = &self.cancel_after_cpu {
            cancel.cancel();
        }
        if self.cpu_error {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "injected CPU refusal",
            ))
        } else {
            Ok(self.ticks.clone())
        }
    }
    fn memory(&mut self) -> io::Result<Memory> {
        self.calls.borrow_mut().push("memory");
        Ok(Memory {
            physical_bytes: if self.bad_memory { 0 } else { 1000 },
            page_size: 1,
            active_bytes: 200,
            inactive_bytes: 400,
            wired_bytes: 100,
            free_bytes: 250,
            compressor_bytes: 50,
            speculative_bytes: 10,
            purgeable_bytes: 20,
            working_set_percent: f64::NAN,
        })
    }
    fn network(&mut self) -> io::Result<Vec<InterfaceCounters>> {
        self.calls.borrow_mut().push("network");
        if self.network_error {
            Err(io::Error::other("injected network failure"))
        } else {
            Ok(self.interfaces.clone())
        }
    }
    fn sampler(&mut self) -> io::Result<ProcessCounters> {
        Ok(ProcessCounters {
            cpu_time_ns: self.ticks.user * 1000,
            resident_bytes: 4096,
        })
    }
    fn disk(&mut self) -> io::Result<Disk> {
        self.slow_calls.set(self.slow_calls.get() + 1);
        Ok(Disk {
            total_bytes: 1000,
            free_bytes: 400,
            available_bytes: 300,
        })
    }
    fn processes(&mut self) -> io::Result<u64> {
        Ok(42)
    }
    fn processes_top(
        &mut self,
        _: usize,
        _: ProcessTopSort,
        _: usize,
        _: u64,
    ) -> io::Result<ProcessTopSnapshot> {
        self.top_calls.set(self.top_calls.get() + 1);
        if self.top_error {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "injected top refusal",
            ));
        }
        Ok(ProcessTopSnapshot {
            rows: self.top_rows.clone(),
            collection: self.top_collection.clone(),
        })
    }
    fn power(&mut self) -> io::Result<Power> {
        Ok(Power {
            on_ac: true,
            battery_percent: None,
            charging: None,
        })
    }
    fn thermal(&mut self) -> io::Result<Thermal> {
        Ok(Thermal::Nominal)
    }
}

fn setup() -> (Sampler<Fake, ManualClock>, ManualClock) {
    let clock = ManualClock::new();
    (
        Sampler::with_clock(Fake::new(), Config::default(), clock.clone()).unwrap(),
        clock,
    )
}

fn tick(sampler: &mut Sampler<Fake, ManualClock>, clock: &ManualClock) -> Snapshot {
    sampler.provider.advance_counters();
    clock.advance(1);
    sampler.sample(&Cancellation::default()).unwrap()
}

#[test]
fn first_sample_warms_then_rates_and_memory_units_are_explicit() {
    let (mut sampler, clock) = setup();
    let first = sampler.sample(&Cancellation::default()).unwrap();
    assert_eq!(first.cpu.state, State::WarmingUp);
    assert!(first.cpu.value.is_none());
    assert!(
        first.network.value.unwrap()[0]
            .received_bytes_per_second
            .is_none()
    );
    let second = tick(&mut sampler, &clock);
    assert_eq!(second.cpu.value.as_ref().unwrap().busy_percent, 30.0);
    assert_eq!(second.cpu.value.as_ref().unwrap().window_ms, 1000);
    assert_eq!(
        second.memory.value.as_ref().unwrap().working_set_percent,
        35.0
    );
    assert_eq!(
        second.network.value.as_ref().unwrap()[0].received_bytes_per_second,
        Some(1024.0)
    );
    assert_eq!(second.disk.age_ms, Some(1000));
}

#[test]
fn repeated_cpu_counters_do_not_refresh_or_destroy_the_last_measurement() {
    let (mut sampler, clock) = setup();
    sampler.sample(&Cancellation::default()).unwrap();
    let measured = tick(&mut sampler, &clock);
    clock.advance(1);
    let cached = sampler.sample(&Cancellation::default()).unwrap();
    assert_eq!(cached.cpu.state, State::Fresh);
    assert_eq!(cached.cpu.observed_unix_ms, measured.cpu.observed_unix_ms);
    assert_eq!(cached.cpu.age_ms, Some(1000));
    assert_eq!(cached.cpu.value.as_ref().unwrap().busy_percent, 30.0);
    let next = tick(&mut sampler, &clock);
    assert_eq!(next.cpu.value.as_ref().unwrap().window_ms, 2000);
    let mut aged = next;
    aged.age_by(Duration::from_secs(4), &Config::default())
        .unwrap();
    assert_eq!(aged.cpu.state, State::Stale);
}

#[test]
fn duplicate_cpu_polling_past_expiry_never_shortens_the_next_counter_window() {
    let clock = ManualClock::new();
    let config = Config {
        interval: Duration::from_millis(250),
        ..Config::default()
    };
    let mut sampler = Sampler::with_clock(Fake::new(), config, clock.clone()).unwrap();
    let advance = || {
        let old = clock.now();
        clock.0.set(TimePoint {
            elapsed: old.elapsed + Duration::from_millis(250),
            wall: old.wall + Duration::from_millis(250),
        });
    };
    sampler.sample(&Cancellation::default()).unwrap();
    advance();
    sampler.provider.advance_counters();
    let original = sampler.sample(&Cancellation::default()).unwrap();
    for _ in 0..4 {
        advance();
        let duplicate = sampler.sample(&Cancellation::default()).unwrap();
        assert_eq!(
            duplicate.cpu.observed_unix_ms,
            original.cpu.observed_unix_ms
        );
        assert_eq!(duplicate.cpu.value.as_ref().unwrap().window_ms, 250);
    }
    let stale = sampler.sample(&Cancellation::default()).unwrap();
    assert_eq!(stale.cpu.state, State::Stale);
    assert_eq!(stale.cpu.age_ms, Some(1000));
    advance();
    sampler.provider.advance_counters();
    let reset = sampler.sample(&Cancellation::default()).unwrap();
    assert_eq!(reset.cpu.state, State::WarmingUp);
    assert!(reset.cpu.value.is_none());
    assert_eq!(
        reset.cpu.error.as_ref().unwrap().code,
        "invalid_counter_window"
    );
    assert_eq!(reset.alerts[0].state, "unknown");
    advance();
    sampler.provider.advance_counters();
    let resumed = sampler.sample(&Cancellation::default()).unwrap();
    assert_eq!(resumed.cpu.state, State::Fresh);
    assert_eq!(resumed.cpu.value.as_ref().unwrap().window_ms, 250);
}

#[test]
fn failed_refresh_preserves_only_stale_data_and_never_clears_alerts() {
    let (mut sampler, clock) = setup();
    sampler.sample(&Cancellation::default()).unwrap();
    tick(&mut sampler, &clock);
    sampler.provider.cpu_error = true;
    sampler.provider.network_error = true;
    let result = tick(&mut sampler, &clock);
    assert_eq!(result.cpu.state, State::Stale);
    assert_eq!(result.cpu.value.as_ref().unwrap().busy_percent, 30.0);
    assert_eq!(result.cpu.error.as_ref().unwrap().code, "permission_denied");
    assert_eq!(result.network.state, State::Stale);
    assert_eq!(
        result.network.value.as_ref().unwrap()[0].rate_state,
        State::Stale
    );
    assert_eq!(result.alerts[0].state, "unknown");
    assert_eq!(result.exit_code(), 3);
}

#[test]
fn reader_ages_stalled_snapshots_instead_of_showing_fresh_forever() {
    let (mut sampler, clock) = setup();
    sampler.sample(&Cancellation::default()).unwrap();
    let mut result = tick(&mut sampler, &clock);
    result
        .age_by(Duration::from_secs(4), &Config::default())
        .unwrap();
    assert_eq!(result.cpu.state, State::Stale);
    assert_eq!(
        result.network.value.as_ref().unwrap()[0].rate_state,
        State::Stale
    );
    assert_eq!(result.disk.state, State::Fresh);
    assert_eq!(result.alerts[0].state, "unknown");
}

#[test]
fn counter_decreases_and_long_gaps_reset_without_spikes_or_zero() {
    let (mut sampler, clock) = setup();
    sampler.sample(&Cancellation::default()).unwrap();
    tick(&mut sampler, &clock);
    sampler.provider.ticks.user = 1;
    sampler.provider.interfaces[0].received_bytes = 1;
    clock.advance(1);
    let reset = sampler.sample(&Cancellation::default()).unwrap();
    assert_eq!(reset.cpu.state, State::WarmingUp);
    assert!(reset.cpu.value.is_none());
    assert!(
        reset.network.value.as_ref().unwrap()[0]
            .received_bytes_per_second
            .is_none()
    );
    tick(&mut sampler, &clock);
    clock.advance(10);
    sampler.provider.advance_counters();
    let gap = sampler.sample(&Cancellation::default()).unwrap();
    assert_eq!(gap.cpu.state, State::WarmingUp);
    assert!(
        gap.network.value.as_ref().unwrap()[0]
            .received_bytes_per_second
            .is_none()
    );
}

#[test]
fn interfaces_are_bounded_unique_and_returning_interfaces_warm_again() {
    let (mut sampler, clock) = setup();
    sampler.sample(&Cancellation::default()).unwrap();
    sampler.provider.interfaces.clear();
    assert!(tick(&mut sampler, &clock).network.value.unwrap().is_empty());
    sampler.provider.interfaces = Fake::new().interfaces;
    assert_eq!(
        tick(&mut sampler, &clock).network.value.unwrap()[0].rate_state,
        State::WarmingUp
    );
    let mut duplicate = sampler.provider.interfaces[0].clone();
    duplicate.name = "other-name".into();
    sampler.provider.interfaces.push(duplicate);
    assert_eq!(tick(&mut sampler, &clock).network.state, State::Stale);
}

#[test]
fn slow_probes_respect_cadence_and_cancellation_stops_new_probes() {
    let (mut sampler, clock) = setup();
    sampler.sample(&Cancellation::default()).unwrap();
    for _ in 0..4 {
        tick(&mut sampler, &clock);
    }
    assert_eq!(sampler.provider.slow_calls.get(), 1);
    tick(&mut sampler, &clock);
    assert_eq!(sampler.provider.slow_calls.get(), 2);
    let cancel = Cancellation::default();
    sampler.provider.calls.borrow_mut().clear();
    sampler.provider.cancel_after_cpu = Some(cancel.clone());
    assert_eq!(
        sampler.sample(&cancel).unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(*sampler.provider.calls.borrow(), ["cpu"]);
}

#[test]
fn invalid_native_values_and_clocks_are_not_success_shaped_defaults() {
    let (mut sampler, clock) = setup();
    sampler.provider.bad_memory = true;
    let first = sampler.sample(&Cancellation::default()).unwrap();
    assert_eq!(first.memory.state, State::Unavailable);
    assert!(first.memory.value.is_none());
    assert!(first.temperature_celsius.value.is_none());
    assert_eq!(first.temperature_celsius.state, State::Unsupported);
    clock.advance(1);
    sampler.sample(&Cancellation::default()).unwrap();
    clock.0.set(TimePoint {
        elapsed: Duration::ZERO,
        wall: UNIX_EPOCH,
    });
    assert!(sampler.sample(&Cancellation::default()).is_err());
    let config = Config {
        cpu_warning_percent: f64::NAN,
        ..Config::default()
    };
    assert!(config.validate().is_err());
    let config = Config {
        interval: Duration::from_millis(249),
        ..Config::default()
    };
    assert!(config.validate().is_err());
}

#[test]
fn json_shapes_have_null_unsupported_values_and_current_threshold_states() {
    let (mut sampler, clock) = setup();
    sampler.config.cpu_warning_percent = 20.0;
    sampler.sample(&Cancellation::default()).unwrap();
    let snapshot = tick(&mut sampler, &clock);
    assert_eq!(snapshot.alerts[0].state, "active");
    let value = serde_json::to_value(snapshot).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["cpu"]["state"], "fresh");
    assert_eq!(value["gpu_utilization_percent"]["state"], "unsupported");
    assert!(value["gpu_utilization_percent"]["value"].is_null());
    assert_eq!(value["process_top"]["state"], "unsupported");
    assert!(value["process_top"]["value"].is_null());
    assert!(value["power"]["value"]["battery_percent"].is_null());
    assert_eq!(value["sequence"], 2);
}

#[test]
fn process_top_is_opt_in_and_disabled_by_default() {
    let (mut sampler, clock) = setup();
    sampler.sample(&Cancellation::default()).unwrap();
    let snapshot = tick(&mut sampler, &clock);
    assert_eq!(snapshot.process_top.state, State::Unsupported);
    assert_eq!(sampler.provider.top_calls.get(), 0);
}

#[test]
fn process_top_collects_on_slow_cadence_and_warms_then_rates() {
    let clock = ManualClock::new();
    let config = Config {
        process_top: Some(ProcessTopConfig {
            limit: 4,
            sort: ProcessTopSort::Cpu,
        }),
        ..Config::default()
    };
    let mut sampler = Sampler::with_clock(Fake::new(), config, clock.clone()).unwrap();
    let first = sampler.sample(&Cancellation::default()).unwrap();
    assert_eq!(first.process_top.state, State::Fresh);
    assert_eq!(sampler.provider.top_calls.get(), 1);
    assert_eq!(
        first.process_top.value.as_ref().unwrap().rows[0].state,
        State::WarmingUp
    );
    sampler.provider.advance_counters();
    clock.advance(5);
    let second = sampler.sample(&Cancellation::default()).unwrap();
    assert_eq!(sampler.provider.top_calls.get(), 2);
    let top = second.process_top.value.unwrap();
    assert_eq!(top.rows.len(), 1);
    assert!(top.rows[0].cpu_percent_one_core.unwrap() > 0.0);
    assert_eq!(top.rows[0].cpu_window_ms, Some(5000));
}

#[test]
fn process_top_pid_reuse_and_counter_decrease_reset_cpu_rate() {
    let clock = ManualClock::new();
    let config = Config {
        process_top: Some(ProcessTopConfig {
            limit: 4,
            sort: ProcessTopSort::Cpu,
        }),
        ..Config::default()
    };
    let mut sampler = Sampler::with_clock(Fake::new(), config, clock.clone()).unwrap();
    sampler.sample(&Cancellation::default()).unwrap();
    sampler.provider.advance_counters();
    clock.advance(5);
    let rated = sampler.sample(&Cancellation::default()).unwrap();
    assert!(
        rated.process_top.value.unwrap().rows[0]
            .cpu_percent_one_core
            .unwrap()
            > 0.0
    );
    sampler.provider.top_rows[0].identity.start_unix_usec += 1;
    sampler.provider.advance_counters();
    clock.advance(5);
    let reused = sampler.sample(&Cancellation::default()).unwrap();
    let row = &reused.process_top.value.unwrap().rows[0];
    assert!(row.cpu_percent_one_core.is_none());
    assert_eq!(row.reason.as_deref(), Some("first_sample"));
    sampler.provider.top_rows[0].total_cpu_time_ns = 1;
    clock.advance(5);
    let decreased = sampler.sample(&Cancellation::default()).unwrap();
    let row = &decreased.process_top.value.unwrap().rows[0];
    assert!(row.cpu_percent_one_core.is_none());
    assert_eq!(row.reason.as_deref(), Some("counter_decreased"));
}

#[test]
fn process_top_sorting_keeps_known_cpu_before_unknown_and_respects_memory_mode() {
    let clock = ManualClock::new();
    let mut fake = Fake::new();
    fake.top_rows = vec![
        ProcessTopCounters {
            identity: ProcessIdentity {
                pid: 1,
                start_unix_sec: 100,
                start_unix_usec: 1,
            },
            name: "zeta".into(),
            resident_bytes: 1024,
            total_cpu_time_ns: 1_000_000,
        },
        ProcessTopCounters {
            identity: ProcessIdentity {
                pid: 2,
                start_unix_sec: 100,
                start_unix_usec: 2,
            },
            name: "alpha".into(),
            resident_bytes: 2048,
            total_cpu_time_ns: 2_000_000,
        },
    ];
    let config = Config {
        process_top: Some(ProcessTopConfig {
            limit: 4,
            sort: ProcessTopSort::Cpu,
        }),
        ..Config::default()
    };
    let mut sampler = Sampler::with_clock(fake, config, clock.clone()).unwrap();
    sampler.sample(&Cancellation::default()).unwrap();
    sampler.provider.top_rows[0].total_cpu_time_ns += 50_000_000;
    clock.advance(5);
    let cpu_sorted = sampler.sample(&Cancellation::default()).unwrap();
    let rows = cpu_sorted.process_top.value.unwrap().rows;
    assert_eq!(rows[0].pid, 1);
    assert!(rows[0].cpu_percent_one_core.is_some());
    assert_eq!(rows[1].cpu_percent_one_core, Some(0.0));
    sampler.config.process_top = Some(ProcessTopConfig {
        limit: 4,
        sort: ProcessTopSort::Memory,
    });
    clock.advance(5);
    let memory_sorted = sampler.sample(&Cancellation::default()).unwrap();
    let rows = memory_sorted.process_top.value.unwrap().rows;
    assert_eq!(rows[0].pid, 2);
}

#[test]
fn process_top_failure_breaks_continuity_until_second_renewed_generation() {
    let clock = ManualClock::new();
    let config = Config {
        process_top: Some(ProcessTopConfig {
            limit: 4,
            sort: ProcessTopSort::Cpu,
        }),
        ..Config::default()
    };
    let mut sampler = Sampler::with_clock(Fake::new(), config, clock.clone()).unwrap();
    sampler.sample(&Cancellation::default()).unwrap();
    sampler.provider.advance_counters();
    clock.advance(5);
    let first_rate = sampler.sample(&Cancellation::default()).unwrap();
    let row = &first_rate.process_top.value.as_ref().unwrap().rows[0];
    assert!(row.cpu_percent_one_core.is_some());
    assert_eq!(row.cpu_window_ms, Some(5000));

    sampler.provider.top_error = true;
    clock.advance(5);
    let failed = sampler.sample(&Cancellation::default()).unwrap();
    assert_eq!(failed.process_top.state, State::Stale);
    assert_eq!(
        failed
            .process_top
            .error
            .as_ref()
            .map(|error| error.code.as_str()),
        Some("permission_denied")
    );

    sampler.provider.top_error = false;
    sampler.provider.advance_counters();
    clock.advance(5);
    let after_failure = sampler.sample(&Cancellation::default()).unwrap();
    let row = &after_failure.process_top.value.as_ref().unwrap().rows[0];
    assert!(row.cpu_percent_one_core.is_none());
    assert!(row.cpu_window_ms.is_none());
    assert_eq!(row.reason.as_deref(), Some("first_sample"));

    sampler.provider.advance_counters();
    clock.advance(5);
    let renewed = sampler.sample(&Cancellation::default()).unwrap();
    let row = &renewed.process_top.value.as_ref().unwrap().rows[0];
    assert!(row.cpu_percent_one_core.unwrap() >= 0.0);
    assert_eq!(row.cpu_window_ms, Some(5000));
}

#[test]
fn process_top_missing_rows_reset_identity_baseline_and_keep_partial_metadata() {
    let clock = ManualClock::new();
    let config = Config {
        process_top: Some(ProcessTopConfig {
            limit: 4,
            sort: ProcessTopSort::Cpu,
        }),
        ..Config::default()
    };
    let mut fake = Fake::new();
    fake.top_rows.push(ProcessTopCounters {
        identity: ProcessIdentity {
            pid: 4321,
            start_unix_sec: 101,
            start_unix_usec: 2,
        },
        name: "helper".into(),
        resident_bytes: 4096,
        total_cpu_time_ns: 9_000_000,
    });
    fake.top_collection.partial = true;
    let mut sampler = Sampler::with_clock(fake, config, clock.clone()).unwrap();
    sampler.sample(&Cancellation::default()).unwrap();
    sampler.provider.advance_counters();
    clock.advance(5);
    let initial = sampler.sample(&Cancellation::default()).unwrap();
    assert_eq!(initial.process_top.value.as_ref().unwrap().rows.len(), 2);

    sampler
        .provider
        .top_rows
        .retain(|row| row.identity.pid != 4321);
    sampler.provider.advance_counters();
    clock.advance(5);
    let missing = sampler.sample(&Cancellation::default()).unwrap();
    assert_eq!(missing.process_top.value.as_ref().unwrap().rows.len(), 1);
    assert!(missing.process_top.value.as_ref().unwrap().partial);

    sampler.provider.top_rows.push(ProcessTopCounters {
        identity: ProcessIdentity {
            pid: 4321,
            start_unix_sec: 101,
            start_unix_usec: 2,
        },
        name: "helper".into(),
        resident_bytes: 4500,
        total_cpu_time_ns: 10_000_000,
    });
    sampler.provider.advance_counters();
    clock.advance(5);
    let reappeared = sampler.sample(&Cancellation::default()).unwrap();
    let helper = reappeared
        .process_top
        .value
        .as_ref()
        .unwrap()
        .rows
        .iter()
        .find(|row| row.pid == 4321)
        .unwrap();
    assert!(helper.cpu_percent_one_core.is_none());
    assert_eq!(helper.reason.as_deref(), Some("first_sample"));
}
