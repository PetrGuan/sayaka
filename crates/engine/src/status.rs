// SPDX-License-Identifier: MPL-2.0

//! Read-only system sampling with explicit counter windows and stale evidence.

use crate::model::Cancellation;
use serde::Serialize;
use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static NEXT_SAMPLER: AtomicU64 = AtomicU64::new(1);
const PROCESS_TOP_PROBE_CAP: usize = 4096;
const PROCESS_TOP_COLLECTION_BUDGET_MS: u64 = 100;

#[derive(Clone, Debug)]
pub struct Config {
    pub interval: Duration,
    pub cpu_warning_percent: f64,
    pub memory_warning_percent: f64,
    pub disk_available_warning_percent: f64,
    pub process_top: Option<ProcessTopConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(1),
            cpu_warning_percent: 90.0,
            memory_warning_percent: 90.0,
            disk_available_warning_percent: 10.0,
            process_top: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessTopSort {
    Cpu,
    Memory,
}

#[derive(Clone, Debug)]
pub struct ProcessTopConfig {
    pub limit: usize,
    pub sort: ProcessTopSort,
}

impl Config {
    pub fn validate(&self) -> io::Result<()> {
        if !(Duration::from_millis(250)..=Duration::from_secs(60)).contains(&self.interval)
            || [
                self.cpu_warning_percent,
                self.memory_warning_percent,
                self.disk_available_warning_percent,
            ]
            .iter()
            .any(|value| !value.is_finite() || !(0.0..=100.0).contains(value))
            || self
                .process_top
                .as_ref()
                .is_some_and(|top| !(1..=32).contains(&top.limit))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "interval must be 250..60000 ms, thresholds finite percentages in 0..100, and top limit in 1..=32",
            ));
        }
        Ok(())
    }
    pub fn slow_interval(&self) -> Duration {
        self.interval.max(Duration::from_secs(5))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct TimePoint {
    pub elapsed: Duration,
    pub wall: SystemTime,
}

pub trait Clock {
    fn now(&self) -> TimePoint;
}

pub struct LiveClock {
    origin: Instant,
}
impl Default for LiveClock {
    fn default() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}
impl Clock for LiveClock {
    fn now(&self) -> TimePoint {
        TimePoint {
            elapsed: self.origin.elapsed(),
            wall: SystemTime::now(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Fresh,
    WarmingUp,
    Stale,
    Unavailable,
    Unsupported,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MetricError {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Metric<T> {
    pub value: Option<T>,
    pub state: State,
    pub source: &'static str,
    pub observed_unix_ms: Option<u64>,
    pub age_ms: Option<u64>,
    pub max_age_ms: u64,
    pub error: Option<MetricError>,
}

impl<T> Metric<T> {
    fn age_by(&mut self, elapsed: u64) {
        if let Some(age) = self.age_ms {
            self.age_ms = age.checked_add(elapsed);
            if self.age_ms.is_none_or(|age| age > self.max_age_ms)
                && matches!(self.state, State::Fresh | State::WarmingUp)
            {
                self.state = State::Stale;
                self.error = Some(MetricError {
                    code: "expired".into(),
                    message: "the latest observation exceeded its freshness budget".into(),
                });
            }
        }
    }
    pub fn is_fresh(&self) -> bool {
        self.state == State::Fresh && self.value.is_some()
    }
}

#[derive(Clone, Debug)]
struct Cache<T> {
    value: Option<T>,
    observed: Option<TimePoint>,
    state: State,
    error: Option<MetricError>,
}

#[derive(Clone, Debug)]
struct ProcessCpuBaseline {
    total_cpu_time_ns: u64,
    observed: TimePoint,
}

impl<T: Clone> Cache<T> {
    fn new() -> Self {
        Self {
            value: None,
            observed: None,
            state: State::Unavailable,
            error: Some(reason("not_sampled", "no observation yet")),
        }
    }
    fn update(&mut self, result: io::Result<T>, now: TimePoint) {
        match result {
            Ok(value) => {
                self.value = Some(value);
                self.observed = Some(now);
                self.state = State::Fresh;
                self.error = None;
            }
            Err(error) => {
                let unsupported = error.kind() == io::ErrorKind::Unsupported;
                if unsupported {
                    self.value = None;
                    self.observed = None;
                }
                self.state = if unsupported {
                    State::Unsupported
                } else if self.value.is_some() {
                    State::Stale
                } else {
                    State::Unavailable
                };
                self.error = Some(reason(io_code(error.kind()), &error.to_string()));
            }
        }
    }
    fn warming(&mut self, now: TimePoint, code: &str) {
        self.value = None;
        self.observed = Some(now);
        self.state = State::WarmingUp;
        self.error = Some(reason(code, "a new valid counter interval is required"));
    }
    fn metric(&self, now: TimePoint, source: &'static str, ttl: Duration) -> Metric<T> {
        let mut result = Metric {
            value: self.value.clone(),
            state: self.state,
            source,
            observed_unix_ms: self.observed.and_then(|time| unix_ms(time.wall)),
            age_ms: self
                .observed
                .and_then(|time| now.elapsed.checked_sub(time.elapsed))
                .and_then(milliseconds),
            max_age_ms: milliseconds(ttl).expect("bounded configured duration"),
            error: self.error.clone(),
        };
        result.age_by(0);
        result
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CpuTicks {
    pub user: u64,
    pub system: u64,
    pub idle: u64,
    pub nice: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct Cpu {
    pub busy_percent: f64,
    pub window_ms: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct Memory {
    pub physical_bytes: u64,
    pub page_size: u64,
    pub active_bytes: u64,
    pub inactive_bytes: u64,
    pub wired_bytes: u64,
    pub free_bytes: u64,
    pub compressor_bytes: u64,
    pub speculative_bytes: u64,
    pub purgeable_bytes: u64,
    pub working_set_percent: f64,
}
#[derive(Clone, Debug)]
pub struct InterfaceCounters {
    pub index: u32,
    pub name: String,
    pub up: bool,
    pub received_bytes: u64,
    pub transmitted_bytes: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct Interface {
    pub index: u32,
    pub name: String,
    pub up: bool,
    pub received_bytes: u64,
    pub transmitted_bytes: u64,
    pub received_bytes_per_second: Option<f64>,
    pub transmitted_bytes_per_second: Option<f64>,
    pub window_ms: Option<u64>,
    pub rate_state: State,
    pub rate_reason: Option<String>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Disk {
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub available_bytes: u64,
}
#[derive(Clone, Debug)]
pub struct ProcessCounters {
    pub cpu_time_ns: u64,
    pub resident_bytes: u64,
}
#[derive(Clone, Debug)]
pub struct ProcessTopCounters {
    pub identity: ProcessIdentity,
    pub name: String,
    pub resident_bytes: u64,
    pub total_cpu_time_ns: u64,
}
#[derive(Clone, Debug)]
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
#[derive(Clone, Debug)]
pub struct ProcessTopSnapshot {
    pub rows: Vec<ProcessTopCounters>,
    pub collection: ProcessTopCollection,
}
#[derive(Clone, Debug, Serialize)]
pub struct SamplerProcess {
    pub cpu_time_ns: u64,
    pub resident_bytes: u64,
    pub cpu_percent_one_core: Option<f64>,
    pub window_ms: Option<u64>,
}
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_unix_sec: u64,
    pub start_unix_usec: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct ProcessTopRow {
    pub pid: u32,
    pub name: String,
    pub identity: ProcessIdentity,
    pub resident_bytes: u64,
    pub cpu_percent_one_core: Option<f64>,
    pub cpu_window_ms: Option<u64>,
    pub state: State,
    pub reason: Option<String>,
}
#[derive(Clone, Debug, Serialize)]
pub struct ProcessTop {
    pub top_schema_version: u32,
    pub sort: ProcessTopSort,
    pub limit: usize,
    pub visible_processes: u64,
    pub candidate_cap: usize,
    pub probe_cap: usize,
    pub collection_budget_ms: u64,
    pub probed: usize,
    pub denied: usize,
    pub disappeared: usize,
    pub invalid: usize,
    pub truncated: bool,
    pub partial: bool,
    pub rows: Vec<ProcessTopRow>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Power {
    pub on_ac: bool,
    pub battery_percent: Option<f64>,
    pub charging: Option<bool>,
}
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Thermal {
    Nominal,
    Fair,
    Serious,
    Critical,
}

/// Providers return native facts or errors, never availability inferred from zero.
pub trait Provider {
    fn cpu(&mut self) -> io::Result<CpuTicks>;
    fn memory(&mut self) -> io::Result<Memory>;
    fn network(&mut self) -> io::Result<Vec<InterfaceCounters>>;
    fn sampler(&mut self) -> io::Result<ProcessCounters>;
    fn disk(&mut self) -> io::Result<Disk>;
    fn processes(&mut self) -> io::Result<u64>;
    fn processes_top(
        &mut self,
        limit: usize,
        sort: ProcessTopSort,
        probe_cap: usize,
        collection_budget_ms: u64,
    ) -> io::Result<ProcessTopSnapshot>;
    fn power(&mut self) -> io::Result<Power>;
    fn thermal(&mut self) -> io::Result<Thermal>;
}

#[derive(Clone, Debug, Serialize)]
pub struct Alert {
    pub metric: &'static str,
    pub state: &'static str,
    pub threshold_percent: f64,
    pub observed_percent: Option<f64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Snapshot {
    pub schema_version: u32,
    pub sampler_id: String,
    pub sequence: u64,
    pub observed_unix_ms: Option<u64>,
    pub elapsed_ms: u64,
    pub interval_ms: u64,
    pub slow_interval_ms: u64,
    pub collection_ms: u64,
    pub coalesced_samples: u64,
    pub clock_error: Option<MetricError>,
    pub cpu: Metric<Cpu>,
    pub memory: Metric<Memory>,
    pub network: Metric<Vec<Interface>>,
    pub disk: Metric<Disk>,
    pub sampler_process: Metric<SamplerProcess>,
    pub visible_processes: Metric<u64>,
    pub power: Metric<Power>,
    pub thermal_state: Metric<Thermal>,
    pub temperature_celsius: Metric<f64>,
    pub gpu_utilization_percent: Metric<f64>,
    pub process_top: Metric<ProcessTop>,
    pub alerts: Vec<Alert>,
}

impl Snapshot {
    pub fn age_by(&mut self, elapsed: Duration, config: &Config) -> io::Result<()> {
        let elapsed = milliseconds(elapsed).ok_or_else(|| invalid("age overflow"))?;
        self.cpu.age_by(elapsed);
        self.memory.age_by(elapsed);
        self.network.age_by(elapsed);
        self.disk.age_by(elapsed);
        self.sampler_process.age_by(elapsed);
        self.visible_processes.age_by(elapsed);
        self.power.age_by(elapsed);
        self.thermal_state.age_by(elapsed);
        self.process_top.age_by(elapsed);
        self.age_network_rates();
        self.alerts = alerts(self, config);
        Ok(())
    }
    fn age_network_rates(&mut self) {
        if self.network.state == State::Stale
            && let Some(interfaces) = &mut self.network.value
        {
            for interface in interfaces {
                if interface.rate_state == State::Fresh {
                    interface.rate_state = State::Stale;
                    interface.rate_reason = Some("stale_interface_observation".into());
                }
            }
        }
    }
    /// Exit status concerns the primary measured surface, not optional capabilities.
    pub fn exit_code(&self) -> u8 {
        let states = [
            self.cpu.state,
            self.memory.state,
            self.network.state,
            self.disk.state,
        ];
        if states
            .iter()
            .all(|state| matches!(state, State::Unsupported | State::Unavailable))
        {
            1
        } else if self.clock_error.is_some()
            || states.iter().any(|state| {
                matches!(
                    state,
                    State::Stale | State::Unavailable | State::Unsupported
                )
            })
        {
            3
        } else {
            0
        }
    }
}

pub struct Sampler<P, C = LiveClock> {
    provider: P,
    clock: C,
    config: Config,
    id: String,
    sequence: u64,
    last_time: Option<Duration>,
    next_slow: Duration,
    cpu_baseline: Option<(CpuTicks, TimePoint)>,
    network_baselines: HashMap<(u32, String), (InterfaceCounters, TimePoint)>,
    process_baseline: Option<(ProcessCounters, TimePoint)>,
    process_top_baselines: HashMap<ProcessIdentity, ProcessCpuBaseline>,
    cpu: Cache<Cpu>,
    memory: Cache<Memory>,
    network: Cache<Vec<Interface>>,
    disk: Cache<Disk>,
    sampler: Cache<SamplerProcess>,
    processes: Cache<u64>,
    power: Cache<Power>,
    thermal: Cache<Thermal>,
    process_top: Cache<ProcessTop>,
}

impl<P: Provider> Sampler<P> {
    pub fn new(provider: P, config: Config) -> io::Result<Self> {
        Self::with_clock(provider, config, LiveClock::default())
    }
}

impl<P: Provider, C: Clock> Sampler<P, C> {
    pub fn with_clock(provider: P, config: Config, clock: C) -> io::Result<Self> {
        config.validate()?;
        let id = NEXT_SAMPLER
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| invalid("sampler identifiers exhausted"))?;
        Ok(Self {
            provider,
            clock,
            config,
            id: format!("{}:{id}", std::process::id()),
            sequence: 0,
            last_time: None,
            next_slow: Duration::ZERO,
            cpu_baseline: None,
            network_baselines: HashMap::new(),
            process_baseline: None,
            process_top_baselines: HashMap::new(),
            cpu: Cache::new(),
            memory: Cache::new(),
            network: Cache::new(),
            disk: Cache::new(),
            sampler: Cache::new(),
            processes: Cache::new(),
            power: Cache::new(),
            thermal: Cache::new(),
            process_top: Cache::new(),
        })
    }
    fn time(&mut self, cancellation: &Cancellation) -> io::Result<TimePoint> {
        if cancellation.is_cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "status sampling cancelled",
            ));
        }
        let now = self.clock.now();
        if self.last_time.is_some_and(|last| now.elapsed < last) {
            return Err(invalid("sampling clock regressed"));
        }
        self.last_time = Some(now.elapsed);
        Ok(now)
    }
    pub fn sample(&mut self, cancellation: &Cancellation) -> io::Result<Snapshot> {
        let started = self.time(cancellation)?;
        let cpu = self.provider.cpu();
        let now = self.time(cancellation)?;
        match cpu {
            Err(error) => self.cpu.update(Err(error), now),
            Ok(current) => {
                let rate =
                    self.cpu_baseline
                        .as_ref()
                        .ok_or("first_sample")
                        .and_then(|(old, stamp)| {
                            if &current == old {
                                return Err("no_tick_progress");
                            }
                            let window = valid_window(*stamp, now, self.config.interval)
                                .ok_or("invalid_counter_window")?;
                            let user = current
                                .user
                                .checked_sub(old.user)
                                .ok_or("counter_decreased")?;
                            let system = current
                                .system
                                .checked_sub(old.system)
                                .ok_or("counter_decreased")?;
                            let nice = current
                                .nice
                                .checked_sub(old.nice)
                                .ok_or("counter_decreased")?;
                            let idle = current
                                .idle
                                .checked_sub(old.idle)
                                .ok_or("counter_decreased")?;
                            let busy = u128::from(user) + u128::from(system) + u128::from(nice);
                            let total = busy + u128::from(idle);
                            if total == 0 {
                                return Err("no_tick_progress");
                            }
                            Ok(Cpu {
                                busy_percent: busy as f64 * 100.0 / total as f64,
                                window_ms: window,
                            })
                        });
                let unchanged = matches!(rate, Err("no_tick_progress"));
                match rate {
                    Ok(rate) => self.cpu.update(Ok(rate), now),
                    Err("no_tick_progress") => {
                        // A cached native counter is not a new measurement.
                        // Retain both the last rate's timestamp and the baseline.
                        if self.cpu.value.is_none() {
                            self.cpu.error = Some(reason(
                                "no_tick_progress",
                                "native CPU counters have not advanced",
                            ));
                        }
                    }
                    Err(code) => self.cpu.warming(now, code),
                }
                if !unchanged {
                    self.cpu_baseline = Some((current, now));
                }
            }
        }
        let memory = self.provider.memory().and_then(validate_memory);
        let now = self.time(cancellation)?;
        self.memory.update(memory, now);
        let network = self.provider.network();
        let now = self.time(cancellation)?;
        match network {
            Err(error) => self.network.update(Err(error), now),
            Ok(entries) => {
                match network_values(entries, &self.network_baselines, now, self.config.interval) {
                    Ok((values, baselines)) => {
                        self.network.update(Ok(values), now);
                        self.network_baselines = baselines;
                    }
                    Err(error) => self.network.update(Err(error), now),
                }
            }
        }
        let process = self.provider.sampler().and_then(|value| {
            if value.resident_bytes == 0 {
                Err(invalid("sampler resident size is unavailable"))
            } else {
                Ok(value)
            }
        });
        let now = self.time(cancellation)?;
        match process {
            Err(error) => self.sampler.update(Err(error), now),
            Ok(current) => {
                let rate = self.process_baseline.as_ref().and_then(|(old, stamp)| {
                    let window = valid_window(*stamp, now, self.config.interval)?;
                    let delta = current.cpu_time_ns.checked_sub(old.cpu_time_ns)?;
                    Some((delta as f64 / (window as f64 * 1_000_000.0) * 100.0, window))
                });
                self.sampler.update(
                    Ok(SamplerProcess {
                        cpu_time_ns: current.cpu_time_ns,
                        resident_bytes: current.resident_bytes,
                        cpu_percent_one_core: rate.map(|(value, _)| value),
                        window_ms: rate.map(|(_, window)| window),
                    }),
                    now,
                );
                self.process_baseline = Some((current, now));
            }
        }
        if now.elapsed >= self.next_slow {
            let disk = self.provider.disk().and_then(validate_disk);
            let now = self.time(cancellation)?;
            self.disk.update(disk, now);
            let processes = self.provider.processes().and_then(|count| {
                if count == 0 || count > 65_536 {
                    Err(invalid(
                        "visible process count is outside its native budget",
                    ))
                } else {
                    Ok(count)
                }
            });
            let now = self.time(cancellation)?;
            self.processes.update(processes, now);
            if let Some(top) = self.config.process_top.clone() {
                let top_rows = self.provider.processes_top(
                    top.limit,
                    top.sort,
                    PROCESS_TOP_PROBE_CAP,
                    PROCESS_TOP_COLLECTION_BUDGET_MS,
                );
                let now = self.time(cancellation)?;
                let top_result = top_rows.and_then(|snapshot| {
                    build_process_top(
                        snapshot,
                        &top,
                        &mut self.process_top_baselines,
                        now,
                        self.config.slow_interval(),
                    )
                });
                if top_result.is_err() {
                    self.process_top_baselines.clear();
                }
                self.process_top.update(top_result, now);
            }
            let power = self.provider.power().and_then(validate_power);
            let now = self.time(cancellation)?;
            self.power.update(power, now);
            let thermal = self.provider.thermal();
            let now = self.time(cancellation)?;
            self.thermal.update(thermal, now);
            self.next_slow = now
                .elapsed
                .checked_add(self.config.slow_interval())
                .ok_or_else(|| invalid("slow deadline overflow"))?;
        }
        let now = self.time(cancellation)?;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| invalid("sample sequence exhausted"))?;
        let fast_ttl = self.config.interval * 3;
        let slow_ttl = self.config.slow_interval() * 2;
        let mut result = Snapshot {
            schema_version: 1,
            sampler_id: self.id.clone(),
            sequence: self.sequence,
            observed_unix_ms: unix_ms(now.wall),
            elapsed_ms: milliseconds(now.elapsed)
                .ok_or_else(|| invalid("elapsed time overflow"))?,
            interval_ms: milliseconds(self.config.interval).expect("validated interval"),
            slow_interval_ms: milliseconds(self.config.slow_interval())
                .expect("validated interval"),
            collection_ms: milliseconds(now.elapsed - started.elapsed)
                .ok_or_else(|| invalid("collection duration overflow"))?,
            coalesced_samples: 0,
            clock_error: unix_ms(now.wall).is_none().then(|| {
                reason(
                    "invalid_wall_clock",
                    "wall time cannot be represented as Unix milliseconds",
                )
            }),
            cpu: self
                .cpu
                .metric(now, "host_statistics/HOST_CPU_LOAD_INFO", fast_ttl),
            memory: self
                .memory
                .metric(now, "host_statistics64 + hw.memsize", fast_ttl),
            network: self.network.metric(
                now,
                "routing NET_RT_IFLIST2 interface counters",
                fast_ttl,
            ),
            disk: self.disk.metric(now, "statfs startup filesystem", slow_ttl),
            sampler_process: self.sampler.metric(
                now,
                "getrusage + Mach task information (self)",
                fast_ttl,
            ),
            visible_processes: self.processes.metric(
                now,
                "libproc visible process count",
                slow_ttl,
            ),
            power: self.power.metric(now, "IOPowerSources", slow_ttl),
            thermal_state: self
                .thermal
                .metric(now, "NSProcessInfo.thermalState", slow_ttl),
            temperature_celsius: unsupported(
                "no supported collector in this slice",
                "numeric temperature is not implemented; thermal state is separate",
            ),
            gpu_utilization_percent: unsupported(
                "no supported collector in this slice",
                "GPU utilization is not implemented",
            ),
            process_top: if self.config.process_top.is_some() {
                self.process_top
                    .metric(now, "libproc PROC_PIDTASKALLINFO", slow_ttl)
            } else {
                unsupported(
                    "disabled unless --top is requested",
                    "per-process top tables are opt-in because process names are sensitive local data",
                )
            },
            alerts: Vec::new(),
        };
        result.age_network_rates();
        result.alerts = alerts(&result, &self.config);
        Ok(result)
    }
}

type InterfaceBaselines = HashMap<(u32, String), (InterfaceCounters, TimePoint)>;
fn network_values(
    entries: Vec<InterfaceCounters>,
    previous: &InterfaceBaselines,
    now: TimePoint,
    interval: Duration,
) -> io::Result<(Vec<Interface>, InterfaceBaselines)> {
    if entries.len() > 128 {
        return Err(invalid("interface budget exceeded"));
    }
    let mut baselines = HashMap::new();
    let mut indices = std::collections::HashSet::new();
    let mut names = std::collections::HashSet::new();
    let mut values = Vec::with_capacity(entries.len());
    for entry in entries {
        if entry.name.is_empty() || entry.name.len() > 64 || entry.index == 0 {
            return Err(invalid("invalid interface identity"));
        }
        let key = (entry.index, entry.name.clone());
        if !indices.insert(entry.index) || !names.insert(entry.name.clone()) {
            return Err(invalid("duplicate interface identity"));
        }
        let rate = previous.get(&key).and_then(|(old, stamp)| {
            if !entry.up || !old.up {
                return None;
            }
            let window = valid_window(*stamp, now, interval)?;
            let received = entry.received_bytes.checked_sub(old.received_bytes)?;
            let transmitted = entry.transmitted_bytes.checked_sub(old.transmitted_bytes)?;
            Some((
                received as f64 * 1000.0 / window as f64,
                transmitted as f64 * 1000.0 / window as f64,
                window,
            ))
        });
        values.push(Interface {
            index: entry.index,
            name: entry.name.clone(),
            up: entry.up,
            received_bytes: entry.received_bytes,
            transmitted_bytes: entry.transmitted_bytes,
            received_bytes_per_second: rate.map(|(value, _, _)| value),
            transmitted_bytes_per_second: rate.map(|(_, value, _)| value),
            window_ms: rate.map(|(_, _, window)| window),
            rate_state: if rate.is_some() {
                State::Fresh
            } else {
                State::WarmingUp
            },
            rate_reason: rate.is_none().then(|| {
                if entry.up {
                    "new_or_discontinuous_counter_window"
                } else {
                    "interface_down"
                }
                .into()
            }),
        });
        baselines.insert(key, (entry, now));
    }
    values.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then(left.index.cmp(&right.index))
    });
    Ok((values, baselines))
}

fn build_process_top(
    snapshot: ProcessTopSnapshot,
    config: &ProcessTopConfig,
    baselines: &mut HashMap<ProcessIdentity, ProcessCpuBaseline>,
    now: TimePoint,
    slow_interval: Duration,
) -> io::Result<ProcessTop> {
    if snapshot.collection.probed == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no process candidates were probed",
        ));
    }
    let mut rows = Vec::with_capacity(snapshot.rows.len());
    let mut next = HashMap::new();
    for row in snapshot.rows {
        let rate = baselines
            .get(&row.identity)
            .ok_or("first_sample")
            .and_then(|old| {
                let window = valid_window(old.observed, now, slow_interval)
                    .ok_or("invalid_counter_window")?;
                let delta = row
                    .total_cpu_time_ns
                    .checked_sub(old.total_cpu_time_ns)
                    .ok_or("counter_decreased")?;
                Ok((delta as f64 / (window as f64 * 1_000_000.0) * 100.0, window))
            });
        rows.push(ProcessTopRow {
            pid: row.identity.pid,
            name: row.name,
            identity: row.identity.clone(),
            resident_bytes: row.resident_bytes,
            cpu_percent_one_core: rate.as_ref().ok().map(|(value, _)| *value),
            cpu_window_ms: rate.as_ref().ok().map(|(_, window)| *window),
            state: if rate.is_ok() {
                State::Fresh
            } else {
                State::WarmingUp
            },
            reason: rate.err().map(ToOwned::to_owned),
        });
        next.insert(
            row.identity,
            ProcessCpuBaseline {
                total_cpu_time_ns: row.total_cpu_time_ns,
                observed: now,
            },
        );
    }
    *baselines = next;
    rows.sort_by(|left, right| match config.sort {
        ProcessTopSort::Cpu => cmp_cpu_first(left, right),
        ProcessTopSort::Memory => cmp_memory_first(left, right),
    });
    if rows.len() > config.limit {
        rows.truncate(config.limit);
    }
    Ok(ProcessTop {
        top_schema_version: 1,
        sort: config.sort,
        limit: config.limit,
        visible_processes: snapshot.collection.visible_processes,
        candidate_cap: snapshot.collection.candidate_cap,
        probe_cap: snapshot.collection.probe_cap,
        collection_budget_ms: PROCESS_TOP_COLLECTION_BUDGET_MS,
        probed: snapshot.collection.probed,
        denied: snapshot.collection.denied,
        disappeared: snapshot.collection.disappeared,
        invalid: snapshot.collection.invalid,
        truncated: snapshot.collection.truncated,
        partial: snapshot.collection.partial,
        rows,
    })
}

fn cmp_cpu_first(left: &ProcessTopRow, right: &ProcessTopRow) -> std::cmp::Ordering {
    match (left.cpu_percent_one_core, right.cpu_percent_one_core) {
        (Some(a), Some(b)) => b
            .partial_cmp(&a)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(right.resident_bytes.cmp(&left.resident_bytes))
            .then(left.name.cmp(&right.name))
            .then(left.pid.cmp(&right.pid))
            .then(
                left.identity
                    .start_unix_sec
                    .cmp(&right.identity.start_unix_sec),
            )
            .then(
                left.identity
                    .start_unix_usec
                    .cmp(&right.identity.start_unix_usec),
            ),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => right
            .resident_bytes
            .cmp(&left.resident_bytes)
            .then(left.name.cmp(&right.name))
            .then(left.pid.cmp(&right.pid))
            .then(
                left.identity
                    .start_unix_sec
                    .cmp(&right.identity.start_unix_sec),
            )
            .then(
                left.identity
                    .start_unix_usec
                    .cmp(&right.identity.start_unix_usec),
            ),
    }
}

fn cmp_memory_first(left: &ProcessTopRow, right: &ProcessTopRow) -> std::cmp::Ordering {
    right
        .resident_bytes
        .cmp(&left.resident_bytes)
        .then_with(
            || match (left.cpu_percent_one_core, right.cpu_percent_one_core) {
                (Some(a), Some(b)) => b.partial_cmp(&a).unwrap_or(std::cmp::Ordering::Equal),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            },
        )
        .then(left.name.cmp(&right.name))
        .then(left.pid.cmp(&right.pid))
        .then(
            left.identity
                .start_unix_sec
                .cmp(&right.identity.start_unix_sec),
        )
        .then(
            left.identity
                .start_unix_usec
                .cmp(&right.identity.start_unix_usec),
        )
}

fn validate_memory(mut value: Memory) -> io::Result<Memory> {
    if value.physical_bytes == 0 || value.page_size == 0 {
        return Err(invalid("invalid physical memory/page size"));
    }
    let working = value
        .active_bytes
        .checked_add(value.wired_bytes)
        .and_then(|sum| sum.checked_add(value.compressor_bytes))
        .ok_or_else(|| invalid("working-set accounting overflow"))?;
    if working > value.physical_bytes || value.free_bytes > value.physical_bytes {
        return Err(invalid("inconsistent physical memory accounting"));
    }
    value.working_set_percent = working as f64 * 100.0 / value.physical_bytes as f64;
    Ok(value)
}
fn validate_disk(value: Disk) -> io::Result<Disk> {
    if value.total_bytes == 0
        || value.free_bytes > value.total_bytes
        || value.available_bytes > value.total_bytes
    {
        return Err(invalid("inconsistent startup filesystem accounting"));
    }
    Ok(value)
}
fn validate_power(value: Power) -> io::Result<Power> {
    if value
        .battery_percent
        .is_some_and(|value| !value.is_finite() || !(0.0..=100.0).contains(&value))
        || (value.battery_percent.is_none() && (value.charging.is_some() || !value.on_ac))
    {
        return Err(invalid("inconsistent battery information"));
    }
    Ok(value)
}
fn valid_window(old: TimePoint, now: TimePoint, interval: Duration) -> Option<u64> {
    let elapsed = now.elapsed.checked_sub(old.elapsed)?;
    if elapsed.is_zero() || elapsed > interval * 3 {
        return None;
    }
    milliseconds(elapsed).filter(|window| *window > 0)
}
fn alerts(snapshot: &Snapshot, config: &Config) -> Vec<Alert> {
    let values = [
        (
            "cpu_busy",
            config.cpu_warning_percent,
            snapshot
                .cpu
                .value
                .as_ref()
                .filter(|_| snapshot.cpu.is_fresh())
                .map(|cpu| cpu.busy_percent),
            false,
        ),
        (
            "memory_working_set",
            config.memory_warning_percent,
            snapshot
                .memory
                .value
                .as_ref()
                .filter(|_| snapshot.memory.is_fresh())
                .map(|memory| memory.working_set_percent),
            false,
        ),
        (
            "disk_available",
            config.disk_available_warning_percent,
            snapshot
                .disk
                .value
                .as_ref()
                .filter(|_| snapshot.disk.is_fresh())
                .map(|disk| disk.available_bytes as f64 * 100.0 / disk.total_bytes as f64),
            true,
        ),
    ];
    values
        .into_iter()
        .map(|(metric, threshold, value, low)| Alert {
            metric,
            threshold_percent: threshold,
            observed_percent: value,
            state: match value {
                None => "unknown",
                Some(value)
                    if if low {
                        value <= threshold
                    } else {
                        value >= threshold
                    } =>
                {
                    "active"
                }
                Some(_) => "clear",
            },
        })
        .collect()
}
fn unsupported<T>(source: &'static str, message: &str) -> Metric<T> {
    Metric {
        value: None,
        state: State::Unsupported,
        source,
        observed_unix_ms: None,
        age_ms: None,
        max_age_ms: 0,
        error: Some(reason("not_implemented", message)),
    }
}
fn reason(code: &str, message: &str) -> MetricError {
    MetricError {
        code: code.into(),
        message: message.into(),
    }
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn milliseconds(value: Duration) -> Option<u64> {
    u64::try_from(value.as_millis()).ok()
}
fn unix_ms(time: SystemTime) -> Option<u64> {
    time.duration_since(UNIX_EPOCH).ok().and_then(milliseconds)
}
fn io_code(kind: io::ErrorKind) -> &'static str {
    match kind {
        io::ErrorKind::Unsupported => "unsupported",
        io::ErrorKind::PermissionDenied => "permission_denied",
        io::ErrorKind::InvalidData => "invalid_native_data",
        io::ErrorKind::Interrupted => "interrupted",
        _ => "probe_failed",
    }
}

pub struct NativeProvider;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(target_os = "macos"))]
impl Provider for NativeProvider {
    fn cpu(&mut self) -> io::Result<CpuTicks> {
        Err(unsupported_platform())
    }
    fn memory(&mut self) -> io::Result<Memory> {
        Err(unsupported_platform())
    }
    fn network(&mut self) -> io::Result<Vec<InterfaceCounters>> {
        Err(unsupported_platform())
    }
    fn sampler(&mut self) -> io::Result<ProcessCounters> {
        Err(unsupported_platform())
    }
    fn disk(&mut self) -> io::Result<Disk> {
        Err(unsupported_platform())
    }
    fn processes(&mut self) -> io::Result<u64> {
        Err(unsupported_platform())
    }
    fn processes_top(
        &mut self,
        _: usize,
        _: ProcessTopSort,
        _: usize,
        _: u64,
    ) -> io::Result<ProcessTopSnapshot> {
        Err(unsupported_platform())
    }
    fn power(&mut self) -> io::Result<Power> {
        Err(unsupported_platform())
    }
    fn thermal(&mut self) -> io::Result<Thermal> {
        Err(unsupported_platform())
    }
}
#[cfg(not(target_os = "macos"))]
fn unsupported_platform() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "native status currently requires macOS",
    )
}

#[cfg(test)]
mod tests;
