// SPDX-License-Identifier: MPL-2.0

use crate::terminal::{Line, Signals, Style, Terminal};
use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use sayaka_engine::model::Cancellation;
use sayaka_engine::status::{
    Config, Metric, NativeProvider, ProcessTopConfig, ProcessTopSort, Sampler, Snapshot, State,
};
use std::io::{self, IsTerminal, Write};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use unicode_width::UnicodeWidthChar;

pub fn command() -> Command {
    Command::new("status")
        .about("Read-only native system metrics; unknown values are never zero")
        .arg(Arg::new("json").long("json").action(ArgAction::SetTrue).help("One JSON snapshot, or NDJSON with --watch"))
        .arg(Arg::new("watch").long("watch").action(ArgAction::SetTrue).help("Continuously sample; terminal panel or NDJSON for pipes"))
        .arg(Arg::new("count").long("count").requires("watch").value_parser(value_parser!(u64).range(1..=10000))
            .help("Stop after N emitted watch snapshots"))
        .arg(Arg::new("interval-ms").long("interval-ms").default_value("1000").value_parser(value_parser!(u64).range(250..=60000))
            .help("Fast sampling interval; slow metrics refresh no faster than 5 seconds"))
        .arg(Arg::new("top").long("top").value_name("N").value_parser(value_parser!(u64).range(1..=32))
            .help("Opt-in local process PID/name/RSS/CPU table; names can be sensitive local data"))
        .arg(Arg::new("top-sort").long("top-sort").requires("top").value_parser(["cpu", "memory"])
            .help("Sort --top rows by cpu (default) or memory"))
        .arg(Arg::new("cpu-warn").long("cpu-warn").default_value("90").value_parser(value_parser!(f64))
            .help("Read-only CPU busy threshold, percent"))
        .arg(Arg::new("memory-warn").long("memory-warn").default_value("90").value_parser(value_parser!(f64))
            .help("Active+wired+physical compressor / RAM threshold; not an OS pressure score"))
        .arg(Arg::new("disk-warn").long("disk-warn").default_value("10").value_parser(value_parser!(f64))
            .help("Read-only startup filesystem available-space threshold, percent or less"))
        .after_help("One-shot waits for a usable CPU counter window (up to five observations).\nWatch never installs a daemon or changes system state. q/Esc exits a terminal panel;\nCtrl-C/SIGTERM cancels and joins the sampler. Numeric temperature remains unsupported.\nProcess PID/name/RSS/CPU rows are collected only with --top.")
}

struct TimedSnapshot {
    value: Snapshot,
    published: Instant,
}

struct Worker {
    cancellation: Cancellation,
    slot: Arc<Mutex<Option<io::Result<TimedSnapshot>>>>,
    handle: Option<JoinHandle<io::Result<()>>>,
}

impl Worker {
    fn start(config: Config) -> io::Result<Self> {
        let cancellation = Cancellation::default();
        let cancel = cancellation.clone();
        let slot = Arc::new(Mutex::new(None));
        let target = Arc::clone(&slot);
        let handle = thread::Builder::new()
            .name("sayaka-status".into())
            .spawn(move || {
                let interval = config.interval;
                let mut sampler = Sampler::new(NativeProvider, config)?;
                while !cancel.is_cancelled() {
                    let started = Instant::now();
                    let sample = sampler.sample(&cancel);
                    let stop = sample.is_err();
                    if cancel.is_cancelled() {
                        return Ok(());
                    }
                    let value = sample.map(|value| TimedSnapshot {
                        value,
                        published: Instant::now(),
                    });
                    *target
                        .lock()
                        .map_err(|_| io::Error::other("status snapshot slot was poisoned"))? =
                        Some(value);
                    if stop {
                        return Ok(());
                    }
                    let now = Instant::now();
                    let deadline = if now.duration_since(started) >= interval {
                        now + interval
                    } else {
                        started + interval
                    };
                    while !cancel.is_cancelled() {
                        let remaining = deadline.saturating_duration_since(Instant::now());
                        if remaining.is_zero() {
                            break;
                        }
                        thread::park_timeout(remaining);
                    }
                }
                Ok(())
            })?;
        Ok(Self {
            cancellation,
            slot,
            handle: Some(handle),
        })
    }
    fn take(&self) -> io::Result<Option<io::Result<TimedSnapshot>>> {
        self.slot
            .lock()
            .map(|mut slot| slot.take())
            .map_err(|_| io::Error::other("status snapshot slot was poisoned"))
    }
    fn finished(&self) -> bool {
        self.handle.as_ref().is_none_or(JoinHandle::is_finished)
    }
    fn cancel(&self) {
        self.cancellation.cancel();
        if let Some(handle) = &self.handle {
            handle.thread().unpark();
        }
    }
    fn join(&mut self) -> io::Result<()> {
        self.cancel();
        if let Some(handle) = self.handle.take() {
            handle
                .join()
                .map_err(|_| io::Error::other("status worker panicked"))??;
        }
        Ok(())
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        if let Err(error) = self.join() {
            eprintln!("status worker cleanup failed: {:?}", error.to_string());
        }
    }
}

pub fn run(args: &ArgMatches) -> io::Result<u8> {
    let json = args.get_flag("json") || (args.get_flag("watch") && !panel_available());
    let result = options(args).and_then(|options| {
        match std::panic::catch_unwind(move || run_inner(options)) {
            Ok(result) => result,
            Err(_) => Err(io::Error::other(
                "status task panicked; terminal and owned worker cleanup were attempted",
            )),
        }
    });
    match result {
        Ok(code) => Ok(code),
        Err(error) => {
            // A broken output must not be followed by another write to that pipe.
            if json && error.kind() != io::ErrorKind::BrokenPipe {
                let mut out = io::stdout().lock();
                serde_json::to_writer(&mut out, &serde_json::json!({
                    "schema_version": 1, "kind": "status_error",
                    "error": {"code": format!("{:?}", error.kind()), "message": error.to_string()}
                })).map_err(json_error)?;
                writeln!(out)?;
            }
            writeln!(
                io::stderr().lock(),
                "status failed: {:?}",
                error.to_string()
            )?;
            Ok(if error.kind() == io::ErrorKind::InvalidInput {
                2
            } else {
                1
            })
        }
    }
}

fn panel_available() -> bool {
    io::stdin().is_terminal()
        && io::stdout().is_terminal()
        && std::env::var_os("TERM").is_none_or(|term| term != "dumb")
}

struct Options {
    config: Config,
    watch: bool,
    panel: bool,
    json: bool,
    count: Option<u64>,
}

fn options(args: &ArgMatches) -> io::Result<Options> {
    let interval = *args
        .get_one::<u64>("interval-ms")
        .ok_or_else(|| io::Error::other("interval missing"))?;
    let config = Config {
        interval: Duration::from_millis(interval),
        process_top: args.get_one::<u64>("top").map(|limit| ProcessTopConfig {
            limit: *limit as usize,
            sort: match args
                .get_one::<String>("top-sort")
                .map(String::as_str)
                .unwrap_or("cpu")
            {
                "memory" => ProcessTopSort::Memory,
                _ => ProcessTopSort::Cpu,
            },
        }),
        cpu_warning_percent: *args
            .get_one::<f64>("cpu-warn")
            .ok_or_else(|| io::Error::other("threshold missing"))?,
        memory_warning_percent: *args
            .get_one::<f64>("memory-warn")
            .ok_or_else(|| io::Error::other("threshold missing"))?,
        disk_available_warning_percent: *args
            .get_one::<f64>("disk-warn")
            .ok_or_else(|| io::Error::other("threshold missing"))?,
    };
    config.validate()?;
    let watch = args.get_flag("watch");
    let panel = watch && !args.get_flag("json") && panel_available();
    let json = args.get_flag("json") || (watch && !panel);
    let count = args.get_one::<u64>("count").copied();
    Ok(Options {
        config,
        watch,
        panel,
        json,
        count,
    })
}

fn run_inner(options: Options) -> io::Result<u8> {
    let Options {
        config,
        watch,
        panel,
        json,
        count,
    } = options;
    let signals = Signals::new()?;
    // Worker declared first: terminal restores before worker join during unwind.
    let mut worker = Worker::start(config.clone())?;
    let mut terminal = if panel {
        Some(Terminal::enter()?)
    } else {
        None
    };
    let mut result = consume(
        &worker,
        &mut terminal,
        &signals,
        &config,
        watch,
        json,
        count,
    );
    worker.cancel();
    if let Some(code) = signals.exit_code() {
        result = Ok(code);
    }
    let restored = terminal.as_mut().map(Terminal::restore).transpose();
    let joined = worker.join();
    restored?;
    joined?;
    result
}

fn consume(
    worker: &Worker,
    terminal: &mut Option<Terminal>,
    signals: &Signals,
    config: &Config,
    watch: bool,
    json: bool,
    count: Option<u64>,
) -> io::Result<u8> {
    let mut latest: Option<TimedSnapshot> = None;
    let mut previous_sequence: Option<u64> = None;
    let mut emitted = 0u64;
    let mut latest_exit_code = 0;
    let mut drawn = Instant::now() - Duration::from_secs(1);
    loop {
        if let Some(code) = signals.exit_code() {
            worker.cancel();
            return Ok(code);
        }
        let mut changed = false;
        if let Some(sample) = worker.take()? {
            latest = Some(sample?);
            changed = true;
        }
        if let Some(sample) = &latest {
            let mut view = sample.value.clone();
            view.age_by(sample.published.elapsed(), config)?;
            latest_exit_code = view.exit_code();
            let once_ready =
                view.sequence >= 2 && (view.cpu.state != State::WarmingUp || view.sequence >= 5);
            if changed && (watch || once_ready || view.exit_code() == 1) {
                view.coalesced_samples = previous_sequence
                    .map(|last| view.sequence.saturating_sub(last + 1))
                    .unwrap_or(0);
                previous_sequence = Some(view.sequence);
                emitted = emitted
                    .checked_add(1)
                    .ok_or_else(|| io::Error::other("emission counter exhausted"))?;
                if json {
                    let mut out = io::stdout().lock();
                    serde_json::to_writer(&mut out, &view).map_err(json_error)?;
                    writeln!(out)?;
                    out.flush()?;
                } else if !watch {
                    print_snapshot(&view)?;
                }
            }
            if let Some(terminal) = terminal
                && (changed || drawn.elapsed() >= Duration::from_millis(250))
            {
                let (width, height) = crossterm::terminal::size()?;
                terminal.draw(
                    &frame(Some(&view), width.min(240), height.min(80)),
                    width.min(240),
                    height.min(80),
                )?;
                drawn = Instant::now();
            }
            if view.exit_code() == 1
                || (!watch && emitted > 0)
                || count.is_some_and(|count| emitted >= count)
            {
                return Ok(if !watch && view.cpu.state == State::WarmingUp {
                    3
                } else {
                    view.exit_code()
                });
            }
        } else if let Some(terminal) = terminal
            && drawn.elapsed() >= Duration::from_millis(250)
        {
            let (width, height) = crossterm::terminal::size()?;
            terminal.draw(
                &frame(None, width.min(240), height.min(80)),
                width.min(240),
                height.min(80),
            )?;
            drawn = Instant::now();
        }
        if worker.finished() && !changed {
            return Err(io::Error::other(
                "status worker stopped without a final sample",
            ));
        }
        if terminal.is_some() {
            if event::poll(Duration::from_millis(20))? {
                match event::read()? {
                    Event::Key(key) if key.kind == KeyEventKind::Press => {
                        if key.modifiers.contains(KeyModifiers::CONTROL)
                            && key.code == KeyCode::Char('c')
                        {
                            worker.cancel();
                            return Ok(130);
                        }
                        if matches!(key.code, KeyCode::Char('q') | KeyCode::Esc) {
                            worker.cancel();
                            return Ok(latest_exit_code);
                        }
                    }
                    Event::Resize(_, _) => {
                        if let Some(terminal) = terminal {
                            terminal.invalidate();
                        }
                        drawn = Instant::now() - Duration::from_secs(1);
                    }
                    _ => {}
                }
            }
        } else {
            thread::sleep(Duration::from_millis(10));
        }
    }
}

fn metric<T>(value: &Metric<T>, format: impl FnOnce(&T) -> String) -> String {
    let data = value
        .value
        .as_ref()
        .map(format)
        .unwrap_or_else(|| "unknown".into());
    let age = value
        .age_ms
        .map(|age| format!("{age}ms"))
        .unwrap_or_else(|| "not observed".into());
    let error = value
        .error
        .as_ref()
        .map(|error| format!("; {}: {:?}", error.code, error.message))
        .unwrap_or_default();
    format!("{data} [{:?}; age {age}{error}]", value.state)
}

fn lines(snapshot: &Snapshot) -> Vec<String> {
    let mut lines = vec![format!(
        "Sample {} | interval {}ms | collect {}ms | coalesced {}",
        snapshot.sequence, snapshot.interval_ms, snapshot.collection_ms, snapshot.coalesced_samples
    )];
    for alert in &snapshot.alerts {
        let observed = alert
            .observed_percent
            .map(|value| format!("{value:.1}%"))
            .unwrap_or_else(|| "unknown".into());
        lines.push(format!(
            "Threshold {}: {} ({} {:.1}%, observed {})",
            alert.metric,
            alert.state,
            if alert.metric == "disk_available" {
                "<="
            } else {
                ">="
            },
            alert.threshold_percent,
            observed
        ));
    }
    lines.extend([
        format!(
            "CPU: {}",
            metric(&snapshot.cpu, |cpu| format!(
                "{:.1}% busy over {}ms",
                cpu.busy_percent, cpu.window_ms
            ))
        ),
        format!(
            "RAM: {}",
            metric(&snapshot.memory, |memory| format!(
                "{:.1}% working set / {}",
                memory.working_set_percent,
                crate::human::size(memory.physical_bytes)
            ))
        ),
    ]);
    if let Some(memory) = &snapshot.memory.value {
        lines.push(format!(
            "  active {} | wired {} | compressor {} | inactive {}",
            crate::human::size(memory.active_bytes),
            crate::human::size(memory.wired_bytes),
            crate::human::size(memory.compressor_bytes),
            crate::human::size(memory.inactive_bytes)
        ));
        lines.push(
            "  Working set = active+wired+physical compressor; not OS pressure or all used RAM."
                .into(),
        );
    }
    lines.push(format!(
        "Disk /: {}",
        metric(&snapshot.disk, |disk| format!(
            "{} available, {} free, {} total",
            crate::human::size(disk.available_bytes),
            crate::human::size(disk.free_bytes),
            crate::human::size(disk.total_bytes)
        ))
    ));
    lines.push(format!(
        "Network: {:?} (per interface; no summed physical-throughput claim)",
        snapshot.network.state
    ));
    if let Some(interfaces) = &snapshot.network.value {
        if interfaces.is_empty() {
            lines.push("  No non-loopback interfaces observed.".into());
        }
        for interface in interfaces.iter().take(8) {
            let rate = |value: Option<f64>| {
                value
                    .map(|value| format!("{value:.0} B/s"))
                    .unwrap_or_else(|| "unknown".into())
            };
            lines.push(format!(
                "  {:?} {}: RX {}  TX {} [{:?}]",
                interface.name,
                if interface.up { "up" } else { "down" },
                rate(interface.received_bytes_per_second),
                rate(interface.transmitted_bytes_per_second),
                interface.rate_state
            ));
        }
        if interfaces.len() > 8 {
            lines.push(format!(
                "  {} more interfaces in JSON output.",
                interfaces.len() - 8
            ));
        }
    } else if let Some(error) = &snapshot.network.error {
        lines.push(format!("  {}: {:?}", error.code, error.message));
    }
    lines.push(format!(
        "Visible processes: {}",
        metric(&snapshot.visible_processes, |count| count.to_string())
    ));
    if let Some(top) = &snapshot.process_top.value {
        lines.push(format!(
            "Top processes (opt-in): sort={:?} shown={} limit={} probed={} visible={} denied={} disappeared={} invalid={}{}{}",
            top.sort,
            top.rows.len(),
            top.limit,
            top.probed,
            top.visible_processes,
            top.denied,
            top.disappeared,
            top.invalid,
            if top.truncated { " truncated" } else { "" },
            if top.partial { " partial" } else { "" }
        ));
        for row in &top.rows {
            lines.push(format!(
                "  pid={} {} cpu={} rss={} window={} state={:?}",
                row.pid,
                row.name,
                row.cpu_percent_one_core
                    .map(|value| format!("{value:.2}%"))
                    .unwrap_or_else(|| "unknown".into()),
                crate::human::size(row.resident_bytes),
                row.cpu_window_ms
                    .map(|value| format!("{value}ms"))
                    .unwrap_or_else(|| "unknown".into()),
                row.state
            ));
        }
    } else if let Some(error) = &snapshot.process_top.error {
        lines.push(format!(
            "Top processes: {}: {:?}",
            error.code, error.message
        ));
    }
    lines.push(format!(
        "Power: {}",
        metric(&snapshot.power, |power| format!(
            "{}; battery {}; charging {}",
            if power.on_ac { "AC" } else { "battery" },
            power
                .battery_percent
                .map(|value| format!("{value:.0}%"))
                .unwrap_or_else(|| "not present".into()),
            power
                .charging
                .map(|value| value.to_string())
                .unwrap_or_else(|| "not applicable".into())
        ))
    ));
    lines.push(format!(
        "Thermal state: {}",
        metric(&snapshot.thermal_state, |state| format!("{state:?}"))
    ));
    lines.push(format!(
        "GPU utilization: {}",
        metric(&snapshot.gpu_utilization_percent, |value| format!(
            "{value:.0}%"
        ))
    ));
    lines.push("Numeric temperature: unsupported in this slice.".into());
    lines.push(format!(
        "Sampler: {}",
        metric(&snapshot.sampler_process, |process| format!(
            "RSS {}, CPU {} (one core=100%)",
            crate::human::size(process.resident_bytes),
            process
                .cpu_percent_one_core
                .map(|value| format!("{value:.2}%"))
                .unwrap_or_else(|| "warming up".into())
        ))
    ));
    if let Some(error) = &snapshot.clock_error {
        lines.push(format!("Clock error: {}: {:?}", error.code, error.message));
    }
    lines
}

fn json_error(error: serde_json::Error) -> io::Error {
    io::Error::new(
        error.io_error_kind().unwrap_or(io::ErrorKind::InvalidData),
        error,
    )
}

fn print_snapshot(snapshot: &Snapshot) -> io::Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out, "Sayaka system status - read-only")?;
    for line in render_terminal_lines(snapshot) {
        writeln!(out, "{line}")?;
    }
    out.flush()
}

fn frame(snapshot: Option<&Snapshot>, width: u16, height: u16) -> Vec<Line> {
    let mut result = vec![
        Line {
            text: String::new(),
            style: Style::Normal
        };
        usize::from(height)
    ];
    if let Some(line) = result.first_mut() {
        *line = Line {
            text: clip("Sayaka / System status - read-only", usize::from(width)),
            style: Style::Header,
        };
    }
    let body = snapshot.map(lines).unwrap_or_else(|| {
        vec!["Sampling native counters; rates require a second observation.".into()]
    });
    let available = usize::from(height).saturating_sub(3);
    for (row, text) in body.iter().take(available).enumerate() {
        result[row + 1] = Line {
            text: clip(text, usize::from(width)),
            style: if text.contains(": active")
                || text.contains("Stale")
                || text.contains("Unavailable")
            {
                Style::Warning
            } else {
                Style::Normal
            },
        };
    }
    if height >= 2 {
        result[usize::from(height) - 1] = Line {
            text: clip(
                if body.len() > available {
                    "q/Esc exit | More metrics in --json or a taller terminal"
                } else {
                    "q/Esc exit | Unknown is not zero; no automatic maintenance"
                },
                usize::from(width),
            ),
            style: Style::Muted,
        };
    }
    result
}

fn clip(text: &str, width: usize) -> String {
    let text = escape_for_terminal(text);
    let mut output = String::new();
    let mut used = 0;
    for ch in text.chars() {
        let columns = ch.width().unwrap_or(0);
        if used + columns > width {
            return output;
        }
        output.push(ch);
        used += columns;
    }
    output
}

fn render_terminal_lines(snapshot: &Snapshot) -> Vec<String> {
    lines(snapshot)
        .into_iter()
        .map(|line| escape_for_terminal(&line))
        .collect()
}

fn escape_for_terminal(text: &str) -> String {
    let sensitive = |ch: char| {
        ch.is_control()
            || ('\u{007f}'..='\u{009f}').contains(&ch)
            || matches!(
                ch,
                '\u{061c}'
                    | '\u{200b}'..='\u{200f}'
                    | '\u{2028}'..='\u{202e}'
                    | '\u{2066}'..='\u{2069}'
            )
    };
    let mut output = String::new();
    for original in text.chars() {
        if sensitive(original) {
            for escaped in original.escape_debug() {
                output.push(escaped);
            }
        } else {
            output.push(original);
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use sayaka_engine::status::{
        Alert, Cpu, Disk, Interface, Memory, MetricError, Power, ProcessIdentity, ProcessTop,
        ProcessTopRow, SamplerProcess, Thermal,
    };

    fn metric<T>(value: Option<T>, state: State) -> Metric<T> {
        Metric {
            value,
            state,
            source: "test",
            observed_unix_ms: Some(1),
            age_ms: Some(0),
            max_age_ms: 1000,
            error: None,
        }
    }

    fn sample_snapshot_with_name(name: &str) -> Snapshot {
        Snapshot {
            schema_version: 1,
            sampler_id: "x".into(),
            sequence: 2,
            observed_unix_ms: Some(1),
            elapsed_ms: 1000,
            interval_ms: 1000,
            slow_interval_ms: 5000,
            collection_ms: 3,
            coalesced_samples: 0,
            clock_error: Some(MetricError {
                code: "clock".into(),
                message: "none".into(),
            }),
            cpu: metric(
                Some(Cpu {
                    busy_percent: 10.0,
                    window_ms: 1000,
                }),
                State::Fresh,
            ),
            memory: metric(
                Some(Memory {
                    physical_bytes: 1024,
                    page_size: 4096,
                    active_bytes: 200,
                    inactive_bytes: 100,
                    wired_bytes: 100,
                    free_bytes: 400,
                    compressor_bytes: 50,
                    speculative_bytes: 0,
                    purgeable_bytes: 0,
                    working_set_percent: 34.0,
                }),
                State::Fresh,
            ),
            network: metric(
                Some(vec![Interface {
                    index: 1,
                    name: "en0".into(),
                    up: true,
                    received_bytes: 1,
                    transmitted_bytes: 1,
                    received_bytes_per_second: Some(1.0),
                    transmitted_bytes_per_second: Some(1.0),
                    window_ms: Some(1000),
                    rate_state: State::Fresh,
                    rate_reason: None,
                }]),
                State::Fresh,
            ),
            disk: metric(
                Some(Disk {
                    total_bytes: 1000,
                    free_bytes: 500,
                    available_bytes: 400,
                }),
                State::Fresh,
            ),
            sampler_process: metric(
                Some(SamplerProcess {
                    cpu_time_ns: 1,
                    resident_bytes: 4096,
                    cpu_percent_one_core: Some(1.0),
                    window_ms: Some(1000),
                }),
                State::Fresh,
            ),
            visible_processes: metric(Some(10), State::Fresh),
            power: metric(
                Some(Power {
                    on_ac: true,
                    battery_percent: None,
                    charging: None,
                }),
                State::Fresh,
            ),
            thermal_state: metric(Some(Thermal::Nominal), State::Fresh),
            temperature_celsius: metric::<f64>(None, State::Unsupported),
            gpu_utilization_percent: metric::<f64>(None, State::Unsupported),
            process_top: metric(
                Some(ProcessTop {
                    top_schema_version: 1,
                    sort: ProcessTopSort::Cpu,
                    limit: 1,
                    visible_processes: 10,
                    candidate_cap: 65536,
                    probe_cap: 4096,
                    collection_budget_ms: 100,
                    probed: 10,
                    denied: 0,
                    disappeared: 0,
                    invalid: 0,
                    truncated: false,
                    partial: false,
                    rows: vec![ProcessTopRow {
                        pid: 42,
                        name: name.to_owned(),
                        identity: ProcessIdentity {
                            pid: 42,
                            start_unix_sec: 1,
                            start_unix_usec: 1,
                        },
                        resident_bytes: 2048,
                        cpu_percent_one_core: None,
                        cpu_window_ms: None,
                        state: State::WarmingUp,
                        reason: Some("first_sample".into()),
                    }],
                }),
                State::Fresh,
            ),
            alerts: vec![Alert {
                metric: "cpu_busy",
                state: "clear",
                threshold_percent: 90.0,
                observed_percent: Some(10.0),
            }],
        }
    }

    #[test]
    fn tiny_frames_are_bounded_and_escape_terminal_controls() {
        for height in 0..8 {
            let result = frame(None, 8, height);
            assert_eq!(result.len(), usize::from(height));
        }
        assert!(
            !clip("bad\x1b[2J\n\u{202e}\u{0085}\u{2067}", 80)
                .chars()
                .any(char::is_control)
        );
    }

    #[test]
    fn rendered_lines_escape_malicious_process_names_without_breaking_unicode() {
        let snapshot = sample_snapshot_with_name("bad\x1b[2J\n\u{202e}\u{0085}\u{2067}中文");
        let lines = render_terminal_lines(&snapshot);
        let top_line = lines
            .iter()
            .find(|line| line.contains("pid=42"))
            .expect("top line");
        assert!(!top_line.chars().any(char::is_control));
        assert!(top_line.contains("\\u{202e}") || top_line.contains("\\x1b"));
        assert!(top_line.contains("中文"));
    }
}
