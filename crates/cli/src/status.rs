// SPDX-License-Identifier: MPL-2.0

use crate::terminal::{Line, Signals, Style, Terminal};
use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use sayaka_engine::model::Cancellation;
use sayaka_engine::status::{Config, Metric, NativeProvider, Sampler, Snapshot, State};
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
        .arg(Arg::new("cpu-warn").long("cpu-warn").default_value("90").value_parser(value_parser!(f64))
            .help("Read-only CPU busy threshold, percent"))
        .arg(Arg::new("memory-warn").long("memory-warn").default_value("90").value_parser(value_parser!(f64))
            .help("Active+wired+physical compressor / RAM threshold; not an OS pressure score"))
        .arg(Arg::new("disk-warn").long("disk-warn").default_value("10").value_parser(value_parser!(f64))
            .help("Read-only startup filesystem available-space threshold, percent or less"))
        .after_help("One-shot waits for a usable CPU counter window (up to five observations).\nWatch never installs a daemon or changes system state. q/Esc exits a terminal panel;\nCtrl-C/SIGTERM cancels and joins the sampler. Numeric temperature, GPU utilization\nand per-process top lists remain explicit unsupported capabilities.")
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
    lines
        .push("Temperature / GPU utilization / per-process top: unsupported in this slice.".into());
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
    for line in lines(snapshot) {
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
    let mut output = String::new();
    let mut used = 0;
    for original in text.chars() {
        let safe = if original.is_control()
            || matches!(original, '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{206f}')
        {
            original.escape_debug().to_string()
        } else {
            original.to_string()
        };
        for ch in safe.chars() {
            let columns = ch.width().unwrap_or(0);
            if used + columns > width {
                return output;
            }
            output.push(ch);
            used += columns;
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tiny_frames_are_bounded_and_escape_terminal_controls() {
        for height in 0..8 {
            let result = frame(None, 8, height);
            assert_eq!(result.len(), usize::from(height));
        }
        assert!(
            !clip("bad\x1b[2J\n\u{202e}", 80)
                .chars()
                .any(char::is_control)
        );
    }
}
