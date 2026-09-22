// SPDX-License-Identifier: MPL-2.0

//! Bounded read-only system diagnostics via fixed official tools (T10 Class A).
//!
//! Only verification is offered; no repair, no privilege escalation, no
//! arbitrary shell. The tool argv is fixed, the environment is reset, and
//! output, runtime and cancellation are bounded.

use crate::terminal::Signals;
use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use serde::Serialize;
use std::borrow::Cow;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command as ProcessCommand, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const DISKUTIL: &str = "/usr/sbin/diskutil";
const DEFAULT_TIMEOUT_SEC: u64 = 300;
const MAX_TIMEOUT_SEC: u64 = 3600;
const MAX_STDOUT_BYTES: usize = 256 * 1024;
const MAX_STDERR_BYTES: usize = 64 * 1024;
const CANCEL_GRACE: Duration = Duration::from_secs(2);

pub fn command() -> Command {
    Command::new("diagnose")
        .about("Bounded read-only diagnostics using fixed official tools")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("disk")
                .about("Verify a volume's filesystem with diskutil verifyVolume (read-only)")
                .arg(
                    Arg::new("volume")
                        .long("volume")
                        .value_name("PATH")
                        .required(true)
                        .value_parser(value_parser!(PathBuf)),
                )
                .arg(
                    Arg::new("timeout-sec")
                        .long("timeout-sec")
                        .value_name("SECONDS")
                        .help(format!(
                            "Tool time budget [default: {DEFAULT_TIMEOUT_SEC}, max: {MAX_TIMEOUT_SEC}]"
                        ))
                        .value_parser(value_parser!(u64)),
                )
                .arg(
                    Arg::new("json")
                        .long("json")
                        .action(ArgAction::SetTrue)
                        .help("Write one versioned JSON report to stdout"),
                )
                .after_help(
                    "Verification only; no repair is performed or authorized. Ctrl-C stops the tool\n(INT, then TERM/KILL after a grace period). Output is bounded and truncation is marked.\nRelative --volume paths are resolved against the current directory.",
                ),
        )
}

pub fn run(args: &ArgMatches) -> io::Result<u8> {
    let result = match args.subcommand() {
        Some(("disk", args)) => run_disk(args),
        _ => Ok(2),
    };
    match result {
        Ok(code) => Ok(code),
        Err(error) => {
            writeln!(
                io::stderr().lock(),
                "diagnose failed: {:?}",
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

#[derive(Serialize)]
struct BoundedOutput {
    text: String,
    bytes: usize,
    truncated: bool,
}

#[derive(Serialize)]
struct DiskReport {
    schema_version: u32,
    kind: &'static str,
    volume: serde_json::Value,
    argv: Vec<String>,
    effects_performed: bool,
    exit_code: Option<i32>,
    signal: Option<i32>,
    timed_out: bool,
    cancelled: bool,
    duration_ms: u64,
    stdout: BoundedOutput,
    stderr: BoundedOutput,
    limits: serde_json::Value,
}

/// Reads a pipe to its end, retaining at most `cap` bytes and draining the
/// rest so the child never blocks on a full pipe.
fn read_bounded(mut pipe: impl Read, cap: usize) -> io::Result<BoundedOutput> {
    let mut kept = Vec::with_capacity(cap.min(4096));
    let mut chunk = [0u8; 8192];
    let mut total = 0usize;
    loop {
        let read = pipe.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read);
        let remaining = cap.saturating_sub(kept.len());
        kept.extend_from_slice(&chunk[..read.min(remaining)]);
    }
    Ok(BoundedOutput {
        text: String::from_utf8_lossy(&kept).into_owned(),
        bytes: total,
        truncated: total > kept.len(),
    })
}

fn run_disk(args: &ArgMatches) -> io::Result<u8> {
    let volume = args
        .get_one::<PathBuf>("volume")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "--volume is required"))?;
    if volume
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "'..' volume traversal is not accepted",
        ));
    }
    let volume = std::path::absolute(volume)?;
    if !volume.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--volume must name an existing directory",
        ));
    }
    let timeout = args
        .get_one::<u64>("timeout-sec")
        .copied()
        .unwrap_or(DEFAULT_TIMEOUT_SEC);
    if timeout == 0 || timeout > MAX_TIMEOUT_SEC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("--timeout-sec must be in 1..={MAX_TIMEOUT_SEC}"),
        ));
    }
    let report = run_verify(&volume, Duration::from_secs(timeout))?;
    if args.get_flag("json") {
        let mut out = io::stdout().lock();
        serde_json::to_writer(&mut out, &report).map_err(|error| {
            io::Error::new(
                error.io_error_kind().unwrap_or(io::ErrorKind::InvalidData),
                error,
            )
        })?;
        out.write_all(b"\n")?;
        out.flush()?;
    } else {
        print_disk_human(&report)?;
    }
    Ok(exit_code_for(&report))
}

/// Maps the honest report outcome to the CLI exit code: 0 verified OK,
/// 3 tool-reported problems or timeout, 130 cancelled, 1 unknown outcome.
fn exit_code_for(report: &DiskReport) -> u8 {
    if report.cancelled {
        130
    } else if report.timed_out {
        3
    } else {
        match report.exit_code {
            Some(0) => 0,
            Some(_) => 3,
            None => 1,
        }
    }
}

/// Owns a spawned tool child so setup failures can never leak a running,
/// unreaped process; mirrors the OwnedChild shape used by the menu module.
struct OwnedChild {
    child: Child,
    reaped: bool,
}

impl OwnedChild {
    fn spawn(volume: &Path) -> io::Result<Self> {
        let child = ProcessCommand::new(DISKUTIL)
            .args(["verifyVolume"])
            .arg(volume)
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        Ok(Self {
            child,
            reaped: false,
        })
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        let result = self.child.try_wait()?;
        if result.is_some() {
            self.reaped = true;
        }
        Ok(result)
    }

    fn wait(&mut self) -> io::Result<ExitStatus> {
        let status = self.child.wait()?;
        self.reaped = true;
        Ok(status)
    }

    fn id(&self) -> u32 {
        self.child.id()
    }

    #[cfg(unix)]
    fn send_signal(&self, signal: rustix::process::Signal) -> io::Result<()> {
        use rustix::process::{Pid, kill_process};
        let pid = Pid::from_raw(self.id() as i32)
            .ok_or_else(|| io::Error::other("child PID does not fit platform PID type"))?;
        match kill_process(pid, signal) {
            Ok(()) => Ok(()),
            Err(errno) if errno == rustix::io::Errno::SRCH => Ok(()),
            Err(errno) => Err(io::Error::from_raw_os_error(errno.raw_os_error())),
        }
    }
}

impl OwnedChild {
    /// Best-effort stop: SIGKILL (ignored when the tool already exited),
    /// then reap. The readers can only end once the tool is gone, so this
    /// must never skip the wait on paths that join them afterwards.
    fn stop_and_reap(&mut self) {
        if let Err(error) = self.child.kill()
            && error.kind() != io::ErrorKind::InvalidInput
        {
            eprintln!("could not request tool stop {}: {error}", self.child.id());
        }
        match self.child.wait() {
            Ok(_) => self.reaped = true,
            Err(error) => eprintln!("could not reap tool child {}: {error}", self.child.id()),
        }
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        match self.child.try_wait() {
            Ok(Some(_)) => self.reaped = true,
            Ok(None) => self.stop_and_reap(),
            Err(error) => {
                eprintln!(
                    "could not poll tool child {}; status unknown: {error}",
                    self.child.id()
                );
                self.stop_and_reap();
            }
        }
    }
}

fn run_verify(volume: &Path, timeout: Duration) -> io::Result<DiskReport> {
    let argv = vec![
        DISKUTIL.to_string(),
        "verifyVolume".to_string(),
        volume.display().to_string(),
    ];
    let signals = Signals::new()?;
    let started = Instant::now();
    let mut child = OwnedChild::spawn(volume)?;
    let mut stdout_pipe = child
        .child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("child stdout pipe missing"))?;
    let mut stderr_pipe = child
        .child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("child stderr pipe missing"))?;
    let stdout_reader = std::thread::Builder::new()
        .name("sayaka-diagnose-stdout".into())
        .spawn(move || read_bounded(&mut stdout_pipe, MAX_STDOUT_BYTES))?;
    let stderr_reader = match std::thread::Builder::new()
        .name("sayaka-diagnose-stderr".into())
        .spawn(move || read_bounded(&mut stderr_pipe, MAX_STDERR_BYTES))
    {
        Ok(reader) => reader,
        Err(error) => {
            // The OwnedChild drop stops the tool, which closes the stdout
            // pipe; join the first reader so no thread is left detached.
            drop(child);
            let _ = stdout_reader.join();
            return Err(error);
        }
    };
    let wait_result = wait_outcome(&mut child, &signals, started, timeout);
    if wait_result.is_err() {
        // Stop and reap the tool so the pipes close and the readers end;
        // never join while the child can still be running.
        drop(child);
    }
    let stdout = stdout_reader
        .join()
        .map_err(|_| io::Error::other("stdout reader panicked"));
    let stderr = stderr_reader
        .join()
        .map_err(|_| io::Error::other("stderr reader panicked"));
    let (status, cancelled, timed_out) = wait_result?;
    let stdout = stdout??;
    let stderr = stderr??;
    Ok(DiskReport {
        schema_version: 1,
        kind: "sayaka.diagnose_disk",
        volume: crate::apps::write_native_path(volume),
        argv,
        effects_performed: false,
        exit_code: status.code(),
        signal: signal_of(&status),
        timed_out,
        cancelled,
        duration_ms: started.elapsed().as_millis() as u64,
        stdout,
        stderr,
        limits: serde_json::json!({
            "timeout_sec": timeout.as_secs(),
            "max_stdout_bytes": MAX_STDOUT_BYTES,
            "max_stderr_bytes": MAX_STDERR_BYTES,
        }),
    })
}

/// Polls the tool to completion, honoring the time budget and Ctrl-C, and
/// returns the tool's real exit status with the honest outcome flags.
fn wait_outcome(
    child: &mut OwnedChild,
    signals: &Signals,
    started: Instant,
    timeout: Duration,
) -> io::Result<(ExitStatus, bool, bool)> {
    let mut cancelled = false;
    let mut timed_out = false;
    let status = loop {
        let cancel = signals.interrupted() || signals.terminated();
        let expired = started.elapsed() > timeout;
        if cancel || expired {
            cancelled = cancel;
            timed_out = !cancel;
            break request_stop(child, cancel)?;
        }
        if let Some(status) = child.try_wait()? {
            break status;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    // Ctrl-C signals the whole foreground process group, so the tool can
    // exit from the shared SIGINT before this loop observes the request.
    // The user's cancellation is still what happened; report it honestly.
    if !cancelled && !timed_out && (signals.interrupted() || signals.terminated()) {
        cancelled = true;
    }
    Ok((status, cancelled, timed_out))
}

#[cfg(unix)]
fn signal_of(status: &ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status.signal()
}

#[cfg(not(unix))]
fn signal_of(_: &ExitStatus) -> Option<i32> {
    None
}

/// Interrupt first (so the tool can stop cleanly), then KILL after a grace
/// window. Returns the tool's real exit status; the child is always reaped.
fn request_stop(child: &mut OwnedChild, interrupt: bool) -> io::Result<ExitStatus> {
    #[cfg(unix)]
    child.send_signal(if interrupt {
        rustix::process::Signal::INT
    } else {
        rustix::process::Signal::TERM
    })?;
    let deadline = Instant::now() + CANCEL_GRACE;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    match child.child.kill() {
        Ok(()) => child.wait(),
        // The tool exited between the last poll and the kill request.
        Err(error) if error.kind() == io::ErrorKind::InvalidInput => child.wait(),
        Err(error) => Err(error),
    }
}

fn print_disk_human(report: &DiskReport) -> io::Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out, "kind: {}", report.kind)?;
    writeln!(
        out,
        "volume: {}",
        report.volume["display"].as_str().unwrap_or("?")
    )?;
    writeln!(out, "effects_performed: false")?;
    let verdict: Cow<'static, str> = if report.cancelled {
        Cow::Borrowed("cancelled (tool stopped; verification incomplete)")
    } else if report.timed_out {
        Cow::Borrowed("timed out (tool stopped; verification incomplete)")
    } else {
        match report.exit_code {
            Some(0) => Cow::Borrowed("verified: the volume appears to be OK"),
            Some(code) => Cow::Owned(format!(
                "problems reported or tool error (exit {code}); read the output"
            )),
            None => match report.signal {
                Some(signal) => Cow::Owned(format!("tool stopped by signal {signal}")),
                None => Cow::Borrowed("tool outcome unknown"),
            },
        }
    };
    writeln!(out, "verdict: {verdict}")?;
    writeln!(out, "duration_ms: {}", report.duration_ms)?;
    writeln!(out, "tool output ({} bytes):", report.stdout.bytes)?;
    write!(out, "{}", report.stdout.text)?;
    if report.stdout.truncated {
        writeln!(out, "[output truncated at {} bytes]", MAX_STDOUT_BYTES)?;
    }
    if !report.stderr.text.is_empty() {
        writeln!(out, "tool stderr ({} bytes):", report.stderr.bytes)?;
        write!(out, "{}", report.stderr.text)?;
        if report.stderr.truncated {
            writeln!(out, "[stderr truncated at {} bytes]", MAX_STDERR_BYTES)?;
        }
    }
    writeln!(
        out,
        "Read-only verification by /usr/sbin/diskutil; no repair was performed or authorized."
    )?;
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(exit_code: Option<i32>, timed_out: bool, cancelled: bool) -> DiskReport {
        DiskReport {
            schema_version: 1,
            kind: "sayaka.diagnose_disk",
            volume: crate::apps::write_native_path(Path::new("/")),
            argv: vec![DISKUTIL.into(), "verifyVolume".into(), "/".into()],
            effects_performed: false,
            exit_code,
            signal: None,
            timed_out,
            cancelled,
            duration_ms: 42,
            stdout: BoundedOutput {
                text: "ok".into(),
                bytes: 2,
                truncated: false,
            },
            stderr: BoundedOutput {
                text: String::new(),
                bytes: 0,
                truncated: false,
            },
            limits: serde_json::json!({"timeout_sec": 300}),
        }
    }

    #[test]
    fn bounded_output_keeps_cap_and_marks_truncation() {
        let data = vec![b'x'; MAX_STDOUT_BYTES + 4096];
        let output = read_bounded(data.as_slice(), MAX_STDOUT_BYTES).unwrap();
        assert_eq!(output.bytes, MAX_STDOUT_BYTES + 4096);
        assert!(output.truncated);
        assert_eq!(output.text.len(), MAX_STDOUT_BYTES);
        let small = read_bounded(b"ok".as_slice(), MAX_STDOUT_BYTES).unwrap();
        assert!(!small.truncated);
        assert_eq!(small.text, "ok");
    }

    #[test]
    fn json_report_has_explicit_outcome_states() {
        let report = report(Some(0), false, false);
        let mut out = Vec::new();
        serde_json::to_writer(&mut out, &report).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["kind"], "sayaka.diagnose_disk");
        assert_eq!(value["effects_performed"], false);
        assert_eq!(value["argv"][1], "verifyVolume");
        assert_eq!(value["timed_out"], false);
        assert_eq!(value["cancelled"], false);
    }

    #[test]
    fn exit_code_distinguishes_outcomes() {
        assert_eq!(exit_code_for(&report(Some(0), false, false)), 0);
        assert_eq!(exit_code_for(&report(Some(1), false, false)), 3);
        assert_eq!(exit_code_for(&report(None, true, false)), 3);
        assert_eq!(exit_code_for(&report(None, false, true)), 130);
        // Cancellation wins even when the tool status was observed first
        // (Ctrl-C is delivered to the whole foreground process group).
        assert_eq!(exit_code_for(&report(Some(0), false, true)), 130);
        assert_eq!(exit_code_for(&report(None, false, false)), 1);
    }
}
