# Read-only system status

The initial T11 slice collects macOS system facts without maintenance actions,
privileged probes, shell collectors, user-file enumeration or a background service.
Windows-native status remains unimplemented and cannot be certified by Mac checks.

```sh
sayaka status
sayaka status --json
sayaka status --watch
sayaka status --watch --json --interval-ms 1000 --count 12
sayaka status --top 10
sayaka status --watch --json --interval-ms 1000 --count 12 --top 10 --top-sort cpu
```

One-shot output takes a baseline and waits for a subsequent usable CPU counter
observation, bounded to five observations when native counters are cached.
It does not present a newly initialized CPU/network rate as zero. `--watch` uses a terminal
panel when both streams are terminals and TERM is not dumb; pipes and `--json`
receive newline-delimited JSON. `--count` bounds emitted watch snapshots and is
only valid with `--watch`. There is no implicit installation or persistent agent.

Fast intervals are 250..60000 ms, default 1000 ms. Slow probes run no faster than
max(5000 ms, the configured interval). Overrun slots are not queued for catch-up.
One sampling worker owns the collector and one coalesced snapshot slot; sequence
numbers and `coalesced_samples` disclose skipped intermediate delivery.

## Metric scope and meaning

| Surface | Native basis | Meaning / limits |
| --- | --- | --- |
| CPU | Mach host CPU ticks | Aggregate busy fraction over the explicit counter window; not an instantaneous reading |
| Memory | Mach VM page categories, native page size, `hw.memsize` | Physical RAM and separate categories; active+wired+physical compressor fraction is a working-set indicator, not OS pressure or all used RAM |
| Network | Bounded routing/interface counters | Per-interface cumulative byte counters and measured rates; no double-counted aggregate across physical/virtual interfaces |
| Disk | Startup filesystem `statfs` | Native total/free/available quantities; not Finder purgeable/reclaimable space |
| Sampler | Current task RSS and cumulative self CPU time | Actual process resident bytes and interval CPU use, where one full core is 100% |
| Processes | Bounded visible PID enumeration and optional `PROC_PIDTASKALLINFO` probe | Default is count-only. `--top N` (1..32) opt-in adds PID/name/RSS/CPU rows sorted by `--top-sort cpu|memory` (default cpu); no command lines, env, cwd, path, or UID names |
| Power | Public IOPowerSources evidence | AC/battery and charge where available; no battery is represented by null, not 0% |
| Thermal state | Public NSProcessInfo classification | Nominal/fair/serious/critical where available; not numeric temperature |
| Temperature / GPU | Not implemented in this slice | Explicit unsupported state and null value |

Per-process top data is disabled by default because process names/PIDs are local
potentially sensitive data. When enabled with `--top`, JSON/NDJSON populates
`process_top` with `top_schema_version: 1`, row-level CPU freshness, and
coverage metadata (`visible_processes`, `probed`, `denied`, `disappeared`,
`invalid`, `truncated`, `partial`, caps, and collection budget).

Native calls live in the existing macOS FFI audit crate. Errors and invalid
returned lengths/units are not silently converted to zero-shaped data.
Network buffers/interfaces and process enumeration are bounded. No IP addresses,
MAC addresses, process arguments or hardware serial numbers are emitted.

Counter decreases, long gaps, newly observed interfaces
and interfaces returning after disappearance require a new rate baseline.
An idle interface can genuinely report 0 B/s only after a valid counter interval.
Interface-down and warming-up rates remain null with a reason.

Repeated identical CPU counters are not a new observation: the previous rate
and its original timestamp remain valid only within their existing freshness
budget, and the rate baseline is not advanced. Before any usable interval,
the value remains null/warming-up. No repeated response extends freshness.
NSProcessInfo may report Nominal when its thermal state is unknown; the enum
is reported as OS evidence, not proof of sensor availability or a cool machine.

Read-only local tracing reproduced unchanged CPU counters under concurrent
250 ms readers. Apple's published
[XNU host-statistics implementation](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/host.c)
rate-limits third-party queries using shared per-flavor caches. This is source
context, not a claim that the published revision exactly matches the running
kernel. Observation timestamps describe retrieval; Mach does not expose a
cache-generation timestamp here. Configuring a faster interval cannot guarantee
new native values on every query.

For opt-in process-top CPU rows, Sayaka converts `PROC_PIDTASKALLINFO`
user+system counters from Mach absolute-time units via `mach_timebase_info`
(consistent with Apple XNU recount examples), and local synthetic self-probe
checks matched converted deltas against process CPU-time evidence.

## Freshness and failure

Each metric carries `value`, `state`, `source`, `observed_unix_ms`, `age_ms`,
`max_age_ms` and an explicit error/reason. States are:

- `fresh`: available within its freshness budget, not necessarily sampled at
  exactly the same instant as another metric.
- `warming_up`: counters exist but no valid rate interval is ready.
- `stale`: old evidence retained after a failed refresh or expiry, never described
  as a current measurement.
- `unavailable`: no successful evidence is available.
- `unsupported`: the capability/source is absent or not implemented.

Fast freshness budgets are three configured intervals; slow budgets are two
slow intervals. The terminal ages its last snapshot even if the collector is
blocked. Stale network snapshots also mark their nested interface rates stale.
Wall-clock failure is explicit; elapsed/rate calculations use monotonic time.

The JSON schema is version 1. One-shot emits one object; watch emits complete
objects separated by newlines, with no human prelude. Optional unavailable
capabilities do not imply full status parity. Exit 0 concerns the configured
primary snapshot/output, not overall machine health; primary partial failure is
3, no primary availability is 1, invalid configuration is 2, SIGINT is 130 and
SIGTERM is 143.

## Read-only alerts

Thresholds are independently configurable:

```sh
sayaka status --watch --cpu-warn 90 --memory-warn 90 --disk-warn 10
```

CPU and working-set thresholds activate at or above the value. Available disk
fraction activates at or below its threshold. Only fresh evidence can make an
alert active or clear; stale/unknown input produces an unknown alert state.
These are transparent indicators, not an invented composite health score.
No alert kills a process, removes files, changes permissions or runs optimize.

## Lifecycle

The status panel reuses the browser's terminal guard, differential renderer and
signal handling. The UI performs no native sampling in its render loop. q/Esc
closes the panel; Ctrl-C/SIGTERM cancels collection and joins the owned worker.
The terminal is restored before waiting on a blocked native read.

Cancellation is checked between probes and during sampling waits. Native calls
already in flight and blocked output cannot be given a universal cancellation
deadline. Broken pipes stop output and cancel/join the worker, rather than
continuing invisible sampling or producing a success-shaped empty result.
SIGKILL/power loss cannot be intercepted.

## Evidence and limits

Default tests use injected providers/clocks for arithmetic, resets, missing
interfaces, stale caches, cancellation, cadence, error propagation and JSON
shapes. Native smoke checks read system metadata only. CLI subprocess/PTY checks
do not launch system maintenance or native GUI automation.

```sh
cargo build -p sayaka-cli --release --locked
python3 scripts/check_status_benchmark.py
```

The versioned [t11-v1 budget](../benchmarks/t11-v1.json) measures NDJSON and terminal
modes separately at 1 Hz fast / 5 s slow cadence, discarding the first two samples
from steady-state CPU/collection statistics. It reports process CPU/RSS,
collection latency, first frame and cancellation/restoration. The PTY helper
keeps its controlling session alive for terminal-state verification and uses
a shared monotonic clock across processes.

These are local same-scope regression budgets, not a Mole comparison, a claim
of superiority or complete T11 capability coverage. The original `t11-v1`
baseline below does not enable process top. The implemented opt-in top path has
its own [t11-top-v1 budget](../benchmarks/t11-top-v1.json); do not substitute
base-mode measurements for its cost. Numerical temperatures, GPU utilization,
Windows and unmeasured host matrices remain explicit gaps. No real-system load
or configuration is changed by the runner.

Local baseline on macOS 26.6.2 arm64 (12 snapshots per mode at 1 Hz):

| Metric | NDJSON | Terminal panel | Frozen ceiling |
| --- | --- | --- | --- |
| Maximum steady self CPU (one core = 100%) | 0.52% | Below 0.54% (display rounding bound) | 2% |
| Resident memory | 8.3 MiB current maximum | 8.5 MiB process peak | 64 MiB |
| Steady collection latency | Below 4 ms (integer-ms bound) | Not separately summarized | 100 ms |
| First frame output | Not applicable | 7.0 ms | 150 ms |
| Normal exit | Process completed | 2.9 ms | 1000 ms |
| SIGINT / SIGTERM exit | Not a stream metric | 22.8 ms / 22.7 ms | 1000 ms |

Temporary fixtures and redirected auxiliary state were cleaned. This sample
does not establish sustained behavior on every host or comparative superiority.
