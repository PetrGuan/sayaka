# M2 read-only scanning

The scanner observes explicitly supplied directories. It does not delete,
restore, uninstall, hydrate file contents, or create executable maintenance plans.
Native scanning targets macOS and an initial Windows local fixed-NTFS slice;
other platforms return an explicit unsupported-platform error. See
[Windows native scope and evidence](WINDOWS.md) for its restrictions and remaining
acceptance gates. The separate [disk browser](BROWSING.md) consumes
these observations without changing this command or its JSON v1 contract. Read-only
`.app` bundle inventory is documented separately in [APPLICATIONS.md](APPLICATIONS.md).

The engine-only [directory assessment](DIRECTORY_ACTIONS.md) reuses the immutable
scan index for observed subtree/ancestor evidence and rejection reasons. It
does not alter scan output, infer ownership/closure from complete coverage, or
authorize directory cleanup. There is no new directory-action CLI in this slice.

Native hosts can use the [read-only C ABI](BINDINGS.md), backed by engine
`scan::task` and the shared `scan::wire` JSON serializer. Its background worker,
coalesced progress and cooperative cancellation do not change the synchronous
scanner or CLI stdout contract.

## CLI contract

```sh
sayaka scan .
```

The default is a readable report: scan status, human-readable file/allocated
sizes, known/unknown subtotals, up to eight largest measured unique files, and
actionable notes. Rejected roots explain the problem without presenting empty
success totals. Partial/cancelled scans label the displayed amounts as incomplete.
Paths are escaped for safety; long display paths are shortened. JSON retains
full lossless paths and the complete available structured report.

Use an actual directory instead of a placeholder. `.` means the current
directory. Interactive terminals receive subtle colors and concise automatic
progress without a full-screen TUI. Pipes remain plain; `NO_COLOR`, `CLICOLOR=0`
or `TERM=dumb` suppress color. Human progress is throttled and never invents a
completion percentage or ETA.

For machine consumption, explicitly select JSON:

```sh
sayaka scan . --json
sayaka scan . --json --progress
sayaka scan . --json --profile-scan-stderr
```

At least one root is required; no command silently scans the current or home
directory. Relative input may be expanded against the current directory, but
parent traversal, filesystem roots and symlink paths are rejected. Use physical
paths: for example, `/private/tmp` rather than the `/tmp` symlink on macOS.
Exact repeated root paths are removed, but every distinct explicit root is
independently validated, including descendants of another root. Physical root
aliases and directory traversal are deduplicated by identity, so nested roots
remain usable even when an ancestor cannot be enumerated. The queue must have
capacity for all distinct explicit roots.
Running just `sayaka scan` prints a normally formatted usage error and a
copyable `scan .` example; it does not start a scan. Parser diagnostics escape
argument values while preserving the generated usage line breaks.
An explicitly requested root that cannot be opened always makes a mixed scan
partial, even if a discovered symlink inside a valid root would be an intentional
non-gap skip.

| Option | Default | Meaning |
| --- | --- | --- |
| `--workers` | 4 | Maximum directory traversal workers (1-32) |
| `--queue-capacity` | 64 | Maximum queued, already opened directories |
| `--max-open-dirs` | 128 | Scanner-owned directory descriptor slots; at least workers + 2 |
| `--max-depth` | 128 | Maximum directory descent depth below a selected root |
| `--max-entries` | 100000 | Maximum retained result entries, including directories/links |
| `--max-path-bytes` | 33554432 | Maximum native path bytes retained in result entries |
| `--timeout-ms` | 30000 | Cooperative traversal time budget |
| `--json` | Off | One final versioned JSON object on stdout |
| `--progress` | Auto for interactive human mode | Readable progress on stderr; NDJSON with `--json` |
| `--profile-scan-stderr` | Off | Diagnostic one-line stderr JSON with aggregate phase timings; requires `--json` |

The engine additionally bounds pending events (128), retained issues (128), root
count (64), and individual emitted paths (at most 64 KiB or the smaller configured
path budget). Issue overflow is reported as `issues_omitted`, never hidden.
Queue, descriptor and result budgets are independent; reaching a budget produces
an explicitly incomplete result rather than pretending the omitted tree is empty.

Exit codes: **0 complete, 3 partial, 130 cancelled, 1 runtime failure, 2 invalid
arguments/options**. Syntactic argument errors use clap's stderr diagnostics.
Semantic scan errors under `--json` use the versioned failure envelope.
SIGINT requests cooperative cancellation, then waits for owned workers and
policy restoration before returning the cancellation result.
Worker creation is fallible: failure stops and joins already-created workers,
releases queued directory handles, and returns a structured runtime error rather
than a caller-thread panic or a success-shaped partial startup.

## JSON v1

Every final envelope contains `schema_version`, `task_id`, `status`, `complete`,
`roots`, `entries`, `issues`, `issues_omitted`, `totals`, and `metrics`.
A failure before a task report exists has a null task ID, empty roots/entries,
a structured issue, null totals/metrics, and `complete: false`.

Paths contain an escaped diagnostic `display`, an `encoding` tag, and lossless
hex `raw` bytes (`unix_bytes_hex` on Unix; UTF-16 units on Windows). Display text
is never converted back into an execution locator. Individual entries include
a task-local resource ID, native identity, kind, nullable logical/allocated bytes,
dataless state, deduplication attribution (`counted`), and depth.

Task IDs include process and generation. Every progress record carries the same
task ID as its final report. Clients must discard events that do not match their
active task. These IDs are not durable cross-process identifiers and cannot be
used as M1 planner IDs or approval credentials.

`--json` writes one final object and newline to stdout. With `--json --progress`, stderr
carries versioned progress records with task identity and observed counts; it
must not be concatenated with stdout when parsing the final result. Human
diagnostics escape control characters. Output failures are errors, not success.
`--profile-scan-stderr` adds a separate diagnostic stderr line (`type:
scan_profile`) with aggregate `main_to_dispatch_ms`, `setup_ms`, `scan_ms`,
combined `json_encode_write_flush_ms`, optional `stdout_json_bytes`, and
`engine_elapsed_ms`. The profile line is opt-in, keeps stdout JSON unchanged,
and is not a claim of zero observer overhead.
Diagnostic schema 2 retains these fields and adds macOS `dispatch_clock_ns`
(host-wide mach-absolute nanoseconds sampled after scan flag lookup) and
`native_admission`: caller policy entry/restoration, native walk time, and up to
64 path-free root records in admission order. Root records separate no-follow
open, volume validation, directory metadata/cursor setup, URL construction, and
each of the four native volume property reads. Failed/unrun phases remain null;
root errors retain their existing codes. Volume subphases nest inside volume
validation, which nests inside the native walk; do not add parent and child
durations. Workers/enumeration/collection remain combined in the native walk
outside root opening. No per-entry clocks or cached admission are introduced.
Other platforms leave the macOS diagnostic fields absent/null. These optional
diagnostics do not alter the version 1 stdout report.

## Measurement semantics

Only regular-file payload contributes byte subtotals. A file identity contributes
once across all selected roots; other hard-link names retain their measurements
but have `counted: false`. `regular_files` counts retained file entries, while
`unique_files` and `duplicate_files` describe identity deduplication.

Logical length and allocated blocks (512-byte units on Darwin) stay separate.
Windows uses native allocation bytes, not Darwin's block conversion. Both
measure the unnamed regular-file payload; Windows alternate data streams are
not enumerated and these totals are not a complete file-footprint measurement.
Directory entries are also retained only once per physical identity, including
when an explicit nested root is later encountered beneath another root.
Invalid/unavailable values are null and increase the corresponding unknown-file
count. A zero-byte file is different from an unmeasured file. Overflow stops
collection with an explicit issue instead of wrapping or saturating byte totals.
Directory entries in M2 JSON retain null byte measurements. The separate immutable
`scan::index::ScanTree` computes per-subtree rollups for the browser; it does not
rewrite M2's global attribution. See [BROWSING.md](BROWSING.md) for non-additive
hardlink accounting, unknown measurements and conservative incomplete coverage.

The result is not an atomic filesystem snapshot. Changed directory metadata,
inconsistent hard-link measurements, failed probes, and omitted subtrees make
the result partial. `complete` means traversal completed within the no-symlinks
policy; it does not prove that every measurement is known, that contents stayed
unchanged throughout the scan, or that any object is safe to delete.
No byte field represents guaranteed reclaimable or already-freed capacity.

## Native boundaries

The engine retains `forbid(unsafe_code)`. A small separately auditable
`sayaka-platform-macos` crate contains the required native policy and volume
metadata FFI. The five-crate workspace also has a separate read-only
`sayaka-platform-windows` boundary; the policies below describe macOS, not a
shared guarantee for both operating systems.

- The caller and each traversal worker disable dataless-file materialization
  for their own thread, with explicit restoration and error propagation.
- This is not the process-only automount-trigger policy; the scanner does not
  change process-wide I/O policies or system configuration.
- Root and child directory opens use Darwin `O_NOFOLLOW_ANY`, without combining
  it with the mutually exclusive leaf-only `O_NOFOLLOW`. There is no weaker retry.
- Directory streams own file descriptors. Child metadata/open operations are
  descriptor-relative, and child identity is checked against the observed entry.
- Native filesystem locality plus explicit CoreFoundation local/internal/
  removable/ejectable flags gate roots. Missing or mistyped flags fail closed;
  unavailable is not converted to false. CF Create/Copy values are released and
  internal autoreleased temporaries are scoped to an autorelease pool.
- External, removable and network volumes are not supported in this initial
  implementation, even as explicit roots. Descendant device changes are skipped
  with a mount-boundary issue. There is no override that bypasses these checks.
- Regular files are only statted, never opened for content. Dataless directories
  are not traversed. The thread policy remains necessary for changes between
  observation and directory access.

These checks are read-only scope defenses, not a native mutation contract.
Mount metadata queries and kernel I/O can block; the budget is checked between
operations and does not promise to interrupt an arbitrary in-flight OS call.
Progress callbacks must return promptly. Scanner-owned descriptor counters do not
purport to count the hosting application's or OS frameworks' own handles.

Native API sources:
[Darwin open flags](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/fcntl.h),
[I/O policies](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/resource.h),
[file flags/accounting](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/stat.h),
and [CFURL property ownership](https://github.com/swiftlang/swift-corelibs-foundation/blob/main/Sources/CoreFoundation/include/CFURL.h).

## Validation and local performance gate

Unit fixtures inject queue pressure, unknown measurements, probe failures,
replacement, cross-device entries, dataless directories, cancellation, deadlines,
policy failures and worker panics. Native macOS fixtures cover ordinary/empty/
deep trees, hard links, sparse files, symlink ancestors, permissions, budgets and
control-character names. CLI subprocess tests validate wire output and exits.

APFS on the current host rejects creation of arbitrary non-UTF-8 filenames.
Synthetic path/serialization checks must not be called a native round trip.
Actual File Provider and network/removable volume scenarios still need dedicated
environments; simulated policy cases do not establish those results. Initial
Windows native evidence and remaining platform gates are recorded separately in
[WINDOWS.md](WINDOWS.md).

The versioned [m2-v1 fixture budget](../benchmarks/m2-v1.json) covers 8242 unique
files, 8370 file entries and 67636228 logical bytes, including a 48-level tree,
empty directories, sparse data, hard-link aliases and a skipped symlink.

```sh
cargo build -p sayaka-engine --release --example scan_fixture_bench --locked
python3 scripts/check_m2_benchmark.py --verify
```

The runner creates its own container, launches only the fixture benchmark,
checks ground truth and cleanup, and measures that child's macOS peak RSS.
Its gate is 500 ms per scan, 100 ms to first result, 100000 microseconds from
cancellation request to return, and 64 MiB peak RSS for this fixture. Structural
worker/queue/descriptor/event/path caps are checked as well.

`first_result_ms` measures the first retained child entry, or completion for a
proven empty traversal, not the initial root-admission progress event. Integer
millisecond zero means less than one millisecond, not instantaneous work.
Fixture creation precedes timing and warms filesystem caches. This is a local
regression gate, not an OS-cold benchmark, a universal latency promise, or a
comparison establishing superiority over Mole.
