# M2 read-only scanning

The scanner observes explicitly supplied directories. It does not delete,
restore, uninstall, hydrate file contents, or create executable maintenance plans.
Native scanning currently targets macOS; other platforms return an explicit
unsupported-platform error. This is not yet the interactive disk explorer.

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
```

At least one root is required; no command silently scans the current or home
directory. Relative input may be expanded against the current directory, but
parent traversal, filesystem roots and symlink paths are rejected. Use physical
paths: for example, `/private/tmp` rather than the `/tmp` symlink on macOS.
Overlapping or repeated roots are normalized by path components; physical root
aliases are deduplicated by identity.
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

## Measurement semantics

Only regular-file payload contributes byte subtotals. A file identity contributes
once across all selected roots; other hard-link names retain their measurements
but have `counted: false`. `regular_files` counts retained file entries, while
`unique_files` and `duplicate_files` describe identity deduplication.

Logical length and allocated blocks (512-byte units on Darwin) stay separate.
Invalid/unavailable values are null and increase the corresponding unknown-file
count. A zero-byte file is different from an unmeasured file. Overflow stops
collection with an explicit issue instead of wrapping or saturating byte totals.
Directory entries currently have null byte measurements; M2 provides global
deduplicated subtotals and per-file measurements, not per-directory rollups.

The result is not an atomic filesystem snapshot. Changed directory metadata,
inconsistent hard-link measurements, failed probes, and omitted subtrees make
the result partial. `complete` means traversal completed within the no-symlinks
policy; it does not prove that every measurement is known, that contents stayed
unchanged throughout the scan, or that any object is safe to delete.
No byte field represents guaranteed reclaimable or already-freed capacity.

## Native boundaries

The engine retains `forbid(unsafe_code)`. A small separately auditable
`sayaka-platform-macos` crate contains the required native policy and volume
metadata FFI; this is the deliberate fourth workspace crate.

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
Actual File Provider, network/removable volume and Windows scenarios still need
dedicated environments; simulated policy cases do not establish those results.

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
