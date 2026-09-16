<!-- SPDX-License-Identifier: MPL-2.0 -->

# Native scan and directory-query ABI v1

Status: a narrow, in-process, read-only C ABI with local macOS C/Swift host
evidence. It is not a full SDK, native App UI, release/signing contract, or
permission to perform cleanup. The Windows x64 Rust branch has cross-target
type-check evidence only; Windows linking/host execution is not certified here.
The directory-query additions reuse the engine's immutable `ScanTree`, including
the same size ordering and accounting used by the terminal browser.

## Build and consumers

```sh
cargo build -p sayaka-bindings --locked
python3 scripts/check_bindings_host.py
```

The crate emits an `rlib`, `staticlib` and `cdylib`. On macOS the dynamic library
is `target/debug/libsayaka_bindings.dylib`; Windows builds produce the platform's
DLL/import-library artifacts when built with a suitable native linker/toolchain.
The checked-in [C header](../crates/bindings/include/sayaka.h) is the v1 layout.
Versioned symbol names permit later ABI versions without changing v1 structures.
The three directory-query symbols are additive: existing v1 layouts and scan
JSON have not changed. A host using queries must ship/load a library build
exporting those symbols; the original scan-only library also reports version 1.
Use the normal C calling convention (C# callers would specify Cdecl).

The [C consumer](../crates/bindings/examples/scan_host.c) and
[Swift consumer](../crates/bindings/examples/scan_host.swift) call the library
directly. The Swift example is a command-line host, not an AppKit/SwiftUI UI.
The C source includes a Windows `wmain`/UTF-16LE input branch, but running the
macOS example does not establish Windows consumer correctness. For Windows
static linking define `SAYAKA_STATIC`; otherwise the header uses DLL imports.

The local host runner selects one matching Apple SDK for C and Swift explicitly,
compiles both consumers, and uses a unique owned fixture. It verifies exact
file/count/byte/native-path identity results, missing-root failure, handle
capacity, cancellation/release, stale handles and caller-buffer bounds. Its
fixture contains 64 unique files, two hardlink aliases across sibling directories,
an empty directory and four directories in total. The C host exercises root
pages and cross-task node rejection; the Swift host recursively pages every
directory, checks individual details against page entries and the full report,
and checks name/logical-size/allocated-size orders over multiple pages.
The C host also races per-handle poll/cancel/result/root-query calls with release.
Successful fixture files and consumers are identity-checked and cleaned; failed
fixture evidence is retained under `target`. No CLI child, user-data scan,
real Trash, mount, package execution or permission expansion occurs.

## Lifecycle

1. Check `sayaka_abi_version_v1()` and initialize `SayakaScanRequestV1` with
   ABI version 1, exact `sizeof` and 1..64 explicit native root descriptors.
2. Call `sayaka_scan_start_v1`. Inputs are copied before return; a successful
   start returns a nonzero process-local handle, not a successful scan result.
3. Poll with `sayaka_scan_poll_v1` for lifecycle state and the latest coalesced
   progress. No foreign callbacks or process-global signal handlers are installed.
4. Request cancellation with `sayaka_scan_cancel_v1` if needed. It is cooperative;
   an already complete result stays complete rather than being rewritten.
5. Once terminal, browse via root/node/children queries or optionally copy the
   full JSON with `sayaka_scan_result_v1`, on a host worker queue. Inspect
   status/complete/issues; copy success is not scan success.
6. Call `sayaka_scan_release_v1`. If the worker is still active, it requests
   cancellation and returns BUSY without invalidating the handle. Retry later.
   OK invalidates the handle and it is never reused.

The library must remain loaded until every handle has successfully released
and all host API calls have returned. Hosts must also stop their own polling/
result callers before unloading; release does not join foreign host threads.
There is no detached-worker release or force-stop function. A native OS call
may block beyond the scan budget, so neither cancellation nor shutdown has a
universal wall-clock bound. Hosts must not spin or block their UI waiting for
release; schedule retries. A Rust `ScanTask` drop cancels and joins owned work,
whereas the C release path will not drop an unfinished task.

Calls on one handle are serialized. Contending poll/cancel/result/query/release calls
return BUSY instead of waiting behind a large result serialization/copy. In
that contention case cancellation may not yet have been requested; retain the
handle and retry. Calls on distinct handles use separate task locks, with only
short registry operations shared. This is not a real-time/wait-free guarantee.
Calls racing a successful release may finish before it or return INVALID_HANDLE;
no caller can obtain a dangling Rust object.

## Native paths and task limits

`SayakaPathV1.byte_length` is a byte count, never a C-string length including NUL.
Use encoding 1 (Unix path bytes) on Unix and 2 (UTF-16 little-endian code units
encoded as bytes) on Windows. Unix non-UTF-8 bytes and Windows unpaired UTF-16
units are not converted through lossy display text. Windows input has an even
byte length; native NULs are rejected.

Roots must be non-root absolute paths without parent traversal. There is no
implicit cwd/HOME scan. Each input is limited to 65,536 bytes and 1..64 roots;
aggregate native path storage is checked against the scan budget. Unsupported
path encodings/arguments fail explicitly. Missing/unavailable directories are
terminal scan errors/reports, not empty successful results.

V1 uses the existing `ScanLimits::default()` profile: four directory workers,
bounded queue/events/handles, 100,000 retained entries, 32 MiB retained path
budget and a cooperative 30-second traversal budget. No native protection,
no-follow or materialization checks are bypassed. See [SCANNING.md](SCANNING.md).

At most four handles may be retained in this library instance, including finished
tasks whose results have not been released. Handles are monotonically allocated
and never recycled; exhaustion/capacity has an explicit error. The JSON payload
cap is 64 MiB per handle, enforced during serialization. This is a payload cap,
not a claim that the retained report, vector capacity, worker stacks and copies
together use only 64 MiB.

## Progress and results

The snapshot uses fixed-width fields and carries ABI/structure sizes. State is
Running, Complete, Partial, Cancelled or Failed. `has_progress=0` means counters
are absent, not measured zeros. `progress_sequence` identifies updates; the one
coalesced slot can skip intermediate progress records without blocking the worker.
Repeated polls can return the same sequence/counters. Final truth is the report,
not the last progress sample.

The shared serializer now lives in `sayaka_engine::scan::wire`, reexported by the
CLI. Result JSON reuses the existing scan/fatal v1 schema, including lossless
`unix_bytes_hex` / `windows_utf16_hex` paths, scoped resource IDs, statuses,
issues and known/unknown accounting. The C handle identifies the asynchronous
job even when a fatal JSON report has no engine task ID. Default CLI JSON is
unchanged; no separate native interpretation of scan findings is introduced.

Query result size with `buffer=NULL, capacity=0` and a valid `required` pointer.
BUFFER_TOO_SMALL supplies the exact required length. An undersized buffer is
not partially written. A successful copy writes exactly that many bytes,
including the report's newline but no terminating NUL; the host owns and frees
the destination storage. A cached result is stable until release.

Result serialization and large copies can take time; perform them off the UI
thread. Before completion, NOT_READY returns no partial result. A result-cap or
serialization failure returns an error, never truncated JSON. Snapshot state
describes the scan itself, so a complete scan can still fail result transfer;
the host must handle that error and release the task.

## Directory queries

| Function | Data returned |
| --- | --- |
| `sayaka_scan_roots_v1(handle, page, buffer, capacity, required)` | A page of observed forest roots with node details |
| `sayaka_scan_node_v1(handle, node, buffer, capacity, required)` | One node with its observed parent, path, measurements and summary |
| `sayaka_scan_children_v1(handle, parent, page, buffer, capacity, required)` | A page of the directory's immediate observed children, not a recursive result |

Initialize `SayakaPageRequestV1` with ABI version 1 and exact `sizeof`.
`limit` is 1..256. `offset` is a zero-based position in the selected order;
`offset == total` returns an empty terminal page, and `offset > total` is
INVALID_ARGUMENT. `sort` is NAME (native path ascending), LOGICAL_SIZE or
ALLOCATED_SIZE (known subtotal descending, unknown last, native path ascending
for ties). Names are not case-folded, locale-collated or sorted by display text.
The same options apply to roots. Keep sort fixed while advancing a page cursor;
reset offset to zero when changing sort or starting a new task.

The first query lazily builds and retains one `ScanTree` from a bounded clone
of the terminal report. It does not scan again, parse the full JSON or change
the original report. Subsequent queries reuse the tree, directory summaries
and cached orderings; they serialize only the requested nodes. Building the tree
is O(N) hierarchy/accounting work plus sorting, not an O(page-size) first query.
The additional report copy, hierarchy and two size-order indexes have memory
cost beyond the output cap. Tree failure is explicit and does not discard the
original scan report or change poll state.

All queries run on the calling thread. Use a host worker queue, not the main/UI
thread, including length queries. Index construction is bounded by the same
100,000-entry/32 MiB native-path index limits but has no universal time promise.
A concurrent cancel/release returns BUSY while a query holds the task lock;
it does not interrupt a query on an already terminal snapshot. Retry release
after that query exits. No ongoing tree-building worker is detached.

The length/copy protocol is the same as full results, but the payload and caller
capacity cap is **1 MiB** (`SAYAKA_MAX_QUERY_BYTES_V1`). A page that cannot be
serialized within the cap returns LIMIT_EXCEEDED with `required=0`, not a partial
page; retry with a smaller limit. Only BUFFER_TOO_SMALL provides a required
length. Other errors leave `required=0`. Buffers are untouched on errors and
too-small capacity; successful JSON has no trailing NUL or newline. Length and
copy calls serialize their bounded payload independently; immutable data makes
the bytes stable unless a concurrent caller releases the handle.

### JSON schema

Every query has `schema_version: 1`, `task_handle` (decimal string),
`scan_task_id` (the original report ID), `scan_status`, `scan_complete`,
`observed_issues` (retained issue count), `issues_omitted`, and `data`.
Use the optional full scan result for individual diagnostic code/message/path
details; no full report transfer is needed for ordinary directory navigation.

For roots/children, `data` is:

```json
{
  "offset": 0,
  "total": 3,
  "next_offset": 1,
  "nodes": [
    {
      "reference": {"task_handle": "7", "node_id": "2"},
      "resource_id": "123:4/2",
      "parent": {"task_handle": "7", "node_id": "1"},
      "path": {
        "display": "\"/fixture/a\"",
        "encoding": "unix_bytes_hex",
        "raw": "2f666978747572652f61"
      },
      "kind": "directory",
      "logical_bytes": 11,
      "allocated_bytes": 4096,
      "directory_summary": {
        "unique_files": 1,
        "logical_bytes_known": 11,
        "logical_bytes_unknown_files": 0,
        "allocated_bytes_known": 4096,
        "allocated_bytes_unknown_files": 0,
        "complete": true
      },
      "child_count": 1,
      "dataless": false
    }
  ]
}
```

`next_offset` is null at the end. Single-node `data` is the node object directly.
`reference` always includes both the task handle and local ID; parse decimal
strings as unsigned 64-bit integers, not floating point, to fill
`SayakaNodeRefV1`. `resource_id` matches the full scan report's entry ID and is
not a substitute for the native handle. `parent` is null for an observed forest
root. `child_count` and `directory_summary` are null for non-directories.
`kind` is `file`, `directory`, `link` or `other`; `dataless` retains the scan
observation. Native paths use the existing lossless encoding; `display` is only
presentation. Windows `windows_utf16_hex` encodes each UTF-16 unit as four hex
digits, whereas scan input uses little-endian bytes. Do not confuse the two.

For files, `logical_bytes`/`allocated_bytes` retain their individual observations.
For directories they are **known subtotals**, not necessarily complete sizes:
always consult the summary's unknown counts and `complete`. Wholly unmeasured
directories and incomplete directories with no observed files return null,
whereas a completely scanned empty directory returns zero. Links and other
non-file objects have null payload sizes. The two measurements stay independent.

Summary accounting is exactly `ScanTree` accounting: each file identity counts
once per subtree, regardless of the report's global `counted` attribution.
Hardlinks in two sibling directories contribute to each sibling and once to
their parent. **Sibling totals are not additive.** Conflicting/unknown alias
measurements remain unknown; file observations themselves are not rewritten.
Coverage is conservative across the report, not a promise that an individual
directory was freshly/atomically observed. These are not reclaimable-byte totals.

### Readiness, refresh and stale references

Running tasks return NOT_READY, never live pages assembled from partial worker
state. Complete, partial and cancelled reports can be indexed; each response
retains its scan status, unknown measurements and coverage. Failed scans return
QUERY_UNAVAILABLE; retrieve the scan result for details rather than showing an
empty successful directory. Missing node IDs return INVALID_NODE, and children
queries on a file/link/other return NOT_DIRECTORY.

Refresh is explicit: start a new task, fetch its roots and replace the App's
active handle and navigation references. There is no in-place rescan or
filesystem watcher. Passing an old reference to the new handle returns
INVALID_NODE even if the old handle is still live and both scans use the same
local node number. Old tasks remain readable immutable snapshots until release;
after release their own queries return INVALID_HANDLE. An App must discard late
responses whose `task_handle` is no longer its active handle.

References are process/library-lifetime identifiers, not persistent locators or
security capabilities. They do not verify that a file still exists and cannot
authorize cleanup, approval or a native viewer. No query performs filesystem
I/O or converts a directory into an execution target.

## Error and memory contract

All fallible functions return an explicit status code. API errors are distinct
from a successfully retrieved failed/partial scan result:

| Status | Meaning |
| --- | --- |
| INVALID_ARGUMENT / UNSUPPORTED_VERSION | Bad arguments, native encoding or v1 layout/version |
| UNSUPPORTED_PLATFORM | No native scan backend for the host |
| INVALID_HANDLE | Unknown/already released handle |
| INVALID_NODE / NOT_DIRECTORY | Missing/cross-task reference or a non-directory children request |
| QUERY_UNAVAILABLE | Failed scan; inspect its structured result |
| LIMIT_EXCEEDED | Retained-task/input/result/index/query capacity cannot be satisfied |
| NOT_READY / BUFFER_TOO_SMALL / BUSY | Retain ownership and follow the lifecycle/size/retry protocol |
| INTERNAL_ERROR / PANIC | Internal state/output error or contained unwinding panic |

`sayaka_status_message_v1` returns a static UTF-8 message that must not be freed.
Async scan failures preserve the shared structured code/message/OS error in JSON.
Worker panics become failed tasks; unwinding panics at C entry points are contained.
The library does not replace the process panic hook, and allocator aborts or
`panic=abort` builds cannot be promised recoverable.

Caller pointers must be readable/writable for the stated length, aligned for
their structures, live through the call and not concurrently accessed or
overlapping with that call's other inputs/outputs. Null/alignment checks cannot
validate arbitrary foreign memory. A dangling/forged pointer is caller undefined
behavior, not something error codes or panic containment can make safe.
Only the bindings crate handles these foreign-memory reads/writes; the engine
remains `forbid(unsafe_code)` and system FFI remains in the platform crates.

## Platform evidence and remaining work

Local macOS arm64 C and Swift consumers exercised this ABI against owned fixtures.
Windows x64 `cargo check -p sayaka-bindings --all-targets
--target x86_64-pc-windows-msvc --locked` passes after isolating the existing
macOS-only clean-policy implementation. Its macOS function bodies are unchanged;
non-macOS policy operations return Unsupported before filesystem access. This
removes a shared-engine compile blocker without enabling Windows cleanup.
Existing unrelated engine warnings remain in that Windows check; it is not a
warning-free Windows release or a DLL/native consumer run.

Windows linking/runtime/consumer evidence, ARM64 binding acceptance, native App
integration and signed distribution remain separate work. No C ABI cleanup,
approval, recovery, directory action, rule management or status sampler is
exported by these read-only scan/browsing slices.
An additional macOS x86_64 Rust type check passes; it is not Intel runtime or
minimum-OS acceptance. The local C/Swift host runs were on Apple silicon.
