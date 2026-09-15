# Terminal disk browser

`sayaka browse ROOT` (alias `analyze`) displays a bounded, read-only snapshot of
one explicitly selected physical directory. No argument defaults to a home
directory or current directory. Existing `scan` and its JSON v1 remain unchanged.
`sayaka menu` is a separate terminal entry point that can launch `browse`,
`rules preview`, installer discovery, or the existing `clean --execute` /
`installer --execute` approval flows only after you pick an action and type an
explicit root. Installer mode defaults to read-only preview; the approval entry
still prompts for exact candidate selection and confirmation in the child CLI.

```sh
sayaka browse .
sayaka analyze .
sayaka browse . --plain
```

Non-terminal stdin/stdout or `TERM=dumb` automatically selects a plain read-only
report. This reports root accounting and up to 100 immediate entries without
entering raw mode. Full-screen mode uses the terminal's alternate screen;
`NO_COLOR` and `CLICOLOR=0` disable colors. Native paths are retained internally;
display escaping, filtering and clipping never become execution locators.

## Navigation

| Key | Action |
| --- | --- |
| Arrows or j/k | Move cursor |
| Enter / Right | Enter an observed directory |
| Left / Backspace | Return to its observed parent |
| Home / End / PgUp / PgDn | Navigate the current list |
| / | Edit the displayed-name filter; Enter accepts, Esc clears |
| s | Size/name ordering |
| a | Logical/allocated measurement |
| Space | Toggle an ordinary file selection |
| x | Toggle an observed file/directory exclusion |
| v | Selected-file view |
| t | Prepare an exact M3 plan |
| o | Explicit Finder reveal |
| p | Read and acknowledge a Quick Look request |
| r | Refresh; clears old selections |
| m / ? / i | Menu, help, scan issues |
| Esc | Cancel the current modal or owned job |
| q / Ctrl-C | Quit / cancel and quit |

Directories are navigable but cannot be selected for recursive Trash. Links and
known cloud placeholders are not action candidates. Selection and exclusions
are limited to 32 each by M3. Excluding a directory covers its observed children;
the final plan still applies the engine's native identity-aware exclusion policy.

The browser does not continuously monitor the filesystem. Results may become
stale, and the interface says so. Refresh creates a new generation after joining
the old job; old results and IDs cannot overwrite or authorize a newer selection.

## Directory accounting

The engine's immutable `scan::index::ScanTree` retains the M2 report and adds a
hierarchy plus per-directory summaries. Each subtree counts a regular-file
identity once, independently of M2's global `counted` attribution. A hardlink in
two siblings contributes to both siblings but only once to their parent.
**Sibling sizes are not additive.**

Logical and allocated measurements remain separate. Unknown or conflicting
measurements for an identity are not resolved by arbitrarily choosing an alias.
Their corresponding unknown counts remain explicit. Directories, links and other
non-file objects do not contribute file-payload bytes.

`*` labels incomplete coverage; `+?` indicates unknown measurements alongside a
known subtotal. A wholly unmeasured or uncovered directory says unknown rather
than appearing as an empty zero-byte directory. These observations are neither
an atomic snapshot nor reclaimable/free-space measurements.

Indexing uses transient small-to-large identity-set merging. Completed descendant
sets are not retained for every ancestor. Construction has checked arithmetic,
cancellation, duplicate/invalid-input rejection, a 100,000-entry limit and a
32 MiB native-path budget. Existing scanner worker, queue, descriptor, event,
depth and timeout budgets remain in force.

## Selection to native approval

Preparing a plan freezes the selected generation, native paths and observed
identities. A background worker validates the observed scope/files and creates
the real `TrashSession`. Its eligible preview must still match the chosen
identities and known sizes. Detected changes require refresh/reselection.

The worker retains its session while the UI displays the immutable plan, scope,
exact escaped paths, exclusions/refusals, measurements and the existing
`revalidated_trash_v1` warning. A long preview is wrapped and scrollable.
Confirmation is disabled until its lines have been presented, and requires the
exact typed `trash N` phrase. A terminal smaller than 60 columns by 14 rows cannot
confirm a plan. Resize invalidates presentation progress.

The confirmation identifies that exact plan and generation. No scan, new plan,
replacement selection or implicit expansion occurs after confirmation.
The existing engine owns approval, final revalidation, intent publication,
native execution and receipts; the UI does not duplicate those policies.
See [EXECUTION.md](EXECUTION.md) for the accepted residual path race and journal
durability/recovery contract.

After an execution the snapshot is marked stale and selection is cleared.
Unknown outcomes remain unknown, retain available recovery evidence, and are
never automatically retried. Refresh is explicit and is not an authorization
to repeat an old action. `--state-dir DIR` selects the same private M3 state
store as the standalone CLI and is not created by scanning or preview cancellation.

## Background work and terminal lifecycle

The UI polls input and renders cached observations. Scanning, indexing, native
plan preparation/execution and system helper waits do not run in the render
loop. Only one owned application job runs at a time. Scan progress occupies one
coalesced slot; preview and confirmation channels each hold at most one message.

Cancellation requests stop new work and join owned workers. Terminal restoration
is attempted before waiting for an in-flight OS call during shutdown. External
SIGINT/SIGTERM are handled cooperatively; raw mode, alternate screen and cursor
are restored on normal return, errors and Rust unwinding. SIGKILL, process abort,
power loss and an unresponsive terminal cannot be guaranteed recoverable.

SIGINT/control-C exits 130 and SIGTERM exits 143. Quitting an active job requests
cancellation; quitting a finished snapshot returns its outcome code. Native
ambiguity/journal failure takes precedence over a successful read-only result.
No worker or mutating native call is silently detached.

## Explicit system viewers

Finder reveal invokes only `/usr/bin/open -R` with a native absolute argument.
Quick Look invokes only `/usr/bin/qlmanage -p` after a separate acknowledgement.
There is no shell command construction, arbitrary executable path or activation
on cursor movement. The scanner's native no-follow policy rechecks scope/target
identity and known file size immediately before dispatch. Changed entries,
links and known placeholders are refused.

An external viewer reads contents and may use installed providers. It does not
inherit an engine-enforced no-hydration or isolation guarantee, and the final
path handoff is not atomic. These are explicit viewing requests, not scanning
side effects. Their helper processes are owned, checked for failure and stopped
on cancellation or a five-minute helper budget. Finder windows may remain open
as user-requested OS UI. No host permission settings are changed.

## Local performance and validation

The [m7-v1 manifest](../benchmarks/m7-v1.json) freezes a fixture with 1024 unique
1 KiB files, 16 hardlink aliases, empty/deep directories and a skipped symlink.
The local PTY runner measures first frame bytes, first usable snapshot, input
response and cooperative shutdown, checks exact root/alias accounting, navigates,
filters, selects and cancels a native preview, and verifies terminal restoration.

```sh
cargo build -p sayaka-cli --release --locked
python3 scripts/check_m7_benchmark.py
```

The runner never confirms Trash or invokes Finder/Quick Look. All files and child
processes are uniquely owned and cleaned. Budgets are local fixture regressions,
not universal I/O deadlines. Processes are fresh; OS cache state is uncontrolled.
PTY timings are not human usability evidence. No full Mole installation,
equivalent-work comparison or complete distribution-size advantage is claimed.

The runner keeps a controlling-terminal broker alive while inspecting the
finished CLI's terminal attributes; macOS can otherwise revoke the slave at
session-leader exit. Cross-process timestamps use `CLOCK_MONOTONIC`, not
Python versions whose `monotonic()` epochs differ across processes. Output is
continuously drained during shutdown, rather than filling the PTY and making a
reader-induced stall look like an application hang. Redirected auxiliary HOME
caches are bounded and cleaned along with explicitly registered fixtures.

Initial local evidence on macOS 26.6.2 arm64, three fresh CLI processes:

| Metric | Observed maximum | Frozen limit |
| --- | --- | --- |
| First frame output | 8.1 ms | 150 ms |
| First usable fixture snapshot | 29.2 ms | 1500 ms |
| Index construction | 2 ms | 250 ms |
| Input-to-response output | 0.4 ms | 100 ms |
| Normal shutdown | 1.2 ms | 1000 ms |
| SIGINT/SIGTERM shutdown | 22 ms | 1000 ms |
| CLI peak RSS | 14.3 MiB | 128 MiB |

These values cover only the declared fixture and mechanical terminal checks.
Real Trash and system viewers were not executed in this M7 validation.
