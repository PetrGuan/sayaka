# Simulator and runtime cleanup contract (draft for review)

Status: **contract only — not implemented.** This document is the required
implementation contract for the first slice of developer-tool operations. It
must pass independent feasibility and scope review before any write code lands.

Xcode simulators and simulator runtimes are often the largest part of the
macOS Storage "Developer" and "System Data" categories. A measured developer Mac
had 34 GB of simulator device data across 59 devices, against 17 GB of
DerivedData, plus six runtimes totalling about 40 GB: one classic disk image
(7.3 GB, under `/Library/Developer/CoreSimulator/Images`) and five
"Patchable Cryptex" images (3.8–8.5 GB each, under
`/System/Library/AssetsV2`, managed by MobileAsset and counted as System Data). They are not file-level caches: CoreSimulator owns their records,
and removing them correctly means asking Apple's `simctl` tool to do it. The
existing purge profile therefore lists `xcrun simctl delete unavailable` as an
unsupported operation and never touches `CoreSimulator/Devices`.

This slice adds a **separately owned, permanent tool-operation session** for
unsandboxed hosts (the Developer ID application and the CLI). It is distinct
from `revalidated_trash_v1`: nothing here moves to Trash, and nothing here may
be offered as a Trash fallback or a Trash failure path.

## Scope

In scope (macOS only):

| Operation | `simctl` argument vector | Effect | Recovery |
| --- | --- | --- | --- |
| Delete unavailable devices | `delete unavailable` | Removes devices whose runtime is no longer supported by the selected Xcode | None for their contents; a new device can be created |
| Erase devices | `erase <udid> [<udid> …]` | Resets contents and settings; the device record stays | None for erased contents |
| Delete devices | `delete <udid> [<udid> …]` | Removes the device record and all its data | None for its contents; a new device can be created |
| Delete runtimes | `runtime delete <identifier>` (one per call) | Removes a runtime from CoreSimulator storage; devices using it become unavailable | Re-download from Xcode Settings ▸ Components or `xcodebuild -downloadPlatform` |

Out of scope for this slice:

- `delete all`, `erase all`, `runtime delete all`, `--notUsedSinceDays`,
  `--unusable` and `--outdated` bulk forms. Bulk intent must be expressed as an
  explicit list of previewed identities.
- Simulator app contents, individual app containers, device logs, Xcode
  Archives, DerivedData (already a purge cache rule), DeviceSupport folders,
  documentation caches and toolchains.
- Package-manager cleanups (`brew cleanup`, `npm cache clean`, `pnpm store
  prune`, `yarn cache clean`, `pip cache purge`). They need their own slice:
  their caches already have recoverable file-level Trash rules, and each tool's
  dry-run support and effect boundary differs.
- Windows, sandboxed hosts, privilege escalation and the privileged helper.
  Nothing in this slice runs as root.

## Tool resolution and process boundary

Process launch is new to the core and is confined to `sayaka-platform-macos`.
`sayaka-engine` stays unsafe-free and receives only parsed, validated records.

- Launch **only** `/usr/bin/xcrun` with argument vectors built from the fixed
  table above and previewed identities. No shell, no string interpolation into
  a command line, no user-supplied arguments, no other executables.
- Environment: start empty, then set `PATH=/usr/bin:/bin`, `HOME` (the account
  home from the password database) and `LANG=C`. `DEVELOPER_DIR` is not
  inherited; `xcrun` uses the system-selected developer directory, and the
  preview records which one (`xcrun --find simctl` and `xcode-select -p`
  results) as evidence. A different selection at execution time is a refusal.
- stdin is `/dev/null`. stdout and stderr are captured with caps (8 MiB stdout,
  64 KiB stderr); exceeding a cap fails the call. Timeouts: 30 s for list and
  dry-run calls, 10 min per execution call; on timeout the child is terminated
  and the outcome is **unknown**, never success.
- If `simctl` is unavailable (Command Line Tools only, no Xcode selected, or
  unlicensed Xcode), the capability is reported as unavailable with the reason;
  nothing falls back to manual file deletion.

## Preview

`simctl list devices -j` and `simctl runtime list -j` are parsed into versioned
records. Unknown JSON shapes, missing required fields or non-UTF-8 output make
the preview fail closed.

Each device record retains: `udid`, `name`, runtime identifier, device type,
`state`, `isAvailable`, `dataPath`, `dataPathSize`, and a last-used observation
(modification time of `dataPath`, reported as an observation, not usage
history). Each runtime record retains: `identifier`, `runtimeIdentifier`,
`version`, `build`, `kind`, `path`, `sizeBytes`, `lastUsedAt`, `deletable`,
`state`, and the devices that reference it.

The preview reports, without effects:

- candidates per operation, with sizes labelled **estimated** (CoreSimulator
  sizes can include clone-shared blocks; freed space is not guaranteed);
- for a runtime delete, the devices that would become unavailable and the
  output of `runtime delete <identifier> --dry-run`;
- refusals (below) and an `execution_eligible` flag per candidate;
- the selected developer directory and tool path evidence;
- the effect class `permanent_tool_operation_v1` and an exact approval token.

Nothing is pre-selected. Hosts must present these operations in their own
confirmation, separate from Trash review, listing every device/runtime by name,
runtime, size and what is lost ("installed apps and their data in these
simulators"). This separate strong confirmation was approved by the maintainer.

## Refusals

A candidate, or the whole request where stated, is refused when:

- Xcode (`com.apple.dt.Xcode`) or Simulator (`com.apple.iphonesimulator`) is
  running — whole request;
- a targeted device is not `Shutdown`, or a runtime has any device that is not
  `Shutdown` — that candidate;
- a runtime is not `deletable`, is the runtime of the selected Xcode's default
  SDK, or is in a transitional `state` — that candidate;
- the developer directory or `simctl` path differs from the preview — whole
  request;
- the request contains duplicate, unknown or non-previewed identities, more than
  32 devices, or more than 4 runtimes — whole request;
- the preview is older than 120 seconds — whole request (re-preview).

## Execution and revalidation

1. The host echoes the exact approval token with the selected identities. The
   session accepts only identities from its own retained preview; it never
   accepts imported JSON or identity claims.
2. Write a durable journal intent (operation, identities, tool evidence, preview
   summary) before the first launch. If the intent cannot be written, nothing
   runs.
3. Revalidate immediately before each call by re-listing: same `udid` with the
   same name, runtime, `dataPath` and `Shutdown` state; same runtime
   `identifier`, `build`, `version` and `path`; Xcode and Simulator not running.
   Any mismatch refuses that call; earlier completed calls are not undone.
4. Run one argument vector at a time (devices may be batched up to 8 UDIDs per
   call; runtimes one per call). Record exit status and capped stderr.
5. Post-check by re-listing: a deleted identity that is gone is `succeeded`; an
   erased device still present and `Shutdown` is `succeeded`; anything else, or
   any timeout, is `unknown` and must not be blindly retried.
6. Write the journal outcome. Results are per identity:
   `succeeded`, `refused`, `failed`, `unknown`.

Residual risk, disclosed rather than hidden: between revalidation and the
`simctl` call another process (Xcode, a test runner, CI) can boot a device or
start using a runtime. `simctl` may then shut it down (runtime delete documents
this) or fail. This race is accepted only with the separate confirmation above
and is never described as race-free.

## Bindings and CLI

- Bindings: a companion `sayaka_devtools_*_v1` ABI following the existing
  start / poll-result / execute / release session pattern, a capability call
  that reports availability and the reason when unavailable, and JSON schemas
  `sayaka.simulator_preview` and `sayaka.simulator_execution` (schema 1).
- CLI: `sayaka devtools simulators` (preview) and an execution form that
  requires the typed token, mirroring `purge` confirmation. `--json` emits the
  schemas above.

## Tests and evidence

- Unit (engine): JSON fixtures recorded from real `simctl` output for several
  Xcode versions; schema drift, missing fields, booted devices, non-deletable
  runtimes, identity changes between preview and execution, token mismatch,
  limits and expiry.
- Fault injection (platform): an injected tool runner for timeout, non-zero
  exit, oversized output, malformed JSON and post-check mismatch.
- Real platform (opt-in only, never on existing devices): create a throwaway
  device with `simctl create`, then erase and delete it through the session.
  Runtime deletion is verified only on an explicitly provided disposable
  runtime; the default suite never deletes a runtime.
- No test may target devices or runtimes it did not create.

## Open decisions for review

1. Confirm `permanent_tool_operation_v1` as a new effect class, with its own
   approval token format, for example `delete 3 simulators` / `delete 1 runtime`.
2. Confirm that `erase` is offered (it keeps the device but loses its contents).
3. Confirm the default-SDK runtime refusal, or allow it with an extra warning.
4. Measure whether `simctl runtime delete` needs administrator rights, for both
   runtime kinds (classic disk image and MobileAsset-managed cryptex image), on
   supported macOS versions. Observed so far: `runtime delete <id> --dry-run`
   succeeds unprivileged ("Would delete …"), which does not prove the real
   deletion does. If either kind needs administrator rights, that kind moves to
   the privileged-helper contract instead of this slice.
5. Cryptex runtimes live in system-managed MobileAsset storage. Confirm that
   deleting them through `simctl` is the supported path, and that the reported
   `sizeBytes` is what the volume actually frees.
