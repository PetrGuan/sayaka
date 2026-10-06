# Simulator and runtime cleanup contract

Status: **slice 1a implemented; native acceptance on throwaway devices pending.**
The policy (`sayaka-engine::devtools`), the launch boundary
(`sayaka-platform-macos::devtools`), the session (`sayaka-engine::devtools::session`),
journal schema 6, the `sayaka_simulators_*_v1` bindings
([BINDINGS.md](BINDINGS.md)) and `sayaka devtools simulators` implement device
erase and delete. Their unit tests are written against an injected host and
journal; the opt-in real-platform cases below have not been run, so no native
outcome is claimed yet. Slice 1b (runtimes) is not implemented.

Xcode simulators and simulator runtimes are often the largest part of the
macOS Storage "Developer" and "System Data" categories. One measured developer
Mac had 34 GB of simulator device data across 59 devices (17 GB of DerivedData
for comparison) and six runtimes totalling about 40 GB: one classic disk image
(7.3 GB, `/Library/Developer/CoreSimulator/Images`) and five "Patchable Cryptex"
images (3.8–8.5 GB each, `/System/Library/AssetsV2`, managed by MobileAsset and
counted as System Data).

These are not file-level caches. CoreSimulator owns their records, and removing
them correctly means asking Apple's `simctl` to do it. The `developer_caches`
purge profile therefore lists `xcrun simctl delete` as an unsupported external
operation and never touches `CoreSimulator/Devices`.

## Slices and dependencies

| Slice | Operations | Status |
| --- | --- | --- |
| 1a | Erase devices; delete devices (including devices `simctl` marks unavailable), always by explicit UDID | This contract |
| 1b | Delete runtime images | **Blocked** on open decisions 4–5; must not be implemented with 1a |
| Later | Package-manager cleanups (`brew cleanup`, `npm cache clean`, `pnpm store prune`, `yarn cache clean`, `pip cache purge`) | Separate contract; their caches already have recoverable Trash rules |

Never in scope: `delete unavailable`, `delete all`, `erase all`, `runtime delete
all`, `--notUsedSinceDays`, `--unusable`, `--outdated`, device names or the
`booted` alias as targets; simulator app containers, logs, Xcode Archives,
DerivedData (a purge rule already), DeviceSupport, documentation caches,
toolchains; Windows; privilege escalation or the privileged helper. Nothing in
these slices runs as root.

`delete unavailable` is excluded because `simctl` resolves "unavailable" when it
runs, so a device that became unavailable after the preview would be deleted
without ever being previewed or approved. Unavailable devices are deleted by
their previewed UDID instead.

## Effect class and governance

These operations are **permanent**: nothing moves to Trash and nothing can be
restored by the app. They form a new, separately owned effect class,
`permanent_tool_operation_v1`, distinct from `revalidated_trash_v1`:

- it is never a Trash fallback, never a Trash-failure path, and never offered
  inside Trash review;
- hosts must present it in a separate, strong confirmation that lists every
  target by name, runtime, size and what is lost, with nothing pre-selected
  (approved by the maintainer for this product);
- its argument table is fixed in this document, so it is not an "arbitrary
  command" in the sense of `AGENTS.md`.

Dependent document updates landed with the slice 1a implementation:
`AGENTS.md` (Trash is no longer the only executable effect class; the
permanent-deletion non-goal gains this explicit, separately confirmed
exception), `docs/EXECUTION.md` and `docs/ARCHITECTURE.md` (effect classes),
`ROADMAP.md`/`docs/IMPLEMENTATION.md` (T10 status) and `docs/COMPETITIVE.md`
(ledger row). The maintainer approved the `AGENTS.md` amendment explicitly
(decision 1 below).

Callers: the CLI, and a bindings host that is not sandboxed (the Developer ID
application). A sandboxed host receives `capability_unavailable` with a reason.

## Supported environment

Measured: macOS 27.0 with Xcode 27.0 (`simctl` with the `runtime` verbs). The
`runtime` verbs need Xcode 15 or later. Supported range for acceptance: macOS 26
and later, Xcode 26 and later. Other versions return `unsupported_tool_version`
until fixtures and native evidence for them exist; JSON fixtures for each
supported Xcode major are a prerequisite for claiming that version.

## Process boundary and threat model

Process launch is new to the core and stays in `sayaka-platform-macos`.
`sayaka-engine` stays unsafe-free and only receives parsed, validated records.

Trust model: consistent with `docs/ARCHITECTURE.md`, the user and their files
are not adversaries. The selected Xcode bundle can be user-writable, so
`simctl` runs with user-level trust; this slice does not claim protection from
a user who modifies their own Xcode. It does require the tool to be the one
previewed:

- Launch only `/usr/bin/xcrun` (Apple-signed; verify its code signature
  identifier and Apple anchor through the Security framework in the platform
  crate) with argument vectors from the fixed tables below.
- Environment allow-list: exactly `PATH=/usr/bin:/bin`, `HOME` (account home
  from the password database), `LANG=C`, `TMPDIR` set to the user's private
  temporary directory. Every other variable is absent, including
  `DEVELOPER_DIR`, `SDKROOT`, `TOOLCHAINS`, `XCODE_*`, `SIMCTL_*`, `DYLD_*`.
  `xcrun` then resolves the system-selected developer directory
  (`xcode-select`'s link).
- Tool evidence, captured with that same environment at preview and again
  before every execution call: `xcrun --find simctl` result, its real path,
  device/inode, size and modification time. Any difference refuses the call;
  these identify the binary, so a same-path Xcode update is also caught and no
  separate version string is needed.
- Spawn without a shell (`std::process::Command`, no `sh -c`), stdin
  `/dev/null`, stdout/stderr pipes, in its own process group so the whole group
  can be terminated. Other host descriptors must be close-on-exec (true for all
  descriptors opened through Rust's standard library, including the journal
  lock); hosts must not pass inheritable descriptors. The `xcrun` signature is
  re-checked before every launch. Leader exit is detected without reaping, so
  the group id cannot be reused before the remaining group is terminated.
- Output caps are enforced while reading: 8 MiB stdout, 64 KiB stderr. On cap
  exceedance or timeout the process group is terminated. (Measured sizes on the
  59-device host: `list devices -j` 33 KB, `runtime list -j` 6.5 KB.)
- Timeouts: 30 s for list and dry-run calls, 10 min per execution call.
- If the host process is interrupted or exits during an execution call, the
  process group is terminated where possible; CoreSimulatorService may still
  complete the operation, so the outcome is `unknown` until a later re-list
  reconciles it. `unknown` is never retried without a fresh preview.
- One devtools execution at a time per user, serialized with the existing
  exclusive journal lock; a second request is refused as busy.

Argument safety: `simctl` accepts names and aliases (`booted`, `all`) where a
UDID is expected and documents no end-of-options marker, so validation is the
only defence. Device targets are canonical UUIDs (`8-4-4-4-12` hex,
upper-cased, never starting with `-`) taken from the retained preview; runtime
targets are canonical image UUIDs. Anything else is rejected before launch.

## Fixed argument tables

Read-only (preview and revalidation): `simctl list devices -j`,
`simctl list pairs -j`, `simctl runtime list -j`, `simctl runtime match list -j`.

Slice 1a execution:

| Operation | Vector | Batch |
| --- | --- | --- |
| Erase | `simctl erase <UDID> …` | up to 8 UDIDs per call |
| Delete | `simctl delete <UDID> …` | up to 8 UDIDs per call |

Slice 1b execution (blocked): `simctl runtime delete <image UUID>`, one per call,
preceded by `simctl runtime delete <image UUID> --dry-run`. Whether to pass
`--keep-asset` is open decision 5; without it the MobileAsset is deleted too,
which frees the space and makes recovery a re-download.

## Preview records

JSON is parsed into versioned records. Unknown extra keys are tolerated; a
missing required key, wrong type, non-UTF-8 output or unknown top-level shape
fails the whole preview closed.

Device (`list devices -j`, keyed by `runtimeIdentifier`): required `udid`,
`name`, `state`, `isAvailable`, `dataPath`, `deviceTypeIdentifier`; optional
`dataPathSize`, `logPathSize`, `lastUsedAt`, `availabilityError`. An absent size
is reported as `size_unknown`, never zero; an absent `lastUsedAt` as
`last_used_unknown`. `availabilityError` explains why a device is unavailable.

Runtime image (`runtime list -j`, keyed by image UUID): required `identifier`,
`runtimeIdentifier`, `version`, `build`, `kind`, `path`, `state`, `deletable`;
optional `sizeBytes`, `lastUsedAt`, `mountPath`, `signatureState`.

Joins: devices reference runtimes by `runtimeIdentifier`, and several images can
share one `runtimeIdentifier` (different builds). A device is affected by an
image delete only when no other usable image serves its `runtimeIdentifier`.
Pairs (`list pairs -j`) link a watch device and a phone device.

The preview reports, without effects, per operation kind: candidates with sizes
labelled **estimated** (CoreSimulator sizes cover the data directory only and can
include clone-shared blocks; freed space is not guaranteed), pair membership,
affected devices for runtime deletes (1b), refusals with reason codes,
`execution_eligible` per candidate, the tool evidence, a plan digest and the
approval token. Nothing is pre-selected.

## Refusals

Whole request:

- `developer_activity`: any of this user's processes whose executable is the
  Xcode or Simulator bundle executable (`…/Contents/MacOS/Xcode`,
  `…/Contents/MacOS/Simulator`, wherever the app bundle lives or however it is
  named), or is named `xcodebuild`, `xctest` or `simctl` (an `xcrun` call
  always runs `simctl` as its child). Executable paths are used rather than
  bundle identifiers because they are available from the process table
  without reading each bundle. Processes whose path cannot be read (other
  users' or protected processes) are skipped; they cannot be this user's
  Xcode or simulators. Command-line test runs are detected through
  `xcodebuild`/`xctest`, not only GUI apps. Sayaka's own `xcrun`/`simctl`
  children (identified by their process group) are excluded. If the process
  table cannot be read, the request fails closed.
- `tool_changed`, `tool_unavailable`, `unsupported_tool_version`.
- `busy` (another devtools execution), `expired` (preview older than 120 s on
  the monotonic clock, matching picked-file sessions), `invalid_request`
  (duplicate, unknown or non-previewed identities; more than 32 devices).

Per candidate:

- device `state` is not exactly `Shutdown` (`Booted`, `Booting`,
  `Shutting Down`, `Creating`, `Unknown` and future states are all refused);
- device is a member of a pair, unless the request is a **delete** containing
  every member of that pair; the confirmation then lists the pair as one entry
  with both devices and their (possibly different) runtimes. Paired devices are
  never offered for erase;
- device is unavailable (`isAvailable` false) and the operation is erase:
  unavailable devices are offered for delete only;
- device name matches Xcode's parallel-testing clones (`Clone N of …`); clones
  are transient and owned by test runs;
- (1b) image not `deletable`; `kind` not in the allow-list (`Disk Image`,
  `Patchable Cryptex Disk Image`); `state` not ready; the image's build equals
  `chosenRuntimeBuild` or `defaultBuild` for any SDK in `runtime match list -j`
  (fails closed if that output cannot be parsed); any affected device not
  `Shutdown`.

## Approval

One operation kind per session (erase, delete, or 1b runtime delete); a request
cannot mix kinds. Approval mirrors the purge binding: `preview_handle`,
`plan_digest`, `1..32` unique item references from that preview, `approval == 1`,
and an exact token whose phrase names the kind and count — `erase N simulators`,
`delete N simulators`, `delete N runtimes` — where `N == item_count`. Tokens are
bound to the sealed preview through the handle and digest, so another preview's
token is not interchangeable. The CLI requires the same typed phrase. There is
no approval boolean without the token, and no imported JSON approval.

## Execution and outcomes

1. Write a durable journal intent (kind, identities, tool evidence, plan
   digest) under the exclusive journal lock. If it cannot be written, nothing
   runs.
2. Before each call (each batch of up to 8), re-run the refusal checks and the
   read-only lists: same `udid`, `name`, `runtimeIdentifier`, `dataPath`,
   `isAvailable`, state `Shutdown`, same pair membership, same tool evidence. A mismatch refuses
   that batch; earlier completed batches are not undone. The window between this
   check and the call is per batch and is part of the disclosed race.
3. Run the vector; record exit status and capped stderr. A batch exit status does
   not map to individual identities.
4. Post-check by re-listing, per identity:
   - delete: identity absent → `succeeded`; present → `failed` if the exit status
     was non-zero, otherwise `unknown`;
   - erase: exit status 0 **and** device present and `Shutdown` with a changed
     data-directory observation (data size or modification time) → `succeeded`;
     exit 0 without an observable change → `unknown` (expected for a device that
     was already empty; hosts explain this rather than reporting a failure);
     non-zero exit → `failed`;
   - timeout, interruption, cap exceedance, or any other tool or I/O error
     during the call → `unknown`.
5. Write the journal outcome. Outcomes: `succeeded`, `refused`, `failed`,
   `unknown`. `unknown` is reconciled by a later re-list, never by retry.

Pair members are always placed in the same batch. Host cancellation skips
batches that have not started; it never interrupts a running call. After an
indeterminate call or a failed post-check, later batches are skipped
(`stopped_after_ambiguous_outcome`). Journal items record the device's data
directory as the path (identity is the UDID in `tool_operation`); a refused
batch is recorded as `skipped` with its reason.

Error codes surfaced to hosts: `capability_unavailable`, `tool_unavailable`,
`unsupported_tool_version`, `tool_changed`, `developer_activity`, `busy`,
`expired`, `invalid_request`, `parse_failed`, `output_cap_exceeded`, `timeout`,
`journal_unavailable`. Journal records are schema-versioned; an unknown schema
version is read-only evidence, never resumed.

Residual risk, disclosed: between revalidation and the call, another process
(Xcode, a test run, CI) can boot a device or start using a runtime. `simctl`
may then fail, or for runtime deletes shut the device down (documented by
`simctl runtime delete` for disk images). This is never described as race-free.

## Resource targets

Measured before acceptance on a fixture host with at least 50 devices and 4
runtimes, then fixed in the implementation record: preview latency (all four
lists), peak resident memory of parsing, and execution latency per batch.
Parsing caps: 8 MiB per list output, 512 devices, 64 runtime images.

## Tests and evidence

- Unit (engine): recorded JSON fixtures per supported Xcode major (anonymised:
  UDIDs and names replaced), covering optional-field absence, unknown extra keys,
  shape drift, multi-image `runtimeIdentifier`, pairs, clones, all device
  states, refusal codes, token/digest mismatch, limits and expiry.
- Fault injection (platform, injected tool runner): timeout, non-zero exit,
  oversized stdout/stderr, malformed JSON, tool evidence change between preview
  and call, journal-write failure, interruption during a call, partial batch
  where only some identities disappear, post-check list failure.
- Real platform (opt-in only, never on existing devices): create throwaway
  devices named `sayaka-test-<random>` with `simctl create`, erase and delete them
  through the session, and delete any leftover `sayaka-test-*` devices in
  teardown, including after failures. Journal state lives under an owned
  temporary prefix that teardown removes. Runtime deletion (1b) is exercised only
  against an explicitly provided disposable runtime; the default suite never
  deletes a runtime.
- No test may target devices or runtimes it did not create.

## Mole capability impact

Narrows the pinned Mole developer-cleanup gap recorded in
`docs/COMPETITIVE.md` (the unsupported `xcrun simctl delete` operation) for
simulator devices; runtime deletion stays a gap until 1b. It does not claim
parity or a throughput result. Size/runtime budget: no new crate dependency.
Process launch uses the standard library; verifying `/usr/bin/xcrun`'s code
signature adds a link to the system Security framework (at the time of writing
the platform crate links CoreFoundation, Foundation and IOKit; re-check at
implementation), with no bundled code. The new link receives the same native
audit as the existing ones.

## Decisions

Approved by the maintainer (2026-10-06):

1. The new effect class `permanent_tool_operation_v1`, and the `AGENTS.md`
   amendment it requires, landing with the implementation.
2. Erase is offered in 1a (available, unpaired devices only).
3. The runtime default rule in **Refusals** (chosen **or** default build for any
   SDK) is the rule; it is defined there only.

Open, blocking 1b only:

4. Measure whether `simctl runtime delete` needs administrator rights for
   each kind. Observed so far: `--dry-run` succeeds unprivileged
   ("Would delete …"), which does not prove the real deletion does. If a kind
   needs administrator rights, it moves to the privileged-helper contract.
5. For MobileAsset-managed cryptex images, confirm `simctl` is the supported
   removal path, decide `--keep-asset`, and verify that the reported
   `sizeBytes` matches the space actually freed.
