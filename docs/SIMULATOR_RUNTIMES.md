# Simulator runtime removal — slice 1b contract

Status: contract only, 2026-10-11. No runtime observation, ABI extension or
runtime removal is implemented by this change. The maintainer requested this
contract PR, independent different-model review and merge before implementation.
Merging accepts the policy below; it does not certify native deletion.

This extends [SIMULATOR_CLEANUP.md](SIMULATOR_CLEANUP.md). That document remains
authoritative for device-only slice 1a. For runtime sessions this document
supersedes its blocked slice 1b argument, join, approval and decision text.
The effect remains `permanent_tool_operation_v1`, never a Trash fallback.

## Scope and fixed commands

Only the existing signed `/usr/bin/xcrun` boundary runs tools, with its existing
minimal environment, selected-Xcode evidence, process-group handling and output
caps. Swift never constructs commands. No direct mutation of CoreSimulator
Volumes, Images, AssetsV2 or simulator directories; no helper or elevation.

Read-only vectors for runtime sessions:

- `simctl runtime list -j`
- `simctl runtime match list -j`
- `simctl list devices -j`
- `simctl list pairs -j`
- `simctl list devicetypes -j`
- `--find simctl` (existing tool identity observation)

Execution vectors, using only retained canonical UUIDs:

- `simctl delete <device UDID> …`, at most 8 devices per call, pairs together;
- `simctl runtime delete <image UUID> --dry-run`, one image per call;
- `simctl runtime delete <image UUID>`, one image per call.

Dry-run uses the 30-second read-only timeout; execution uses 10 minutes per call.
All stdout/stderr caps remain 8 MiB/64 KiB. Runtime removal does not pass
`--keep-asset`: its purpose includes removing the associated downloaded asset.
Apple's installed `simctl help runtime` documents `--keep-asset` as keeping that
asset. This is evidence for command semantics, not successful deletion or space
recovery. No aliases (`all`, `booted`, `unavailable`), age selectors, `--outdated`,
`--unusable`, caller argv, shutdown, unpair, or retry commands are added.
`delete unavailable` remains unsupported; explicit observed UDIDs are used.

## Observation and protection

Read the five lists completely within a 160-second overall preview budget;
cancellation stops pending calls. Failure, cap exhaustion or invalid required
shape makes the runtime plan unavailable, never empty. Keep the existing device
schema; optional runtime `lastUsedAt` and `sizeBytes` stay unknown when absent.
Malformed optional values produce an issue and cannot establish a suggestion.
Runtime UUID keys must agree with `identifier`; reject duplicate identities.
Validate required runtime fields described in SIMULATOR_CLEANUP, known platform
and numeric version, `state == Ready`, and the exact supported kinds `Disk Image`
and `Patchable Cryptex Disk Image`. Unknown kinds/platforms/states are visible
but ineligible, not silently skipped. Bound all strings and lists; limits are
64 images, 512 devices, 512 pairs, 512 device types and 128 SDK matches, with
8 MiB per command and a 1 MiB serialized host report. Limit exhaustion refuses
the plan; never publish a truncated executable dependency list.

Protect a runtime if its build equals either `chosenRuntimeBuild` or
`defaultBuild` for its platform in `runtime match list -j`. Both are needed:
selected and default builds can differ even at the same SDK major.minor.
A missing/invalid mapping for an installed platform refuses that platform's
runtime removal. No SDK-version fallback weakens this rule. Read-only mapping
platforms are normalized explicitly: iphoneos/iOS, watchos/watchOS,
appletvos/tvOS and xros/visionOS. Unknown mapping platforms fail closed.

Also refuse nondeletable images, non-Ready images, and runtime deletion while
any dependent device is not exactly Shutdown. Preserve the existing global
Xcode/Simulator/xcodebuild/xctest/simctl activity refusal and tool identity checks;
unknown activity is not permission. The system-selected developer directory is
used, never silently changed or replaced with a discovered Xcode installation.

Join devices by exact `runtimeIdentifier`. In this first implementation, multiple
images sharing that identifier are **observation only** (`ambiguous_runtime_images`).
Do not guess which build a device uses or delete its data while another image
may serve it. A later relaxation requires an explicit contract change.

A runtime's complete dependent-device list must be retained. Compare each device
name with the exact name for its `deviceTypeIdentifier` from the device-type
list. Custom names, missing/ambiguous type names, testing clones, multiple pairs,
or a paired partner outside the runtime's dependency set refuse runtime removal.
Do not expand a selection to a different runtime to resolve a pair. These
conservative refusals preserve potentially unique work and are shown by name.
They do not change slice 1a's separately approved explicit device operations.

## Suggestions, sizes and UI

A suggestion is advisory and includes `evidence` and `rebuildability_note`:
Xcode can download a runtime again, but apps/data in its devices cannot be
restored by Sayaka. Suggest only eligible runtimes with no custom/unknown-name
dependents when a newer usable runtime of the same platform exists, or a valid
last-use timestamp is at least 90 days old. Compare parsed numeric version
components, never strings; future, absent or invalid dates cannot prove age.
Unknown last use does not prevent the independently evidenced older-version
suggestion. Never infer never-used from an absent timestamp.

Developer review shows a runtime section above devices: platform/version/build,
estimated size or Size unknown, last use or Last use unknown, dependent count,
and expandable device names with Custom badges and protection explanations.
Nothing is preselected. Select suggested selects eligible suggestions only;
Select Unavailable retains its device-only behavior. Protected rows are disabled.
Runtime plans and device-only plans are separate operation modes, never mixed.

Use existing One Button components and short English/Chinese/Japanese copy.
Never include runtimes or simulators in Clean cards, cleanup totals or the main
Clean number. Deduplicate dependent UDIDs in the displayed estimate; label
“estimated size of runtimes and simulators”, preserve unknown-size counts and
never claim reclaimed/free space. APFS sharing and tool estimates prevent such
a claim. Execution remains Direct-edition-only behind cleanup access.

## Sealed plan and confirmation

A runtime preview seals image UUID, runtime identifier, version, build, kind,
path, state and deletability; the complete dependency set and each device's
existing slice 1a identity/pair facts; relevant device-type names and SDK mapping;
tool evidence; refusal/suggestion evidence; sizes and observation timestamps.
Use monotonic expiry of 120 seconds from completion. Selection creates a sealed
plan of 1..32 runtimes and at most 32 dependent devices total, bounded rather
than silently split into approvals. Device-only item references cannot be used.

Add a distinct runtime operation and versioned binding/report representation;
retain device-only ABI semantics. The implementation PR must specify numeric
operation values and exact request/response schema, and update BINDINGS.md and
the C header together. Imported JSON never confers approval. Bind the handle,
plan digest and exact selection to a typed phrase `delete N runtimes and M
simulators`, with N and M derived from the sealed plan. The existing boolean
approval alone is insufficient. Changing selection invalidates confirmation.

The separate permanent-action sheet lists every image and dependent device by
name (including pairs), runtime and size/unknown. It says: “This can't be undone.
Apps and data inside these simulators are deleted. Xcode can download the runtime
again.” No Trash wording and no preselected rows. Cancellation before execution
has no effects; licensing cannot be bypassed by a runtime operation value.

## Execution, journal and partial outcomes

Use the existing per-user exclusive operation lock. Before any device deletion,
re-read all lists and tool/activity evidence, check expiry, exact sealed identity
and dependency equality, protections, kind evidence gate below, and successful
dry-run for every selected runtime. Dry-run output is diagnostic only and never
selects targets. Any added/missing/changed dependent, mapping or relevant type
name refuses the plan; nothing silently joins an approved selection.

Write and durably publish the complete intent before effects. Extend the journal
with a new version that distinguishes device and runtime items, typed image
identity and dependencies; preserve old schema 6 device history. Never represent
an image UUID as a device or fabricate a filesystem target to satisfy the old
schema. Unknown future schemas remain read-only and cannot resume operations.

For each runtime in deterministic UUID order:

1. Revalidate its surviving dependencies and all protections before each device
   batch. Only devices already confirmed absent by this plan may be absent from
   the original dependency set. Delete dependents first using existing explicit
   UDID deletion and per-device post-checks, with pairs in the same batch.
2. If any device is refused, skipped, failed or unknown, do not delete the runtime.
   Stop the remaining plan after any failure or ambiguity. Earlier deletions are
   irreversible; record them individually and make no rollback claim.
3. Immediately before deleting the runtime, re-list all evidence. Its dependencies
   must be absent, no new devices may reference it, image identity and protections
   must still match, and a fresh dry-run must succeed. Publish durable started
   state, then invoke the single UUID runtime delete.
4. Re-list runtime images and devices. Report runtime success only after a normal
   tool return and a complete post-check proving that UUID absent and no device
   still references its runtimeIdentifier. A nonzero return with absence can be
   recorded as observed removal with command diagnostics; never claim untouched.
   A nonzero exit with unchanged image is failed; exit zero with image still
   present, changed identity or new dependent is unknown. Timeout, interruption,
   output cap, failed post-check or ambiguous mutation is unknown, regardless of
   a later partial observation. Stop later effects and preserve evidence.

No auto-retry, rollback, runtime reinstall, or automatic orphan deletion after
execution. New dependent devices discovered after deletion are reported as an
unknown consistency outcome, not deleted. Cancellation skips unstarted effects;
a running call completes under its existing deadline. Journal failure before a
started record prevents that call; failure after a call makes durable outcome
uncertain and stops subsequent effects. Crash recovery is read-only reconciliation.
Each runtime/device reports removed/refused/skipped/failed/unknown with a reason.

A device boot or new device can race the final check; simctl may shut down devices
when removing an image. No orphan-free or race-free guarantee is made. The
successful acceptance case requires no remaining dependents; races remain
explicit unknown outcomes. Journal placement must exclude every affected device
and log directory as in slice 1a, and runtime-managed paths (including resolved
aliases); ambiguous/unverifiable placement refuses before effects.

## Native evidence gates and delivery

The policy decisions formerly numbered 4–5 are resolved as follows:

- Only ordinary-user simctl deletion is allowed. A permission failure remains a
  failure, never an elevation request or helper fallback.
- Omit `--keep-asset` using documented simctl semantics. Sizes remain estimated;
  matching an actual free-space delta is not a safety criterion or a promise.
- Before production execution is enabled for each kind/tool-version combination,
  record an ordinary-user round trip using an explicitly disposable runtime and
  owned devices, including associated asset behavior, no remaining dependents,
  journal/history and negative protection cases. Unverified combinations are
  observable but execution-ineligible with `native_evidence_missing`.
- A narrowly scoped manual development acceptance entry may exercise only the
  explicitly supplied disposable image UUID and owned device UUIDs to establish
  that evidence. It bypasses only the evidence gate, no identity/activity/SDK,
  approval, licensing or journal protections; it is absent from release hosts.
  This is not blanket permission to delete existing runtimes or user devices.

2026-10-11 read-only observation on Xcode 27: two Patchable Cryptex runtimes were
Ready and deletable, but protected as selected SDK builds; last-use fields were
absent. SDK match data had differing chosen/default builds. The system-selected
CommandLineTools directory could not resolve simctl; explicitly setting Xcode for
that one diagnostic process allowed observation, without changing system settings.
No deletion, permission success, runtime reinstall or reclaimed space was verified.
Apple's local `simctl help runtime` documents UUID removal, dry-run and keep-asset.
This contract does not claim native evidence for older versions or Disk Image.

Delivery order: core parser/policy/session/journal/bindings PR, then App pin/UI/
history PR. Each gets independent different-model review and fixes verified
before merge. Run builds and compile test sources only; do not execute unit/UI
tests, including injected-host suites. Add compile-only fixtures for malformed
JSON, optional values, build matching, multi-image joins, custom names/pairs,
new dependents, changed tools, cancellation, partial device failure, runtime
unknown and journal failures. Report builds, manual observations and unexecuted
tests separately. Native acceptance uses one real App instance and explicitly
disposable targets; the feature issue stays open when required evidence is absent.
