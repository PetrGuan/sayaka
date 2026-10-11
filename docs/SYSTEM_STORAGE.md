# System storage: ordinary-user observation and installer review

Status: proposed contract, not implemented. Scope choices D1–D6 were confirmed
by the owner on 2026-10-11. A reviewed contract PR still requires owner approval
before implementation. This document is self-contained; issue numbers identify
work slices, not additional authority.

## Product decisions and evidence

| Resource | v1 decision |
| --- | --- |
| Time Machine local snapshots | Read-only count and dates; no deletion or thinning. |
| Time Machine configuration/activity | Read-only status; no backup-tree traversal. |
| Reclaimable space | Show an OS capacity estimate separately from cleanup totals. |
| Device firmware cache | Read-only in v1: the evidence gate below is not met. |
| Downloaded macOS installers | Discover exact bundles; explicitly open existing bundle-only uninstall review. Same-major installers remain reviewable with a reuse warning. |
| Other deep-system storage | Unsupported, with visible reasons; no helper effects. |

System Storage belongs in the App's Space panel (D4). Snapshot deletion and
privileged cache operations require separate issues and resource contracts (D6).
The helper's existing handshake-only protocol and empty effect allowlist do not
change. Never register, launch or connect to the helper for this feature or its
validation. The existing Finder administrator delegation for uninstall remains
available; this is not a new helper privilege.

Evidence checked 2026-10-11:

- [Apple: local snapshots](https://support.apple.com/en-us/102154) explains that
  macOS removes snapshots as they age or space is needed. The App links this
  explanation and Time Machine settings; it does not implement deletion.
- [Apple: bootable installers](https://support.apple.com/en-us/101578) identifies
  installer apps in Applications and their reuse to install macOS. Removal is
  a user choice, not proof that an installer is obsolete.
- Apple's public Foundation properties
  [important-usage capacity](https://developer.apple.com/documentation/foundation/urlresourcevalues/volumeavailablecapacityforimportantusage)
  and [available capacity](https://developer.apple.com/documentation/foundation/urlresourcevalues/volumeavailablecapacity)
  supply the two measurements. Their difference is our estimate, not an Apple
  API reporting exact snapshot bytes or guaranteed recoverable bytes.
- The installed `tmutil(8)` manual/help and ordinary-user command observations
  establish the fixed read-only verbs below. Their text is not a stable public
  serialization format; unfamiliar output must remain unknown.
- No Apple-authored source located in this research establishes both the three
  historical iTunes firmware cache paths and safe on-demand reconstruction of
  their entire contents. Apple-hosted community posts and third-party cleanup
  rules do not satisfy this gate. This is an evidence gap, not a claim that no
  such documentation exists.

## A. Read-only overview boundary

All native commands and capacity reads live in `sayaka-platform-macos`; engine
code remains unsafe-free. The proposed process-launch exception is only this
closed enum, in addition to existing approved developer-tool commands:

| Enum case | Executable | Exact arguments |
| --- | --- | --- |
| LocalSnapshots | `/usr/bin/tmutil` | `listlocalsnapshots`, `/` |
| BackupStatus | `/usr/bin/tmutil` | `status` |
| Destinations | `/usr/bin/tmutil` | `destinationinfo` |

No shell, PATH lookup, caller arguments, alternate executable, volume selector,
`diskutil`, `latestbackup`, deletion/thinning, backup initiation or configuration
change. Validate the protected Apple executable using the platform's existing
system-tool trust discipline. Clear the environment; supply only `LANG=C` and
`LC_ALL=C`, null stdin, and bounded pipes. Each command has a 5-second deadline,
256 KiB stdout and 16 KiB stderr limits. Reuse bounded process-group teardown and
reaping; timeout/cap/read/spawn/nonzero-exit errors invalidate that command's
value. Never retry automatically. Diagnostics expose bounded reason codes, not
raw destination names, network URLs or command output.

One overview collection at a time, no polling loop. Allow manual refresh; close
cancels pending work and suppresses late publication. Give the collection a
20-second observation deadline, including the three sequential commands and
capacity read. Native filesystem/Foundation calls are not forcibly interruptible:
run them off the main thread with one bounded worker, report timeout to the
caller and discard late results; do not spawn more workers while one remains
outstanding. A deadline is not a promise the underlying OS call has stopped.

### Parsing and completeness

UTF-8 only; at most 4,096 lines, 4,096 bytes per line, 1,024 snapshot entries,
32 destination records, and 128 issue summaries (additional issues have a
truncation count). Reject duplicate/conflicting scalar keys and overflow. An
unrecognized nonblank line always produces an issue. No text is executed.

- Snapshots: require the exact header `Snapshots for disk /:`. Admit only exact
  `com.apple.TimeMachine.YYYY-MM-DD-HHMMSS.local` names with valid calendar/time
  components, no suffix or prefix additions. Keep the original local date/time
  label; do not invent a timezone/UTC instant. Deduplicate with an issue and mark
  incomplete. Header plus no entries is complete zero. Missing header, malformed
  dates, truncated output or other lines make completeness false; retain valid
  entries only as partial evidence, with the authoritative count null. In
  particular `com.apple.os.update-*` is excluded and reported as unrecognized,
  never a cleanup target.
- Status: require `Backup session status:` followed by one complete dictionary
  in the observed OpenStep plist syntax, with exactly one `Running` integer
  equal to 0 or 1. Use a bounded data parser, never a shell/plist evaluation.
  `ClientID` is optional text. Recognized additional status fields may be
  structurally consumed as opaque bounded data; unknown keys produce issues
  without changing an independently valid Running observation. Missing,
  contradictory or malformed Running means unknown, not idle. Overall source
  completeness is false for unknown fields even if Running itself is known.
- Destinations: exact successful output `tmutil: No destinations configured.`
  means configured=false. Otherwise parse complete records separated by the
  observed equals-sign separator, with `Name`, `Kind`, `ID` and optional
  `Mount Point`/`URL` labeled fields. A record needs nonempty name, kind and a
  UUID ID; duplicate fields, unknown fields, mixed no-destination text, missing
  IDs or incomplete records make configured unknown. Names/URLs are discarded
  after parsing; output only configured=true/false/unknown and record count.
  Exact separator spelling and positive fixtures must be recorded from native
  evidence in PR2 before a positive format is accepted; until then it is unknown.
- Last successful backup: null/unknown in v1. Neither accepted status nor
  destination grammar establishes it. Never infer it from snapshot dates,
  current activity, plist file mtime or a successful command exit.

Ordinary-user research on 2026-10-11 observed a successful snapshot header with
no entries, status dictionary `ClientID = "com.apple.backupd"; Running = 0;`,
and the exact no-destinations message above. These are read-only observations,
not executed tests or evidence for configured/active cases.

Each published value carries `source`, `observed_unix_ms`, `complete`, `issues`
and nullable `value`. Timestamp is observation completion, not backup creation;
failed/unavailable observations still have a timestamp and an explicit reason.
Aggregate completeness cannot hide individual failures. Partial lists must be
labeled partial; unknown is never displayed as zero/false. App values older than
60 seconds are visibly stale, remain read-only and are not refreshed implicitly.

### Capacity estimate

Read the two URL resource values together for the fixed startup data-volume URL
`/System/Volumes/Data` (not the current Space scan root). Verify the URL denotes
an available local volume; failure is unknown, with no fallback to another disk.
Use checked nonnegative integers. If either is missing or important-usage is
less than available, return unknown with an inconsistency issue, not a clamped
zero. Otherwise estimate = important-usage minus available. Present the measured
volume and time. It can include snapshots and system-managed purgeable data;
macOS decides what it can reclaim. It is not additive to free space in cleanup
statistics and never enters selected, cleanable or freed byte totals.

### API

Add synchronous bounded `sayaka_system_storage_overview_v1` using the existing
caller-buffer JSON binding convention; callers invoke it on a background worker.
The envelope has schema_version=1, kind=`sayaka.system_storage_overview`,
effects_performed=false and separately sourced observations. It creates no
session, plan, approval, receipt or journal. Buffer sizing/retry must not cause
multiple simultaneous collections; document the exact binding behavior in PR2.
Unsupported platforms return explicit unsupported observations. Update the
header, BINDINGS and the AGENTS process-launch rule only when implementing the
approved three-verb exception.

## B. Firmware: evidence-gated read-only fallback

Only inspect these historical exact leaves beneath the native user's home:

- `Library/iTunes/iPhone Software Updates`
- `Library/iTunes/iPad Software Updates`
- `Library/iTunes/iPod Software Updates`

This v1 does not add executable rules, native allowtable entries, approval or
Trash routes for them. Read-only metadata sizes may be shown in Space; no Home
Caches selection is offered while the evidence gate is unmet. Say “possible
downloaded device firmware” rather than certifying cache ownership from a name.
Do not claim safe deletion or redownloadability without the missing evidence.

Anchor ancestry without following links; respect existing cloud/dataless and
volume boundaries. Inspect only direct regular `.ipsw` children, case-sensitive;
no content reads, recursion, mount crossing or materialization. At most 4,096
entries per leaf and a shared 2-second cooperative metadata budget. Report
logical bytes of observed files, not allocated or reclaimable bytes. Missing
leaf is observed absent; denied/changed/linked/dataless paths and budget overruns
are partial/unknown, not zero. Other contents are excluded with issues.

D2's preferred future shape is the entire exact cache leaf under
`revalidated_cache_trash_v1`, not individual picked-file Trash. Enabling it
requires an amended reviewed, owner-approved contract with Apple evidence for
both location and reconstruction, content/layout admission, and exact updater
ownership. Finder sync, Apple Devices, Configurator and download agents must be
covered. A complete process census and directory activity evidence must refuse
active or unknown writers; a newest-mtime age of at least 24 hours is a necessary
additional check, never proof of inactivity. Long-running Finder alone neither
proves an update nor proves safety. Do not improvise activity detection in an
implementation PR. Configurator Group Containers remain unsupported.

## C. macOS installer discovery and existing uninstall handoff

Enumerate only direct children of `/Applications`. Admit a physical directory
whose case-sensitive name matches `Install macOS *.app` (nonempty middle) and
whose bounded, actually parsed `Contents/Info.plist` has a string
`CFBundleIdentifier` beginning `com.apple.InstallAssistant.` with nonempty suffix.
Both must match. Do not trust a filename, Spotlight record or caller-provided
identifier. No symlink ancestors, content materialization or mount crossing.
These checks classify a candidate; they do not authenticate Apple's signature.
A forged plist is not certified genuine or silently authorized for removal.

Read `CFBundleShortVersionString` as the **installer app version**, not the
installed OS version. Target OS major is unknown unless separately evidenced by
explicit installer OS metadata; do not equate it with app version or infer it
from the marketing filename. PR4 must document any accepted exact metadata key
and fixture; absent that evidence, show unknown and the reuse warning for every
installer. Same known OS major remains Review, never default selected. Explain
that the installer can be retained for reinstalling or making bootable media.

Bound enumeration to 4,096 children, 32 candidates, Info.plist to 1 MiB and total
observation to a 5-second cooperative budget. Bounded size traversal uses existing
no-follow scanner protections, depth 64 and 100,000 entries total, with no content
reads. Report partial size with completeness/issues; do not turn a budget stop
into a complete zero. Retain directory/plist identities and re-observe them at
handoff; changes require rediscovery before opening review.

Add `sayaka_macos_installer_preview_v1`, schema_version=1,
kind=`sayaka.macos_installer_preview`, effects_performed=false, using the same
read-only JSON buffer conventions. Candidate paths, metadata and provenance are
evidence only, never execution capabilities. App handoff selects exactly one
bundle in the existing uninstall window and starts a fresh native preview;
related items stay unselected. Existing typed confirmation, running-process
checks, freshness, ordinary Trash and eligible Finder-admin delegation, journals
and recovery semantics are unchanged. Do not add a new execution API or schema.

Code audit at core b03ba64: `app_uninstall::preview_bundle_uninstall` refuses
`/System`, not all `/Applications` children, and does not blanket-refuse
`com.apple.*` IDs or Apple signatures. `platform-macos::trash` owns ordinary and
admin bundle admission; the existing bundle exceptions cover `com.apple.macl`
and eligible App Store metadata. Restricted flags, unsupported attributes,
unknown processes and unsafe ancestry remain refusals. See
[UNINSTALL_EXECUTION.md](UNINSTALL_EXECUTION.md). No relaxation is proposed;
if a real installer fails these protections, preserve refusal and obtain a new
contract decision before changing admission. A discovery match does not promise
that every installer can be moved.

## Unsupported operations and presentation

Show readable unsupported rows and relevant Apple settings/help links, without
execution controls, for: snapshot deletion/thinning (OS-managed recovery data),
failed backups including `Backups.backupdb/**/*.inProgress` (recovery history;
no traversal), generic `/Library` caches/logs and diagnostic/power/GPU stores
(no exact disposable-resource contract), `/Library/Updates` and
`/macOS Install Data` (Software Update owned), Rosetta/Apple Silicon caches
(OS-managed), and Configurator Group Containers (shared ownership unknown).
Opening settings is navigation only; it never toggles backup/update settings.
If a settings deep link fails, show the manual System Settings navigation route.

## Delivery, review and validation

1. This docs-only contract and cache-catalog cross-reference: independent
   different-model review, then explicit owner approval before implementation.
2. Core overview A, fixed command boundary, capacity API, bindings and parser
   fixtures. Positive configured/active formats need real read-only evidence;
   otherwise remain unknown. No execution on parser guesses.
3. Core firmware B: read-only metadata fallback only, with bounded binding/schema
   documentation. No cache rule activation under this evidence state.
4. Core installer C: discovery, binding and identity-safe handoff evidence.
5. App pin/integration: Space panel, installer review cards, capability catalog
   and EN/zh-Hans/ja copy, unsupported explanations and settings navigation.

Each implementation task has a separate PR and different-model independent
review; resolve findings before merging and fast-forward local main afterwards.
Do not run unit or UI tests, including indirectly. Compile parser/negative
fixture test sources and build the App only. Report builds, manual observations
and unexecuted tests separately. No helper registration/launch or real-content
cleanup as validation. Manual cases include empty/nonempty/OS-update snapshots,
unknown output/permission/timeout, active/unconfigured/configured-idle backups,
capacity failures, firmware link/dataless/partial observations, installer name/ID
mismatch and changed/running bundles. Real installer download and Trash
acceptance belong to an explicitly authorized disposable setup; builds and
synthetic fixture compilation do not establish native acceptance.
