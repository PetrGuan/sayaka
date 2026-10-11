# Bounded system maintenance: operation, threat and recovery contract

Design for issue PetrGuan/SayakaCleaner#30 (T10). This document is the
architect contract that must be confirmed before **any** maintenance effect is
enabled. It implements nothing: no diagnostic or mutation described here is
authorized by merging this document. Each future operation requires its own
reviewed slice in a disposable native environment.

Frozen upstream reference: Mole **V1.53.0** `optimize`, source commit
`1b9023b5f151c2d963bbcb9cb658f4824137b8aa`. The 21-task catalog and its
`unsupported` / `unmeasured_blocked` status are pinned in
[benchmarks/c0-mole-v1.53.0-ledger.json](../benchmarks/c0-mole-v1.53.0-ledger.json);
the mechanisms below were read from the pinned `lib/optimize/catalog.sh` and
`lib/optimize/tasks.sh`. Do not mix development-branch scripts with the release
catalog.

## Design principles

1. **Diagnosis never authorizes change.** High CPU, large caches or a warning
   panel are observations. A change operation is selected explicitly by the
   user from named operations; no diagnostic flow auto-escalates into an
   effect.
2. **Named operations only.** Every operation names the actual OS mechanism,
   tool and evidence. There is no generic "speed up", "free memory" or
   "optimize the system" operation, and no operation is sold by a score.
3. **Official mechanisms with structured parameters.** Operations use
   documented APIs or fixed system tools with fixed argument vectors — never
   an arbitrary shell string, never a user-supplied command, never a
   downloaded helper. Timeout, cancellation and controlled environment are
   part of the mechanism contract.
4. **Ordinary authority first.** Anything achievable with the user's own
   permissions is done without privilege. Privileged operations (Class D
   below) require a separate privilege-design review, an explicit per-run
   confirmation, and are never made default. No setuid helper, no LaunchDaemon,
   no change to system authentication configuration is installed silently.
5. **Journal, preview and equal work.** Effects are previewed per item,
   journaled with intent/outcome like the M3 Trash contract, and reported with
   real granularity. Skipping journal/confirmation to win a speed comparison
   is forbidden by the C0 equal-work rule.
6. **Refusal is not coverage.** An operation that refuses, is unsupported, or
   is skipped (busy/unknown/unnecessary) keeps a stable distinct state. None of
   them count as feature coverage.

## Operation contract template

Every operation slice MUST define, before implementation:

| Field | Content |
| --- | --- |
| Platform / OS bounds | Exact macOS versions and volumes where the mechanism is supported |
| Applicability | Preconditions that make the operation meaningful (and the "unnecessary" state when they are absent) |
| Necessity evidence | What observation justifies running it; absence of evidence yields `unnecessary`, not a run |
| Impact scope | Exact paths/services/settings mutated; what is provably untouched |
| Concurrency | What may not run simultaneously (apps, other operations, system jobs) and how conflicts are detected |
| Permission | Ordinary user vs explicit privileged confirmation; no silent escalation |
| Recovery limits | What can and cannot be undone, with the honest residual cost |
| Result granularity | Per-item outcomes: changed/unchanged/skipped/failed with reasons; never a bare success count |

## Catalog triage (21 pinned tasks)

Proposed effect classes and sequencing. Status today: `disk_verify`,
`login_items_audit` and the `system_maintenance` diagnostic part
(`sayaka diagnose disk` / `login-items` / `spotlight`) have read-only CLI
diagnostic slices; their isolated-host native acceptance is still pending,
the `system_maintenance` DNS flush part stays Class D, and the other 18
tasks remain `gap`.

### Class A — read-only diagnostics (first candidates, no effects)

| Task | Mechanism (pinned) | Notes |
| --- | --- | --- |
| `disk_verify` | `diskutil verifyVolume` | Read-only verification; any repair stays a separately confirmed privileged operation |
| `login_items_audit` | `sfltool dumpbtm` (audit only) | Reports broken entries; removal is a Class B/C effect, not part of the audit |
| `system_maintenance` (diagnostic part only) | `mdutil -s` Spotlight status observation | Observation only; the same Mole task's DNS flush (`dscacheutil` + `mDNSResponder` HUP) is Class D and stays blocked |

### Class B — user-domain reversible file effects (ordinary authority)

`saved_state_cleanup`, `fix_broken_configs`, `quarantine_cleanup`,
`notification_cleanup`, `coreduet_cleanup`, `legacy_overrides_audit`,
`shared_file_list_repair` (repair part), `launch_agents_cleanup` (user
LaunchAgents only), Spotlight orphan-rule removal
(`spotlight_orphan_rules_cleanup`).

These delete or edit files/databases inside the user's Library. Each requires
its own slice with: exact target enumeration, per-item preview and selection,
running/ownership protection where relevant, M3-style journaled effects, and
Trash-not-delete where the object is user-visible. "Old" (30+ days) and
"broken" definitions must be fixed per operation and shown in the preview.

### Class C — persistent preference changes

`prevent_network_dsstore` (`defaults write com.apple.desktopservices
DSDontWriteNetworkStores -bool true`) and the override removals of
`legacy_overrides_audit` (`defaults delete`).

A persistent settings change is a different contract from a file effect: the
preview must show current value, proposed value, persistence and the exact
restore command; the journal records both values. Reverting must restore the
prior value, not blindly delete.

### Class D — privileged global effects (blocked pending privilege design)

`system_maintenance` (DNS flush: `sudo dscacheutil -flushcache`, `sudo
killall -HUP mDNSResponder`), `network_optimization`, `network_stack_optimize`
(`sudo route -n flush`, `sudo arp -a -d`), `disk_permissions_repair` (`sudo
diskutil resetUserPermissions /`), `spotlight_index_optimize` (`sudo mdutil
-E /`), `periodic_maintenance` (`sudo periodic daily weekly monthly`).

These restart system services, flush global network state, or rewrite global
indexes. They are **not implementable** until the privilege design (below) is
reviewed. Each then needs a disposable-host slice: explicit per-run
confirmation, per-effect journal, cancellation/timeout behavior verified
against the real tool, and published irreversibility costs (e.g. Spotlight
rebuild duration, DNS cache cold-start).

### Class E — database mutations with concurrency constraints

`sqlite_vacuum` (VACUUM on Mail/Safari/Messages databases; upstream skips when
the owning app runs) and `launch_services_rebuild` (`lsregister` database
rebuild).

Contracts must define the running-application detection (the T9 running
observation machinery is the intended source), the backup/quarantine of the
pre-operation database where applicable, first-launch side effects (Launch
Services rebuild resets some associations), and per-database outcomes.

## Privilege design boundary

No privileged operation ships before a separate privilege-design review
covering: the exact confirmation UX (per-run, per-operation, never blanket),
how authentication is requested (system prompt only; no stored credentials,
no setuid, no daemon, no modified sudoers), what happens on denial/timeout
(stable `authorization_required` state, not a fallback to weaker execution),
and the audit trail. Denial of privilege is a supported user outcome, not a
failure mode to route around.

## Touch ID / native authentication convenience

User outcome: after an explicit opt-in, a privileged operation that the user
has just confirmed interactively may be re-authenticated with Touch ID instead
of a password. Boundaries: enrollment is user-initiated and revocable; nothing
is written to global authentication configuration silently; no credential is
stored by Sayaka; unsupported hosts report `unsupported` (which is not feature
coverage). Integration surface belongs to T12 (#32); this document only fixes
the boundary.

## Threat model and required evidence

| Threat | Contract answer |
| --- | --- |
| Data loss in user Library | Class B slices use Trash/journal; no permanent-delete fallback; per-item recovery limits published |
| Settings left changed | Class C previews/journals prior and new values; documented exact restore |
| Database corruption/concurrent access | Class E running-app detection plus first-party skip discipline; tested on disposable host, never faked |
| Privilege escalation | Class D blocked until privilege review; system prompt only; denial is stable state |
| Cancellation mid-effect | Real tool timeout/cancellation verified natively; partial states reported, not hidden |
| Benchmark gaming | Equal-work rule: same catalog coverage, journal and confirmations; no skipped safety for speed |

Native evidence rules: effects are verified in a disposable native
environment, never on the developer's real system; failure/busy/unknown/
unsupported/authorization-required states each keep recorded evidence.

## C0 status table

### Mac App Store user-scope operation contracts (#151)

The nine user-scope tasks below have **no App effect implementation**. Their
current `unsupported` availability is published by the versioned, read-only
[maintenance catalog](../crates/engine/assets/maintenance_catalog_v1.json),
which the native App obtains through `sayaka_maintenance_catalog_v1`. A drafted
contract, a CLI diagnostic, an accessible path or a user bookmark does not
make a mutation supported. Any future status change requires an operation
specific preview, owner/concurrency check, per-item approval and journal,
revalidation at the native effect boundary, and disposable-host evidence.

| Task | Proposed operation / exact target class | Threat and admission condition | Recovery boundary |
| --- | --- | --- | --- |
| `cache_refresh` | Refresh Quick Look/icon services; offer only `~/Library/Caches/com.apple.QuickLook.thumbnailcache`, `~/Library/Caches/com.apple.iconservices.store`, and `~/Library/Caches/com.apple.iconservices` for individual Trash selection | Finder and cache services may be writing; broad `~/Library/Caches` deletion is not admitted | Cache regeneration is expected but is not a rollback; Put Back applies only to the exact moved files before Trash is emptied |
| `saved_state_cleanup` | Individually select old `*.savedState` bundles in the user's Saved Application State directory; full contract in [SAVED_STATE_CLEANUP.md](SAVED_STATE_CLEANUP.md) | A running owner or unknown bundle identity blocks; losing window/resume state is a disclosed cost | Put Back before Trash is emptied; subsequent app writes may prevent a faithful restore |
| `fix_broken_configs` | Lint individually attributed third-party preference plists, then offer only confirmed damaged files for Trash | A lint error alone does not establish disposability; active writers and shared/credential preferences block | Put Back the exact plist; settings changed after the move may conflict |
| `sqlite_vacuum` | Integrity-check and VACUUM individually selected Mail, Safari or Messages databases | TCC/sandbox access, live owners, WAL companions and free-space needs are unresolved; refuse all without a consistent backup | Requires a verified same-snapshot backup and owner-specific restore; unavailable today |
| `quarantine_cleanup` | Select download-provenance rows in `QuarantineEventsV2`, without altering file quarantine flags | Gatekeeper history is sensitive metadata; live database and schema ownership are unresolved | Requires a verified database backup and exact restore; unavailable today |
| `shared_file_list_repair` | Inspect selected `.sfl2`/`.sfl3` lists, excluding recent-document lists; Trash only proven damaged files | Lint alone can discard useful Finder/Dock state; active service ownership must be known | Put Back before Trash is emptied; service ordering may still require manual repair |
| `launch_agents_cleanup` | Identify a user LaunchAgent with a truly missing absolute executable, then explicitly disable and Trash its plist | An unmounted volume, path search or running service can make a valid agent appear broken; owner evidence is required | Put Back restores the file while retained in Trash; launchd re-enable is a separate explicit operation |
| `notification_cleanup` | Select old delivered notification records in the Notification Center database | Service-owned and often in a group container; concurrent writes or schema changes can lose notifications | Requires a verified database snapshot and service-aware restore; unavailable today |
| `coreduet_cleanup` | Inspect the Knowledge database with WAL/SHM companions, then offer a named per-database action | Live CoreDuet writes make deleting companions or rewriting the database unsafe | Requires a consistent snapshot and service-aware restore; unavailable today |

All nine report `unsupported` in the Mac App Store catalog. This is an honest
capability status, not a scan result, an empty candidate set or a reason to
request broader access. The catalog includes a per-operation reason and the
proposed operation, threat and recovery text for display. It does not read any
of the paths named above. The three existing read-only CLI diagnostics are
outside these user-scope effect contracts and do not imply App support.

| Task | Class | Status |
| --- | --- | --- |
| system_maintenance | D (DNS flush) | gap (privilege design pending); diagnostic `mdutil -s` part: partial (read-only CLI slice, real-host observation recorded 2026-09-22) |
| cache_refresh | B | gap (mechanism contract pending) |
| saved_state_cleanup | B | contract drafted ([SAVED_STATE_CLEANUP.md](SAVED_STATE_CLEANUP.md)); implementation and native evidence pending |
| fix_broken_configs | B | gap |
| network_optimization | D | gap (privilege design pending) |
| sqlite_vacuum | E | gap |
| launch_services_rebuild | E | gap |
| prevent_network_dsstore | C | gap |
| legacy_overrides_audit | B/C | gap |
| network_stack_optimize | D | gap (privilege design pending) |
| disk_permissions_repair | D | gap (privilege design pending) |
| spotlight_index_optimize | D | gap (privilege design pending) |
| spotlight_orphan_rules_cleanup | B | gap |
| periodic_maintenance | D | gap (privilege design pending) |
| shared_file_list_repair | B | gap |
| disk_verify | A | partial (read-only CLI slice; real-host observation recorded 2026-09-22) |
| login_items_audit | A | partial (read-only CLI slice; real-host observation recorded 2026-09-22) |
| quarantine_cleanup | B | gap |
| launch_agents_cleanup | B | gap |
| notification_cleanup | B | gap |
| coreduet_cleanup | B | gap |

The pinned equivalence rule applies: no optimize comparison claim is valid
without equal catalog task coverage and isolated-host proof.

## Recorded Class A native acceptance (2026-09-22)

The three read-only diagnostics were run against the owner's macOS 27.0
(26A428) arm64 host (debug CLI from `80e4e16be2` + one-line footer fix):
`diagnose disk --volume /` verified the boot volume OK in 7 s with exit 0;
`diagnose login-items` captured 46,488 bytes of `sfltool dumpbtm` output
with declared limits and exit 0; `diagnose spotlight` observed
`indexing: enabled` with the raw `mdutil -s` output retained and exit 0.
All three reports carried `effects_performed: false`; the tools are
read-only by design, so the developer host was sufficient evidence for the
observation paths. Timeout/cancellation paths are covered by the bounded
runner's review and the effect-slice acceptance records; no repair,
removal or privilege path was exercised.

## Read-only diagnostics v1 — issues #152 and #153

**Draft, pending owner approval before implementation.** On 2026-10-11 the owner
selected D1–D5: all observations are read-only; replace the Maintenance window
with Diagnostics; preference changes belong to a future issue; show copyable
Touch ID guidance without executing it; omit Launch Services duplicate detection
in v1. This section supersedes the earlier Touch ID convenience proposal for
these issues. It neither enables helper endpoints nor authorizes maintenance
mutations. Merging a document alone does not implement these capabilities.

Target: ordinary-user Developer ID macOS App and CLI, macOS 14 or later where
sources are available. Unsupported source/OS combinations return unavailable;
no fallback requests elevation. The old Mac App Store catalog is historical,
not a reason to label ordinary-user observations as requiring an administrator.

### Per-operation disposition

| Requested capability | v1 observation and source | Effects excluded |
| --- | --- | --- |
| DNS flush / network optimization | No flush diagnostic or generic optimization claim; network observations below are separate facts | dscacheutil flush, mDNSResponder signals |
| Network stack | Default IPv4/IPv6 route presence; configured resolver addresses; resolution of fixed `www.apple.com` | route/ARP flush, VPN changes, connection repair |
| Disk permissions repair | Boot volume verification plus bounded home owner/mode observations; these are separate diagnoses, not equivalent to permission repair | resetUserPermissions, chmod/chown |
| Spotlight indexing | Per-local-mounted-volume indexing state, not index correctness | enable/disable/rebuild/index erasure |
| Spotlight exclusion rules | Evidence-gated reading of exclusion entries; absent paths explicitly may mean an unmounted volume | rule deletion, rewriting EnabledPreferenceRules |
| periodic maintenance | Tool availability only; absent tool means system tool unavailable, including the observed macOS 27 host | invoking periodic or replacement tasks |
| Launch Services rebuild | Unsupported; duplicate-registration diagnosis deferred by D5 | database rebuild |
| Network .DS_Store preference | Exact current-user value of `com.apple.desktopservices` / `DSDontWriteNetworkStores` | preference writes |
| Legacy overrides | Exact current-user global `NSAppSleepDisabled`, and `com.apple.frameworks.diskimages` keys `skip-verify`, `skip-verify-locked`, `skip-verify-remote` | removing overrides |
| sudo Touch ID | PAM configuration observation plus independent App biometric availability | editing PAM, testing sudo, prompting authentication |

These decisions implement diagnostic coverage only. An observed preference is
not proof its consumer currently honors it, and a successful disk verification
is not evidence about home ownership, permissions or the health of every disk.

### Shared native boundary and closed request table

The engine owns models/parsers; native reads and process launch stay in
`sayaka-platform-macos`. Reuse and extract the existing bounded runner used by
`system_storage`/`tmutil`; do not introduce a second weaker subprocess path.
Migrate CLI diagnostics to this shared boundary while retaining explicit CLI
compatibility adapters. The new App/ABI request contains only one known enum ID.
It cannot supply a path, argv, environment, timeout, URL or shell fragment.

| ID | Fixed source / argument construction | Budget |
| --- | --- | --- |
| `disk` | `/usr/sbin/diskutil verifyVolume /` | 300 s |
| `login_items` | `/usr/bin/sfltool dumpbtm`; audit output only, no broken-entry inference | 10 s |
| `network` | `/sbin/route -n get default`, `/sbin/route -n get -inet6 default`; `/usr/sbin/scutil --dns`; public DNSServiceGetAddrInfo for `www.apple.com` with IPv4 and IPv6 | 5 s per tool, 5 s DNS, 20 s total |
| `home_permissions` | effective user's home from account database, descriptor-relative metadata only | 5 s, 256 direct entries |
| `spotlight` | native mounted-volume inventory, then `/usr/bin/mdutil -s <verified-mount-root>` for each local mount | 5 s per command, 30 s total, 32 volumes |
| `spotlight_exclusions` | source adapter described below | 5 s, 256 entries |
| `network_dsstore`, `legacy_overrides` | CFPreferences reads of only the domains/keys above | 5 s per request |
| `sudo_touch_id` | anchored reads of sudo, sudo_local and optional sudo_local.template in `/private/etc/pam.d` | 5 s total |
| `periodic_availability` | no-follow metadata at `/usr/sbin/periodic` only | 5 s |

The only variable tool argument in this ABI is an internally enumerated absolute
mount root, never text from UI or command output. It must still name the same
local mount when invoked; a changed/unavailable mount produces unknown. Tool
calls verify Apple signing identity for each fixed binary, reset environment
(`LANG=C`, `LC_ALL=C` only), close stdin, use no shell, and bound stdout to 256 KiB
and stderr to 64 KiB. Existing tmutil verbs keep their stricter 5 s / 256 KiB /
16 KiB limits and closed three-verb allowlist. Do not expand simulator effects.

Existing CLI `--volume` compatibility may retain a separately validated absolute
local mount-root selector; reject arbitrary files/subdirectories, option-like
values and non-local mounts. It cannot enter the App ABI. Existing CLI timeout
options may lower or retain their legacy upper bound of 3600 s for explicit disk
verification; they do not change the App's closed budget table. Document CLI
schema/behavior changes rather than silently reinterpreting old JSON consumers.

Cancel/timeout signals are allowed only to the runner's own child process group
for cleanup; never signal existing system services. This qualifies the issue's
"no signals" requirement: it prohibits maintenance signals, not bounded child
cleanup. Retain deadline/output-cap/process-group safeguards from the existing
runner. A blocked native read cannot hold the App main thread or spawn unlimited
replacement workers: one in-flight diagnostics worker, no retry while it remains
outstanding. Discard stale completions by request generation. A UI deadline is
not a claim that the underlying OS operation has stopped.

### Results, privacy and status semantics

`sayaka_diagnostics_run_v1` returns schema 1 with `id`, `status`, typed `facts`,
`source`, `observed_unix_ms`, `complete`, bounded `summary`, stable `reason_codes`,
and `effects_performed: false`. Reject unknown IDs before observation. Follow
the existing ABI allocation/free and error conventions; cap serialized output
at 512 KiB, individual text at 4 KiB and summaries at 8 KiB. Invalid UTF-8,
overflow or unexpected schema must not turn into empty success.

- `ok`: accepted, complete observation with no defined attention fact in this
  diagnostic; never a whole-machine health assessment.
- `attention`: a supported fact the user may want to inspect (for example an
  explicitly disabled index or an enabled legacy override), not an instruction
  to repair. May coexist with `complete: false` and unknown subfacts.
- `unavailable`: known missing tool/source, unsupported capability or access
  denial with an explicit reason. Missing PAM files remain distinct facts.
- `unknown`: ambiguous formats, timeout, cancellation, changed input, nonzero
  command exit without a recognized outcome, truncation or failed observation.

Aggregate precedence is proven attention, then unknown, then unavailable, then
ok; individual subfacts always retain their state. `complete` means every
required observation finished with an accepted format, not that configuration
is correct. Incomplete results cannot be ok. An empty inventory is not complete
unless enumeration itself succeeded. A missing preference key can be a complete
`unset` fact; it must not be converted to false or a claimed system default.

No journal, telemetry, console log or persistent cache of these results. App
shows DNS addresses, paths and login-item details only locally and on deliberate
expansion; redact home prefix/usernames, hostnames, volume labels, addresses and
unapproved raw lines in the default summary. Structured local details preserve
necessary values without remote transmission. The explicit CLI output request
may print those local details; do not additionally log them. Escape control
characters in CLI/UI. Discard raw tool buffers after bounded parsing; never
export raw PAM content or unknown preference strings as a diagnostic summary.

`effects_performed: false` means no maintenance/configuration mutation, helper,
authentication prompt or repair was requested. OS reads may update service
caches/logs. The network card discloses the fixed DNS lookup before the user runs
it; the resolver may send this query over the network. There is no HTTP fetch,
reachability probe to arbitrary hosts, upload or automatic background scan.

### Source and parsing rules

**Network.** Parse only recognized route fields under C locale. A recognized
missing-route response is `absent`; other failures are unknown. Either family
may have a route without the other. Preserve resolver scopes from scutil;
configured resolvers are not proof of the resolver used by the lookup. An empty
address list is not proof DNS is broken. A bounded DNSServiceGetAddrInfo callback
with a valid address establishes resolution only, not internet access. A
negative answer or timeout reports "could not resolve" plus its actual reason,
never infers VPN/router/ISP failure. Dispose the DNSServiceRef on completion or
cancellation; no detached, unbounded getaddrinfo fallback.

**Home.** Open the account home directory without following links, then use
no-follow descriptor-relative metadata for the directory and immediate entries
only. Do not recurse or read file contents. Check home UID against effective
UID; report mode and group/other-write flags as facts. Non-owned direct entries
are review hints, not proof of damage. Symlinks are reported but not followed;
non-directories are skipped. ACLs may change effective access: explicitly state
that this is not a full ACL/effective-permission audit. Identity changes, entry
limits or unreadable metadata mark partial/unknown coverage. Never chown.

**Spotlight status.** Enumerate all mounted volumes without triggering mounts;
retain local volumes only, deduplicate by native identity, and preserve an
unavailable row for a volume that disappears. Parse recognized enabled/disabled
status per mount; unknown headers/diagnostics or nonzero exit cannot become
enabled. Disabled is a factual attention state and may be intentional. Offer
normal System Settings > Spotlight navigation, not a rebuild operation.

**Exclusions.** The issue's `EnabledPreferenceRules` name alone does not prove
that it is the Spotlight privacy exclusion list. On the observed macOS 27 host
that array was empty, while the Data volume's
`.Spotlight-V100/VolumeConfiguration.plist` was unreadable to the ordinary
process; neither observation proves no exclusions. Before admitting a source,
PR 2 must document its exact path, schema, OS bounds and evidence correlating
entries with Spotlight privacy settings on a disposable account or pre-existing
owner-approved configuration. Until then the adapter returns
`unavailable/source_not_verified`, not an empty list, and this acceptance item
remains outstanding. No private API, privilege escalation or guessed plist walk
is authorized to fill the gap. A supported adapter reads only a bounded regular
plist through no-follow descriptors (1 MiB maximum) and accepts only documented
path-entry shapes. Reject relative paths, NULs and unexpected types. Check each
absolute path with bounded no-follow metadata: only ENOENT is "path not present
(may be an unmounted volume)"; EACCES and other failures are unknown. Never use
"orphan", "safe to delete", or infer intent from absence.

**Preferences.** CFPreferences uses current user / any host for the exact domains
and keys, without synchronize/write APIs; inspect managed/forced status where
supported and label it separately. Distinguish explicit Boolean, unset,
unexpected type and unavailable read. Do not coerce strings/numbers to Boolean.
True NSAppSleepDisabled requests disabling App Nap; true skip-verify keys request
skipping the corresponding image verification; explain these as requests, not
proof of active behavior. DSDontWriteNetworkStores describes a request to avoid
Finder .DS_Store writes on network volumes. Effective per-host overrides and
consumer behavior are not certified; present the queried scope.

**PAM.** Read at most 64 KiB per regular file using O_NOFOLLOW. Anchor through
`/private/etc/pam.d` (the system `/etc` alias is resolved by the fixed contract,
not by following arbitrary caller paths); reject unexpected intermediate links,
file replacement during read, non-root ownership or group/other-writable files
as unknown. Never request broader filesystem permission on failure.

Parse UTF-8 lines after stripping comments and whitespace. Recognize the simple
PAM type/control/module/arguments grammar; complex controls, continuations,
unrecognized auth includes or ambiguous constructs make effective status
unknown. Accept the standard direct `auth sufficient pam_tid.so` module (also
exact `/usr/lib/pam/pam_tid.so`) as a configuration fact. Other control flags or
module arguments are reported as observed but do not certify enabled behavior.
Follow only the exact `auth include sudo_local` edge, once, and only if present
in sudo. A pam_tid line in an unreferenced sudo_local is not effective evidence.
Do not traverse additional includes or model arbitrary PAM control flow.

Return separate file states (`readable`, `missing`, `unreadable`, `unsupported`),
include presence, direct/local active-line evidence and `configuration`:
`configured`, `not_configured`, `local_file_missing`, `unknown`. Only a completely
recognized reachable stack permits configured/not_configured. A missing sudo
file is unknown; a missing included sudo_local is local_file_missing, never
"Touch ID disabled". A commented template line is guidance, not active config.
Even configured means a recognized configuration line, not a promise that sudo
will authenticate with Touch ID. Do not invoke sudo to test it.

**Biometrics (App only).** Call a fresh LAContext's
`canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)` and then read
biometryType; never call evaluatePolicy or access enrollment data. Touch ID with
successful policy evaluation is available; biometryNotEnrolled is not_enrolled;
biometryLockout is locked_out; biometryNotAvailable is unavailable; other errors
are unknown. In particular, unavailable/biometryType none cannot reliably prove
physical hardware absence (closed lid/session conditions may affect availability).
Display "Touch ID unavailable" rather than inventing a no-hardware diagnosis.
Keep this separate from PAM configuration, with its own timestamp/source. CLI
and core do not claim App biometric availability. No generic password fallback.

### Touch ID guidance and App presentation

Explain that `/etc/pam.d/sudo_local` is the local configuration included by sudo
and that the observed Apple template comments describe persistence over updates.
Show `/etc/pam.d/sudo_local.template` as the source; do not promise that every
OS/custom configuration uses it. Copyable commands in v1 are inspection only:
`cat /etc/pam.d/sudo`, `cat /etc/pam.d/sudo_local.template`, and
`cat /etc/pam.d/sudo_local`. They are plain text, never executed or passed to
Terminal. Explain that the template's commented pam_tid line is enabled only by
a deliberate user edit in the included local file; supply no blind overwrite,
sed, sudo command, installer or automatic enable/disable sequence. Before any
user-initiated edit, guidance says to retain a working administrator terminal.
Remote/screen-sharing and tmux sessions may not offer Touch ID; no workaround is
installed. These boundaries apply in English, Simplified Chinese and Japanese.

Diagnostics replaces the Maintenance window, with explicit Run per card and no
run-all on launch. Show conclusion, facts, source, observation time, completeness
and stale state; preserve unsupported maintenance items as unsupported. Closing
or starting a newer run cannot publish an older result as fresh. There is no
repair/enable/disable button and no helper registration, connection or password
prompt. `hasRunnableMaintenance` must not become an effect capability merely
because diagnostics exist; add a separate diagnostic capability. #152/#153 copy
becomes "read-only diagnosis / modification unsupported".

Replace the historical catalog platform value with a versioned Developer ID
compatible value in both producer and consumer, update strict validation and
catalog fixtures together, and preserve the status of unrelated effect rows.
Document compatibility with older pinned Apps; do not accept arbitrary platform
strings to make validation pass. Prefer normal System Settings navigation over
undocumented pane URLs; if Spotlight cannot be targeted, open Settings and show
manual navigation instructions.

### PR sequence and evidence

1. This contract PR: independent different-model review, then explicit owner
   approval before any implementation. Scope selection alone is not that approval.
2. Shared fixed-tool boundary, engine/ABI/CLI and compile-only positive/negative
   parser fixtures. Update native-boundary documentation/AGENTS allowlists as part
   of this approved implementation; never silently extend generic command access.
3. App pin, Diagnostics UI, separate LAContext observation, three-language
   guidance, catalog compatibility and capability documentation.

Each implementation PR receives different-model review, fixes and reviewer
verification before merge; fast-forward local main after merge. No unit/UI tests
may be executed in either repository for this task. Builds and test-source
compilation are allowed and reported separately from manual observations.

Fixtures must cover malformed/truncated/nonzero/timed-out input, IPv6-only and
no-route observations, failed DNS, mount changes, home metadata limits, all PAM
missing/commented/reachable/unreachable/complex-stack states, unknown preference
types and unavailable exclusion provenance. Compile only. Manually inspect
ordinary read-only facts on the owner's Mac; do not toggle networking, indexing,
preferences, enrollment or PAM to manufacture acceptance cases. Real variant
acceptance needs a separately authorized disposable environment. No helper or
sudo validation. Missing native cases remain explicitly outstanding, not passed
because a fixture compiled. No claim of complete #152/#153 acceptance until
implemented sources and the required evidence are documented.

References: the installed Apple PAM files/template (observed 2026-10-11),
[Apple LAContext policy availability](https://developer.apple.com/documentation/localauthentication/lacontext/canevaluatepolicy(_:error:)),
[Apple biometric availability error](https://developer.apple.com/documentation/localauthentication/laerror-swift.struct/biometrynotavailable),
and the already implemented [system storage boundary](SYSTEM_STORAGE.md).

## Non-goals

No "free RAM"/purge-style memory claims, no health score, no daemon or
scheduled maintenance, no automatic optimization, no arbitrary shell runner,
no default privilege helper, no change to system authentication defaults.

## Diagnostic implementation compatibility (#152/#153)

The shared CLI replaces the three legacy per-tool JSON envelopes with the
schema-1 diagnostic report (`id`, `status`, `facts`, `complete`, sources and
time). `diagnose disk --volume /` remains accepted; arbitrary volume paths and
caller timeouts are no longer accepted. Spotlight enumerates local mounts.
Consumers of the old `kind`/raw stdout envelopes must migrate explicitly.
Catalog ABI v1 remains unchanged for older Apps; the new v2 catalog reports
schema 2 / `macos_developer_id`. Its unrelated effect rows remain unsupported.
