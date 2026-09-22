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

| Task | Class | Status |
| --- | --- | --- |
| system_maintenance | D (DNS flush) | gap (privilege design pending); diagnostic `mdutil -s` part: partial (read-only CLI slice, real-host observation recorded 2026-09-22) |
| cache_refresh | B | gap (mechanism contract pending) |
| saved_state_cleanup | B | read-only preview implemented + real-host staged ([SAVED_STATE_CLEANUP.md](SAVED_STATE_CLEANUP.md)); execution slice and its native evidence pending |
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

## Non-goals

No "free RAM"/purge-style memory claims, no health score, no daemon or
scheduled maintenance, no automatic optimization, no arbitrary shell runner,
no default privilege helper, no change to system authentication defaults.
