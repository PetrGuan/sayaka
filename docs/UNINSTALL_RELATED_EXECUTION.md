<!-- SPDX-License-Identifier: MPL-2.0 -->

# Uninstall related data: proposed execution contract

Status: **owner approved 2026-10-11; core implementation is acceptance-gated**.
The engine/platform coordinator and CLI preview/selection are implemented.
`NATIVE_ACCEPTANCE_RECORDED` remains false: every related row reports
`native_acceptance_pending`, and approval refuses before creating journals or
moving a bundle. Only a reviewed change attaching the owner-native evidence may
open this gate. Existing bundle-only execution is unchanged. Bindings and App
integration are subsequent slices; no native acceptance is claimed.

Read with [UNINSTALL_EXECUTION.md](UNINSTALL_EXECUTION.md),
[PURGE_EXECUTION.md](PURGE_EXECUTION.md), [EXECUTION.md](EXECUTION.md) and
[SAVED_STATE_CLEANUP.md](SAVED_STATE_CLEANUP.md). Existing bundle-only uninstall,
read-only related preview v1 and other Trash contracts retain their semantics.

## Owner-approved decisions

| Decision | Proposed resolution |
| --- | --- |
| Default selection | Only eligible caches, logs and saved state are on by default. HTTP storage and WebKit are off: they can include login sessions and persistent website data. All other rules are off. Sensitive-app classification overrides every default to off. |
| Containers | Include the exact per-app container in the proposed rule set, off by default, with a strong all-app-data warning; admission still needs evidence and native acceptance below. No Group Containers. |
| Confirmation | One confirmation binds the bundle and the exact selected related subset. Bundle moves first; related data is never an independent retry after bundle failure. |
| Apple and security apps | Refuse all `com.apple.*`, `group.*`, official-uninstaller and listed endpoint-security identities for related execution. No Xcode exception. Bundle-only eligibility is unchanged. |
| CLI | Implement the same session in the CLI as a fixture acceptance surface, with explicit item IDs and terminal-only typed approval; no automatic selection or `--yes`. |
| Attribution limit | Exact namespace convention plus complete bounded observations is the accepted evidence level, not proof of exclusive ownership. Rules lacking reviewed exact-path evidence stay read-only. Unknown/shared evidence refuses execution. |
| Process census | Complete enumeration of processes owned by the effective UID, plus the exact bundle-ID running-app query. Root/other-user writers remain outside this guarantee; current-user observation must be proven feasible under ordinary authority before enablement. |
| Approval lifetime | Preview expires after 120 seconds. Valid acceptance starts one nonrenewable 120-second execution deadline, including Finder's password prompt. Expiry never reverses the bundle move. |

The HTTP/WebKit defaults deliberately narrow the initial research suggestion.
The attribution limit needs an explicit owner decision: ordinary macOS apps can
write outside their own namespace, and no public inventory proves that every
unregistered app or unrelated writer has been found. If that residual risk is
unacceptable, this contract must remain read-only rather than claim certainty.

## Objects, rules and evidence

Let `H` be the effective account's native home returned by `getpwuid_r`, never
an environment variable or caller-provided Library root. Let `B` be the exact
`CFBundleIdentifier` from the selected bundle's retained, revalidated regular
`Contents/Info.plist`. Reuse `valid_bundle_id_component_path()` unchanged:
ASCII alphanumeric, hyphen and underscore within nonempty dot-separated
components; no separators, traversal, NUL, case folding or Unicode
normalization. A filesystem spelling alias is not an exact rule match.

Paths below are relative to `H/Library`. Each HTTP row is a separate candidate.
Proposed IDs are `org.apple.library.<key>.bundle_id_convention.v1`, with
`http_storages` and `http_storages_cookies` distinct. These are new executable
rule definitions scoped to the new contract, not an eligibility upgrade to
read-only v1 rows that happen to have the same rule ID.

| Key / exact path | Type | Role, consequence and what it is not | Default | Evidence / limits |
| --- | --- | --- | --- | --- |
| `caches`: `Caches/B` | directory | Rebuildable cache: next launch may redownload or rebuild. Not a promise that arbitrary contents are dispensable. | on | [Library guide][library] documents the bundle-ID convention. |
| `logs`: `Logs/B` | directory | Diagnostic history: old logs will not regenerate; support investigations may lose evidence. Not user documents or proof of reclaimable cache. | on | [Library guide][library] documents Logs, not exclusive ownership of this exact leaf; exact-leaf evidence gate applies. |
| `saved_state`: `Saved Application State/B.savedState` | directory | Window/resume state: restored windows and possibly unsaved resume context can be lost. Not a documents backup. | on | Existing [saved-state contract](SAVED_STATE_CLEANUP.md) documents the naming convention and its limits; native rule acceptance remains required. |
| `http_storages`: `HTTPStorages/B` | directory | HTTP state, potentially cookies and authentication state: may sign the user out. Not all rebuildable cache. | off | [Cookie API][cookies] documents persistence/sharing, not this exact disk path; exact-leaf evidence gate applies. |
| `http_storages_cookies`: `HTTPStorages/B.binarycookies` | regular file | Persistent cookies: login sessions may be lost. Not credentials known to be safely regenerated. | off | Same exact-leaf evidence gate as HTTP storage. |
| `webkit`: `WebKit/B` | directory | Persistent website data, potentially local databases/offline content: may lose local-only data or sessions. Not just web cache. | off | [Website data store][webkit] describes persistent website storage, not this exact disk path; exact-leaf evidence gate applies. |
| `cookies`: `Cookies/B.binarycookies` | regular file | Login/session cookies: may sign the user out. Not the keychain and not necessarily exclusive to one process. | off | [Cookie API][cookies] and exact-leaf evidence gate; group cookie stores are excluded. |
| `preferences`: `Preferences/B.plist` | regular file | Settings: preferences may reset, or be recreated by a system daemon. Not a supported way to reset the live defaults database. | off | [Application defaults domain][defaults] documents the filename but discourages direct edits; this is a proposed post-uninstall Trash action with no live-reset guarantee. |
| `application_support`: `Application Support/B` | directory | User data/configuration: may contain the only copy of documents, profiles or databases. Not rebuildable by definition. | off | [Library guide][library] documents the bundle-ID convention; does not prove exclusive ownership. |
| `containers`: `Containers/B` | directory | Entire sandbox app data: documents, settings and databases may be lost. Not merely a cache. Access may cause a system prompt or be denied. | off | [Sandbox guide][sandbox] describes the per-app container. Exact-path/identity and supported-OS acceptance remain required; no entitlement or Full Disk Access bypass. |

Every row uses the same process checks below, including executable paths inside
that candidate and the original/moved bundle, plus the exact running bundle-ID
query. Rule-specific evidence must also document known sharing and daemon
writers; a known active/shared writer disqualifies the item. No rule claims
that process path checks prove absence of every open file descriptor.

**Exact-leaf evidence gate:** general API documentation, a matching basename,
or a Mole rule alone is not sufficient evidence of the exact private storage
layout. Before enabling a rule, its implementation PR must include an immutable
primary-source reference or reproducible native fixture observations for each
supported OS family, explaining attribution, sharing, and the exact filename.
Until that gate passes it reports `execution_supported: false` and
`rule_evidence_unavailable`. Approval of this document does not waive the gate.
No new path pattern may be introduced as an undocumented implementation choice.

[Library guide][library] is convention evidence, not a security boundary.
Preserve the distinction in UI and JSON: `ownership_basis: bundle_id_convention`,
never `exclusive_owner_verified`. Known conflicting evidence always wins.

### Excluded objects and identities

Display existing protected evidence where available; do not expand read-only
v1 discovery just to populate this feature. Shared browser-family profiles,
Group Containers, LaunchAgents, Preferences/ByHost, embedded helper/extension
IDs, display-name variants, dot-directories, system `/Library`, LaunchDaemons,
receipts and already-orphaned data never become selectable. No unload, process
signal, privileged related move, permanent deletion or programmatic restore.

Deny exact ASCII prefixes `com.apple.` and `group.`, plus any bundle carrying
`vendor_uninstaller`. For endpoint protection, the initial exact-prefix table
is `com.crowdstrike.`, `com.sentinelone.`, `com.sentinel-labs.`, `com.eset.`,
`com.jamf.`, `com.jamfsoftware.`, `com.paloaltonetworks.`,
`com.cisco.anyconnect`, `com.cisco.secureclient`. This is deliberately a prefix
check (the Cisco entries need not end in a dot), with no regex or display-name
matching. This table is not an exhaustive detector of installed security tools.

Sensitive-data warnings and default-off overrides initially cover exact
prefixes `com.1password.`, `com.agilebits.`, `com.lastpass.`, `com.dashlane.`,
`com.bitwarden.`, `com.keepassx.`, `org.keepassx.`, `org.keepassxc.`,
`com.authy.`, `com.yubico.`. The warning says local vaults/authentication data
may be lost and the user must know their recovery method. The absence of a
match never means data is nonsensitive: every user-data rule has its own
consequence warning. Maintain both tables centrally in the core with a version
bound into the plan digest. Prefix tables were researched against
[Mole's protection data at a fixed revision][mole]; reimplement policy facts,
do not copy its shell implementation or imply that it proves ownership.

## Eight mandatory execution conditions

Preview establishes potential eligibility. Approval checks all observable
conditions again before *any* effect. Each related native guard repeats the
conditions immediately before its move. Condition 5 is intentionally pending
in preview/approval and becomes a mandatory phase barrier afterwards, not an
impossible requirement that the bundle was already removed during preview.
Any unknown condition fails closed.

1. **Exact path and admission.** Derive the path only from `H`, `B` and the
   compiled rule table. Verify native directory-entry spelling component by
   component (including on case-insensitive/normalizing volumes); do not
   canonicalize a symlink or alias into eligibility. Open ancestry without
   following links. Home, Library and each intermediate component must be real
   directories; the final object must match its rule type. Retain the existing
   ordinary-authority owner/mode/ACL/attribute guards. Require the same local,
   internal, writable supported APFS volume and device as Library, no mount
   crossing, dataless/cloud source or unsafe metadata. A regular-file target
   must have `nlink == 1`. Missing targets are absent, not zero-byte successes.
2. **Stable identity.** Bind target and ancestry device/inode/type. Files also
   bind size and mtime. Bind the selected bundle and Info.plist evidence before
   its move, and the verified moved bundle afterwards. Replacement, missing
   identity or type drift yields `resource_changed`; do not recapture and
   silently authorize a new object. Directory members are not a frozen set.
3. **Admissible owner.** Apply the exact bundle-ID validator, deny tables,
   vendor-uninstaller refusal, rule evidence and known-sharing checks. Preserve
   strong consequences/default overrides for sensitive data. Caller-provided
   identity text or an approval Boolean cannot establish ownership.
4. **No observed other copy.** Combine the bounded root inventory and all URLs
   from LaunchServices as specified below. Any extant distinct non-Trash copy
   refuses every related item (`other_copy_present`). Uncertain observation
   refuses every related item (`copies_unknown`).
5. **Bundle durably succeeded in this session.** Start related moves only after
   the retained bundle operation is durably `succeeded` with validated Trash
   destination/identity. No imported parent ID, history record, host-reported
   success or replayed JSON can open this barrier. A failed, unknown or skipped
   bundle yields `skipped(bundle_not_removed)` for every selected related item.
6. **No observed running owner/writer.** Use a complete bounded census of processes owned by the
   effective UID (scope below) and [runningApplicationsWithBundleIdentifier:][running]. Refuse executables
   within the original bundle, verified Trash bundle or candidate, and any
   running exact-ID app. Use component containment, never textual prefix
   matching. A failed or incomplete observation is `running_unknown`. Never
   signal processes, unload jobs or wait for a process to exit and retry.
7. **Policy permits the whole object.** Capture `exclusions-v1.json` using the
   shared exclusions machinery. An exclusion equal to, above or below a target
   protects it, since a directory moves whole. Unresolved/malformed policy
   makes the preview ineligible. Recheck snapshot identity/content and current
   exclusions before approval and every effect; a changed/unavailable policy
   invalidates the operation, never silently replaces the approved policy.
8. **Complete safety preview.** Required inventory, candidate admission,
   sharing and process observations must all finish without errors, timeouts
   or truncation. Otherwise no related candidate may execute. Advisory size
   measurement is separate: unknown/partial size does not masquerade as zero
   and cannot satisfy a missing safety observation.

### Narrow Library admission

Introduce `RelatedTrashCandidate` with a typed internal admission mode reachable
only from `RevalidatedRelatedTrashV1` (`revalidated_related_trash_v1`). Lift the
Library prohibition solely for the verified `H/Library/<table-prefix>/<leaf>`
chain and exact rule target. All other native protections still apply. The
final directory is a whole-container target; other package ancestors remain
refused. File, bundle, purge, cache and saved-state contracts cannot request
this mode. No general `allow_library` flag or arbitrary caller-provided suffix.
Keep all native FFI in `sayaka-platform-macos`; the engine stays unsafe-free.

### Copy observation and its limits

Mandatory roots are `/Applications`, native `H/Applications`, the selected
bundle's parent and user-added app folders; normalize duplicates without
following links. The request accepts at most eight user-added roots, and the
combined list at most eleven. Bind the complete root set and its directory
identities into the plan. A caller cannot omit mandatory roots. Absent optional
`H/Applications` is a recorded empty root; permission denial is not absence.

Use a bounded no-follow app inventory, descending ordinary folders and stopping
at app/package boundaries. Truncation, unreadable branches, a root replacement
or ambiguous alias that could hide a copy makes coverage unknown. Query
[NSWorkspace URLsForApplicationsWithBundleIdentifier:][copies], available from
macOS 12; an older runtime or failed invocation is unsupported/unknown. Do not
substitute the singular best-match API. Native exceptions, invalid URLs,
non-file URLs and uninspectable existing paths are failures, never empty lists.

Deduplicate by actual directory identity, validate actual Info.plist IDs rather
than trusting registry labels, and match `B` exactly. Ignore a stale registered
URL only after a no-follow observation proves nonexistence; retain a
`stale_registration` issue. Permission denial is not a stale entry. Ignore a
copy in Trash only after native containment in a verified per-user Trash root,
not a basename such as `.Trash`. The selected object's verified Trash destination
is specifically recognized after bundle success. A re-created source bundle or
new distinct copy blocks remaining items. An existing but unverifiable registry
entry is `copies_unknown`.

LaunchServices exposes registered/known apps, not a filesystem-wide proof.
Report the roots, registry result, omitted counts and `coverage:
registered_and_selected_roots`; never state "no copies anywhere". An empty
successful registry response alone does not certify coverage. The bounded
inventory and residual unregistered-copy risk must also be disclosed.

The census covers **all processes owned by the effective UID**, not all
system processes. Enumerate with the native UID filter and validate UID/process
identity while reading executable paths; a change or ambiguity is unknown.
Combine this with the exact-ID running-app query for the user session. Root and
other-user processes are outside the census, even if they can access the data;
known external writers/sharing still refuse execution. Do not claim the census
proves absence of privileged or other-user writers. Native acceptance must show
that a positive complete census is possible under ordinary authority; if not,
keep execution disabled rather than ignore errors or weaken the scope.

Within this scope, process enumeration must distinguish vanished PIDs (verified
exit) from access-denied paths, a full/truncated buffer, PID reuse or unavailable
metadata. Unresolved cases fail closed; do not reuse a status sampler that skips
unreadable processes as evidence of no running owner. System daemons may rewrite
preferences/cookies despite these checks; no claim of permanent erasure or
complete writer exclusion is permitted.

## Session, ABI and confirmation

The proposed `sayaka_uninstall_related_preview_v2` runs on the retained,
not-yet-executed uninstall handle. It derives the native home internally, accepts
bounded extra app roots and the explicit policy directory, and seals its own
candidate evidence. New preview supersedes the old related digest/IDs; release,
cancellation or bundle execution prevents minting a new related plan.

Proposed output kind `sayaka.app_uninstall_related_preview`, schema 2, includes
`plan_digest`, `expires_unix_ms`, overall completeness, copy/running evidence,
and per candidate `item_id`, native path, rule ID/version, identity, type, role,
`ownership_basis`, consequence, nullable logical size plus size completeness,
`execution_supported`, refusals and `default_selected`. A default is a UI
suggestion, never durable approval. Refused candidates must have default false.
Read-only v1 remains unselected with no authorized action, and is never consumed
by the executor. Deduplicate physical targets; conflicting rule attribution or
ancestor/descendant selections are refused, not silently expanded.

Seal at most 32 related targets. This table currently yields at most ten exact
paths, but the ABI rejects over-limit selections. IDs are opaque, unique,
session-local and bound to the preview generation; requests provide IDs, not
paths. Accept only a nonempty unique subset plus the exact current digest and
exact token `uninstall <Bundle>.app and trash N related items`. The digest binds
bundle/Info.plist identity, all related candidate evidence and rule versions,
root coverage, policy snapshot, warnings/default policy and expiry. The
accepted approval binds the exact subset separately as well as the digest.
Count/token mismatch, duplicate/unknown/refused IDs, replay, altered digest or
expired preview refuses before moving the bundle. Selection/order cannot be
changed once accepted. An empty subset uses the existing bundle-only token and
workflow, including when related preview is incomplete.

One App confirmation lists the bundle, each selected path and consequence,
known/unknown sizes and scope limits. Existing `canExecute` then
`authorizeExecution()` gates stay in place. CLI uses the same session with
`uninstall --bundle PATH --related --execute`: this invocation first displays
the related preview, then reads an explicit item-ID subset interactively, then
asks for the typed combined token. It never accepts IDs imported from another
process. Without `--execute`, `--related` produces read-only preview output.
Terminal input is mandatory; no piped token, `--yes` or approval Boolean bypass.

Use monotonic time to enforce 120 seconds from related preview to approval.
A valid approval starts one 120-second monotonic execution deadline shared by
bundle and related phases. Wall-clock expiry is for display/audit only and must
not renew authority after clock rollback. Check the execution deadline before
the bundle effect/delegation and every related call. Do not interrupt a native
call already underway; report its actual outcome.

Proposed ordinary `sayaka_uninstall_execute_v2` and delegated
`sayaka_uninstall_admin_begin_v2` consume this approval exactly once. The retained
job records whether it is v1 or v2; `admin_finish_v1` can finish a v2 begin only
through that job's bound continuation, never from new host input. Existing
`sayaka_uninstall_result_v1` preserves v1 output exactly and includes a related
section only for v2 jobs; ABI docs and strict Swift DTOs must version this shape
explicitly before enabling it. No ad hoc shape accepted by legacy DTOs.

## Bundle-first effects, cancellation and failure

Before bundle effects, validate the entire approved related subset and publish
both bundle and related intents durably under one operation coordinator/Store
lock. Failure of either publication performs no effect. Multiple files are not
an atomic transaction: a crash between publications leaves intent only, with no
permission to resume. Do not nest two exclusive Store locks and deadlock.

Ordinary bundle move keeps its existing native contract. Finder delegation
keeps its administrator-only bundle boundary and begin/finish identity proof.
Related moves always run as the ordinary user, including after Finder approval.
A host's Finder-success Boolean never counts as durable bundle success.

After durable bundle success, repeat shared copy/running/policy observations
and each target's native guard. One Foundation `trashItemAtURL` attempt per
item, no retry or fallback. Persist `started` before that attempt and its actual
outcome afterwards. Foundation destination/contradiction handling follows the
bundle contract. A target-local admission failure is skipped with its reason;
a native access denial is failed with the OS error. Continue other selected
items only while shared guards remain valid. If journal publication fails,
stop further effects and preserve started/unknown evidence; never report all
items moved just because the bundle did.

For a slow password dialog, finish and durably record the bundle outcome even
if the related deadline has passed. A succeeded bundle with an expired deadline
leaves all remaining related items `skipped(approval_expired)`. Explain "The app
was moved; related data stayed because approval expired." This session cannot
refresh/retry related moves; orphan cleanup is a separate future operation.
Do not tell the user to preview an app that no longer exists at its old path.

Precedence for unattempted items: bundle not succeeded -> `bundle_not_removed`;
otherwise explicit cancellation -> `cancelled`; otherwise expired deadline ->
`approval_expired`; otherwise the specific guard refusal. Cancelling before any
move abandons approval. Cancellation during a synchronous native call cannot
retract it; journal the actual outcome and skip later items. Closing/releasing
a delegated job must preserve its started bundle evidence, never release a
background worker still able to start related effects.

Interrupted durable `started` items reconcile to `unknown`, never retried.
Unattempted related `planned` items reconcile to `skipped(interrupted)`; records
are audit evidence only. Never synthesize a successful parent after restart or
resume an approved selection from disk.

Containers can cause a macOS App Data Protection prompt. Observation denial
makes the preview incomplete/ineligible; a denial during the native move is an
honest per-item failed result. Surface permission guidance without claiming Full
Disk Access guarantees success or automatically retrying/escalating the move.

## Journal, history and recovery

Reserve plan/journal schema **8/8**, engine version 2, rules version 1, contract
`revalidated_related_trash_v1` (unused at the reviewed core baseline). Recheck
allocation before implementation if other contracts land first. Do not change
schema 4 (bundle) or 7 (Finder delegation) to add related items.

The parent is the existing one-item bundle record. The child is a separate
1..32-item related record with `parent_operation_id` and a required
`related_context` carrying schema 1, bundle path/ID and identity, Info.plist
identity, approved digest/subset, rule versions, native home/Library identity,
copy coverage, policy snapshot binding and approval/deadline audit timestamps.
Parent linkage is allocated in memory before either intent is written. A
combined UI can show 33 outcomes; no single journal record exceeds 32 items.
Zero selected related items creates no child record.

Each child item binds its rule, native path, resource identity/type and approved
consequence, plus the existing lifecycle state, reason, native error and recovery
evidence/destination. Pin the exact serialized key/type table in the engine/ABI
PR and update both core validation and App strict decoding together before App
enablement. Unknown fields/schema, invalid native paths, duplicate item identity,
illegal state combinations or malformed parent linkage are unsupported, not
coerced into success. Retain Store size/publication/reconciliation limits.

Both records live in the uninstall journal directory. New readers accept
schema 8 only with its matching plan/engine/rule/contract tuple and required
context; other schemas must reject related-only keys. Older App readers report unsupported schema 8 per record and still read the
unchanged parent. Older core/CLI Store readers reject an entire directory with
an unknown schema: downgrade after schema 8 has been written is unsupported.
Keep the writer gate closed through reader rollout; do not claim old CLI
forward-schema compatibility. A missing
or malformed parent is shown as incomplete/unlinked history, never authorization
or proof the bundle was removed. Group linked records without double-counting
outcomes, preserve both even when one failed, and never delete operation history
or the policy store as a related target. Refuse targets overlapping active
state/policy directories in either direction.

Recovery is Finder Put Back or manually moving the recorded destination, per
item. It may fail if the original parent changed. No automatic rollback of a
successful bundle when related items fail; no atomic all-or-nothing claim.
Trash moves do not free disk space until Trash is emptied, which this operation
never does. Destinations are recovery evidence, not durable restore capability.

## Residual risks that must be disclosed

Final no-follow/identity guards do not atomically bind the pathname Foundation
or Finder subsequently resolves. Ancestors or targets can change in that final
window. Directory identity does not freeze descendants: a whole directory move
can include new data. Registered/selected-root inventory misses unregistered
copies elsewhere. Bundle-ID conventions are not signed ownership evidence.
Processes may start after a census; root/other-user processes are outside its
scope, and independent helpers/daemons can write data
without an executable under the checked paths. System preferences may reappear.
The contracts detect observed changes and refuse unknown observations; they do
not eliminate these races or guarantee complete uninstall/erasure.

## Limits and implementation sequence

Safety observation budgets: 8 extra roots, 11 total roots, 4,096 inventoried app
bundles, 256 registry URLs, 65,536 PIDs, 32 related candidates and 256 retained
issues. Root walking is additionally capped at 100,000 entries and depth 32.
Safety preview and each re-observation have a 5-second scheduling budget;
exceeding any cap refuses related execution, never takes a truncated sample as
complete. Native calls may block beyond a deadline; recheck elapsed time after
return and discard late evidence. Do not promise hard interruptibility.

Size measurement is separate, bounded to 100,000 entries and a 2-second budget
per preview with no hydration or symlink traversal. Report nullable/partial
logical bytes; even complete logical totals are not reclaimed physical space.
No directory member list becomes an executable target list.

1. Owner-approved contract only (this PR).
2. Engine/platform implementation, schema 8, rules/evidence gates, shared session
   coordinator and CLI fixture surface; add positive/negative test sources.
3. Versioned bindings, header and [BINDINGS.md](BINDINGS.md); preserve v1 and fix
   the exact request/result/journal shape tables before host integration.
4. App pin update, checkbox review, confirmation, per-item outcomes, strict
   history reader and capabilities/release documentation describing only merged
   behavior. UI calls after `await`/render stay in `ExceptionBoundary.run`.

No unit or UI tests may be executed for this work, including in this core
repository or through reviewers/scripts. Building and compiling test sources
without executing them is allowed. Report builds, manual observations and
unexecuted tests separately. Each implementation PR requires a different-model
independent review, resolution/reverification of findings, then merge and local
fast-forward. Owner-native acceptance remains explicitly unverified until run
by the owner; do not equate compiled fixture sources with passed cases.

## Required acceptance evidence (all pending)

Use disposable owned fixture apps and registered fixture-only Library children.
Never exercise removal against real apps, real settings, or third-party data.
The owner controls the native acceptance run and fixture manifest/cleanup.

| Case | Required evidence |
| --- | --- |
| Every enabled rule | Exact-path provenance plus supported-OS fixture: selected objects and bundle reach Trash, unselected objects stay, recorded identities/content match. Include directory and regular-file shapes. |
| Defaults and warnings | Only permitted categories default on; sensitive override always off; unsupported rows disabled; persistent web/cookie data not called disposable cache. |
| Duplicate copies | Copies in each mandatory/extra root and registered outside roots block related moves; same-identity duplicates deduplicate; stale registry URLs are issues; denied/truncated/query-failed observations refuse. Bundle-only action still works. |
| Path/identity | Case aliases, links at each component, replaced ancestor/target, hard-linked files, wrong type, nonlocal/mounted/dataless sources refused at preview, approval and final guard. No link following. |
| Running | Fixture executable within candidate, original bundle and moved bundle, and exact-ID running app each refuse; failed census/PID reuse stays unknown. Demonstrate complete effective-UID census on the supported OS under ordinary authority and disclose excluded root/other-user writers. No signal is sent. |
| Bundle barrier | Bundle failed, unknown, skipped or cancelled => every related item skipped, none attempted. Imported success/parent IDs and finish-before-begin cannot authorize effects. |
| Finder | Cancel password dialog; successful delegation; source replaced; contradictory success; dialogue exceeds deadline; release/interruption mid-dialog. Verify actual bundle outcome separately from related skips. |
| Approval | Changed digest/IDs/count/token/policy, stale generation, replay, expiry and wall-clock rollback refuse; empty selection remains bundle-only. |
| Policy | Protected parent, child or target, unresolved exclusion, changed policy and state-directory overlap all refuse. |
| Permissions | Container denied during preview => not selectable; denied during native call => failed once, no elevation or retry. |
| Journal faults | Fail either initial publication => no effects; interrupt between intents; fail started/outcome publication => stop subsequent effects, retain honest unknown evidence. No nested-lock deadlock. |
| Cancellation | Before approval, between phases/items, native-call race and interrupted durable started/planned records have the specified distinct states. |
| History/recovery | Core/App accept exact schema 8 and reject invalid context; grouped bundle + 32 related entries do not exceed per-record bounds; old parent remains readable; orphan child honest. Finder Put Back restores owned fixtures, including name conflicts. |
| Boundedness | Cap/timeouts produce ineligible safety preview; unknown size stays unknown; report first-result/cancellation latency and memory on versioned fixtures, not universal speed claims. |

Compile the core and relevant test sources; build the App Debug artifact and
compile its tests with `build-for-testing`, without executing any tests. Record
actual commands and compiler results in the corresponding implementation PRs.
No native acceptance or performance result is claimed by this document.

[library]: https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/MacOSXDirectories/MacOSXDirectories.html
[defaults]: https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/UserDefaults/AboutPreferenceDomains/AboutPreferenceDomains.html
[cookies]: https://developer.apple.com/documentation/foundation/httpcookiestorage
[webkit]: https://developer.apple.com/documentation/webkit/wkwebsitedatastore
[sandbox]: https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AppSandboxInDepth/AppSandboxInDepth.html
[copies]: https://developer.apple.com/documentation/appkit/nsworkspace/urlsforapplications(withbundleidentifier:)
[running]: https://developer.apple.com/documentation/appkit/nsrunningapplication/runningapplications(withbundleidentifier:)
[mole]: https://github.com/tw93/Mole/blob/383a037ff5d6b77f0ebc2a8aec100a46b6d3417c/lib/core/app_protection_data.sh

## Implemented core slice and exact schema 8 fields

The first enabled-path evidence set is limited to the Apple-documented caches,
Application Support and Preferences filenames. Other proposed rules remain
`rule_evidence_unavailable` even after the global native acceptance gate opens.
The read-only v1 rule output is unchanged. Protected targets and state/policy
paths are compared through held physical paths to prevent case-alias overlap.
A shared guard refusal latches for all remaining items, including the final
native guard; there is no observation/retry loop waiting for authority to return.

Schema 8 retains the existing top-level fields `schema_version`,
`plan_schema_version`, `engine_version`, `rules_version`, `operation_id`,
`contract`, `scope`, `created_unix_ms`, `items`, and adds required
`related_context`. The optional `clean_policy`, `tool_operation`, `delegation`
contexts must be absent. Legacy records omit `related_context` entirely.

`related_context` has exactly: `schema_version` (1), `parent_operation_id`,
`bundle_path` (NativePath), `bundle_id`, `bundle_device`, `bundle_inode`,
`manifest_device`, `manifest_inode`, `manifest_digest`, `plan_digest`,
`policy_digest`, `home` (NativePath), `library_device`, `library_inode`,
`copy_roots` (1..11 NativePaths), `coverage`, `approved_unix_ms`,
`deadline_unix_ms`, and `selected` (1..32 bindings, in item order).
Each selected binding has exactly `item_id`, `rule_id`, `rule_version` (1),
`path` (NativePath), `kind` (`file`/`directory`), and `consequence`.
The existing item record contains the matched device/inode, approved logical
bytes, lifecycle, reason, destination and ambiguous recovery evidence.
NativePath retains `encoding`, native `bytes`, and verified quoted `display`.
Digests are 64 hexadecimal characters. Deadline is exactly approval + 120000
milliseconds for audit; the retained monotonic deadline enforces execution.
Validation requires exact rule-derived paths and types, matching selected/item
paths, unique IDs and identities, and a distinct valid parent operation ID.
No context or history record can instantiate an executable session.

Validation of this slice: workspace build and compilation of test targets,
without executing tests. Owner-native observations and acceptance remain pending.
