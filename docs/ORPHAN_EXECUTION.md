<!-- SPDX-License-Identifier: MPL-2.0 -->

# Orphaned application data: proposed execution contract

Status: **owner approved 2026-10-11; core implementation is acceptance-gated**.
The engine/platform session and CLI are implemented with
`ORPHAN_NATIVE_ACCEPTANCE_RECORDED = false`. Bindings and App integration remain
subsequent slices. Native acceptance is a separate, later gate; document
approval does not open it. No native acceptance is claimed.

The baseline is core `ee504503`: related uninstall and installed-app cache
cleaning provide reusable machinery, but neither authorizes orphan execution.
Read with [UNINSTALL_RELATED_EXECUTION.md](UNINSTALL_RELATED_EXECUTION.md),
[APP_CACHE_RULES.md](APP_CACHE_RULES.md), [EXECUTION.md](EXECUTION.md),
and [ORPHAN_APP_CACHE_REVIEW.md](ORPHAN_APP_CACHE_REVIEW.md).
If a referenced existing rule is more restrictive, preserve that restriction.

## Owner-approved decisions

| Decision | Approved resolution |
| --- | --- |
| D1: tiers | T1 verified trashed bundle may use evidenced related rules; T3 name-only may execute only an eligible exact cache directory. |
| D2: inactivity | T3 needs at least 30 days since the latest observed mtime in the entire bounded candidate tree, including its root. |
| D3: Spotlight | Additional positive copy evidence vetoes execution; failure is unknown; an empty completed query is recorded, never proof of global coverage. Only the retained, verified T1 Trash evidence is exempt from the copy veto. |
| D4: entry points | Replace the existing Leftovers window and add “Check leftovers” after successful bundle-only uninstall. Defer a Home Clean card. |
| D5: sensitive IDs | T3 is read-only; T1 is always default-off with the strong data-loss warning. |
| D6: history | Use a dedicated leftovers journal root accepting only schema 9, keeping other roots unchanged. |

“No app found” never proves that data has no owner. Eligibility accepts exact
naming conventions and complete bounded observations, with the residual risks
below. UI and JSON must say “no installed copy observed within this coverage,”
not “this Mac has no such app” or “exclusive owner verified.”

## Scope, discovery and evidence tiers

`H` is the effective account home obtained natively with `getpwuid_r`, never
`HOME`, a caller-supplied home or a folder-picker grant. Candidate `B` comes only
from exact directory/file names in the compiled related rule table. Reuse
`valid_bundle_id_component_path()` unchanged, including case-sensitive identity
and its component grammar. Strip only a rule's literal suffix. No display-name,
keyword, substring, case-folded or Unicode-normalized identity matching.
Discovery visits direct children of exact rule directories; it does not turn
arbitrary Library descendants or folder selections into targets.

Reuse `org.apple.library.<key>.bundle_id_convention.v1` rules and their versions,
path types, consequences and evidence gates, with **Containers excluded**:

| Key | Exact path under `H/Library` | Type | T1 evidence now / default when eligible | Consequence |
| --- | --- | --- | --- | --- |
| caches | `Caches/B` | directory | evidenced / on | May redownload or rebuild; arbitrary contents are not guaranteed dispensable. |
| logs | `Logs/B` | directory | gated / on | Diagnostic history may be lost. |
| saved_state | `Saved Application State/B.savedState` | directory | gated / on | Window/resume state and possibly unsaved context may be lost. |
| http_storages | `HTTPStorages/B` | directory | gated / off | Persistent HTTP/login state may be lost. |
| http_storages_cookies | `HTTPStorages/B.binarycookies` | regular file | gated / off | Persistent cookies/login sessions may be lost. |
| webkit | `WebKit/B` | directory | gated / off | Local-only website data and sessions may be lost. |
| cookies | `Cookies/B.binarycookies` | regular file | gated / off | Login sessions may be lost. |
| preferences | `Preferences/B.plist` | regular file | evidenced / off | Settings may reset or be recreated by a daemon; no live-defaults reset guarantee. |
| application_support | `Application Support/B` | directory | evidenced / off | May contain the only copy of documents, profiles or databases. |

“Evidenced” is convention evidence from the related contract, not native
acceptance. Currently only caches, Application Support and Preferences pass
the shared exact-leaf evidence gate. Other rows report
`rule_evidence_unavailable`; a later reviewed shared rule-evidence change may
make them eligible without broadening this path table. Sensitive prefixes
override every T1 default to off; any refused row has default false.

**T1 `trashed_bundle`:** retain a real `.app` in the verified current-user
`H/.Trash` root and read its regular `Contents/Info.plist` now. Its single valid
string `CFBundleIdentifier` must equal B exactly. Observe direct Trash children,
plus bounded journal destination locators still contained in that same root.
Journal data only locates a bundle: schema 4 has no bundle ID, and a schema 8 ID
is not authority. Never trust an imported operation ID, history success, path
text or serialized preview to mint a session. No recursive arbitrary Trash
search, external-volume `.Trashes`, or verification by basename alone.

Trash containment requires native root ownership/identity and no-follow
component/physical containment, with retained bundle and manifest identities
and manifest digest. Use the shared verification primitives; extend them for
this contract without changing #149's same-session bundle-removal barrier.
Retain all observed matching T1 bundles (up to eight); unreadable evidence,
identity ambiguity or overflow is unknown, never permission to downgrade to
T3. A bundle restored, removed or replaced invalidates its retained evidence.

**T3 `name_only`:** complete bounded installed-copy and Trash observations
found no matching bundle. Only `Caches/B` can be eligible; every other rule
is read-only, and every T3 row is default-off. Sensitive prefixes are read-only.
The root and all descendants must have readable mtime, and their maximum must
be at least 30 days old. Traverse without following links or materializing
cloud data, bounded to 100,000 entries and two seconds per candidate at every
required check. Truncation, unreadable metadata, future timestamps, unsafe
entries or an incomplete traversal mean inactivity unknown and refusal. A
recent child vetoes an old root; unknown is never zero or “old.”

## Eight mandatory conditions

Check all conditions in preview, again at approval **before any effect**, and
again in each native final guard. Never replace retained evidence with a fresh
identity to rescue a stale plan. Any unknown fails closed.

1. **Exact path/admission — same as #149 condition 1.** Derive targets solely
   from native H, B and the compiled table; verify exact directory-entry
   spellings, no-follow ancestry and expected final type. Require the same
   local internal writable supported APFS volume/device as Library, no mount
   crossing or dataless source, and the existing owner/mode/ACL/attribute
   guards. Regular files require `nlink == 1`. Absent is not a zero-byte success.
2. **Stable identity — #149 condition 2, with orphan evidence.** Retain target,
   ancestry and Library device/inode/type; regular files also size/mtime.
   Bind every T1 bundle and manifest device/inode/digest and verified Trash
   root. Missing, changed or replaced evidence yields `resource_changed`.
   Directory members are not frozen by retaining a directory inode.
3. **Admissible owner — #149 condition 3 plus installed-family veto.** Share
   the existing DENIED/SENSITIVE tables and exact-ID vendor-uninstaller policy,
   including Docker's `com.docker.docker` refusal. Extract the existing pure
   ID classification for T3; absence of a bundle does not bypass that policy.
   T1 must also pass actual manifest classification. Preserve #149 semantics
   when extracting helpers; no new claim of exhaustive vendor detection.
   If any observed installed ID A has `B.starts_with(A + ".")`, refuse as
   `installed_family_member`. Incomplete family inventory cannot clear this
   check. Embedded helper/extension identities remain outside scope.
4. **No observed installed copy — #149 condition 4 plus orphan roots and
   Spotlight.** Follow the coverage rules below. An observed non-Trash copy
   vetoes all rows for B; incomplete observation yields `copies_unknown`.
   T1's verified retained Trash evidence is not an installed copy.
5. **No observed running owner/writer — same as #149 condition 6.** Complete
   effective-UID process census plus the exact-ID running-app query; executable
   containment in any selected candidate or retained Trash bundle vetoes.
   UID/PID reuse, unreadable executables or incomplete enumeration are unknown.
   Never send signals, unload jobs, wait for exit and retry, or imply coverage
   of root/other-user writers.
6. **No LaunchAgent reference — orphan addition.** Read only native
   `H/Library/LaunchAgents/*.plist`, with no-follow ancestry, retained root/file
   identities and bounded parsing. `Label`, `Program`, or `ProgramArguments[0]`
   equal to B or beginning `B.` veto as `launch_agent_reference`; a program path
   equal to or inside a candidate also vetoes. Compare path components and
   physical locations, not textual prefixes. Missing optional fields are
   distinct from malformed types; malformed plists, ambiguous paths, denied
   access, replacement, timeout or truncation are unknown and refuse. A proven
   absent directory is recorded absent. Never modify/load/unload these jobs.
7. **Policy allows the whole object — same as #149 condition 7, using #140's
   all-root snapshots.** An exclusion equal to, above or below the target
   protects it. Bind all saved-root exclusions and revalidate identities and
   content; unknown/changed policy refuses. Reject lexical or physical overlap
   with session state, journal and policy directories, including alias paths.
8. **Complete safety preview — #149 condition 8 plus orphan observations.**
   Copy/family inventory, Trash evidence, Spotlight, LaunchAgents, process and
   admission observations must all complete. T3's latest-mtime traversal must
   also complete. Advisory size may be unknown, displayed as unknown; size
   success cannot compensate for incomplete safety evidence.

### Coverage and bounded native observations

There is no selected live app whose parent can be an automatic root. Mandatory
live roots are `/Applications` and native `H/Applications`, plus at most eight
explicit extra roots (at most ten distinct roots). Record proven absent
`H/Applications`; access denial is not absence. Bind directory identities,
including existing ancestors for absent roots. T1's parent is the separately
verified Trash evidence root, never an inferred former install location.
A journal's original path cannot silently expand roots or authorize a scan.

Reuse bounded no-follow recursive app-root inventories, stopping at app/package
boundaries, plus **all** LaunchServices URLs for B. Read actual bundle IDs;
registry labels are not manifest evidence. Inspect and deduplicate physical
identities. A stale URL can be ignored only after proven absence, with an issue
recorded. Invalid/non-file URLs, extant unverifiable entries, aliases that hide
coverage or truncation fail closed. Family checks use all installed IDs from
root inventory and also query each valid dot-prefix ancestor ID of B through
the all-URL registry helper, so a registered parent outside those roots vetoes.

Add native `NSMetadataQuery` for exact `kMDItemCFBundleIdentifier == B` and for
those ancestor IDs, with a literal parameter rather than interpolated query
syntax. Record scope and completed initial gathering; stop/release query work
on completion, failure, timeout or cancellation. Bound each query to five
seconds/256 results and all discovery/ownership observations to a shared
30-second deadline, with 10,000 discovered entries/256 candidate rows. Record
limits and omissions. No shell `mdfind`, arbitrary command or hydration.
A Spotlight positive outside retained verified T1 Trash evidence blocks even
if unregistered; an uninspectable positive is unknown. For ancestor queries,
a verified installed ancestor yields `installed_family_member`. An empty query
is weak negative evidence only. A Trash-looking string never earns exemption;
a newly discovered bundle requires a new preview, not approval-time recapture.

Bound the Trash listing and history locator inventory within the discovery
budget; every required source must finish. Bound LaunchAgent inventory to
1,024 entries, 1 MiB per plist, 16 MiB total parsed bytes and two seconds per
observation. Retain the root/absence witness and full plist identity/digest
set across phases; relative program paths are unknown, even without a slash. Budget exhaustion
refuses, never silently truncates. The implementation must record exact native
scope and capability errors in preview/ABI documentation before enablement.

Expose `coverage: registered_and_selected_roots`, actual roots and completeness,
separate Spotlight scope/status/counts, Trash/family observations and residual
risk. Never reinterpret empty Spotlight as filesystem-wide completeness.
Share copy-observation code with #140: observed installed owner permits only
its cache contract; complete zero permits only potential orphan eligibility;
unknown permits neither. Every execution rechecks, so a changed observation
invalidates the old plan; simultaneous previews are not a permanent partition.
Keep each contract's own stronger admission requirements and #149's behavior.

## Typed session, effects and ABI

New contract: **`revalidated_orphan_trash_v1`**. A private typed
`OrphanTrashCandidate` permits only the validated orphan subset of the shared
Library rule table. Related-uninstall, cache, purge and other sessions cannot
request it; orphan sessions cannot request their admission modes. No general
`allow_library`, caller-provided target path or Boolean override. Native FFI
stays in platform-macos; engine remains unsafe-free.

Preview lasts 120 seconds. Accept a nonempty unique subset of at most 32 opaque
session/generation-bound item IDs, exact current plan digest, and exact token
`trash N leftovers`. Bind target/evidence identities, tier, rules/policy versions,
root observations, warnings/defaults, expiry and selected order. Duplicate,
unknown/refused IDs, count/token/digest mismatch, replay, cancellation, release,
expiry or clock rollback refuses before journal/effects. Use monotonic elapsed
time as well as wall-clock validation. Accepted approval starts one immutable
120-second execution deadline; rechecks and native dialogs consume it.

Each selected target gets at most one `trashItemAtURL` attempt, after durable
`started` publication. No retry, permanent-delete fallback, privileged fallback,
process signaling or automatic restore. Shared guard refusal latches all
remaining items. Journal publication failure before starting means no effects;
after an uncertain attempted move preserve `unknown`, never retry from history.
Report per-item succeeded/failed/skipped/unknown faithfully. Cancellation or
expiry never reverses a completed move.

The App partitions more than 32 desired items into explicit batches. Every
batch gets a fresh preview, visible exact paths, consequences and count, and
its own user confirmation/token; never replay one approval, silently truncate
or auto-approve the rest. Defaults are suggestions, not approvals. Physical
aliases, conflicting attribution and ancestor/descendant selections refuse.

Proposed bindings: `sayaka_orphan_preview_v2` derives native home and accepts
at most eight extra app roots plus policy directory; execution uses
`sayaka_orphan_execute_v1` with asynchronous poll/result/release. Preview owns
retained evidence; JSON is not executable authority. The existing read-only
`sayaka_orphan_preview_v1` stays unchanged. Freeze request/result structures,
opaque handle lifecycle and journal keys in the engine/ABI slices before App
integration. CLI `orphans --related --execute` shows preview, then prompts for
item IDs and typed token on a terminal: no `--yes`, pipe token or auto-selection.

## Journal draft and history isolation

Use record/plan **9/9**, engine/rules **1/1**, with required
`orphan_context` schema **1**. Schema 9 was unoccupied at `ee504503`; recheck
before implementation. The engine slice freezes the following schema-9 keys; the bindings slice must
publish the same shape before App integration.
Use existing NativePath encoding, bounded integers and lowercase SHA-256
hex digests; never use escaped display strings as path authority.

| Object | Proposed keys and validation |
| --- | --- |
| Record | Existing `schema_version`, `plan_schema_version`, `engine_version`, `rules_version`, `operation_id`, `contract`, `scope`, `created_unix_ms`, `items`; required `orphan_context`. Unrelated optional contexts absent. Exact contract/version tuple required. |
| Item | Existing `path`, `device`, `inode`, `logical_bytes`, `state`, optional `reason`, optional `destination`, optional `recovery_evidence`, `updated_unix_ms`; `rule_binding` absent (typed orphan binding is in context). `logical_bytes` is the native identity/recovery size; directory advisory totals use selected[].measured_logical_bytes and never substitute a measured zero. |
| orphan_context | `schema_version`, `home`, `library_device`, `library_inode`, `copy_roots`, `coverage`, `spotlight`, `policy_digest`, `plan_digest`, `approved_unix_ms`, `deadline_unix_ms`, `selected`. |
| copy_roots[] | `path`, `state`, `device`, `inode`; present roots record their identities; proven-absent roots record their retained existing parent identities and are explicitly tagged. Bounded complete root set, not caller omissions. |
| spotlight[] | `bundle_id`, `scope`, `status`, `result_count`, `verified_trash_count`, `stale_registrations` (NativePath array); one summary for each queried ID, explicit unknown distinct from zero, bound into plan digest. |
| selected[] | `item_id`, `bundle_id`, `tier`, `rule_id`, `rule_version`, `path`, `kind`, `consequence`, nullable `measured_logical_bytes`, optional `trashed_bundles`. One-to-one with items in approved order; no missing, duplicated or extra binding. |
| trashed_bundles[] | T1 required nonempty; T3 absent. `path`, `device`, `inode`, `manifest_device`, `manifest_inode`, `manifest_digest`, `trash_root`, `trash_device`, `trash_inode`. All retained T1 evidence, not only one chosen convenient copy. |

Validate tier/rule/path/type combinations, version tuple, binding equality,
counts, limits, digests and timestamp order when reading; malformed/unknown
values cannot be coerced. Older schemas omit the new context and keep their
readers. A new dedicated **leftovers history root** uses `NativeHistoryReader`
whitelist `[9]`; do not write schema 9 into uninstall/cache roots. History is
outcome evidence only, never a source of approval or an executable session.

## Enablement, delivery and owner acceptance

Compile-time `ORPHAN_NATIVE_ACCEPTANCE_RECORDED = false`. Every candidate
reports `native_acceptance_pending`, is non-executable/default-off, and approval
refuses before any journal or effect. No environment variable, caller flag,
debug switch or old history can bypass it. Potential tier defaults shown above
apply only after all evidence and acceptance gates pass.

Deliver separate reviewed PRs in this order:
1. This contract and the read-only v1 documentation; owner approval before code.
2. Shared engine/platform observations, typed admission, session/journal and
   CLI acceptance entry point; positive/negative fixture sources compiled only.
3. Versioned bindings, header/BINDINGS documentation and frozen journal keys.
4. App core pin, grouped Leftovers selection with tier/evidence/uncertainty and
   per-path consequences/results, dedicated history root, three languages and
   visible acceptance gate. Remove the two folder pickers. Bundle-only success
   opens the same window through “Check leftovers” with **nothing selected**.
   Preserve `ExceptionBoundary.run` around AppKit calls after await/render.
5. Only after owner-recorded native acceptance: attach evidence and open gate.

Before merge, a reviewer using a different explicitly selected model performs
independent review and verifies fixes. After merge, fast-forward local main.
Do not run unit/UI tests, including indirectly; builds and compiling test
sources are allowed. Report build results, manual observations and unexecuted
tests separately. Native acceptance below is performed by the owner, only with
disposable self-created fixture apps/data, and remains **pending**:

| Case | Required observation |
| --- | --- |
| T1 normal | Trashed fixture yields an eligible/default-on cache; only explicitly selected paths move. |
| T1 restore | Restoring the app after preview refuses approval; no effects. |
| T1 replacement | Bundle/manifest replacement yields resource_changed. |
| T3 age | Forty-day-old complete cache can be selected but defaults off; one-day-old descendant blocks. |
| T3 user data | Application Support is read-only. |
| Copies | A copy in every mandatory/extra root and a Spotlight-only location vetoes. |
| Running | Starting exact-ID fixture after preview blocks; no signal is sent. |
| LaunchAgent | An ID or target-path reference blocks; malformed plist is unknown. |
| Protection | Apple/group/EDR IDs and sensitive T3 never selectable. |
| Family | Installed com.fixture.app blocks com.fixture.app.helper. |
| Native identity | Links, spelling aliases, replaced ancestors and dataless sources fail at preview, approval and final guard. |
| Approval | Altered digest/IDs/count/token, replay, expiry and clock rollback fail; over-32 selection requires separately approved batches. |
| Journal | Initial publication failure has no effects; interruption after started recovers unknown with no retry. |
| History/restore | Schema 9 history renders; old roots still read; Finder Put Back restores the fixture. |

Because production approval is gate-closed, any fixture build needed to observe
successful native moves must be an owner-controlled, unpublished source build
with an explicit local gate change. It is not a runtime bypass or evidence that
the shipped gate was opened. Record exact revision, source change, OS/filesystem,
fixture identities and outcomes; PR 5 must include owner evidence and review.

## Non-goals and residual risks

Never target LaunchAgents/Daemons, privileged helpers, Containers or stubs,
Group Containers, Application Scripts, system `/Library`, external Trash,
non-ID names or embedded helper/extension identities. Installed-app caches
belong to #140 and installed saved state to its existing contract. No empty
Trash, permanent deletion, automatic restoration or claim of exhaustive removal.

Unregistered copies outside observed roots can be missed; Spotlight may be
unavailable, disabled or incomplete. Naming conventions are not signed ownership
proof. ID-prefix family checks are bounded observations, not a complete embedded
extension inventory. Vendor/security lists are not exhaustive. Other-user/root
writers and daemons can still modify data; paths can be replaced after the last
check, and directory membership is not frozen during a whole-directory move.
A complete mtime traversal does not prove inactivity or dispensability. These
limitations must remain visible in confirmation and cannot be removed by
calling an unknown observation “complete.” If this evidence level is not
acceptable to the owner, retain the read-only surface and keep the gate closed.

## Core implementation notes

`OrphanSession` owns retained identities and the selection. The release gate
rejects approval before opening a journal or moving anything. CLI
`orphans --related --policy-dir <directory> [--app-root <root>] [--execute]`
uses the same session; `--execute` requires terminal input for IDs and token.
The default CLI leftovers root is native-home
`Library/Application Support/SayakaLeftoversJournal`; its parent must already
exist. A caller-supplied state directory must be a dedicated leftovers root,
and cannot overlap or nest inside an existing journal root.

Trash locators read only existing journals at native-home
`Library/Application Support/Sayaka`, `SayakaCleaner/UninstallJournal` and
`SayakaCleaner Direct/UninstallJournal`. Missing roots are recorded by bounded
absence checks; unreadable or incomplete locator inventories refuse. The
retained bundle/manifest evidence, not the locator, determines T1.

Shared copy observations now cover native application roots, all registered
URLs and Spotlight for both orphan and generic installed-cache contracts. This
may conservatively refuse previously eligible generic caches if the added
observations cannot finish. It does not widen their allowed namespaces or
change related-uninstall's bundle-first behavior.

Build validation compiles the workspace and positive/negative fixture sources;
unit/UI tests and native fixture moves are not executed by the implementation
agent. Native acceptance and enabling the release gate remain pending.

Schema-9 `recovery_evidence`, when present, uses the existing journal recovery
shape exactly: `approved`, nullable `returned_destination`, nullable
`held_source`, nullable `held_source_path`, and `observation_errors`. The two
path fields use NativePath. File evidence (`approved`/`held_source`) contains
`device`, `inode`, `logical_bytes`, and `modified`; `modified` contains
`before_unix_epoch`, `seconds`, `nanoseconds`. Only an `unknown` item may carry
this evidence, and approved identity/size must match its Item record.
