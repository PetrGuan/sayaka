# Finder-delegated empty Trash contract

Status: **proposal for owner approval; no implementation or native acceptance**.
This is PR 1 of the empty-Trash work. On 2026-10-11 the owner selected the product
choices below for drafting. Those choices are not approval of this completed
contract, permission to implement PR 2, or permission to empty a real account's
Trash. PR 2 must wait for explicit approval of the reviewed contract.

## 1. Product decisions and scope

| Decision | Owner-selected draft scope (2026-10-11) |
| --- | --- |
| D1 | S2 only: ask Finder to empty the entire current Trash. |
| D2 | Independent destructive confirmation; exact typed `empty trash`. |
| D3 | Secondary action on successful cleanup result pages and a Tools menu item; no additional home-page entry in v1. |
| D4 | Reclaimed disk space remains **not measured**. |
| D5 | Accept and disclose that Finder also empties attached volumes' Trash and items placed there by the user or other apps. |
| D6 | Wait at most 600 seconds for the destructive event reply; timeout is unknown, never retry or claim Finder stopped. |

| Alternative | Benefit | Why excluded from v1 |
| --- | --- | --- |
| S2: Finder empties all Trash | Uses the system operation and its handling of volumes, locks and warnings; no recursive deletion implementation. | Selected, with the broad, changing scope explicitly approved in each confirmation. |
| S1: delete only app-journaled items | A bounded set of known identities. | Needs a separately approved no-follow recursive deletion boundary and partial-deletion contract; permissions/volume requirements are unverified. |
| S3: recursively delete home Trash ourselves | Direct home-only implementation. | Arbitrary user-content recursion, permission requirements, and a different scope from Finder; not approved. |

The new effect class is `finder_delegated_empty_trash_v1`. It is separate from
all recoverable Trash operations and from `permanent_tool_operation_v1` simulator
operations. Ordinary cleaning has no permanent-delete fallback. Failed moves,
scans, cancellation, missing permissions, unknown outcomes, scheduler activity,
and successful cleanup do not trigger this operation. The privileged helper,
shell execution, recursive unlink/removal, and secure-delete options are absent.
CLI v1 offers only a read-only known-subset preview; it cannot dispatch an event.

The approved object is **Finder's entire Trash at the time Finder acts**, not a
frozen list, the known subset, a selected subset, or just this app's moved files.
Count equality does not freeze identities. Concurrent arrivals can be deleted,
and equal-count replacement cannot be excluded. Attached external-volume Trash
is included even though the independent v1 observations cover only home Trash.

## 2. Entry and confirmation

A user must explicitly choose **Empty Trash…** from a separate, non-default
secondary action. Cleanup List, Project Cleanup, Uninstall and the existing
cleanup result/review surfaces may show it after at least one successful move;
that success does not preauthorize emptying. The Tools menu is an independent
entry. It is never in the same confirmation as a move to Trash. Cancel is the
safe default; Return in an unfilled text field never authorizes destruction.

Preserve `ExecutionEntitlements.canExecute` and recheck
`authorizeExecution()` immediately before begin. An unconfigured/inactive
license disables the destructive action. Preview and permission explanations
must not activate a license or bypass the gate. Core bindings assume a trusted
host for license enforcement and event dispatch, as with existing delegation;
a typed token is not authentication of an arbitrary in-process host.

The confirmation displays:

- Finder-reported current **top-level item count**, not descendants or bytes.
- K independently matched home-Trash entries from the scanned journals, with
  their paths and historical known logical bytes, or explicit unavailability.
- Known-subset coverage and limits. If incomplete: "At least K matched items;
  other items are unaccounted for." N minus K may only be a count of unaccounted
  top-level entries, never a claim about who placed them there.
- **Everything Finder includes will be permanently deleted**, including items
  from other apps/users and attached volumes. The known list is not a filter.
- Put Back will no longer be available for deleted entries. Cancellation cannot
  undo deletion already performed. Actual reclaimed space is not measured.
- If Finder's warning setting is true, Finder may show an additional confirmation.
  If false, this typed confirmation is still mandatory. The app never changes
  that preference or promises a second dialog when its value is unknown.
- The disclosed count/identity race and the possibility of partial/unknown results.

Input is exactly `empty trash` (case-sensitive, no surrounding whitespace).
The preview lifetime is 120 seconds from the start of core evidence capture,
measured by a retained monotonic deadline; slow capture does not renew it.
Wall-clock approval/deadline times are audit fields only; clock rollback cannot
extend validity. No persisted record, imported JSON, restart or released handle
can restore a preview or dispatch authorization.

Finder count and warning reads must succeed with strict integer/Boolean types
before the destructive confirmation is ready. Unknown is never zero/false. A
zero Finder count produces "Finder reports Trash empty" and no event; it is not
a verified global emptiness claim. If K exceeds Finder's reported count, refuse
and require a fresh preview rather than manufacture a reconciled number.

## 3. Read-only evidence and bounds

Resolve the current effective account's home through the native account API,
not environment variables. Observe its `.Trash` root and its ancestry without
following symlinks; retain the native directory witness, device/inode and
permission/ACL evidence. A missing, replaced, aliased or unverifiable root
makes execution unavailable. Never create, chmod or repair the Trash root.
Do not enumerate its contents or traverse item descendants for the known subset.
Whether required metadata is accessible without Full Disk Access is an
**unverified native acceptance question**, not an availability promise.

The host supplies up to eight explicit journal roots. App v1 uses its known
PickedJournal, PurgeJournal, UninstallJournal and LeftoversJournal roots;
SimulatorJournal and the new MaintenanceJournal are not move sources. Other
callers must supply source roots with their supported schema allowlists; no
arbitrary recursive search, folder picker, imported receipt or alternate-home
selector expands the effect. Missing roots are reported as absent. Unreadable,
busy, corrupt or unsupported input records make coverage incomplete, not empty.
Read source journals under their existing privacy, no-follow and shared reader/
writer exclusion rules, one bounded root read at a time; never steal a lock.
Pending/interrupted records cannot authorize source claims or history badges.

Across the whole preview, cap known entries at 4,096, journal-directory entries
inspected at 10,000, committed records read at 1,024, aggregate journal input at
16 MiB, each record at 1 MiB and elapsed observation at two seconds. All entries,
including ignored names, consume budgets. No unbounded path/glob expansion.
Check time before/after native operations; a synchronous syscall cannot be
forcibly interrupted by the deadline. Overrun is incomplete evidence, never a
claim of hard two-second syscall cancellation.

A known entry must originate from a strictly validated supported move record,
be `succeeded` with a verified destination, and currently match that destination's
recorded device/inode through no-follow, descriptor-relative metadata. The
destination must be an exact **direct child** of the retained home-Trash root;
reject traversal, alternate spelling, descendant-only matches and volume/device
mismatches. External Trash, ambiguous recovery hints and missing/replaced items
are not included. Do not open special files, follow leaf links or hydrate cloud
content. Any unavailable metadata is recorded as incomplete coverage.

Deduplicate the same destination path/device/inode across source records and
retain all bounded source references. Distinct directory entries remain distinct
counts, even if hard-linked; bytes are not unique storage. Conflicting source
claims are omitted and disclosed. Retain source record digests and row identities,
root witnesses and current native item stamps for revalidation; no silent
recapture of changed evidence into an approved preview. Historical device/inode
matching does not defeat inode reuse since the original move, and current
identity does not freeze directory contents. Disclose both limits.

A successfully read historical size remains a historical logical measurement,
not a fresh directory size or space recovered. Use the source contract's correct
size semantics (including nullable schema-9 measurements). An unknown size is
not zero. Preview/context track unknown-size count; no recursive measurement is
performed to fill gaps. Omitted count is nullable: a lower bound and coverage
reasons are retained when the remaining population was never enumerated.

Incomplete source coverage may proceed only with explicit disclosure because S2
authorizes all Finder Trash, not that list. A changed/unknown **retained** root,
source record or matched item at begin refuses the operation; reducing the list
after confirmation is not allowed. Source roots or unobserved additions outside
that retained evidence remain part of the disclosed unaccounted population.

## 4. Preview / begin / event / finish lifecycle

The native engine remains unsafe-free. Native metadata stays in platform-macos;
Foundation Apple Events stay in the App. There is no core deletion callback,
recursive remover or executable effect in the read-only CLI.

1. **Preview:** capture the bounded known subset and root evidence, accept strictly
   typed, source-labelled Finder count/warning observations from the trusted host,
   and return an opaque live session, plan digest, coverage, consequences and
   expiry. The digest binds contract/schema, root, source evidence, item order,
   Finder observations, limits and irreversible all-Trash scope. Finder values
   are advisory and never described as independent core verification.
2. **Confirm:** show that exact preview and require the typed phrase and active
   execution entitlement. Only one maintenance flow is active per host. Disable
   all duplicate entry points during begin, dispatch and finish.
3. **Pre-dispatch observation:** immediately before begin, the App reads Finder's
   count and warning again. Changed count or warning, failed reads or expired
   preview refuse dispatch. Supply these fresh observations to begin; core checks
   equality and all retained evidence. No count equality claim excludes an
   equal-count replacement. Begin has its own bounded two-second revalidation;
   exceeding it refuses the event. Reads and begin run off the main thread.
4. **Durable begin:** atomically consume the exact digest/token/live preview.
   Acquire and retain the canonical per-account MaintenanceJournal store lock;
   hosts cannot choose a second output root to bypass serialization. Publish and
   confirm a durable whole-operation `started` intent, including every known item
   as started, before returning one single-use dispatch permit. Privacy failure,
   ambiguous pending history, write/fsync/rename/marker-cleanup failure or any
   validation error returns **no permit, no destructive event**. Empty-subset
   intent is still an operation, not an invented item or a missing journal.
5. **Dispatch:** after successful begin, recheck cancellation/entitlement and the
   permit's original monotonic preview deadline immediately before sending. If
   revoked/expired, do not send; finish with `not_dispatched`. Otherwise consume
   the permit and send exactly one `fndr`/`empt` event to `com.apple.finder`, direct
   object an object specifier for application property `trsh`. No script text,
   secure-delete parameter, resend, retry or helper. A returned error never
   authorizes a second attempt. Keep the owned operation alive until finish.
6. **Finish:** after the event returns or times out, independently inspect each
   retained known destination, anchored in the same verified root/ancestry. Also
   obtain a fresh Finder remaining count if possible. Failure to obtain it is
   null with evidence, never zero. Core finish gets a fresh two-second budget
   from the start of its post-event observation, capped at the retained 4,096
   entries; the already-expired preview deadline does not cancel reconciliation.
   On exhaustion, all unobserved entries are unknown, never absent. Finder query
   time is bounded separately. Finish is single-use and cannot send an event.
   Publish the observed item and aggregate outcomes durably, then release the
   lock. Missing finish/crash/release reconciles durable started intent as unknown
   even when there are zero item rows. It never replays the event.

Read-only Finder queries send one event each and have a 30-second response limit;
query timeouts refuse a preview/begin or leave post-count unknown. The destructive
event uses `waitForReply` off the main thread with the owner-selected 600-second
limit. The 120-second preview deadline controls **starting** the event, not
whether a later reply can be recorded. Local timeout or cancellation while the
event is pending does not cancel Finder's work. Do not interrupt the observation
or relabel the operation as no-effect; finish records what can be observed.

A timeout, transport ambiguity, lost finish or undurable outcome leaves an
unresolved maintenance record. New dispatch is blocked while that ambiguity
remains. A timeout banner tells the user to inspect Finder; no automatic resend,
background continuation, "retry" button or automatic journal eviction exists.
V1 provides no in-app or CLI transition that clears this barrier. Preserve a
bounded per-account unresolved marker outside normally archived history, bound
to the operation ID/digest, durably before returning a dispatch permit. Clear it
only after a durably confirmed, non-ambiguous finish; a missing/corrupt marker or
inconsistent active journal fails closed. Ordinary history archival, changed
output paths and restart do not authorize a new dispatch. Manual inspection of
Finder is useful but is not machine-verifiable proof of completion. Any future
supported resolution/acknowledgment transition needs a separately reviewed,
owner-approved contract amendment defining its evidence and persisted state;
it must preserve the original unknown outcome. Native acceptance must establish
that this barrier survives process restart and an empty known subset.

## 5. Result semantics and unavoidable uncertainty

Classify Finder replies as `reported_completed`, `user_cancelled`,
`automation_denied`, `failed`, `timed_out`, `transport_unknown`, or
`not_dispatched`. Preserve a bounded native error code and sanitized message.
`errAEEventNotPermitted` supplies the Automation settings direction; cancellation
and denial remain distinguishable. Never infer success from return code alone.

For each known item, revalidate the root before and after its no-follow lookup:

| Independent observation | Item state / reason |
| --- | --- |
| Exact expected leaf returns ENOENT under the unchanged verified parent/root | `succeeded` / `absent_after_delegation` (observed absence only). |
| Same path and retained identity still present | `failed` / `still_present`; may include Finder's cancellation/error as advisory context. |
| Different identity, changed/unreadable ancestor/root, ENOTDIR, denied metadata, deadline/budget exhaustion or other lookup error | `unknown` / specific evidence reason. |
| Host proves it did not dispatch | `skipped` / `not_dispatched`; independently observed absence is recorded separately, never attributed to this operation. |

Do not describe ENOENT alone as proof of permanent deletion: a concurrent actor
may have restored or moved the object, and links/hard links/snapshots can preserve
content. This is an observation-based delegation contract with disclosed
attribution limits. Per-item `succeeded` means the retained entry is now absent,
not that storage was freed or every descendant was destroyed. Even after Finder
cancellation/error, inspect known items: some may already be absent.

Aggregate precedence (journal durability failure always makes the displayed
operation unconfirmed regardless of the proposed aggregate):

1. Proven no dispatch: `cancelled` with `not_dispatched` and no claimed effect.
2. Finder cancellation/Automation denial: `cancelled`, with any observed partial
   changes displayed explicitly; cancellation is not an assertion of no effects.
3. Any observed retained entry still present, or a valid nonzero Finder remaining
   count: `partial` (means residual entries, not proof some deletion occurred).
4. Timeout, transport ambiguity, failed reply, unknown required observation or
   changed root: `unknown`; preserve the individual observations.
5. `reported_completed`, at least one known item, all known items observed absent,
   valid post-count zero and stable root: `succeeded`, labelled **Finder reported
   completion; the K known entries are absent**. Unaccounted/external entries are
   not independently verified; incomplete source coverage stays visible.
6. Zero known items: `unknown` even with completion/zero reported by Finder. Show
   the Finder report, but never manufacture independent success by vacuous truth.

Timeout/transport uncertainty remains a retry barrier even if residual evidence
makes the displayed aggregate partial. Finder's count and warn preference are
point-in-time reports and can race; neither is a filesystem authority. Global
permanent deletion is not independently verified in v1. No bytes-freed headline,
secure erasure claim or guaranteed backup/restore statement is permitted.

## 6. Journal schema 10 draft and history

Repository inspection at core `d1f2a1d` finds schemas 1–9 allocated; reserve
schema/plan **10/10**, engine/rules **1/1** for this contract only. Recheck before
PR 2. The exact strict decoding keys must be frozen together in core, bindings
and App fixtures before integration; unknown/missing/conflicting fields fail
closed. Other contracts cannot carry `empty_trash_context`.

Top-level draft (all required unless explicitly stated):

| Keys | Value / invariant |
| --- | --- |
| `schema_version`, `plan_schema_version`, `engine_version`, `rules_version` | `10`, `10`, `1`, `1`. |
| `operation_id`, `created_unix_ms` | Existing validated ID and audit time. |
| `contract` | `finder_delegated_empty_trash_v1`. |
| `scope` | Lossless native home-Trash path; **observation scope only**, not the wider effect scope. |
| `items` | Zero to 4,096 aligned known-entry ItemRecords. |
| `empty_trash_context` | Required context below; no tool/rule/clean/delegation/related/orphan context. |

`empty_trash_context` draft:

| Keys | Type / meaning |
| --- | --- |
| `schema_version`, `performer`, `effect_scope` | `1`, `finder`, `all_finder_trash_including_attached_volumes`. |
| `trash_root`, `trash_device`, `trash_inode` | Lossless native path and observed root identity, matching top-level scope. |
| `plan_digest`, `approved_unix_ms`, `deadline_unix_ms` | SHA-256 digest and audit times; monotonic deadline remains live-session authority. |
| `operation_state`, `aggregate_outcome` | `started` or `finished`; aggregate null while started, otherwise enum from section 5. |
| `finder_preview_count`, `finder_before_count`, `finder_after_count` | u64, u64, nullable u64; before equals preview. Values are Finder-reported. |
| `warns_before_emptying` | Required Boolean rechecked equal at begin. |
| `finder_outcome`, `finder_error_code`, `finder_message` | Nullable while started; bounded classification, optional i32 code and bounded sanitized text. |
| `dispatch_timeout_seconds`, `dispatch_may_continue` | `600`; conservative Boolean true for unresolved started/timeout/transport outcomes. |
| `known_subset_complete`, `coverage_reasons` | Boolean and bounded reasons; completion is relative to supplied source roots only. |
| `omitted_count`, `omitted_lower_bound`, `unknown_size_count` | Nullable exact omitted count, known lower bound, count of retained items whose correct source size is unknown. |
| `source_roots` | Bounded path/schema allowlist/status/digest evidence summaries. |
| `known_items` | Exactly aligned per-item provenance and measurement context below. |
| `unaccounted_logical_bytes`, `reclaimed_bytes` | Always null; never encode unknown other-content sizes as zero. |

Each `known_items` element has `source_refs` (bounded original root index,
operation ID, item index and record digest), `historical_logical_bytes` (nullable
u64 under the source contract), and `observation` (started/present/absent/unknown/
not_dispatched). Alignment with `items` binds the exact lossless destination and
device/inode. Deduplicated origins share one item; conflicting origins do not
silently pick one measurement.

An ItemRecord's `path` is its verified Trash destination, `device`/`inode` its
retained identity, `destination` is null, `state` and `reason` follow section 5.
`logical_bytes` retains the source ItemRecord's nonnullable historical u64, but
must not be used when the aligned contract-correct measurement is null. It is
never a fabricated size for an unaccounted item. Rule binding/recovery evidence
are absent. Maintenance has no move destination or Put Back capability.

The current generic 32-item/nonempty validation is **not** sufficient: add a
schema-10-only allowance for 0–4,096 items and a durable operation lifecycle
independent of item count. Other schemas retain their limits and meanings.
Keep the 1 MiB record and 16 MiB read bounds; preview must report execution
unavailable when the complete bounded intent/outcome cannot fit the record
limit, with bounded per-item/error strings and reserved worst-case outcome
space. Never drop provenance/known items at begin, write partial intents, split
one global Finder event into falsely independent batches, or raise all contracts'
limits. Existing durable publication barriers and pending-receipt precedence
apply to both context and rows, including zero-item operations.

Use the canonical `MaintenanceJournal` beneath the approved per-account app state
base. App accepts only schema `[10]` there, with source **Maintenance**. Pin and
validate that one base before preview; alternate bases cannot evade the
per-account active/ambiguous operation barrier. Output is separate from source
move journals. Core/CLI receipt reading, reconciliation and size/accounting code
must handle the new contract explicitly; generic `handled_bytes` must not add
maintenance to moved-to-Trash totals. No old journal is rewritten.

History links records by original root/operation ID/item index/digest and exact
identity, not display name or path alone. Only a durably finished maintenance
record, Finder completion and an independently absent known item can add the
qualified annotation **Absent after Empty Trash at <time>; Finder reported
completion**. Explain that it may have been moved elsewhere and that permanent
deletion of content is not independently proven. For cancellation/unknown or
changed origin records, show uncertainty instead of an "already permanently
deleted" claim. Suppress stale reveal/Put Back affordances for entries confirmed
absent; any later reveal still requires current identity validation. A source
record missing from a bounded history page remains unresolved, never falsely
unlinked. Local TrashHistory does not count this as another move or freed space.

## 7. ABI and implementation sequence

PR 1 changes documentation only: this file and the execution-contract index.
A different-model reviewer must review the contract; owner approval is then
required before implementation. Design approval never authorizes a destructive
native acceptance run on the current account.

After approval, PR 2 adds the separately owned core session, native read-only
observation and strict schema 10, plus `sayaka_empty_trash_preview_v1`,
`sayaka_empty_trash_begin_v1`, `sayaka_empty_trash_finish_v1`,
`sayaka_empty_trash_result_v1` and release APIs. Define explicit state transitions,
single-use begin/finish, bounded input/result sizes, cancellation, native error
classification, ABI version/struct-size/reserved validation and unsupported-OS
behavior in `sayaka.h` and BINDINGS.md. A host cannot finish-before-begin, replay a
permit, change roots/digest/token after approval, or turn read-only preview into
an event. CLI gets no execution flag. Compile positive/negative fixture sources;
do not execute tests. Update governance references only after owner approval.

PR 3 pins the reviewed core, adds the three single-event Finder helpers and
independent UI flow, performs license/state/deadline gates, and implements strict
MaintenanceJournal/history support. Provide English, Simplified Chinese and
Japanese copy. AppKit calls after await/render remain inside
`ExceptionBoundary.run`. Update capabilities, distribution/trash-results and
README only to reflect delivered capabilities and remaining native acceptance.

Each PR receives independent review by a different explicitly selected model;
fixes are reverified before merging. Fast-forward local target branches after
merge. No new workflow, test runner, helper permission or global safety bypass.

## 8. Native acceptance — pending and separately authorized

Never send `empty trash` on a real account during this task. Irreversible native
acceptance requires an owner-controlled disposable macOS user or VM whose home
and every attached-volume Trash contain **only disposable fixtures**. Obtain
explicit action-time owner authorization before any actual empty event. Existing
approval to move fixtures to Trash, earlier #144 acceptance, or this contract's
approval does not authorize it. Never disable Finder warnings, permissions or
license checks to make an observation pass.

| Case | Required recorded observation |
| --- | --- |
| Automation denied | Clear Automation settings direction; no event effect; durable cancelled/denied result and independent subset observation. |
| Finder warning on, cancel | Finder confirmation shown; cancellation recorded; partial disappearance still observed. |
| Confirm empty | Known entries absent; Finder completion and zero remainder recorded; qualified history link and no stale recovery action. |
| Finder warning off | Typed phrase still mandatory; no implicit second-confirmation assumption. |
| Locked and open entries | Observe actual residual/unknown behavior; never assume locks/open handles prevent deletion. |
| Added entry before begin | Changed count refuses before event and before irreversible authorization. |
| Equal-count replacement and late arrival | Record residual risk; identity changes in the known subset refuse begin, unaccounted arrivals are not claimed frozen. |
| External volume fixture | Finder scope and count behavior recorded; unknown independent external verification stays explicit. |
| Timeout / interrupted wait | Unknown/partial observation, no resend, Finder may continue; persistent ambiguity barrier survives restart. |
| Zero known subset | Durable operation-level intent and unknown-on-interruption; no synthetic item/zero-size claim or vacuous success. |
| Journal intent / outcome fault | Initial publication failure sends no event; post-event durability failure keeps conservative unknown evidence and blocks a new dispatch. |
| Expiry / replay / malformed ABI | Wrong token/digest/count/warning, stale/consumed/released handle, clock rollback, duplicate begin/finish all refuse unauthorized event. |
| Native identity / permissions | Root/ancestor/item replacement, links/aliases, unreadable metadata and interrupted/busy source records preserve refusal/coverage semantics. |
| Bounds / accounting | 4,096 entries, source/time/record-byte limits, duplicates/conflicts and nullable sizes; no existing-schema limit widening or repeated move totals. |
| Entitlement | Inactive/unconfigured license disables dispatch; loss after confirmation/begin causes not_dispatched. |
| Without Full Disk Access | Record exactly which root/item metadata operations succeed or fail; do not advertise an unverified entitlement-free path. |
| History compatibility | Maintenance `[10]`, strict decoding, source correlations, legacy records, pending precedence and no stale reveal/recovery claim. |

Record OS/build, filesystem/volume scope, exact revisions, Finder warning state,
Automation/FDA/license state, immutable fixture identities, event result and
independent before/after observations. Report builds, manual observations and
unexecuted tests separately. No unit/UI tests may be run through agents or
scripts. Source review and compilation do not constitute native acceptance.

## 9. References and contract boundaries

The installed `/System/Library/CoreServices/Finder.app/Contents/Resources/Finder.sdef`
was inspected read-only: command `empty` is `fndr`/`empt`, application property
`trash` is `trsh`, trash-object has `warns before emptying` (`warn`), and `security`
is obsolete. No Apple Event was sent during contract preparation. The existing
App `Platform/FinderTrash.swift` supplies the single-event delegation precedent;
its unlimited administrator-move timeout is not inherited by this new effect.

See [execution](EXECUTION.md), [delegated uninstall](UNINSTALL_EXECUTION.md),
[simulator permanent operations](SIMULATOR_CLEANUP.md), and [bindings](BINDINGS.md).
This proposal does not authorize S1/S3, general permanent deletion, secure erase,
recursive filesystem effects or changes to any existing cleanup contract.
