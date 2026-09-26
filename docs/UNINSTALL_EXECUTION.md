# Uninstall execution contract: single .app bundle to Trash

Design for issue PetrGuan/SayakaCleaner#29 (T9), confirmed by independent
review in PetrGuan/sayaka#42 and implemented in the subsequent execution
slice. Inputs: the read-only
[uninstall preview](APPLICATIONS.md#uninstall-preview-and-execution-contract)
(evidence, protections, refusal surface), the M3 ordinary-file Trash contract
(EXECUTION.md), and the read-only [directory foundation](DIRECTORY_ACTIONS.md).

## Scope of the first execution slice

- **Exactly one** explicit `.app` bundle directory, selected with
  `uninstall --bundle PATH --execute`, is moved to the user Trash via
  `NSFileManager trashItemAtURL:resultingItemURL:error:` — the same mechanism
  Finder uses, including for directories.
- Excluded in this slice: related data / preferences / caches (always
  protected, never listed as targets), multiple bundles per invocation,
  bundles that are running, `/System`, permanent deletion of any kind, and
  any programmatic restore.

The App Store client's optional `sayaka_uninstall_related_preview_v1` call
now exposes the existing `app_related` evidence for one retained bundle and
one separately authorized Library folder. It inventories the selected app
folder and probes bounded related locations, but returns only candidates
linked by bundle-ID/location evidence to the selected copy in that folder.
Other copies outside user-granted roots remain unknown even when the local
inventory is complete. Every row is explicitly unselected and
has no authorized action. This call does not modify the sealed bundle plan or
permit a related-data Trash move. A future execution contract needs its own
ownership, shared-copy, live-process, identity and approval checks before any
related location can become actionable.

## Why the plan contract must change

The M1 planner's `refusal()` currently returns `UnsupportedResource` for any
snapshot whose kind is not `ResourceKind::File`, and the native
`TrashCandidate` deliberately rejects package boundaries and recognized app
roots. Bundle uninstall is therefore not a small wiring change: it extends
the execution contract to a directory target. The extension is deliberately
narrow:

1. A new execution contract variant **`RevalidatedBundleTrashV1`**
   (`bundle_trash_v1`), sibling to `RevalidatedTrashV1`, is required for the
   plan to reach native execution. `ModelOnly` and imported JSON still cannot
   authorize effects.
2. Under this variant the planner accepts `ResourceKind::Directory` **only**
   for a sealed bundle candidate produced by the uninstall session's own
   preview; all other kinds stay refused. File-trash semantics are unchanged.
3. The existing `OwnerState::Running` refusal is bound to the running
   observation defined by the preview contract: any running bundle
   executable (exact resolved path, exact PIDs) maps to `OwnerRunning` and
   refuses the plan. Running is re-observed at approval time and again by
   the platform guard immediately before the native call; a bundle that
   starts running between preview and effect is refused, never signaled.

## Native bundle candidate

The platform bundle candidate reuses the M3 evidence pipeline with the
minimum deltas:

- **Target admission**: directory (not regular file), name ends `.app`,
  not a symlink, `Contents/Info.plist` a regular file, no dataless/cloud
  attributes, same supported local writable APFS volume as the scope. The
  package-boundary rejection applies to **ancestors** exactly as today; it is
  lifted for the target because the target *is* the package.
- **Ancestors/protections/volume**: unchanged from the M3 candidate
  (ordinary authority, writable/untrusted ancestry refusal, hidden/system
  roots, Library, cloud roots, volume identity and device binding).
- **Identity**: bundle directory device/inode/size/mtime plus
  `Contents/Info.plist` identity, revalidated after approval and again by
  the last native guard before the move, using the same revalidation
  discipline as file candidates.
- **Effect**: one synchronous `trashItemAtURL` call is the only mutation
  attempt; there is no fallback path. The returned destination URL is
  captured as the recovery witness. NO means the item was not moved
  (documented Foundation contract): NO without a destination is `Failed`.
  Only a YES without a usable destination, a YES with an error, or a
  contradictory NO+destination yields the existing `Unknown` outcome with
  preserved evidence, never a retry without new approval.
- **No partial directory semantics**: the bundle moves as one object. There
  is no per-member progress, no recursive walk by Sayaka, and no
  partial-success state; if the bundle cannot move as a whole, the item
  fails whole.

## Approval, confirmation and journal

- Preview is the only evidence source. The preview shipped with
  `can_execute == false`; the execution slice (now implemented) derives
  approval eligibility only when zero refusals remain and running is
  `not_running`.
- Approval seals the plan for 120 seconds; expiry invalidates it.
- Confirmation is typed and exact: the bundle directory name
  (e.g. `uninstall Fixture.app`). Empty input cancels. No `--yes`, no
  numeric selection, no piped approval; stdin must be a terminal.
- The journal records intent before the effect (existing M3 `Store`
  publish discipline) and the outcome per item: the bundle path, directory
  identity evidence, the returned Trash destination, and the state
  (`planned`/`started`/`succeeded`/`skipped`/`failed`/`unknown` — the
  existing item states; there is no `cancelled` state). Cancellation before
  the native call records `skipped` with reason `cancelled`; only a durable
  interrupted `started` record reconciles to `unknown`. Recovery evidence
  on `Unknown` follows the existing schema; no new journal schema is
  required.
- Operation history is never deleted by uninstall, including the record of
  the uninstall itself.

## Recovery

- Recovery is **Finder 'Put Back'** (or dragging the bundle out of Trash)
  using the journaled destination path. There is no programmatic restore in
  this contract; 'Put Back' itself may fail if the original parent changed,
  and that limit is disclosed in the execution output.
- A failed Trash operation never falls back to permanent deletion.

## Cancellation and interruption

- Cancellation before the native call leaves zero effects; items not yet
  attempted are journaled `skipped` with reason `cancelled`, never
  `succeeded`. Only a durable `started` record interrupted mid-effect
  reconciles to `unknown`.
- Cancellation racing the synchronous Foundation call cannot retract it; the
  item is reported from the actual native outcome (`moved`/`failed`/
  `unknown`), not from the cancellation request.
- Quit/close during confirmation abandons the approval; nothing moves.

## Required native evidence (acceptance gate, partially recorded)

Cases 1–6 are recorded as of 2026-09-22 — see *Recorded native acceptance*
below. Still open: non-local volume and dataless placeholder shapes.

All in disposable, owned fixtures — never on real installed applications:

1. Fixture `.app` with a self-built executable: preview → typed confirmation
   → moved to Trash; destination, receipt and journal identity verified;
   content and hard-link structure unchanged by the move.
2. Same fixture while its executable runs: refused with exact PIDs at
   preview, at approval, and (forced race) at the last native guard.
3. Symlinked bundle path, missing `Info.plist`, dataless placeholder,
   non-local volume: each refused without any effect.
4. 'Put Back' performed by the operator; bundle intact and launchable.
5. Destination-name conflict in Trash (two same-named bundles from
   different parents): both destinations journaled distinctly.
6. Interrupted run (SIGINT during confirmation, during the native window):
   no effect before the call; honest outcome after it.

## C0 and equal-work notes

Uninstall comparisons must use equal task scope (single bundle, same
fixture), include the confirmation and journal work in Sayaka timings, and
must not substitute skipped protections for speed. The slice is not Mole
`uninstall` parity: multi-copy handling, related-data selection and official
uninstaller flows remain ledger gaps.

## Recorded native acceptance (2026-09-22)

Same authorized run, host and discipline as the purge record above. The
fixture `.app` bundles carried a self-built sleeping executable under an
owned fixture tree; every Trash move targeted only registered fixture
bundles, each restored afterwards.

| Contract case | Result |
| --- | --- |
| 1. Fixture bundle move | Passed: preview → typed `uninstall Fixture.app` → `succeeded`; journal `revalidated_bundle_trash_v1` (4,4), recorded destination, `Info.plist`/executable verified at the destination |
| 2. Running refusal | Passed: with the fixture executable running, preview reports `running` with the exact PID and refuses — the process was never signaled (verified still alive afterwards). The approval and last-native-guard re-observations share the same code path and were not separately staged |
| 3. Refused shapes | Symlinked bundle path and missing `Info.plist` refused with exact codes; non-local volume and dataless placeholder **not staged** |
| 4. Operator 'Put Back' | Passed: bundle restored intact and again preview-clean |
| 5. Destination-name conflict | Passed: two `Fixture.app` bundles from different parents moved to distinct destinations (`Fixture.app`, `Fixture 21-06-21-180.app`), both journaled |
| 6. SIGINT during confirmation | Passed: no handler is installed at confirmation time, so SIGINT terminates the process by signal; nothing moved, no approval persisted |
