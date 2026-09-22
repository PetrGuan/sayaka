<!-- SPDX-License-Identifier: MPL-2.0 -->

# Purge execution contract: selected project artifacts to Trash

Design for issue PetrGuan/SayakaCleaner#28 (T8). This contract was
confirmed by independent review in PetrGuan/sayaka#48 and **is implemented**
by the subsequent execution slice (PetrGuan/sayaka#51,
`revalidated_purge_trash_v1`). The required native evidence below is the
remaining acceptance gate: until it is recorded on a guarded disposable
host, the slice is implemented but **not validated directory coverage**.
Inputs: the read-only [purge preview](PURGE.md) (qualification rules,
evidence base), the M3 ordinary-file Trash contract
([EXECUTION.md](EXECUTION.md)), the single-bundle uninstall
execution/recovery contract
([UNINSTALL_EXECUTION.md](UNINSTALL_EXECUTION.md)) and the read-only
[directory foundation](DIRECTORY_ACTIONS.md).

## Scope of the first execution slice

- **Explicitly selected** artifact directories from the purge preview's own
  candidate set, moved to the user Trash via
  `NSFileManager trashItemAtURL:resultingItemURL:error:` — the same
  mechanism Finder uses, one synchronous call per item.
- Selection is per item and explicit: `sayaka purge ROOT... --execute
  --only PATH [--only PATH...]` (1..32 items). Every `--only` path must
  match, exactly and after the preview's own normalization, one candidate
  artifact directory produced by **this invocation's** preview. `--execute`
  without `--only` selects nothing and refuses (exit 2). There is no
  "select all" flag, no numeric selection, no staleness auto-selection:
  `stale` is an observation, never a selection rule.
- Excluded in this slice: permanent deletion of any kind, recursive
  member-level effects, selection of projects or roots (only artifact
  directories are targets), dataless placeholders, nested artifacts, and
  any programmatic restore.

## Why the plan contract must change again

The planner's directory admission added for bundle uninstall
(`RevalidatedBundleTrashV1`) accepts only a sealed **single** `.app` bundle
candidate from the uninstall session's preview. Purge needs multiple
directory items per plan from a different evidence base. The extension is
deliberately narrow:

1. A new execution contract variant **`RevalidatedPurgeTrashV1`
   (`purge_trash_v1`)**, sibling to `RevalidatedTrashV1` and
   `RevalidatedBundleTrashV1`, is required for a purge plan to reach native
   execution. `ModelOnly` and imported JSON still cannot authorize effects.
2. Under this variant the planner accepts `ResourceKind::Directory` **only**
   for sealed artifact candidates produced by the purge preview of the same
   invocation, each carrying its binding marker evidence. All other kinds
   and all unsealed directories stay refused. File-trash and bundle-trash
   semantics are unchanged.
3. Item count is bounded (1..32) and the sealed selection is part of the
   approval: changing any path, identity or marker evidence after approval
   invalidates that item, never silently substitutes it.

## Native artifact candidate

Per item, the candidate reuses the bundle candidate's admission pipeline
with the purge-specific deltas:

- **Target admission**: directory (not regular file), **not** required to
  end in `.app`, not a symlink, no dataless/cloud attributes, on the same
  supported local writable volume as the selected artifact's own project
  root and marker witness (each item is judged against its own volume;
  the roots of one invocation may span volumes). The package-boundary
  rejection applies to the target and its ancestors exactly as today: an
  artifact directory nested inside an `.app` bundle is refused.
- **Marker binding revalidated**: the marker file named by the preview
  (`Cargo.toml`, `package.json`, `pyproject.toml` or `Package.swift`) must
  still exist as a regular, non-symlink file at the same project root at
  approval time and again immediately before the native call. A removed or
  replaced marker means the rebuild evidence changed: the item is refused,
  never "cleaned anyway".
- **Nesting revalidated**: the artifact still does not nest inside another
  project's artifact, and no new nested artifact is observed at approval or
  the last native guard; the preview's exclusion rule is re-evaluated,
  not trusted.
- **Identity**: artifact directory device/inode/size/mtime revalidated
  after approval and again by the last native guard before the move, using
  the same revalidation discipline as file and bundle candidates. A changed
  identity skips the item (`skipped` with reason), never follows the new
  object.
- **Ancestors/protections/volume**: unchanged from the M3 candidate
  (ordinary authority, writable/untrusted ancestry refusal, hidden/system
  roots, Library, cloud roots, volume identity and device binding).
- **Effect**: one synchronous `trashItemAtURL` call per item is the only
  mutation attempt; there is no fallback path. The returned destination URL
  is captured as the recovery witness. NO means the item was not moved
  (documented Foundation contract): NO without a destination is `Failed`.
  Only a YES without a usable destination, a YES with an error, or a
  contradictory NO+destination yields `Unknown` with preserved evidence,
  never a retry without new approval.
- **No partial directory semantics**: each artifact moves as one object.
  There is no per-member progress, no recursive walk by Sayaka, and no
  partial-success state within an item; if an artifact cannot move as a
  whole, that item fails whole and later items are still attempted (their
  outcomes are their own).

## Approved object: the container, not a member set

Following the directory-action decision gate, this contract explicitly
approves the artifact directory **container under revalidation** — never
an "exact observed member set". The preview's sizes, counts and staleness
are bounded observations of a moment; the revalidation above proves the
container's identity, marker binding and nesting at approval and at the
last native guard, but **a stable container identity does not prove stable
descendants**. Concurrent additions, removals or rewrites inside the
artifact after the last bounded check move to Trash with it, exactly as if
the user had dragged the folder in Finder at that moment. The execution
output discloses this: displayed byte totals are observations, not a
promise of what moved, and never "reclaimed space".

## Running-build limitation (disclosed, not detected)

A project build tool running against an artifact directory is **not**
detected by this contract. Moving `target/` while `cargo` writes to it can
break that build; the artifact moves as user-visible data under ordinary
authority, exactly as Finder would move it. This limitation is printed in
the execution output. Process working-directory or file-handle inspection
is explicitly out of scope for this slice.

## Approval, confirmation and journal

- The preview of the same invocation is the only evidence source. Approval
  eligibility requires: every `--only` path matched a candidate, every
  selected candidate's revalidation still passes, and the item count stays
  within 1..32.
- Approval seals the plan for 120 seconds; expiry invalidates it.
- Confirmation is typed and exact: `purge N artifacts` with the sealed
  count `N` (e.g. `purge 3 artifacts`). Empty input cancels. No `--yes`, no
  numeric selection, no piped approval; stdin must be a terminal.
- The journal records intent before the effect (existing M3 `Store`
  publish discipline) and the outcome **per item**: artifact path, marker
  path, directory identity evidence, the returned Trash destination, and
  the state (`planned`/`started`/`succeeded`/`skipped`/`failed`/`unknown`).
  Cancellation before an item's native call records that item `skipped`
  with reason `cancelled`; only a durable interrupted `started` record
  reconciles to `unknown`. Marker evidence and multi-item artifact records
  fit the existing extensible item evidence/recovery fields, so no new
  journal schema is required.
- Operation history is never deleted by purge, including the record of the
  purge itself.

## Recovery

- Recovery is **Finder 'Put Back'** (or dragging the artifact out of Trash)
  per item, using the journaled destination path. There is no programmatic
  restore in this contract; 'Put Back' itself may fail if the original
  parent changed, and that limit is disclosed in the execution output.
  The journaled Trash location is **evidence, not durable recovery
  capability**: the user or another application may move or empty the
  Trash at any time (M3 caveat, inherited unchanged).
- Rebuild is the primary recovery for this object class by design: the
  marker file is the retained rebuild evidence and is never itself a
  target.
- A failed Trash operation never falls back to permanent deletion.

## Cancellation and interruption

- Cancellation before an item's native call leaves that item without
  effects; items not yet attempted are journaled `skipped` with reason
  `cancelled`, never `succeeded`. Only a durable `started` record
  interrupted mid-effect reconciles to `unknown`.
- Cancellation racing the synchronous Foundation call cannot retract it;
  the item is reported from the actual native outcome (`moved`/`failed`/
  `unknown`), not from the cancellation request.
- Quit/close during confirmation abandons the approval; nothing moves.

## Required native evidence (acceptance gate, still open)

All in disposable, owned fixtures — never on real project checkouts the
operator cares about:

1. Fixture project (`Cargo.toml` + `target/` with content): preview →
   `--only` selection → typed confirmation → moved to Trash; destination,
   receipt and journal identity verified; marker untouched.
2. Multi-item selection (3 artifacts across 2 projects): per-item outcomes
   journaled independently; one forced per-item failure (read-only fixture
   parent) does not stop later items.
3. Marker removed between preview and confirmation: item refused, no
   effect. Marker replaced (identity change): refused.
4. Artifact replaced between approval and native call (forced race):
   skipped with reason, new object never followed.
5. Nested artifact, dataless placeholder, artifact inside an `.app`
   bundle: each refused without any effect. A bare lookalike directory
   (`target/` without its marker) never qualifies and `--only` naming it
   is refused as a non-candidate.
6. Destination-name conflict in Trash (two same-named artifacts from
   different projects): both destinations journaled distinctly.
7. Interrupted run (SIGINT during confirmation, during the native window):
   no effect before the call; honest per-item outcome after it.
   Cancellation after some items have succeeded but before later items
   start: the completed items stay `succeeded` with their destinations,
   every unattempted item is journaled `skipped` with reason `cancelled`,
   and the summary never merges the two.
8. 'Put Back' performed by the operator; artifact intact, project rebuilds
   (or the fixture's rebuild surrogate) from the retained marker.
9. Partial or unknown size coverage in the preview (unknown member sizes,
   budget-limited coverage): the displayed totals stay labeled as
   incomplete observations, the container decision is unchanged, and the
   journal does not relabel unknown bytes as reclaimed.
10. Native Trash environment failure (Trash unavailable or refusing the
    item, e.g. simulated destination failure in the fixture harness):
    honest per-item `failed`/`unknown` outcomes with preserved evidence,
    no retry loop, no permanent-delete fallback.

## C0 and equal-work notes

Purge comparisons against Mole `purge` must use equal task scope (same
fixture trees, same selected set), include preview, confirmation, journal
and revalidation work in Sayaka timings, and must not substitute skipped
protections for speed. Displayed byte totals are bounded observations,
never "reclaimed space" (the PURGE.md rule), and no comparison may present
them as freed bytes. The slice is not full Mole `purge` parity: custom
root sets, staleness-based filtering UX and grouped-project reporting
remain ledger gaps tracked by the C0 `purge` row.

## Recorded native acceptance (2026-09-22)

A separately authorized run on the owner's macOS 27.0 (26A428) arm64 host
exercised the debug CLI built from `80e4e16be2` plus a one-line footer fix
(`6f779da`). Fixtures lived under an owned `~/sayaka-acceptance-fixtures`
tree; every Trash move targeted only registered fixture directories, each
restored afterwards. Typed confirmations ran through a real PTY.

| Contract case | Result |
| --- | --- |
| 1. Single artifact move | Passed: preview → typed `purge 1 artifacts` → `succeeded`; journal `revalidated_purge_trash_v1` (5,5), recorded destination, marker untouched |
| 2. Multi-item independence | Passed: 3-item run with a forced read-only parent — two `succeeded`, one honest per-item `failed` (NSError 513 evidence); a second run with the failing item **first** still moved the later item |
| 3. Marker removed mid-confirmation | Passed: approval refused `resource_changed`, nothing moved |
| 4. Artifact replaced mid-confirmation | Passed: refused `resource_changed`; the replacement object was never followed (staged at the approval boundary; the final native-guard window is covered by the candidate's internal revalidation, not separately staged) |
| 5. Excluded shapes | Nested artifact: excluded at preview (`excluded: 1`). Artifact inside an `.app`: never qualifies, `--only` naming it is refused (exit 2). Dataless placeholder: **not staged** (requires a cloud fixture) |
| 6. Destination-name conflict | Passed: two `target` directories moved to `~/.Trash/target` and `~/.Trash/target 20-55-20-739`, both journaled |
| 7. SIGINT during confirmation | Passed with a documented nuance: SIGINT sets the cancellation flag; the prompt still reads one line (the scan-phase handler stays installed), then the flow exits **130** "Cancelled; nothing moved" — fixture intact, no Trash entry |
| 8. Operator 'Put Back' | Passed: `mv` back from the recorded destination; content byte-identical |
| 9. Partial/unknown coverage | Passed: a permission-denied subdirectory yields `status: partial`, artifact `complete: false`, known-only byte totals and a retained `permission_denied` issue; `--execute` requires a complete preview |
| 10. Trash environment failure | Partially staged: the read-only-parent case produced the honest `failed` outcome with preserved evidence, no retry and no delete fallback; a fully unavailable Trash was **not staged** |

The displayed sizes (14–46 B fixture bytes) are handled fixture bytes, not
freed space. The real Trash was never enumerated beyond the recorded
destinations; all fixture items were restored and no fixture process was
left running.
