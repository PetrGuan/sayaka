<!-- SPDX-License-Identifier: MPL-2.0 -->

# Saved-state cleanup: operation, threat and recovery contract

Design for issue PetrGuan/SayakaCleaner#30 (T10), Class B operation
`saved_state_cleanup` from the umbrella contract
([MAINTENANCE.md](MAINTENANCE.md)). This document is the architect contract
that must be confirmed before **any** effect is enabled. It implements
nothing: merging this document authorizes no removal.

Frozen upstream reference: Mole V1.53.0 `opt_saved_state_cleanup`
(`lib/optimize/tasks.sh`, pinned commit
`1b9023b5f151c2d963bbcb9cb658f4824137b8aa`): find `*.savedState`
directories directly under `~/Library/Saved Application State` older than
30 days (`MOLE_SAVED_STATE_AGE_DAYS`), skip protected paths, remove each.

## What the object is

A `*.savedState` bundle is one application's window/resume state, written by
macOS on the app's behalf. It is **not** documents, preferences, caches or
credentials, and it is not the application. Deleting one changes how the app
restores windows at next launch; the residual cost is disclosed below, never
hidden behind a "cleanup" label.

## Operation contract

| Field | Content |
| --- | --- |
| Platform / OS bounds | macOS with the per-user `~/Library/Saved Application State` location; ordinary user authority only. Other platforms: `unsupported_platform`, never a silent skip |
| Applicability | The fixed named location exists and is a directory owned by the current user. Absent/unreadable location is `unnecessary`/`unknown`, never an error disguised as success |
| Necessity evidence | None required beyond the user's explicit request: this is a named user-initiated cleanup, not an optimization. No "speed up", "free memory" or health-score language anywhere. Age is a filter, not a judgment: mtime is an observation, not proof of disuse |
| Impact scope | Exactly the selected `*.savedState` bundle directories, each moved to the user Trash as one container. Provably untouched: every other file in the location, the owning applications, their documents/preferences/caches/credentials, and the Trash itself beyond the additions |
| Concurrency | The owning application must not be running — detected by exact bundle identifier via `NSRunningApplication runningApplicationsWithBundleIdentifier:` (official, unprivileged, per-item). A running owner refuses the item at preview, at approval and at the last native guard; it is never signaled or terminated. Other Sayaka operations are unaffected |
| Permission | Ordinary user authority. No privilege escalation of any kind |
| Recovery limits | Finder 'Put Back' per item from the journaled Trash destination (M3 caveat: Trash location is evidence, not durable recovery capability). Primary recovery is the app regenerating its state at next launch. **Disclosed residual cost: window positions and resume state are not restorable once Trash is emptied; this is the honest price of the operation and is printed in preview and execution output.** No programmatic restore; no permanent-delete fallback |
| Result granularity | Per-item outcomes: `moved`/`skipped` (with reason)/`failed`/`unknown`, journaled individually. Never a bare success count |

## Enumeration and eligibility

- Scope is the **fixed named location only**, taken as one explicit path
  resolved against the current user's home (no environment-variable trust;
  the home comes from the native user directory, not `$HOME` text). No
  recursion below the location's direct children, no other directories.
- A direct child is a candidate only when: its name ends `.savedState`, it
  is a directory (never a symlink), not dataless, and its prefix before
  `.savedState` parses as a bundle identifier (reverse-DNS shape). Anything
  else stays invisible — it is not reported as a candidate and is never
  touched.
- Each candidate reports: directory name, derived bundle identifier,
  logical/allocated subtotals (unknown stays unknown, partial marked),
  observed mtime, and its age vs the cutoff. Default cutoff 30 days
  (Mole-pinned), adjustable with an explicit flag bounded 30..3650; the
  effective value is published.
- Per-item preview states: `eligible` (old enough, owner not running),
  `too_recent`, `running` (with the bundle identifier), `not_attributable`
  (running state cannot be proven clear — fail closed), `unknown`
  (metadata/observation failure — fail closed). Only `eligible` items are
  selectable. An empty eligible set is `unnecessary`, distinct from
  `unknown` and from a failed observation.

## Selection, admission and effect

- Selection is per item and explicit: `--only NAME...` (1..32) matching
  candidate directory names from the same invocation's preview, exactly as
  with purge. No select-all, no age-based auto-selection.
- The effect mechanism reuses the bounded native directory-candidate
  pipeline introduced for purge (`revalidated_purge_trash_v1` shape):
  ordinary-authority directory admission, full ancestry protection chain,
  volume identity, cloud/dataless refusal, package-boundary rejection — but
  **without a marker requirement**; the binding evidence here is the
  bundle-identifier naming convention plus the running observation. A
  dedicated plan variant `RevalidatedSavedStateTrashV1`
  (`saved_state_trash_v1`, own plan/journal schema tuple) is required;
  the purge and bundle variants stay untouched.
- One synchronous `trashItemAtURL` call per item is the only mutation
  attempt; single-attempt discipline, destination URL journaled as the
  recovery witness, NO-means-not-moved semantics exactly as in the
  file/bundle/purge contracts. The artifact moves as one container; the
  purge contract's container-not-member-set disclosure applies and is
  repeated in output.
- Approval seals for 120 seconds with typed exact confirmation
  (`clean N saved states`). No `--yes`, no piped approval; stdin must be a
  terminal.
- Running re-observation happens per item at approval and at the last
  native guard via the same bundle-identifier query. An owner that starts
  between preview and effect is refused, never raced.

## Cancellation and interruption

Same discipline as the bundle/purge contracts: cancellation before an
item's native call journals that item `skipped` with reason `cancelled`;
only a durable interrupted `started` record reconciles to `unknown`;
cancellation racing the synchronous Foundation call reports the actual
native outcome, never the request.

## Journal and history

Per-item M3 journaled intent/outcome under the new schema tuple: candidate
name, derived bundle identifier, directory identity evidence, the returned
Trash destination, and the item state. Operation history is never deleted
by this operation, including its own record.

## Required native evidence (acceptance gate, still open)

All in disposable, owned fixtures — never against the operator's real
`~/Library/Saved Application State`:

1. Fixture location with old/new/running states: preview states correct;
   eligible selection → typed confirmation → moved; destination and
   journal verified; a `too_recent` item is not selectable.
2. Running owner (fixture app launched by bundle identifier): refused at
   preview, at approval, and (forced race) at the last native guard; the
   process is never signaled.
3. Owner quits between preview and approval: eligible again, moves.
4. Non-conforming names (`randomdir`, `weird.savedState` without a bundle
   identifier shape, symlink, dataless placeholder): invisible or refused,
   never touched.
5. Bundle replaced between approval and native call (forced identity
   race): skipped with reason; the new object never followed.
6. Destination-name conflict in Trash: both destinations journaled
   distinctly.
7. Interrupted run (SIGINT during confirmation, during the native window):
   no effect before the call; honest per-item outcome after it.
8. 'Put Back' performed by the operator; bundle intact.

## C0 and equal-work notes

Comparisons against Mole's `saved_state_cleanup` must use equal task scope
(same fixture location, same ages, same selected set) and include preview,
running observation, confirmation, journal and revalidation work in Sayaka
timings. Sayaka's per-item selection and Trash-not-delete are deliberate
extra work over Mole's find-and-remove; that cost is reported, not skipped.
The slice is not full Class B coverage: the remaining Class B operations
each need their own contract.
