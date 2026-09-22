<!-- SPDX-License-Identifier: MPL-2.0 -->

# Directory actions: read-only foundation and decision gate

**Status:** implemented observation-only assessment. Native directory actions
beyond two separately contracted slices are not approved or implemented: the
single `.app` bundle Trash contract
([UNINSTALL_EXECUTION.md](UNINSTALL_EXECUTION.md)) and the bounded
marker-bound purge artifact contract
([PURGE_EXECUTION.md](PURGE_EXECUTION.md)) each seal their own candidates and
are not directory actions of this foundation. This document remains no
directory-cleaning command, application uninstaller, executable plan, or
extension of `revalidated_trash_v1`; the ordinary-file planner and native
Trash adapter continue to reject directories.

## Implemented read-only surface

`scan::directory_review::assess_directory` borrows an immutable `ScanTree` and
requires the current `ScanTaskId`, an observed explicit scope-root entry ID,
one selected directory entry ID, and at most 32 distinct observed exclusion IDs.
This first slice accepts one explicit scan root. Stale task IDs, unknown IDs,
invalid scope/type, duplicate/excess exclusions and cancellation return errors,
not empty success.

`DirectoryAssessment` retains task-bound member IDs and the observed
scope-to-parent chain. Its fields are private; getters borrow the original
scan entries and directory summary. It neither reads the filesystem nor copies
observations into a native candidate. A compile-fail case proves it cannot be
passed to `TrashSession::execute` as a `Plan`.

The assessment always reports `ExecutionContract::ModelOnly`. There is no
approve/execute method, native-action flag, readiness status, serialized
approval import or conversion to an executable plan. **An empty observed-blocker
list is not permission and does not mean native safety checks passed.**

Observed blockers include:

- Selecting the scope root or a location protected by the existing coarse model
  policy.
- Incomplete/gapped/cancelled/failed scan coverage or omitted issues.
- An excluded ancestor, selected directory or descendant: the whole container
  is blocked; children are not subtracted from a hypothetical directory move.
- An observed identity shared with an excluded entry elsewhere in the scan.
- Links, special entries, dataless observations, volume-identity changes, and
  repeated file/directory identities. The observed ancestor chain is checked
  as well as the selected subtree.
- Unknown/conflicting logical or allocation measurements in the existing index.

Examples are bounded to 128 with an explicit omitted count. Subtree counts
include the selected directory, directory/file-name/link/special/dataless counts;
ancestor observations are separate. Sizes and unique-file accounting come
directly from `ScanTree`, including its hardlink deduplication and unknown counts.
Sibling totals are not additive, and known subtotals are not freed space.

The index bounds actual entries/paths (100,000 entries and 32 MiB path bytes).
Assessment uses bounded identity counts and iterative traversal with cancellation
checks, not recursion or native opens. It does not trust reported metric fields
to bypass those index limits.

## Evidence that remains unverified

Every assessment retains all of these native gates, regardless of observed
blockers:

| Gate | Why scan observations do not establish it |
| --- | --- |
| Native identity/freshness | A scan is not a retained native capability or atomic filesystem snapshot |
| Ownership, mode, ACL | ScanEntry does not carry a complete native authority/protection witness |
| Native volume capability | Equal observed device/volume IDs do not prove supported writable local storage |
| Packages/protected locations | A directory kind or filename does not classify every native package/system location |
| Full subtree coverage | Complete means within the supplied traversal policy; package pruning can omit contents |
| External links/exclusion resolution | No observed alias does not prove single linkage or resolve aliases outside the scan |
| Activity/concurrent contents | Root metadata and advisory coordination do not exclude other filesystem writers |
| Approved directory/recovery contract | No directory effect contract or receipt/recovery semantics have been authorized |

These are unknown/unverified, never defaulted to false, zero or clear. The
assessment does not infer ownership, reconstructability, inactivity or disposal
safety from names such as `target`, `build`, `cache` or `.app`.

## Verified in-fixture counterexample

The macOS `directory_observation` integration fixture creates a container with a
nested file and builds the read-only assessment. It then inserts another file
inside the existing nested directory. The container root's device/inode and
mtime/ctime remain unchanged.

An exclusive rename **inside that same owned fixture**, not into Trash, moves
the container and both files while preserving the container inode. Thus:

- Checking only the root inode, or even its mtime/ctime, does not prove that a
  nested subtree still equals the displayed inventory.
- No-overwrite rename protects destination occupancy, not the previously
  observed source member set.
- A directory can move content absent from an earlier review without a root
  identity substitution.

A fresh scan after the relocation sees both files. The old scan task cannot be
reused as a selection in that new tree. No second inventory was inserted between
the late child creation and the exclusive move in this counterexample.

The fixture also verifies that an excluded child remains in the observations
while blocking the whole container, and that the existing ordinary-file Trash
session still has no eligible directory item. No real Trash call, user directory,
mount, package execution or inherited native-test authorization is involved.

## Proposed first native scope, not execution approval

A future slice should start with one explicitly selected, current-user ordinary
non-package directory strictly beneath its explicit scope, on an accepted
same-device native volume. It needs positive, bounded evidence for all retained
ancestors and descendants. Unknown ownership/protection, incomplete traversal,
packages, links, special/dataless entries, mount boundaries, external hardlinks,
activity and conflicting/unknown exclusions must be resolved or refused.
Missing evidence cannot be repaired by weakening the no-follow/materialization
policy or by assuming a directory name identifies build artifacts.

Any exclusion overlapping the selected container, or aliasing an object within
it, blocks the entire directory. Moving everything except the excluded children
would be a different per-item operation, not an atomic container move. Do not
silently switch to recursive deletion, permanent removal, permission rewrites,
private staging or an unapproved helper.

## Decision required before implementing effects

The product must explicitly choose and disclose the approved object:

1. **An exact observed member set.** Repeated full inventory can refuse observed
   changes, but it does not atomically bind a later directory move to that set.
   If exact membership at effect time is required, directory execution must
   remain unavailable without a genuinely suitable primitive/environment.
2. **A directory container under a revalidation contract.** Even after bounded
   checks, a concurrent writer can introduce/change descendants before the move.
   Accepting this is a new container-content risk decision, not permission
   inherited from the ordinary-file final-pathname warning.

No choice has been approved here. File coordination, locks, stable root metadata
or test success cannot be presented as exclusion of arbitrary writers. A future
native contract needs separate action/plan versions, full scope/exclusion and
inventory semantics, resource/deadline behavior, known residual races and genuine
user confirmation before any directory effect is enabled.

Directory receipts must distinguish root movement from verified member-set
observations and from unknown post-effect outcomes. A directory's own stat size
is not its file payload size or reclaimed capacity. Durable intent/outcome
failures, interruption and changed contents must preserve uncertainty and stop
unsafe continuation; no automatic replay or rollback of unverified locations.
Recovery must verify the retained directory identity and return without
overwriting or merging an occupied destination. It is not a general restore
guarantee. Native system evidence, including any actual directory Trash call,
requires a new explicit opt-in scope.

## Targeted checks

```sh
cargo test -p sayaka-engine --lib --locked directory_review
cargo test -p sayaka-engine --test directory_observation --locked
cargo test -p sayaka-engine --doc --locked directory_review
```

These verify observations and refusal/type boundaries, not native directory
acceptance. Existing file/installer behavior and JSON remain unchanged.
