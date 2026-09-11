# Explicit native Trash

M3 is a narrow, user-initiated ordinary-file workflow, not general cleaning.
Scanning and M1 planning remain read-only. Native Trash/recovery environment
acceptance is separate from default model, journal and admission checks.

## Approved guarantee and its limit

`revalidated_trash_v1` binds approval to the complete engine-owned preview:
selected identities, paths, scope, exclusions, metadata, versions, expiry and
the execution/recovery description. Only a native `TrashSession` can execute
its own preview. Arbitrary probes, M1 approvals and imported JSON cannot invoke
the production executor.

The native adapter retains evidence and checks it again immediately before one
Foundation `FileManager.trashItem(at:resultingItemURL:)` call. An observed change,
unknown protection/capability, cancellation or expiry refuses the effect.
Revalidation can reduce the approved set, never refresh it to new targets.

**This is not atomic identity-and-ancestry comparison at the filesystem effect.**
A different process can replace a file or ancestor after the final check, and
the system operation could move a different object. Ordinary applications doing
save-by-replacement can cause this as well as malicious processes. Later
verification may discover a problem but cannot guarantee prevention, detection
or restoration. Do not use this workflow on actively modified files.

The original stronger gate remains unsupported. Native experiments showed that
`renameat`/`renameatx_np` can move replacement entries; EXCL protects a destination
collision, not approved source identity. The revised contract is an explicit
product decision, not a claim that those experiments now pass.

File coordination can assist cooperating file presenters but is not a lock
against arbitrary filesystem writers. No helper, elevation, ownership/permission
rewrite, private staging move or post-hoc check is used to claim otherwise.

## Scope and resource limits

- Only explicitly selected ordinary single-link files on supported local,
  internal, nonremovable APFS volumes, with ordinary user authority.
- No directories, recursive traversal for selection, application uninstall,
  symlinks, cloud placeholders, remote/removable volumes or permanent deletion.
- Protected/unsupported application and system locations remain unavailable.
  Every retained ancestor is classified for native package boundaries at capture
  and revalidation. Known disk-image/VM package suffixes are also refused without
  depending on local application registration. Unknown evidence is refusal, not
  presumed permission.
- At most 32 selected files and 32 exclusions per session; native paths and
  ancestor evidence are bounded. The plan expires after 120 seconds.
- No batch expansion after confirmation; no cross-process saved approval.
- One native call at a time. Cancellation prevents the next call, but an OS call
  already entered may finish. There is no universal cancellation deadline.

Each native candidate owns its descriptors and is private to the session.
The existing `sayaka-platform-macos` crate owns FFI and thread I/O policy;
the engine remains `forbid(unsafe_code)`.

## CLI

```sh
sayaka trash --scope . ./file.txt
sayaka trash --scope . ./file.txt --json
sayaka trash --scope . ./file.txt --execute
sayaka receipt --json
```

Use existing physical paths; replace the example filename. `..` traversal is
rejected, not normalized into another allowed selection. Exclusions are
repeatable with `--exclude PATH`; lexical overlap and native identity/ancestry
checks prevent differently spelled filesystem aliases from bypassing an
exclusion. ASCII case-overlap exclusions are deliberately conservative even on
case-sensitive volumes. Unverifiable exclusion evidence aborts instead of permitting effects.
Excluded/refused entries are shown separately.

Without `--execute`, no target or application state is modified. `--execute`
requires terminal stdin/stdout/stderr, shows the exact preview and risk statement,
and requires the exact phrase `trash N`. Blank input, EOF or another phrase
cancels. There is no `--yes`, piped approval or JSON approval import.
`--json` is for preview and receipt readout and cannot be combined with execution.
Both JSON surfaces use a versioned envelope; preview includes the separate
plan-schema and action-contract versions. Native path bytes accompany escaped
display text and are never reconstructed from display text.

Exit codes: `0` for an eligible preview, completed eligible batch or ordinary
receipt read; `2` for invalid arguments/confirmation environment; `3` for partial
or refused selections/results or pending journal snapshots; `130` for cancellation;
`1` for storage/native ambiguity and other operational failure. Exclusions alone
are not failures when eligible files remain. An empty eligible plan cannot execute.

No system command, Finder AppleScript or external `trash` binary is invoked.
There is no alternate-route retry after an attempted native operation. A failed
Trash operation never falls back to permanent removal.

## Durable records

State defaults to `~/Library/Application Support/Sayaka`. `--state-dir DIR`
selects a private local directory, including a fixture-specific directory for
tests. Its parent must already exist. Creation occurs only for explicit execution.
The final directory must be user-owned and private; symlink traversal, public
file permissions, extended ACL entries (including deny-only ACLs), hard-linked
records and nonregular record files are rejected. Unknown ACL evidence is an
error rather than treating mode bits alone as proof of privacy.

An exclusive OS file lock serializes both writers and readers. Process exit
releases it; the lock file is not a PID-based stale-lock authority. A receipt
reader refuses a busy store instead of classifying an active operation as crashed.

Each operation has a schema-versioned JSON record. Before publishing an update,
a separate `.pending` conservative receipt is written, full-synced, directory-
synced and full-synced again. It retains earlier completed outcomes while treating
new terminal outcomes as unconfirmed. A `.next` snapshot carries the proposed
record; it is full-synced, renamed to `.json`, directory-synced and full-synced.
The conservative receipt remains in place throughout these durability barriers,
so a post-rename sync failure cannot expose optimistic success on reopen.

Only after the result is confirmed durable is the `.pending` marker removed.
Marker cleanup failure is reported separately and stops the batch, but does not
relabel an already-durable native outcome as an uncommitted one. An intent cleanup
failure still prevents entering the native call. A marker that survives a crash
may conservatively retain uncertainty; it never grants permission to replay.
If a durability step reports failure, the next target operation is forbidden.
This relies on the local OS/filesystem durability contract, not protection against
hardware failure, dishonest storage or malicious same-user state tampering.

Per-item lifecycle:

```text
Planned -> Started -> Succeeded | Skipped | Failed | Unknown
```

`Started` must be confirmed durable before entering the native action boundary.
Intent failure means no native call for that item. If the outcome cannot be
confirmed durable after a call, stop the batch and disclose ambiguity.
Preserve prior completed items; do not replace them with a batch-wide failure.

On a locked, read-only reopen, committed `Started` is presented as `Unknown`;
unstarted `Planned` is presented as skipped. Neither is retried. This
interpretation does not rewrite history or imply that a crash caused no effect.
Leftover `.pending` and `.next` snapshots are explicitly listed, never replayed,
and block new executions until investigated/archived. A valid conservative
`.pending` receipt takes precedence over `.json`, preserving prior completed
items while reporting the affected outcome as unconfirmed. Damaged pending
evidence is an explicit read error, not a reason to trust an optimistic `.json`.

Unsupported schemas, malformed/oversized records and inconsistent native/display
paths are errors. Limits are 32 items and 1 MiB per record, 1024 committed records
and a 16 MiB aggregate read budget. Hitting a limit requires explicit archival;
there is no automatic eviction or cleanup of ambiguous records.

`receipt --json` is the local export surface. Records contain sensitive file
paths, identities, sizes and possible Trash locations; do not upload them
automatically or include them in public issues. Retention is explicit/manual:
keep original records during investigation and archive completed records only
while no execution is using the store. Preserve pending evidence together with
its operation; never delete a marker or copy only an optimistic `.json` to make
an uncertain operation look successful. Archived records are not executable plans.

## Outcome and recovery

Native success requires evidence of the approved file identity at the returned
Trash destination. Missing or inconsistent post-call evidence is `Unknown` and
stops the batch. System-reported failure is distinct from refusal before the call.
No timeout is interpreted as proof that an effect did not happen.

Source admission and post-effect verification are distinct policies: the system
may add `com.apple.macl` during Trash. Only post-effect verification accommodates
that established metadata change; source restrictions and unknown/cloud/resource-
fork refusals remain in force. Attributes are never removed to make a check pass.

Ambiguous outcomes preserve structured `recovery_evidence`: the approved native
identity/measurement, Foundation's returned path explicitly marked unverified,
available identity/path observations from the retained source descriptor, and
errors for unavailable observations. Journal and CLI retain these hints without
turning them into verified destinations, success, or restore authorization.
Records without this optional field remain readable. Readers that do not
recognize a newer field must refuse it, never interpret it as approval.

A recorded Trash location is evidence, not a permanent recovery capability.
Another application or user can empty/move Trash entries. There is no automatic
restore command in this slice and no overwriting a conflicting original path.
Handled logical bytes sum the approved measurements for identities whose move
was verified. They are not a fresh destination measurement, an assertion that
another process cannot change the file, or reclaimed space. A trashed file still
occupies storage.

## Validation and acceptance

Default tests use synthetic private fixtures, fake effects, and journal fault
injection. They cover exact approval, stale identities, expiry/cancellation at
the native boundary, intent/outcome failures, ambiguous results, process exit,
record corruption and no automatic replay. CLI checks must never call real
Trash merely to test confirmation or output.

Real system Trash/recovery tests require explicit opt-in and precise
object-specific cleanup. If verified restoration cannot be guaranteed, use a
dedicated account or disposable VM. Never empty Trash or find cleanup targets by
name/glob. A mocked move does not establish native acceptance. Windows execution,
other volume types and untested OS versions are not certified by macOS tests.

The actual one-file system case is registered but ignored by default:

```sh
SAYAKA_M3_TRASH_TEST=1 SAYAKA_M3_TRASH_TEST_QUIESCENT=1 \
  cargo test -p sayaka-platform-macos --locked \
  trash::native::tests::real_foundation_trash_owned_fixture_round_trip \
  -- --ignored --exact --nocapture --test-threads=1
```

Set the quiescence confirmation only after assuring that no other tool will
move or empty Trash during this case. Do not run all ignored tests. Prechecks
require Foundation-discovered existing Trash, same-device internal APFS, private
user-owned recovery directories with no ACL entries granting access, no-follow ancestry, and a
successful no-overwrite preflight. Failure is **blocked before the Trash call**,
not a passing native test. The test permits empty or deny-only recovery ACLs;
allow entries, unknown tags and unreadable ACL evidence refuse. Exact ACL
stability and an actual no-overwrite preflight are still required. This does not
change the production journal's stricter no-extended-ACL policy. Never change
the user's Trash permissions to pass.

The case creates one marked synthetic file, retains its identity, verifies the
returned destination, restores only that object without overwrite and verifies
contents before exact cleanup. Ambiguity after a call preserves recovery evidence
instead of searching or deleting guessed Trash entries.

The first authorized local invocation was blocked by an overly restrictive
empty-ACL recovery precheck before any Foundation Trash call. The test now
distinguishes non-granting deny-only entries without modifying host permissions.
Native Trash/recovery acceptance requires an actual completed roundtrip, not
merely passing default checks or compiling this system test.

The corrected one-file roundtrip passed on local internal APFS, macOS 26.6.2
arm64, with Rust 1.93.1. It verified the returned identity, restored without
overwrite and completed exact fixture cleanup. This evidence covers that narrow
native case and host, not Windows, every macOS version, or broader maintenance
actions. No Trash permission changes or directory-wide cleanup were performed.

## Native references

- [Foundation Trash](https://developer.apple.com/documentation/foundation/filemanager/trashitem(at:resultingitemurl:))
- [File coordinators](https://developer.apple.com/documentation/foundation/nsfilecoordinator)
- [Apple rename manual](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/man/man2/rename.2)

The implementation is original; reference-product code is not copied into the
MPL-2.0 core.
