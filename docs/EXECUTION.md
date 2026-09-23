# Explicit native Trash

M3 is a narrow, user-initiated ordinary-file workflow, not general cleaning.
Scanning and M1 planning remain read-only. Native Trash/recovery environment
acceptance is separate from default model, journal and admission checks.
Plain file, rule-bound clean and installer selection frontends now use this
shared executor. Controlled local native evidence includes
[installer CLI single/batch round trips](INSTALLER_PREVIEW.md#recorded-native-acceptance);
that does not certify every frontend/environment or provide a general restore
command. Windows effects and directory execution remain unavailable.

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

The [directory-action foundation](DIRECTORY_ACTIONS.md) is a separate read-only
assessment and unapproved contract discussion. It always remains ModelOnly,
cannot enter this executor as a plan, and does not lift the directory exclusion
above. Stable directory identity does not imply stable descendant contents.

## CLI

```sh
sayaka clean .
sayaka clean . --filter module
sayaka clean . --execute
sayaka clean exclusions list .
sayaka clean exclusions add . ./pkg/__pycache__
sayaka clean exclusions remove . ./pkg/__pycache__
sayaka clean exclusions remove-root .
sayaka installer . --select ./Example.dmg
sayaka installer . --select ./Example.dmg --json
sayaka installer . --execute
sayaka trash --scope . ./file.txt
sayaka trash --scope . ./file.txt --json
sayaka trash --scope . ./file.txt --execute
sayaka rules trash . --rule org.python.cpython.pep3147.source_backed_pyc --select ./pkg/__pycache__/m.cpython-311.pyc
sayaka rules trash . --rule org.python.cpython.pep3147.source_backed_pyc --select ./pkg/__pycache__/m.cpython-311.pyc --json
sayaka rules trash . --rule org.python.cpython.pep3147.source_backed_pyc --select ./pkg/__pycache__/m.cpython-311.pyc --execute
sayaka rules trash . --rule org.openjdk.javac.source_backed_class --select ./Foo.class
sayaka rules trash . --rule org.openjdk.javac.source_backed_class --select ./Foo.class --json
sayaka rules trash . --rule org.openjdk.javac.source_backed_class --select ./Foo.class --execute
sayaka receipt --json
```

Use existing physical paths; replace the example filename. `rules trash` requires
an explicit root, `--rule`, and one or more explicit `--select` files (max 32);
it never imports `rules preview --json` and never broadens to additional
candidates after selection. `..` traversal is
rejected, not normalized into another allowed selection. Exclusions are
repeatable with `--exclude PATH`; lexical overlap and native identity/ancestry
checks prevent differently spelled filesystem aliases from bypassing an
exclusion. ASCII case-overlap exclusions are deliberately conservative even on
case-sensitive volumes. Unverifiable exclusion evidence aborts instead of permitting effects.
Excluded/refused entries are shown separately.

`clean` defaults to source-backed CPython `__pycache__` `.pyc` entries and
accepts explicit `--rule` for other built-in rules (for example
`org.openjdk.javac.source_backed_class`). It always starts with a read-only
preview. `--filter` only narrows the display list and does not change policy. `--execute` requires terminal stdin,
stdout, and stderr; without explicit `--select`, it prompts for bounded numeric
selection and then requires the exact `trash N` phrase. There is no implicit
"all selected" execution path. The engine seals the exact native execution plan
before asking for `trash N`; approval is bound to that sealed plan and to the
captured clean policy snapshot.

`clean exclusions` uses a separate strict config file (`exclusions-v1.json`) in
the Sayaka config directory (`$SAYAKA_CONFIG_DIR`, else `$XDG_CONFIG_HOME/sayaka`,
else `$HOME/.config/sayaka`; override with `--config-dir`). This config is
clean-only and is not read by `trash`, `rules trash`, or `browse`. Missing
exclusion entries are reported as `needs_attention`; they block `clean --execute`
until removed or repaired with explicit management commands.

`installer` adds a narrower selection frontend over the same ordinary-file
executor. It requires complete discovery, recognized UDIF/flat-PKG structure,
current-user single-link files, private inspection-to-native witness matching,
and a sealed plan before exact confirmation. A native refusal prevents approval
of the whole installer batch. Its explicit exclusions are retained native
protections; it does not import clean policy or classify installation state.
Default preview JSON remains unchanged; explicit selection has a separate
read-only action envelope. See [installer files](INSTALLER_PREVIEW.md).
Installer outcomes reuse ordinary-file records; recognition is not a durable
rule authorization, and no new journal/schema or recovery guarantee is implied.

The native bindings expose the project-artifact purge frontend as an asynchronous
C ABI in `sayaka_purge_*_v1`; see [BINDINGS.md](BINDINGS.md#purge-preview-and-revalidated-trash-execution).
Preview accepts one explicit security-scoped root supplied by the host and the
same staleness option as the CLI. It returns marker-bound artifact candidates
grouped by project with lossless scan `NativePath` JSON, null for unknown sizes,
reasons/evidence, stable preview-scoped item references and a SHA-256
`plan_digest`. Execution requires that preview handle, the exact digest, a
nonempty unique subset of item ids and an explicit approval token
`purge N artifacts`. The binding prepares the existing engine `PurgeSession`
from that subset, revalidates identity/ancestry/marker evidence, journals through
`Store` as the CLI does, and moves only through the native Trash contract
`revalidated_purge_trash_v1`.

The same preview surface now has an additive `developer_caches` profile for the
Mac App Store sandbox flow. It scans only the explicit user-granted root and
reports documented rebuildable developer-tool cache locations at or below that
root (Xcode DerivedData/cache/CoreSimulator cache, npm/pnpm/Yarn/pip/Cargo/
Gradle caches and Homebrew downloads). Complete, cleanup-supported candidates
can enter the distinct `revalidated_cache_trash_v1` contract through
`sayaka_purge_execute_start_v1` with the exact same-preview item references,
plan digest, absolute journal state directory and approval token
`trash N caches`. It never targets Xcode Archives, CoreSimulator Devices,
installed products, simulator/app user data, package-manager configuration/logs,
or Homebrew Cellar entries. External-command operations such as `brew cleanup`,
`xcrun simctl delete unavailable`, package-manager cache-clean commands and
Gradle daemon/cache commands are still reported as unsupported with reasons and
are not emulated by the App.

`revalidated_cache_trash_v1` revalidates each approved cache before approval and
again immediately before its native call: the target must still be the same
device/inode directory observed in the preview, still a real directory rather
than a symlink, still exactly the recognized documented cache path under the
effective `getpwuid_r` home, and still cleanup-supported (activity lock files or
other profile refusal evidence fail closed). Trash is the only effect; if the
Foundation Trash call fails, the item fails and Sayaka never retries with
permanent deletion. The journal record reuses schema 5. The same residual final
pathname/ancestor replacement race disclosed above remains present for cache
directories.

FFI execution never imports approval from JSON, broadens a subset, silently
selects all candidates or falls back to permanent deletion. Unknown, changed,
missing, not-revalidated, cancelled, policy-refused and journal-ambiguous items
are reported per item as skipped/failed/unknown; unknown is never reported as
success. Every execution item carries the selected preview `id` plus
`reference: {preview_handle, item_id}` and emits `path`/`destination` in the same
lossless scan `NativePath` shape as preview (`display`, hex `encoding`, `raw`);
the journal's durable native-byte receipt is not changed. Whole-batch native
preparation or approval revalidation refusal is still a successful API result:
the bounded `purge_execution` envelope has `status: "refused"`,
`effects_performed: false`, `error.reason`, and skipped per-selected-item
statuses with no destinations. The same residual final pathname/ancestor
replacement race disclosed above remains present for the App: a different object
can still be moved if a file or ancestor is replaced after the final check and
before Foundation's Trash operation takes effect.

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

Each operation has a schema-versioned JSON record. Legacy explicit-file records
(`schema_version:1`, `plan_schema_version:2`, `engine_version:2`, `rules_version:1`)
remain readable unchanged. Rule-bound records use
`schema_version:2`, `plan_schema_version:3`, `engine_version:2`, `rules_version:2`
and require complete per-item rule binding evidence (rule id/version/ruleset
revision/semantics digest, selected root/exclusions, target/source/root/ancestor
witnesses). Supported tuples currently include CPython source-backed `.pyc`
(historical ruleset r2 and current r3) and OpenJDK `javac` source-backed
same-directory `.class` (ruleset r3). Unknown tuples, missing/malformed bindings, and mismatched
target/source identities are rejected.
Clean executions use `schema_version:3` with the same plan/rules tuple and must
include a clean policy context record (policy file state witness, selected root
identity, and effective exclusions). Missing or malformed clean policy context
is rejected.
Before publishing an update,
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
may add `com.apple.macl` during Trash. During the initial destination metadata
and ACL observation, verification tolerates bounded ctime settling only. After
that capture anchor is established, later held-handle checks and final
revalidation require full target equality again (including ctime), while still
requiring stable identity, mode, uid/gid, nlink, logical size, allocated
blocks, flags, created time, modified time, and ACL consistency. Source
restrictions and unknown/cloud/resource-
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

### Historical native failures and later scoped evidence

An earlier authorized invocation failed **before any
effect** because the fixture root was created in system temp (hidden/protected
path class). Native cases now use non-hidden project-owned fixtures; the
rule-bound case uses `<repo>/crates/engine/target/native-test-fixtures`, and
other registered cases have their own explicit fixture locations.

A subsequent authorized invocation reached Foundation and returned an
`Unknown` outcome because destination verification observed a metadata transition
during ACL capture (`object safety changed during ACL capture`). Recovery
evidence preserved exact returned path and approved/held identities; parent
performed explicit identity-checked no-overwrite restore and fixture cleanup.
That record did not include per-field deltas, so the exact changed field(s) are
not known from that run alone. Default deterministic no-effect tests now
reproduce and bound the ACL-window assumption used by post-move verification.
That historical attempt remains an Unknown outcome with an unresolved exact
metadata-transition cause, not a retroactively passing run.

The later independently authorized installer CLI acceptance recorded three
successful owned-file moves, receipts, exclusive-restore conflict checks and
restores. Its [sanitized evidence and limitations](INSTALLER_PREVIEW.md#recorded-native-acceptance)
are separate from these earlier failures. It closes only that local synthetic
installer slice, not all platforms, real downloads or arbitrary recovery.
No historical or completed test authorization carries forward to a new run.

## Native references

- [Foundation Trash](https://developer.apple.com/documentation/foundation/filemanager/trashitem(at:resultingitemurl:))
- [File coordinators](https://developer.apple.com/documentation/foundation/nsfilecoordinator)
- [Apple rename manual](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/man/man2/rename.2)

The implementation is original; reference-product code is not copied into the
MPL-2.0 core.
