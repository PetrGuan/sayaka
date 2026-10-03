# Explicit picked-file Trash binding

The `sayaka_picked_*_v1` companion ABI exposes the existing engine-owned
`revalidated_trash_v1` session for **1–32 explicitly selected regular files**
under one authorized root. It performs no recursive discovery or expansion.
Directories, packages/package contents, symlinks, hard-linked files, cloud or
unverifiable resources remain refused by the native boundary. Directory cache
and project-artifact removal continue to use their specialized purge contracts;
this API does not label an arbitrary selected file as a recreatable cache.

This v1 supports the regular-file portion of installer, largest-file and AI-log
cleanup. It does not authorize arbitrary directory cleanup, AI conversations,
credentials, generated user work, permanent deletion, or privilege escalation.
The host must restrict any product-specific categories further and obtain a
fresh explicit selection/confirmation; tool attribution is not consent.

## Lifecycle and wire contract

1. Start a preview with `SayakaPickedPreviewRequestV1`: ABI/version/size,
   absolute native root, copied native path array (1–32), mandatory application
   policy directory and zero reserved field. Relative/traversal paths, roots as
   targets, duplicate paths and targets outside the root are invalid. Start
   returns an opaque monotonically allocated handle counted in the shared
   four-task budget. Inputs may be freed when the call returns.
2. Hold sandbox/security access for the root through terminal release. Poll
   `sayaka_picked_result_v1`; it returns `NOT_READY` while a worker is active,
   otherwise follows the usual size-probe/caller-buffer JSON contract (64 MiB).
   Preparation errors return a stable error code; no native effect has occurred.
3. Preview JSON `sayaka.picked_preview` schema 1 includes requested paths,
   retained native dev/inode identity, logical size, explicit-selection reason,
   `user_file_not_assumed_recreatable` risk, refusals/issues, `execution_eligible`,
   expiration and the exact approval token. No effects occur. Any refusal,
   incomplete selection or policy attention blocks the **entire** selection.
4. After showing the exact selection and obtaining confirmation, echo its token
   to `sayaka_picked_execute_v1` with a mandatory safe journal directory. This
   consumes the retained session exactly once and starts asynchronous execution.
   It never accepts imported JSON/identity claims. A changed subset needs a new
   preview. Tokens include the opaque preview handle and count, so another
   live preview's token is not interchangeable. Preview lifetime is the native
   session's 120 seconds; expired plans require a fresh preview.
5. Poll the same handle for `sayaka.picked_execution`. `OK` from execute means
   started, not moved. `refused` means no native effect; `finished` means the
   returned operation report is terminal, **not that all items succeeded**.
   Inspect every report item (`succeeded`, `skipped`, `failed`, `unknown`) and
   journal errors. Unknown results must not be blindly retried.
6. Cancel is monotonic and can be called concurrently while execution runs.
   Release requests cancellation and returns `BUSY` until owned work joins;
   retain the handle and access scopes and retry. Released handles cannot be
   reused. Cancellation/refusal never falls back to permanent deletion.

The policy snapshot is identity-bound and checked again during execution by the
existing per-effect policy guard. Policy storage is protected from selection;
selected files cannot reside within the operation journal directory. Native
candidate handles are retained from preview through execution, preserving
no-follow opens, confinement, identity/metadata revalidation, platform Trash
recovery and per-item journal evidence. The existing last-check/path-replacement
race remains: **this is not race-free**, and Trash does not guarantee Put Back
or prove freed disk space. A caller must not treat preview JSON as execution
authority or generate approvals automatically on scan completion.

## Validation boundary

The implementation is governed by the Cleaner owner's no-agent-unit/UI-test
policy. Source fixtures cover input caps, traversal/confinement/duplicates and a
read-only native identity/size/risk preview. They may be compiled but are not
executed by agents. Existing native Trash session tests remain the underlying
contract fixtures; owner validation should additionally cover replacement,
policy changes, cancellation, journal failure and replay in owned disposable
folders. No real user files or privileged helper are used for validation.
