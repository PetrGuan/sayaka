<!-- SPDX-License-Identifier: MPL-2.0 -->

# Installer files: bounded preview and explicit Trash

`sayaka installer ROOT` performs explicit-root discovery of existing ordinary
`.dmg` and `.pkg` filenames and inspects only bounded structural bytes:

- `.dmg`: final 512-byte UDIF `koly` footer checks only.
- `.pkg`: XAR header + bounded compressed TOC + bounded XML descriptor hints.

## Safety and non-goals

- No mount/attach/install/execute operations.
- No payload/Bom/Scripts/PackageInfo body extraction.
- No signature trust, certificate, notarization, or receipt/install-state checks.
- No quarantine/origin/provenance attribute reads in this slice (`not_read`).

These statements describe discovery. Explicit native admission additionally
uses the existing bounded extended-attribute **name** allowlist and ACL/metadata
checks; it does not read provenance/quarantine values or assess their trust.

## Explicit selection and approval

Default `installer ROOT` and `installer ROOT --json` keep the read-only v1
`installer_preview` contract. No target or journal is changed by discovery,
selection, native admission, or cancellation before confirmation.

```sh
sayaka installer ./Downloads
sayaka installer ./Downloads --select ./Downloads/Example.dmg
sayaka installer ./Downloads --select ./Downloads/Example.dmg --json
sayaka installer ./Downloads --execute
sayaka installer ./Downloads --select ./Downloads/Example.dmg --execute
sayaka receipt --json
```

The initial macOS action slice admits only explicitly selected current-user,
single-link ordinary files with recognized UDIF DMG or flat-PKG XAR structure.
Recognition is **not** a signature, safety, disposability, download-completion,
or not-in-use assertion. Corrupt/unsupported/unknown candidates remain visible
but cannot enter this action flow. Incomplete, failed, cancelled or changed
discovery cannot authorize a batch. Filters and explicit exclusions narrow the
current selectable set. Clean's separate persisted exclusions are not inherited.

`--select PATH` is repeatable, bounded to 32 distinct current candidates, and
rejects parent traversal, out-of-set targets and duplicates. Without `--select`,
`--execute` offers a bounded comma/range numeric chooser; blank lines or empty
EOF cancel. Ctrl-C also cancels while waiting at either prompt without requiring
another Enter. Terminal input remains in cooked mode and does not read ahead
into the next prompt.
It never chooses all candidates automatically. A truncated/overlong selection
line is rejected instead of accepting its prefix.

Execution requires terminal stdin, stdout and stderr. A native plan is sealed
before the exact `trash N` confirmation. Any native refusal blocks approval
of the **whole** installer batch; it does not silently execute an eligible
subset. `--json --execute`, `--yes`, piped approval and imported JSON approval
are unsupported. `--state-dir DIR` selects the existing private journal location;
it is opened/created only after confirmation and successful approval.
The menu exposes preview first and a separate installer approval entry using
the same CLI, and completions follow that command definition.

## Identity and execution binding

Successful inspection retains private metadata witnesses, not hundreds of open
candidate descriptors. The engine verifies the original complete-preview
context, the selected path and format, and the retained native target/root/
ancestor witnesses when preparing `InstallerSession`. Changing public display
fields cannot create a successful inspection witness.

Target identity, size, owner/group, mode, flags, link count and native timestamps
must still match. Directory identity and safety metadata must match; unrelated
sibling directory-content timestamps are not approval inputs. The native plan
retains descriptors and protections, rechecks before approval and before the
effect, and never refreshes to replacement targets. Explicit exclusions become
native protections, including checks after confirmation.

The existing [revalidated Trash contract](EXECUTION.md) still applies, including
the residual replacement race after the final pathname check. Use only stable
files not being modified by other applications. There is no directory action,
mount/install, elevation, permanent-delete fallback, automatic retry or
guaranteed restore. A file's logical size is not freed disk space.

The ordinary-file journal/receipt schema is reused unchanged: it records target
identities and per-item outcomes, not an installer trust assessment or an
offline/replayable format approval. Durable intent precedes effects; later
changes, cancellation and failures preserve skipped/failed/unknown outcomes
through the existing executor. Unknown outcomes are never replayed.

## Action preview output and validation scope

Installer leaf opens and reopens use no-follow plus nonblocking flags. A scanned
regular file replaced by a writerless FIFO is refused by its metadata rather
than blocking before the kind/identity check. This does not promise a universal
deadline for arbitrary OS storage I/O.

Only explicit `--select --json` uses a separate v1 `installer_trash_preview`
envelope with `discovery`, requested paths, the existing native Trash `plan`,
and `effects_performed: false`. A ready plan is still awaiting interactive
confirmation, not an executed operation. Incomplete discovery returns a refused
action envelope; invalid selections are structured input errors.

Exit codes follow existing CLI conventions: 0 for a complete read-only result
or completed eligible execution; 2 for invalid arguments/selection/TTY; 3 for
incomplete discovery or refused native batch; 130 for cancellation; 1 for
operational/storage failures or ambiguous outcomes.

Default validation covers owned-fixture inspection/admission, stale identities,
same-size content changes, root/ancestor/protection changes, refusal of partial
batches, and a PTY selection/confirmation-cancellation flow. The only new
executor integration invocation is cancelled before any native effect and
checks the skipped receipt. Shared executor fault tests cover intent/outcome
failures and unknown results. A real installer-file Trash round trip still
requires separate explicit native-system authorization; it is not claimed by
these no-effect checks.

## Recorded native acceptance

A separately authorized local macOS arm64/internal-APFS run exercised the
actual release CLI from `6a499555f66923b55ac7313d32ac9c562a15fa05`
(SHA-256 `f4e8a28c1b6d7055b48957e0ce1dee278520bb891fc8d96526d8336c04adbba8`).
The [sanitized native record](../benchmarks/results/installer-cli-native-roundtrip-v1.json)
binds the helper, runner and private evidence hashes without publishing host
paths, user identities or receipt contents.

| Case | Selection | Actual Trash / restored | Exclusive restore conflicts |
| --- | --- | ---: | ---: |
| Synthetic recognized UDIF | Explicit path | 1 / 1 | 1 EEXIST, both objects preserved |
| Fresh synthetic UDIF + flat-PKG | Numeric chooser | 2 / 2 | 2 EEXIST, both objects preserved |

All three receipts were succeeded with no pending snapshots. Retained original
identities, ACLs and full synthetic contents matched at the returned/restored
locations; both non-target sentinels stayed unchanged. The successful run's
registered fixture was cleaned and its three exact former Trash names were
absent afterward. Only those registered identities/returned names were used;
the Trash directory's contents were never enumerated or globally audited.
The 4,194 logical bytes are handled fixture bytes, not measured freed space.

An earlier attempt stopped after read-only preview with zero mutating intents
because of a tool process-group signalling issue. Its source identity/content
and empty journal were verified, and its inactive fixture/evidence were retained.
After a live-broker fix, fresh review and renewed authorization/quiescence, the
successful run above was performed once. No unknown result was retried.

These are inert structural fixtures, not proof of mountability, installability,
trust or suitability of real downloads. This closes only this local controlled
installer CLI round-trip slice; Windows, arbitrary accounts/volumes, directory
actions and general recovery guarantees remain unaccepted. The residual final
pathname race and explicit opt-in requirements still apply to every future run.

## Frozen limits

- Candidate paths: 512
- DMG footer read: exactly 512 bytes
- XAR TOC: 4 MiB compressed, 16 MiB expanded (per file)
- XML: depth 32, nodes 50,000, retained name/text bytes 1 MiB
- Aggregate candidate I/O: 64 MiB
- Aggregate expanded TOC bytes: 128 MiB
- Combined scan + inspection budget: 30 seconds

When limits/cancellation/freshness checks trigger, status is partial/cancelled
and retained evidence is reported without claiming success.

## Dependency/license notes

This slice uses:

- `flate2` (MIT/Apache-2.0) for bounded zlib decoding
- `quick-xml` (MIT) for streaming XML parsing
- `nix` (MIT, already used transitively) for safe, cancellable Unix terminal
  readiness checks; unlike Darwin `poll`, `select` also supports `/dev/tty`.

The implementation is original Rust code under MPL-2.0 and does not copy Apple
or third-party parser code/prose.

## Reference provenance (facts, not copied implementation)

- XAR header/TOC format facts: Apple OSS XAR public sources and license:
  - https://raw.githubusercontent.com/apple-oss-distributions/xar/main/xar/include/xar.h.in
  - https://raw.githubusercontent.com/apple-oss-distributions/xar/main/xar/lib/archive.c
  - https://raw.githubusercontent.com/apple-oss-distributions/xar/main/xar/LICENSE
- UDIF trailer field facts in this slice are based on public reverse-engineered
  references (non-Apple-primary), currently libyal/libmodi documentation:
  - https://raw.githubusercontent.com/libyal/libmodi/main/documentation/Mac%20OS%20disk%20image%20types.asciidoc

This command reports bounded structural evidence only. It does **not** prove a
DMG is mountable or a PKG is installable/authentic.
