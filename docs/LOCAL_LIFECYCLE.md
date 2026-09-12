# History, completion and local installation

This initial T12 slice makes the existing CLI easier to use without introducing
downloads, online updates, signing claims, authentication changes or a daemon.
Local installation is initially macOS-only. Windows installation, launchers,
stable/nightly distribution and Touch ID remain separate work.

## Read-only history

```sh
sayaka history
sayaka history --state unknown --state failed --json
sayaka history --since 2026-09-01T00:00:00Z --until 2026-10-01T00:00:00Z
sayaka history --limit 20 --offset 20
```

`--id` matches an exact operation ID. Repeated state filters use OR; an operation
matches if any item has the requested terminal state, but the whole operation
is retained so mixed outcomes and recovery evidence are not hidden.

Creation-time boundaries require RFC3339 with an explicit offset. `since` is
inclusive and `until` exclusive. Sub-millisecond boundaries are rounded upward
to the next representable journal millisecond, preserving the comparisons.
Nonzero digits beyond the date parser's nanosecond precision are retained for
that rounding decision rather than silently truncated away.
Human dates use UTC; values outside the formatter range retain their exact
numeric epoch milliseconds rather than an invented date.

Ordering is newest creation time first, with operation-ID ordering for ties.
The default page limit is 20, maximum 1024; offset is bounded by the existing
journal budget. Each invocation queries one locked read snapshot, not a stable
cursor across later modifications.

All stored records are validated and reconciled before filtering. Corruption
outside the requested ID/time range is still an error. Interrupted Started
states remain Unknown. Global `.pending`/`.next` warnings are never filtered or
paginated away, and make the read return a partial-status exit code.
Nothing is replayed, restored, erased or reclassified as success.

`history --json` emits a versioned envelope with total/matched counts, page
parameters, complete selected records and store-wide uncommitted evidence.
The existing `receipt` JSON contract is unchanged. Both use `--state-dir DIR`
or the existing default journal location; neither creates missing history.

## Completion

```sh
sayaka completions zsh
sayaka completions bash
sayaka completions fish
```

PowerShell and Elvish are also supported by the generator. Scripts are generated
from the actual Clap command tree, including aliases/options, and written only
to stdout. They are not automatically sourced or installed. No shell startup
file or PATH value is edited. Follow the chosen shell's completion setup
procedure when saving or sourcing a generated script.

Completion support does not imply that every native command is implemented on
every shell's host operating system.

## Dedicated prefix

The default local prefix is `~/.local/share/sayaka`, with the executable under
`bin/sayaka` and versioned ownership metadata. A custom `--prefix DIR` must also
be a dedicated physical directory, not a shared bin directory.

Before the command is installed, build and preview from the source checkout:

```sh
cargo build -p sayaka-cli --release --locked
mkdir -p "$HOME/.local/share"
./target/release/sayaka install
```

The directory-creation command above is an explicit user setup step, not a hidden
installer action. Add `--execute` only after checking the preview.

```sh
sayaka install
sayaka install --execute
sayaka update
sayaka update --execute
sayaka recover
sayaka recover --execute
sayaka remove
sayaka remove --execute
```

Without `--execute`, these commands inspect and preview only. `--json` provides
one preview or result envelope. Installation copies the running program's
**on-disk executable**, never fetches code. This is a locally trusted input,
not a signature, publisher authentication or online-release verification.

The prefix's physical parent must already exist. For the default location, a
user may prepare it with `mkdir -p "$HOME/.local/share"` if needed. The installer
does not silently create shared ancestors, follow symlinks or change permissions
on existing directories.

The layout is private and ownership-checked. Source identity/content are checked
across bounded SHA-256 copying. A complete staged layout is synchronized before
no-replace publication. Unknown or conflicting existing prefixes are refused;
verified identical installations can be reported without replacing files.
`update` uses only the explicitly running local executable as candidate input.
Execution requires verifiable Mach-O target metadata for the running candidate;
non-Mach-O compatibility guessing is refused.
No URL/download source, publisher authentication claim, or automatic rollback is
performed. Downgrade and same-version/different-hash replacement are refused by
default and require explicit policy flags:

```sh
sayaka update --allow-downgrade --execute
sayaka update --allow-same-version-replace --execute
```

`recover` is explicit and lock-preserving: it inspects one versioned lifecycle
record path under the prefix parent, revalidates current/candidate identities,
binds staged executable/manifest evidence by exact descriptor identity, mode,
size, and SHA-256 digest before any unlink/rename,
and either abandons pre-commit staging or finalizes/records post-commit update
outcome. Unknown or ambiguous evidence fails closed with exact paths.
An explicit execution retry also revalidates and synchronizes the owned package,
its directories and its parent before returning already-installed. A visible
prefix alone is not proof that a previous failed publication became durable;
unconfirmed synchronization retains an incomplete result and exact recovery path.

Pending or malformed lifecycle sidecar evidence blocks `install` and `remove`
before any filesystem mutation, including when the managed prefix is currently
absent. This prevents orphaning in-progress update evidence by reusing the same
prefix name. Historical completed sidecars (`outcome_recorded`) are tolerated
for future remove/reinstall so they do not permanently poison the prefix name.
Interop note: old v1 clients do not read parent-side lifecycle sidecars, so
cross-version safety still depends on shared lock discipline during live
operations and on v2 inventory checks inside the managed prefix.

After a successful install, the user can add the verified `bin` directory to
PATH manually. For the default prefix, that directory is
`$HOME/.local/share/sayaka/bin`. A custom prefix is displayed as a native path,
not as executable shell text; diagnostic path escaping is not shell quoting.

## Removal and interruption

Removal is restricted to the fixed managed package layout. Native identities,
hashes, owner/mode/ACLs, links and unexpected entries are checked before effects.
Unrecognized, replaced, modified or additional files cause refusal, not a broader
delete. There is no recursive removal of arbitrary user paths or elevation.

The managed prefix must be quiescent except for cooperating locked Sayaka
operations. These checks do not claim atomic protection against hostile
same-user namespace modification after a check. Observed changes are rejected.
An ownership manifest is local bookkeeping, not cryptographic authorization
against the user who owns and can rewrite it.

Incomplete staging, update, recovery, or removal reports exact recovery
locations and errors.
Do not discover recovery targets by glob or treat a matching name as ownership.
No failed operation silently retries, deletes unknown leftovers or claims a
completed removal. A crash may require explicit inspection/manual cleanup of
retained owned staging evidence; this is not a transactional filesystem undo.

The journal and other user state are outside the managed package and are
preserved. The installer does not create or remove operation history, shell
configuration, native application data or other software's executables.

Reported footprint covers the known regular files in this installation profile,
with logical and known allocated bytes kept separate. It does not establish a
complete filesystem-overhead total or superiority over Mole's full distribution.

## Validation

Tests use unique marked temporary prefixes, not the actual default installation.
They cover copy/hash/identity integrity, non-overwrite conflicts, modified and
unowned entries, symlinks/hardlinks/permissions, cancellation/partial failure,
history preservation and execution of the installed fixture binary.
History cases cover pending precedence, corruption outside filters, time bounds
and pagination; completion cases check the actual command tree.

No online release, signature, authentication change or real-user installation
is performed as part of these default checks.

An additional release-profile check uses only a temporary prefix, verifies the
copied binary and fixed-file footprint, rejects an added unowned entry, invokes
self-removal from the installed binary, and checks unrelated state preservation:

```sh
cargo build -p sayaka-cli --release --locked
python3 scripts/check_local_install.py
```

Its measured regular-file totals are local profile evidence, not a full Mole
installation comparison or a claim that filesystem directory overhead is known.
