# Sayaka

An open-source local maintenance engine and CLI, targeting macOS and Windows.

**Status: bounded scanning, read-only rules preview, macOS native Trash, and an initial terminal browser.** macOS and
initial Windows local fixed-NTFS scanning support explicit roots, bounded resources,
cancellation and structured output. See [Windows scope and native evidence](docs/WINDOWS.md)
for remaining acceptance gates and platform differences. The
in-memory core supports plans, exact-preview approval and read-only preflight.
Scanning never modifies files. The separate `trash` command previews explicitly
selected ordinary files; `--execute` additionally requires terminal confirmation.
This native action uses a [revalidation contract](docs/EXECUTION.md), not an
atomic guarantee against path replacement. It records durable per-item intent
and results. Broad cleaning, uninstall, Windows execution and bindings remain
unimplemented. Native Trash/recovery acceptance is a separate opt-in gate.

An initial [terminal disk browser](docs/BROWSING.md) adds directory summaries,
navigation, filtering, multiselect and exact M3 preview/confirmation:

```sh
sayaka browse .
sayaka browse . --plain
```

The root must be explicit. Browsing and selecting do not modify files; directories
remain read-only. Non-terminal output automatically uses the plain snapshot report.

The initial [read-only system status](docs/STATUS.md) command adds native metrics,
explicit freshness/error states and a bounded watch process:

```sh
sayaka status --json
sayaka status --watch
sayaka status --watch --json --count 12
```

Status never optimizes the system or installs a daemon. Unsupported temperature,
GPU and top-process capabilities are marked explicitly, not filled with zeroes.

Initial [local CLI lifecycle tools](docs/LOCAL_LIFECYCLE.md) provide filtered
`history`, generated `completions`, and preview-first `install` / `remove` for a
dedicated user prefix. They do not download updates, edit shell startup files
or remove operation history.

## Direction

Sayaka aims to make local maintenance explainable, previewable, and auditable:

```text
scan -> findings -> plan -> user approval -> execute -> journal
```

The planned open-source scope includes the Rust engine, rules, platform execution
adapters, operation protocol, and a full maintenance CLI. Native graphical clients such as
SayakaCleaner are separate projects and are not included in this repository.

Safety checks, basic previews, and operation records belong in the shared core,
not behind a paid feature gate. Platform-specific permissions, file identities,
trash behavior, and partial failures must remain explicit. No maintenance action
should require AI or an online account.

## Workspace

| Crate | Purpose |
| --- | --- |
| `sayaka-engine` | In-memory planning, approval, read-only preflight and receipt contracts |
| `sayaka-cli` | Command-line entry point, installed as `sayaka` |
| `sayaka-bindings` | Reserved for native-client bindings; no ABI exported yet |
| `sayaka-platform-macos` | Audited I/O policy, volume metadata and explicit native Trash boundary |
| `sayaka-platform-windows` | Read-only NT handle, volume, identity and directory enumeration boundary |

## Build

Install a current stable Rust toolchain, then run from the repository root:

```sh
cargo build --workspace --locked
```

The executable is written to `target/debug/sayaka` (`sayaka.exe` on Windows).

```sh
cargo run --quiet --locked -p sayaka-cli -- --help
cargo run --quiet --locked -p sayaka-cli -- scan .
```

For a file you explicitly want to inspect for Trash eligibility:

```sh
sayaka trash --scope . ./file.txt
sayaka trash --scope . ./file.txt --json
```

Replace `./file.txt` with an existing ordinary file. These commands only preview.
Adding `--execute` requires an interactive terminal and the exact typed
confirmation shown after the preview. A file or ancestor replaced after the last
check can still cause a different file to be moved. Do not use this on files
being modified by other apps. There is no permanent-delete or elevation fallback.

`sayaka receipt --json` reads local records without retrying interrupted work.
See [execution, state storage, and recovery limits](docs/EXECUTION.md).

Read-only built-in rule discovery currently includes one CPython `__pycache__`
source-backed `.pyc` rule, and explicit rule-bound Trash preview/execute:

```sh
sayaka rules list
sayaka rules list --json
sayaka rules preview . --rule org.python.cpython.pep3147.source_backed_pyc
sayaka rules preview . --rule org.python.cpython.pep3147.source_backed_pyc --json
sayaka rules trash . --rule org.python.cpython.pep3147.source_backed_pyc --select ./pkg/__pycache__/m.cpython-311.pyc
sayaka rules trash . --rule org.python.cpython.pep3147.source_backed_pyc --select ./pkg/__pycache__/m.cpython-311.pyc --json
```

This preview never executes effects. Candidate bytes are observed bytes, not
freed space, and candidate actions remain `preview_only` / `manual_review`.
`rules trash` requires explicit `--select` targets (max 32), keeps metadata-only
source/target rule witnesses in the v3 plan and v2 journal, and still uses the
same exact interactive `trash N` confirmation for `--execute`.

Installer preview (read-only, explicit root only) can distinguish ordinary
`.dmg`/`.pkg` names from bounded structural hints:

```sh
sayaka installer .
sayaka installer . --filter pkg --exclude ./archive --json
```

This command does **not** mount images, execute installers, read payload files,
validate signatures, read quarantine/origin URLs, or check installed receipts.
Results are structural hints only (`udif_koly_footer`, `xar_flat_pkg_manifest_hint`,
`xar_archive_not_pkg`) and may remain unknown/unsupported/corrupt. See
[installer preview contract](docs/INSTALLER_PREVIEW.md).

Application inventory (read-only, explicit roots only) can discover `.app`
bundle candidates with bounded `Contents/Info.plist` metadata and optional
metadata-only executable-path existence checks:

```sh
sayaka apps .
sayaka apps . --json
sayaka apps-related --app-root /Applications --library-root "$HOME/Library"
sayaka apps-related --app-root /Applications --library-root "$HOME/Library" --json
```

This command does **not** launch applications, load bundles, verify signatures,
read receipts/quarantine/user data, or infer uninstall scope. A `.app` suffix
and declared bundle metadata are observations, not trust/install proofs. See
[application inventory contract](docs/APPLICATIONS.md).

`clean` wraps the CPython source-backed rule with persistent clean-only exclusions:

```sh
sayaka clean .
sayaka clean . --execute
sayaka clean exclusions list .
```

Default `clean` is read-only preview (no implicit all-selection). For execution,
the engine seals and displays the exact native plan first, then requires exact
`trash N` confirmation bound to that plan and policy snapshot.

`scan .` scans the current directory and prints a readable terminal report with
sizes, largest files and actionable scan notes. Replace `.` with another
**existing physical directory** when needed. Do not type a placeholder path.
Colors and concise progress are automatic in an interactive terminal; redirected
output stays plain, and `NO_COLOR`, `CLICOLOR=0`, and `TERM=dumb` disable color.

JSON is intended for scripts, not normal interactive reading:

```sh
cargo run --quiet --locked -p sayaka-cli -- scan . --json
```

Package publication is disabled while the public API is being established.
The target platforms are a development goal, not a claim of production readiness.

## Roadmap and development

Start with deterministic contracts and a read-only macOS scanner, then a narrow
approved execution loop. Validate Windows early, before expanding rules, and
stabilize native bindings against both platforms.

The long-term CLI objective is to cover all major Mole CLI capabilities and
demonstrate better usability, faster equivalent work, and a smaller complete
distribution. This is not a claim of current parity or measured superiority.
See the [competitive contract](docs/COMPETITIVE.md) for the pinned comparison
version, capability matrix, and evidence requirements.

See the [roadmap](ROADMAP.md), [core architecture](docs/ARCHITECTURE.md),
[implementation responsibilities](docs/IMPLEMENTATION.md), and
[testing policy](docs/TESTING.md) for dependencies and acceptance gates.
These describe intended work, not currently available features.

Local automated unit, integration, and appropriately isolated system tests are
part of development. M1 validates the model; M2 adds native read-only fixtures,
CLI subprocess checks and a versioned performance fixture. The initial Windows
slice adds native NTFS and CLI fixtures; it does not establish Windows write
support or atomic mutation race guarantees. Default M3 checks
exercise model failures, private journal persistence and read-only native
admission. Real system Trash cases require explicit opt-in.

```sh
cargo test -p sayaka-engine --locked
```

See the [implemented M1 contract](docs/ARCHITECTURE.md#implemented-m1-contract)
for the trusted probe boundary and the distinction between preflight and execution.
See the [scanning contract](docs/SCANNING.md) for limits, JSON/exit semantics,
measurement definitions, native restrictions and benchmark reproduction.

## Contributing

Discuss substantial changes in an issue before implementing them. Keep changes
focused and preserve the boundary between facts, plans, approval, and execution.
Contributions must be original or appropriately licensed; record the provenance
of any third-party code or rules.

Source files use `SPDX-License-Identifier: MPL-2.0`. Contributions to this project
are accepted under MPL-2.0.

## License

Licensed under the [Mozilla Public License 2.0](LICENSE).

MPL-2.0 permits commercial use and combination with separately licensed clients.
When distributing covered software, comply with its source-availability and
notice requirements, including for modifications to covered files. See the
[official FAQ](https://www.mozilla.org/en-US/MPL/2.0/FAQ/) for guidance; the
license text governs.
