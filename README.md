# Sayaka

An open-source local maintenance engine and CLI, targeting macOS and Windows.

**Status: source-built developer preview with working, narrowly scoped CLI
workflows; not a complete maintenance suite or a stable binary release.**
The core supports bounded scanning, exact-plan approval, native macOS
ordinary-file Trash and durable per-item records. Scan and preview commands
never authorize effects by themselves. Native Trash uses a
[revalidation contract](docs/EXECUTION.md), not an atomic guarantee against
path replacement, and always requires explicit selection and confirmation.

## Current capabilities

Status reviewed on 2026-09-16. "Implemented" below refers to the stated scope,
not full Mole parity or support on every target platform.

| Capability | Implemented scope | Remaining boundary |
| --- | --- | --- |
| Scan and directory accounting | Explicit-root bounded scans, cancellation, JSON, hardlink-aware index | Scan coverage is not an atomic filesystem snapshot |
| Terminal interaction | `menu`, `browse` / `analyze`, filtering, navigation, ordinary-file selection and approval entry | Accepted interactive/native-viewing scope is macOS; directories stay read-only |
| Native file Trash and records | Exact plans, explicit confirmation, durable intent/outcomes, `receipt` and `history` | Ordinary single-link files on accepted local internal APFS; no permanent-delete fallback or automatic restoration |
| Rules and `clean` | CPython source-backed `.pyc` and OpenJDK `javac` source-backed `.class`; clean-only persistent exclusions | Two narrow rules, not a broad cache/log/project-artifact cleanup catalog |
| Installer files | Bounded UDIF/flat-PKG discovery, selected native plans and terminal-confirmed file Trash | Recognized current-user files and complete discovery only; no trust/install-state assessment |
| Applications | `apps` inventory, `apps-related` association preview and opt-in running-process attribution | Read-only evidence; no uninstall or related-data removal |
| System status | CPU/memory/network/disk/power/thermal state, IOKit GPU utilization, optional process top, JSON/watch panel | No numeric temperature, Windows sampler or system-maintenance actions |
| Local CLI lifecycle | Dedicated-prefix install/update/recover/remove, shell completion and Raycast/Alfred terminal launchers | Local executable input only; no online updater or authenticated release channel |
| Directory-action foundation | Task-bound engine-only observations, blockers and unresolved native gates | Always ModelOnly; no directory action, executable plan or new CLI |
| Native-client bindings | C ABI for scans/directory queries, bounded diagnostic pages, installer discovery, candidate pages and explicit read-only selection checks; local C/Swift consumers | Installer checks are macOS-only; Windows cross-check is not native host acceptance; no effects/status bindings |

Controlled native evidence includes an
[installer CLI single-file and two-file round trip](docs/INSTALLER_PREVIEW.md#recorded-native-acceptance).
That evidence covers owned synthetic fixtures on the recorded local environment,
not arbitrary recovery or real-download safety. Every future real-Trash
validation still requires fresh opt-in authorization and quiescence.

## Platform and distribution scope

| Platform | Current evidence and limits |
| --- | --- |
| macOS / Apple silicon | Local arm64 evidence for scanning and the implemented macOS workflows. Native Trash is restricted to supported local internal APFS. Minimum OS versions and a broader hardware/release matrix are not yet established. |
| macOS / Intel | No native acceptance claim is recorded here; do not infer it from the macOS implementation. |
| Windows 11+ / x64 | Native read-only local fixed-NTFS scan and CLI evidence on the documented Windows 11 host. This does not cover Windows writes, native status, local installation or all CLI workflows. |
| Windows 11+ / ARM64 | Product target with recorded all-target compilation checks; linked-build/native acceptance remains a follow-up. |
| Other platforms | No native filesystem/maintenance support commitment. Portable models or command parsing do not establish native support. |

See the [Windows contract and exact evidence](docs/WINDOWS.md) and
[macOS scan restrictions](docs/SCANNING.md). A command appearing in `--help`
does not mean its native backend exists on that host. Windows rule catalog/
preview entry points are not evidence of macOS-equivalent native rule inspection.

As of this status review, there are no published GitHub Releases and Cargo
package publication is disabled. Build from source; local `install` and `update`
copy the explicitly running executable, not a download. Binary distribution,
publisher authentication/signing and release channels remain separate work.
The [roadmap](ROADMAP.md) distinguishes implemented slices from those gates.

## Using the implemented workflows

The [terminal disk browser](docs/BROWSING.md) provides directory summaries,
navigation, filtering, multiselect and exact M3 preview/confirmation:

```sh
sayaka menu
sayaka browse .
sayaka browse . --plain
```

The root must be explicit. Browsing and selecting do not modify files; directories
remain read-only. Non-terminal output automatically uses the plain snapshot report.
`sayaka menu` keeps that same boundary while adding a compact action chooser
for browse, Python/Java rule previews, installer files, and the existing
`clean --execute` / `installer --execute` approval flows. Preview stays the
default; neither flow preselects cleanup targets.

The [read-only system status](docs/STATUS.md) command provides native metrics,
explicit freshness/error states and a bounded watch process:

```sh
sayaka status --json
sayaka status --watch
sayaka status --watch --json --count 12
sayaka status --top 10
```

Status never optimizes the system or installs a daemon. Process top is opt-in;
numeric temperature and GPU capabilities remain explicitly unsupported, not
filled with zeroes.

The [local CLI lifecycle tools](docs/LOCAL_LIFECYCLE.md) provide filtered
`history`, generated `completions`, and preview-first `install`, `update`,
`recover` and `remove` for a dedicated user prefix, plus Raycast/Alfred
terminal `launchers` with owned-artifact cleanup. They do not download updates,
edit shell startup files or remove operation history. `recover` reconciles local
installation state; it is not a Trash-restore command.

## Direction

Sayaka aims to make local maintenance explainable, previewable, and auditable:

```text
scan -> findings -> plan -> user approval -> execute -> journal
```

The repository contains the Rust engine, built-in rules, platform adapters,
operation protocols and CLI; expanding these into a full maintenance tool is
the roadmap goal. The engine is intended to serve the macOS and Windows
SayakaCleaner applications as well as the CLI. Shared rules, policy and operation
state belong here; native UI belongs to the separate clients. Those graphical
applications are not included in this repository, and the bindings
crate now provides a [read-only scan, directory and installer-query API](docs/BINDINGS.md), not a
complete native SDK.

Safety checks, basic previews, and operation records belong in the shared core,
not behind a paid feature gate. Platform-specific permissions, file identities,
trash behavior, and partial failures must remain explicit. No maintenance action
should require AI or an online account.

## Workspace

| Crate | Purpose |
| --- | --- |
| `sayaka-engine` | Planning/approval, scanning/indexes, rules/previews, execution/journal and lifecycle/status logic |
| `sayaka-cli` | Command-line entry point, installed as `sayaka` |
| `sayaka-bindings` | Versioned read-only C scan/directory/diagnostic/installer ABI and C/Swift host examples |
| `sayaka-platform-macos` | Audited I/O policy, metadata, native Trash and read-only status boundary |
| `sayaka-platform-windows` | Read-only NT handle, volume, identity and directory enumeration boundary |

## Build

Native hosts can build the library with `cargo build -p sayaka-bindings --locked`;
see [BINDINGS.md](docs/BINDINGS.md) for the C header, ownership and platform limits.

Install a current stable Rust toolchain, then run from the repository root:

```sh
cargo build --workspace --locked
```

The executable is written to `target/debug/sayaka` (`sayaka.exe` on Windows).
Examples written as `sayaka ...` assume that executable is on PATH; from a source
checkout, use `./target/debug/sayaka ...` or the `cargo run` form below instead.
Building does not install the executable or change PATH.

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

Read-only built-in rule discovery includes explicit CPython `__pycache__`
source-backed `.pyc` and explicit OpenJDK `javac` same-directory source-backed
`.class` rules, with explicit rule-bound Trash preview/execute:

```sh
sayaka rules list
sayaka rules list --json
sayaka rules preview . --rule org.python.cpython.pep3147.source_backed_pyc
sayaka rules preview . --rule org.python.cpython.pep3147.source_backed_pyc --json
sayaka rules preview . --rule org.openjdk.javac.source_backed_class
sayaka rules preview . --rule org.openjdk.javac.source_backed_class --json
sayaka rules trash . --rule org.python.cpython.pep3147.source_backed_pyc --select ./pkg/__pycache__/m.cpython-311.pyc
sayaka rules trash . --rule org.python.cpython.pep3147.source_backed_pyc --select ./pkg/__pycache__/m.cpython-311.pyc --json
sayaka rules trash . --rule org.openjdk.javac.source_backed_class --select ./Foo.class
sayaka rules trash . --rule org.openjdk.javac.source_backed_class --select ./Foo.class --json
```

This preview never executes effects. Candidate bytes are observed bytes, not
freed space, and candidate actions remain `preview_only` / `manual_review`.
`rules trash` requires explicit `--select` targets (max 32), keeps metadata-only
source/target rule witnesses in the v3 plan and v2 journal, and still uses the
same exact interactive `trash N` confirmation for `--execute`.

Installer discovery (read-only by default, explicit root only) can distinguish ordinary
`.dmg`/`.pkg` names from bounded structural hints:

```sh
sayaka installer .
sayaka installer . --filter pkg --exclude ./archive --json
sayaka installer . --select ./Example.dmg --json
sayaka installer . --execute
```

This command does **not** mount images, execute installers, read payload files,
validate signatures, read quarantine/origin URLs, or check installed receipts.
Results are structural hints only (`udif_koly_footer`, `xar_flat_pkg_manifest_hint`,
`xar_archive_not_pkg`) and may remain unknown/unsupported/corrupt. See
[installer preview contract](docs/INSTALLER_PREVIEW.md).
Explicit selection is limited to recognized current-user single-link ordinary
files from a complete preview. `--execute` requires terminal selection and the
exact `trash N` phrase after a sealed native plan; there is no implicit all/yes.
It uses the existing revalidated Trash contract, not permanent deletion or
application uninstall. Format hints are not proof that a file is safe to discard.

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

`clean` defaults to the CPython source-backed rule, with optional explicit
`--rule` selection and persistent clean-only exclusions:

```sh
sayaka clean .
sayaka clean . --execute
sayaka clean . --rule org.openjdk.javac.source_backed_class
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
They separate current implementations and recorded acceptance from intended work.

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
