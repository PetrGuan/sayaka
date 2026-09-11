# Sayaka

An open-source local maintenance engine and CLI, targeting macOS and Windows.

**Status: M2 read-only scanner and M1 planning core.** macOS scanning supports
explicit roots, bounded resources, cancellation and structured output. The
in-memory core supports plans, exact-preview approval and read-only preflight.
Sayaka does not clean, uninstall, or modify scanned files. Native execution,
durable journaling, Windows scanning and client bindings remain unimplemented.

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
| `sayaka-platform-macos` | Audited thread-policy and native volume-metadata boundary |

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
CLI subprocess checks and a versioned performance fixture. None of these
establish actual OS trash behavior, mutation race guarantees, or Windows support.

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
