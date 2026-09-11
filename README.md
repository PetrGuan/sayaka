# Sayaka

An open-source local maintenance engine and CLI, targeting macOS and Windows.

**Status: initial scaffold.** Sayaka does not yet scan, clean, uninstall, or
modify files. The CLI currently exposes only help and version information.
The engine and bindings crates are placeholders, not usable APIs.

## Direction

Sayaka aims to make local maintenance explainable, previewable, and auditable:

```text
scan -> findings -> plan -> user approval -> execute -> journal
```

The planned open-source scope includes the Rust engine, rules, platform execution
adapters, operation protocol, and a basic CLI. Native graphical clients such as
SayakaCleaner are separate projects and are not included in this repository.

Safety checks, basic previews, and operation records belong in the shared core,
not behind a paid feature gate. Platform-specific permissions, file identities,
trash behavior, and partial failures must remain explicit. No maintenance action
should require AI or an online account.

## Workspace

| Crate | Purpose |
| --- | --- |
| `sayaka-engine` | Shared maintenance engine; implementation pending |
| `sayaka-cli` | Command-line entry point, installed as `sayaka` |
| `sayaka-bindings` | Reserved for native-client bindings; no ABI exported yet |

## Build

Install a current stable Rust toolchain, then run from the repository root:

```sh
cargo build --workspace --locked
```

The executable is written to `target/debug/sayaka` (`sayaka.exe` on Windows).

```sh
cargo run --locked -p sayaka-cli -- --help
cargo run --locked -p sayaka-cli -- --version
```

Package publication is disabled while the public API is being established.
The target platforms are a development goal, not a claim of production readiness.

## Initial milestones

1. A bounded macOS workflow: authorized scan, findings, preview, explicit approval,
   supported trash operations, and accurate result records.
2. An early Windows implementation to validate shared interfaces before broadening
   the rule set.
3. Evidence-backed platform rules and application management, followed by history
   and optional AI explanations. AI must never bypass execution safeguards.

These milestones describe intended work, not currently available features.

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
