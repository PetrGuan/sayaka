# Windows native read-only slice

Status: native read-only NTFS slice implemented and tested on Windows 11 x64.
The maintainer selected Windows 11 or later, x64 and ARM64 as product targets.
This closeout is scoped to the x64 native read-only slice; ARM64 native acceptance
is a separate follow-up. ARM64 all-target compilation checks pass, but a complete
linked build and native execution are not verified. Windows writes and provider/
network/removable environments remain unsupported. A tested Insider host is not
evidence that every Windows 11 release or architecture has been run.
Rule catalog/preview entry points reuse the shared CLI, but the native
ownership/ancestry/marker inspection used by the CPython and `javac` rules is
currently implemented only on macOS. Unsupported native rule inspection is
reported explicitly on Windows; parser/catalog availability is not rule parity.

The first [native scan bindings](BINDINGS.md) have Windows x64 cross-target
type-check coverage, including native UTF-16 input. Binding DLL linking and
execution from a Windows host are not yet accepted. The macOS-only clean-policy
implementation is now gated separately so it does not prevent a Windows scan
library from compiling; unsupported policy operations do not become empty success.

## Contract

Inputs are explicitly selected absolute directory paths. The shared scanner
retains its limits, cancellation, task IDs, accounting and JSON v1 semantics.
CLI root arguments reject parent traversal before Windows absolute-path
normalization can erase it. If an observed directory becomes a reparse path
before opening, that failure is a `changed_entry` gap, not a complete link skip.
Paths remain native UTF-16; display strings never locate native operations.
The Windows adapter uses a separately reviewable FFI boundary, leaving the engine
unsafe-free. File identity is the volume serial plus the full 128-bit File ID.

Initial scope is positively identified local fixed NTFS volumes. Unsupported
filesystems, network/removable volumes and unavailable volume evidence fail
closed. Root opens reject ancestor reparse traversal; child opens and directory
enumeration are relative to owned handles. Reparse points, including junctions,
are not followed. Offline/recall-marked directories are not enumerated. Cloud
provider behavior remains unverified until a dedicated environment is tested.
No content reads or hydration requests are issued.

`NtCreateFile` uses `OBJ_DONT_REPARSE`, `FILE_DIRECTORY_FILE`,
`FILE_SYNCHRONOUS_IO_NONALERT` and `FILE_OPEN_REPARSE_POINT`; there is no weaker
retry. Adding `FILE_OPEN_NO_RECALL` to these directory options returned Windows
error 87 on the recorded host. The implemented defense is reparse refusal and
attribute checks before enumeration, not a process-wide provider policy. These
tests do not prove that arbitrary filesystem filter/provider activity cannot
download data. Do not extend the supported cloud scope from synthetic flags.

The Windows locality gate checks handle-derived device type/characteristics and
filesystem name, not macOS internal-volume properties. A fixed external device
can differ from a removable device; this is not a claim to identify internal
hardware. Each directory owns one handle and a 64 KiB enumeration buffer;
the shared open-directory limit bounds both. Child opens are handle-relative.

Logical length and native allocation size are separate observations, not free
space or reclaimability claims. Missing measurements are unknown, not zero.
Sharing violations, denied access, replacement and enumeration errors produce
observable gaps (`busy`, `permission_denied`, or `io_error`, retaining OS codes);
a mixed scan must not report complete. Cancellation is
cooperative between OS calls and never promises to interrupt blocked kernel I/O.

Windows Trash, restore, installation and native external viewing remain
unsupported. The macOS `revalidated_trash_v1` decision does not approve Windows
shell path-based operations. No fallback to permanent deletion or elevation is
permitted. Windows write feasibility and independent review remain prerequisites
to enabling effects; rejection must leave fixtures and journal state unchanged.

## Native Tests

Run native tests on the recorded Windows/MSVC host using only unique owned
temporary fixtures. Cover ordinary/empty/nested directories, full identities,
hardlink accounting, native strings, unsafe roots, junctions and their ancestors,
real handle sharing violations, cancellation, mixed results and CLI wire output.
Fixture cleanup must verify ownership and report errors. Do not scan user data
or mutate a cloud provider, system ACLs or the recycle bin for default tests.

Run focused tests first, then formatting, workspace tests/build and strict Clippy.
Record nonzero counts, pass/fail/skipped/blocked and cleanup outcomes separately.
Real cloud placeholders, removable/network volumes and recycle-bin
recovery require their own evidence or explicit blocked status. Shared injected
tests are not Windows-native evidence. Independent review is not self-certified.

The shared worker, queue, handle and result caps remain the structural budgets.
Windows latency/RSS targets must be fixed after an owned-fixture baseline; macOS
benchmark numbers do not establish Windows performance or competitive parity.
The new platform crate is target-specific; runtime/size impact is unmeasured.

## Recorded Evidence

Baseline: merged Windows slice `f0d74da814a0f88da88e5523ae69e93a226092db` plus
the closeout changes described below. Host: Windows 11 Enterprise Insider
Preview, build 26310 (`10.0.26310`),
x64. Toolchain: Rust 1.93.1, `x86_64-pc-windows-msvc`. Clippy and rustfmt were
installed for this existing user toolchain. No elevation or external host was used.

Fixtures: Windows slice v1, unique temporary synthetic directories only. Engine
fixtures use the existing owned-fixture helper; CLI fixtures redirect home,
state, config and temp and retain `SystemRoot` only for Windows process startup.
The ACL case uses the system `icacls.exe` on one newly created fixture directory,
verifies actual denied enumeration, removes its explicit denial and checks
access restoration before cleanup. Junctions are explicitly removed. Successful
native and CLI cases completed cleanup; no recycle-bin cleanup was attempted.

Closeout fixtures create randomized directories exclusively relative to a retained
parent capability, then immediately open the new child without following links.
They never adopt an existing directory or junction. Pathname-based automatic cleanup
is disabled before creation; initialization failures preserve the partial fixture
and are not retried as naming collisions. Fixtures retain a capability directory
handle, native same-file identity and a unique marker. Cleanup validates ancestors, reparse absence, current root
identity and the marker, then removes through the retained directory capability.
Cleanup disarms itself before validation, so a refusal preserves the fixture and
cannot retry deletion by its old name.
Windows capability handles prevent relevant renames while held; tests exercise
both prevented replacements and explicit identity mismatch (even with a copied
marker). Child-controlled teardown is not an atomic deletion guarantee against
arbitrary hostile concurrent namespace mutation on every OS: the capability
library documents residual rename limits. Tests run in owned, otherwise quiescent
roots, join child work first and never discover cleanup targets by name matching.
Creation and no-follow handle capture are also separate operations: callers must
exclude concurrent replacement during initialization as well as teardown.

Run from the repository root:

```sh
cargo test -p sayaka-platform-windows --locked
cargo test -p sayaka-engine --test scan_windows --locked
cargo test -p sayaka-cli --test scan_cli windows_ --locked
cargo test -p sayaka-engine --lib windows_roots --locked
cargo clippy -p sayaka-platform-windows --all-targets --locked -- -D warnings
cargo test -p sayaka-cli --locked
cargo fmt --all -- --check
cargo build --workspace --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo check --workspace --all-targets --target aarch64-pc-windows-msvc --locked
```

| Check | Result | Evidence/limit |
| --- | --- | --- |
| Platform tests | PASS, 10 | Sparse allocation, malformed enumeration buffers, path/cloud-flag decisions and 6 fixture lifecycle tests; synthetic flags are not cloud-provider evidence |
| Engine native tests | PASS, 12 | 6 native scan cases plus 6 fixture lifecycle tests; empty/nested trees, hardlinks/full IDs, native UTF-16, sharing violation, cancellation/budget, junctions and ancestor replacement |
| Windows CLI-specific cases | PASS, 6 | Original 4 native cases plus raw parent traversal and unsupported journal commands without HOME |
| Native root unit test | PASS, 1 | Drive root, relative/parent forms rejected; native UTF-16 preserved |
| Platform strict Clippy | PASS | All targets, no warning suppression |
| Complete CLI suite | PASS, 38 | 19 unit plus 19 integration checks, including fixture lifecycle assertions |
| Workspace tests | PASS, 169 | Engine library: 95 passed; zero failures or ignored tests |
| Workspace strict Clippy | PASS | All targets with `-D warnings`; no blanket warning exemptions |
| ARM64 all-target check | PASS | Rust 1.93.1 cross-compilation check only; no binary execution |
| ARM64 linked build/native execution | BLOCKED, separate follow-up | ARM64 MSVC linker and native host unavailable; maintainer split this from x64 closeout |
| Cloud provider/network/removable host cases | NOT RUN, unsupported scope | No dedicated fixture/environment; no simulated pass claimed |
| Windows Trash/recovery/system journal | REFUSED, unsupported scope | Preparation/storage reject; no native effects or recovery guarantees claimed |
| Minimum platform | SELECTED | Windows 11+ x64/ARM64 product targets; only x64 build 26310 has runtime evidence here |
| Independent review | PASS, scoped x64 read-only closeout | Initial findings corrected; independent reviewer reran 169 checks, strict Clippy and fmt; no blocking findings under the owned quiescent-fixture contract |
| Latency/RSS and broader release matrix | UNMEASURED | No competitive or all-version performance claim; separate acceptance work |

The closeout fixes unused-code diagnostics with platform/test compilation
conditions, not `allow` attributes. The injected executor now tests deterministic
item failure in either batch position while preserving successful results and
without retry/fallback. Non-macOS journal default-directory selection returns
Unsupported before consulting HOME, matching explicit-store refusal.

Independent read-only review found raw-argument normalization, reparse-gap
classification and fixture cleanup weaknesses. Focused regression tests now cover
all three, including unchanged parent metadata and released scanner handles.
The reviewer also requested malformed native record coverage, now included.

The initial run had 16 engine failures (76 passed); all 16 now pass without
disabling tests or weakening production validation:

- The pre-epoch timestamp fixture uses the host-representable tick (100 ns on
	Windows, 1 ns on Unix), asserts it is genuinely before the epoch and verifies
	exact serialized evidence.
- The journal validation test and 3 history tests use explicit Unix wire fixtures
	instead of asking the Windows native-path encoder to construct Unix records.
- The 11 executor tests use host-valid virtual paths and register their Unix wire
	representations in the fake platform. The existing private platform interface
	owns journal-path encoding; its production default remains `NativePath::from_path`.
	The fake journal validates every unmodified published record, including durable
	intent, outcome and recovery evidence. Approval and injected failure assertions
	remain intact.
- One added Windows regression test confirms display-only scope/item paths still
	fail real journal validation. This accounts for 93 rather than 92 engine tests.

The 169 checks comprise 95 engine unit tests, 9 in-memory integration checks, 12
Windows scanner checks, 19 CLI unit tests, 19 CLI integration checks, 10 Windows
platform checks, 1 non-macOS unsupported-source test and 4 compile-fail doc tests.
The shared cleanup tests are compiled in multiple test targets; this is a count
of executed tests, not a claim of 153 distinct native scenarios.
Rows in the table overlap and must not be summed. Bindings and macOS scanner
targets with zero tests on this host are not capability passes; macOS-native
execution was not run. The executor tests above are injected contract checks,
not Windows effects or journal-storage acceptance.

The persistent journal still stores Unix device/inode evidence and emits only
display data for Windows paths. No production journal schema was changed. Do not
truncate a Windows File ID or claim Windows journal compatibility without a
versioned execution design.
The non-macOS `processes_top` stub signature was corrected to match its native
interface; its unsupported-source test and compile-fail policy check passed.

## API And Dependency Sources

Native bindings use `windows-sys` 0.61 (MIT/Apache-2.0); test-only junction creation
uses `junction` 1.4 (MIT), and temporary fixture handling uses the existing
`tempfile` dependency (MIT/Apache-2.0). No third-party source was copied.
Test-only capability cleanup uses `cap-std`/`cap-primitives` 4 and identity comparisons
use `same-file` 1; these dependencies do not enter the product runtime dependency tree.

- [NT file opening](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile)
- [Object attributes and reparse refusal](https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes)
- [Handle-based directory/identity queries](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileinformationbyhandleex)
- [Extended directory records](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_extd_dir_info)

Windows shell recycling is not enabled: path-oriented shell actions do not inherit
the approved macOS primitive's scope or identity guarantees. A separate reviewed
Windows contract and versioned identity/journal representation are required before
approvals, native write batches or restoration can be accepted.