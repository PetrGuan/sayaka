# Windows native read-only slice

Status: initial native read-only NTFS slice implemented and tested. Full Windows
milestone acceptance is **not complete**: workspace strict static checks, write
feasibility, independent review and environmental cases remain open. Minimum
supported Windows versions and release architectures remain a maintainer
decision. A tested host is not a supported-system matrix.

## Contract

Inputs are explicitly selected absolute directory paths. The shared scanner
retains its limits, cancellation, task IDs, accounting and JSON v1 semantics.
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

Baseline: `bf3d37bce4dfabe1fdba5c86a6e8ee5b5a996a5b` plus the uncommitted Windows
slice. Host: Windows 11 Enterprise Insider Preview, build 26310 (`10.0.26310`),
x64. Toolchain: Rust 1.93.1, `x86_64-pc-windows-msvc`. Clippy and rustfmt were
installed for this existing user toolchain. No elevation or external host was used.

Fixtures: Windows slice v1, unique temporary synthetic directories only. Engine
fixtures use the existing owned-fixture helper; CLI fixtures redirect home,
state, config and temp and retain `SystemRoot` only for Windows process startup.
The ACL case uses the system `icacls.exe` on one newly created fixture directory,
verifies actual denied enumeration, removes its explicit denial and checks
access restoration before cleanup. Junctions are explicitly removed. Successful
native and CLI cases completed cleanup; no recycle-bin cleanup was attempted.

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
```

| Check | Result | Evidence/limit |
| --- | --- | --- |
| Platform tests | PASS, 3 | Native sparse allocation cross-checked with `GetCompressedFileSizeW`; 2 pure path/cloud-flag tests are not cloud-provider evidence |
| Engine native tests | PASS, 6 | Empty/nested trees, hardlinks/full IDs, 901-file buffer traversal, actual unpaired UTF-16 names, real sharing violation, cancellation/budget, junction escape/cycle/ancestors, replaced ancestor handle binding |
| Windows CLI tests | PASS, 4 | JSON v1/progress IDs/native strings, mixed-root partial exit, real ACL denial/restoration, Trash rejection without file changes or journal creation |
| Native root unit test | PASS, 1 | Drive root, relative/parent forms rejected; native UTF-16 preserved |
| Platform strict Clippy | PASS | All targets, no warning suppression |
| Complete CLI suite | PASS, 30 | 19 unit and 11 subprocess tests, including the 4 Windows-specific cases above |
| Workspace format/build | PASS | Locked debug build succeeds; existing non-macOS warnings remain |
| Workspace tests | PASS, 140 | Engine library: 93 passed; full default command completes with zero failures or ignored tests |
| Workspace strict Clippy | FAIL | Existing non-macOS unused execution/journal/plan code: 12 library diagnostics, plus unused `Effect::Failed` in tests |
| Cloud provider/network/removable host cases | BLOCKED | No dedicated fixture/environment; no simulated pass claimed |
| Windows Trash/recovery/system journal | BLOCKED | Unsupported; no native effects, recovery, crash-window or real partial-write acceptance claimed |
| Independent review/minimum OS/latency and RSS budgets | BLOCKED | Not independently reviewed or selected/measured |

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

The 140 checks comprise 93 engine unit tests, 3 in-memory integration tests, 6
Windows scanner tests, 19 CLI unit tests, 11 CLI subprocess tests, 3 Windows
platform tests, 1 non-macOS unsupported-source test and 4 compile-fail doc tests.
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

- [NT file opening](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile)
- [Object attributes and reparse refusal](https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes)
- [Handle-based directory/identity queries](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileinformationbyhandleex)
- [Extended directory records](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_extd_dir_info)

Windows shell recycling is not enabled: path-oriented shell actions do not inherit
the approved macOS primitive's scope or identity guarantees. A separate reviewed
Windows contract and versioned identity/journal representation are required before
approvals, native write batches or restoration can be accepted.