# Runtime settlement observations

2026-10-11, macOS 27.0.1, selected Xcode 27.0 (27A266a), CoreSimulator 1171.7.
This evidence does not enable a production kind/tool-version combination.

## Scope

Only owner-authorized disposable iOS 26.4 (23E244, arm64, Patchable Cryptex Disk
Image) resources were used. This follow-up imported an existing local exported
bundle; it started no downloads. Two original runtime UUIDs and 16 original
device UUIDs were retained as a protected baseline. No unit/UI tests, helper,
sudo execution or direct CoreSimulator/AssetsV2 filesystem mutation was used.

An independently reviewed temporary manual client called the engine's debug
`prepare_disposable` entry with exact owned image/device UUIDs and the phrase
`delete 1 runtimes and 1 simulators`. It used the App SimulatorJournal and held
the default CLI journal lock. No concurrent custom-state-dir CLI operation was
run; this does not certify universal exclusion across arbitrary state paths.

## Observations and correction

The original implementation recorded device success and runtime
`unknown/post_check_mismatch`. Later registration absence did not rewrite that
record. The original immediate raw list was not retained, so its precise cause
was not established.

An intermediate settlement implementation observed absence after 13 image/device
observations and published success. Inspection then found that the sealed image
path still contained its restore payload. That record is retained as evidence
of registration-only confirmation; it is not complete asset-removal acceptance.

The final implementation adds the sealed-path absence requirement. A fresh
local import and one newly created default-named iPhone 17 produced:

- device `succeeded`;
- runtime `unknown`, reason
  `runtime_post_check:deadline_asset_path_present;observations=57`;
- schema 11 journal publication succeeded (`journal_error: null`);
- runtime registration and dependent device absent in subsequent complete lists;
- recorded image path and restore DMG still present;
- exactly the original two runtime and 16 device UUIDs remaining.

Each session issued only one runtime delete; the repeated operations were reads,
not effect retries. The final result accurately refuses to turn registration
absence into complete success. The earlier MobileAsset download payload also
remained. Neither directory sizes nor these file observations measure physical
space recovery (APFS copies may share blocks).

System logs during the disposable removal reported CoreSimulator cryptex-unmount
errors. Those logs support investigating incomplete Apple-side cleanup but do
not establish its cause. No extra deletion command or filesystem workaround was
attempted. Existing exported source bundles are not cleanup targets.

## Validation and remaining boundary

`cargo build --workspace --tests --locked` passed. Compile-only fixture sources
cover delayed disappearance, decreasing read budgets, deadline expiry during a
read, cancellation, malformed/capped/failed reads, tool/activity changes, changed
identity, replacement/reappearing images, new dependents, and retained/unreadable
image paths. They were not executed. GPT-6 Astra independently reviewed the
change and verified the validation/path-guard fixes.

Production deletion remains gated. The current Apple tool route has not proved
complete asset cleanup for this kind/version; a bounded post-check reports that
limitation but does not repair Apple's retained payload. Do not claim issue
completion or asset reclamation. Any different removal route or direct asset
mutation requires its own approved contract; it is not a fallback here.
