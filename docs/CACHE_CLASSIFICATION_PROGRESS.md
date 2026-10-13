# Cache classification: shared inventory and observable work

Scope: one developer-cache preview captures the installed-application inventory once, on demand, and shares it across bundle-owned cache candidates. An inventory failure is reported once and stops this ownership slice; fixed-location rules remain available with incomplete coverage. No failed observation becomes evidence that an app is absent. This does not change approved cleanup scope or perform filesystem effects.

Copy matching uses the inventory snapshot for this read-only preview, while registry/Spotlight observations, matching-owner no-follow witnesses, manifest digests and activity checks remain in place. Execution's `Proof::revalidate` rebuilds inventory through `capture`; snapshots are never global or reused across previews/execution. Existing orphan/copy callers retain their revalidation path.

Application manifest diagnostics now include the actual manifest path and bounded parser error category/message (unsupported format, malformed data, parser limits, etc.). They do not include file contents. The existing static-error metadata API remains compatible; its diagnostic companion provides detail to ownership observation. This slice locates parsing failures; it does not loosen the parser to accept unsupported data.

Progress separates application enumeration (count read, total unknown) from cache ownership (attempts completed / candidate count). Callbacks run at inventory traversal/application and candidate boundaries and check cancellation; native calls and a bounded plist parse already in flight remain cooperative. No artificial percentages, bytes or eligible-cleanup counts are emitted. Legacy purge poll V1 has unchanged layout/meaning; additive `sayaka_purge_poll_v2` returns a nested V1 snapshot plus independent classification fields (phase 0 ordinary, 1 inventory, 2 ownership; total zero means unknown). V2 observes the same task under the same lock; it does not scan again.

Validation plan: compile engine/bindings and regression sources only; do not execute unit/UI tests. Regression source checks diagnostic path/category without file contents, legacy error compatibility, inventory count publication and callback cancellation. Host integration must show classification activity separately from measured bytes and retain ordinary sizing/Stop behavior. Actual wall-time savings, screen responsiveness and full natural-completion coverage require owner runtime acceptance; no measured speedup is claimed.

## Legacy Apple XML declaration compatibility

The bounded XML plist reader also accepts the exact `-//Apple Computer//DTD PLIST 1.0//EN` public identifier paired with the existing `http://www.apple.com/DTDs/PropertyList-1.0.dtd` URI. The existing `-//Apple//DTD PLIST 1.0//EN` declaration remains accepted. These two declarations are inert whitelisted text: no DTD is downloaded or resolved. Other identifiers/locations, internal subsets (including entity declarations), and unknown general entities remain rejected; predefined XML and valid numeric character references retain their existing handling and budgets. No permissive DTD parser or resolver is introduced.

Regression sources cover both accepted declarations, predefined/numeric references, unknown entities, internal/general/parameter entity subsets, alternate public IDs and network/file/SYSTEM declarations. Engine/bindings and test sources passed `cargo check --locked -p sayaka-engine -p sayaka-bindings --tests`; no tests or harnesses executed. Full application inventory completion and real scan timing remain owner acceptance work.

## Application shortcut observations (#158)

Installed-cache classification accepts a single application shortcut link only
when its absolute or child-relative target remains inside an already captured
application root and ends in a real `.app` bundle with a readable, valid bundle
identifier. Extensionless shortcut names are supported (for example an
uninstaller pointing into an application's `Contents/Helpers`). Parent (`..`)
traversal, intermediate/target links, dangling links, non-app targets, and targets
outside these roots remain unknown. The existing signed system Safari exception
is unchanged. Generic orphan inventory retains its previous stricter policy.

The platform holds the shortcut inode and no-follow parent descriptors and checks
identity, metadata, ACL and raw target text. The engine captures the destination
with the existing no-follow bundle/manifest witnesses. Registry and Spotlight
paths normalize only aliases already verified in this inventory; they cannot
introduce another link-following permission. Execution revalidates retained link
evidence and rebuilds inventory. This observation does not admit links or app
bundles as cleanup targets or bypass running/unknown-owner protection.

A rejected shortcut reports its source, raw target (or unavailable), lexically
resolved candidate and failure reason. `resolved` is not a claim that the target
was successfully opened. Paths are quoted to distinguish embedded newlines.
Regression sources cover accepted helper shortcuts, replacement, unknown targets
and preservation of strict orphan inventory; agent validation compiles but does
not execute them. Native end-to-end classification completion still requires a
manual scan with the built application.
