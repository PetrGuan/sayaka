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

## Bounded directory metadata observations and inventory diagnostics (#158)

Debug builds emit bounded `[SayakaInventory]` records: current operation/path,
operation and total elapsed microseconds, remaining deadline, visited entry,
directory and application counts, terminal outcome, and per-operation totals and
slowest paths. Detail records are capped at 128 per inventory; the fixed set of
operation summaries still appears. Paths are quoted and these diagnostics remain
local; Release builds do not emit these stderr records. Error messages in either
build identify the operation/path or the exact exhausted budget (deadline,
entries, shared entries, depth, queued paths or queued path bytes). A terminal
classification summary distinguishes processed candidates from per-owner issues.

A read-only CLI observation localized the original 30-second failure to 7,701
Finder alias checks in a large installed SDK/documentation tree: 29.14 seconds,
compared with about 6.6 ms for the two application links. Further process sampling
identified leaf `openat` calls as the remaining cost after removing repeated
ancestor enumeration. These are native diagnostic observations, not benchmark
results or App UI latency measurements.

The inventory now observes each real parent once and binds enumerated spellings
to its identity and directory generation (including change time). It inspects
**every** regular file's FinderInfo through `getxattr` with the public Darwin
`XATTR_NOFOLLOW_ANY` flag, without opening file contents or following any path
link. File identity, metadata and generation are checked around the read;
changed/unreadable/dataless objects and malformed attributes remain unknown. Only
`ENOATTR` establishes absence of FinderInfo. The thread-local no-materialization
policy is held for each directory and explicitly restored at successful finish;
its non-Send guard restores it on early exit. The ordinary last-check/path-race
limitation still applies; this is not a race-free observation claim.

The syscall flag is defined in the macOS SDK `sys/xattr.h`. Missing returned
FinderInfo fields from `getattrlist` must **not** be interpreted as absence:
[Apple's implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/vfs/vfs_attrlist.c)
can omit that attribute after permission and other errors too. The explicit
`getxattr` error code retains that distinction.

Installed-cache inventory's entry cap is 100,000 (previously 10,000); the observed
SDK tree needs more than 68,000 visits. Entries are inspected, not retained as
file records. The 30-second discovery deadline and depth 32 remain unchanged;
pending paths are limited to 10,000 and 32 MiB. Cancellation is checked at least
every 128 enumerated entries as well as directory boundaries. Ordinary orphan
inventory keeps its 10,000-entry cap and strict link policy. Copy/owner limits,
unknown/running-owner protections and execution-time rebuilding are unchanged.

Compile-only regression sources cover plain files and extension-disguised Finder
aliases, case-only rename and linked leaf rejection, and specific budget causes.
No unit/UI tests are executed by the agent. A real CLI cache preview may finish
all classification candidates and still correctly report partial coverage when
one candidate exceeds the existing eight-owner bound. Complete classification
is not permission to clean that protected candidate.

Final diagnostic CLI observation for this change: inventory completed 68,921
entries / 1,666 directories / 54 application records in 6.177 s; classification
processed 53/53 candidates in about 7.506 s including inventory. Cache preview
engine time was 9.275 s, with 32 cache candidates and no effects. One owner-count
issue remained protected, so overall coverage correctly stayed partial. This
single run does not establish a percentile or a full App scan duration.

## Bounded preview ownership observations

An owner App observation completed application inventory in 11.332 s but then
stalled at candidate 29/53. Classification returned after 327.279 s with an owner
copy deadline and only 30/53 processed; full App request time was 392.179 s. The
previous deadline was checked between operations and could not bound a synchronous
native registry query or filesystem validation already in progress. The terminal
error did not identify which primitive blocked; a later CLI observation did not
reproduce the long stall. Do not label a specific macOS API as proven responsible.

A development application's registered copies (32) and Spotlight results (161)
exposed unnecessary work: the eight-owner protection used to run after all source
queries and copy validations. Cache ownership now rejects as soon as the union
exceeds eight paths. Inventory and registry positives keep their existing identity
checks; Spotlight positives retain their conservative refusal semantics. Duplicate
paths do not increase the count, and a stale registry entry is not a positive.
This early exit only refuses cleanup; it never produces an incomplete valid proof.
The generic orphan copy limit remains 256 and mandatory-source checks remain on
all successful observations. Execution still rebuilds/revalidates its evidence.

Only preview candidate capture and activity observation use bounded waits:

- Each candidate waits at most five seconds or the remaining global 30-second
  discovery deadline, whichever is shorter. The caller polls progress/cancellation
  every 25 ms and checks the deadline again before accepting a returned result.
- At most two read-only ownership workers exist process-wide. There is no queued
  backlog. A timeout/cancellation abandons its receiver, signals the worker to
  stop between operations, and discards late evidence. A saturated pool reports
  ownership unknown immediately, rather than spawning replacement workers.
- A synchronous macOS/filesystem call cannot be forcibly interrupted. An in-flight
  worker may outlive scan result/release, retaining its finite inventory/evidence
  until it returns. It retains its slot throughout that lifetime. This is bounded
  caller responsiveness, not a claim of kernel-call termination or all-resource
  settlement. No worker executes cleanup or returns late evidence to another scan.
- Every worker installs/restores its own thread-local read-only I/O policy.
  Unknown, timeout, worker failure, saturation and activity failure never admit
  a candidate to cleanup. Execution-side fresh capture remains synchronous.

Debug records distinguish registry, registry-link/presence/bundle, Spotlight,
owner-proof and activity operations, with paths, operation/owner duration and
remaining budget. Detail logs share a 256-record cap per classification. Timeout
errors retain the current operation/path even after this cap; slow/error candidate
summaries and the terminal processed/total summary remain separate. A processed
candidate can still be protected; completed classification is not complete safety
coverage.

Validation: engine/bindings regression sources compile with `cargo check --tests`
without executing tests. Actual read-only CLI preview processed 53/53, classification
including inventory was 6.028 s, cache preview engine time 7.913 s, and the
many-copy owner was refused in 84 ms. One owner-limit issue remained, with no
cleanup effects or deadline error. These single-run CLI numbers do not certify
full-App wall time, runtime timeout/cancel behavior, or native blockage recovery.
No unit/UI tests, test binaries, harnesses or benchmarks were executed.
