# Project artifact rules

The native macOS `project_rules::PROJECT_ARTIFACT_RULES` table is shared by discovery and fresh Trash admission. `ProjectMarker` describes a marker name/glob, a relative artifact path, a rebuild cost and layout evidence. The old four engine marker identifiers remain only for portable index previews and transport compatibility; the macOS scanner emits table evidence for all rules, including those original pairs.

These are conventional generated-directory heuristics, not proof that a project has no custom configuration or manually stored files. Each candidate still requires complete discovery/sizing, a fresh no-tracked-files Git observation, native identity/ownership/volume/package protection, explicit review and the existing revalidated Trash contract. No project command or configuration is executed. A running build is not detected. The documented final pathname replacement race remains.

| Rule | Sibling marker | Artifact relative to project root | Display / rebuild cost | Additional evidence |
| --- | --- | --- | --- | --- |
| `cargo_target` | `Cargo.toml` | `target` | Rust build output. Rebuilt by cargo build. | Marker is a regular file |
| `node_modules` | `package.json` | `node_modules` | Node dependencies. Restored by the package manager; downloads may be needed. | Marker is a regular file |
| `node_dist` | `package.json` | `dist` | JavaScript build output. Rebuilt by the project build command. | Marker is a regular file |
| `python_dist` | `pyproject.toml` | `dist` | Python distributions. Rebuilt by the Python build tool. | Marker is a regular file |
| `python_build` | `pyproject.toml` | `build` | Python build output. Rebuilt by the Python build tool. | Marker is a regular file |
| `swift_build` | `Package.swift` | `.build` | Swift build output. Rebuilt by swift build; dependencies may download again. | Marker is a regular file |
| `xcode_build` | `*.xcodeproj` or `*.xcworkspace` | `build` | Xcode build output. Rebuilt by the next Xcode build. | Marker is a directory |
| `next_build` | `package.json` | `.next` | Next.js build output. Rebuilt by next build. | Marker is a regular file |
| `nuxt_build` | `package.json` | `.nuxt` | Nuxt build output. Rebuilt by nuxt build. | Marker is a regular file |
| `svelte_build` | `package.json` | `.svelte-kit` | SvelteKit build output. Rebuilt by the SvelteKit build command. | Marker is a regular file |
| `turbo_cache` | `package.json` | `.turbo` | Turborepo cache. Recreated by the next task run. | Marker is a regular file |
| `parcel_cache` | `package.json` | `.parcel-cache` | Parcel cache. Recreated by the next Parcel build. | Marker is a regular file |
| `angular_cache` | `package.json` | `.angular/cache` | Angular cache. Recreated by the next Angular build. | Marker is a regular file |
| `next_export` | `package.json` | `out` | Next.js static export. Rebuilt by next build with static export enabled. | Regular `next.config.*` file required |
| `gradle_build` | `build.gradle`, `build.gradle.kts` or `settings.gradle*` | `build` | Gradle build output. Rebuilt by the next Gradle build. | Marker is a regular file |
| `gradle_cache` | `build.gradle`, `build.gradle.kts` or `settings.gradle*` | `.gradle` | Gradle project cache. Recreated by Gradle; the next build may take longer. | Marker is a regular file |
| `pods` | `Podfile` | `Pods` | CocoaPods dependencies. Restored by pod install; downloads may be needed. | Regular `Podfile.lock` and Git ignored=true required |
| `flutter_tool` | `pubspec.yaml` | `.dart_tool` | Dart tooling data. Recreated by flutter pub get and the next build. | Marker is a regular file |
| `flutter_build` | `pubspec.yaml` | `build` | Flutter build output. Rebuilt by the next Flutter build. | Marker is a regular file |
| `ruby_bundle` | `Gemfile` | `vendor/bundle` | Bundler dependencies. Restored by bundle install; downloads may be needed. | Marker is a regular file |
| `python_venv` | `pyproject.toml`, `requirements.txt` or `setup.py` | `.venv` | Python virtual environment. Recreate the environment and reinstall dependencies. | Marker is a regular file |
| `python_tox` | `pyproject.toml`, `requirements.txt` or `setup.py` | `.tox` | Tox environments. Recreated by the next tox run. | Marker is a regular file |
| `python_mypy` | `pyproject.toml`, `requirements.txt` or `setup.py` | `.mypy_cache` | Mypy cache. Recreated by the next mypy run. | Marker is a regular file |
| `python_pytest` | `pyproject.toml`, `requirements.txt` or `setup.py` | `.pytest_cache` | Pytest cache. Recreated by the next pytest run. | Marker is a regular file |
| `python_ruff` | `pyproject.toml`, `requirements.txt` or `setup.py` | `.ruff_cache` | Ruff cache. Recreated by the next Ruff run. | Marker is a regular file |
| `cmake_build` | `CMakeLists.txt` | `build` | CMake build output. Reconfigure and rebuild with CMake. | Marker is a regular file |
| `cmake_named` | `CMakeLists.txt` | `cmake-build-*` | CMake build output. Reconfigure and rebuild with CMake. | Marker is a regular file |

`|` separates marker alternatives. `*` matches sibling entry names only, including an empty suffix; glob expansion never recurses. Nested rules admit only the literal `.angular/cache` and `vendor/bundle` suffixes, never their parent containers. `go.mod` deliberately has no rule: global Go caches belong to another profile. A build artifact inside another candidate artifact is excluded.

Every listed pair was exercised with an isolated constructed layout and the real CLI's read-only `purge --json` preview. These observations validate classification, not third-party default configurations or native Trash runtime acceptance. The existing Cargo/Node/Python/Swift pairs are unchanged. Xcode's content-signature rule remains available separately for custom DerivedData names.

## Supplemental evidence and refusal

- [Cache Directory Tagging Specification](https://bford.info/cachedir/): validate an ordinary no-follow `CACHEDIR.TAG` by its exact first 43 bytes, `Signature: 8a477f597d28d172789f06886806bc55`. A newline is not required. Never read the rest. Valid tags augment marker evidence. A tag without a known project rule is a non-executable Review observation, never a recommendation or cleanup authority. An invalid tag adds no evidence.
- [Next.js distDir](https://nextjs.org/docs/app/api-reference/config/next-config-js/distDir) documents the conventional `.next` output and configurable alternatives. We recognize the fixed conventional layout; `out` additionally needs `next.config.*`, and the UI explains static-export rebuilding rather than promising configuration was parsed.
- [CocoaPods usage](https://guides.cocoapods.org/using/using-cocoapods.html) describes Podfile, lockfile and dependency installation. `Pods` needs both regular marker files. Without confirmed Git ignore status it remains visible as Review but cannot be selected. Tracked contents always stay Keep. Git and lockfile evidence is refreshed at preparation and immediately before native Trash.

Probes open ancestors with `O_NOFOLLOW_ANY`, open markers descriptor-relative with `O_NOFOLLOW`, reject dataless entries and mount crossings, and verify descriptor identities. Directory marker enumeration is limited to 4,096 sibling entries and two transient descriptors; failure is incomplete discovery, not absence. Cache tag contents are read under the scanner's nonmaterializing policy. Native admission seals marker identities (including directory markers, prerequisite files, and any observed tag) and rechecks the fixed rule. Only the matched artifact suffix receives a hidden-name exception; hidden project ancestors, system/cloud locations and package targets stay protected.

## Validation record

Build/compile-only validation and CLI layout observations are recorded in the implementation PR. No unit tests, UI tests, test binaries or Trash effects are executed as part of this delivery. Regression test sources cover rule prerequisites, nested paths and malformed wire data and are compiled only.
