// SPDX-License-Identifier: MPL-2.0
//! One fixed project rule table, used by discovery and native Trash revalidation.
//! Patterns apply only to sibling entry names, never recursively or as shell globs.
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug)]
pub struct ProjectMarker {
    pub id: &'static str,
    pub marker: &'static str,
    pub artifact: &'static str,
    pub display_name: &'static str,
    pub rebuildability_note: &'static str,
    pub evidence: &'static str,
    pub directory_marker: bool,
    pub prerequisite: Option<&'static str>,
    pub requires_ignored: bool,
}
pub const PROJECT_ARTIFACT_RULES: &[ProjectMarker] = &[
    ProjectMarker {
        id: "cargo_target",
        marker: "Cargo.toml",
        artifact: "target",
        display_name: "Rust build output",
        rebuildability_note: "Rebuilt by cargo build",
        evidence: "Cargo.toml beside target; conventional generated project directory, with a fresh Git check before cleanup.",
        directory_marker: false,
        prerequisite: None,
        requires_ignored: false,
    },
    ProjectMarker {
        id: "node_modules",
        marker: "package.json",
        artifact: "node_modules",
        display_name: "Node dependencies",
        rebuildability_note: "Restored by the package manager; downloads may be needed",
        evidence: "package.json beside node_modules; conventional generated project directory, with a fresh Git check before cleanup.",
        directory_marker: false,
        prerequisite: None,
        requires_ignored: false,
    },
    ProjectMarker {
        id: "node_dist",
        marker: "package.json",
        artifact: "dist",
        display_name: "JavaScript build output",
        rebuildability_note: "Rebuilt by the project build command",
        evidence: "package.json beside dist; conventional generated project directory, with a fresh Git check before cleanup.",
        directory_marker: false,
        prerequisite: None,
        requires_ignored: false,
    },
    ProjectMarker {
        id: "python_dist",
        marker: "pyproject.toml",
        artifact: "dist",
        display_name: "Python distributions",
        rebuildability_note: "Rebuilt by the Python build tool",
        evidence: "pyproject.toml beside dist; conventional generated project directory, with a fresh Git check before cleanup.",
        directory_marker: false,
        prerequisite: None,
        requires_ignored: false,
    },
    ProjectMarker {
        id: "python_build",
        marker: "pyproject.toml",
        artifact: "build",
        display_name: "Python build output",
        rebuildability_note: "Rebuilt by the Python build tool",
        evidence: "pyproject.toml beside build; conventional generated project directory, with a fresh Git check before cleanup.",
        directory_marker: false,
        prerequisite: None,
        requires_ignored: false,
    },
    ProjectMarker {
        id: "swift_build",
        marker: "Package.swift",
        artifact: ".build",
        display_name: "Swift build output",
        rebuildability_note: "Rebuilt by swift build; dependencies may download again",
        evidence: "Package.swift beside .build; conventional generated project directory, with a fresh Git check before cleanup.",
        directory_marker: false,
        prerequisite: None,
        requires_ignored: false,
    },
    ProjectMarker {
        id: "xcode_build",
        marker: "*.xcodeproj|*.xcworkspace",
        artifact: "build",
        display_name: "Xcode build output",
        rebuildability_note: "Rebuilt by the next Xcode build",
        evidence: "*.xcodeproj|*.xcworkspace beside build; conventional generated project directory, with a fresh Git check before cleanup.",
        directory_marker: true,
        prerequisite: None,
        requires_ignored: false,
    },
    ProjectMarker {
        id: "next_build",
        marker: "package.json",
        artifact: ".next",
        display_name: "Next.js build output",
        rebuildability_note: "Rebuilt by next build",
        evidence: "package.json beside .next; conventional generated project directory, with a fresh Git check before cleanup.",
        directory_marker: false,
        prerequisite: None,
        requires_ignored: false,
    },
    ProjectMarker {
        id: "nuxt_build",
        marker: "package.json",
        artifact: ".nuxt",
        display_name: "Nuxt build output",
        rebuildability_note: "Rebuilt by nuxt build",
        evidence: "package.json beside .nuxt; conventional generated project directory, with a fresh Git check before cleanup.",
        directory_marker: false,
        prerequisite: None,
        requires_ignored: false,
    },
    ProjectMarker {
        id: "svelte_build",
        marker: "package.json",
        artifact: ".svelte-kit",
        display_name: "SvelteKit build output",
        rebuildability_note: "Rebuilt by the SvelteKit build command",
        evidence: "package.json beside .svelte-kit; conventional generated project directory, with a fresh Git check before cleanup.",
        directory_marker: false,
        prerequisite: None,
        requires_ignored: false,
    },
    ProjectMarker {
        id: "turbo_cache",
        marker: "package.json",
        artifact: ".turbo",
        display_name: "Turborepo cache",
        rebuildability_note: "Recreated by the next task run",
        evidence: "package.json beside .turbo; conventional generated project directory, with a fresh Git check before cleanup.",
        directory_marker: false,
        prerequisite: None,
        requires_ignored: false,
    },
    ProjectMarker {
        id: "parcel_cache",
        marker: "package.json",
        artifact: ".parcel-cache",
        display_name: "Parcel cache",
        rebuildability_note: "Recreated by the next Parcel build",
        evidence: "package.json beside .parcel-cache; conventional generated project directory, with a fresh Git check before cleanup.",
        directory_marker: false,
        prerequisite: None,
        requires_ignored: false,
    },
    ProjectMarker {
        id: "angular_cache",
        marker: "package.json",
        artifact: ".angular/cache",
        display_name: "Angular cache",
        rebuildability_note: "Recreated by the next Angular build",
        evidence: "package.json beside .angular/cache; conventional generated project directory, with a fresh Git check before cleanup.",
        directory_marker: false,
        prerequisite: None,
        requires_ignored: false,
    },
    ProjectMarker {
        id: "next_export",
        marker: "package.json",
        artifact: "out",
        display_name: "Next.js static export",
        rebuildability_note: "Rebuilt by next build with static export enabled",
        evidence: "package.json beside out; conventional generated project directory, with a fresh Git check before cleanup.",
        directory_marker: false,
        prerequisite: Some("next.config.*"),
        requires_ignored: false,
    },
    ProjectMarker {
        id: "gradle_build",
        marker: "build.gradle|build.gradle.kts|settings.gradle*",
        artifact: "build",
        display_name: "Gradle build output",
        rebuildability_note: "Rebuilt by the next Gradle build",
        evidence: "build.gradle|build.gradle.kts|settings.gradle* beside build; conventional generated project directory, with a fresh Git check before cleanup.",
        directory_marker: false,
        prerequisite: None,
        requires_ignored: false,
    },
    ProjectMarker {
        id: "gradle_cache",
        marker: "build.gradle|build.gradle.kts|settings.gradle*",
        artifact: ".gradle",
        display_name: "Gradle project cache",
        rebuildability_note: "Recreated by Gradle; the next build may take longer",
        evidence: "build.gradle|build.gradle.kts|settings.gradle* beside .gradle; conventional generated project directory, with a fresh Git check before cleanup.",
        directory_marker: false,
        prerequisite: None,
        requires_ignored: false,
    },
    ProjectMarker {
        id: "pods",
        marker: "Podfile",
        artifact: "Pods",
        display_name: "CocoaPods dependencies",
        rebuildability_note: "Restored by pod install; downloads may be needed",
        evidence: "Podfile beside Pods; conventional generated project directory, with a fresh Git check before cleanup.",
        directory_marker: false,
        prerequisite: Some("Podfile.lock"),
        requires_ignored: true,
    },
    ProjectMarker {
        id: "flutter_tool",
        marker: "pubspec.yaml",
        artifact: ".dart_tool",
        display_name: "Dart tooling data",
        rebuildability_note: "Recreated by flutter pub get and the next build",
        evidence: "pubspec.yaml beside .dart_tool; conventional generated project directory, with a fresh Git check before cleanup.",
        directory_marker: false,
        prerequisite: None,
        requires_ignored: false,
    },
    ProjectMarker {
        id: "flutter_build",
        marker: "pubspec.yaml",
        artifact: "build",
        display_name: "Flutter build output",
        rebuildability_note: "Rebuilt by the next Flutter build",
        evidence: "pubspec.yaml beside build; conventional generated project directory, with a fresh Git check before cleanup.",
        directory_marker: false,
        prerequisite: None,
        requires_ignored: false,
    },
    ProjectMarker {
        id: "ruby_bundle",
        marker: "Gemfile",
        artifact: "vendor/bundle",
        display_name: "Bundler dependencies",
        rebuildability_note: "Restored by bundle install; downloads may be needed",
        evidence: "Gemfile beside vendor/bundle; conventional generated project directory, with a fresh Git check before cleanup.",
        directory_marker: false,
        prerequisite: None,
        requires_ignored: false,
    },
    ProjectMarker {
        id: "python_venv",
        marker: "pyproject.toml|requirements.txt|setup.py",
        artifact: ".venv",
        display_name: "Python virtual environment",
        rebuildability_note: "Recreate the environment and reinstall dependencies",
        evidence: "pyproject.toml|requirements.txt|setup.py beside .venv; conventional generated project directory, with a fresh Git check before cleanup.",
        directory_marker: false,
        prerequisite: None,
        requires_ignored: false,
    },
    ProjectMarker {
        id: "python_tox",
        marker: "pyproject.toml|requirements.txt|setup.py",
        artifact: ".tox",
        display_name: "Tox environments",
        rebuildability_note: "Recreated by the next tox run",
        evidence: "pyproject.toml|requirements.txt|setup.py beside .tox; conventional generated project directory, with a fresh Git check before cleanup.",
        directory_marker: false,
        prerequisite: None,
        requires_ignored: false,
    },
    ProjectMarker {
        id: "python_mypy",
        marker: "pyproject.toml|requirements.txt|setup.py",
        artifact: ".mypy_cache",
        display_name: "Mypy cache",
        rebuildability_note: "Recreated by the next mypy run",
        evidence: "pyproject.toml|requirements.txt|setup.py beside .mypy_cache; conventional generated project directory, with a fresh Git check before cleanup.",
        directory_marker: false,
        prerequisite: None,
        requires_ignored: false,
    },
    ProjectMarker {
        id: "python_pytest",
        marker: "pyproject.toml|requirements.txt|setup.py",
        artifact: ".pytest_cache",
        display_name: "Pytest cache",
        rebuildability_note: "Recreated by the next pytest run",
        evidence: "pyproject.toml|requirements.txt|setup.py beside .pytest_cache; conventional generated project directory, with a fresh Git check before cleanup.",
        directory_marker: false,
        prerequisite: None,
        requires_ignored: false,
    },
    ProjectMarker {
        id: "python_ruff",
        marker: "pyproject.toml|requirements.txt|setup.py",
        artifact: ".ruff_cache",
        display_name: "Ruff cache",
        rebuildability_note: "Recreated by the next Ruff run",
        evidence: "pyproject.toml|requirements.txt|setup.py beside .ruff_cache; conventional generated project directory, with a fresh Git check before cleanup.",
        directory_marker: false,
        prerequisite: None,
        requires_ignored: false,
    },
    ProjectMarker {
        id: "cmake_build",
        marker: "CMakeLists.txt",
        artifact: "build",
        display_name: "CMake build output",
        rebuildability_note: "Reconfigure and rebuild with CMake",
        evidence: "CMakeLists.txt beside build; conventional generated project directory, with a fresh Git check before cleanup.",
        directory_marker: false,
        prerequisite: None,
        requires_ignored: false,
    },
    ProjectMarker {
        id: "cmake_named",
        marker: "CMakeLists.txt",
        artifact: "cmake-build-*",
        display_name: "CMake build output",
        rebuildability_note: "Reconfigure and rebuild with CMake",
        evidence: "CMakeLists.txt beside cmake-build-*; conventional generated project directory, with a fresh Git check before cleanup.",
        directory_marker: false,
        prerequisite: None,
        requires_ignored: false,
    },
];

pub fn rule(id: &str) -> Option<&'static ProjectMarker> {
    PROJECT_ARTIFACT_RULES.iter().find(|r| r.id == id)
}
pub fn name_matches(pattern: &str, name: &str) -> bool {
    pattern.split('|').any(|p| match p.split_once('*') {
        Some((before, after)) => {
            name.len() >= before.len() + after.len()
                && name.starts_with(before)
                && name.ends_with(after)
        }
        None => p == name,
    })
}
/// Exactly one or two components, with wildcards restricted to the final name.
pub fn project_root(rule: &ProjectMarker, path: &Path) -> Option<PathBuf> {
    let name = path.file_name()?.to_str()?;
    let parent = path.parent()?;
    if let Some((prefix, final_name)) = rule.artifact.split_once('/') {
        (parent.file_name()?.to_str()? == prefix && name_matches(final_name, name))
            .then(|| parent.parent().map(Path::to_path_buf))
            .flatten()
    } else {
        name_matches(rule.artifact, name).then(|| parent.to_path_buf())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn globs_are_sibling_names_and_settings_accepts_empty_suffix() {
        assert!(name_matches("settings.gradle*", "settings.gradle"));
        assert!(name_matches("settings.gradle*", "settings.gradle.kts"));
        assert!(!name_matches("*.xcodeproj", "App.xcodeproj/child"));
        assert!(name_matches("*.xcodeproj|*.xcworkspace", "App.xcworkspace"));
    }
    #[test]
    fn nested_rule_binds_only_the_leaf_to_its_project() {
        let angular = rule("angular_cache").unwrap();
        assert_eq!(
            project_root(angular, Path::new("/projects/web/.angular/cache")),
            Some(PathBuf::from("/projects/web"))
        );
        assert_eq!(
            project_root(angular, Path::new("/projects/web/cache")),
            None
        );
        assert_eq!(
            project_root(angular, Path::new("/projects/web/.angular")),
            None
        );
        assert_eq!(rule("pods").unwrap().prerequisite, Some("Podfile.lock"));
        assert!(rule("pods").unwrap().requires_ignored);
        assert_eq!(
            rule("next_export").unwrap().prerequisite,
            Some("next.config.*")
        );
        assert!(!PROJECT_ARTIFACT_RULES.iter().any(|r| r.marker == "go.mod"));
    }
}
