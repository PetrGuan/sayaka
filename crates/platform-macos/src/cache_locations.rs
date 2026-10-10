// SPDX-License-Identifier: MPL-2.0

//! Native permitted shapes for the existing cache Trash contract. The engine
//! separately binds passwd home, profile evidence and activity. A caller's
//! rule ID grants no native authority; the native guard checks the path itself.
use std::path::{Component, Path};

#[derive(Clone, Copy, Debug)]
pub struct CacheLocation {
    pub rule_id: &'static str,
    pub base: &'static [&'static str],
    /// Exactly one visible profile component followed by this exact leaf.
    pub profile_leaf: Option<&'static str>,
}
impl CacheLocation {
    pub fn accepts(&self, path: &Path) -> bool {
        let mut parts = Vec::new();
        for part in path.components() {
            match part {
                Component::RootDir => {}
                Component::Normal(value) => parts.push(value.as_encoded_bytes()),
                _ => return false,
            }
        }
        if !path.is_absolute() {
            return false;
        }
        let count = self.base.len() + if self.profile_leaf.is_some() { 2 } else { 0 };
        if parts.len() <= count {
            return false;
        }
        let suffix = &parts[parts.len() - count..];
        if !suffix
            .iter()
            .zip(self.base)
            .all(|(part, expected)| part.eq_ignore_ascii_case(expected.as_bytes()))
        {
            return false;
        }
        match self.profile_leaf {
            None => true,
            Some(leaf) => {
                let profile = suffix[self.base.len()];
                !profile.is_empty()
                    && !profile.starts_with(b".")
                    && suffix[self.base.len() + 1].eq_ignore_ascii_case(leaf.as_bytes())
            }
        }
    }
}

/// The reviewed exact engine rules (including the two approved Adobe leaves). No generic bundle-ID or Containers shape.
pub const CACHE_LOCATIONS: &[CacheLocation] = &[
    CacheLocation {
        rule_id: "com.adobe.common.media_cache_files.macos",
        base: &[
            "Library",
            "Application Support",
            "Adobe",
            "Common",
            "Media Cache Files",
        ],
        profile_leaf: None,
    },
    CacheLocation {
        rule_id: "com.adobe.common.media_cache_database.macos",
        base: &[
            "Library",
            "Application Support",
            "Adobe",
            "Common",
            "Media Cache",
        ],
        profile_leaf: None,
    },
    CacheLocation {
        rule_id: "com.apple.xcode.derived_data",
        base: &["Library", "Developer", "Xcode", "DerivedData"],
        profile_leaf: None,
    },
    CacheLocation {
        rule_id: "com.apple.xcode.cache",
        base: &["Library", "Caches", "com.apple.dt.Xcode"],
        profile_leaf: None,
    },
    CacheLocation {
        rule_id: "com.apple.coresimulator.cache",
        base: &["Library", "Developer", "CoreSimulator", "Caches"],
        profile_leaf: None,
    },
    CacheLocation {
        rule_id: "org.npm.cacache",
        base: &[".npm", "_cacache"],
        profile_leaf: None,
    },
    CacheLocation {
        rule_id: "io.pnpm.store",
        base: &["Library", "pnpm", "store"],
        profile_leaf: None,
    },
    CacheLocation {
        rule_id: "com.yarnpkg.classic_cache",
        base: &["Library", "Caches", "Yarn"],
        profile_leaf: None,
    },
    CacheLocation {
        rule_id: "pypa.pip.cache",
        base: &["Library", "Caches", "pip"],
        profile_leaf: None,
    },
    CacheLocation {
        rule_id: "org.rust-lang.cargo.registry_cache",
        base: &[".cargo", "registry", "cache"],
        profile_leaf: None,
    },
    CacheLocation {
        rule_id: "org.gradle.modules_cache",
        base: &[".gradle", "caches", "modules-2", "files-2.1"],
        profile_leaf: None,
    },
    CacheLocation {
        rule_id: "sh.homebrew.downloads_cache",
        base: &["Library", "Caches", "Homebrew", "downloads"],
        profile_leaf: None,
    },
    CacheLocation {
        rule_id: "com.microsoft.teams.classic_cache.macos",
        base: &["Library", "Caches", "com.microsoft.teams"],
        profile_leaf: None,
    },
    CacheLocation {
        rule_id: "com.discord.stable.cache.macos",
        base: &["Library", "Application Support", "discord", "Cache"],
        profile_leaf: None,
    },
    CacheLocation {
        rule_id: "com.google.chrome.http_cache.macos",
        base: &["Library", "Caches", "Google", "Chrome"],
        profile_leaf: Some("Cache"),
    },
    CacheLocation {
        rule_id: "com.google.chrome.code_cache.macos",
        base: &["Library", "Caches", "Google", "Chrome"],
        profile_leaf: Some("Code Cache"),
    },
    CacheLocation {
        rule_id: "com.google.chrome.gpu_cache.macos",
        base: &["Library", "Caches", "Google", "Chrome"],
        profile_leaf: Some("GPUCache"),
    },
    CacheLocation {
        rule_id: "com.microsoft.edge.http_cache.macos",
        base: &["Library", "Caches", "Microsoft Edge"],
        profile_leaf: Some("Cache"),
    },
    CacheLocation {
        rule_id: "com.microsoft.edge.code_cache.macos",
        base: &["Library", "Caches", "Microsoft Edge"],
        profile_leaf: Some("Code Cache"),
    },
    CacheLocation {
        rule_id: "com.microsoft.edge.gpu_cache.macos",
        base: &["Library", "Caches", "Microsoft Edge"],
        profile_leaf: Some("GPUCache"),
    },
    CacheLocation {
        rule_id: "org.mozilla.firefox.http_cache.macos",
        base: &["Library", "Caches", "Firefox", "Profiles"],
        profile_leaf: Some("cache2"),
    },
];
pub fn cache_location(rule_id: &str) -> Option<&'static CacheLocation> {
    CACHE_LOCATIONS
        .iter()
        .find(|entry| entry.rule_id == rule_id)
}
pub fn permitted_cache_location(path: &Path) -> bool {
    CACHE_LOCATIONS.iter().any(|entry| entry.accepts(path))
}
/// Independently checked generic shape; caller rule IDs never authorize it.
pub fn bundle_owned_cache_location(path: &Path, home: &Path) -> bool {
    let root = home.join("Library/Caches");
    if path.parent() != Some(root.as_path()) {
        return false;
    }
    let Some(id) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    let lower = id.to_ascii_lowercase();
    id.len() <= 255
        && id.split('.').count() >= 3
        && id
            .split('.')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
        && !lower.starts_with("com.apple.")
        && !lower.starts_with("group.")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generic_shape_is_independent_exact_home_and_denies_reserved_namespaces() {
        let home = Path::new("/Users/fixture");
        assert!(bundle_owned_cache_location(
            Path::new("/Users/fixture/Library/Caches/com.example.App"),
            home
        ));
        for path in [
            "/Users/other/Library/Caches/com.example.App",
            "/Users/fixture/Library/Caches/COM.APPLE.foo",
            "/Users/fixture/Library/Caches/GROUP.example.foo",
            "/Users/fixture/Library/Caches/com.example.App/child",
            "/Users/fixture/Library/Caches/com.example_bad.App",
            "/Users/fixture/Library/Caches/com.two",
        ] {
            assert!(
                !bundle_owned_cache_location(Path::new(path), home),
                "{path}"
            );
        }
        assert!(!permitted_cache_location(Path::new(
            "/Users/fixture/Library/Caches/com.example.App"
        )));
    }
    #[test]
    fn every_reviewed_shape_accepts_only_the_whole_leaf() {
        for rule in CACHE_LOCATIONS {
            let mut path = std::path::PathBuf::from("/Users/fixture");
            for part in rule.base {
                path.push(part);
            }
            if let Some(leaf) = rule.profile_leaf {
                path.push("Default");
                path.push(leaf);
            }
            assert!(rule.accepts(&path), "{}", rule.rule_id);
            assert!(!rule.accepts(path.parent().unwrap()));
            assert!(!rule.accepts(&path.join("child")));
        }
    }
    #[test]
    fn profile_wildcard_cannot_widen_to_roots_hidden_profiles_or_account_data() {
        for path in [
            "/Users/fixture/Library/Caches/Google/Chrome",
            "/Users/fixture/Library/Caches/Google/Chrome/Default",
            "/Users/fixture/Library/Caches/Google/Chrome/.hidden/Cache",
            "/Users/fixture/Library/Caches/Google/Chrome/Default/nested/Cache",
            "/Users/fixture/Library/Caches/Google/Chrome/Default/Cookies",
            "/Users/fixture/Library/Application Support/Google/Chrome/Default/Cache",
            "/Users/fixture/Library/Application Support/discord/Local Storage",
            "/Users/fixture/Library/Caches/Firefox/Profiles/.hidden/cache2",
            "/Users/fixture/Library/Caches/com.example.unreviewed",
            "/Users/fixture/Library/Containers/com.example.app/Data/Library/Caches",
        ] {
            assert!(!permitted_cache_location(Path::new(path)), "{path}");
        }
    }
}
