// SPDX-License-Identifier: MPL-2.0
//! On-demand diagnostics. Results grant no mutation authority.
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Id {
    Disk = 1,
    LoginItems = 2,
    Network = 3,
    HomePermissions = 4,
    Spotlight = 5,
    SpotlightExclusions = 6,
    NetworkDsstore = 7,
    LegacyOverrides = 8,
    SudoTouchId = 9,
    PeriodicAvailability = 10,
}
impl Id {
    pub fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            1 => Self::Disk,
            2 => Self::LoginItems,
            3 => Self::Network,
            4 => Self::HomePermissions,
            5 => Self::Spotlight,
            6 => Self::SpotlightExclusions,
            7 => Self::NetworkDsstore,
            8 => Self::LegacyOverrides,
            9 => Self::SudoTouchId,
            10 => Self::PeriodicAvailability,
            _ => return None,
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Disk => "disk",
            Self::LoginItems => "login_items",
            Self::Network => "network",
            Self::HomePermissions => "home_permissions",
            Self::Spotlight => "spotlight",
            Self::SpotlightExclusions => "spotlight_exclusions",
            Self::NetworkDsstore => "network_dsstore",
            Self::LegacyOverrides => "legacy_overrides",
            Self::SudoTouchId => "sudo_touch_id",
            Self::PeriodicAvailability => "periodic_availability",
        }
    }
}
#[derive(Serialize, Debug)]
pub struct Fact {
    pub name: String,
    pub value: String,
    pub status: &'static str,
    pub source: &'static str,
}
#[derive(Serialize, Debug)]
pub struct Report {
    pub schema_version: u32,
    pub id: &'static str,
    pub status: &'static str,
    pub facts: Vec<Fact>,
    pub source: &'static str,
    pub observed_unix_ms: u64,
    pub complete: bool,
    pub summary: &'static str,
    pub reason_codes: Vec<&'static str>,
    pub effects_performed: bool,
}
fn safe(s: &str) -> (String, bool) {
    let mut out = String::new();
    for c in s.chars() {
        let part = if c.is_control() {
            c.escape_default().to_string()
        } else {
            c.to_string()
        };
        if out.len() + part.len() > 4096 {
            return (out, true);
        }
        out.push_str(&part);
    }
    (out, false)
}
impl Report {
    fn new(id: Id) -> Self {
        Self {
            schema_version: 1,
            id: id.name(),
            status: "unknown",
            facts: Vec::new(),
            source: source(id),
            observed_unix_ms: 0,
            complete: true,
            summary: "read_only_observation",
            reason_codes: Vec::new(),
            effects_performed: false,
        }
    }
    fn fact(&mut self, name: &str, value: &str, status: &'static str) {
        let (name, a) = safe(name);
        let (value, b) = safe(value);
        let status = if a || b {
            self.complete = false;
            self.reason_codes.push("text_truncated");
            "unknown"
        } else {
            status
        };
        self.facts.push(Fact {
            name,
            value,
            status,
            source: self.source,
        });
        if matches!(status, "unknown" | "unavailable") {
            self.complete = false
        }
    }
    fn fail(&mut self, reason: &'static str) {
        self.complete = false;
        self.reason_codes.push(reason);
        self.fact("observation", reason, "unknown")
    }
    fn finish(mut self) -> Self {
        self.status = if self.facts.iter().any(|f| f.status == "attention") {
            "attention"
        } else if self.facts.iter().any(|f| f.status == "unknown") {
            "unknown"
        } else if self.facts.iter().any(|f| f.status == "unavailable") {
            "unavailable"
        } else if self.complete && !self.facts.is_empty() {
            "ok"
        } else {
            "unknown"
        };
        self.observed_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(u64::MAX as u128) as u64;
        self
    }
}
fn source(id: Id) -> &'static str {
    match id {
        Id::Disk => "/usr/sbin/diskutil verifyVolume /",
        Id::LoginItems => "/usr/bin/sfltool dumpbtm",
        Id::Network => "route / scutil --dns / DNSServiceGetAddrInfo(www.apple.com)",
        Id::HomePermissions => "getpwuid_r / openat / fstatat (no-follow)",
        Id::Spotlight => "getfsstat / mdutil -s",
        Id::SpotlightExclusions => "unverified Spotlight privacy source",
        Id::NetworkDsstore | Id::LegacyOverrides => "CFPreferences current-user / any-host",
        Id::SudoTouchId => "/private/etc/pam.d/sudo + sudo_local",
        Id::PeriodicAvailability => "lstat /usr/sbin/periodic",
    }
}
static RUNNING: std::sync::Mutex<()> = std::sync::Mutex::new(());
pub fn run(id: Id) -> Report {
    run_cancellable(id, &|| false)
}
pub fn run_cancellable(id: Id, cancel: &dyn Fn() -> bool) -> Report {
    let mut r = Report::new(id);
    let Ok(_guard) = RUNNING.try_lock() else {
        r.fail("observation_busy");
        return r.finish();
    };
    #[cfg(target_os = "macos")]
    observe(id, &mut r, cancel);
    if cancel() {
        r.fail("cancelled")
    }
    #[cfg(not(target_os = "macos"))]
    r.fact("platform", "unsupported_platform", "unavailable");
    r.finish()
}
pub fn pam_configuration(sudo: &str, local: Option<&str>) -> &'static str {
    fn rows(text: &str) -> Option<Vec<Vec<&str>>> {
        let mut rows = Vec::new();
        for l in text.lines() {
            let l = l.split('#').next()?.trim();
            if l.is_empty() {
                continue;
            }
            let row = l.split_whitespace().collect::<Vec<_>>();
            if row.len() != 3 {
                return None;
            }
            rows.push(row);
        }
        Some(rows)
    }
    fn tid(r: &[&str]) -> bool {
        r.len() == 3
            && r[0] == "auth"
            && r[1] == "sufficient"
            && ["pam_tid.so", "/usr/lib/pam/pam_tid.so"].contains(&r[2])
    }
    let Some(mut stack) = rows(sudo) else {
        return "unknown";
    };
    let direct = stack.first().is_some_and(|r| tid(r));
    if direct {
        stack.remove(0);
    }
    let include = stack
        .first()
        .is_some_and(|r| r == &["auth", "include", "sudo_local"]);
    if include {
        stack.remove(0);
    }
    let standard = vec![
        vec!["auth", "sufficient", "pam_smartcard.so"],
        vec!["auth", "required", "pam_opendirectory.so"],
        vec!["account", "required", "pam_permit.so"],
        vec!["password", "required", "pam_deny.so"],
        vec!["session", "required", "pam_permit.so"],
    ];
    if stack != standard {
        return "unknown";
    }
    let active = if include {
        let Some(local) = local else {
            return "local_file_missing";
        };
        let Some(local) = rows(local) else {
            return "unknown";
        };
        if local.is_empty() {
            false
        } else if local.len() == 1 && tid(&local[0]) {
            true
        } else {
            return "unknown";
        }
    } else {
        false
    };
    if direct || active {
        "configured"
    } else {
        "not_configured"
    }
}
pub fn indexing(text: &str) -> Option<&'static str> {
    let lines = text
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    if lines.len() != 2 || !lines[0].starts_with('/') || !lines[0].ends_with(':') {
        return None;
    }
    match lines[1] {
        "Indexing enabled." => Some("enabled"),
        "Indexing disabled." => Some("disabled"),
        _ => None,
    }
}
fn classify_output<'a>(
    success: bool,
    stdout: &'a [u8],
    stderr: &[u8],
) -> Result<&'a str, &'static str> {
    if !success {
        return Err("command_failed");
    }
    if !stderr.is_empty() {
        return Err("command_diagnostic");
    }
    std::str::from_utf8(stdout).map_err(|_| "output_encoding")
}
fn route_fact(success: bool, stdout: &[u8], stderr: &[u8]) -> (&'static str, &'static str) {
    let (Ok(s), Ok(e)) = (std::str::from_utf8(stdout), std::str::from_utf8(stderr)) else {
        return ("unrecognized_route", "unknown");
    };
    if success
        && e.is_empty()
        && s.lines().any(|l| l.trim() == "destination: default")
        && s.lines().any(|l| l.trim_start().starts_with("interface:"))
    {
        ("present", "ok")
    } else if !success
        && s.is_empty()
        && [
            "route: writing to routing socket: not in table",
            "route: route has not been found",
        ]
        .contains(&e.trim())
    {
        ("absent", "attention")
    } else {
        ("unrecognized_route", "unknown")
    }
}
fn resolver_facts(s: &str, r: &mut Report) {
    let mut count = 0;
    let mut scope = String::new();
    let mut section = String::new();
    for line in s.lines() {
        let l = line.trim();
        if l.starts_with("DNS configuration") {
            section = l.to_owned();
        }
        if l.starts_with("resolver #") {
            scope = format!("{section} / {l}");
        }
        if [
            "domain",
            "search domain",
            "if_index",
            "flags",
            "reach",
            "order",
            "options",
        ]
        .iter()
        .any(|p| l.starts_with(p))
        {
            r.fact(&scope, l, "ok");
        }
        if l.starts_with("nameserver[") {
            let Some((_, address)) = l.split_once(" : ") else {
                r.fail("resolver_format");
                continue;
            };
            if address.parse::<std::net::IpAddr>().is_ok()
                || address
                    .split_once('%')
                    .is_some_and(|(ip, _)| ip.parse::<std::net::Ipv6Addr>().is_ok())
            {
                if count < 128 {
                    r.fact(&scope, address, "ok")
                } else {
                    r.fail("resolver_limit");
                    break;
                }
                count += 1;
            } else {
                r.fail("resolver_format")
            }
        }
    }
    if count == 0 {
        r.fact("resolvers", "no_addresses_observed", "unknown")
    }
}
#[cfg(target_os = "macos")]
fn observe(id: Id, r: &mut Report, cancel: &dyn Fn() -> bool) {
    use sayaka_platform_macos::{diagnostic_reads as reads, diagnostic_tools as tools};
    use std::time::{Duration, Instant};
    let output = |t: tools::Tool| {
        let v = tools::run_cancel(t, cancel)?;
        classify_output(v.success, &v.stdout, &v.stderr).map(str::to_owned)
    };
    match id {
        Id::Disk => match output(tools::Tool::Disk) {
            Ok(s) => {
                if s.contains("appears to be OK") && s.contains("Finished file system verification")
                {
                    r.fact("boot_volume", "verification_completed", "ok")
                } else {
                    r.fail("verification_output_unrecognized")
                }
            }
            Err(e) => r.fail(e),
        },
        Id::LoginItems => match output(tools::Tool::LoginItems) {
            Ok(s) => {
                // dumpbtm has no stable documented record schema; retain evidence without claiming completeness.
                r.fact("capture", "audit_captured_format_unverified", "unknown");
                r.fact("local_details", &s, "ok");
                if s.chars().count() > 4096 {
                    r.fail("details_truncated")
                }
            }
            Err(e) => r.fail(e),
        },
        Id::Network => {
            let start = Instant::now();
            for (t, name) in [
                (tools::Tool::Route4, "ipv4_default_route"),
                (tools::Tool::Route6, "ipv6_default_route"),
            ] {
                match tools::run_cancel(t, cancel) {
                    Ok(v) => {
                        let (value, status) = route_fact(v.success, &v.stdout, &v.stderr);
                        r.fact(name, value, status);
                    }
                    Err(e) => r.fact(name, e, "unknown"),
                }
            }
            match output(tools::Tool::Dns) {
                Ok(s) => {
                    resolver_facts(&s, r);
                }
                Err(e) => r.fail(e),
            }
            if start.elapsed() > Duration::from_secs(15) {
                r.fail("network_deadline")
            } else {
                match reads::dns_lookup(cancel) {
                    Ok(true) => r.fact("www.apple.com", "resolved_not_internet_verification", "ok"),
                    Ok(false) => r.fact("www.apple.com", "could_not_resolve", "attention"),
                    Err(e) => r.fact("www.apple.com", e, "unknown"),
                }
            }
            if start.elapsed() > Duration::from_secs(20) {
                r.fail("network_deadline")
            }
        }
        Id::HomePermissions => match reads::home(cancel) {
            Ok((entries, complete)) => {
                for e in entries {
                    r.fact(
                        &e.name,
                        &format!(
                            "owner_matches={} mode={:04o} symlink={} acl_not_audited",
                            e.owner_matches, e.mode, e.symlink
                        ),
                        if e.symlink {
                            "ok"
                        } else if !e.owner_matches || e.mode & 0o022 != 0 {
                            "attention"
                        } else {
                            "ok"
                        },
                    )
                }
                if !complete {
                    r.fail("home_partial")
                }
            }
            Err(e) => r.fail(e),
        },
        Id::Spotlight => match tools::mounts() {
            Ok(mounts) => {
                let start = Instant::now();
                for (i, m) in mounts.iter().enumerate() {
                    if cancel() {
                        r.fail("cancelled");
                        break;
                    }
                    if i >= 32 || start.elapsed() >= Duration::from_secs(30) {
                        r.fail("volume_budget");
                        break;
                    }
                    let remaining = Duration::from_secs(30).saturating_sub(start.elapsed());
                    match tools::spotlight(m, remaining, cancel) {
                        Ok(v) if v.success && v.stderr.is_empty() => {
                            match std::str::from_utf8(&v.stdout).ok().and_then(indexing) {
                                Some(s) => r.fact(
                                    m.path(),
                                    s,
                                    if s == "disabled" { "attention" } else { "ok" },
                                ),
                                None => r.fact(m.path(), "indexing_unknown", "unknown"),
                            }
                        }
                        Ok(_) => r.fact(m.path(), "command_failed", "unknown"),
                        Err(e) => r.fact(m.path(), e, "unknown"),
                    }
                }
                if start.elapsed() > Duration::from_secs(30) {
                    r.fail("volume_deadline")
                }
            }
            Err(e) => r.fail(e),
        },
        Id::SpotlightExclusions => {
            r.fact("privacy_exclusions", "source_not_verified", "unavailable")
        }
        Id::NetworkDsstore | Id::LegacyOverrides => {
            let keys = if id == Id::NetworkDsstore {
                vec![("DSDontWriteNetworkStores", reads::Preference::NetworkStores)]
            } else {
                vec![
                    ("NSAppSleepDisabled", reads::Preference::AppNap),
                    ("skip-verify", reads::Preference::Verify),
                    ("skip-verify-locked", reads::Preference::VerifyLocked),
                    ("skip-verify-remote", reads::Preference::VerifyRemote),
                ]
            };
            let start = Instant::now();
            for (name, p) in keys {
                if cancel() {
                    r.fail("cancelled");
                    break;
                }
                match reads::preference(p) {
                    Ok((value, forced)) => r.fact(
                        name,
                        &format!(
                            "{value}; managed={}; current_user_any_host",
                            forced
                                .map(|v| v.to_string())
                                .unwrap_or_else(|| "unknown".into())
                        ),
                        if value == "unexpected_type" {
                            "unknown"
                        } else if id == Id::LegacyOverrides && value == "true" {
                            "attention"
                        } else {
                            "ok"
                        },
                    ),
                    Err(e) => r.fact(name, e, "unknown"),
                }
            }
            if start.elapsed() > Duration::from_secs(5) {
                r.fail("preference_deadline")
            }
        }
        Id::SudoTouchId => {
            let start = Instant::now();
            let sudo = reads::pam("sudo", cancel);
            let local = reads::pam("sudo_local", cancel);
            for (name, v) in [("sudo", &sudo), ("sudo_local", &local)] {
                r.fact(
                    name,
                    match v {
                        Ok(Some(_)) => "readable",
                        Ok(None) => "missing",
                        Err(e) => e,
                    },
                    if v.is_err() { "unknown" } else { "ok" },
                )
            }
            for (label, v) in [("sudo", &sudo), ("sudo_local", &local)] {
                if let Ok(Some(text)) = v {
                    let lines = text
                        .lines()
                        .map(|l| {
                            l.split('#')
                                .next()
                                .unwrap_or("")
                                .split_whitespace()
                                .collect::<Vec<_>>()
                        })
                        .collect::<Vec<_>>();
                    r.fact(
                        &format!("{label}_include_sudo_local"),
                        if lines
                            .iter()
                            .any(|r| r == &["auth", "include", "sudo_local"])
                        {
                            "observed"
                        } else {
                            "not_observed"
                        },
                        "ok",
                    );
                    r.fact(
                        &format!("{label}_pam_tid_line"),
                        if lines.iter().any(|r| {
                            r.len() >= 3
                                && r[0] == "auth"
                                && ["pam_tid.so", "/usr/lib/pam/pam_tid.so"].contains(&r[2])
                        }) {
                            "observed_configuration_only"
                        } else {
                            "not_observed"
                        },
                        "ok",
                    );
                }
            }
            let state = match (sudo, local) {
                (Ok(Some(s)), Ok(l)) => pam_configuration(&s, l.as_deref()),
                _ => "unknown",
            };
            r.fact(
                "configuration",
                state,
                match state {
                    "unknown" => "unknown",
                    "local_file_missing" => "unavailable",
                    "not_configured" => "attention",
                    _ => "ok",
                },
            );
            if start.elapsed() > Duration::from_secs(5) {
                r.fail("pam_deadline")
            }
        }
        Id::PeriodicAvailability => match reads::periodic_available() {
            Ok(true) => r.fact("periodic", "present_execution_unsupported", "ok"),
            Ok(false) => r.fact("periodic", "system_tool_unavailable", "unavailable"),
            Err(e) => r.fail(e),
        },
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    const BASE: &str = "auth sufficient pam_smartcard.so\nauth required pam_opendirectory.so\naccount required pam_permit.so\npassword required pam_deny.so\nsession required pam_permit.so";
    fn stack() -> String {
        format!("auth include sudo_local\n{BASE}")
    }
    #[test]
    fn missing_and_comments() {
        assert_eq!(pam_configuration(&stack(), None), "local_file_missing");
        assert_eq!(
            pam_configuration(&stack(), Some("#auth sufficient pam_tid.so")),
            "not_configured"
        );
    }
    #[test]
    fn reachable_only() {
        assert_eq!(
            pam_configuration(&stack(), Some("auth sufficient pam_tid.so")),
            "configured"
        );
        assert_eq!(
            pam_configuration(BASE, Some("auth sufficient pam_tid.so")),
            "not_configured"
        );
    }
    #[test]
    fn malformed_or_blocking_unknown() {
        for s in [
            "",
            "#empty",
            "auth required pam_deny.so\nauth sufficient pam_tid.so",
            "auth [success=1 default=ignore] pam_tid.so",
        ] {
            assert_eq!(pam_configuration(s, None), "unknown");
        }
        assert_eq!(
            pam_configuration(
                &stack(),
                Some("auth required pam_deny.so\nauth sufficient pam_tid.so")
            ),
            "unknown"
        );
    }
    #[test]
    fn exact_indexing() {
        assert_eq!(indexing("/:\n Indexing enabled.\n"), Some("enabled"));
        assert_eq!(indexing("error: not enabled"), None);
        assert_eq!(indexing("/:\nIndexing enabled.\nwarning"), None);
    }
    #[test]
    fn unknown_enum() {
        assert!(Id::from_u32(0).is_none());
        assert!(Id::from_u32(11).is_none());
    }
    #[test]
    fn utf8_and_escape_cap() {
        let (s, truncated) = safe(&"界".repeat(2000));
        assert!(truncated);
        assert!(s.len() <= 4096);
        let (_, truncated) = safe(&"\0".repeat(2000));
        assert!(truncated);
    }
    #[test]
    fn partial_never_ok() {
        let mut r = Report::new(Id::HomePermissions);
        r.fact("entry", "observed", "ok");
        r.fail("home_partial");
        assert!(!r.finish().complete);
    }
    #[test]
    fn unexpected_preference_and_failed_command() {
        for code in [
            "unexpected_type",
            "command_failed",
            "command_timeout",
            "dns_no_such_record",
            "resolver_format",
        ] {
            let mut r = Report::new(Id::Network);
            r.fact("fact", code, "unknown");
            let r = r.finish();
            assert_eq!(r.status, "unknown");
            assert!(!r.complete);
        }
    }
    #[test]
    fn route_families_and_failures() {
        assert_eq!(
            route_fact(true, b"destination: default\ninterface: en0", b""),
            ("present", "ok")
        );
        assert_eq!(
            route_fact(false, b"", b"route: route has not been found"),
            ("absent", "attention")
        );
        assert_eq!(route_fact(true, b"destination: def", b"").1, "unknown");
        assert_eq!(
            route_fact(false, b"destination: default\ninterface: en0", b"failure").1,
            "unknown"
        );
    }
    #[test]
    fn resolver_scopes_and_malformed() {
        let mut r = Report::new(Id::Network);
        resolver_facts(
            "DNS configuration\nresolver #1\n nameserver[0] : 1.1.1.1\nDNS configuration (for scoped queries)\nresolver #1\n nameserver[0] : ::1\n if_index : 4 (en0)",
            &mut r,
        );
        assert_ne!(r.facts[0].name, r.facts[1].name);
        assert_eq!(r.facts[2].value, "if_index : 4 (en0)");
        let mut r = Report::new(Id::Network);
        resolver_facts("resolver #1\nnameserver[0] : bad", &mut r);
        assert!(!r.complete);
    }
    #[test]
    fn command_results() {
        assert_eq!(
            classify_output(false, b"enabled", b""),
            Err("command_failed")
        );
        assert_eq!(
            classify_output(true, b"enabled", b"warning"),
            Err("command_diagnostic")
        );
        assert_eq!(classify_output(true, &[255], b""), Err("output_encoding"));
    }
}
