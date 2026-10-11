// SPDX-License-Identifier: MPL-2.0
//! Runtime image policy. Native effects are owned only by RuntimeSession.
use super::*;
use serde_json::Value;
#[cfg(any(target_os = "macos", test))]
mod runtime_session;
#[cfg(any(target_os = "macos", test))]
pub use runtime_session::*;
pub const MAX_REPORT: usize = 1024 * 1024;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Runtime {
    pub identifier: String,
    pub runtime_identifier: String,
    pub version: String,
    pub build: String,
    pub kind: String,
    pub path: String,
    pub state: String,
    pub deletable: bool,
    pub size_bytes: Option<u64>,
    pub last_used_at: Option<String>,
    pub issues: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SdkMatch {
    pub platform: String,
    pub chosen: String,
    pub default: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RuntimeCandidate {
    pub runtime: Runtime,
    pub dependents: Vec<Candidate>,
    pub custom_devices: Vec<String>,
    pub refusals: Vec<String>,
    pub suggested: bool,
    pub evidence: Vec<String>,
    pub rebuildability_note: String,
}
impl RuntimeCandidate {
    pub fn eligible(&self) -> bool {
        self.refusals.is_empty()
    }
}
pub(crate) fn bad(s: &str) -> ParseError {
    ParseError::Shape(s.into())
}
pub(crate) fn string(v: &Value, k: &str) -> Result<String, ParseError> {
    v.get(k)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 4096 && !s.contains('\0'))
        .map(str::to_owned)
        .ok_or_else(|| bad("missing or invalid bounded string"))
}
// Reject duplicate object keys at every level instead of silently losing identities.
#[derive(Debug)]
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Unique;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("JSON without duplicate keys")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(self, mut m: M) -> Result<Unique, M::Error> {
                let mut o = serde_json::Map::new();
                while let Some((k, v)) = m.next_entry::<String, Unique>()? {
                    if o.insert(k, v.0).is_some() {
                        return Err(serde::de::Error::custom("duplicate key"));
                    }
                }
                Ok(Unique(Value::Object(o)))
            }
            fn visit_seq<S: serde::de::SeqAccess<'de>>(self, mut s: S) -> Result<Unique, S::Error> {
                let mut a = Vec::new();
                while let Some(v) = s.next_element::<Unique>()? {
                    a.push(v.0)
                }
                Ok(Unique(Value::Array(a)))
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Unique, E> {
                Ok(Unique(Value::String(s.into())))
            }
            fn visit_string<E: serde::de::Error>(self, s: String) -> Result<Unique, E> {
                Ok(Unique(Value::String(s)))
            }
            fn visit_bool<E: serde::de::Error>(self, b: bool) -> Result<Unique, E> {
                Ok(Unique(Value::Bool(b)))
            }
            fn visit_u64<E: serde::de::Error>(self, n: u64) -> Result<Unique, E> {
                Ok(Unique(Value::from(n)))
            }
            fn visit_i64<E: serde::de::Error>(self, n: i64) -> Result<Unique, E> {
                Ok(Unique(Value::from(n)))
            }
            fn visit_f64<E: serde::de::Error>(self, n: f64) -> Result<Unique, E> {
                Ok(Unique(Value::from(n)))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
        }
        d.deserialize_any(Visitor)
    }
}
pub(crate) fn json(bytes: &[u8]) -> Result<Value, ParseError> {
    serde_json::from_str::<Unique>(bounded_utf8(bytes)?)
        .map(|x| x.0)
        .map_err(|_| bad("invalid JSON"))
}
pub fn parse_runtimes(bytes: &[u8]) -> Result<Vec<Runtime>, ParseError> {
    let root = json(bytes)?;
    let map = root.as_object().ok_or_else(|| bad("runtime object"))?;
    if map.len() > 64 {
        return Err(ParseError::TooLarge);
    }
    let mut result = Vec::new();
    let mut ids = BTreeSet::new();
    for (key, v) in map {
        let id = string(v, "identifier")?;
        let id = canonical_udid(&id).ok_or_else(|| bad("runtime UUID"))?;
        if canonical_udid(key).as_ref() != Some(&id) || !ids.insert(id.clone()) {
            return Err(bad("runtime identity mismatch"));
        }
        let mut issues = Vec::new();
        let size = v.get("sizeBytes").and_then(Value::as_u64);
        if v.get("sizeBytes").is_some_and(|v| !v.is_null()) && size.is_none() {
            issues.push("invalid_size".into())
        }
        let used = v
            .get("lastUsedAt")
            .and_then(Value::as_str)
            .filter(|s| timestamp(s).is_some())
            .map(str::to_owned);
        if v.get("lastUsedAt").is_some_and(|v| !v.is_null()) && used.is_none() {
            issues.push("invalid_last_use".into())
        }
        let path = string(v, "path")?;
        if !valid_path(&path) {
            return Err(bad("invalid image path"));
        }
        result.push(Runtime {
            identifier: id,
            runtime_identifier: string(v, "runtimeIdentifier")?,
            version: string(v, "version")?,
            build: string(v, "build")?,
            kind: string(v, "kind")?,
            path,
            state: string(v, "state")?,
            deletable: v
                .get("deletable")
                .and_then(Value::as_bool)
                .ok_or_else(|| bad("deletable"))?,
            size_bytes: size,
            last_used_at: used,
            issues,
        });
    }
    result.sort_by(|a, b| a.identifier.cmp(&b.identifier));
    Ok(result)
}
pub fn parse_matches(bytes: &[u8]) -> Result<Vec<SdkMatch>, ParseError> {
    let root = json(bytes)?;
    let map = root.as_object().ok_or_else(|| bad("SDK match object"))?;
    if map.len() > 128 {
        return Err(ParseError::TooLarge);
    }
    let mut out = Vec::new();
    for v in map.values() {
        let platform = match string(v, "platform")?.as_str() {
            "com.apple.platform.iphoneos" => "iOS",
            "com.apple.platform.watchos" => "watchOS",
            "com.apple.platform.appletvos" => "tvOS",
            "com.apple.platform.xros" => "visionOS",
            _ => return Err(bad("unknown SDK platform")),
        };
        out.push(SdkMatch {
            platform: platform.into(),
            chosen: string(v, "chosenRuntimeBuild")?,
            default: string(v, "defaultBuild")?,
        });
    }
    out.sort_by(|a, b| {
        (&a.platform, &a.chosen, &a.default).cmp(&(&b.platform, &b.chosen, &b.default))
    });
    Ok(out)
}
pub fn parse_types(bytes: &[u8]) -> Result<BTreeMap<String, String>, ParseError> {
    let root = json(bytes)?;
    let a = root
        .get("devicetypes")
        .and_then(Value::as_array)
        .ok_or_else(|| bad("device types"))?;
    if a.len() > 512 {
        return Err(ParseError::TooLarge);
    }
    let mut out = BTreeMap::new();
    for v in a {
        if out
            .insert(string(v, "identifier")?, string(v, "name")?)
            .is_some()
        {
            return Err(bad("duplicate device type"));
        }
    }
    Ok(out)
}
pub(crate) fn valid_path(s: &str) -> bool {
    s.starts_with('/')
        && s.len() <= 4096
        && !s.contains('\0')
        && !s.split('/').any(|s| s == ".." || s == ".")
}
pub fn platform(r: &Runtime) -> Option<&'static str> {
    let s = r
        .runtime_identifier
        .strip_prefix("com.apple.CoreSimulator.SimRuntime.")?;
    [
        ("iOS-", "iOS"),
        ("watchOS-", "watchOS"),
        ("tvOS-", "tvOS"),
        ("xrOS-", "visionOS"),
        ("visionOS-", "visionOS"),
    ]
    .into_iter()
    .find(|(prefix, _)| s.starts_with(prefix))
    .map(|(_, p)| p)
}
fn version(s: &str) -> Option<Vec<u32>> {
    let mut a = s
        .split('.')
        .map(|s| {
            if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
                s.parse().ok()
            } else {
                None
            }
        })
        .collect::<Option<Vec<_>>>()?;
    if a.is_empty() || a.len() > 4 {
        return None;
    }
    while a.len() < 4 {
        a.push(0)
    }
    Some(a)
}
// Strict UTC ISO-8601 with optional fractional seconds, the observed simctl format.
pub fn timestamp(s: &str) -> Option<u64> {
    if !s.is_ascii() || s.len() < 20 || s.len() > 32 || !s.ends_with('Z') {
        return None;
    }
    if &s[4..5] != "-"
        || &s[7..8] != "-"
        || &s[10..11] != "T"
        || &s[13..14] != ":"
        || &s[16..17] != ":"
    {
        return None;
    }
    let part = |a, b| s[a..b].parse::<u64>().ok();
    let (y, m, d, h, n, t) = (
        part(0, 4)?,
        part(5, 7)?,
        part(8, 10)?,
        part(11, 13)?,
        part(14, 16)?,
        part(17, 19)?,
    );
    if s.len() > 20
        && (&s[19..20] != "."
            || s.len() == 21
            || !s[20..s.len() - 1].bytes().all(|b| b.is_ascii_digit()))
    {
        return None;
    }
    if !(1970..=9999).contains(&y) || !(1..=12).contains(&m) || h > 23 || n > 59 || t > 59 {
        return None;
    }
    let leap = |y: u64| y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400));
    let months = [
        31,
        if leap(y) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if d == 0 || d > months[m as usize - 1] {
        return None;
    }
    let days = (1970..y)
        .map(|y| if leap(y) { 366 } else { 365 })
        .sum::<u64>()
        + months[..m as usize - 1].iter().sum::<u64>()
        + d
        - 1;
    Some(days * 86400 + h * 3600 + n * 60 + t)
}
/// Production allow-list intentionally empty until disposable native evidence lands.
pub fn native_evidence(_kind: &str, _xcode: Option<&str>) -> bool {
    false
}
pub fn assess(
    images: &[Runtime],
    devices: &[Device],
    pairs: &[(String, String)],
    types: &BTreeMap<String, String>,
    matches: &[SdkMatch],
    xcode: Option<&str>,
    now: u64,
) -> Vec<RuntimeCandidate> {
    let all = candidates(devices, pairs, Operation::Delete);
    images.iter().map(|r|{
        let mut refusals=Vec::new();let mut evidence=Vec::new();let mut custom=Vec::new();
        let deps:Vec<_>=all.iter().filter(|d|d.device.runtime_identifier==r.runtime_identifier).cloned().collect();
        let p=platform(r);let v=version(&r.version);
        if p.is_none()||v.is_none(){refusals.push("unknown_platform_or_version".into())}
        if !r.deletable{refusals.push("not_deletable".into())}if r.state!="Ready"{refusals.push("not_ready".into())}
        if !matches!(r.kind.as_str(),"Disk Image"|"Patchable Cryptex Disk Image"){refusals.push("unsupported_kind".into())}
        if !matches.iter().any(|s|Some(s.platform.as_str())==p){refusals.push("sdk_mapping_unknown".into())}
        if matches.iter().any(|s|Some(s.platform.as_str())==p&&(s.chosen==r.build||s.default==r.build)){refusals.push("required_by_xcode".into())}
        if images.iter().filter(|i|i.runtime_identifier==r.runtime_identifier).count()!=1{refusals.push("ambiguous_runtime_images".into())}
        for c in &deps {
            if types.get(&c.device.device_type_identifier)!=Some(&c.device.name){custom.push(c.device.udid.clone());refusals.push("custom_or_unknown_device_name".into())}
            if !c.eligible(){refusals.push("dependent_device_refused".into())}
            if c.paired_with.as_ref().is_some_and(|id|!deps.iter().any(|d|&d.device.udid==id)){refusals.push("paired_outside_runtime".into())}
        }
        if !native_evidence(&r.kind,xcode){refusals.push("native_evidence_missing".into())}
        let older=images.iter().any(|i|platform(i)==p&&p.is_some()&&i.state=="Ready"&&version(&i.version).zip(v.clone()).is_some_and(|(a,b)|a>b));
        let aged=r.last_used_at.as_deref().and_then(timestamp).is_some_and(|t|t<=now&&now-t>=90*86400);
        if older{evidence.push("newer_runtime_same_platform".into())}if aged{evidence.push("unused_at_least_90_days".into())}
        refusals.sort();refusals.dedup();let suggested=refusals.is_empty()&&r.issues.is_empty()&&(older||aged);
        RuntimeCandidate{runtime:r.clone(),dependents:deps,custom_devices:custom,refusals,suggested,evidence,rebuildability_note:"Xcode can download the runtime again. Apps and data in its simulators cannot be restored by Sayaka.".into()}
    }).collect()
}
