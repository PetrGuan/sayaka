// SPDX-License-Identifier: MPL-2.0

//! Simulator cleanup policy for slice 1a of `docs/SIMULATOR_CLEANUP.md`.
//!
//! Pure parsing and decisions over `simctl` JSON: no process launch, no
//! filesystem effects. The macOS platform crate runs the fixed `simctl`
//! argument vectors; this module decides what may be offered, how a request
//! is validated, what must still match before each call, and how post-check
//! observations map to per-identity outcomes.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Effect class of every operation here: permanent, never a Trash fallback.
pub const EFFECT_CLASS: &str = "permanent_tool_operation_v1";
pub const PREVIEW_SCHEMA_VERSION: u32 = 1;
/// Maximum bytes accepted from one `simctl` list call.
pub const MAX_LIST_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_DEVICES: usize = 512;
pub const MAX_REQUEST_DEVICES: usize = 32;
/// Devices per `simctl erase|delete` call.
pub const MAX_BATCH: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Erase,
    Delete,
}

impl Operation {
    pub fn verb(self) -> &'static str {
        match self {
            Operation::Erase => "erase",
            Operation::Delete => "delete",
        }
    }

    /// Exact approval phrase, mirroring the purge binding's typed tokens.
    pub fn approval_phrase(self, count: usize) -> String {
        format!("{} {count} simulators", self.verb())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseError {
    TooLarge,
    NotUtf8,
    Shape(String),
    TooManyDevices,
    InvalidUdid(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::TooLarge => write!(f, "simctl output exceeds the size cap"),
            ParseError::NotUtf8 => write!(f, "simctl output is not UTF-8"),
            ParseError::Shape(detail) => write!(f, "unexpected simctl JSON shape: {detail}"),
            ParseError::TooManyDevices => write!(f, "more than {MAX_DEVICES} devices"),
            ParseError::InvalidUdid(udid) => write!(f, "invalid device identifier {udid:?}"),
        }
    }
}

impl std::error::Error for ParseError {}

/// A device from `simctl list devices -j`. Unknown extra keys are tolerated.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Device {
    pub udid: String,
    pub name: String,
    pub runtime_identifier: String,
    pub device_type_identifier: String,
    pub state: String,
    pub is_available: bool,
    pub data_path: String,
    pub data_path_size: Option<u64>,
    pub log_path_size: Option<u64>,
    pub last_used_at: Option<String>,
    pub availability_error: Option<String>,
}

#[derive(Deserialize)]
struct RawDevices {
    devices: BTreeMap<String, Vec<RawDevice>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawDevice {
    udid: String,
    name: String,
    state: String,
    is_available: bool,
    data_path: String,
    device_type_identifier: String,
    #[serde(default)]
    data_path_size: Option<u64>,
    #[serde(default)]
    log_path_size: Option<u64>,
    #[serde(default)]
    last_used_at: Option<String>,
    #[serde(default)]
    availability_error: Option<String>,
}

#[derive(Deserialize)]
struct RawPairs {
    pairs: BTreeMap<String, RawPair>,
}

#[derive(Deserialize)]
struct RawPair {
    watch: RawPairMember,
    phone: RawPairMember,
}

#[derive(Deserialize)]
struct RawPairMember {
    udid: String,
}

/// Canonical device identifier: upper-case `8-4-4-4-12` hex. `simctl` also
/// accepts names and aliases (`booted`, `all`) and has no end-of-options
/// marker, so only this form may ever reach an argument vector.
pub fn canonical_udid(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    if bytes.len() != 36 || bytes.first() == Some(&b'-') {
        return None;
    }
    for (index, byte) in bytes.iter().enumerate() {
        let dash = matches!(index, 8 | 13 | 18 | 23);
        if dash != (*byte == b'-') || (!dash && !byte.is_ascii_hexdigit()) {
            return None;
        }
    }
    Some(value.to_ascii_uppercase())
}

fn bounded_utf8(bytes: &[u8]) -> Result<&str, ParseError> {
    if bytes.len() > MAX_LIST_BYTES {
        return Err(ParseError::TooLarge);
    }
    std::str::from_utf8(bytes).map_err(|_| ParseError::NotUtf8)
}

/// Parses `simctl list devices -j`. Fails closed on missing required keys,
/// wrong types or non-canonical identifiers.
pub fn parse_devices(bytes: &[u8]) -> Result<Vec<Device>, ParseError> {
    let raw: RawDevices = serde_json::from_str(bounded_utf8(bytes)?)
        .map_err(|error| ParseError::Shape(error.to_string()))?;
    let mut devices = Vec::new();
    for (runtime, entries) in raw.devices {
        for entry in entries {
            if devices.len() == MAX_DEVICES {
                return Err(ParseError::TooManyDevices);
            }
            let udid = canonical_udid(&entry.udid).ok_or(ParseError::InvalidUdid(entry.udid))?;
            devices.push(Device {
                udid,
                name: entry.name,
                runtime_identifier: runtime.clone(),
                device_type_identifier: entry.device_type_identifier,
                state: entry.state,
                is_available: entry.is_available,
                data_path: entry.data_path,
                data_path_size: entry.data_path_size,
                log_path_size: entry.log_path_size,
                last_used_at: entry.last_used_at,
                availability_error: entry.availability_error,
            });
        }
    }
    let unique: BTreeSet<_> = devices.iter().map(|device| &device.udid).collect();
    if unique.len() != devices.len() {
        return Err(ParseError::Shape("duplicate device identifier".into()));
    }
    Ok(devices)
}

/// Parses `simctl list pairs -j` into (watch, phone) identifier pairs.
pub fn parse_pairs(bytes: &[u8]) -> Result<Vec<(String, String)>, ParseError> {
    let raw: RawPairs = serde_json::from_str(bounded_utf8(bytes)?)
        .map_err(|error| ParseError::Shape(error.to_string()))?;
    raw.pairs
        .into_values()
        .map(|pair| {
            let watch =
                canonical_udid(&pair.watch.udid).ok_or(ParseError::InvalidUdid(pair.watch.udid))?;
            let phone =
                canonical_udid(&pair.phone.udid).ok_or(ParseError::InvalidUdid(pair.phone.udid))?;
            Ok((watch, phone))
        })
        .collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateRefusal {
    /// State is anything but exactly `Shutdown`.
    NotShutdown,
    /// Xcode parallel-testing clone (`Clone N of …`), owned by test runs.
    TestClone,
    /// Unavailable devices are offered for delete only.
    UnavailableErase,
    /// Paired devices are never erased; deleted only as a whole pair.
    PairedErase,
}

/// One device as offered for an operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Candidate {
    pub device: Device,
    /// The other member of a watch/phone pair, if any.
    pub paired_with: Option<String>,
    pub refusals: Vec<CandidateRefusal>,
}

impl Candidate {
    pub fn eligible(&self) -> bool {
        self.refusals.is_empty()
    }
}

fn is_test_clone(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("Clone ") else {
        return false;
    };
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    digits > 0 && rest[digits..].starts_with(" of ")
}

/// Evaluates every device for one operation. Nothing is pre-selected.
pub fn candidates(
    devices: &[Device],
    pairs: &[(String, String)],
    operation: Operation,
) -> Vec<Candidate> {
    let mut partner = BTreeMap::new();
    for (watch, phone) in pairs {
        partner.insert(watch.clone(), phone.clone());
        partner.insert(phone.clone(), watch.clone());
    }
    devices
        .iter()
        .map(|device| {
            let paired_with = partner.get(&device.udid).cloned();
            let mut refusals = Vec::new();
            if device.state != "Shutdown" {
                refusals.push(CandidateRefusal::NotShutdown);
            }
            if is_test_clone(&device.name) {
                refusals.push(CandidateRefusal::TestClone);
            }
            if operation == Operation::Erase {
                if !device.is_available {
                    refusals.push(CandidateRefusal::UnavailableErase);
                }
                if paired_with.is_some() {
                    refusals.push(CandidateRefusal::PairedErase);
                }
            }
            Candidate {
                device: device.clone(),
                paired_with,
                refusals,
            }
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum RequestRefusal {
    Empty,
    TooMany,
    Duplicate {
        udid: String,
    },
    NotPreviewed {
        udid: String,
    },
    Ineligible {
        udid: String,
    },
    /// A delete must include every member of a pair.
    IncompletePair {
        udid: String,
        missing: String,
    },
}

/// Validates a selection against the retained preview's candidates.
pub fn validate_request(
    candidates: &[Candidate],
    selected: &[String],
) -> Result<(), RequestRefusal> {
    if selected.is_empty() {
        return Err(RequestRefusal::Empty);
    }
    if selected.len() > MAX_REQUEST_DEVICES {
        return Err(RequestRefusal::TooMany);
    }
    let by_udid: BTreeMap<_, _> = candidates
        .iter()
        .map(|c| (c.device.udid.as_str(), c))
        .collect();
    let mut seen = BTreeSet::new();
    for udid in selected {
        if !seen.insert(udid.as_str()) {
            return Err(RequestRefusal::Duplicate { udid: udid.clone() });
        }
        let candidate = by_udid
            .get(udid.as_str())
            .ok_or_else(|| RequestRefusal::NotPreviewed { udid: udid.clone() })?;
        if !candidate.eligible() {
            return Err(RequestRefusal::Ineligible { udid: udid.clone() });
        }
    }
    for udid in selected {
        if let Some(partner) = &by_udid[udid.as_str()].paired_with
            && !seen.contains(partner.as_str())
        {
            return Err(RequestRefusal::IncompletePair {
                udid: udid.clone(),
                missing: partner.clone(),
            });
        }
    }
    Ok(())
}

/// Digest binding an approval to one sealed preview: operation, tool evidence
/// and every candidate's identity-relevant fields, in a stable order.
pub fn plan_digest(operation: Operation, tool_evidence: &str, candidates: &[Candidate]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(EFFECT_CLASS.as_bytes());
    hasher.update([0]);
    hasher.update(operation.verb().as_bytes());
    hasher.update([0]);
    hasher.update(tool_evidence.as_bytes());
    let mut ordered: Vec<_> = candidates.iter().collect();
    ordered.sort_by(|a, b| a.device.udid.cmp(&b.device.udid));
    for candidate in ordered {
        let device = &candidate.device;
        for field in [
            device.udid.as_str(),
            device.name.as_str(),
            device.runtime_identifier.as_str(),
            device.data_path.as_str(),
            device.state.as_str(),
            candidate.paired_with.as_deref().unwrap_or(""),
        ] {
            hasher.update([0]);
            hasher.update(field.as_bytes());
        }
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// What must still hold immediately before a call, per previewed device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum Mismatch {
    Missing,
    IdentityChanged,
    NotShutdown,
    PairingChanged,
}

pub fn revalidate(
    previewed: &Candidate,
    current: &[Device],
    current_pairs: &[(String, String)],
) -> Result<(), Mismatch> {
    let device = current
        .iter()
        .find(|device| device.udid == previewed.device.udid)
        .ok_or(Mismatch::Missing)?;
    let before = &previewed.device;
    if device.name != before.name
        || device.runtime_identifier != before.runtime_identifier
        || device.data_path != before.data_path
    {
        return Err(Mismatch::IdentityChanged);
    }
    if device.state != "Shutdown" {
        return Err(Mismatch::NotShutdown);
    }
    let partner = current_pairs.iter().find_map(|(watch, phone)| {
        if *watch == device.udid {
            Some(phone.clone())
        } else if *phone == device.udid {
            Some(watch.clone())
        } else {
            None
        }
    });
    if partner != previewed.paired_with {
        return Err(Mismatch::PairingChanged);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Succeeded,
    Refused,
    Failed,
    Unknown,
}

/// How a batch call ended, as seen by the runner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallEnd {
    Exited {
        success: bool,
    },
    /// Timeout, interruption or output cap: the service may still finish.
    Indeterminate,
}

/// Observation of a device's data directory, supplied by the platform crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct DataObservation {
    pub size: Option<u64>,
    pub modified_unix_ns: Option<i128>,
}

/// Maps a post-check re-list to one identity's outcome. A batch exit status
/// alone never decides an identity.
pub fn classify(
    operation: Operation,
    end: CallEnd,
    after: Option<&Device>,
    data_before: DataObservation,
    data_after: DataObservation,
) -> Outcome {
    let CallEnd::Exited { success } = end else {
        return Outcome::Unknown;
    };
    match operation {
        Operation::Delete => match (after, success) {
            (None, _) => Outcome::Succeeded,
            (Some(_), false) => Outcome::Failed,
            (Some(_), true) => Outcome::Unknown,
        },
        Operation::Erase => {
            if !success {
                return Outcome::Failed;
            }
            let observable_change = (data_before.size.is_some()
                || data_before.modified_unix_ns.is_some())
                && data_before != data_after;
            match after {
                Some(device) if device.state == "Shutdown" && observable_change => {
                    Outcome::Succeeded
                }
                // Exit 0 with no observable change is expected for an already-empty device.
                _ => Outcome::Unknown,
            }
        }
    }
}

/// Splits a validated selection into argument batches of at most [`MAX_BATCH`].
pub fn batches(selected: &[String]) -> Vec<Vec<String>> {
    selected.chunks(MAX_BATCH).map(<[String]>::to_vec).collect()
}

/// The fixed argument vector for one batch (after `xcrun`).
pub fn argument_vector(operation: Operation, batch: &[String]) -> Option<Vec<String>> {
    if batch.is_empty() || batch.len() > MAX_BATCH {
        return None;
    }
    let mut args = vec!["simctl".to_string(), operation.verb().to_string()];
    for udid in batch {
        args.push(canonical_udid(udid)?);
    }
    Some(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    const WATCH: &str = "11111111-1111-1111-1111-111111111111";
    const PHONE: &str = "22222222-2222-2222-2222-222222222222";
    const LONE: &str = "33333333-3333-3333-3333-333333333333";
    const GONE: &str = "44444444-4444-4444-4444-444444444444";

    fn devices_json() -> String {
        format!(
            r#"{{"devices": {{
              "com.apple.CoreSimulator.SimRuntime.iOS-27-0": [
                {{"udid": "{PHONE}", "name": "Phone", "state": "Shutdown", "isAvailable": true,
                  "dataPath": "/d/{PHONE}/data", "dataPathSize": 100, "deviceTypeIdentifier": "t.phone",
                  "lastUsedAt": "2026-10-04T01:35:22Z", "futureKey": 1}},
                {{"udid": "{LONE}", "name": "Clone 2 of Phone", "state": "Booted", "isAvailable": true,
                  "dataPath": "/d/{LONE}/data", "deviceTypeIdentifier": "t.phone"}}
              ],
              "com.apple.CoreSimulator.SimRuntime.watchOS-27-0": [
                {{"udid": "{WATCH}", "name": "Watch", "state": "Shutdown", "isAvailable": true,
                  "dataPath": "/d/{WATCH}/data", "dataPathSize": 50, "deviceTypeIdentifier": "t.watch"}}
              ],
              "com.apple.CoreSimulator.SimRuntime.iOS-17-5": [
                {{"udid": "{GONE}", "name": "Old", "state": "Shutdown", "isAvailable": false,
                  "availabilityError": "runtime profile not found", "dataPath": "/d/{GONE}/data",
                  "deviceTypeIdentifier": "t.phone"}}
              ]
            }}}}"#
        )
    }

    fn pairs_json() -> String {
        format!(
            r#"{{"pairs": {{"P": {{"watch": {{"udid": "{WATCH}", "name": "Watch", "state": "Shutdown"}},
            "phone": {{"udid": "{PHONE}", "name": "Phone", "state": "Shutdown"}}, "state": "(active, disconnected)"}}}}}}"#
        )
    }

    fn fixture() -> (Vec<Device>, Vec<(String, String)>) {
        (
            parse_devices(devices_json().as_bytes()).unwrap(),
            parse_pairs(pairs_json().as_bytes()).unwrap(),
        )
    }

    fn find<'a>(candidates: &'a [Candidate], udid: &str) -> &'a Candidate {
        candidates.iter().find(|c| c.device.udid == udid).unwrap()
    }

    #[test]
    fn parses_required_and_optional_fields_and_tolerates_extra_keys() {
        let (devices, pairs) = fixture();
        assert_eq!(devices.len(), 4);
        let phone = devices.iter().find(|d| d.udid == PHONE).unwrap();
        assert_eq!(phone.data_path_size, Some(100));
        assert_eq!(
            phone.runtime_identifier,
            "com.apple.CoreSimulator.SimRuntime.iOS-27-0"
        );
        let gone = devices.iter().find(|d| d.udid == GONE).unwrap();
        assert_eq!(gone.data_path_size, None);
        assert!(gone.availability_error.is_some());
        assert_eq!(pairs, vec![(WATCH.to_string(), PHONE.to_string())]);
    }

    #[test]
    fn missing_required_field_or_bad_identifier_fails_closed() {
        let missing = r#"{"devices": {"r": [{"udid": "11111111-1111-1111-1111-111111111111", "name": "x"}]}}"#;
        assert!(matches!(
            parse_devices(missing.as_bytes()),
            Err(ParseError::Shape(_))
        ));
        let alias = r#"{"devices": {"r": [{"udid": "booted", "name": "x", "state": "Shutdown",
            "isAvailable": true, "dataPath": "/d", "deviceTypeIdentifier": "t"}]}}"#;
        assert!(matches!(
            parse_devices(alias.as_bytes()),
            Err(ParseError::InvalidUdid(_))
        ));
        assert_eq!(
            parse_devices(&vec![b' '; MAX_LIST_BYTES + 1]),
            Err(ParseError::TooLarge)
        );
        assert_eq!(parse_devices(&[0xff]), Err(ParseError::NotUtf8));
    }

    #[test]
    fn canonical_udid_rejects_names_aliases_and_option_like_values() {
        assert_eq!(canonical_udid(&LONE.to_lowercase()), Some(LONE.to_string()));
        for bad in [
            "booted",
            "all",
            "-11111111-1111-1111-1111-11111111111",
            "11111111111111111111111111111111",
            "1111111-11111-1111-1111-111111111111",
            "G1111111-1111-1111-1111-111111111111",
        ] {
            assert_eq!(canonical_udid(bad), None, "{bad}");
        }
    }

    #[test]
    fn refusals_cover_state_clones_unavailable_and_pairs() {
        let (devices, pairs) = fixture();
        let erase = candidates(&devices, &pairs, Operation::Erase);
        assert!(
            find(&erase, LONE)
                .refusals
                .contains(&CandidateRefusal::NotShutdown)
        );
        assert!(
            find(&erase, LONE)
                .refusals
                .contains(&CandidateRefusal::TestClone)
        );
        assert_eq!(
            find(&erase, GONE).refusals,
            vec![CandidateRefusal::UnavailableErase]
        );
        assert_eq!(
            find(&erase, WATCH).refusals,
            vec![CandidateRefusal::PairedErase]
        );
        let delete = candidates(&devices, &pairs, Operation::Delete);
        assert!(find(&delete, GONE).eligible());
        assert!(find(&delete, WATCH).eligible());
        assert_eq!(find(&delete, WATCH).paired_with.as_deref(), Some(PHONE));
    }

    #[test]
    fn request_validation_enforces_preview_membership_and_whole_pairs() {
        let (devices, pairs) = fixture();
        let delete = candidates(&devices, &pairs, Operation::Delete);
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(validate_request(&delete, &[]), Err(RequestRefusal::Empty));
        assert!(matches!(
            validate_request(&delete, &s(&[WATCH])),
            Err(RequestRefusal::IncompletePair { .. })
        ));
        assert_eq!(validate_request(&delete, &s(&[WATCH, PHONE])), Ok(()));
        assert!(matches!(
            validate_request(&delete, &s(&[GONE, GONE])),
            Err(RequestRefusal::Duplicate { .. })
        ));
        assert!(matches!(
            validate_request(&delete, &s(&[LONE])),
            Err(RequestRefusal::Ineligible { .. })
        ));
        let unknown = "55555555-5555-5555-5555-555555555555";
        assert!(matches!(
            validate_request(&delete, &s(&[unknown])),
            Err(RequestRefusal::NotPreviewed { .. })
        ));
    }

    #[test]
    fn digest_binds_operation_tool_and_identities() {
        let (devices, pairs) = fixture();
        let delete = candidates(&devices, &pairs, Operation::Delete);
        let erase = candidates(&devices, &pairs, Operation::Erase);
        let base = plan_digest(Operation::Delete, "tool-a", &delete);
        assert_eq!(base.len(), 64);
        assert_ne!(base, plan_digest(Operation::Erase, "tool-a", &erase));
        assert_ne!(base, plan_digest(Operation::Delete, "tool-b", &delete));
        let mut renamed = delete.clone();
        renamed[0].device.name.push('!');
        assert_ne!(base, plan_digest(Operation::Delete, "tool-a", &renamed));
        assert_eq!(Operation::Delete.approval_phrase(2), "delete 2 simulators");
    }

    #[test]
    fn revalidation_detects_every_listed_change() {
        let (devices, pairs) = fixture();
        let delete = candidates(&devices, &pairs, Operation::Delete);
        let phone = find(&delete, PHONE);
        assert_eq!(revalidate(phone, &devices, &pairs), Ok(()));
        let mut booted = devices.clone();
        booted.iter_mut().find(|d| d.udid == PHONE).unwrap().state = "Booted".into();
        assert_eq!(
            revalidate(phone, &booted, &pairs),
            Err(Mismatch::NotShutdown)
        );
        let mut renamed = devices.clone();
        renamed.iter_mut().find(|d| d.udid == PHONE).unwrap().name = "Other".into();
        assert_eq!(
            revalidate(phone, &renamed, &pairs),
            Err(Mismatch::IdentityChanged)
        );
        assert_eq!(
            revalidate(phone, &devices, &[]),
            Err(Mismatch::PairingChanged)
        );
        let without: Vec<_> = devices
            .iter()
            .filter(|d| d.udid != PHONE)
            .cloned()
            .collect();
        assert_eq!(revalidate(phone, &without, &pairs), Err(Mismatch::Missing));
    }

    #[test]
    fn classification_never_trusts_exit_status_alone() {
        let (devices, _) = fixture();
        let phone = devices.iter().find(|d| d.udid == PHONE).unwrap();
        let before = DataObservation {
            size: Some(100),
            modified_unix_ns: Some(1),
        };
        let after = DataObservation {
            size: Some(10),
            modified_unix_ns: Some(2),
        };
        let ok = CallEnd::Exited { success: true };
        let failed = CallEnd::Exited { success: false };
        assert_eq!(
            classify(Operation::Delete, ok, None, before, after),
            Outcome::Succeeded
        );
        assert_eq!(
            classify(Operation::Delete, ok, Some(phone), before, after),
            Outcome::Unknown
        );
        assert_eq!(
            classify(Operation::Delete, failed, Some(phone), before, after),
            Outcome::Failed
        );
        assert_eq!(
            classify(
                Operation::Delete,
                CallEnd::Indeterminate,
                None,
                before,
                after
            ),
            Outcome::Unknown
        );
        assert_eq!(
            classify(Operation::Erase, ok, Some(phone), before, after),
            Outcome::Succeeded
        );
        assert_eq!(
            classify(Operation::Erase, ok, Some(phone), before, before),
            Outcome::Unknown
        );
        assert_eq!(
            classify(Operation::Erase, failed, Some(phone), before, after),
            Outcome::Failed
        );
        assert_eq!(
            classify(Operation::Erase, ok, None, before, after),
            Outcome::Unknown
        );
    }

    #[test]
    fn argument_vectors_are_fixed_and_bounded() {
        let udids: Vec<String> = (0..9)
            .map(|i| format!("{i:08X}-1111-1111-1111-111111111111"))
            .collect();
        assert_eq!(
            batches(&udids).iter().map(Vec::len).collect::<Vec<_>>(),
            vec![8, 1]
        );
        let args = argument_vector(Operation::Erase, &udids[..1]).unwrap();
        assert_eq!(
            args,
            vec!["simctl", "erase", "00000000-1111-1111-1111-111111111111"]
        );
        assert_eq!(argument_vector(Operation::Delete, &udids), None);
        assert_eq!(
            argument_vector(Operation::Delete, &["booted".to_string()]),
            None
        );
    }
}
