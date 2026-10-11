// SPDX-License-Identifier: MPL-2.0
//! Compile-only fixtures in this task; never invoke the test runner.
use super::*;
use crate::devtools::session::{ToolFailure, ToolResult};
use std::cell::RefCell;
const IMAGE: &str = "11111111-1111-1111-1111-111111111111";
const DEVICE: &str = "22222222-2222-2222-2222-222222222222";
struct Fake {
    calls: RefCell<Vec<Vec<String>>>,
    device: RefCell<bool>,
    image: RefCell<bool>,
    fail_device: bool,
    timeout_image: bool,
}
fn fake() -> Fake {
    Fake {
        calls: RefCell::new(vec![]),
        device: RefCell::new(true),
        image: RefCell::new(true),
        fail_device: false,
        timeout_image: false,
    }
}
impl Host for Fake {
    fn tool_identity(&self) -> Result<ToolIdentity, ToolFailure> {
        Ok(ToolIdentity {
            fingerprint: "fixture-tool".into(),
            real_path: PathBuf::from("/fixture/simctl"),
        })
    }
    fn tool_versions(&self, _: &ToolIdentity) -> ToolVersions {
        ToolVersions {
            macos: Some("27.0".into()),
            xcode: Some("27.0".into()),
        }
    }
    fn developer_activity(&self) -> std::io::Result<Vec<String>> {
        Ok(vec![])
    }
    fn data_modified_unix_ns(&self, _: &Path) -> Option<i128> {
        Some(1)
    }
    fn data_identity(&self, _: &Path) -> Option<(u64, u64)> {
        Some((1, 1))
    }
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn run(&self, args: &[String], execute: bool) -> Result<ToolResult, ToolFailure> {
        let a = args.iter().map(String::as_str).collect::<Vec<_>>();
        self.calls.borrow_mut().push(args.to_vec());
        let mut success = true;
        let v = match a.as_slice() {
            ["simctl", "runtime", "list", "-j"] => {
                if *self.image.borrow() {
                    serde_json::json!({IMAGE:{"identifier":IMAGE,"runtimeIdentifier":"com.apple.CoreSimulator.SimRuntime.iOS-26-0","version":"26.0","build":"old","kind":"Disk Image","path":"/fixture/image","state":"Ready","deletable":true,"sizeBytes":1234}})
                } else {
                    serde_json::json!({})
                }
            }
            ["simctl", "runtime", "match", "list", "-j"] => {
                serde_json::json!({"iphoneos27":{"platform":"com.apple.platform.iphoneos","chosenRuntimeBuild":"new","defaultBuild":"new"}})
            }
            ["simctl", "list", "devices", "-j"] => {
                serde_json::json!({"devices":{"com.apple.CoreSimulator.SimRuntime.iOS-26-0":if *self.device.borrow(){vec![serde_json::json!({"udid":DEVICE,"name":"iPhone","state":"Shutdown","isAvailable":true,"dataPath":"/fixture/device/data","deviceTypeIdentifier":"phone","dataPathSize":12})]}else{vec![]}}})
            }
            ["simctl", "list", "pairs", "-j"] => serde_json::json!({"pairs":{}}),
            ["simctl", "list", "devicetypes", "-j"] => {
                serde_json::json!({"devicetypes":[{"identifier":"phone","name":"iPhone"}]})
            }
            ["simctl", "runtime", "delete", IMAGE, "--dry-run"] => {
                assert!(!execute);
                serde_json::json!({})
            }
            ["simctl", "delete", DEVICE] => {
                assert!(execute);
                if self.fail_device {
                    success = false
                } else {
                    *self.device.borrow_mut() = false
                }
                serde_json::json!({})
            }
            ["simctl", "runtime", "delete", IMAGE] => {
                assert!(execute);
                if self.timeout_image {
                    return Err(ToolFailure::Timeout);
                }
                *self.image.borrow_mut() = false;
                serde_json::json!({})
            }
            _ => panic!("unexpected fixed vector {a:?}"),
        };
        Ok(ToolResult {
            success,
            stdout: serde_json::to_vec(&v).unwrap(),
            stderr: vec![],
        })
    }
}
struct Memory {
    records: RefCell<Vec<Record>>,
    fail_started: bool,
}
impl ToolJournal for Memory {
    fn new_id(&self) -> std::io::Result<String> {
        Ok("1-1".into())
    }
    fn publish(&self, r: &Record, _: bool) -> std::io::Result<journal::Publication> {
        r.validate()?;
        if self.fail_started
            && r.runtime_context
                .as_ref()
                .unwrap()
                .items
                .iter()
                .any(|i| i.state == ItemState::Started)
        {
            return Err(std::io::Error::other("fixture write failure"));
        }
        self.records.borrow_mut().push(r.clone());
        Ok(journal::Publication::default())
    }
}
fn request(s: &RuntimeSession<Fake>) -> ExecuteRequest {
    ExecuteRequest {
        plan_digest: s.preview.plan_digest.clone(),
        items: vec![IMAGE.into()],
        approval_token: "delete 1 runtimes and 1 simulators".into(),
    }
}
#[test]
fn production_gate_refuses_before_effects() {
    let s = RuntimeSession::prepare(fake(), &Cancellation::default()).unwrap();
    assert!(s.check_approval(&request(&s)).is_err());
    assert!(
        s.preview.candidates[0]
            .refusals
            .contains(&"native_evidence_missing".into())
    );
}
#[test]
fn owned_dependencies_first_and_typed_journal() {
    let mut s = RuntimeSession::prepare_disposable(
        fake(),
        &Cancellation::default(),
        IMAGE,
        &[DEVICE.into()],
    )
    .unwrap();
    let q = request(&s);
    let m = Memory {
        records: RefCell::new(vec![]),
        fail_started: false,
    };
    let r = s.execute_with(&q, &Cancellation::default(), &m).unwrap();
    assert!(r.record.items.is_empty());
    assert!(
        r.record
            .runtime_context
            .unwrap()
            .items
            .iter()
            .all(|i| i.state == ItemState::Succeeded)
    );
    let calls = s.host.calls.borrow();
    let device = calls
        .iter()
        .position(|a| a == &["simctl", "delete", DEVICE])
        .unwrap();
    let image = calls
        .iter()
        .position(|a| a == &["simctl", "runtime", "delete", IMAGE])
        .unwrap();
    assert!(device < image);
}
#[test]
fn device_failure_stops_runtime() {
    let mut h = fake();
    h.fail_device = true;
    let mut s =
        RuntimeSession::prepare_disposable(h, &Cancellation::default(), IMAGE, &[DEVICE.into()])
            .unwrap();
    let q = request(&s);
    let r = s
        .execute_with(
            &q,
            &Cancellation::default(),
            &Memory {
                records: RefCell::new(vec![]),
                fail_started: false,
            },
        )
        .unwrap();
    assert_eq!(
        r.record.runtime_context.unwrap().items[1].state,
        ItemState::Skipped
    );
    assert!(*s.host.image.borrow());
}
#[test]
fn timeout_unknown_not_success() {
    let mut h = fake();
    h.timeout_image = true;
    let mut s =
        RuntimeSession::prepare_disposable(h, &Cancellation::default(), IMAGE, &[DEVICE.into()])
            .unwrap();
    let q = request(&s);
    let r = s
        .execute_with(
            &q,
            &Cancellation::default(),
            &Memory {
                records: RefCell::new(vec![]),
                fail_started: false,
            },
        )
        .unwrap();
    assert_eq!(
        r.record.runtime_context.unwrap().items[1].state,
        ItemState::Unknown
    );
}
#[test]
fn started_publication_failure_prevents_effect() {
    let mut s = RuntimeSession::prepare_disposable(
        fake(),
        &Cancellation::default(),
        IMAGE,
        &[DEVICE.into()],
    )
    .unwrap();
    let q = request(&s);
    let r = s
        .execute_with(
            &q,
            &Cancellation::default(),
            &Memory {
                records: RefCell::new(vec![]),
                fail_started: true,
            },
        )
        .unwrap();
    assert!(r.journal_error.is_some());
    assert!(*s.host.device.borrow());
    assert!(*s.host.image.borrow());
}
#[test]
fn cancellation_and_wrong_token() {
    let s = RuntimeSession::prepare_disposable(
        fake(),
        &Cancellation::default(),
        IMAGE,
        &[DEVICE.into()],
    )
    .unwrap();
    let mut q = request(&s);
    q.approval_token = "delete 1 runtimes".into();
    assert!(s.check_approval(&q).is_err());
    let cancel = Cancellation::default();
    cancel.cancel();
    assert!(RuntimeSession::prepare(fake(), &cancel).is_err());
}
#[test]
fn changed_dependency_refuses() {
    let s = RuntimeSession::prepare_disposable(
        fake(),
        &Cancellation::default(),
        IMAGE,
        &[DEVICE.into()],
    )
    .unwrap();
    let c = &s.preview.candidates[0];
    let mut l = s.listing.clone();
    l.devices[0].name = "My work".into();
    assert!(s.validate(&l, c, &BTreeSet::new()).is_err());
    l = s.listing.clone();
    l.devices.clear();
    assert!(s.validate(&l, c, &BTreeSet::new()).is_err());
}
#[test]
fn parser_and_policy_fail_closed() {
    assert!(parse_runtimes(br#"{"x":{},"x":{}}"#).is_err());
    assert!(
        parse_matches(
            br#"{"sdk":{"platform":"unknown","chosenRuntimeBuild":"x","defaultBuild":"y"}}"#
        )
        .is_err()
    );
    assert!(timestamp("2026-02-30T00:00:00Z").is_none());
    assert!(timestamp("2026-10-11T00:00:00.123Z").is_some());
    let s = RuntimeSession::prepare(fake(), &Cancellation::default()).unwrap();
    let mut l = s.listing.clone();
    l.matches[0].default = "old".into();
    l.devices[0].name = "My work".into();
    l.images.push(l.images[0].clone());
    let a = assess(
        &l.images,
        &l.devices,
        &l.pairs,
        &l.types,
        &l.matches,
        Some("27"),
        0,
    );
    assert!(a[0].refusals.contains(&"required_by_xcode".into()));
    assert!(a[0].refusals.contains(&"ambiguous_runtime_images".into()));
    assert!(
        a[0].refusals
            .contains(&"custom_or_unknown_device_name".into())
    );
}

#[test]
fn fallback_retains_previous_durable_outcomes() {
    let mut s = RuntimeSession::prepare_disposable(
        fake(),
        &Cancellation::default(),
        IMAGE,
        &[DEVICE.into()],
    )
    .unwrap();
    let q = request(&s);
    let memory = Memory {
        records: RefCell::new(vec![]),
        fail_started: false,
    };
    let report = s
        .execute_with(&q, &Cancellation::default(), &memory)
        .unwrap();
    let previous = memory
        .records
        .borrow()
        .iter()
        .find(|r| {
            let i = &r.runtime_context.as_ref().unwrap().items;
            i[0].state == ItemState::Succeeded && i[1].state == ItemState::Planned
        })
        .unwrap()
        .runtime_context
        .clone()
        .unwrap();
    let mut next = report.record.runtime_context.unwrap();
    next.unconfirmed(Some(&previous));
    assert_eq!(next.items[0].state, ItemState::Succeeded);
    assert_eq!(next.items[1].state, ItemState::Unknown);
}
