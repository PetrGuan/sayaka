// SPDX-License-Identifier: MPL-2.0
//! Compile-only fixtures in this task; never invoke the test runner.
use super::*;
use crate::devtools::session::{ToolFailure, ToolResult};
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
const IMAGE: &str = "11111111-1111-1111-1111-111111111111";
const DEVICE: &str = "22222222-2222-2222-2222-222222222222";
struct Fake {
    calls: RefCell<Vec<Vec<String>>>,
    device: RefCell<bool>,
    image: RefCell<bool>,
    fail_device: bool,
    timeout_image: bool,
    nonzero_image: bool,
    runtime_called: Cell<bool>,
    post_images: RefCell<VecDeque<serde_json::Value>>,
    post_device: bool,
    asset_present: bool,
    asset_error: bool,
    origin: Instant,
    elapsed: Cell<Duration>,
    budgets: RefCell<Vec<Duration>>,
    read_advance: Duration,
    read_failure: bool,
    read_cap: bool,
    malformed_device: bool,
    changed_tool: bool,
    activity: bool,
    cancellation: Option<Cancellation>,
}
fn fake() -> Fake {
    Fake {
        calls: RefCell::new(vec![]),
        device: RefCell::new(true),
        image: RefCell::new(true),
        fail_device: false,
        timeout_image: false,
        nonzero_image: false,
        runtime_called: Cell::new(false),
        post_images: RefCell::new(VecDeque::new()),
        post_device: false,
        asset_present: false,
        asset_error: false,
        origin: Instant::now(),
        elapsed: Cell::new(Duration::ZERO),
        budgets: RefCell::new(vec![]),
        read_advance: Duration::ZERO,
        read_failure: false,
        read_cap: false,
        malformed_device: false,
        changed_tool: false,
        activity: false,
        cancellation: None,
    }
}
impl Host for Fake {
    fn tool_identity(&self) -> Result<ToolIdentity, ToolFailure> {
        Ok(ToolIdentity {
            fingerprint: if self.runtime_called.get() && self.changed_tool {
                "changed"
            } else {
                "fixture-tool"
            }
            .into(),
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
        Ok(if self.runtime_called.get() && self.activity {
            vec!["Xcode".into()]
        } else {
            vec![]
        })
    }
    fn data_modified_unix_ns(&self, _: &Path) -> Option<i128> {
        Some(1)
    }
    fn data_identity(&self, _: &Path) -> Option<(u64, u64)> {
        Some((1, 1))
    }
    fn runtime_path_present(&self, _: &Path) -> std::io::Result<bool> {
        if self.asset_error {
            Err(std::io::Error::other("unavailable"))
        } else {
            Ok(self.asset_present)
        }
    }
    fn wait_for_runtime_post_check(&self, duration: Duration) {
        self.elapsed.set(self.elapsed.get() + duration);
    }
    fn now(&self) -> Instant {
        self.origin + self.elapsed.get()
    }
    fn run_read_with_timeout(
        &self,
        args: &[String],
        timeout: Duration,
    ) -> Result<ToolResult, ToolFailure> {
        self.budgets.borrow_mut().push(timeout);
        self.elapsed.set(self.elapsed.get() + self.read_advance);
        if self.read_failure {
            return Err(ToolFailure::Timeout);
        }
        if self.read_cap {
            return Ok(ToolResult {
                success: true,
                stdout: vec![b' '; MAX_LIST_BYTES + 1],
                stderr: vec![],
            });
        }
        self.run(args, false)
    }
    fn run(&self, args: &[String], execute: bool) -> Result<ToolResult, ToolFailure> {
        let a = args.iter().map(String::as_str).collect::<Vec<_>>();
        self.calls.borrow_mut().push(args.to_vec());
        if self.runtime_called.get() && a == ["simctl", "runtime", "list", "-j"] {
            if let Some(v) = self.post_images.borrow_mut().pop_front() {
                return Ok(ToolResult {
                    success: true,
                    stdout: serde_json::to_vec(&v).unwrap(),
                    stderr: vec![],
                });
            }
        }
        if self.runtime_called.get()
            && self.malformed_device
            && a == ["simctl", "list", "devices", "-j"]
        {
            let v = serde_json::json!({"devices":{"com.apple.CoreSimulator.SimRuntime.iOS-27-0":[{"udid":DEVICE,"name":"other","state":"Shutdown","isAvailable":true,"dataPath":"relative/path","deviceTypeIdentifier":"phone"}]}});
            return Ok(ToolResult {
                success: true,
                stdout: serde_json::to_vec(&v).unwrap(),
                stderr: vec![],
            });
        }
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
                success = !self.nonzero_image;
                self.runtime_called.set(true);
                if let Some(cancel) = &self.cancellation {
                    cancel.cancel();
                }
                *self.image.borrow_mut() = false;
                if self.post_device {
                    *self.device.borrow_mut() = true;
                }
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

fn post_image(id: &str, state: &str, path: &str) -> serde_json::Value {
    serde_json::json!({id:{"identifier":id,"runtimeIdentifier":"com.apple.CoreSimulator.SimRuntime.iOS-26-0","version":"26.0","build":"old","kind":"Disk Image","path":path,"state":state,"deletable":true}})
}
fn execute_fixture(h: Fake) -> RuntimeReport {
    let mut s =
        RuntimeSession::prepare_disposable(h, &Cancellation::default(), IMAGE, &[DEVICE.into()])
            .unwrap();
    let q = request(&s);
    let m = Memory {
        records: RefCell::new(vec![]),
        fail_started: false,
    };
    let r = s.execute_with(&q, &Cancellation::default(), &m).unwrap();
    assert_eq!(
        s.host
            .calls
            .borrow()
            .iter()
            .filter(|a| a.as_slice() == ["simctl", "runtime", "delete", IMAGE])
            .count(),
        1
    );
    r
}
#[test]
fn delayed_deleting_disappearance_uses_only_one_effect() {
    let h = fake();
    h.post_images
        .borrow_mut()
        .push_back(post_image(IMAGE, "Deleting", "/fixture/image"));
    let r = execute_fixture(h);
    let item = &r.record.runtime_context.as_ref().unwrap().items[1];
    assert_eq!(item.state, ItemState::Succeeded);
    assert_eq!(
        item.reason.as_deref(),
        Some("runtime_and_path_absence_confirmed;observations=2")
    );
}
#[test]
fn replacement_image_is_unknown_even_when_original_absent() {
    let h = fake();
    h.post_images.borrow_mut().push_back(post_image(
        "33333333-3333-3333-3333-333333333333",
        "Ready",
        "/fixture/replacement",
    ));
    let r = execute_fixture(h);
    let item = &r.record.runtime_context.as_ref().unwrap().items[1];
    assert_eq!(item.state, ItemState::Unknown);
    assert!(item.reason.as_ref().unwrap().contains("ambiguous_images"));
}
#[test]
fn changed_path_latches_unknown_without_waiting_for_absence() {
    let h = fake();
    h.post_images
        .borrow_mut()
        .push_back(post_image(IMAGE, "Deleting", "/fixture/replacement"));
    let r = execute_fixture(h);
    let item = &r.record.runtime_context.as_ref().unwrap().items[1];
    assert_eq!(item.state, ItemState::Unknown);
    assert!(
        item.reason
            .as_ref()
            .unwrap()
            .contains("identity_changed;observations=1")
    );
}
#[test]
fn new_dependent_after_delete_is_not_deleted() {
    let mut h = fake();
    h.post_device = true;
    let r = execute_fixture(h);
    let item = &r.record.runtime_context.as_ref().unwrap().items[1];
    assert_eq!(item.state, ItemState::Unknown);
    assert!(item.reason.as_ref().unwrap().contains("dependent_observed"));
}
#[test]
fn permanently_deleting_image_exhausts_observation_bound() {
    let h = fake();
    for _ in 0..MAX_SETTLE_OBSERVATIONS {
        h.post_images
            .borrow_mut()
            .push_back(post_image(IMAGE, "Deleting", "/fixture/image"));
    }
    let r = execute_fixture(h);
    let item = &r.record.runtime_context.as_ref().unwrap().items[1];
    assert_eq!(item.state, ItemState::Unknown);
    assert!(
        item.reason
            .as_ref()
            .unwrap()
            .contains("deadline_deleting;observations=120")
    );
}

fn runtime_reason(r: &RuntimeReport) -> &str {
    let item = &r.record.runtime_context.as_ref().unwrap().items[1];
    assert_eq!(item.state, ItemState::Unknown);
    item.reason.as_deref().unwrap()
}
#[test]
fn expired_read_cannot_certify_absence() {
    let mut h = fake();
    h.read_advance = Duration::from_secs(31);
    assert!(runtime_reason(&execute_fixture(h)).contains("deadline"));
}
#[test]
fn native_reads_receive_decreasing_remaining_budget() {
    let mut h = fake();
    h.read_advance = Duration::from_secs(1);
    h.post_images
        .borrow_mut()
        .push_back(post_image(IMAGE, "Deleting", "/fixture/image"));
    let mut s =
        RuntimeSession::prepare_disposable(h, &Cancellation::default(), IMAGE, &[DEVICE.into()])
            .unwrap();
    let q = request(&s);
    let m = Memory {
        records: RefCell::new(vec![]),
        fail_started: false,
    };
    let r = s.execute_with(&q, &Cancellation::default(), &m).unwrap();
    assert_eq!(
        r.record.runtime_context.unwrap().items[1].state,
        ItemState::Succeeded
    );
    let budgets = s.host.budgets.borrow();
    assert_eq!(budgets.len(), 4);
    assert_eq!(budgets[0], SETTLE_WINDOW);
    assert!(budgets.windows(2).all(|w| w[1] < w[0]));
}
#[test]
fn cancellation_after_effect_is_unknown_without_postcheck() {
    let cancel = Cancellation::default();
    let mut h = fake();
    h.cancellation = Some(cancel.clone());
    let mut s = RuntimeSession::prepare_disposable(h, &cancel, IMAGE, &[DEVICE.into()]).unwrap();
    let q = request(&s);
    let m = Memory {
        records: RefCell::new(vec![]),
        fail_started: false,
    };
    let r = s.execute_with(&q, &cancel, &m).unwrap();
    assert!(runtime_reason(&r).contains("cancelled;observations=0"));
    assert!(s.host.budgets.borrow().is_empty());
}
#[test]
fn read_failure_cap_and_malformed_observation_latch_unknown() {
    let mut h = fake();
    h.read_failure = true;
    assert!(runtime_reason(&execute_fixture(h)).contains("read_failed"));
    let mut h = fake();
    h.read_cap = true;
    assert!(runtime_reason(&execute_fixture(h)).contains("read_failed_or_capped"));
    let mut h = fake();
    h.malformed_device = true;
    assert!(runtime_reason(&execute_fixture(h)).contains("invalid_devices"));
    let h = fake();
    h.post_images
        .borrow_mut()
        .push_back(serde_json::json!({"invalid":{}}));
    assert!(runtime_reason(&execute_fixture(h)).contains("invalid_images"));
}
#[test]
fn changed_tool_or_activity_latches_unknown_before_observation() {
    let mut h = fake();
    h.changed_tool = true;
    assert!(
        runtime_reason(&execute_fixture(h)).contains("tool_changed_or_unavailable;observations=0")
    );
    let mut h = fake();
    h.activity = true;
    assert!(
        runtime_reason(&execute_fixture(h))
            .contains("activity_changed_or_unavailable;observations=0")
    );
}

#[test]
fn registration_absence_does_not_certify_retained_asset_path() {
    let mut h = fake();
    h.asset_present = true;
    assert!(runtime_reason(&execute_fixture(h)).contains("deadline_asset_path_present"));
}
#[test]
fn unavailable_asset_path_observation_is_not_absence() {
    let mut h = fake();
    h.asset_error = true;
    assert!(runtime_reason(&execute_fixture(h)).contains("asset_path_unavailable;observations=1"));
}

#[test]
fn registration_reappearing_while_asset_remains_is_unknown() {
    let mut h = fake();
    h.asset_present = true;
    h.post_images.borrow_mut().push_back(serde_json::json!({}));
    h.post_images
        .borrow_mut()
        .push_back(post_image(IMAGE, "Deleting", "/fixture/image"));
    assert!(runtime_reason(&execute_fixture(h)).contains("runtime_reappeared;observations=2"));
}

#[test]
fn nonzero_runtime_absence_does_not_bypass_asset_confirmation() {
    let mut h = fake();
    h.nonzero_image = true;
    let r = execute_fixture(h);
    assert_eq!(
        runtime_reason(&r),
        "runtime_absence_after_nonzero_exit;observations=1"
    );
}
