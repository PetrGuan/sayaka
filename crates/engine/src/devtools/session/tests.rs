use super::*;
use serde_json::json;
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::Duration;

const A: &str = "AAAAAAAA-0000-0000-0000-000000000001";
const B: &str = "AAAAAAAA-0000-0000-0000-000000000002";
const WATCH: &str = "AAAAAAAA-0000-0000-0000-000000000003";
const PHONE: &str = "AAAAAAAA-0000-0000-0000-000000000004";
const RUNTIME: &str = "com.apple.CoreSimulator.SimRuntime.iOS-27-0";

fn device(udid: &str, name: &str, state: &str, size: u64) -> serde_json::Value {
    json!({
        "udid": udid, "name": name, "state": state, "isAvailable": true,
        "dataPath": format!("/fixture/Devices/{udid}/data"), "dataPathSize": size,
        "deviceTypeIdentifier": "com.apple.CoreSimulator.SimDeviceType.iPhone-17"
    })
}

fn devices(list: &[serde_json::Value]) -> String {
    json!({ "devices": { RUNTIME: list } }).to_string()
}

fn no_pairs() -> String {
    json!({ "pairs": {} }).to_string()
}

#[derive(Default)]
struct Fake {
    devices: RefCell<String>,
    pairs: RefCell<String>,
    /// Device list that replaces `devices` after an execution call.
    after: RefCell<Option<String>>,
    execute_failure: RefCell<Option<ToolFailure>>,
    execute_success: Cell<bool>,
    list_failure_after_execute: Cell<bool>,
    executed: Cell<bool>,
    calls: RefCell<Vec<Vec<String>>>,
    activity: RefCell<Vec<String>>,
    activity_error: Cell<bool>,
    tool: RefCell<String>,
    macos: RefCell<Option<String>>,
    xcode: RefCell<Option<String>>,
    mtime: Cell<i128>,
    /// Models a device whose data does not change on erase.
    freeze_mtime: Cell<bool>,
    elapsed: Cell<Duration>,
    base: Option<Instant>,
}

fn fake(list: &[serde_json::Value]) -> Rc<Fake> {
    let fake = Fake {
        base: Some(Instant::now()),
        ..Fake::default()
    };
    *fake.devices.borrow_mut() = devices(list);
    *fake.pairs.borrow_mut() = no_pairs();
    *fake.tool.borrow_mut() = "/x/simctl|/x/simctl|1:2|3|4".into();
    *fake.macos.borrow_mut() = Some("27.0.1".into());
    *fake.xcode.borrow_mut() = Some("27.0".into());
    fake.execute_success.set(true);
    fake.mtime.set(100);
    Rc::new(fake)
}

impl Host for Rc<Fake> {
    fn tool_identity(&self) -> Result<ToolIdentity, ToolFailure> {
        Ok(ToolIdentity {
            fingerprint: self.tool.borrow().clone(),
            real_path: PathBuf::from("/Applications/Xcode.app/Contents/Developer/usr/bin/simctl"),
        })
    }
    fn tool_versions(&self, _: &ToolIdentity) -> ToolVersions {
        ToolVersions {
            macos: self.macos.borrow().clone(),
            xcode: self.xcode.borrow().clone(),
        }
    }
    fn run(&self, args: &[String], execute: bool) -> Result<ToolResult, ToolFailure> {
        self.calls.borrow_mut().push(args.to_vec());
        if execute {
            assert!(matches!(args[1].as_str(), "erase" | "delete"));
            self.executed.set(true);
            if let Some(after) = self.after.borrow_mut().take() {
                *self.devices.borrow_mut() = after;
            }
            if let Some(failure) = self.execute_failure.borrow_mut().take() {
                return Err(failure);
            }
            if !self.freeze_mtime.get() {
                self.mtime.set(self.mtime.get() + 1);
            }
            return Ok(ToolResult {
                success: self.execute_success.get(),
                stdout: Vec::new(),
                stderr: if self.execute_success.get() {
                    Vec::new()
                } else {
                    b"Unable to delete".to_vec()
                },
            });
        }
        assert_eq!(args[1], "list");
        if self.executed.get() && self.list_failure_after_execute.get() {
            return Err(ToolFailure::Timeout);
        }
        let stdout = match args[2].as_str() {
            "devices" => self.devices.borrow().clone(),
            "pairs" => self.pairs.borrow().clone(),
            other => panic!("unexpected list {other}"),
        };
        Ok(ToolResult {
            success: true,
            stdout: stdout.into_bytes(),
            stderr: Vec::new(),
        })
    }
    fn developer_activity(&self) -> io::Result<Vec<String>> {
        if self.activity_error.get() {
            return Err(io::Error::other("process table unreadable"));
        }
        Ok(self.activity.borrow().clone())
    }
    fn data_modified_unix_ns(&self, _: &Path) -> Option<i128> {
        Some(self.mtime.get())
    }
    fn data_identity(&self, path: &Path) -> Option<(u64, u64)> {
        Some((1, path.as_os_str().len() as u64))
    }
    fn now(&self) -> Instant {
        self.base.unwrap() + self.elapsed.get()
    }
}

#[derive(Default)]
struct MemJournal {
    records: RefCell<Vec<Record>>,
    fail_on: Cell<usize>,
    calls: Cell<usize>,
}

impl ToolJournal for MemJournal {
    fn new_id(&self) -> io::Result<String> {
        Ok("7-a".into())
    }
    fn publish(&self, record: &Record, _: bool) -> io::Result<journal::Publication> {
        record.validate()?;
        self.calls.set(self.calls.get() + 1);
        if self.calls.get() == self.fail_on.get() {
            return Err(io::Error::other("injected journal failure"));
        }
        self.records.borrow_mut().push(record.clone());
        Ok(journal::Publication::default())
    }
}

fn request(session: &SimulatorSession<Rc<Fake>>, items: &[&str]) -> ExecuteRequest {
    ExecuteRequest {
        plan_digest: session.preview().plan_digest.clone(),
        items: items.iter().map(|udid| (*udid).to_owned()).collect(),
        approval_token: session.approval_phrase(items.len()),
    }
}

fn executions(fake: &Fake) -> Vec<Vec<String>> {
    fake.calls
        .borrow()
        .iter()
        .filter(|args| args[1] != "list")
        .cloned()
        .collect()
}

fn prepare(host: &Rc<Fake>, operation: Operation) -> SimulatorSession<Rc<Fake>> {
    SimulatorSession::prepare(host.clone(), operation, &Cancellation::default()).unwrap()
}

fn run(session: &mut SimulatorSession<Rc<Fake>>, items: &[&str]) -> ExecutionReport {
    let request = request(session, items);
    session
        .execute_with(&request, &Cancellation::default(), &MemJournal::default())
        .unwrap()
}

#[test]
fn preview_is_effect_free_and_sealed() {
    let host = fake(&[
        device(A, "iPhone", "Shutdown", 10),
        device(B, "Booted one", "Booted", 5),
    ]);
    let session = prepare(&host, Operation::Delete);
    let preview = session.preview();
    assert_eq!(preview.effect_class, "permanent_tool_operation_v1");
    assert_eq!(preview.candidates.len(), 2);
    assert!(
        preview
            .candidates
            .iter()
            .any(|c| c.device.udid == B && !c.eligible())
    );
    assert_eq!(preview.plan_digest.len(), 64);
    assert!(executions(&host).is_empty());
}

#[test]
fn old_or_unknown_versions_are_unsupported() {
    for (macos, xcode) in [
        (Some("25.6"), Some("27.0")),
        (Some("27.0"), Some("16.4")),
        (None, Some("27.0")),
        (Some("27.0"), None),
    ] {
        let host = fake(&[device(A, "iPhone", "Shutdown", 10)]);
        *host.macos.borrow_mut() = macos.map(str::to_owned);
        *host.xcode.borrow_mut() = xcode.map(str::to_owned);
        let error =
            SimulatorSession::prepare(host.clone(), Operation::Delete, &Cancellation::default())
                .err()
                .unwrap();
        assert_eq!(error.code(), "unsupported_tool_version");
        assert!(host.calls.borrow().is_empty());
    }
}

#[test]
fn malformed_list_fails_the_preview_closed() {
    let host = fake(&[]);
    *host.devices.borrow_mut() = "{\"devices\": []}".into();
    let error = SimulatorSession::prepare(host, Operation::Erase, &Cancellation::default())
        .err()
        .unwrap();
    assert_eq!(error.code(), "parse_failed");
}

#[test]
fn approval_requires_digest_phrase_and_valid_selection() {
    let host = fake(&[
        device(A, "iPhone", "Shutdown", 10),
        device(B, "Booted one", "Booted", 5),
    ]);
    let session = prepare(&host, Operation::Delete);
    let mut wrong_digest = request(&session, &[A]);
    wrong_digest.plan_digest = "0".repeat(64);
    let mut wrong_phrase = request(&session, &[A]);
    wrong_phrase.approval_token = "erase 1 simulators".into();
    let mut wrong_count = request(&session, &[A]);
    wrong_count.approval_token = "delete 2 simulators".into();
    for bad in [
        wrong_digest,
        wrong_phrase,
        wrong_count,
        request(&session, &[B]),
        request(&session, &[A, A]),
        request(&session, &[]),
    ] {
        assert_eq!(
            session.check_approval(&bad).unwrap_err().code(),
            "invalid_request"
        );
    }
    assert!(session.check_approval(&request(&session, &[A])).is_ok());
}

#[test]
fn expired_preview_is_refused_without_journal_or_call() {
    let host = fake(&[device(A, "iPhone", "Shutdown", 10)]);
    let mut session = prepare(&host, Operation::Delete);
    host.elapsed.set(PREVIEW_TTL);
    let journal = MemJournal::default();
    let error = session
        .execute_with(&request(&session, &[A]), &Cancellation::default(), &journal)
        .unwrap_err();
    assert_eq!(error, SessionError::Expired);
    assert!(journal.records.borrow().is_empty());
    assert!(executions(&host).is_empty());
}

#[test]
fn developer_activity_refuses_the_whole_request() {
    let host = fake(&[device(A, "iPhone", "Shutdown", 10)]);
    let mut session = prepare(&host, Operation::Delete);
    host.activity
        .borrow_mut()
        .push("/Applications/Xcode.app/Contents/MacOS/Xcode".into());
    let journal = MemJournal::default();
    let error = session
        .execute_with(&request(&session, &[A]), &Cancellation::default(), &journal)
        .unwrap_err();
    assert_eq!(error.code(), "developer_activity");
    assert!(journal.records.borrow().is_empty());
    assert!(executions(&host).is_empty());
    // An activity refusal keeps the preview; after Xcode quits it can run once.
    host.activity.borrow_mut().clear();
    *host.after.borrow_mut() = Some(devices(&[]));
    let report = session
        .execute_with(&request(&session, &[A]), &Cancellation::default(), &journal)
        .unwrap();
    assert_eq!(report.record.items[0].state, ItemState::Succeeded);
    assert_eq!(
        session
            .execute_with(&request(&session, &[A]), &Cancellation::default(), &journal)
            .unwrap_err(),
        SessionError::Consumed
    );
}

#[test]
fn unreadable_process_table_fails_closed() {
    let host = fake(&[device(A, "iPhone", "Shutdown", 10)]);
    let mut session = prepare(&host, Operation::Delete);
    host.activity_error.set(true);
    let error = session
        .execute_with(
            &request(&session, &[A]),
            &Cancellation::default(),
            &MemJournal::default(),
        )
        .unwrap_err();
    assert_eq!(
        error,
        SessionError::DeveloperActivity {
            executables: vec![]
        }
    );
}

#[test]
fn tool_change_after_preview_is_refused() {
    let host = fake(&[device(A, "iPhone", "Shutdown", 10)]);
    let mut session = prepare(&host, Operation::Delete);
    *host.tool.borrow_mut() = "/x/simctl|/x/simctl|1:2|3|5".into();
    let error = session
        .execute_with(
            &request(&session, &[A]),
            &Cancellation::default(),
            &MemJournal::default(),
        )
        .unwrap_err();
    assert_eq!(error, SessionError::ToolChanged);
    assert!(executions(&host).is_empty());
}

#[test]
fn journal_intent_failure_runs_nothing() {
    let host = fake(&[device(A, "iPhone", "Shutdown", 10)]);
    let mut session = prepare(&host, Operation::Delete);
    let journal = MemJournal::default();
    journal.fail_on.set(1);
    let error = session
        .execute_with(&request(&session, &[A]), &Cancellation::default(), &journal)
        .unwrap_err();
    assert_eq!(error.code(), "journal_unavailable");
    assert!(executions(&host).is_empty());
}

#[test]
fn started_publication_failure_runs_nothing() {
    let host = fake(&[device(A, "iPhone", "Shutdown", 10)]);
    let mut session = prepare(&host, Operation::Delete);
    let journal = MemJournal::default();
    journal.fail_on.set(2);
    let report = session
        .execute_with(&request(&session, &[A]), &Cancellation::default(), &journal)
        .unwrap();
    assert!(executions(&host).is_empty());
    assert_eq!(report.record.items[0].state, ItemState::Skipped);
    assert!(report.journal_error.is_some());
}

#[test]
fn delete_succeeds_when_the_identity_disappears() {
    let host = fake(&[
        device(A, "iPhone", "Shutdown", 10),
        device(B, "iPad", "Shutdown", 7),
    ]);
    let mut session = prepare(&host, Operation::Delete);
    *host.after.borrow_mut() = Some(devices(&[device(B, "iPad", "Shutdown", 7)]));
    let journal = MemJournal::default();
    let report = session
        .execute_with(&request(&session, &[A]), &Cancellation::default(), &journal)
        .unwrap();
    assert_eq!(
        executions(&host),
        vec![vec!["simctl".to_string(), "delete".into(), A.into()]]
    );
    assert_eq!(report.record.items[0].state, ItemState::Succeeded);
    assert!(report.record.items[0].destination.is_none());
    assert_eq!(report.record.contract, "permanent_tool_operation_v1");
    assert_eq!(report.exit_code(), 0);
    let records = journal.records.borrow();
    assert_eq!(records[0].items[0].state, ItemState::Planned);
    assert!(
        records
            .iter()
            .any(|r| r.items[0].state == ItemState::Started)
    );
    let intent = records[0].tool_operation.as_ref().unwrap();
    assert_eq!(intent.operation, "delete");
    assert_eq!(intent.devices[0].udid, A);
    assert_eq!(intent.plan_digest, session.preview().plan_digest);
}

#[test]
fn delete_still_present_after_success_exit_is_unknown_and_after_failure_is_failed() {
    for (success, expected) in [(true, ItemState::Unknown), (false, ItemState::Failed)] {
        let host = fake(&[device(A, "iPhone", "Shutdown", 10)]);
        host.execute_success.set(success);
        let mut session = prepare(&host, Operation::Delete);
        let report = run(&mut session, &[A]);
        assert_eq!(report.record.items[0].state, expected);
    }
}

#[test]
fn erase_needs_an_observable_change() {
    let host = fake(&[device(A, "iPhone", "Shutdown", 10)]);
    let mut session = prepare(&host, Operation::Erase);
    *host.after.borrow_mut() = Some(devices(&[device(A, "iPhone", "Shutdown", 1)]));
    let report = run(&mut session, &[A]);
    assert_eq!(executions(&host)[0][1], "erase");
    assert_eq!(report.record.items[0].state, ItemState::Succeeded);
}

#[test]
fn timeout_is_unknown_and_stops_later_batches() {
    let udids: Vec<String> = (1..=10)
        .map(|n| format!("BBBBBBBB-0000-0000-0000-{n:012}"))
        .collect();
    let list: Vec<_> = udids
        .iter()
        .map(|udid| device(udid, "Phone", "Shutdown", 1))
        .collect();
    let host = fake(&list);
    *host.execute_failure.borrow_mut() = Some(ToolFailure::Timeout);
    let mut session = prepare(&host, Operation::Delete);
    let refs: Vec<&str> = udids.iter().map(String::as_str).collect();
    let report = run(&mut session, &refs);
    assert_eq!(executions(&host).len(), 1);
    assert_eq!(executions(&host)[0].len(), 2 + MAX_BATCH);
    assert!(
        report.record.items[..MAX_BATCH]
            .iter()
            .all(|item| item.state == ItemState::Unknown)
    );
    assert!(report.record.items[MAX_BATCH..].iter().all(|item| {
        item.state == ItemState::Skipped
            && item.reason.as_deref() == Some("stopped_after_ambiguous_outcome")
    }));
    assert_eq!(report.exit_code(), 1);
}

#[test]
fn post_check_failure_is_unknown() {
    let host = fake(&[device(A, "iPhone", "Shutdown", 10)]);
    host.list_failure_after_execute.set(true);
    let mut session = prepare(&host, Operation::Delete);
    let report = run(&mut session, &[A]);
    assert_eq!(report.record.items[0].state, ItemState::Unknown);
}

#[test]
fn device_booted_after_preview_refuses_its_batch_without_a_call() {
    let host = fake(&[device(A, "iPhone", "Shutdown", 10)]);
    let mut session = prepare(&host, Operation::Delete);
    *host.devices.borrow_mut() = devices(&[device(A, "iPhone", "Booted", 10)]);
    let report = run(&mut session, &[A]);
    assert!(executions(&host).is_empty());
    assert_eq!(report.record.items[0].state, ItemState::Skipped);
    assert!(
        report.record.items[0]
            .reason
            .as_deref()
            .unwrap()
            .starts_with("revalidation_mismatch: not_shutdown")
    );
}

#[test]
fn pairs_are_deleted_together_in_one_call() {
    let host = fake(&[
        device(WATCH, "Watch", "Shutdown", 1),
        device(PHONE, "Phone", "Shutdown", 1),
        device(A, "Other", "Shutdown", 1),
    ]);
    *host.pairs.borrow_mut() = json!({ "pairs": { "P": {
        "watch": { "udid": WATCH, "name": "Watch", "state": "Shutdown" },
        "phone": { "udid": PHONE, "name": "Phone", "state": "Shutdown" },
        "state": "(active, disconnected)"
    }}})
    .to_string();
    *host.after.borrow_mut() = Some(devices(&[]));
    let mut session = prepare(&host, Operation::Delete);
    let report = run(&mut session, &[WATCH, A, PHONE]);
    let calls = executions(&host);
    assert_eq!(calls.len(), 1);
    assert_eq!(&calls[0][2..], [WATCH, PHONE, A]);
    assert!(
        report
            .record
            .items
            .iter()
            .all(|item| item.state == ItemState::Succeeded)
    );
}

#[test]
fn pair_batches_never_split_a_pair() {
    let candidate = |udid: &str, partner: Option<&str>| Candidate {
        device: parse_devices(devices(&[device(udid, "x", "Shutdown", 1)]).as_bytes())
            .unwrap()
            .remove(0),
        paired_with: partner.map(str::to_owned),
        refusals: vec![],
    };
    let mut candidates = Vec::new();
    let mut selected = Vec::new();
    for n in 0..7 {
        let udid = format!("CCCCCCCC-0000-0000-0000-{n:012}");
        candidates.push(candidate(&udid, None));
        selected.push(udid);
    }
    for (me, partner) in [(WATCH, PHONE), (PHONE, WATCH)] {
        candidates.push(candidate(me, Some(partner)));
        selected.push(me.into());
    }
    let batches = pair_batches(&candidates, &selected);
    assert_eq!(batches.len(), 2);
    assert_eq!(batches[0].len(), 7);
    assert_eq!(batches[1], [WATCH, PHONE]);
}

#[test]
fn cancellation_before_execution_runs_nothing() {
    let host = fake(&[device(A, "iPhone", "Shutdown", 10)]);
    let mut session = prepare(&host, Operation::Delete);
    let cancel = Cancellation::default();
    let request = request(&session, &[A]);
    cancel.cancel();
    assert_eq!(
        session
            .execute_with(&request, &cancel, &MemJournal::default())
            .unwrap_err(),
        SessionError::Cancelled
    );
    assert!(executions(&host).is_empty());
}

#[test]
fn reads_version_plist_strings() {
    let plist = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>BuildVersion</key><string>2</string>
<key>Nested</key><dict><key>CFBundleShortVersionString</key><string>1.0</string></dict>
<key>CFBundleShortVersionString</key><string>27.0</string>
</dict></plist>"#;
    assert_eq!(
        plist_string(plist, "CFBundleShortVersionString").as_deref(),
        Some("27.0")
    );
    assert_eq!(plist_string(plist, "Missing"), None);
    assert_eq!(version_major(Some("27.0.1")), Some(27));
    assert_eq!(version_major(Some("beta")), None);
    assert_eq!(
        xcode_version_plist(Path::new(
            "/Applications/Xcode.app/Contents/Developer/usr/bin/simctl"
        )),
        Some(PathBuf::from(
            "/Applications/Xcode.app/Contents/version.plist"
        ))
    );
}

#[test]
fn tool_records_are_valid_and_trash_records_reject_tool_intent() {
    let host = fake(&[device(A, "iPhone", "Shutdown", 10)]);
    let mut session = prepare(&host, Operation::Delete);
    *host.after.borrow_mut() = Some(devices(&[]));
    let mut record = run(&mut session, &[A]).record;
    record.validate().unwrap();
    let mut without_intent = record.clone();
    without_intent.tool_operation = None;
    assert!(without_intent.validate().is_err());
    let mut as_trash = record.clone();
    as_trash.contract = "revalidated_trash_v1".into();
    assert!(as_trash.validate().is_err());
    record.items[0].destination = Some(NativePath::from_path(Path::new("/x/.Trash/data")));
    assert!(record.validate().is_err());
}

fn many(prefix: &str, count: usize) -> Vec<String> {
    (1..=count)
        .map(|n| format!("{prefix}-0000-0000-0000-{n:012}"))
        .collect()
}

#[test]
fn delete_still_listed_after_success_exit_stops_later_batches() {
    let udids = many("DDDDDDDD", 10);
    let list: Vec<_> = udids
        .iter()
        .map(|udid| device(udid, "Phone", "Shutdown", 1))
        .collect();
    let host = fake(&list);
    let mut session = prepare(&host, Operation::Delete);
    let refs: Vec<&str> = udids.iter().map(String::as_str).collect();
    let report = run(&mut session, &refs);
    assert_eq!(executions(&host).len(), 1);
    assert!(report.record.items[..MAX_BATCH].iter().all(|item| {
        item.state == ItemState::Unknown
            && item.reason.as_deref() == Some("still_listed_after_success_exit")
    }));
    assert!(
        report.record.items[MAX_BATCH..]
            .iter()
            .all(|item| item.state == ItemState::Skipped)
    );
}

#[test]
fn erase_of_already_empty_devices_continues_with_later_batches() {
    let udids = many("EEEEEEEE", 10);
    let list: Vec<_> = udids
        .iter()
        .map(|udid| device(udid, "Phone", "Shutdown", 1))
        .collect();
    let host = fake(&list);
    host.freeze_mtime.set(true);
    let mut session = prepare(&host, Operation::Erase);
    let refs: Vec<&str> = udids.iter().map(String::as_str).collect();
    let report = run(&mut session, &refs);
    assert_eq!(executions(&host).len(), 2);
    assert!(report.record.items.iter().all(|item| {
        item.state == ItemState::Unknown
            && item.reason.as_deref() == Some("exited_without_observable_change")
    }));
}

#[test]
fn failing_erase_batch_with_changed_data_is_unknown_not_failed() {
    let host = fake(&[device(A, "iPhone", "Shutdown", 10)]);
    host.execute_success.set(false);
    *host.after.borrow_mut() = Some(devices(&[device(A, "iPhone", "Shutdown", 1)]));
    let mut session = prepare(&host, Operation::Erase);
    let report = run(&mut session, &[A]);
    assert_eq!(report.record.items[0].state, ItemState::Unknown);
    assert!(
        report.record.items[0]
            .reason
            .as_deref()
            .unwrap()
            .starts_with("failed_after_data_changed")
    );
}

#[test]
fn journal_inside_a_device_is_refused() {
    let host = fake(&[device(A, "iPhone", "Shutdown", 10)]);
    let session = prepare(&host, Operation::Delete);
    let inside = PathBuf::from(format!("/fixture/Devices/{A}/journal"));
    assert_eq!(
        session.check_state_dir(&inside).unwrap_err().code(),
        "invalid_request"
    );
    assert!(session.check_state_dir(Path::new("/fixture/state")).is_ok());
}
