// SPDX-License-Identifier: MPL-2.0

mod support;

use sayaka_engine::Planner;
use sayaka_engine::model::*;
use sayaka_engine::receipt::{Receipt, ReceiptState};
use std::fs;
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

struct FixtureProbe;

impl Probe for FixtureProbe {
    fn inspect(&mut self, scope: &Scope, path: &Path) -> Result<Snapshot, ProbeError> {
        assert!(path.starts_with(scope.root()));
        let identity = if path == scope.root().join("target.txt") {
            1
        } else if path == scope.root().join("protected/keep.txt") {
            2
        } else {
            return Err(ProbeError::NotFound);
        };
        let metadata =
            fs::symlink_metadata(path).map_err(|error| ProbeError::Other(error.to_string()))?;
        assert!(metadata.is_file());
        // Synthetic evidence exercises the embedding contract, not OS identity
        // or trash capability. This test probe cannot authorize real effects.
        Ok(Snapshot {
            identity: Some(FileIdentity::Unix {
                device: 0,
                inode: identity,
            }),
            kind: ResourceKind::File,
            logical_bytes: Some(metadata.len()),
            modified_at: Some(UNIX_EPOCH),
            complete: true,
            boundary: Boundary::Verified,
            protection: Protection::Clear,
            trash: Capability::Available,
            owner: OwnerState::NotApplicable,
        })
    }
}

fn run_flow(root: &Path) {
    assert_eq!(
        fs::read(root.join("owner-marker")).unwrap(),
        b"sayaka-m1-owned-fixture"
    );
    let scope = Scope::new(root.to_path_buf(), vec![root.join("protected")]).unwrap();
    let mut planner = Planner::new(
        scope,
        Versions {
            engine: 1,
            rules: 1,
        },
    )
    .unwrap();
    let mut probe = FixtureProbe;
    let target = planner
        .discover(&root.join("target.txt"), &mut probe)
        .unwrap()
        .observation()
        .id();
    let protected = planner
        .discover(&root.join("protected/keep.txt"), &mut probe)
        .unwrap()
        .observation()
        .id();
    let plan = planner
        .prepare(&[target, protected], &[], Duration::from_secs(60))
        .unwrap();
    assert_eq!(plan.items().len(), 1);
    assert_eq!(plan.rejected()[0].resource, protected);
    assert_eq!(plan.rejected()[0].code, ReasonCode::Protected);
    let approval = planner.approve(&plan).unwrap();
    let report = planner
        .validate(&plan, &approval, &mut probe, &Cancellation::default())
        .unwrap();
    assert_eq!(report.ready.len(), 1);
    assert!(report.skipped.is_empty());
    let receipt = Receipt::new(&plan, target).unwrap();
    assert_eq!(receipt.state(), ReceiptState::Planned);
    assert_eq!(
        fs::read(root.join("target.txt")).unwrap(),
        b"test-owned target"
    );
    assert_eq!(
        fs::read(root.join("protected/keep.txt")).unwrap(),
        b"must remain unchanged"
    );
}

#[test]
fn isolated_plan_round_trip() {
    if let Some(root) = std::env::var_os("SAYAKA_M1_CHILD_ROOT") {
        if std::env::var_os("SAYAKA_M1_CHILD_PARK").is_some() {
            loop {
                std::thread::park();
            }
        }
        run_flow(Path::new(&root));
        println!("M1_FIXTURE_READY=1");
    } else {
        let fixture = support::Fixture::new().unwrap();
        let root = fixture.path().to_path_buf();
        run_flow(&root);
        let (status, stdout, stderr) = support::run_child(&root).unwrap();
        assert!(
            status.success(),
            "child failed: {status}\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert!(
            stdout.contains("M1_FIXTURE_READY=1"),
            "child did not complete the real flow: {stdout}"
        );
        run_flow(&root);
        fixture.close().expect("explicit fixture cleanup failed");
        assert!(!root.exists());
    }
}

#[test]
fn child_failures_are_reported_and_fixtures_are_removed() {
    let fixture = support::Fixture::new().unwrap();
    let root = fixture.path().to_path_buf();
    fs::write(root.join("owner-marker"), b"fault-injected invalid marker").unwrap();
    let (status, stdout, stderr) = support::run_child(&root).unwrap();
    assert!(!status.success());
    assert!(!stdout.contains("M1_FIXTURE_READY=1"));
    assert!(stderr.contains("assertion"), "{stderr}");
    fixture.close().expect("cleanup after failed child failed");
    assert!(!root.exists());
}

#[test]
fn stalled_owned_child_is_terminated_and_reaped_before_cleanup() {
    let fixture = support::Fixture::new().unwrap();
    let root = fixture.path().to_path_buf();
    let error =
        support::run_child_with_timeout(&root, Duration::from_millis(50), true).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    fixture
        .close()
        .expect("cleanup after timed-out child failed");
    assert!(!root.exists());
}
