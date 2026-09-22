// SPDX-License-Identifier: MPL-2.0

//! Native fixture checks for the bundle uninstall session. These prepare and
//! inspect sealed plans only; the sole native effect in this file is the
//! creation/removal of the owned fixture directory itself. No Trash move is
//! executed here (operator-driven acceptance covers the move round-trip).

use sayaka_engine::execute::BundleUninstallSession;
use sayaka_engine::model::{Cancellation, ExecutionContract, ReasonCode, Scope};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

struct FixtureDir(PathBuf);

impl FixtureDir {
    fn new() -> Self {
        // Trash admission refuses /var and /private roots, so the fixture
        // lives beneath the crate directory like the platform fixtures.
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::current_dir()
            .expect("cwd")
            .join(format!("uninstall-fixture-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&root).expect("create fixture root");
        Self(root)
    }

    fn bundle(&self, name: &str) -> PathBuf {
        let bundle = self.0.join(name);
        fs::create_dir_all(bundle.join("Contents").join("MacOS")).expect("bundle tree");
        fs::write(bundle.join("Contents").join("Info.plist"), b"plist").expect("plist");
        fs::write(bundle.join("Contents").join("MacOS").join("Run"), b"inert").expect("exe");
        bundle
    }
}

impl Drop for FixtureDir {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!("uninstall fixture cleanup failed: {error}");
        }
    }
}

#[test]
fn bundle_session_prepares_sealed_directory_plan_without_effect() {
    let fixture = FixtureDir::new();
    let bundle = fixture.bundle("Fixture.app");
    let scope = Scope::new(fixture.0.clone(), vec![]).expect("scope");
    let mut session =
        BundleUninstallSession::prepare(scope, &bundle, &Cancellation::default()).expect("prepare");
    let plan = session.preview();
    assert_eq!(
        plan.execution_contract(),
        ExecutionContract::RevalidatedBundleTrashV1
    );
    assert_eq!(plan.schema_version(), 4);
    assert_eq!(
        plan.items().len(),
        1,
        "issues: {:?}, refusals: {:?}",
        session.issues(),
        session.refusals()
    );
    assert!(
        session.approve(&plan.clone()).map(|_| ()).is_ok(),
        "approval must succeed for a clear non-running bundle"
    );
    // Nothing moved: approval alone has no effect.
    assert!(bundle.join("Contents/Info.plist").exists());
}

#[test]
fn bundle_contract_rejects_file_targets() {
    let fixture = FixtureDir::new();
    let file = fixture.0.join("ordinary.txt");
    fs::write(&file, b"x").expect("file");
    let scope = Scope::new(fixture.0.clone(), vec![]).expect("scope");
    let session =
        BundleUninstallSession::prepare(scope, &file, &Cancellation::default()).expect("prepare");
    assert!(session.preview().items().is_empty());
    assert!(
        session
            .refusals()
            .iter()
            .any(|refusal| refusal.reason == ReasonCode::UnsupportedResource.as_str())
    );
}
