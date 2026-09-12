// SPDX-License-Identifier: MPL-2.0

use super::*;
use crossterm::event::{KeyCode, KeyModifiers};
use jobs::PlanDisplay;
use model::Command as Action;
use sayaka_engine::execute::TrashSession;
use sayaka_engine::model::Scope;
use std::fs;
use std::os::unix::fs::{MetadataExt, symlink};
use std::thread;
use tempfile::TempDir;

struct Fixture {
    directory: Option<TempDir>,
    root: PathBuf,
    identity: (u64, u64),
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::Builder::new()
            .prefix("sayaka-browser-test-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .unwrap();
        let base = directory.path().canonicalize().unwrap();
        fs::write(base.join("ownership-marker"), b"sayaka-m7-owned-fixture").unwrap();
        let root = base.join("root");
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("folder")).unwrap();
        fs::write(root.join("folder/nested.txt"), b"nested content").unwrap();
        fs::write(root.join("file.txt"), b"payload").unwrap();
        fs::write(root.join("zero.txt"), b"").unwrap();
        let info = fs::metadata(&base).unwrap();
        Self {
            directory: Some(directory),
            root,
            identity: (info.dev(), info.ino()),
        }
    }
    fn data(&self) -> BrowserData {
        let report = scan::scan(
            std::slice::from_ref(&self.root),
            &ScanLimits::default(),
            &Cancellation::default(),
            |_| {},
        )
        .unwrap();
        assert!(report.complete);
        BrowserData::build(report, &Cancellation::default()).unwrap()
    }
    fn app(&self) -> App {
        let mut app = App::new(self.root.clone());
        app.accept_scan(app.generation, self.data()).unwrap();
        app
    }
    fn preview(&self) -> PlanDisplay {
        let session = TrashSession::prepare(
            Scope::new(self.root.clone(), vec![]).unwrap(),
            &[self.root.join("file.txt")],
            &[],
            &Cancellation::default(),
        )
        .unwrap();
        assert_eq!(session.preview().items().len(), 1, "{:?}", session.issues());
        PlanDisplay {
            plan: session.preview().clone(),
            refusals: session.refusals(),
            issues: session.issues().to_vec(),
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let Some(directory) = self.directory.take() else {
            return;
        };
        let info = fs::symlink_metadata(directory.path()).unwrap();
        assert_eq!((info.dev(), info.ino()), self.identity);
        assert_eq!(
            fs::read(directory.path().join("ownership-marker")).unwrap(),
            b"sayaka-m7-owned-fixture"
        );
        directory.close().expect("owned browser fixture cleanup");
    }
}

fn key(app: &mut App, code: KeyCode) -> Action {
    app.key(code, KeyModifiers::NONE).unwrap()
}

fn focus(app: &mut App, name: &str) {
    let data = app.data.as_ref().unwrap();
    app.cursor = app
        .rows
        .iter()
        .position(|id| data.tree.entry(*id).unwrap().path.file_name().unwrap() == name)
        .unwrap();
}

#[test]
fn navigation_filter_sort_and_zero_size_are_consistent() {
    let fixture = Fixture::new();
    let mut app = fixture.app();
    assert_eq!(app.rows.len(), 3);
    focus(&mut app, "folder");
    key(&mut app, KeyCode::Enter);
    assert_eq!(app.rows.len(), 1);
    assert_eq!(
        app.data
            .as_ref()
            .unwrap()
            .entry(app.rows[0])
            .unwrap()
            .path
            .file_name()
            .unwrap(),
        "nested.txt"
    );
    key(&mut app, KeyCode::Left);
    assert_eq!(app.rows.len(), 3);
    key(&mut app, KeyCode::Char('/'));
    for ch in "zero".chars() {
        key(&mut app, KeyCode::Char(ch));
    }
    assert_eq!(app.rows.len(), 1);
    assert_eq!(
        app.data
            .as_ref()
            .unwrap()
            .size(app.rows[0], model::Metric::Logical),
        Some(0)
    );
    key(&mut app, KeyCode::Esc);
    assert_eq!(app.rows.len(), 3);
    key(&mut app, KeyCode::Char('s'));
    assert_eq!(app.sort, model::Sort::Name);
    assert_eq!(
        app.data
            .as_ref()
            .unwrap()
            .entry(app.rows[0])
            .unwrap()
            .path
            .file_name()
            .unwrap(),
        "file.txt"
    );
}

#[test]
fn directories_are_not_selected_and_exclusions_cover_descendants() {
    let fixture = Fixture::new();
    let mut app = fixture.app();
    focus(&mut app, "folder");
    key(&mut app, KeyCode::Char(' '));
    assert!(app.selected.is_empty());
    key(&mut app, KeyCode::Char('x'));
    key(&mut app, KeyCode::Enter);
    assert!(app.is_excluded(app.rows[0]));
    key(&mut app, KeyCode::Char(' '));
    assert_eq!(app.selected.len(), 1);
    assert_eq!(
        app.frozen_selection().unwrap()[0].path,
        fixture.root.join("folder/nested.txt")
    );
    assert_eq!(app.excluded_paths().unwrap(), [fixture.root.join("folder")]);
}

#[test]
fn stale_snapshots_and_old_generations_cannot_authorize_new_actions() {
    let fixture = Fixture::new();
    let mut app = fixture.app();
    focus(&mut app, "file.txt");
    key(&mut app, KeyCode::Char(' '));
    app.stale = true;
    assert_eq!(key(&mut app, KeyCode::Char('t')), Action::None);
    let old_generation = app.generation;
    let data = app.data.take().unwrap();
    app.start_scan().unwrap();
    assert!(app.selected.is_empty());
    app.accept_scan(old_generation, data).unwrap();
    assert!(app.data.is_none());
    app.accept_plan(old_generation, fixture.preview());
    assert!(app.preview.is_none());
}

#[test]
fn plan_confirmation_requires_full_presentation_and_exact_text() {
    let fixture = Fixture::new();
    let mut app = fixture.app();
    app.accept_plan(app.generation, fixture.preview());
    app.preview
        .as_mut()
        .unwrap()
        .lines
        .extend((0..20).map(|index| format!("Additional displayed detail {index}")));
    render::frame(&mut app, 80, 14).unwrap();
    assert_eq!(key(&mut app, KeyCode::Enter), Action::None);
    key(&mut app, KeyCode::End);
    render::frame(&mut app, 80, 14).unwrap();
    assert!(
        app.preview.as_ref().unwrap().seen_through < app.preview.as_ref().unwrap().wrapped.len()
    );
    app.preview.as_mut().unwrap().scroll = 0;
    loop {
        render::frame(&mut app, 80, 14).unwrap();
        let preview = app.preview.as_mut().unwrap();
        if preview.seen_through == preview.wrapped.len() {
            break;
        }
        preview.scroll = preview.seen_through;
    }
    for ch in "yes".chars() {
        key(&mut app, KeyCode::Char(ch));
    }
    assert_eq!(key(&mut app, KeyCode::Enter), Action::None);
    app.preview.as_mut().unwrap().input.clear();
    for ch in "trash 1".chars() {
        key(&mut app, KeyCode::Char(ch));
    }
    assert_eq!(key(&mut app, KeyCode::Enter), Action::Confirm);
    render::frame(&mut app, 40, 10).unwrap();
    assert_eq!(key(&mut app, KeyCode::Enter), Action::None);
    assert_eq!(fs::read(fixture.root.join("file.txt")).unwrap(), b"payload");
}

#[test]
fn prepared_native_worker_can_only_be_cancelled_or_confirmed_for_its_generation() {
    let fixture = Fixture::new();
    let mut app = fixture.app();
    focus(&mut app, "file.txt");
    key(&mut app, KeyCode::Char(' '));
    let state = fixture.root.parent().unwrap().join("state");
    let mut worker = Job::prepare(
        app.generation,
        app.root_entry().unwrap(),
        app.frozen_selection().unwrap(),
        vec![],
        Some(state.clone()),
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let plan = loop {
        if let Some(plan) = worker.take_plan().unwrap() {
            break plan;
        }
        assert!(
            Instant::now() < deadline,
            "owned plan worker did not prepare"
        );
        assert!(!worker.is_finished(), "plan worker ended before preview");
        thread::sleep(Duration::from_millis(5));
    };
    worker.confirm(app.generation + 1, plan.plan.id()).unwrap();
    assert!(worker.finish().is_err());
    assert!(!state.exists());
    assert_eq!(fs::read(fixture.root.join("file.txt")).unwrap(), b"payload");
}

#[test]
fn cancelled_plan_worker_creates_no_journal_or_effect() {
    let fixture = Fixture::new();
    let app = fixture.app();
    let entry = app
        .data
        .as_ref()
        .unwrap()
        .tree
        .report()
        .entries
        .iter()
        .find(|entry| entry.path == fixture.root.join("file.txt"))
        .unwrap()
        .clone();
    let state = fixture.root.parent().unwrap().join("state");
    let mut job = Job::prepare(
        app.generation,
        app.root_entry().unwrap(),
        vec![entry],
        vec![],
        Some(state.clone()),
    )
    .unwrap();
    job.cancel();
    match job.finish() {
        Ok(jobs::ResultValue::Action(ActionResult::Cancelled)) => {}
        Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
        other => panic!(
            "unexpected cancelled plan result: {}",
            match other {
                Ok(_) => "other result".into(),
                Err(error) => error.to_string(),
            }
        ),
    }
    assert!(!state.exists());
    assert_eq!(fs::read(fixture.root.join("file.txt")).unwrap(), b"payload");
}

#[test]
fn external_handoff_rejects_changes_and_symlink_replacement() {
    let fixture = Fixture::new();
    let mut app = fixture.app();
    focus(&mut app, "file.txt");
    let (scope, entry) = app.viewer_entries().unwrap();
    scan::verify_entry(&scope, &entry).unwrap();
    fs::write(&entry.path, b"changed contents").unwrap();
    assert_eq!(
        scan::verify_entry(&scope, &entry).unwrap_err().code,
        scan::ScanCode::ChangedEntry
    );
    fs::rename(&entry.path, fixture.root.join("original")).unwrap();
    symlink("zero.txt", &entry.path).unwrap();
    assert!(scan::verify_entry(&scope, &entry).is_err());
}

#[test]
fn external_handoff_rejects_scope_replacement() {
    let fixture = Fixture::new();
    let mut app = fixture.app();
    focus(&mut app, "file.txt");
    let (scope, entry) = app.viewer_entries().unwrap();
    fs::rename(&fixture.root, fixture.root.with_file_name("old-root")).unwrap();
    fs::create_dir(&fixture.root).unwrap();
    fs::write(&entry.path, b"payload").unwrap();
    assert_eq!(
        scan::verify_entry(&scope, &entry).unwrap_err().code,
        scan::ScanCode::ChangedEntry
    );
}
