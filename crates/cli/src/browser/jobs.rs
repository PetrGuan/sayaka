// SPDX-License-Identifier: MPL-2.0

use super::{model::BrowserData, scan_error};
use sayaka_engine::execute::{ExecutionReport, SelectionIssue, SelectionRefusal, TrashSession};
use sayaka_engine::journal::{self, Store};
use sayaka_engine::model::{Cancellation, Plan, PlanId, ResourceKind, Scope};
use sayaka_engine::scan::{self, ScanEntry, ScanLimits, ScanProgress};
use std::io;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Viewer {
    Reveal,
    Preview,
}

pub struct PlanDisplay {
    pub plan: Plan,
    pub refusals: Vec<SelectionRefusal>,
    pub issues: Vec<SelectionIssue>,
}

pub enum ActionResult {
    Cancelled,
    Executed(Box<ExecutionReport>),
}
pub enum ResultValue {
    Scan(Box<BrowserData>),
    Action(ActionResult),
    Viewer(String),
}

struct Confirmation {
    generation: u64,
    plan: PlanId,
}

pub struct Job {
    generation: u64,
    cancellation: Cancellation,
    handle: Option<JoinHandle<io::Result<ResultValue>>>,
    progress: Option<Arc<Mutex<Option<ScanProgress>>>>,
    preview: Option<mpsc::Receiver<PlanDisplay>>,
    confirmation: Option<mpsc::SyncSender<Confirmation>>,
}

impl Job {
    pub fn scan(generation: u64, root: PathBuf) -> io::Result<Self> {
        let cancellation = Cancellation::default();
        let cancel = cancellation.clone();
        let progress = Arc::new(Mutex::new(None));
        let slot = Arc::clone(&progress);
        let handle = thread::Builder::new()
            .name("sayaka-browser-scan".into())
            .spawn(move || {
                let mut progress_failed = false;
                let result = scan::scan(
                    &[root],
                    &ScanLimits::default(),
                    &cancel,
                    |state| match slot.lock() {
                        Ok(mut slot) => *slot = Some(state.clone()),
                        Err(_) => {
                            progress_failed = true;
                            cancel.cancel();
                        }
                    },
                )
                .map_err(scan_error);
                if progress_failed {
                    return Err(io::Error::other("scan progress slot was poisoned"));
                }
                BrowserData::build(result?, &cancel).map(|data| ResultValue::Scan(Box::new(data)))
            })?;
        Ok(Self {
            generation,
            cancellation,
            handle: Some(handle),
            progress: Some(progress),
            preview: None,
            confirmation: None,
        })
    }

    pub fn prepare(
        generation: u64,
        scope_entry: ScanEntry,
        selection: Vec<ScanEntry>,
        excluded: Vec<PathBuf>,
        state: Option<PathBuf>,
    ) -> io::Result<Self> {
        let cancellation = Cancellation::default();
        let cancel = cancellation.clone();
        let (preview_tx, preview) = mpsc::sync_channel(1);
        let (confirmation, decisions) = mpsc::sync_channel::<Confirmation>(1);
        let handle = thread::Builder::new()
            .name("sayaka-browser-plan".into())
            .spawn(move || {
                for entry in &selection {
                    if cancel.is_cancelled() {
                        return Ok(ResultValue::Action(ActionResult::Cancelled));
                    }
                    scan::verify_entry(&scope_entry, entry).map_err(scan_error)?;
                }
                let paths: Vec<_> = selection.iter().map(|entry| entry.path.clone()).collect();
                let scope = Scope::new(scope_entry.path.clone(), vec![])
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
                let mut session = TrashSession::prepare(scope, &paths, &excluded, &cancel)?;
                let plan = session.preview().clone();
                validate_preview(&selection, &plan)?;
                scan::verify_entry(&scope_entry, &scope_entry).map_err(scan_error)?;
                if cancel.is_cancelled() {
                    return Ok(ResultValue::Action(ActionResult::Cancelled));
                }
                let expires = plan.expires_at();
                let wait_started = Instant::now();
                let display = PlanDisplay {
                    plan: plan.clone(),
                    refusals: session.refusals(),
                    issues: session.issues().to_vec(),
                };
                if preview_tx.send(display).is_err() {
                    return Ok(ResultValue::Action(ActionResult::Cancelled));
                }
                loop {
                    if cancel.is_cancelled() {
                        return Ok(ResultValue::Action(ActionResult::Cancelled));
                    }
                    if SystemTime::now() >= expires
                        || wait_started.elapsed() >= Duration::from_secs(120)
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "plan expired; prepare a fresh preview",
                        ));
                    }
                    match decisions.recv_timeout(Duration::from_millis(25)) {
                        Ok(decision) => {
                            if decision.generation != generation || decision.plan != plan.id() {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    "confirmation does not match the displayed plan generation",
                                ));
                            }
                            break;
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => {
                            return Ok(ResultValue::Action(ActionResult::Cancelled));
                        }
                    }
                }
                if cancel.is_cancelled() {
                    return Ok(ResultValue::Action(ActionResult::Cancelled));
                }
                let approval = session
                    .approve(&plan)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
                let state = match state {
                    Some(path) => path,
                    None => journal::default_directory()?,
                };
                let store = Store::open(&state, true)?;
                session
                    .execute(&plan, &approval, &cancel, &store)
                    .map(|report| ResultValue::Action(ActionResult::Executed(Box::new(report))))
            })?;
        Ok(Self {
            generation,
            cancellation,
            handle: Some(handle),
            progress: None,
            preview: Some(preview),
            confirmation: Some(confirmation),
        })
    }

    pub fn viewer(
        generation: u64,
        scope: ScanEntry,
        entry: ScanEntry,
        viewer: Viewer,
    ) -> io::Result<Self> {
        let cancellation = Cancellation::default();
        let cancel = cancellation.clone();
        let handle = thread::Builder::new()
            .name("sayaka-browser-viewer".into())
            .spawn(move || {
                scan::verify_entry(&scope, &entry).map_err(scan_error)?;
                if cancel.is_cancelled() {
                    return Ok(ResultValue::Viewer("Viewing cancelled.".into()));
                }
                let (executable, args) = viewer_command(viewer, &entry)?;
                let child = Command::new(executable)
                    .args(args)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()?;
                let mut child = ViewerChild(child);
                let start = Instant::now();
                loop {
                    match child.0.try_wait() {
                        Ok(Some(status)) if status.success() => {
                            return Ok(ResultValue::Viewer(
                                "System viewing request completed.".into(),
                            ));
                        }
                        Ok(Some(status)) => {
                            return Err(io::Error::other(format!(
                                "system viewer failed ({status}); check macOS viewing permissions"
                            )));
                        }
                        Ok(None) => {}
                        Err(error) => {
                            return Err(io::Error::other(format!("viewer status failed: {error}")));
                        }
                    }
                    if cancel.is_cancelled() || start.elapsed() >= Duration::from_secs(300) {
                        child.stop()?;
                        return Ok(ResultValue::Viewer(
                            "Owned viewer helper stopped; Finder windows may remain open.".into(),
                        ));
                    }
                    thread::sleep(Duration::from_millis(20));
                }
            })?;
        Ok(Self {
            generation,
            cancellation,
            handle: Some(handle),
            progress: None,
            preview: None,
            confirmation: None,
        })
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn is_finished(&self) -> bool {
        self.handle.as_ref().is_none_or(JoinHandle::is_finished)
    }
    pub fn cancel(&mut self) {
        self.cancellation.cancel();
        self.confirmation.take();
        self.preview.take();
    }
    pub fn progress(&self) -> io::Result<Option<ScanProgress>> {
        self.progress
            .as_ref()
            .map(|slot| {
                slot.lock()
                    .map(|mut slot| slot.take())
                    .map_err(|_| io::Error::other("scan progress slot was poisoned"))
            })
            .transpose()
            .map(Option::flatten)
    }
    pub fn take_plan(&mut self) -> io::Result<Option<PlanDisplay>> {
        let Some(receiver) = &self.preview else {
            return Ok(None);
        };
        match receiver.try_recv() {
            Ok(plan) => {
                self.preview.take();
                Ok(Some(plan))
            }
            Err(mpsc::TryRecvError::Empty | mpsc::TryRecvError::Disconnected) => Ok(None),
        }
    }
    pub fn confirm(&mut self, generation: u64, plan: PlanId) -> io::Result<()> {
        let sender = self
            .confirmation
            .take()
            .ok_or_else(|| io::Error::other("confirmation is no longer available"))?;
        sender
            .try_send(Confirmation { generation, plan })
            .map_err(|error| io::Error::other(format!("confirmation delivery failed: {error}")))
    }
    pub fn finish(mut self) -> io::Result<ResultValue> {
        self.handle
            .take()
            .ok_or_else(|| io::Error::other("job already joined"))?
            .join()
            .map_err(|_| io::Error::other("owned browser worker panicked"))?
    }
}

struct ViewerChild(std::process::Child);

impl ViewerChild {
    fn stop(&mut self) -> io::Result<()> {
        if self.0.try_wait()?.is_some() {
            return Ok(());
        }
        let killed = self.0.kill();
        let waited = self.0.wait();
        match (killed, waited) {
            (_, Err(error)) => Err(error),
            (Err(error), Ok(_)) => Err(io::Error::other(format!(
                "viewer signal failed before child exited: {error}"
            ))),
            (Ok(()), Ok(_)) => Ok(()),
        }
    }
}

impl Drop for ViewerChild {
    fn drop(&mut self) {
        if let Err(error) = self.stop() {
            eprintln!("owned viewer cleanup failed: {:?}", error.to_string());
        }
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            self.cancel();
            match handle.join() {
                Ok(Ok(_)) => {}
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => {}
                Ok(Err(error)) => eprintln!("browser worker cleanup: {:?}", error.to_string()),
                Err(_) => eprintln!("browser worker panicked during cleanup"),
            }
        }
    }
}

fn validate_preview(selection: &[ScanEntry], plan: &Plan) -> io::Result<()> {
    for item in plan.items() {
        let observed = selection
            .iter()
            .find(|entry| entry.path == item.observation().path())
            .ok_or_else(|| io::Error::other("preview expanded beyond the frozen selection"))?;
        let current = item.observation().snapshot();
        if current.identity != Some(observed.identity)
            || observed
                .logical_bytes
                .is_some_and(|size| current.logical_bytes != Some(size))
        {
            return Err(io::Error::other(
                "selected identity or size changed; refresh and select again",
            ));
        }
    }
    Ok(())
}

fn viewer_command(
    viewer: Viewer,
    entry: &ScanEntry,
) -> io::Result<(&'static str, Vec<std::ffi::OsString>)> {
    if !cfg!(target_os = "macos") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "system viewing currently requires macOS",
        ));
    }
    if entry.dataless
        || !matches!(entry.kind, ResourceKind::File | ResourceKind::Directory)
        || !entry.path.is_absolute()
        || (viewer == Viewer::Preview && entry.kind != ResourceKind::File)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "this observed entry cannot be sent to the system viewer",
        ));
    }
    let (command, flag) = match viewer {
        Viewer::Reveal => ("/usr/bin/open", "-R"),
        Viewer::Preview => ("/usr/bin/qlmanage", "-p"),
    };
    Ok((
        command,
        vec![flag.into(), entry.path.as_os_str().to_owned()],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sayaka_engine::model::FileIdentity;
    #[test]
    fn viewer_arguments_are_fixed_native_arguments_not_shell_text() {
        let mut entry = ScanEntry {
            id: 1,
            path: "/fixture/a;echo unsafe\n.txt".into(),
            kind: ResourceKind::File,
            identity: FileIdentity::Unix {
                device: 1,
                inode: 2,
            },
            logical_bytes: Some(1),
            allocated_bytes: None,
            dataless: false,
            counted: true,
            depth: 1,
        };
        if cfg!(target_os = "macos") {
            let (program, args) = viewer_command(Viewer::Reveal, &entry).unwrap();
            assert_eq!(program, "/usr/bin/open");
            assert_eq!(args.len(), 2);
            assert_eq!(args[1], entry.path.as_os_str());
            entry.dataless = true;
            assert!(viewer_command(Viewer::Preview, &entry).is_err());
        } else {
            assert!(viewer_command(Viewer::Reveal, &entry).is_err());
        }
    }
}
