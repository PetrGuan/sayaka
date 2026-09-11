// SPDX-License-Identifier: MPL-2.0

use crate::model::*;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);

pub trait Clock {
    fn now(&self) -> SystemTime;
}

#[derive(Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

pub trait IdSource {
    fn next_id(&mut self) -> Option<u64>;
}

pub struct SequentialIds {
    next: Option<u64>,
}

impl Default for SequentialIds {
    fn default() -> Self {
        Self { next: Some(1) }
    }
}

impl IdSource for SequentialIds {
    fn next_id(&mut self) -> Option<u64> {
        let id = self.next?;
        self.next = id.checked_add(1);
        Some(id)
    }
}

struct PlanRecord {
    plan: Plan,
    state: PlanState,
}

pub struct Planner<C = SystemClock, I = SequentialIds> {
    session: u64,
    scope: Scope,
    versions: Versions,
    generation: u64,
    clock: C,
    ids: I,
    last_time: Option<SystemTime>,
    used_ids: HashSet<u64>,
    observations: HashMap<ResourceId, Observation>,
    paths: HashSet<PathBuf>,
    plans: HashMap<PlanId, PlanRecord>,
    contract: ExecutionContract,
}

impl Planner {
    pub fn new(scope: Scope, versions: Versions) -> Result<Self, Error> {
        Self::with_sources(scope, versions, SystemClock, SequentialIds::default())
    }
}

impl<C: Clock, I: IdSource> Planner<C, I> {
    pub fn with_sources(scope: Scope, versions: Versions, clock: C, ids: I) -> Result<Self, Error> {
        versions.validate()?;
        let session = NEXT_SESSION
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| Error::new(ReasonCode::IdentifierUnavailable))?;
        Ok(Self {
            session,
            scope,
            versions,
            clock,
            ids,
            generation: 0,
            last_time: None,
            used_ids: HashSet::new(),
            observations: HashMap::new(),
            paths: HashSet::new(),
            plans: HashMap::new(),
            contract: ExecutionContract::ModelOnly,
        })
    }

    /// Register one trusted read-only observation, not a recursive scan.
    pub fn discover(&mut self, path: &Path, probe: &mut impl Probe) -> Result<Finding, Error> {
        if !valid_absolute_path(path) {
            return Err(Error::new(ReasonCode::InvalidPath));
        }
        if !self.scope.contains(path) {
            return Err(Error::new(ReasonCode::OutsideScope));
        }
        if self.paths.contains(path) {
            return Err(Error::new(ReasonCode::DuplicateResource));
        }
        self.time()?;
        let snapshot = probe
            .inspect(&self.scope, path)
            .map_err(|error| Error::probe(error, None))?;
        let observed_at = self.time()?;
        let id = ResourceId {
            session: self.session,
            value: self.id()?,
        };
        let observation = Observation {
            id,
            path: path.to_path_buf(),
            observed_at,
            snapshot,
        };
        let refusal = self.refusal(&observation.path, &observation.snapshot);
        self.paths.insert(observation.path.clone());
        self.observations.insert(id, observation.clone());
        Ok(Finding {
            observation,
            refusal,
            contract: self.contract,
        })
    }

    pub fn prepare(
        &mut self,
        selected: &[ResourceId],
        excluded: &[ResourceId],
        lifetime: Duration,
    ) -> Result<Plan, Error> {
        if lifetime.is_zero() {
            return Err(Error::new(ReasonCode::InvalidLifetime));
        }
        if selected.is_empty() {
            return Err(Error::new(ReasonCode::EmptyPlan));
        }
        let created_at = self.time()?;
        let expires_at = created_at
            .checked_add(lifetime)
            .ok_or_else(|| Error::new(ReasonCode::InvalidLifetime))?;
        let mut seen = HashSet::new();
        let mut observations = Vec::with_capacity(selected.len());
        for id in selected {
            let observation = self.observation(*id)?;
            if !seen.insert(*id) {
                return Err(Error::at(ReasonCode::DuplicateSelection, *id));
            }
            observations.push(observation);
        }
        let mut exclusions = Vec::with_capacity(excluded.len());
        seen.clear();
        for id in excluded {
            let observation = self.observation(*id)?;
            if !seen.insert(*id) {
                return Err(Error::at(ReasonCode::DuplicateSelection, *id));
            }
            exclusions.push(observation);
        }
        let mut ordered = observations.clone();
        ordered.sort_by(|left, right| left.path.cmp(&right.path));
        for pair in ordered.windows(2) {
            if overlaps(&pair[0].path, &pair[1].path) {
                return Err(Error::at(ReasonCode::OverlappingSelection, pair[1].id));
            }
        }

        let mut identities = HashSet::new();
        let mut items = Vec::new();
        let mut rejected = Vec::new();
        let mut bytes = ByteEstimate::default();
        for observation in observations {
            let code = if self.scope.protects(&observation.path)
                || observation.snapshot.protection == Protection::Protected
            {
                Some(ReasonCode::Protected)
            } else if exclusions
                .iter()
                .any(|entry| overlaps(&observation.path, &entry.path))
            {
                Some(ReasonCode::Excluded)
            } else {
                self.refusal(&observation.path, &observation.snapshot)
            };
            if let Some(code) = code {
                rejected.push(Rejection::new(observation.id, code));
                continue;
            }
            if let Some(identity) = observation.snapshot.identity
                && !identities.insert(identity)
            {
                return Err(Error::at(ReasonCode::DuplicateIdentity, observation.id));
            }
            match observation.snapshot.logical_bytes {
                Some(size) => {
                    bytes.known_bytes = bytes
                        .known_bytes
                        .checked_add(size)
                        .ok_or_else(|| Error::new(ReasonCode::SizeOverflow))?;
                }
                None => bytes.unknown_items += 1,
            }
            items.push(PlanItem {
                observation: observation.clone(),
                contract: self.contract,
            });
        }
        let plan = Plan {
            id: PlanId {
                session: self.session,
                value: self.id()?,
            },
            scope: self.scope.root().to_path_buf(),
            created_at,
            expires_at,
            versions: self.versions,
            generation: self.generation,
            items,
            excluded: excluded.to_vec(),
            rejected,
            bytes,
            contract: self.contract,
        };
        self.plans.insert(
            plan.id,
            PlanRecord {
                plan: plan.clone(),
                state: PlanState::Prepared,
            },
        );
        Ok(plan)
    }

    /// Called by the trusted client only after displaying this exact preview
    /// and obtaining user confirmation. Does not authenticate a human or IPC peer.
    pub fn approve(&mut self, preview: &Plan) -> Result<Approval, Error> {
        let now = self.time()?;
        self.check_plan(preview, now)?;
        if preview.items.is_empty() {
            return Err(Error::new(ReasonCode::EmptyPlan));
        }
        let record = self
            .plans
            .get_mut(&preview.id)
            .ok_or_else(|| Error::new(ReasonCode::UnknownPlan))?;
        if record.state != PlanState::Prepared {
            return Err(Error::new(ReasonCode::InvalidPlanState));
        }
        record.state = PlanState::Approved;
        Ok(Approval { plan: preview.id })
    }

    /// One-shot, read-only preflight. Never enumerates new targets or mutates
    /// files; a native executor cannot treat this report as an effect permit.
    pub fn validate(
        &mut self,
        preview: &Plan,
        approval: &Approval,
        probe: &mut impl Probe,
        cancellation: &Cancellation,
    ) -> Result<ValidationReport, Error> {
        let now = self.time()?;
        self.check_plan(preview, now)?;
        if approval.plan != preview.id {
            return Err(Error::new(ReasonCode::ApprovalMismatch));
        }
        let record = self
            .plans
            .get_mut(&preview.id)
            .ok_or_else(|| Error::new(ReasonCode::UnknownPlan))?;
        if record.state != PlanState::Approved {
            return Err(Error::new(ReasonCode::InvalidPlanState));
        }
        record.state = PlanState::Validated;
        let mut report = ValidationReport {
            plan: preview.id,
            ready: Vec::new(),
            skipped: Vec::new(),
        };
        for item in &preview.items {
            let id = item.resource();
            if let Some(code) = self.preflight_stop(preview, cancellation) {
                report.skipped.push(Rejection::new(id, code));
                continue;
            }
            let snapshot = match probe.inspect(&self.scope, item.observation.path()) {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    report.skipped.push(Rejection {
                        resource: id,
                        code: ReasonCode::ProbeFailed,
                        probe_error: Some(error),
                    });
                    continue;
                }
            };
            let refusal = self
                .preflight_stop(preview, cancellation)
                .or_else(|| self.refusal(item.observation.path(), &snapshot))
                .or_else(|| {
                    (snapshot != item.observation.snapshot).then_some(ReasonCode::ResourceChanged)
                });
            if let Some(code) = refusal {
                report.skipped.push(Rejection::new(id, code));
            } else {
                report.ready.push(item.clone());
            }
        }
        Ok(report)
    }

    pub fn state(&self, plan: PlanId) -> Result<PlanState, Error> {
        self.plans
            .get(&plan)
            .map(|record| record.state)
            .ok_or_else(|| Error::new(ReasonCode::UnknownPlan))
    }

    pub(crate) fn for_revalidated_trash(mut self) -> Self {
        self.contract = ExecutionContract::RevalidatedTrashV1;
        self
    }

    pub(crate) fn stop_reason(
        &mut self,
        plan: &Plan,
        cancellation: &Cancellation,
    ) -> Option<ReasonCode> {
        self.preflight_stop(plan, cancellation)
    }

    /// Every semantic change permanently invalidates older plans, even if a
    /// previous version number is subsequently restored.
    pub fn set_versions(&mut self, versions: Versions) -> Result<(), Error> {
        versions.validate()?;
        if versions != self.versions {
            self.generation = self
                .generation
                .checked_add(1)
                .ok_or_else(|| Error::new(ReasonCode::IdentifierUnavailable))?;
            self.versions = versions;
        }
        Ok(())
    }

    fn id(&mut self) -> Result<u64, Error> {
        let id = self
            .ids
            .next_id()
            .filter(|id| *id != 0)
            .ok_or_else(|| Error::new(ReasonCode::IdentifierUnavailable))?;
        if !self.used_ids.insert(id) {
            return Err(Error::new(ReasonCode::IdentifierCollision));
        }
        Ok(id)
    }

    fn time(&mut self) -> Result<SystemTime, Error> {
        let now = self.clock.now();
        if self.last_time.is_some_and(|last| now < last) {
            return Err(Error::new(ReasonCode::ClockInvalid));
        }
        self.last_time = Some(now);
        Ok(now)
    }

    fn observation(&self, id: ResourceId) -> Result<&Observation, Error> {
        self.observations
            .get(&id)
            .ok_or_else(|| Error::at(ReasonCode::UnknownResource, id))
    }

    fn check_plan(&self, preview: &Plan, now: SystemTime) -> Result<(), Error> {
        let record = self
            .plans
            .get(&preview.id)
            .ok_or_else(|| Error::new(ReasonCode::UnknownPlan))?;
        if &record.plan != preview {
            return Err(Error::new(ReasonCode::PlanMismatch));
        }
        if preview.generation != self.generation || preview.versions != self.versions {
            return Err(Error::new(ReasonCode::StalePlan));
        }
        if now >= preview.expires_at {
            return Err(Error::new(ReasonCode::ExpiredPlan));
        }
        Ok(())
    }

    fn preflight_stop(&mut self, plan: &Plan, cancellation: &Cancellation) -> Option<ReasonCode> {
        if cancellation.is_cancelled() {
            return Some(ReasonCode::Cancelled);
        }
        match self.time() {
            Ok(now) if now >= plan.expires_at => Some(ReasonCode::ExpiredPlan),
            Ok(_) => None,
            Err(error) => Some(error.code),
        }
    }

    fn refusal(&self, path: &Path, snapshot: &Snapshot) -> Option<ReasonCode> {
        if self.scope.protects(path) || snapshot.protection == Protection::Protected {
            return Some(ReasonCode::Protected);
        }
        if snapshot.protection == Protection::Unknown {
            return Some(ReasonCode::ProtectionUnknown);
        }
        match snapshot.boundary {
            Boundary::OutsideScope => return Some(ReasonCode::OutsideScope),
            Boundary::TraversesLink => return Some(ReasonCode::BoundaryUnverified),
            Boundary::Unknown => return Some(ReasonCode::BoundaryUnverified),
            Boundary::Verified => {}
        }
        if snapshot.kind != ResourceKind::File {
            return Some(ReasonCode::UnsupportedResource);
        }
        if !snapshot.complete || snapshot.modified_at.is_none() {
            return Some(ReasonCode::IncompleteObservation);
        }
        if snapshot.identity.is_none() {
            return Some(ReasonCode::IdentityUnknown);
        }
        match snapshot.trash {
            Capability::Unsupported => return Some(ReasonCode::UnsupportedCapability),
            Capability::NotAuthorized => return Some(ReasonCode::NotAuthorized),
            Capability::TemporarilyUnavailable => return Some(ReasonCode::TemporarilyUnavailable),
            Capability::Unknown => return Some(ReasonCode::UnknownCapability),
            Capability::Available => {}
        }
        match snapshot.owner {
            OwnerState::Running => Some(ReasonCode::OwnerRunning),
            OwnerState::Unknown => Some(ReasonCode::OwnerUnknown),
            OwnerState::Stopped | OwnerState::NotApplicable => None,
        }
    }
}

#[cfg(test)]
mod tests;
