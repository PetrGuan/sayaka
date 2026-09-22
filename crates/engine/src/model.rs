// SPDX-License-Identifier: MPL-2.0

use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

/// A process-local reference issued by a planner, not an input path.
///
/// ```compile_fail
/// use sayaka_engine::model::ResourceId;
/// fn forge() -> ResourceId { ResourceId { session: 1, value: 1 } }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ResourceId {
    pub(crate) session: u64,
    pub(crate) value: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PlanId {
    pub(crate) session: u64,
    pub(crate) value: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReasonCode {
    InvalidScope,
    InvalidPath,
    OutsideScope,
    Protected,
    Excluded,
    UnknownResource,
    DuplicateResource,
    DuplicateSelection,
    OverlappingSelection,
    DuplicateIdentity,
    EmptyPlan,
    InvalidLifetime,
    ClockInvalid,
    IdentifierUnavailable,
    IdentifierCollision,
    InvalidVersions,
    UnknownPlan,
    ExpiredPlan,
    StalePlan,
    PlanMismatch,
    ApprovalMismatch,
    InvalidPlanState,
    IdentityUnknown,
    ProtectionUnknown,
    BoundaryUnverified,
    UnsupportedResource,
    IncompleteObservation,
    UnsupportedCapability,
    NotAuthorized,
    TemporarilyUnavailable,
    UnknownCapability,
    OwnerRunning,
    OwnerUnknown,
    ResourceChanged,
    ProbeFailed,
    Cancelled,
    SizeOverflow,
    InvalidTransition,
    OperationFailed,
    OutcomeUnknown,
}

impl ReasonCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidScope => "invalid_scope",
            Self::InvalidPath => "invalid_path",
            Self::OutsideScope => "outside_scope",
            Self::Protected => "protected",
            Self::Excluded => "excluded",
            Self::UnknownResource => "unknown_resource",
            Self::DuplicateResource => "duplicate_resource",
            Self::DuplicateSelection => "duplicate_selection",
            Self::OverlappingSelection => "overlapping_selection",
            Self::DuplicateIdentity => "duplicate_identity",
            Self::EmptyPlan => "empty_plan",
            Self::InvalidLifetime => "invalid_lifetime",
            Self::ClockInvalid => "clock_invalid",
            Self::IdentifierUnavailable => "identifier_unavailable",
            Self::IdentifierCollision => "identifier_collision",
            Self::InvalidVersions => "invalid_versions",
            Self::UnknownPlan => "unknown_plan",
            Self::ExpiredPlan => "expired_plan",
            Self::StalePlan => "stale_plan",
            Self::PlanMismatch => "plan_mismatch",
            Self::ApprovalMismatch => "approval_mismatch",
            Self::InvalidPlanState => "invalid_plan_state",
            Self::IdentityUnknown => "identity_unknown",
            Self::ProtectionUnknown => "protection_unknown",
            Self::BoundaryUnverified => "boundary_unverified",
            Self::UnsupportedResource => "unsupported_resource",
            Self::IncompleteObservation => "incomplete_observation",
            Self::UnsupportedCapability => "unsupported_capability",
            Self::NotAuthorized => "not_authorized",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::UnknownCapability => "unknown_capability",
            Self::OwnerRunning => "owner_running",
            Self::OwnerUnknown => "owner_unknown",
            Self::ResourceChanged => "resource_changed",
            Self::ProbeFailed => "probe_failed",
            Self::Cancelled => "cancelled",
            Self::SizeOverflow => "size_overflow",
            Self::InvalidTransition => "invalid_transition",
            Self::OperationFailed => "operation_failed",
            Self::OutcomeUnknown => "outcome_unknown",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub code: ReasonCode,
    pub resource: Option<ResourceId>,
    pub probe_error: Option<ProbeError>,
}

impl Error {
    pub(crate) fn new(code: ReasonCode) -> Self {
        Self {
            code,
            resource: None,
            probe_error: None,
        }
    }

    pub(crate) fn at(code: ReasonCode, resource: ResourceId) -> Self {
        Self {
            resource: Some(resource),
            ..Self::new(code)
        }
    }

    pub(crate) fn probe(error: ProbeError, resource: Option<ResourceId>) -> Self {
        Self {
            code: ReasonCode::ProbeFailed,
            resource,
            probe_error: Some(error),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code.as_str())?;
        if let Some(error) = &self.probe_error {
            write!(f, ": {error}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.probe_error
            .as_ref()
            .map(|error| error as &dyn std::error::Error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeError {
    NotFound,
    PermissionDenied,
    Unavailable,
    Other(String),
}

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ProbeError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capability {
    Available,
    Unsupported,
    NotAuthorized,
    TemporarilyUnavailable,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerState {
    NotApplicable,
    Stopped,
    Running,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Boundary {
    Verified,
    OutsideScope,
    TraversesLink,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protection {
    Clear,
    Protected,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceKind {
    File,
    Directory,
    Link,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(tag = "platform", rename_all = "snake_case")]
pub enum FileIdentity {
    Unix {
        device: u64,
        inode: u64,
    },
    Windows {
        volume_serial: u64,
        file_id: [u8; 16],
    },
}

/// Facts supplied by a trusted probe. Metadata equality is not proof against
/// filesystem races; native execution needs its own explicitly bounded contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub identity: Option<FileIdentity>,
    pub kind: ResourceKind,
    pub logical_bytes: Option<u64>,
    pub modified_at: Option<SystemTime>,
    pub complete: bool,
    pub boundary: Boundary,
    pub protection: Protection,
    pub trash: Capability,
    pub owner: OwnerState,
}

/// Read-only effect boundary. Implementations must not mutate or hydrate targets.
pub trait Probe {
    fn inspect(&mut self, scope: &Scope, path: &Path) -> Result<Snapshot, ProbeError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    MoveToTrash,
    RevalidatedMoveToTrash,
}

/// A pre-call check is not an atomic filesystem identity predicate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionContract {
    ModelOnly,
    RevalidatedTrashV1,
    /// Single sealed `.app` bundle directory to the user Trash (T9).
    RevalidatedBundleTrashV1,
    /// Sealed marker-bound project artifact directories to the user Trash (T8).
    RevalidatedPurgeTrashV1,
}

impl ExecutionContract {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ModelOnly => "model_only",
            Self::RevalidatedTrashV1 => "revalidated_trash_v1",
            Self::RevalidatedBundleTrashV1 => "revalidated_bundle_trash_v1",
            Self::RevalidatedPurgeTrashV1 => "revalidated_purge_trash_v1",
        }
    }

    pub const fn warning(self) -> &'static str {
        match self {
            Self::ModelOnly => "Read-only model; no native execution is authorized.",
            Self::RevalidatedTrashV1 => {
                "A file or ancestor replaced after the last check could cause a different file to be moved. Trash does not free space or guarantee restoration."
            }
            Self::RevalidatedBundleTrashV1 => {
                "A bundle or ancestor replaced after the last check could cause a different directory to be moved. Trash does not free space or guarantee restoration; related data is never touched."
            }
            Self::RevalidatedPurgeTrashV1 => {
                "An artifact, marker or ancestor replaced after the last check could cause a different directory to be moved; a stable container does not prove stable members. Trash does not free space or guarantee restoration; the marker stays untouched."
            }
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recovery {
    PlatformDependentTrash,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindingReason {
    ExplicitSelection,
}

impl FindingReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExplicitSelection => "explicit_selection",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Versions {
    pub engine: u32,
    pub rules: u32,
}

impl Versions {
    pub(crate) fn validate(self) -> Result<(), Error> {
        if self.engine == 0 || self.rules == 0 {
            return Err(Error::new(ReasonCode::InvalidVersions));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scope {
    root: PathBuf,
    protected: Vec<PathBuf>,
}

impl Scope {
    pub fn new(root: PathBuf, protected: Vec<PathBuf>) -> Result<Self, Error> {
        if !valid_absolute_path(&root) || root.parent().is_none() {
            return Err(Error::new(ReasonCode::InvalidScope));
        }
        if protected.iter().any(|path| !valid_absolute_path(path)) {
            return Err(Error::new(ReasonCode::InvalidPath));
        }
        Ok(Self { root, protected })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn protected_paths(&self) -> &[PathBuf] {
        &self.protected
    }

    pub(crate) fn contains(&self, path: &Path) -> bool {
        path.starts_with(&self.root)
    }

    pub(crate) fn protects(&self, path: &Path) -> bool {
        path == self.root
            || self.protected.iter().any(|entry| overlaps(path, entry))
            || system_protected(path)
    }
}

pub(crate) fn valid_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && !path.as_os_str().as_encoded_bytes().contains(&0)
        && !path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
}

pub(crate) fn overlaps(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn system_protected(path: &Path) -> bool {
    #[cfg(unix)]
    {
        const ROOTS: &[&str] = &[
            "/System",
            "/bin",
            "/sbin",
            "/usr",
            "/etc",
            "/private/etc",
            "/private/var/db",
            "/dev",
            "/proc",
            "/sys",
        ];
        ROOTS.iter().any(|root| overlaps(path, Path::new(root)))
    }
    #[cfg(windows)]
    {
        // Lexical defense only; the native probe must also enforce physical
        // identity, protected locations, aliases, and case-insensitive boundaries.
        path.components().any(|component| match component {
            Component::Normal(name) => [
                "Windows",
                "Program Files",
                "Program Files (x86)",
                "ProgramData",
            ]
            .iter()
            .any(|protected| {
                name.to_str()
                    .is_some_and(|name| name.eq_ignore_ascii_case(protected))
            }),
            _ => false,
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        true
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    pub(crate) id: ResourceId,
    pub(crate) path: PathBuf,
    pub(crate) observed_at: SystemTime,
    pub(crate) snapshot: Snapshot,
}

impl Observation {
    pub fn id(&self) -> ResourceId {
        self.id
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn observed_at(&self) -> SystemTime {
        self.observed_at
    }
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }

    pub fn display_path(&self) -> String {
        format!("{:?}", self.path.as_os_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub(crate) observation: Observation,
    pub(crate) refusal: Option<ReasonCode>,
    pub(crate) contract: ExecutionContract,
}

impl Finding {
    pub fn observation(&self) -> &Observation {
        &self.observation
    }
    pub fn reason(&self) -> FindingReason {
        FindingReason::ExplicitSelection
    }
    pub fn refusal(&self) -> Option<ReasonCode> {
        self.refusal
    }
    pub fn action(&self) -> Option<Action> {
        self.refusal.is_none().then_some(match self.contract {
            ExecutionContract::ModelOnly => Action::MoveToTrash,
            ExecutionContract::RevalidatedTrashV1
            | ExecutionContract::RevalidatedBundleTrashV1
            | ExecutionContract::RevalidatedPurgeTrashV1 => Action::RevalidatedMoveToTrash,
        })
    }
}

/// Known subtotal plus an explicit count of unmeasured items, never a fake zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ByteEstimate {
    pub known_bytes: u64,
    pub unknown_items: usize,
}

impl ByteEstimate {
    pub fn exact(self) -> Option<u64> {
        (self.unknown_items == 0).then_some(self.known_bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanItem {
    pub(crate) observation: Observation,
    pub(crate) contract: ExecutionContract,
    pub(crate) rule_binding: Option<RuleBinding>,
}

impl PlanItem {
    pub fn resource(&self) -> ResourceId {
        self.observation.id
    }
    pub fn observation(&self) -> &Observation {
        &self.observation
    }
    pub fn action(&self) -> Action {
        match self.contract {
            ExecutionContract::ModelOnly => Action::MoveToTrash,
            ExecutionContract::RevalidatedTrashV1
            | ExecutionContract::RevalidatedBundleTrashV1
            | ExecutionContract::RevalidatedPurgeTrashV1 => Action::RevalidatedMoveToTrash,
        }
    }
    pub fn reason(&self) -> FindingReason {
        FindingReason::ExplicitSelection
    }
    pub fn recovery(&self) -> Recovery {
        Recovery::PlatformDependentTrash
    }
    pub fn rule_binding(&self) -> Option<&RuleBinding> {
        self.rule_binding.as_ref()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleWitness {
    pub path: PathBuf,
    pub identity: FileIdentity,
    pub kind: ResourceKind,
    pub logical_bytes: u64,
    pub modified_at: SystemTime,
    pub changed_at: SystemTime,
    pub created_at: SystemTime,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub nlink: u64,
    pub flags: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleBinding {
    pub(crate) schema_version: u32,
    pub(crate) rule_id: String,
    pub(crate) rule_version: u32,
    pub(crate) ruleset_schema_version: u32,
    pub(crate) ruleset_revision: u32,
    pub(crate) semantics: String,
    pub(crate) semantics_digest: String,
    pub(crate) selected_root: PathBuf,
    pub(crate) exclusions: Vec<PathBuf>,
    pub(crate) target: RuleWitness,
    pub(crate) source: RuleWitness,
    pub(crate) root: RuleWitness,
    pub(crate) target_ancestors: Vec<RuleWitness>,
    pub(crate) source_ancestors: Vec<RuleWitness>,
    pub(crate) warnings: Vec<String>,
}

impl RuleBinding {
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }
    pub fn rule_id(&self) -> &str {
        &self.rule_id
    }
    pub fn rule_version(&self) -> u32 {
        self.rule_version
    }
    pub fn ruleset_schema_version(&self) -> u32 {
        self.ruleset_schema_version
    }
    pub fn ruleset_revision(&self) -> u32 {
        self.ruleset_revision
    }
    pub fn semantics(&self) -> &str {
        &self.semantics
    }
    pub fn semantics_digest(&self) -> &str {
        &self.semantics_digest
    }
    pub fn selected_root(&self) -> &Path {
        &self.selected_root
    }
    pub fn exclusions(&self) -> &[PathBuf] {
        &self.exclusions
    }
    pub fn target(&self) -> &RuleWitness {
        &self.target
    }
    pub fn source(&self) -> &RuleWitness {
        &self.source
    }
    pub fn root(&self) -> &RuleWitness {
        &self.root
    }
    pub fn target_ancestors(&self) -> &[RuleWitness] {
        &self.target_ancestors
    }
    pub fn source_ancestors(&self) -> &[RuleWitness] {
        &self.source_ancestors
    }
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rejection {
    pub resource: ResourceId,
    pub code: ReasonCode,
    pub probe_error: Option<ProbeError>,
}

impl Rejection {
    pub(crate) fn new(resource: ResourceId, code: ReasonCode) -> Self {
        Self {
            resource,
            code,
            probe_error: None,
        }
    }
}

/// Immutable preview; clients can inspect but cannot rewrite approved targets.
///
/// ```compile_fail
/// use sayaka_engine::model::Plan;
/// fn change_targets(plan: &mut Plan) { plan.items.clear(); }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub(crate) id: PlanId,
    pub(crate) scope: PathBuf,
    pub(crate) created_at: SystemTime,
    pub(crate) expires_at: SystemTime,
    pub(crate) versions: Versions,
    pub(crate) generation: u64,
    pub(crate) items: Vec<PlanItem>,
    pub(crate) excluded: Vec<ResourceId>,
    pub(crate) rejected: Vec<Rejection>,
    pub(crate) bytes: ByteEstimate,
    pub(crate) contract: ExecutionContract,
}

impl Plan {
    pub fn id(&self) -> PlanId {
        self.id
    }
    pub fn schema_version(&self) -> u32 {
        match self.contract {
            ExecutionContract::ModelOnly => 1,
            ExecutionContract::RevalidatedBundleTrashV1 => 4,
            ExecutionContract::RevalidatedPurgeTrashV1 => 5,
            ExecutionContract::RevalidatedTrashV1 => {
                if self.items.iter().any(|item| item.rule_binding.is_some()) {
                    3
                } else {
                    2
                }
            }
        }
    }
    pub fn execution_contract(&self) -> ExecutionContract {
        self.contract
    }
    pub fn scope(&self) -> &Path {
        &self.scope
    }
    pub fn created_at(&self) -> SystemTime {
        self.created_at
    }
    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }
    pub fn versions(&self) -> Versions {
        self.versions
    }
    pub fn items(&self) -> &[PlanItem] {
        &self.items
    }
    pub fn exclusions(&self) -> &[ResourceId] {
        &self.excluded
    }
    pub fn rejected(&self) -> &[Rejection] {
        &self.rejected
    }
    pub fn bytes(&self) -> ByteEstimate {
        self.bytes
    }
}

/// Process-local confirmation of an immutable preview; not an IPC credential.
///
/// ```compile_fail
/// use sayaka_engine::model::{Approval, PlanId};
/// fn forge(plan: PlanId) -> Approval { Approval { plan } }
/// ```
#[derive(Debug)]
pub struct Approval {
    pub(crate) plan: PlanId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanState {
    Prepared,
    Approved,
    Validated,
}

#[derive(Clone, Default, Debug)]
pub struct Cancellation(Arc<AtomicBool>);

impl Cancellation {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Read-only preflight results. `ready` does not authorize filesystem effects.
#[derive(Debug)]
pub struct ValidationReport {
    pub plan: PlanId,
    pub ready: Vec<PlanItem>,
    pub skipped: Vec<Rejection>,
}
