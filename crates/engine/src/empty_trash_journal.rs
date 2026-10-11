// SPDX-License-Identifier: MPL-2.0
//! Schema 10 records observations, never global deletion or executable authority.
use crate::journal::{self, ItemState, NativePath, Record};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, io, path::PathBuf};
pub const CONTRACT: &str = "finder_delegated_empty_trash_v1";
pub const EFFECT_SCOPE: &str = "all_finder_trash_including_attached_volumes";
pub const MAX_ITEMS: usize = 4096;
pub const MAX_REFS: usize = 32;
pub(crate) fn required_option<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}
macro_rules! wire_enum { ($name:ident {$($v:ident),*}) => { #[derive(Clone,Copy,Debug,PartialEq,Eq,Serialize,Deserialize)] #[serde(rename_all="snake_case")] pub enum $name {$($v),*} }; }
wire_enum!(FinderOutcome {
    ReportedCompleted,
    UserCancelled,
    AutomationDenied,
    Failed,
    TimedOut,
    TransportUnknown,
    NotDispatched
});
wire_enum!(Aggregate {
    Cancelled,
    Partial,
    Unknown,
    Succeeded
});
wire_enum!(Observation {
    Started,
    Present,
    Absent,
    Unknown,
    NotDispatched
});
wire_enum!(OperationState { Started, Finished });
wire_enum!(SourceStatus {
    Read,
    Absent,
    Incomplete
});
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRoot {
    pub path: NativePath,
    pub schemas: Vec<u32>,
    pub status: SourceStatus,
    #[serde(deserialize_with = "required_option")]
    pub device: Option<u64>,
    #[serde(deserialize_with = "required_option")]
    pub inode: Option<u64>,
}
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRef {
    pub root_index: usize,
    pub operation_id: String,
    pub item_index: usize,
    pub record_digest: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnownItem {
    pub source_refs: Vec<SourceRef>,
    #[serde(deserialize_with = "required_option")]
    pub historical_logical_bytes: Option<u64>,
    pub observation: Observation,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub schema_version: u32,
    pub performer: String,
    pub effect_scope: String,
    pub trash_root: NativePath,
    pub trash_device: u64,
    pub trash_inode: u64,
    pub plan_digest: String,
    pub approved_unix_ms: u64,
    pub deadline_unix_ms: u64,
    pub operation_state: OperationState,
    #[serde(deserialize_with = "required_option")]
    pub aggregate_outcome: Option<Aggregate>,
    pub finder_preview_count: u64,
    pub finder_before_count: u64,
    #[serde(deserialize_with = "required_option")]
    pub finder_after_count: Option<u64>,
    pub warns_before_emptying: bool,
    #[serde(deserialize_with = "required_option")]
    pub finder_outcome: Option<FinderOutcome>,
    #[serde(deserialize_with = "required_option")]
    pub finder_error_code: Option<i32>,
    #[serde(deserialize_with = "required_option")]
    pub finder_message: Option<String>,
    pub dispatch_timeout_seconds: u32,
    pub dispatch_may_continue: bool,
    pub known_subset_complete: bool,
    pub coverage_reasons: Vec<String>,
    #[serde(deserialize_with = "required_option")]
    pub omitted_count: Option<u64>,
    pub omitted_lower_bound: u64,
    pub unknown_size_count: u64,
    pub source_roots: Vec<SourceRoot>,
    pub known_items: Vec<KnownItem>,
    #[serde(deserialize_with = "required_option")]
    pub unaccounted_logical_bytes: Option<u64>,
    #[serde(deserialize_with = "required_option")]
    pub reclaimed_bytes: Option<u64>,
}
pub(crate) fn error() -> io::Error {
    journal::invalid("invalid empty Trash evidence")
}
pub(crate) fn hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(crate) fn path(p: &NativePath) -> io::Result<PathBuf> {
    p.validate()?;
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let v = PathBuf::from(std::ffi::OsStr::from_bytes(&p.bytes));
        if p.encoding != "unix_bytes"
            || p.bytes.len() > 4096
            || p.bytes.contains(&0)
            || p.bytes.last() == Some(&b'/')
            || p.bytes.windows(2).any(|w| w == b"//")
            || p.bytes
                .split(|b| *b == b'/')
                .any(|c| c == b"." || c == b"..")
            || !v.is_absolute()
            || v.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
            || v.as_os_str().as_bytes() != p.bytes
        {
            return Err(error());
        }
        Ok(v)
    }
    #[cfg(not(unix))]
    {
        Err(error())
    }
}
pub fn aggregate(
    outcome: FinderOutcome,
    observations: impl IntoIterator<Item = Observation>,
    count: Option<u64>,
    root_valid: bool,
) -> Aggregate {
    let items: Vec<_> = observations.into_iter().collect();
    if outcome == FinderOutcome::NotDispatched
        || matches!(
            outcome,
            FinderOutcome::UserCancelled | FinderOutcome::AutomationDenied
        )
    {
        Aggregate::Cancelled
    } else if items.contains(&Observation::Present) || count.is_some_and(|n| n > 0) {
        Aggregate::Partial
    } else if outcome == FinderOutcome::ReportedCompleted
        && root_valid
        && !items.is_empty()
        && items.iter().all(|o| *o == Observation::Absent)
        && count == Some(0)
    {
        Aggregate::Succeeded
    } else {
        Aggregate::Unknown
    }
}
impl Context {
    pub fn validate(&self, r: &Record) -> io::Result<()> {
        let root = path(&self.trash_root)?;
        if (
            r.schema_version,
            r.plan_schema_version,
            r.engine_version,
            r.rules_version,
        ) != (10, 10, 1, 1)
            || r.contract != CONTRACT
            || !journal::valid_id(&r.operation_id)
            || r.clean_policy.is_some()
            || r.tool_operation.is_some()
            || r.related_context.is_some()
            || r.orphan_context.is_some()
            || r.delegation.is_some()
            || self.schema_version != 1
            || self.performer != "finder"
            || self.effect_scope != EFFECT_SCOPE
            || path(&r.scope)? != root
            || root.file_name() != Some(std::ffi::OsStr::new(".Trash"))
            || self.trash_inode == 0
            || !hex(&self.plan_digest)
            || self.deadline_unix_ms.checked_sub(self.approved_unix_ms) != Some(120_000)
            || r.created_unix_ms != self.approved_unix_ms
            || self.dispatch_timeout_seconds != 600
            || self.finder_before_count != self.finder_preview_count
            || self.finder_preview_count == 0
            || self.finder_preview_count < r.items.len() as u64
            || self.known_items.len() != r.items.len()
            || r.items.len() > MAX_ITEMS
            || self.source_roots.len() > 8
            || self.coverage_reasons.len() > 32
            || self
                .coverage_reasons
                .iter()
                .any(|s| s.is_empty() || s.len() > 128 || s.chars().any(char::is_control))
            || self.known_subset_complete != self.coverage_reasons.is_empty()
            || self
                .omitted_count
                .is_some_and(|n| n < self.omitted_lower_bound)
            || self.unaccounted_logical_bytes.is_some()
            || self.reclaimed_bytes.is_some()
            || self
                .finder_message
                .as_ref()
                .is_some_and(|s| s.len() > 512 || s.chars().any(char::is_control))
        {
            return Err(error());
        }
        let mut roots = HashSet::new();
        for s in &self.source_roots {
            if !roots.insert(path(&s.path)?)
                || s.schemas.is_empty()
                || s.schemas.len() > 8
                || s.schemas.iter().any(|n| !matches!(n,1..=5|7..=9))
                || s.schemas.iter().collect::<HashSet<_>>().len() != s.schemas.len()
                || s.device.is_some() != s.inode.is_some()
                || s.inode == Some(0)
                || (s.status == SourceStatus::Read && s.inode.is_none())
                || (s.status == SourceStatus::Absent && s.inode.is_some())
            {
                return Err(error());
            }
        }
        let mut paths = HashSet::new();
        let mut unknown = 0;
        for (i, k) in r.items.iter().zip(&self.known_items) {
            let p = path(&i.path)?;
            if p.parent() != Some(root.as_path())
                || !paths.insert(p)
                || i.inode == 0
                || i.device != self.trash_device
                || i.destination.is_some()
                || i.rule_binding.is_some()
                || i.recovery_evidence.is_some()
                || i.updated_unix_ms < r.created_unix_ms
                || k.historical_logical_bytes
                    .is_some_and(|n| n != i.logical_bytes)
                || k.source_refs.is_empty()
                || k.source_refs.len() > MAX_REFS
                || k.source_refs.iter().collect::<HashSet<_>>().len() != k.source_refs.len()
            {
                return Err(error());
            }
            for s in &k.source_refs {
                if s.root_index >= self.source_roots.len()
                    || self.source_roots[s.root_index].inode.is_none()
                    || !journal::valid_id(&s.operation_id)
                    || s.item_index >= 32
                    || !hex(&s.record_digest)
                {
                    return Err(error());
                }
            }
            if k.historical_logical_bytes.is_none() {
                unknown += 1;
            }
            let pair = match k.observation {
                Observation::Started => (ItemState::Started, None),
                Observation::Present => (ItemState::Failed, Some("still_present")),
                Observation::Absent => (ItemState::Succeeded, Some("absent_after_delegation")),
                Observation::Unknown => (ItemState::Unknown, Some("observation_unknown")),
                Observation::NotDispatched => (ItemState::Skipped, Some("not_dispatched")),
            };
            if i.state != pair.0 || i.reason.as_deref() != pair.1 {
                return Err(error());
            }
        }
        if unknown != self.unknown_size_count {
            return Err(error());
        }
        match self.operation_state {
            OperationState::Started => {
                if self.aggregate_outcome.is_some()
                    || self.finder_outcome.is_some()
                    || self.finder_after_count.is_some()
                    || self.finder_error_code.is_some()
                    || self.finder_message.is_some()
                    || !self.dispatch_may_continue
                    || self
                        .known_items
                        .iter()
                        .any(|i| i.observation != Observation::Started)
                {
                    return Err(error());
                }
            }
            OperationState::Finished => {
                let o = self.finder_outcome.ok_or_else(error)?;
                if self
                    .known_items
                    .iter()
                    .any(|i| i.observation == Observation::Started)
                    || self.known_items.iter().any(|i| {
                        (i.observation == Observation::NotDispatched)
                            != (o == FinderOutcome::NotDispatched)
                    })
                    || self.aggregate_outcome
                        != Some(aggregate(
                            o,
                            self.known_items.iter().map(|i| i.observation),
                            self.finder_after_count,
                            true,
                        ))
                    || self.dispatch_may_continue
                        != matches!(o, FinderOutcome::TimedOut | FinderOutcome::TransportUnknown)
                {
                    return Err(error());
                }
            }
        }
        Ok(())
    }
}
/// Pending publications and interrupted whole operations must be conservative,
/// including operations with zero independently known entries.
pub(crate) fn unconfirmed(r: &mut Record) {
    if let Some(c) = &mut r.empty_trash_context {
        c.operation_state = OperationState::Finished;
        c.aggregate_outcome = Some(Aggregate::Unknown);
        c.finder_outcome = Some(FinderOutcome::TransportUnknown);
        c.finder_error_code = None;
        c.finder_message = None;
        c.finder_after_count = None;
        c.dispatch_may_continue = true;
        for (k, i) in c.known_items.iter_mut().zip(&mut r.items) {
            k.observation = Observation::Unknown;
            i.state = ItemState::Unknown;
            i.reason = Some("observation_unknown".into());
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) fn intent() -> Record {
        let root = NativePath::unix_fixture("/Users/fixture/.Trash");
        serde_json::from_value(serde_json::json!({"schema_version":10,"plan_schema_version":10,"engine_version":1,"rules_version":1,"operation_id":"a-1","contract":CONTRACT,"scope":root,"created_unix_ms":1,"items":[],"empty_trash_context":{
 "schema_version":1,"performer":"finder","effect_scope":EFFECT_SCOPE,"trash_root":root,"trash_device":1,"trash_inode":2,"plan_digest":"a".repeat(64),"approved_unix_ms":1,"deadline_unix_ms":120001,"operation_state":"started","aggregate_outcome":null,"finder_preview_count":2,"finder_before_count":2,"finder_after_count":null,"warns_before_emptying":true,"finder_outcome":null,"finder_error_code":null,"finder_message":null,"dispatch_timeout_seconds":600,"dispatch_may_continue":true,"known_subset_complete":true,"coverage_reasons":[],"omitted_count":0,"omitted_lower_bound":0,"unknown_size_count":0,"source_roots":[],"known_items":[],"unaccounted_logical_bytes":null,"reclaimed_bytes":null}})).unwrap()
    }
    #[test]
    fn zero_item_intent_is_an_operation_and_interruption_is_unknown() {
        let r = intent();
        r.validate().unwrap();
        let r = r.reconciled();
        r.validate().unwrap();
        let c = r.empty_trash_context.as_ref().unwrap();
        assert_eq!(c.aggregate_outcome, Some(Aggregate::Unknown));
        assert!(c.dispatch_may_continue);
        assert_eq!(r.handled_bytes(), None);
    }
    #[test]
    fn no_vacuous_success() {
        assert_eq!(
            aggregate(FinderOutcome::ReportedCompleted, [], Some(0), true),
            Aggregate::Unknown
        );
        assert_eq!(
            aggregate(
                FinderOutcome::ReportedCompleted,
                [Observation::Absent],
                Some(0),
                true
            ),
            Aggregate::Succeeded
        );
        assert_eq!(
            aggregate(
                FinderOutcome::ReportedCompleted,
                [Observation::Absent],
                None,
                true
            ),
            Aggregate::Unknown
        );
        assert_eq!(
            aggregate(
                FinderOutcome::ReportedCompleted,
                [Observation::Absent],
                Some(0),
                false
            ),
            Aggregate::Unknown
        );
    }
    #[test]
    fn aggregate_priority_does_not_claim_deletion_on_partial_or_cancel() {
        assert_eq!(
            aggregate(
                FinderOutcome::TimedOut,
                [Observation::Present],
                Some(1),
                true
            ),
            Aggregate::Partial
        );
        assert_eq!(
            aggregate(
                FinderOutcome::UserCancelled,
                [Observation::Absent, Observation::Present],
                Some(1),
                true
            ),
            Aggregate::Cancelled
        );
        assert_eq!(
            aggregate(FinderOutcome::Failed, [Observation::Absent], Some(0), true),
            Aggregate::Unknown
        );
    }
    #[test]
    fn strict_required_null_fields_and_unknown_keys() {
        let value = serde_json::to_value(intent()).unwrap();
        for key in [
            "finder_outcome",
            "finder_error_code",
            "finder_message",
            "finder_after_count",
            "aggregate_outcome",
            "reclaimed_bytes",
            "unaccounted_logical_bytes",
            "omitted_count",
        ] {
            let mut v = value.clone();
            v["empty_trash_context"]
                .as_object_mut()
                .unwrap()
                .remove(key);
            assert!(serde_json::from_value::<Record>(v).is_err(), "{key}");
        }
        let mut v = value;
        v["empty_trash_context"]["delete_all"] = true.into();
        assert!(serde_json::from_value::<Record>(v).is_err());
    }
    #[test]
    fn empty_operations_cannot_manufacture_success_or_space() {
        let mut r = intent();
        let c = r.empty_trash_context.as_mut().unwrap();
        c.operation_state = OperationState::Finished;
        c.aggregate_outcome = Some(Aggregate::Succeeded);
        c.finder_outcome = Some(FinderOutcome::ReportedCompleted);
        c.finder_after_count = Some(0);
        c.dispatch_may_continue = false;
        assert!(r.validate().is_err());
        r.empty_trash_context.as_mut().unwrap().aggregate_outcome = Some(Aggregate::Unknown);
        r.validate().unwrap();
        r.empty_trash_context.as_mut().unwrap().reclaimed_bytes = Some(0);
        assert!(r.validate().is_err());
    }
    #[test]
    fn context_cannot_extend_other_contracts() {
        let mut r = intent();
        r.schema_version = 1;
        assert!(r.validate().is_err());
        r.schema_version = 10;
        r.plan_schema_version = 9;
        assert!(r.validate().is_err());
    }
}

#[cfg(test)]
mod review_regressions {
    use super::*;
    #[test]
    fn exact_paths_refuse_repeated_or_trailing_separators() {
        for p in [
            "/Users/u/.Trash//x",
            "/Users/u/.Trash/x/",
            "/Users/u/./.Trash/x",
        ] {
            assert!(path(&NativePath::from_path(std::path::Path::new(p))).is_err());
        }
    }
    #[test]
    fn finish_nullable_keys_are_required() {
        let v = serde_json::json!({"outcome":"not_dispatched","error_code":null,"message":null,"finder_after_count":null});
        #[cfg(target_os = "macos")]
        for key in ["error_code", "message", "finder_after_count"] {
            let mut v = v.clone();
            v.as_object_mut().unwrap().remove(key);
            assert!(serde_json::from_value::<crate::empty_trash::FinishInput>(v).is_err());
        }
    }
}
