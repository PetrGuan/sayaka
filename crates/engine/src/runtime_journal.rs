// SPDX-License-Identifier: MPL-2.0
//! Schema 11 has typed tool targets, never synthetic filesystem Trash items.
use crate::{
    devtools::{canonical_udid, runtimes::Runtime},
    journal::{self, ItemState, Record},
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, io};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Target {
    Runtime {
        image: Runtime,
        dependent_udids: Vec<String>,
    },
    Device {
        udid: String,
        name: String,
        runtime_identifier: String,
        paired_with: Option<String>,
    },
}
impl Target {
    pub fn id(&self) -> &str {
        match self {
            Self::Runtime { image, .. } => &image.identifier,
            Self::Device { udid, .. } => udid,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Item {
    pub target: Target,
    pub logical_bytes: Option<u64>,
    pub state: ItemState,
    pub reason: Option<String>,
    pub updated_unix_ms: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub schema_version: u32,
    pub operation: String,
    pub tool_evidence: String,
    pub plan_digest: String,
    pub items: Vec<Item>,
}
impl Context {
    pub fn validate(&self, r: &Record) -> io::Result<()> {
        let invalid = || journal::invalid("invalid runtime tool journal");
        if r.schema_version != 11
            || r.plan_schema_version != 11
            || r.engine_version != 2
            || r.rules_version != 1
            || r.contract != journal::TOOL_CONTRACT
            || !journal::valid_id(&r.operation_id)
            || !r.items.is_empty()
            || r.tool_operation.is_some()
            || r.empty_trash_context.is_some()
            || r.clean_policy.is_some()
            || r.related_context.is_some()
            || r.orphan_context.is_some()
            || r.delegation.is_some()
            || self.schema_version != 1
            || self.operation != "runtime_delete"
            || self.tool_evidence.is_empty()
            || self.tool_evidence.len() > 8192
            || !crate::empty_trash_journal::hex(&self.plan_digest)
            || self.items.is_empty()
            || self.items.len() > 64
        {
            return Err(invalid());
        }
        r.scope.validate()?;
        let mut images = BTreeSet::new();
        let mut devices = BTreeSet::new();
        for i in &self.items {
            if canonical_udid(i.target.id()).as_deref() != Some(i.target.id())
                || i.reason.as_ref().is_some_and(|s| s.len() > 512)
                || i.updated_unix_ms < r.created_unix_ms
            {
                return Err(invalid());
            }
            match &i.target {
                Target::Runtime {
                    image,
                    dependent_udids,
                } => {
                    if !images.insert(image.identifier.clone())
                        || dependent_udids.len() > 32
                        || dependent_udids.iter().collect::<BTreeSet<_>>().len()
                            != dependent_udids.len()
                        || image.runtime_identifier.len() > 4096
                        || image.build.len() > 4096
                        || !crate::devtools::runtimes::valid_path(&image.path)
                    {
                        return Err(invalid());
                    }
                    for id in dependent_udids {
                        if !self.items.iter().any(|i|matches!(&i.target,Target::Device{udid,runtime_identifier,..} if udid==id&&runtime_identifier==&image.runtime_identifier)){return Err(invalid())}
                    }
                }
                Target::Device {
                    udid,
                    name,
                    runtime_identifier,
                    paired_with,
                } => {
                    if !devices.insert(udid.clone())
                        || name.len() > 4096
                        || runtime_identifier.len() > 4096
                    {
                        return Err(invalid());
                    }
                    if self.items.iter().filter(|i|matches!(&i.target,Target::Runtime{image,dependent_udids} if image.runtime_identifier==*runtime_identifier&&dependent_udids.contains(udid))).count()!=1{return Err(invalid())}
                    if paired_with.as_ref().is_some_and(|partner|partner==udid||!self.items.iter().any(|i|matches!(&i.target,Target::Device{udid:other,paired_with:Some(back),runtime_identifier:rt,..} if other==partner&&back==udid&&rt==runtime_identifier))){return Err(invalid())}
                }
            }
        }
        if images.is_empty() || images.len() > 32 || devices.len() > 32 {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn reconcile(&mut self) {
        for i in &mut self.items {
            match i.state {
                ItemState::Started => {
                    i.state = ItemState::Unknown;
                    i.reason = Some("interrupted; never automatically retried".into())
                }
                ItemState::Planned => {
                    i.state = ItemState::Skipped;
                    i.reason = Some("not_started_before_session_ended".into())
                }
                _ => {}
            }
        }
    }
    pub fn unconfirmed(&mut self, previous: Option<&Self>) {
        for i in &mut self.items {
            if matches!(i.state, ItemState::Succeeded | ItemState::Failed)
                && !previous.is_some_and(|p| {
                    p.items
                        .iter()
                        .any(|old| old.target == i.target && old.state == i.state)
                })
            {
                i.state = ItemState::Unknown;
                i.reason = Some("outcome_publication_not_confirmed".into())
            }
        }
    }
}
