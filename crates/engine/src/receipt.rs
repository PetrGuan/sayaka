// SPDX-License-Identifier: MPL-2.0

use crate::model::{
    Action, Error, Plan, PlanId, PlanItem, ReasonCode, Recovery, ResourceId, Versions,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Succeeded,
    Skipped(ReasonCode),
    Failed(ReasonCode),
    Unknown(ReasonCode),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptState {
    Planned,
    Started,
    Finished(Outcome),
}

/// Pure lifecycle model, not a durable journal or evidence that an OS effect
/// occurred. A future executor is responsible for supplying truthful outcomes.
#[derive(Debug)]
pub struct Receipt {
    plan: PlanId,
    item: PlanItem,
    versions: Versions,
    state: ReceiptState,
}

impl Receipt {
    pub fn new(plan: &Plan, resource: ResourceId) -> Result<Self, Error> {
        let item = plan
            .items()
            .iter()
            .find(|item| item.resource() == resource)
            .ok_or_else(|| Error::at(ReasonCode::UnknownResource, resource))?;
        Ok(Self {
            plan: plan.id(),
            item: item.clone(),
            versions: plan.versions(),
            state: ReceiptState::Planned,
        })
    }

    pub fn plan(&self) -> PlanId {
        self.plan
    }
    pub fn resource(&self) -> ResourceId {
        self.item.resource()
    }
    pub fn versions(&self) -> Versions {
        self.versions
    }
    pub fn action(&self) -> Action {
        self.item.action()
    }
    pub fn recovery(&self) -> Recovery {
        self.item.recovery()
    }
    pub fn state(&self) -> ReceiptState {
        self.state
    }

    pub fn start(&mut self) -> Result<(), Error> {
        if self.state != ReceiptState::Planned {
            return Err(Error::new(ReasonCode::InvalidTransition));
        }
        self.state = ReceiptState::Started;
        Ok(())
    }

    pub fn finish(&mut self, outcome: Outcome) -> Result<(), Error> {
        match (self.state, outcome) {
            (ReceiptState::Started, _) | (ReceiptState::Planned, Outcome::Skipped(_)) => {
                self.state = ReceiptState::Finished(outcome);
                Ok(())
            }
            _ => Err(Error::new(ReasonCode::InvalidTransition)),
        }
    }
}
