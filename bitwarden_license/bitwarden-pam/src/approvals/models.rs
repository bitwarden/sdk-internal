use bitwarden_api_api::models::{
    AccessDecisionRequestModel, AccessDecisionVerdict as ApiAccessDecisionVerdict,
};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;

use crate::{AccessDecisionVerdict, error::LeasingError};

/// An approver's decision on a pending access request.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct AccessDecisionRequest {
    /// The verdict to record. [`AccessDecisionVerdict::Unknown`] is a read-side spelling and
    /// cannot be submitted.
    pub verdict: AccessDecisionVerdict,
    /// An optional note recorded with the decision - for example the reason for a denial. Surfaced
    /// to the requester.
    pub comment: Option<String>,
}

impl TryFrom<AccessDecisionRequest> for AccessDecisionRequestModel {
    type Error = LeasingError;

    fn try_from(request: AccessDecisionRequest) -> Result<Self, Self::Error> {
        let verdict = match request.verdict {
            AccessDecisionVerdict::Approve => ApiAccessDecisionVerdict::Approve,
            AccessDecisionVerdict::Deny => ApiAccessDecisionVerdict::Deny,
            AccessDecisionVerdict::Unknown => return Err(LeasingError::UnsubmittableVerdict),
        };

        Ok(Self {
            verdict,
            comment: request.comment,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approve_converts_to_model() {
        let request = AccessDecisionRequest {
            verdict: AccessDecisionVerdict::Approve,
            comment: Some("Looks fine".to_string()),
        };

        let model = AccessDecisionRequestModel::try_from(request).unwrap();

        assert_eq!(model.verdict, ApiAccessDecisionVerdict::Approve);
        assert_eq!(model.comment, Some("Looks fine".to_string()));
    }

    #[test]
    fn deny_converts_to_model() {
        let request = AccessDecisionRequest {
            verdict: AccessDecisionVerdict::Deny,
            comment: None,
        };

        let model = AccessDecisionRequestModel::try_from(request).unwrap();

        assert_eq!(model.verdict, ApiAccessDecisionVerdict::Deny);
        assert_eq!(model.comment, None);
    }

    #[test]
    fn unknown_verdict_is_rejected() {
        let request = AccessDecisionRequest {
            verdict: AccessDecisionVerdict::Unknown,
            comment: None,
        };

        let result = AccessDecisionRequestModel::try_from(request);

        assert!(matches!(result, Err(LeasingError::UnsubmittableVerdict)));
    }
}
