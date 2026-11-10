use bitwarden_api_api::models::{
    AccessDecisionRequestModel, AccessDecisionVerdict as ApiAccessDecisionVerdict,
    AccessRequestHistoryPageResponseModel, AccessRequestHistoryRequesterResponseModel,
    AccessRequestRevokeRequestModel,
};
use bitwarden_collections::collection::CollectionId;
use bitwarden_core::{UserId, require};
use serde::{Deserialize, Serialize};

use super::error::ApprovalError;
use crate::{AccessDecisionVerdict, access_requests::AccessRequestView, error::PamDecodeError};

/// How a request ended, as the approver history lists it.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[bitwarden_ffi::wasm_record]
#[serde(rename_all = "snake_case")]
pub enum AccessRequestHistoryStatus {
    /// An approver denied the request, or withdrew an approval before it was started.
    Denied,
    /// An approver ended the lease early.
    Revoked,
    /// The requester withdrew the request.
    Canceled,
    /// The window closed with the request unanswered, or approved and never started.
    Expired,
    /// The lease ran to its end, or its holder ended it.
    SessionEnded,
}

impl AccessRequestHistoryStatus {
    /// The name the server reads in the `status` query parameter.
    pub(crate) fn wire_name(self) -> &'static str {
        match self {
            Self::Denied => "denied",
            Self::Revoked => "revoked",
            Self::Canceled => "canceled",
            Self::Expired => "expired",
            Self::SessionEnded => "sessionEnded",
        }
    }
}

/// Which page of the approver history to read, and what to narrow it to. An empty list matches
/// everything; values within a list are OR-ed, lists are AND-ed.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[bitwarden_ffi::wasm_record]
#[serde(rename_all = "camelCase")]
pub struct AccessRequestHistoryQuery {
    /// 0-based.
    pub page: u32,
    /// Rows per page, 1 to 100.
    pub page_size: u32,
    /// How the request ended.
    pub statuses: Vec<AccessRequestHistoryStatus>,
    /// The request's collection.
    pub collection_ids: Vec<CollectionId>,
    /// Who made the request.
    pub requester_ids: Vec<UserId>,
}

/// One page of the approver history: the ended requests on collections the caller manages, and
/// the caller's own, newest request first.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[bitwarden_ffi::wasm_record]
#[serde(rename_all = "camelCase")]
pub struct AccessRequestHistoryPage {
    /// The requests on this page.
    pub requests: Vec<AccessRequestView>,
    /// How many requests match the query, across all pages.
    pub total: u32,
    /// Everyone with a request in the history, whatever the query, for the Requester filter.
    pub requesters: Vec<AccessRequestHistoryRequester>,
    /// Every collection with a request in the history, whatever the query.
    pub collection_ids: Vec<CollectionId>,
}

/// A requester with a request in the approver history.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[bitwarden_ffi::wasm_record]
#[serde(rename_all = "camelCase")]
pub struct AccessRequestHistoryRequester {
    /// The requester's user id.
    pub id: UserId,
    /// The requester's name, if they set one.
    pub name: Option<String>,
    /// The requester's email.
    pub email: Option<String>,
}

impl TryFrom<AccessRequestHistoryRequesterResponseModel> for AccessRequestHistoryRequester {
    type Error = PamDecodeError;

    fn try_from(response: AccessRequestHistoryRequesterResponseModel) -> Result<Self, Self::Error> {
        Ok(Self {
            id: UserId::new(require!(response.id)),
            name: response.name,
            email: response.email,
        })
    }
}

impl TryFrom<AccessRequestHistoryPageResponseModel> for AccessRequestHistoryPage {
    type Error = PamDecodeError;

    fn try_from(response: AccessRequestHistoryPageResponseModel) -> Result<Self, Self::Error> {
        Ok(Self {
            requests: response
                .data
                .unwrap_or_default()
                .into_iter()
                .map(AccessRequestView::try_from)
                .collect::<Result<_, _>>()?,
            total: u32::try_from(require!(response.total)).unwrap_or_default(),
            requesters: response
                .requesters
                .unwrap_or_default()
                .into_iter()
                .map(AccessRequestHistoryRequester::try_from)
                .collect::<Result<_, _>>()?,
            collection_ids: response
                .collection_ids
                .unwrap_or_default()
                .into_iter()
                .map(CollectionId::new)
                .collect(),
        })
    }
}

/// An approver's decision on a pending access request.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[bitwarden_ffi::wasm_record]
#[serde(rename_all = "camelCase")]
pub struct AccessDecisionRequest {
    /// The verdict to record; [`AccessDecisionVerdict::Unknown`] cannot be submitted.
    pub verdict: AccessDecisionVerdict,
    /// An optional note shown to the requester.
    pub comment: Option<String>,
}

impl TryFrom<AccessDecisionRequest> for AccessDecisionRequestModel {
    type Error = ApprovalError;

    fn try_from(request: AccessDecisionRequest) -> Result<Self, Self::Error> {
        let verdict = match request.verdict {
            AccessDecisionVerdict::Approve => ApiAccessDecisionVerdict::Approve,
            AccessDecisionVerdict::Deny => ApiAccessDecisionVerdict::Deny,
            AccessDecisionVerdict::Unknown => return Err(ApprovalError::UnsubmittableVerdict),
        };

        Ok(Self {
            verdict,
            comment: request.comment,
        })
    }
}

/// An approver revoking an approved access request the requester has not started.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[bitwarden_ffi::wasm_record]
#[serde(rename_all = "camelCase")]
pub struct AccessRequestRevokeRequest {
    /// Why the approval is revoked. Required by the server; recorded with the approver's decision
    /// and shown to the requester.
    pub reason: String,
}

impl From<AccessRequestRevokeRequest> for AccessRequestRevokeRequestModel {
    fn from(request: AccessRequestRevokeRequest) -> Self {
        Self {
            reason: Some(request.reason),
        }
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

        assert!(matches!(result, Err(ApprovalError::UnsubmittableVerdict)));
    }

    #[test]
    fn revoke_converts_to_model() {
        let model = AccessRequestRevokeRequestModel::from(AccessRequestRevokeRequest {
            reason: "Approved by mistake".to_string(),
        });

        assert_eq!(model.reason.as_deref(), Some("Approved by mistake"));
    }
}
