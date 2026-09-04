use std::num::NonZeroU32;

use bitwarden_api_api::models::{
    AccessLeaseExtensionRequestModel, AccessLeaseResponseModel, AccessLeaseRevokeRequestModel,
    AccessLeaseStatus as ApiAccessLeaseStatus,
};
use bitwarden_collections::collection::CollectionId;
use bitwarden_core::{OrganizationId, UserId, require};
use bitwarden_vault::CipherId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{AccessLeaseId, AccessRequestId, error::LeasingError};

/// The lifecycle state of an access lease.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[bitwarden_ffi::wasm_record]
#[serde(rename_all = "snake_case")]
pub enum AccessLeaseStatus {
    /// The lease is currently within its access window and grants access.
    Active,
    /// The lease's access window has closed; it no longer grants access.
    Expired,
    /// The lease was revoked before its window closed.
    Revoked,
    /// The lease was cancelled by its requester before its window closed.
    Canceled,
    /// A status value this SDK version does not recognize. Kept as a distinct variant so listing
    /// leases never fails on a newer server's status.
    Unknown,
}

impl From<ApiAccessLeaseStatus> for AccessLeaseStatus {
    fn from(status: ApiAccessLeaseStatus) -> Self {
        match status {
            ApiAccessLeaseStatus::Active => Self::Active,
            ApiAccessLeaseStatus::Expired => Self::Expired,
            ApiAccessLeaseStatus::Revoked => Self::Revoked,
            ApiAccessLeaseStatus::Cancelled => Self::Canceled,
            ApiAccessLeaseStatus::__Unknown(_) => Self::Unknown,
        }
    }
}

/// A decrypted view of an access lease, as its requester sees it.
///
/// A lease is the single-use grant that an approved [`AccessRequest`](crate::AccessRequestView)
/// mints when the requester activates it. While a lease is [`Active`](AccessLeaseStatus::Active)
/// the requester may open the otherwise-gated cipher; once it
/// [`Expired`](AccessLeaseStatus::Expired) or is [`Revoked`](AccessLeaseStatus::Revoked) the cipher
/// re-locks.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[bitwarden_ffi::wasm_record]
#[serde(rename_all = "camelCase")]
pub struct AccessLeaseView {
    /// The lease's unique identifier.
    pub id: AccessLeaseId,
    /// The request this lease was minted from.
    pub request_id: AccessRequestId,
    /// The cipher the lease grants access to.
    pub cipher_id: CipherId,
    /// The collection the cipher belongs to.
    pub collection_id: CollectionId,
    /// The organization that owns the cipher. None when the server omits it.
    pub organization_id: Option<OrganizationId>,
    /// The user the lease was granted to (the original requester).
    pub requester_id: UserId,
    /// The lease's lifecycle state.
    pub status: AccessLeaseStatus,
    /// When the lease's access window opens (UTC).
    pub not_before: DateTime<Utc>,
    /// When the lease's access window closes (UTC).
    pub not_after: DateTime<Utc>,
    /// When the lease was revoked early (UTC); None unless it was revoked before expiry.
    pub revoked_at: Option<DateTime<Utc>>,
    /// The user who revoked the lease; None unless it was revoked early.
    pub revoked_by_user_id: Option<UserId>,
}

impl TryFrom<AccessLeaseResponseModel> for AccessLeaseView {
    type Error = LeasingError;

    fn try_from(response: AccessLeaseResponseModel) -> Result<Self, Self::Error> {
        Ok(Self {
            id: AccessLeaseId::new(require!(response.id)),
            request_id: AccessRequestId::new(require!(response.request_id)),
            cipher_id: CipherId::new(require!(response.cipher_id)),
            collection_id: CollectionId::new(require!(response.collection_id)),
            organization_id: response.organization_id.map(OrganizationId::new),
            requester_id: UserId::new(require!(response.requester_id)),
            status: AccessLeaseStatus::from(require!(response.status)),
            not_before: require!(response.not_before).parse()?,
            not_after: require!(response.not_after).parse()?,
            revoked_at: response.revoked_at.map(|d| d.parse()).transpose()?,
            revoked_by_user_id: response.revoked_by_user_id.map(UserId::new),
        })
    }
}

/// Request to extend an active lease.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[bitwarden_ffi::wasm_record]
#[serde(rename_all = "camelCase")]
pub struct AccessLeaseExtensionRequest {
    /// How much further to push out the lease's end, in seconds. None asks the server to apply the
    /// governing rule's default extension. Must be positive and within the rule's maximum.
    pub duration_seconds: Option<NonZeroU32>,
    /// The justification recorded with the extension. Required by the server to be non-empty.
    pub reason: String,
}

impl From<AccessLeaseExtensionRequest> for AccessLeaseExtensionRequestModel {
    fn from(request: AccessLeaseExtensionRequest) -> Self {
        Self {
            duration_seconds: request.duration_seconds.map(|d| d.get() as i32),
            reason: request.reason,
        }
    }
}

/// Request to revoke (end) a lease before it expires.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
#[bitwarden_ffi::wasm_record]
#[serde(rename_all = "camelCase")]
pub struct AccessLeaseRevokeRequest {
    /// An optional note explaining the revocation. Recorded on the audit trail only.
    pub reason: Option<String>,
}

impl From<AccessLeaseRevokeRequest> for AccessLeaseRevokeRequestModel {
    fn from(request: AccessLeaseRevokeRequest) -> Self {
        Self {
            reason: request.reason,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use super::*;

    #[test]
    fn access_lease_extension_request_converts_to_model() {
        let request = AccessLeaseExtensionRequest {
            duration_seconds: NonZeroU32::new(3600),
            reason: "Need more time".to_string(),
        };

        let model = AccessLeaseExtensionRequestModel::from(request);

        assert_eq!(model.duration_seconds, Some(3600));
        assert_eq!(model.reason, "Need more time".to_string());
    }
}
