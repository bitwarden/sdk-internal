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
#[cfg(feature = "wasm")]
use tsify::Tsify;

use crate::{AccessLeaseId, AccessRequestId, error::PamDecodeError};

/// The lifecycle state of an access lease.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
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
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
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
    /// How the lease's access ended ahead of its window, or None if it ran to
    /// [`Expired`](AccessLeaseStatus::Expired) or is still [`Active`](AccessLeaseStatus::Active).
    ///
    /// This carries what [`AccessLeaseStatus::Revoked`] cannot: that status covers both a
    /// self-service end and an operator-initiated revoke, and callers had to tell them apart by
    /// scanning the originating request's decision log for a human `deny` whose decider id matched
    /// the requester. Modelling it as an enum also makes the incoherent states unrepresentable -
    /// a revoker with no revocation time, or a self-end attributed to another user.
    pub termination: Option<AccessLeaseTermination>,
}

/// How an access lease's grant ended before its window closed.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AccessLeaseTermination {
    /// The holder ended their own lease.
    EndedByHolder {
        /// When the holder ended it (UTC).
        at: DateTime<Utc>,
    },
    /// An operator revoked the lease out from under the holder.
    Revoked {
        /// When it was revoked (UTC).
        at: DateTime<Utc>,
        /// The operator who revoked it. None when the server did not attribute the revocation.
        by_user_id: Option<UserId>,
    },
}

impl TryFrom<AccessLeaseResponseModel> for AccessLeaseView {
    type Error = PamDecodeError;

    fn try_from(response: AccessLeaseResponseModel) -> Result<Self, Self::Error> {
        let requester_id = UserId::new(require!(response.requester_id));
        let revoked_by_user_id = response.revoked_by_user_id.map(UserId::new);
        // `revoked_at` is the authoritative marker that access was cut short: a revoker id without
        // a revocation time is incoherent server data, and treating it as "not terminated" keeps
        // the lease readable rather than failing the whole list.
        let termination = response
            .revoked_at
            .map(|at| at.parse())
            .transpose()?
            .map(|at| {
                if revoked_by_user_id == Some(requester_id) {
                    AccessLeaseTermination::EndedByHolder { at }
                } else {
                    AccessLeaseTermination::Revoked {
                        at,
                        by_user_id: revoked_by_user_id,
                    }
                }
            });

        Ok(Self {
            id: AccessLeaseId::new(require!(response.id)),
            request_id: AccessRequestId::new(require!(response.request_id)),
            cipher_id: CipherId::new(require!(response.cipher_id)),
            collection_id: CollectionId::new(require!(response.collection_id)),
            organization_id: response.organization_id.map(OrganizationId::new),
            requester_id,
            status: AccessLeaseStatus::from(require!(response.status)),
            not_before: require!(response.not_before).parse()?,
            not_after: require!(response.not_after).parse()?,
            termination,
        })
    }
}

/// Request to extend an active lease.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
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
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
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

    use uuid::uuid;

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

    fn requester_id() -> uuid::Uuid {
        uuid!("88888888-8888-8888-8888-888888888888")
    }

    fn base_lease_response() -> AccessLeaseResponseModel {
        AccessLeaseResponseModel {
            id: Some(uuid!("33333333-3333-3333-3333-333333333333")),
            request_id: Some(uuid!("44444444-4444-4444-4444-444444444444")),
            cipher_id: Some(uuid!("55555555-5555-5555-5555-555555555555")),
            collection_id: Some(uuid!("66666666-6666-6666-6666-666666666666")),
            requester_id: Some(requester_id()),
            status: Some(ApiAccessLeaseStatus::Revoked),
            not_before: Some("2025-01-01T00:00:00Z".to_string()),
            not_after: Some("2025-01-01T01:00:00Z".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn termination_is_ended_by_holder_when_revoker_is_the_requester() {
        let response = AccessLeaseResponseModel {
            revoked_at: Some("2025-01-01T00:30:00Z".to_string()),
            revoked_by_user_id: Some(requester_id()),
            ..base_lease_response()
        };

        let view = AccessLeaseView::try_from(response).unwrap();

        assert_eq!(
            view.termination,
            Some(AccessLeaseTermination::EndedByHolder {
                at: "2025-01-01T00:30:00Z".parse().unwrap()
            })
        );
    }

    #[test]
    fn termination_is_revoked_when_revoker_is_an_operator() {
        let response = AccessLeaseResponseModel {
            revoked_at: Some("2025-01-01T00:30:00Z".to_string()),
            revoked_by_user_id: Some(uuid!("99999999-9999-9999-9999-999999999999")),
            ..base_lease_response()
        };

        let view = AccessLeaseView::try_from(response).unwrap();

        assert_eq!(
            view.termination,
            Some(AccessLeaseTermination::Revoked {
                at: "2025-01-01T00:30:00Z".parse().unwrap(),
                by_user_id: Some(UserId::new(uuid!("99999999-9999-9999-9999-999999999999"))),
            })
        );
    }

    #[test]
    fn termination_is_revoked_with_no_attribution_when_the_server_omits_the_revoker() {
        let response = AccessLeaseResponseModel {
            revoked_at: Some("2025-01-01T00:30:00Z".to_string()),
            revoked_by_user_id: None,
            ..base_lease_response()
        };

        let view = AccessLeaseView::try_from(response).unwrap();

        assert_eq!(
            view.termination,
            Some(AccessLeaseTermination::Revoked {
                at: "2025-01-01T00:30:00Z".parse().unwrap(),
                by_user_id: None,
            })
        );
    }

    #[test]
    fn a_revoker_without_a_revocation_time_is_not_a_termination() {
        // Incoherent server data: `revoked_at` is the authoritative marker, so the lease stays
        // readable rather than failing the whole list.
        let response = AccessLeaseResponseModel {
            revoked_at: None,
            revoked_by_user_id: Some(requester_id()),
            ..base_lease_response()
        };

        let view = AccessLeaseView::try_from(response).unwrap();

        assert_eq!(view.termination, None);
    }

    #[test]
    fn termination_is_none_when_the_lease_was_never_revoked() {
        let response = AccessLeaseResponseModel {
            status: Some(ApiAccessLeaseStatus::Active),
            revoked_at: None,
            revoked_by_user_id: None,
            ..base_lease_response()
        };

        let view = AccessLeaseView::try_from(response).unwrap();

        assert_eq!(view.termination, None);
    }
}
