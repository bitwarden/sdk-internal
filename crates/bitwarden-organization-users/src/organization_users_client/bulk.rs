//! Shared request and response handling for the bulk member operations, which all post the same
//! list of member ids and return one outcome row per member.

use bitwarden_api_api::models::{
    OrganizationUserBulkRequestModel, OrganizationUserBulkResponseModel,
    OrganizationUserBulkResponseModelListResponseModel,
};
use bitwarden_core::{MissingFieldError, require};
use bitwarden_organizations::OrganizationUserId;
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;

/// The outcome of a bulk member operation for one organization member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi))]
pub struct OrganizationUserBulkResponse {
    /// The organization membership this outcome refers to.
    pub id: OrganizationUserId,
    /// Why the operation was skipped for this member. Absent when it succeeded.
    pub error: Option<String>,
}

impl OrganizationUserBulkResponse {
    /// Maps a bulk list response into one outcome per member.
    ///
    /// A missing list is treated as empty, matching how the clients parse list responses.
    pub(crate) fn from_list(
        response: OrganizationUserBulkResponseModelListResponseModel,
    ) -> Result<Vec<Self>, MissingFieldError> {
        response
            .data
            .unwrap_or_default()
            .into_iter()
            .map(Self::try_from)
            .collect()
    }
}

impl TryFrom<OrganizationUserBulkResponseModel> for OrganizationUserBulkResponse {
    type Error = MissingFieldError;

    fn try_from(model: OrganizationUserBulkResponseModel) -> Result<Self, Self::Error> {
        Ok(Self {
            id: OrganizationUserId::new(require!(model.id)),
            // The server reports success as an empty error string rather than omitting it.
            error: model.error.filter(|error| !error.is_empty()),
        })
    }
}

/// Builds the request body shared by the bulk member endpoints.
pub(crate) fn bulk_request(
    organization_user_ids: Vec<OrganizationUserId>,
) -> OrganizationUserBulkRequestModel {
    OrganizationUserBulkRequestModel::new(
        organization_user_ids.into_iter().map(Into::into).collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::organization_users_client::test_fixtures::{MEMBER_A, MEMBER_B, list, member, row};

    #[test]
    fn maps_each_row_and_normalizes_empty_errors() {
        let results = OrganizationUserBulkResponse::from_list(list(Some(vec![
            row(Some(MEMBER_A), ""),
            row(Some(MEMBER_B), "User is not staged."),
        ])))
        .unwrap();

        assert_eq!(
            results,
            vec![
                OrganizationUserBulkResponse {
                    id: member(MEMBER_A),
                    error: None,
                },
                OrganizationUserBulkResponse {
                    id: member(MEMBER_B),
                    error: Some("User is not staged.".to_owned()),
                },
            ]
        );
    }

    #[test]
    fn treats_a_missing_list_as_empty() {
        let results = OrganizationUserBulkResponse::from_list(list(None)).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn fails_when_a_row_has_no_id() {
        let result = OrganizationUserBulkResponse::from_list(list(Some(vec![row(None, "")])));
        assert!(result.is_err());
    }

    #[test]
    fn request_carries_the_member_ids_in_order() {
        let request = bulk_request(vec![member(MEMBER_A), member(MEMBER_B)]);

        let ids: Vec<OrganizationUserId> = request
            .ids
            .into_iter()
            .map(OrganizationUserId::new)
            .collect();
        assert_eq!(ids, vec![member(MEMBER_A), member(MEMBER_B)]);
        assert!(request.default_user_collection_name.is_none());
    }
}
