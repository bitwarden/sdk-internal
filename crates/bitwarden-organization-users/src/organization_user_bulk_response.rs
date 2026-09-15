use bitwarden_api_api::models::{
    OrganizationUserBulkResponseModel, OrganizationUserBulkResponseModelListResponseModel,
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

/// Builders for the rows the bulk member endpoints return, shared by the tests in this crate.
#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;

    /// Builds the row the server emits for one member. Success is an empty error string.
    pub(crate) fn row(id: Option<&str>, error: &str) -> OrganizationUserBulkResponseModel {
        OrganizationUserBulkResponseModel {
            object: Some("organizationUserBulkResponseModel".to_owned()),
            id: id.map(|id| id.parse().unwrap()),
            error: Some(error.to_owned()),
        }
    }

    pub(crate) fn list(
        data: Option<Vec<OrganizationUserBulkResponseModel>>,
    ) -> OrganizationUserBulkResponseModelListResponseModel {
        OrganizationUserBulkResponseModelListResponseModel {
            object: Some("list".to_owned()),
            data,
            continuation_token: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        fixtures::{list, row},
        *,
    };

    const MEMBER_A: &str = "1c4d9d5a-0000-4000-8000-00000000000a";
    const MEMBER_B: &str = "1c4d9d5a-0000-4000-8000-00000000000b";

    fn member(id: &str) -> OrganizationUserId {
        id.parse().unwrap()
    }

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
}
