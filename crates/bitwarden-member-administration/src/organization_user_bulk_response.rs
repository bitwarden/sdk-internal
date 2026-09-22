use bitwarden_api_api::models::OrganizationUserBulkResponseModel;
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
    /// Why the operation failed for this member. Absent when it succeeded.
    pub error: Option<String>,
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

#[cfg(test)]
mod tests {
    use super::*;

    const MEMBER_A: &str = "1c4d9d5a-0000-4000-8000-00000000000a";

    /// Builds the row the server emits for one member. Success is an empty error string.
    fn row(id: Option<&str>, error: &str) -> OrganizationUserBulkResponseModel {
        OrganizationUserBulkResponseModel {
            object: Some("organizationUserBulkResponseModel".to_owned()),
            id: id.map(|id| id.parse().unwrap()),
            error: Some(error.to_owned()),
        }
    }

    #[test]
    fn empty_error_means_success() {
        let response = OrganizationUserBulkResponse::try_from(row(Some(MEMBER_A), "")).unwrap();

        assert_eq!(response.id, MEMBER_A.parse().unwrap());
        assert_eq!(response.error, None);
    }

    #[test]
    fn keeps_a_member_error() {
        let response =
            OrganizationUserBulkResponse::try_from(row(Some(MEMBER_A), "User is not staged."))
                .unwrap();

        assert_eq!(response.error, Some("User is not staged.".to_owned()));
    }

    #[test]
    fn fails_when_a_row_has_no_id() {
        assert!(OrganizationUserBulkResponse::try_from(row(None, "")).is_err());
    }
}
