use std::sync::Arc;

use bitwarden_core::{ApiError, Client, FromClient, MissingFieldError, client::ApiConfigurations};
use bitwarden_error::bitwarden_error;
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

mod bulk;
mod bulk_reinvite;
mod reinvite;
mod send_staged_invites;

pub use bulk::OrganizationUserBulkResponse;

/// Errors returned from [`OrganizationUsersClient`] operations.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum OrganizationUsersError {
    /// The request was rejected as a whole, for example because the caller may not manage
    /// members. Problems with individual members are reported on the returned rows instead.
    #[error(transparent)]
    Api(#[from] ApiError),
    /// A required field was missing from the server response.
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
}

/// Client for managing the members of an organization.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(FromClient)]
pub struct OrganizationUsersClient {
    pub(crate) api_configurations: Arc<ApiConfigurations>,
}

/// Extension trait exposing [`OrganizationUsersClient`] on [`Client`].
pub trait OrganizationUsersClientExt {
    /// Organization member operations.
    fn organization_users(&self) -> OrganizationUsersClient;
}

impl OrganizationUsersClientExt for Client {
    fn organization_users(&self) -> OrganizationUsersClient {
        OrganizationUsersClient::from_client(self)
    }
}

/// Fixtures shared by the command tests: a client over a mocked API and the rows the bulk
/// endpoints return.
#[cfg(test)]
pub(crate) mod test_fixtures {
    use std::sync::Arc;

    use bitwarden_api_api::{
        apis::ApiClient,
        models::{
            OrganizationUserBulkResponseModel, OrganizationUserBulkResponseModelListResponseModel,
        },
    };
    use bitwarden_core::{OrganizationId, client::ApiConfigurations};
    use bitwarden_organizations::OrganizationUserId;

    use super::OrganizationUsersClient;

    pub(crate) const ORGANIZATION_ID: &str = "1bc9ac1e-f5aa-45f2-94bf-b181009709b8";
    pub(crate) const MEMBER_A: &str = "1c4d9d5a-0000-4000-8000-00000000000a";
    pub(crate) const MEMBER_B: &str = "1c4d9d5a-0000-4000-8000-00000000000b";

    pub(crate) fn make_client(api_client: ApiClient) -> OrganizationUsersClient {
        OrganizationUsersClient {
            api_configurations: Arc::new(ApiConfigurations::from_api_client(api_client)),
        }
    }

    pub(crate) fn organization_id() -> OrganizationId {
        ORGANIZATION_ID.parse().unwrap()
    }

    pub(crate) fn member(id: &str) -> OrganizationUserId {
        id.parse().unwrap()
    }

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
