use std::sync::Arc;

use bitwarden_api_api::models::OrganizationUserBulkRequestModel;
use bitwarden_core::{
    ApiError, Client, FromClient, MissingFieldError, OrganizationId, client::ApiConfigurations,
};
use bitwarden_error::bitwarden_error;
use bitwarden_organizations::OrganizationUserId;
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::OrganizationUserBulkResponse;

/// Errors returned from [`OrganizationUsersClient`] operations.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum OrganizationUsersError {
    /// The request failed as a whole.
    #[error(transparent)]
    Api(#[from] ApiError),
    /// A required field was missing from the server response.
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
}

/// Client for administering the members of an organization. Every operation requires the caller
/// to be permitted to manage the organization's members.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(FromClient)]
pub struct OrganizationUsersClient {
    pub(crate) api_configurations: Arc<ApiConfigurations>,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl OrganizationUsersClient {
    /// Sends invites to the given staged members, promoting them to invited and consuming a seat.
    ///
    /// Returns an `Err` if the entire request fails. Otherwise returns `Ok` containing success or
    /// failure information for each member.
    pub async fn send_staged_invites(
        &self,
        organization_id: OrganizationId,
        organization_user_ids: Vec<OrganizationUserId>,
    ) -> Result<Vec<OrganizationUserBulkResponse>, OrganizationUsersError> {
        let response = self
            .api_configurations
            .api_client
            .organization_users_api()
            .send_invite_to_staged_users(
                organization_id.into(),
                Some(bulk_request(organization_user_ids)),
            )
            .await?;

        OrganizationUserBulkResponse::from_list(response).map_err(Into::into)
    }

    /// Re-sends the invitation email to the given invited members.
    ///
    /// Returns an `Err` if the entire request fails. Otherwise returns `Ok` containing success or
    /// failure information for each member.
    pub async fn bulk_reinvite(
        &self,
        organization_id: OrganizationId,
        organization_user_ids: Vec<OrganizationUserId>,
    ) -> Result<Vec<OrganizationUserBulkResponse>, OrganizationUsersError> {
        let response = self
            .api_configurations
            .api_client
            .organization_users_api()
            .bulk_reinvite(
                organization_id.into(),
                Some(bulk_request(organization_user_ids)),
            )
            .await?;

        OrganizationUserBulkResponse::from_list(response).map_err(Into::into)
    }

    /// Re-sends the invitation email to a single invited member.
    pub async fn reinvite(
        &self,
        organization_id: OrganizationId,
        organization_user_id: OrganizationUserId,
    ) -> Result<(), OrganizationUsersError> {
        self.api_configurations
            .api_client
            .organization_users_api()
            .reinvite(organization_id.into(), organization_user_id.into())
            .await?;

        Ok(())
    }
}

/// Builds the request body shared by the bulk member endpoints.
fn bulk_request(
    organization_user_ids: Vec<OrganizationUserId>,
) -> OrganizationUserBulkRequestModel {
    OrganizationUserBulkRequestModel::new(
        organization_user_ids.into_iter().map(Into::into).collect(),
    )
}

/// Extension trait exposing [`OrganizationUsersClient`] on [`Client`].
pub trait OrganizationUsersClientExt {
    /// Organization member administration operations.
    fn organization_users(&self) -> OrganizationUsersClient;
}

impl OrganizationUsersClientExt for Client {
    fn organization_users(&self) -> OrganizationUsersClient {
        OrganizationUsersClient::from_client(self)
    }
}
