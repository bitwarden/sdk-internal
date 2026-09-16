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

/// Errors returned from [`OrganizationUsersManagementClient`] operations.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum OrganizationUsersManagementError {
    /// The request failed as a whole.
    #[error(transparent)]
    Api(#[from] ApiError),
    /// A required field was missing from the server response.
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
}

/// Client for administering the members of an organization.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(FromClient)]
pub struct OrganizationUsersManagementClient {
    pub(crate) api_configurations: Arc<ApiConfigurations>,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl OrganizationUsersManagementClient {
    /// Sends invites to the given staged members, promoting them to invited and consuming a seat.
    ///
    /// Returns an `Err` if the entire request fails. Otherwise returns `Ok` containing success or
    /// failure information for each member.
    pub async fn send_staged_invites(
        &self,
        organization_id: OrganizationId,
        organization_user_ids: Vec<OrganizationUserId>,
    ) -> Result<Vec<OrganizationUserBulkResponse>, OrganizationUsersManagementError> {
        let response = self
            .api_configurations
            .api_client
            .organization_users_api()
            .send_invite_to_staged_users(
                organization_id.into(),
                Some(bulk_request(organization_user_ids)),
            )
            .await?;

        // A missing list is treated as empty, matching how the clients parse list responses.
        response
            .data
            .unwrap_or_default()
            .into_iter()
            .map(|row| OrganizationUserBulkResponse::try_from(row).map_err(Into::into))
            .collect()
    }

    /// Re-sends the invitation email to the given invited members.
    ///
    /// Returns an `Err` if the entire request fails. Otherwise returns `Ok` containing success or
    /// failure information for each member.
    pub async fn bulk_reinvite(
        &self,
        organization_id: OrganizationId,
        organization_user_ids: Vec<OrganizationUserId>,
    ) -> Result<Vec<OrganizationUserBulkResponse>, OrganizationUsersManagementError> {
        let response = self
            .api_configurations
            .api_client
            .organization_users_api()
            .bulk_reinvite(
                organization_id.into(),
                Some(bulk_request(organization_user_ids)),
            )
            .await?;

        // A missing list is treated as empty, matching how the clients parse list responses.
        response
            .data
            .unwrap_or_default()
            .into_iter()
            .map(|row| OrganizationUserBulkResponse::try_from(row).map_err(Into::into))
            .collect()
    }

    /// Re-sends the invitation email to a single invited member.
    pub async fn reinvite(
        &self,
        organization_id: OrganizationId,
        organization_user_id: OrganizationUserId,
    ) -> Result<(), OrganizationUsersManagementError> {
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

/// Extension trait exposing [`OrganizationUsersManagementClient`] on [`Client`].
pub trait OrganizationUsersManagementClientExt {
    /// Organization member administration operations.
    fn organization_users_management(&self) -> OrganizationUsersManagementClient;
}

impl OrganizationUsersManagementClientExt for Client {
    fn organization_users_management(&self) -> OrganizationUsersManagementClient {
        OrganizationUsersManagementClient::from_client(self)
    }
}
