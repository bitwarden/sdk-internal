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

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl OrganizationUsersClient {
    /// Sends invites to the given staged members, promoting them to invited.
    ///
    /// The server handles each member separately and reports the outcome per member: a member
    /// that is no longer staged is skipped with an error on its own row rather than failing the
    /// batch, so a stale selection degrades to a partial send. The call fails as a whole when
    /// the caller may not manage members or when the organization cannot add the seats the
    /// invites need, because seats are reserved once for the entire set.
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

    /// Re-sends the invitation to the given invited members.
    ///
    /// The server handles each member separately and reports the outcome per member: a member
    /// that is not in the invited state is reported with an error on its own row rather than
    /// failing the batch. The call fails as a whole when the caller may not manage members.
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

    /// Re-sends the invitation to a single invited member.
    ///
    /// Unlike [`bulk_reinvite`](Self::bulk_reinvite), the server answers with no body, so the
    /// call either succeeds or fails as a whole. It fails when the member is not in the invited
    /// state or when the caller may not manage members.
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
    /// Organization member operations.
    fn organization_users(&self) -> OrganizationUsersClient;
}

impl OrganizationUsersClientExt for Client {
    fn organization_users(&self) -> OrganizationUsersClient {
        OrganizationUsersClient::from_client(self)
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::apis::ApiClient;

    use super::*;
    use crate::organization_user_bulk_response::fixtures::{list, row};

    const ORGANIZATION_ID: &str = "1bc9ac1e-f5aa-45f2-94bf-b181009709b8";
    const MEMBER_A: &str = "1c4d9d5a-0000-4000-8000-00000000000a";
    const MEMBER_B: &str = "1c4d9d5a-0000-4000-8000-00000000000b";

    fn make_client(api_client: ApiClient) -> OrganizationUsersClient {
        OrganizationUsersClient {
            api_configurations: Arc::new(ApiConfigurations::from_api_client(api_client)),
        }
    }

    fn organization_id() -> OrganizationId {
        ORGANIZATION_ID.parse().unwrap()
    }

    fn member(id: &str) -> OrganizationUserId {
        id.parse().unwrap()
    }

    fn rejected() -> ApiError {
        ApiError::Io(std::io::Error::other("connection reset"))
    }

    #[test]
    fn bulk_request_carries_the_member_ids_in_order() {
        let request = bulk_request(vec![member(MEMBER_A), member(MEMBER_B)]);

        let ids: Vec<OrganizationUserId> = request
            .ids
            .into_iter()
            .map(OrganizationUserId::new)
            .collect();
        assert_eq!(ids, vec![member(MEMBER_A), member(MEMBER_B)]);
        assert!(request.default_user_collection_name.is_none());
    }

    #[tokio::test]
    async fn send_staged_invites_posts_the_organization_and_member_ids() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.organization_users_api
                .expect_send_invite_to_staged_users()
                .withf(|org_id, body| {
                    OrganizationId::new(*org_id) == organization_id()
                        && *body == Some(bulk_request(vec![member(MEMBER_A), member(MEMBER_B)]))
                })
                .times(1)
                .returning(|_, _| Ok(list(Some(vec![]))));
        });

        make_client(api_client)
            .send_staged_invites(organization_id(), vec![member(MEMBER_A), member(MEMBER_B)])
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn send_staged_invites_keeps_per_member_errors_without_failing_the_batch() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.organization_users_api
                .expect_send_invite_to_staged_users()
                .returning(|_, _| {
                    Ok(list(Some(vec![
                        row(Some(MEMBER_A), ""),
                        row(Some(MEMBER_B), "User is not staged."),
                    ])))
                });
        });

        let results = make_client(api_client)
            .send_staged_invites(organization_id(), vec![member(MEMBER_A), member(MEMBER_B)])
            .await
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

    #[tokio::test]
    async fn send_staged_invites_propagates_a_rejected_batch() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.organization_users_api
                .expect_send_invite_to_staged_users()
                .returning(|_, _| Err(rejected()));
        });

        let result = make_client(api_client)
            .send_staged_invites(organization_id(), vec![member(MEMBER_A)])
            .await;

        assert!(matches!(result, Err(OrganizationUsersError::Api(_))));
    }

    #[tokio::test]
    async fn send_staged_invites_fails_when_a_row_has_no_id() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.organization_users_api
                .expect_send_invite_to_staged_users()
                .returning(|_, _| Ok(list(Some(vec![row(None, "")]))));
        });

        let result = make_client(api_client)
            .send_staged_invites(organization_id(), vec![member(MEMBER_A)])
            .await;

        assert!(matches!(
            result,
            Err(OrganizationUsersError::MissingField(_))
        ));
    }

    #[tokio::test]
    async fn bulk_reinvite_posts_the_organization_and_member_ids() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.organization_users_api
                .expect_bulk_reinvite()
                .withf(|org_id, body| {
                    OrganizationId::new(*org_id) == organization_id()
                        && *body == Some(bulk_request(vec![member(MEMBER_A), member(MEMBER_B)]))
                })
                .times(1)
                .returning(|_, _| Ok(list(Some(vec![]))));
        });

        make_client(api_client)
            .bulk_reinvite(organization_id(), vec![member(MEMBER_A), member(MEMBER_B)])
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn bulk_reinvite_keeps_per_member_errors_without_failing_the_batch() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.organization_users_api
                .expect_bulk_reinvite()
                .returning(|_, _| {
                    Ok(list(Some(vec![
                        row(Some(MEMBER_A), ""),
                        row(Some(MEMBER_B), "User invalid."),
                    ])))
                });
        });

        let results = make_client(api_client)
            .bulk_reinvite(organization_id(), vec![member(MEMBER_A), member(MEMBER_B)])
            .await
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
                    error: Some("User invalid.".to_owned()),
                },
            ]
        );
    }

    #[tokio::test]
    async fn bulk_reinvite_propagates_a_rejected_batch() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.organization_users_api
                .expect_bulk_reinvite()
                .returning(|_, _| Err(rejected()));
        });

        let result = make_client(api_client)
            .bulk_reinvite(organization_id(), vec![member(MEMBER_A)])
            .await;

        assert!(matches!(result, Err(OrganizationUsersError::Api(_))));
    }

    #[tokio::test]
    async fn reinvite_posts_to_the_member_reinvite_endpoint() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.organization_users_api
                .expect_reinvite()
                .withf(|org_id, id| {
                    OrganizationId::new(*org_id) == organization_id()
                        && OrganizationUserId::new(*id) == member(MEMBER_A)
                })
                .times(1)
                .returning(|_, _| Ok(()));
        });

        make_client(api_client)
            .reinvite(organization_id(), member(MEMBER_A))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn reinvite_propagates_a_rejected_request() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.organization_users_api
                .expect_reinvite()
                .returning(|_, _| Err(rejected()));
        });

        let result = make_client(api_client)
            .reinvite(organization_id(), member(MEMBER_A))
            .await;

        assert!(matches!(result, Err(OrganizationUsersError::Api(_))));
    }
}
