use bitwarden_core::OrganizationId;
use bitwarden_organizations::OrganizationUserId;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{
    OrganizationUserBulkResponse, OrganizationUsersClient, OrganizationUsersError,
    organization_users_client::bulk::bulk_request,
};

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
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::apis::ApiClient;
    use bitwarden_core::{ApiError, OrganizationId};

    use super::*;
    use crate::organization_users_client::test_fixtures::{
        MEMBER_A, MEMBER_B, list, make_client, member, organization_id, row,
    };

    #[tokio::test]
    async fn posts_the_organization_and_member_ids() {
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
    async fn keeps_per_member_errors_without_failing_the_batch() {
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
    async fn propagates_a_rejected_batch() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.organization_users_api
                .expect_send_invite_to_staged_users()
                .returning(|_, _| Err(ApiError::Io(std::io::Error::other("connection reset"))));
        });

        let result = make_client(api_client)
            .send_staged_invites(organization_id(), vec![member(MEMBER_A)])
            .await;

        assert!(matches!(result, Err(OrganizationUsersError::Api(_))));
    }

    #[tokio::test]
    async fn fails_when_a_row_has_no_id() {
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
}
