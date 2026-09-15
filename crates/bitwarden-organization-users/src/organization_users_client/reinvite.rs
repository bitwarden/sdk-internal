use bitwarden_core::OrganizationId;
use bitwarden_organizations::OrganizationUserId;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{OrganizationUsersClient, OrganizationUsersError};

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl OrganizationUsersClient {
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

#[cfg(test)]
mod tests {
    use bitwarden_api_api::apis::ApiClient;
    use bitwarden_core::{ApiError, OrganizationId};

    use super::*;
    use crate::organization_users_client::test_fixtures::{
        MEMBER_A, make_client, member, organization_id,
    };

    #[tokio::test]
    async fn posts_to_the_member_reinvite_endpoint() {
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
    async fn propagates_a_rejected_request() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.organization_users_api
                .expect_reinvite()
                .returning(|_, _| Err(ApiError::Io(std::io::Error::other("connection reset"))));
        });

        let result = make_client(api_client)
            .reinvite(organization_id(), member(MEMBER_A))
            .await;

        assert!(matches!(result, Err(OrganizationUsersError::Api(_))));
    }
}
