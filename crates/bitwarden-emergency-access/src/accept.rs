use bitwarden_api_api::models::OrganizationUserAcceptRequestModel;
use bitwarden_core::ApiError;
use bitwarden_error::bitwarden_error;
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{EmergencyAccessClient, EmergencyAccessId};

/// Errors returned when accepting an emergency access invite.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum EmergencyAccessAcceptError {
    /// The request to the server failed.
    #[error(transparent)]
    Api(#[from] ApiError),
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl EmergencyAccessClient {
    /// Accepts an emergency access invite with the `token` from the invite email. Step 2 of the
    /// setup; the grantor confirms next.
    ///
    /// Called by the grantee.
    pub async fn accept(
        &self,
        emergency_access_id: EmergencyAccessId,
        token: String,
    ) -> Result<(), EmergencyAccessAcceptError> {
        // The server reuses the organization invite request model; only the token applies.
        let request = OrganizationUserAcceptRequestModel {
            token,
            reset_password_key: None,
        };

        self.api_configurations
            .api_client
            .emergency_access_api()
            .accept(emergency_access_id.into(), Some(request))
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::client::test_accounts::test_bitwarden_com_account_v2;

    use super::*;
    use crate::{
        EmergencyAccessClientExt,
        test_support::{api_error, is_test_id, test_client, test_id},
    };

    const TEST_TOKEN: &str = "invite-token";

    #[tokio::test]
    async fn sends_token() {
        let client = test_client(test_bitwarden_com_account_v2(), |mock| {
            mock.emergency_access_api
                .expect_accept()
                .withf(|id, request| {
                    is_test_id(id)
                        && *request
                            == Some(OrganizationUserAcceptRequestModel {
                                token: TEST_TOKEN.to_owned(),
                                reset_password_key: None,
                            })
                })
                .returning(|_, _| Ok(()))
                .once();
        })
        .await;

        client
            .emergency_access()
            .accept(test_id(), TEST_TOKEN.to_owned())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn fails_when_request_fails() {
        let client = test_client(test_bitwarden_com_account_v2(), |mock| {
            mock.emergency_access_api
                .expect_accept()
                .returning(|_, _| api_error())
                .once();
        })
        .await;

        let result = client
            .emergency_access()
            .accept(test_id(), TEST_TOKEN.to_owned())
            .await;

        assert!(matches!(result, Err(EmergencyAccessAcceptError::Api(_))));
    }
}
