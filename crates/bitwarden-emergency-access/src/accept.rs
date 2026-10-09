use bitwarden_api_api::models::EmergencyAccessAcceptRequestModel;
use bitwarden_core::ApiError;
use bitwarden_error::bitwarden_error;
use thiserror::Error;

use crate::{EmergencyAccessClient, EmergencyAccessId};

/// Errors returned when accepting an emergency access invite.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum EmergencyAccessAcceptError {
    /// The request to the server failed.
    #[error(transparent)]
    Api(#[from] ApiError),
}

#[bitwarden_ffi::wasm_export]
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
        let request = EmergencyAccessAcceptRequestModel { token };

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
                            == Some(EmergencyAccessAcceptRequestModel {
                                token: TEST_TOKEN.to_owned(),
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
