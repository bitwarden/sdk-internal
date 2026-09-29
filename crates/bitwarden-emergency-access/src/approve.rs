use bitwarden_core::ApiError;
use bitwarden_error::bitwarden_error;
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{EmergencyAccessClient, EmergencyAccessId};

/// Errors returned when approving an emergency access request.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum EmergencyAccessApproveError {
    /// The request to the server failed.
    #[error(transparent)]
    Api(#[from] ApiError),
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl EmergencyAccessClient {
    /// Approves the grantee's access request before the wait time passes.
    ///
    /// Called by the grantor.
    pub async fn approve(
        &self,
        emergency_access_id: EmergencyAccessId,
    ) -> Result<(), EmergencyAccessApproveError> {
        self.api_configurations
            .api_client
            .emergency_access_api()
            .approve(emergency_access_id.into())
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::client::test_accounts::test_bitwarden_com_account;

    use super::*;
    use crate::{
        EmergencyAccessClientExt,
        test_support::{api_error, is_test_id, test_client, test_id},
    };

    #[tokio::test]
    async fn approves() {
        let client = test_client(test_bitwarden_com_account(), |mock| {
            mock.emergency_access_api
                .expect_approve()
                .withf(is_test_id)
                .returning(|_| Ok(()))
                .once();
        })
        .await;

        client.emergency_access().approve(test_id()).await.unwrap();
    }

    #[tokio::test]
    async fn fails_when_request_fails() {
        let client = test_client(test_bitwarden_com_account(), |mock| {
            mock.emergency_access_api
                .expect_approve()
                .returning(|_| api_error())
                .once();
        })
        .await;

        let result = client.emergency_access().approve(test_id()).await;

        assert!(matches!(result, Err(EmergencyAccessApproveError::Api(_))));
    }
}
