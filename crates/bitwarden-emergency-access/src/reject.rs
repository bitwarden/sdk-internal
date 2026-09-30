use bitwarden_core::ApiError;
use bitwarden_error::bitwarden_error;
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{EmergencyAccessClient, EmergencyAccessId};

/// Errors returned when rejecting an emergency access request.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum EmergencyAccessRejectError {
    /// The request to the server failed.
    #[error(transparent)]
    Api(#[from] ApiError),
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl EmergencyAccessClient {
    /// Rejects the grantee's access request.
    ///
    /// Called by the grantor.
    pub async fn reject(
        &self,
        emergency_access_id: EmergencyAccessId,
    ) -> Result<(), EmergencyAccessRejectError> {
        self.api_configurations
            .api_client
            .emergency_access_api()
            .reject(emergency_access_id.into())
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
    async fn rejects() {
        let client = test_client(test_bitwarden_com_account(), |mock| {
            mock.emergency_access_api
                .expect_reject()
                .withf(is_test_id)
                .returning(|_| Ok(()))
                .once();
        })
        .await;

        client.emergency_access().reject(test_id()).await.unwrap();
    }

    #[tokio::test]
    async fn fails_when_request_fails() {
        let client = test_client(test_bitwarden_com_account(), |mock| {
            mock.emergency_access_api
                .expect_reject()
                .returning(|_| api_error())
                .once();
        })
        .await;

        let result = client.emergency_access().reject(test_id()).await;

        assert!(matches!(result, Err(EmergencyAccessRejectError::Api(_))));
    }
}
