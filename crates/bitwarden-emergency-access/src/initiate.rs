use bitwarden_core::ApiError;
use bitwarden_error::bitwarden_error;
use thiserror::Error;

use crate::{EmergencyAccessClient, EmergencyAccessId};

/// Errors returned when requesting emergency access.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum EmergencyAccessInitiateError {
    /// The request to the server failed.
    #[error(transparent)]
    Api(#[from] ApiError),
}

#[bitwarden_ffi::wasm_export]
impl EmergencyAccessClient {
    /// Requests access to the grantor's account. Access is granted once the grantor approves or
    /// the wait time passes.
    ///
    /// Called by the grantee.
    pub async fn initiate(
        &self,
        emergency_access_id: EmergencyAccessId,
    ) -> Result<(), EmergencyAccessInitiateError> {
        self.api_configurations
            .api_client
            .emergency_access_api()
            .initiate(emergency_access_id.into())
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

    #[tokio::test]
    async fn initiates() {
        let client = test_client(test_bitwarden_com_account_v2(), |mock| {
            mock.emergency_access_api
                .expect_initiate()
                .withf(is_test_id)
                .returning(|_| Ok(()))
                .once();
        })
        .await;

        client.emergency_access().initiate(test_id()).await.unwrap();
    }

    #[tokio::test]
    async fn fails_when_request_fails() {
        let client = test_client(test_bitwarden_com_account_v2(), |mock| {
            mock.emergency_access_api
                .expect_initiate()
                .returning(|_| api_error())
                .once();
        })
        .await;

        let result = client.emergency_access().initiate(test_id()).await;

        assert!(matches!(result, Err(EmergencyAccessInitiateError::Api(_))));
    }
}
