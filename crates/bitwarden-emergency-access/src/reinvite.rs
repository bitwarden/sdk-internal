use bitwarden_core::ApiError;
use bitwarden_error::bitwarden_error;
use thiserror::Error;

use crate::{EmergencyAccessClient, EmergencyAccessId};

/// Errors returned when re-sending an emergency access invite.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum EmergencyAccessReinviteError {
    /// The request to the server failed.
    #[error(transparent)]
    Api(#[from] ApiError),
}

#[bitwarden_ffi::wasm_export]
impl EmergencyAccessClient {
    /// Re-sends the invite email of an emergency access the grantee has not accepted yet.
    ///
    /// Called by the grantor.
    pub async fn reinvite(
        &self,
        emergency_access_id: EmergencyAccessId,
    ) -> Result<(), EmergencyAccessReinviteError> {
        self.api_configurations
            .api_client
            .emergency_access_api()
            .reinvite(emergency_access_id.into())
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
    async fn reinvites() {
        let client = test_client(test_bitwarden_com_account(), |mock| {
            mock.emergency_access_api
                .expect_reinvite()
                .withf(is_test_id)
                .returning(|_| Ok(()))
                .once();
        })
        .await;

        client.emergency_access().reinvite(test_id()).await.unwrap();
    }

    #[tokio::test]
    async fn fails_when_request_fails() {
        let client = test_client(test_bitwarden_com_account(), |mock| {
            mock.emergency_access_api
                .expect_reinvite()
                .returning(|_| api_error())
                .once();
        })
        .await;

        let result = client.emergency_access().reinvite(test_id()).await;

        assert!(matches!(result, Err(EmergencyAccessReinviteError::Api(_))));
    }
}
