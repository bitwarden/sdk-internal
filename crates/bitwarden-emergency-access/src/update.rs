use bitwarden_api_api::models::EmergencyAccessUpdateRequestModel;
use bitwarden_core::ApiError;
use bitwarden_error::bitwarden_error;
use thiserror::Error;

use crate::{EmergencyAccessClient, EmergencyAccessId, EmergencyAccessType};

/// Errors returned when editing an emergency access.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum EmergencyAccessUpdateError {
    /// The request to the server failed.
    #[error(transparent)]
    Api(#[from] ApiError),
}

#[bitwarden_ffi::wasm_export]
impl EmergencyAccessClient {
    /// Changes the access type and wait time of an emergency access.
    ///
    /// Called by the grantor.
    pub async fn update(
        &self,
        emergency_access_id: EmergencyAccessId,
        r#type: EmergencyAccessType,
        wait_time_days: i32,
    ) -> Result<(), EmergencyAccessUpdateError> {
        // The shared key is left untouched; it only changes on confirm and key rotation.
        let request = EmergencyAccessUpdateRequestModel {
            r#type: r#type.into(),
            wait_time_days,
            key_encrypted: None,
        };

        self.api_configurations
            .api_client
            .emergency_access_api()
            .put(emergency_access_id.into(), Some(request))
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::models::EmergencyAccessType as ApiEmergencyAccessType;
    use bitwarden_core::client::test_accounts::test_bitwarden_com_account;

    use super::*;
    use crate::{
        EmergencyAccessClientExt,
        test_support::{api_error, is_test_id, test_client, test_id},
    };

    const TEST_WAIT_TIME_DAYS: i32 = 14;

    #[tokio::test]
    async fn sends_type_and_wait_time() {
        let client = test_client(test_bitwarden_com_account(), |mock| {
            mock.emergency_access_api
                .expect_put()
                .withf(|id, request| {
                    is_test_id(id)
                        && *request
                            == Some(EmergencyAccessUpdateRequestModel {
                                r#type: ApiEmergencyAccessType::View,
                                wait_time_days: TEST_WAIT_TIME_DAYS,
                                key_encrypted: None,
                            })
                })
                .returning(|_, _| Ok(()))
                .once();
        })
        .await;

        client
            .emergency_access()
            .update(test_id(), EmergencyAccessType::View, TEST_WAIT_TIME_DAYS)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn fails_when_request_fails() {
        let client = test_client(test_bitwarden_com_account(), |mock| {
            mock.emergency_access_api
                .expect_put()
                .returning(|_, _| api_error())
                .once();
        })
        .await;

        let result = client
            .emergency_access()
            .update(test_id(), EmergencyAccessType::View, TEST_WAIT_TIME_DAYS)
            .await;

        assert!(matches!(result, Err(EmergencyAccessUpdateError::Api(_))));
    }
}
