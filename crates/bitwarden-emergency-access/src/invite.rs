use bitwarden_api_api::models::EmergencyAccessInviteRequestModel;
use bitwarden_core::ApiError;
use bitwarden_error::bitwarden_error;
use thiserror::Error;

use crate::{EmergencyAccessClient, EmergencyAccessType};

/// Errors returned when inviting an emergency contact.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum EmergencyAccessInviteError {
    /// The request to the server failed.
    #[error(transparent)]
    Api(#[from] ApiError),
}

#[bitwarden_ffi::wasm_export]
impl EmergencyAccessClient {
    /// Invites `grantee_email` to become a trusted emergency contact. Step 1 of the setup; the
    /// grantee accepts next.
    ///
    /// Called by the grantor.
    pub async fn invite(
        &self,
        grantee_email: String,
        r#type: EmergencyAccessType,
        wait_time_days: i32,
    ) -> Result<(), EmergencyAccessInviteError> {
        let request = EmergencyAccessInviteRequestModel {
            email: grantee_email.trim().to_owned(),
            r#type: r#type.into(),
            wait_time_days,
        };

        self.api_configurations
            .api_client
            .emergency_access_api()
            .invite(Some(request))
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
        test_support::{api_error, test_client},
    };

    const TEST_EMAIL: &str = "grantee@bitwarden.com";
    const TEST_WAIT_TIME_DAYS: i32 = 7;

    #[tokio::test]
    async fn sends_trimmed_invite() {
        let client = test_client(test_bitwarden_com_account(), |mock| {
            mock.emergency_access_api
                .expect_invite()
                .withf(|request| {
                    *request
                        == Some(EmergencyAccessInviteRequestModel {
                            email: TEST_EMAIL.to_owned(),
                            r#type: ApiEmergencyAccessType::Takeover,
                            wait_time_days: TEST_WAIT_TIME_DAYS,
                        })
                })
                .returning(|_| Ok(()))
                .once();
        })
        .await;

        client
            .emergency_access()
            .invite(
                format!("  {TEST_EMAIL} "),
                EmergencyAccessType::Takeover,
                TEST_WAIT_TIME_DAYS,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn fails_when_request_fails() {
        let client = test_client(test_bitwarden_com_account(), |mock| {
            mock.emergency_access_api
                .expect_invite()
                .returning(|_| api_error())
                .once();
        })
        .await;

        let result = client
            .emergency_access()
            .invite(
                TEST_EMAIL.to_owned(),
                EmergencyAccessType::View,
                TEST_WAIT_TIME_DAYS,
            )
            .await;

        assert!(matches!(result, Err(EmergencyAccessInviteError::Api(_))));
    }
}
