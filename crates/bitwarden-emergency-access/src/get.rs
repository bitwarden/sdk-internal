use bitwarden_core::{ApiError, MissingFieldError};
use bitwarden_error::bitwarden_error;
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{EmergencyAccessClient, EmergencyAccessId, GranteeEmergencyAccess};

/// Errors returned when fetching an emergency access.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum EmergencyAccessGetError {
    /// The request to the server failed.
    #[error(transparent)]
    Api(#[from] ApiError),
    /// A required field was missing from the server response.
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl EmergencyAccessClient {
    /// Fetches an emergency access the current user granted.
    ///
    /// Called by the grantor.
    pub async fn get(
        &self,
        emergency_access_id: EmergencyAccessId,
    ) -> Result<GranteeEmergencyAccess, EmergencyAccessGetError> {
        let response = self
            .api_configurations
            .api_client
            .emergency_access_api()
            .get(emergency_access_id.into())
            .await?;

        Ok(response.try_into()?)
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::models::{
        EmergencyAccessGranteeDetailsResponseModel, EmergencyAccessStatusType,
        EmergencyAccessType as ApiEmergencyAccessType,
    };
    use bitwarden_core::client::test_accounts::test_bitwarden_com_account;

    use super::*;
    use crate::{
        EmergencyAccessClientExt, EmergencyAccessStatus, EmergencyAccessType,
        test_support::{TEST_EMERGENCY_ACCESS_ID, api_error, is_test_id, test_client, test_id},
    };

    async fn get(
        response: EmergencyAccessGranteeDetailsResponseModel,
    ) -> Result<GranteeEmergencyAccess, EmergencyAccessGetError> {
        let client = test_client(test_bitwarden_com_account(), move |mock| {
            mock.emergency_access_api
                .expect_get()
                .withf(is_test_id)
                .returning(move |_| Ok(response.clone()))
                .once();
        })
        .await;

        client.emergency_access().get(test_id()).await
    }

    #[tokio::test]
    async fn maps_emergency_access() {
        let response = EmergencyAccessGranteeDetailsResponseModel {
            id: Some(TEST_EMERGENCY_ACCESS_ID.parse().unwrap()),
            status: Some(EmergencyAccessStatusType::Accepted),
            r#type: Some(ApiEmergencyAccessType::View),
            wait_time_days: Some(3),
            email: Some("grantee@bitwarden.com".to_owned()),
            ..Default::default()
        };

        let result = get(response).await.unwrap();

        assert_eq!(result.id, test_id());
        assert_eq!(result.r#type, EmergencyAccessType::View);
        assert_eq!(result.status, EmergencyAccessStatus::Accepted);
        assert_eq!(result.wait_time_days, 3);
        assert_eq!(result.email.as_deref(), Some("grantee@bitwarden.com"));
    }

    #[tokio::test]
    async fn fails_when_id_is_missing() {
        let result = get(EmergencyAccessGranteeDetailsResponseModel::default()).await;

        assert!(matches!(
            result,
            Err(EmergencyAccessGetError::MissingField(_))
        ));
    }

    #[tokio::test]
    async fn fails_when_request_fails() {
        let client = test_client(test_bitwarden_com_account(), |mock| {
            mock.emergency_access_api
                .expect_get()
                .returning(|_| api_error())
                .once();
        })
        .await;

        let result = client.emergency_access().get(test_id()).await;

        assert!(matches!(result, Err(EmergencyAccessGetError::Api(_))));
    }
}
