use bitwarden_core::{ApiError, MissingFieldError};
use bitwarden_error::bitwarden_error;
use thiserror::Error;

use crate::{EmergencyAccessClient, GrantorEmergencyAccess};

/// Errors returned when listing the emergency accesses granted to the current user.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum EmergencyAccessListGrantedError {
    /// The request to the server failed.
    #[error(transparent)]
    Api(#[from] ApiError),
    /// A required field was missing from the server response.
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
}

#[bitwarden_ffi::wasm_export]
impl EmergencyAccessClient {
    /// Lists the emergency accesses granted to the current user, one per grantor.
    ///
    /// Called by the grantee.
    pub async fn list_granted(
        &self,
    ) -> Result<Vec<GrantorEmergencyAccess>, EmergencyAccessListGrantedError> {
        let response = self
            .api_configurations
            .api_client
            .emergency_access_api()
            .get_grantees()
            .await?;

        // A missing list is treated as empty, matching how the clients parse list responses.
        Ok(response
            .data
            .unwrap_or_default()
            .into_iter()
            .map(GrantorEmergencyAccess::try_from)
            .collect::<Result<_, _>>()?)
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::models::{
        EmergencyAccessGrantorDetailsResponseModel,
        EmergencyAccessGrantorDetailsResponseModelListResponseModel, EmergencyAccessStatusType,
        EmergencyAccessType as ApiEmergencyAccessType,
    };
    use bitwarden_core::client::test_accounts::test_bitwarden_com_account_v2;

    use super::*;
    use crate::{
        EmergencyAccessClientExt, EmergencyAccessStatus, EmergencyAccessType,
        test_support::{TEST_EMERGENCY_ACCESS_ID, api_error, test_client, test_id},
    };

    const TEST_GRANTOR_ID: &str = "3ed3b8a2-6a1e-4e8b-9b6f-1c2d3e4f5a6b";

    fn approved() -> EmergencyAccessGrantorDetailsResponseModel {
        EmergencyAccessGrantorDetailsResponseModel {
            id: Some(TEST_EMERGENCY_ACCESS_ID.parse().unwrap()),
            status: Some(EmergencyAccessStatusType::RecoveryApproved),
            r#type: Some(ApiEmergencyAccessType::Takeover),
            wait_time_days: Some(2),
            grantor_id: Some(TEST_GRANTOR_ID.parse().unwrap()),
            name: Some("Grantor".to_owned()),
            email: Some("test@bitwarden.com".to_owned()),
            avatar_color: None,
            ..Default::default()
        }
    }

    async fn list(
        data: Option<Vec<EmergencyAccessGrantorDetailsResponseModel>>,
    ) -> Result<Vec<GrantorEmergencyAccess>, EmergencyAccessListGrantedError> {
        let response = EmergencyAccessGrantorDetailsResponseModelListResponseModel {
            data,
            ..Default::default()
        };

        let client = test_client(test_bitwarden_com_account_v2(), move |mock| {
            mock.emergency_access_api
                .expect_get_grantees()
                .returning(move || Ok(response.clone()))
                .once();
        })
        .await;

        client.emergency_access().list_granted().await
    }

    #[tokio::test]
    async fn maps_grantors() {
        let result = list(Some(vec![approved()])).await.unwrap();

        assert_eq!(
            result,
            [GrantorEmergencyAccess {
                id: test_id(),
                grantor_id: TEST_GRANTOR_ID.parse().unwrap(),
                name: Some("Grantor".to_owned()),
                email: Some("test@bitwarden.com".to_owned()),
                r#type: EmergencyAccessType::Takeover,
                status: EmergencyAccessStatus::RecoveryApproved,
                wait_time_days: 2,
                avatar_color: None,
            }]
        );
    }

    #[tokio::test]
    async fn returns_empty_list_when_data_is_missing() {
        assert!(list(None).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn fails_when_grantor_id_is_missing() {
        let missing = EmergencyAccessGrantorDetailsResponseModel {
            grantor_id: None,
            ..approved()
        };

        let result = list(Some(vec![missing])).await;

        assert!(matches!(
            result,
            Err(EmergencyAccessListGrantedError::MissingField(_))
        ));
    }

    #[tokio::test]
    async fn fails_when_request_fails() {
        let client = test_client(test_bitwarden_com_account_v2(), |mock| {
            mock.emergency_access_api
                .expect_get_grantees()
                .returning(api_error)
                .once();
        })
        .await;

        let result = client.emergency_access().list_granted().await;

        assert!(matches!(
            result,
            Err(EmergencyAccessListGrantedError::Api(_))
        ));
    }
}
