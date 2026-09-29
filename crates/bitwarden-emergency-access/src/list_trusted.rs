use bitwarden_core::{ApiError, MissingFieldError};
use bitwarden_error::bitwarden_error;
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{EmergencyAccessClient, GranteeEmergencyAccess};

/// Errors returned when listing the current user's trusted emergency contacts.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum EmergencyAccessListTrustedError {
    /// The request to the server failed.
    #[error(transparent)]
    Api(#[from] ApiError),
    /// A required field was missing from the server response.
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl EmergencyAccessClient {
    /// Lists the emergency accesses the current user granted, one per trusted contact.
    ///
    /// Called by the grantor.
    pub async fn list_trusted(
        &self,
    ) -> Result<Vec<GranteeEmergencyAccess>, EmergencyAccessListTrustedError> {
        let response = self
            .api_configurations
            .api_client
            .emergency_access_api()
            .get_contacts()
            .await?;

        // A missing list is treated as empty, matching how the clients parse list responses.
        Ok(response
            .data
            .unwrap_or_default()
            .into_iter()
            .map(GranteeEmergencyAccess::try_from)
            .collect::<Result<_, _>>()?)
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::models::{
        EmergencyAccessGranteeDetailsResponseModel,
        EmergencyAccessGranteeDetailsResponseModelListResponseModel, EmergencyAccessStatusType,
        EmergencyAccessType as ApiEmergencyAccessType,
    };
    use bitwarden_core::client::test_accounts::test_bitwarden_com_account;

    use super::*;
    use crate::{
        EmergencyAccessClientExt, EmergencyAccessStatus, EmergencyAccessType,
        test_support::{TEST_EMERGENCY_ACCESS_ID, api_error, test_client, test_id},
    };

    const TEST_GRANTEE_ID: &str = "060000fb-0922-4dd3-b170-6e15cb5df8c8";

    fn invited() -> EmergencyAccessGranteeDetailsResponseModel {
        EmergencyAccessGranteeDetailsResponseModel {
            id: Some(TEST_EMERGENCY_ACCESS_ID.parse().unwrap()),
            status: Some(EmergencyAccessStatusType::Invited),
            r#type: Some(ApiEmergencyAccessType::View),
            wait_time_days: Some(7),
            email: Some("invited@bitwarden.com".to_owned()),
            ..Default::default()
        }
    }

    fn confirmed() -> EmergencyAccessGranteeDetailsResponseModel {
        EmergencyAccessGranteeDetailsResponseModel {
            id: Some(TEST_EMERGENCY_ACCESS_ID.parse().unwrap()),
            status: Some(EmergencyAccessStatusType::Confirmed),
            r#type: Some(ApiEmergencyAccessType::Takeover),
            wait_time_days: Some(1),
            grantee_id: Some(TEST_GRANTEE_ID.parse().unwrap()),
            name: Some("Grantee".to_owned()),
            email: Some("grantee@bitwarden.com".to_owned()),
            avatar_color: Some("#175ddc".to_owned()),
            ..Default::default()
        }
    }

    async fn list(
        data: Option<Vec<EmergencyAccessGranteeDetailsResponseModel>>,
    ) -> Result<Vec<GranteeEmergencyAccess>, EmergencyAccessListTrustedError> {
        let response = EmergencyAccessGranteeDetailsResponseModelListResponseModel {
            data,
            ..Default::default()
        };

        let client = test_client(test_bitwarden_com_account(), move |mock| {
            mock.emergency_access_api
                .expect_get_contacts()
                .returning(move || Ok(response.clone()))
                .once();
        })
        .await;

        client.emergency_access().list_trusted().await
    }

    #[tokio::test]
    async fn maps_trusted_contacts() {
        let result = list(Some(vec![invited(), confirmed()])).await.unwrap();

        assert_eq!(
            result,
            [
                GranteeEmergencyAccess {
                    id: test_id(),
                    grantee_id: None,
                    name: None,
                    email: Some("invited@bitwarden.com".to_owned()),
                    r#type: EmergencyAccessType::View,
                    status: EmergencyAccessStatus::Invited,
                    wait_time_days: 7,
                    avatar_color: None,
                },
                GranteeEmergencyAccess {
                    id: test_id(),
                    grantee_id: Some(TEST_GRANTEE_ID.parse().unwrap()),
                    name: Some("Grantee".to_owned()),
                    email: Some("grantee@bitwarden.com".to_owned()),
                    r#type: EmergencyAccessType::Takeover,
                    status: EmergencyAccessStatus::Confirmed,
                    wait_time_days: 1,
                    avatar_color: Some("#175ddc".to_owned()),
                },
            ]
        );
    }

    #[tokio::test]
    async fn returns_empty_list_when_data_is_missing() {
        assert!(list(None).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn fails_when_status_is_unknown() {
        let unknown = EmergencyAccessGranteeDetailsResponseModel {
            status: Some(EmergencyAccessStatusType::__Unknown(42)),
            ..confirmed()
        };

        let result = list(Some(vec![unknown])).await;

        assert!(matches!(
            result,
            Err(EmergencyAccessListTrustedError::MissingField(_))
        ));
    }

    #[tokio::test]
    async fn fails_when_request_fails() {
        let client = test_client(test_bitwarden_com_account(), |mock| {
            mock.emergency_access_api
                .expect_get_contacts()
                .returning(api_error)
                .once();
        })
        .await;

        let result = client.emergency_access().list_trusted().await;

        assert!(matches!(
            result,
            Err(EmergencyAccessListTrustedError::Api(_))
        ));
    }
}
