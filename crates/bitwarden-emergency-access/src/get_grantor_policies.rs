use bitwarden_api_api::models::PolicyType as ApiPolicyType;
use bitwarden_core::ApiError;
use bitwarden_error::bitwarden_error;
use bitwarden_policies::{Policy, PolicyParseError};
use thiserror::Error;

use crate::{EmergencyAccessClient, EmergencyAccessId};

/// Errors returned when fetching the policies that apply to a grantor.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum EmergencyAccessGetGrantorPoliciesError {
    /// The request to the server failed.
    #[error(transparent)]
    Api(#[from] ApiError),
    /// A policy in the server response could not be parsed.
    #[error(transparent)]
    PolicyParse(#[from] PolicyParseError),
}

#[bitwarden_ffi::wasm_export]
impl EmergencyAccessClient {
    /// Fetches the policies of the organizations the grantor owns, to enforce them on the new
    /// master password during a takeover.
    ///
    /// The server only returns policies when the grantor owns an organization: other members are
    /// removed from their organizations on takeover, so their policies don't apply.
    ///
    /// Called by the grantee.
    pub async fn get_grantor_policies(
        &self,
        emergency_access_id: EmergencyAccessId,
    ) -> Result<Vec<Policy>, EmergencyAccessGetGrantorPoliciesError> {
        let response = self
            .api_configurations
            .api_client
            .emergency_access_api()
            .policies(emergency_access_id.into())
            .await?;

        // A missing list means no policies apply. Policy types unknown to this SDK can't be
        // enforced; skip them rather than failing the whole list.
        Ok(response
            .data
            .unwrap_or_default()
            .into_iter()
            .filter(|policy| !matches!(policy.r#type, Some(ApiPolicyType::__Unknown(_))))
            .map(Policy::try_from)
            .collect::<Result<_, _>>()?)
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::models::{PolicyResponseModel, PolicyResponseModelListResponseModel};
    use bitwarden_core::client::test_accounts::test_bitwarden_com_account_v2;
    use bitwarden_policies::PolicyType;

    use super::*;
    use crate::{
        EmergencyAccessClientExt,
        test_support::{api_error, is_test_id, test_client, test_id},
    };

    const TEST_POLICY_ID: &str = "0ae2ad8e-2f1c-4d1b-9d7c-7a4c3f4b8a11";
    const TEST_ORGANIZATION_ID: &str = "5b9e0a0c-7f3e-4b8a-9c1d-2e6f4a8b0c22";

    fn master_password_policy() -> PolicyResponseModel {
        PolicyResponseModel {
            id: Some(TEST_POLICY_ID.parse().unwrap()),
            organization_id: Some(TEST_ORGANIZATION_ID.parse().unwrap()),
            r#type: Some(ApiPolicyType::MasterPassword),
            data: Some(serde_json::json!({ "minLength": 12 })),
            enabled: Some(true),
            ..Default::default()
        }
    }

    async fn policies(
        data: Option<Vec<PolicyResponseModel>>,
    ) -> Result<Vec<Policy>, EmergencyAccessGetGrantorPoliciesError> {
        let response = PolicyResponseModelListResponseModel {
            data,
            ..Default::default()
        };

        let client = test_client(test_bitwarden_com_account_v2(), move |mock| {
            mock.emergency_access_api
                .expect_policies()
                .withf(is_test_id)
                .returning(move |_| Ok(response.clone()))
                .once();
        })
        .await;

        client
            .emergency_access()
            .get_grantor_policies(test_id())
            .await
    }

    #[tokio::test]
    async fn maps_policies() {
        let result = policies(Some(vec![master_password_policy()]))
            .await
            .unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id.to_string(), TEST_POLICY_ID);
        assert_eq!(result[0].organization_id.to_string(), TEST_ORGANIZATION_ID);
        assert_eq!(result[0].r#type, PolicyType::MasterPassword);
        assert_eq!(result[0].data.as_deref(), Some(r#"{"minLength":12}"#));
        assert!(result[0].enabled);
    }

    #[tokio::test]
    async fn returns_empty_list_when_data_is_missing() {
        assert!(policies(None).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn maps_enabled_and_disabled_policies() {
        // A disabled policy is still returned; the caller decides whether it applies.
        let disabled = PolicyResponseModel {
            enabled: Some(false),
            ..master_password_policy()
        };

        let result = policies(Some(vec![master_password_policy(), disabled]))
            .await
            .unwrap();

        let enabled: Vec<bool> = result.iter().map(|policy| policy.enabled).collect();
        assert_eq!(enabled, vec![true, false]);
    }

    #[tokio::test]
    async fn skips_unknown_policy_types() {
        // Mirrors the server returning every policy of the grantor's organizations, including
        // types newer than this SDK.
        let policy = |r#type| PolicyResponseModel {
            r#type: Some(r#type),
            ..master_password_policy()
        };

        let result = policies(Some(vec![
            policy(ApiPolicyType::__Unknown(998)),
            policy(ApiPolicyType::MasterPassword),
            policy(ApiPolicyType::TwoFactorAuthentication),
            policy(ApiPolicyType::__Unknown(999)),
            policy(ApiPolicyType::ResetPassword),
        ]))
        .await
        .unwrap();

        let types: Vec<PolicyType> = result.into_iter().map(|policy| policy.r#type).collect();
        assert_eq!(
            types,
            vec![
                PolicyType::MasterPassword,
                PolicyType::TwoFactorAuthentication,
                PolicyType::ResetPassword,
            ]
        );
    }

    #[tokio::test]
    async fn fails_when_request_fails() {
        let client = test_client(test_bitwarden_com_account_v2(), |mock| {
            mock.emergency_access_api
                .expect_policies()
                .returning(|_| api_error())
                .once();
        })
        .await;

        let result = client
            .emergency_access()
            .get_grantor_policies(test_id())
            .await;

        assert!(matches!(
            result,
            Err(EmergencyAccessGetGrantorPoliciesError::Api(_))
        ));
    }
}
