use std::sync::Arc;

use bitwarden_core::{ApiError, FromClient, OrganizationId, client::ApiConfigurations};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use super::{
    error::AccessRuleError,
    models::{AccessRuleAddEditRequest, AccessRuleView},
    validate::validate_request,
};
use crate::AccessRuleId;

/// Client for PAM access rule CRUD operations.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(FromClient)]
pub struct AccessRulesClient {
    pub(crate) api_configurations: Arc<ApiConfigurations>,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl AccessRulesClient {
    /// Lists all access rules for an organization.
    pub async fn list(
        &self,
        organization_id: OrganizationId,
    ) -> Result<Vec<AccessRuleView>, AccessRuleError> {
        let response = self
            .api_configurations
            .api_client
            .access_rules_api()
            .get_all(organization_id.into())
            .await
            .map_err(ApiError::from)?;

        response
            .data
            .unwrap_or_default()
            .into_iter()
            .map(AccessRuleView::try_from)
            .collect()
    }

    /// Retrieves a single access rule by ID.
    pub async fn get(
        &self,
        organization_id: OrganizationId,
        id: AccessRuleId,
    ) -> Result<AccessRuleView, AccessRuleError> {
        let response = self
            .api_configurations
            .api_client
            .access_rules_api()
            .get(organization_id.into(), id.into())
            .await
            .map_err(ApiError::from)?;

        AccessRuleView::try_from(response)
    }

    /// Validates and creates a new access rule.
    pub async fn create(
        &self,
        organization_id: OrganizationId,
        request: AccessRuleAddEditRequest,
    ) -> Result<AccessRuleView, AccessRuleError> {
        validate_request(&request)?;

        let response = self
            .api_configurations
            .api_client
            .access_rules_api()
            .post(organization_id.into(), request.try_into()?)
            .await
            .map_err(ApiError::from)?;

        AccessRuleView::try_from(response)
    }

    /// Validates and updates an existing access rule.
    pub async fn update(
        &self,
        organization_id: OrganizationId,
        id: AccessRuleId,
        request: AccessRuleAddEditRequest,
    ) -> Result<AccessRuleView, AccessRuleError> {
        validate_request(&request)?;

        let response = self
            .api_configurations
            .api_client
            .access_rules_api()
            .put(organization_id.into(), id.into(), request.try_into()?)
            .await
            .map_err(ApiError::from)?;

        AccessRuleView::try_from(response)
    }

    /// Deletes an access rule.
    pub async fn delete(
        &self,
        organization_id: OrganizationId,
        id: AccessRuleId,
    ) -> Result<(), AccessRuleError> {
        self.api_configurations
            .api_client
            .access_rules_api()
            .delete(organization_id.into(), id.into())
            .await
            .map_err(ApiError::from)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{apis::ApiClient, models::AccessRuleResponseModel};
    use uuid::uuid;

    use super::*;
    use crate::AccessCondition;

    fn org_id() -> OrganizationId {
        OrganizationId::new(uuid!("11111111-1111-1111-1111-111111111111"))
    }

    fn rule_id() -> AccessRuleId {
        AccessRuleId::new(uuid!("22222222-2222-2222-2222-222222222222"))
    }

    fn client(api_client: ApiClient) -> AccessRulesClient {
        AccessRulesClient {
            api_configurations: Arc::new(ApiConfigurations::from_api_client(api_client)),
        }
    }

    fn sample_response(id: uuid::Uuid, organization_id: uuid::Uuid) -> AccessRuleResponseModel {
        let mut response = AccessRuleResponseModel::new();
        response.id = Some(id);
        response.organization_id = Some(organization_id);
        response.name = Some("My rule".to_string());
        response.conditions = Some(serde_json::json!([]));
        response.creation_date = Some("2025-01-01T00:00:00Z".to_string());
        response.revision_date = Some("2025-01-01T00:00:00Z".to_string());
        response
    }

    fn sample_request() -> AccessRuleAddEditRequest {
        AccessRuleAddEditRequest {
            name: "My rule".to_string(),
            description: None,
            enabled: true,
            conditions: vec![AccessCondition::HumanApproval],
            single_active_lease: false,
            default_lease_duration_seconds: None,
            max_lease_duration_seconds: None,
            allows_extensions: false,
            max_extension_duration_seconds: None,
            collections: Vec::new(),
        }
    }

    #[tokio::test]
    async fn list_returns_views() {
        let organization_id = org_id();
        let rule = rule_id();
        let response = sample_response(rule.into(), organization_id.into());

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.access_rules_api
                .expect_get_all()
                .returning(move |_org_id| {
                    let mut list_response =
                        bitwarden_api_api::models::AccessRuleResponseModelListResponseModel::new();
                    list_response.data = Some(vec![response.clone()]);
                    Ok(list_response)
                })
                .once();
        });

        let result = client(api_client).list(organization_id).await.unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, rule);
    }

    #[tokio::test]
    async fn get_returns_view() {
        let organization_id = org_id();
        let rule = rule_id();
        let response = sample_response(rule.into(), organization_id.into());

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.access_rules_api
                .expect_get()
                .returning(move |_org_id, _id| Ok(response.clone()))
                .once();
        });

        let result = client(api_client).get(organization_id, rule).await.unwrap();

        assert_eq!(result.id, rule);
    }

    #[tokio::test]
    async fn get_surfaces_api_error() {
        let organization_id = org_id();
        let rule = rule_id();

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.access_rules_api
                .expect_get()
                .returning(move |_org_id, _id| {
                    Err(bitwarden_api_api::apis::Error::Response(
                        bitwarden_api_api::apis::ResponseContent {
                            status: reqwest::StatusCode::NOT_FOUND,
                            message: String::new(),
                        },
                    ))
                })
                .once();
        });

        let result = client(api_client).get(organization_id, rule).await;

        assert!(matches!(result, Err(AccessRuleError::Api(_))));
    }

    #[tokio::test]
    async fn create_rejects_invalid_request_without_calling_the_api() {
        let organization_id = org_id();
        let mut request = sample_request();
        request.name = String::new();

        let api_client = ApiClient::new_mocked(|mock| {
            mock.access_rules_api.expect_post().never();
        });

        let result = client(api_client).create(organization_id, request).await;

        assert!(matches!(result, Err(AccessRuleError::Validation(_))));
    }

    #[tokio::test]
    async fn create_returns_created_view() {
        let organization_id = org_id();
        let rule = rule_id();
        let response = sample_response(rule.into(), organization_id.into());

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.access_rules_api
                .expect_post()
                .returning(move |_org_id, _request| Ok(response.clone()))
                .once();
        });

        let result = client(api_client)
            .create(organization_id, sample_request())
            .await
            .unwrap();

        assert_eq!(result.id, rule);
    }

    #[tokio::test]
    async fn create_surfaces_api_error() {
        let organization_id = org_id();

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.access_rules_api
                .expect_post()
                .returning(move |_org_id, _request| {
                    Err(bitwarden_api_api::apis::Error::Response(
                        bitwarden_api_api::apis::ResponseContent {
                            status: reqwest::StatusCode::BAD_REQUEST,
                            message: "Invalid rule".to_string(),
                        },
                    ))
                })
                .once();
        });

        let result = client(api_client)
            .create(organization_id, sample_request())
            .await;

        assert!(matches!(result, Err(AccessRuleError::Api(_))));
    }

    #[tokio::test]
    async fn update_returns_updated_view() {
        let organization_id = org_id();
        let rule = rule_id();
        let response = sample_response(rule.into(), organization_id.into());

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.access_rules_api
                .expect_put()
                .returning(move |_org_id, _id, _request| Ok(response.clone()))
                .once();
        });

        let result = client(api_client)
            .update(organization_id, rule, sample_request())
            .await
            .unwrap();

        assert_eq!(result.id, rule);
    }

    #[tokio::test]
    async fn delete_succeeds() {
        let organization_id = org_id();
        let rule = rule_id();

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.access_rules_api
                .expect_delete()
                .returning(move |_org_id, _id| Ok(()))
                .once();
        });

        let result = client(api_client).delete(organization_id, rule).await;

        assert!(result.is_ok());
    }
}
