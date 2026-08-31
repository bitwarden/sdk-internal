use std::sync::Arc;

use bitwarden_collections::collection::CollectionId;
use bitwarden_core::{FromClient, OrganizationId, client::ApiConfigurations};
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
            .await?;

        response
            .data
            .unwrap_or_default()
            .into_iter()
            .map(AccessRuleView::try_from)
            .collect()
    }

    /// Retrieves a single access rule by ID. Fails with
    /// [`NotFound`](AccessRuleError::NotFound) when no such rule is visible to the caller.
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
            .map_err(AccessRuleError::from_by_id_api_error)?;

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
            .await?;

        AccessRuleView::try_from(response)
    }

    /// Validates and updates an existing access rule. Fails with
    /// [`NotFound`](AccessRuleError::NotFound) when the rule was deleted before the write landed.
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
            .map_err(AccessRuleError::from_by_id_api_error)?;

        AccessRuleView::try_from(response)
    }

    /// Where this rule fails to gate: the collections letting the ciphers it governs through
    /// without a lease.
    ///
    /// `GET /organizations/{orgId}/access-rules/{id}/bypassable-ciphers`. Gating is a union — a
    /// cipher is withheld only when EVERY collection reaching it gates — so a credential also
    /// sitting in an ordinary collection is not protected at all. These are the ordinary
    /// collections, de-duplicated across the ciphers they expose.
    ///
    /// An empty list is the normal answer and means the rule protects everything it governs; a rule
    /// that is switched off answers empty too, since it gates nothing. A NON-EMPTY list is itself
    /// the "something is wrong" signal, so there is no separate flag to keep in step.
    ///
    /// The affected ciphers are deliberately not reported: naming one means decrypting it from the
    /// caller's own vault, and an admin outside the collection — the one being warned — has none of
    /// them there. Collections are both reliably nameable and what remediation acts on.
    ///
    /// Errors surface as [`Api`](AccessRuleError::Api), NOT
    /// [`NotFound`](AccessRuleError::NotFound): this endpoint never 404s a missing rule (the server
    /// answers empty for absent, other-organization and disabled alike), so every 404 that can
    /// actually arrive is infrastructural — the PAM feature flag off, or a server predating the
    /// endpoint. Reporting those as "the rule does not exist" would be a lie about a rule the admin
    /// is looking at. See `from_by_id_api_error`.
    pub async fn bypassable_ciphers(
        &self,
        organization_id: OrganizationId,
        id: AccessRuleId,
    ) -> Result<Vec<CollectionId>, AccessRuleError> {
        let response = self
            .api_configurations
            .api_client
            .access_rules_api()
            .get_bypassable_ciphers(organization_id.into(), id.into())
            .await?;

        Ok(response
            .ungated_collection_ids
            // An omitted list is the same answer as an empty one: nothing is bypassable.
            .unwrap_or_default()
            .into_iter()
            .map(CollectionId::new)
            .collect())
    }

    /// Enables or disables a rule, leaving everything else about it untouched.
    ///
    /// Takes the rule as the caller already has it - every surface that offers this toggle is
    /// listing rules - so this costs one round trip rather than a read followed by a write. The
    /// full payload is rebuilt from that view by [`From<AccessRuleView>`], so no caller has to
    /// enumerate the editable fields and none can drop one; see that conversion for the bug this
    /// prevents.
    pub async fn set_enabled(
        &self,
        organization_id: OrganizationId,
        rule: AccessRuleView,
        enabled: bool,
    ) -> Result<AccessRuleView, AccessRuleError> {
        let id = rule.id;
        let request = AccessRuleAddEditRequest {
            enabled,
            ..rule.into()
        };

        self.update(organization_id, id, request).await
    }

    /// Deletes an access rule. Fails with [`NotFound`](AccessRuleError::NotFound) when the rule is
    /// already gone.
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
            .map_err(AccessRuleError::from_by_id_api_error)?;

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

    fn collection_id() -> uuid::Uuid {
        uuid!("44444444-4444-4444-4444-444444444444")
    }

    fn bypassable_response(
        ungated: Option<Vec<uuid::Uuid>>,
    ) -> bitwarden_api_api::models::RuleBypassableCiphersResponseModel {
        let mut response = bitwarden_api_api::models::RuleBypassableCiphersResponseModel::new();
        response.rule_id = Some(rule_id().into());
        response.ungated_collection_ids = ungated;
        response
    }

    #[tokio::test]
    async fn bypassable_ciphers_returns_the_reported_collections() {
        let organization_id = org_id();
        let rule = rule_id();
        let other = uuid!("55555555-5555-5555-5555-555555555555");

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.access_rules_api
                .expect_get_bypassable_ciphers()
                .returning(move |_org_id, _id| {
                    Ok(bypassable_response(Some(vec![collection_id(), other])))
                })
                .once();
        });

        let result = client(api_client)
            .bypassable_ciphers(organization_id, rule)
            .await
            .unwrap();

        // Identity and order, not just length: a conversion that dropped, defaulted or reordered
        // ids would otherwise pass.
        assert_eq!(
            result.into_iter().map(uuid::Uuid::from).collect::<Vec<_>>(),
            vec![collection_id(), other]
        );
    }

    #[tokio::test]
    async fn bypassable_ciphers_treats_an_omitted_list_as_empty() {
        let organization_id = org_id();
        let rule = rule_id();

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.access_rules_api
                .expect_get_bypassable_ciphers()
                .returning(move |_org_id, _id| Ok(bypassable_response(None)))
                .once();
        });

        let result = client(api_client)
            .bypassable_ciphers(organization_id, rule)
            .await
            .unwrap();

        assert!(result.is_empty());
    }

    fn api_error(status: reqwest::StatusCode) -> bitwarden_api_api::ApiError {
        bitwarden_api_api::ApiError::Response(bitwarden_api_api::ResponseContent {
            status,
            message: String::new(),
        })
    }

    /// This endpoint never 404s a missing rule — the server answers empty for absent, other-org and
    /// disabled alike. So a 404 is infrastructural (PAM flag off, or a server predating the
    /// endpoint) and must NOT be reported as a missing rule the admin is looking at.
    #[tokio::test]
    async fn bypassable_ciphers_leaves_not_found_as_api() {
        let organization_id = org_id();
        let rule = rule_id();

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.access_rules_api
                .expect_get_bypassable_ciphers()
                .returning(move |_org_id, _id| Err(api_error(reqwest::StatusCode::NOT_FOUND)))
                .once();
        });

        let error = client(api_client)
            .bypassable_ciphers(organization_id, rule)
            .await
            .unwrap_err();

        assert!(
            matches!(error, AccessRuleError::Api(_)),
            "expected Api, got {error:?}"
        );
    }

    #[tokio::test]
    async fn get_maps_not_found_to_not_found() {
        let organization_id = org_id();
        let rule = rule_id();

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.access_rules_api
                .expect_get()
                .returning(move |_org_id, _id| Err(api_error(reqwest::StatusCode::NOT_FOUND)))
                .once();
        });

        let result = client(api_client).get(organization_id, rule).await;

        assert!(matches!(result, Err(AccessRuleError::NotFound)));
    }

    #[tokio::test]
    async fn get_surfaces_other_api_errors_as_api() {
        let organization_id = org_id();
        let rule = rule_id();

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.access_rules_api
                .expect_get()
                .returning(move |_org_id, _id| {
                    Err(api_error(reqwest::StatusCode::INTERNAL_SERVER_ERROR))
                })
                .once();
        });

        let result = client(api_client).get(organization_id, rule).await;

        assert!(matches!(result, Err(AccessRuleError::Api(_))));
    }

    #[tokio::test]
    async fn update_maps_not_found_to_not_found() {
        let organization_id = org_id();
        let rule = rule_id();

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.access_rules_api
                .expect_put()
                .returning(move |_org_id, _id, _request| {
                    Err(api_error(reqwest::StatusCode::NOT_FOUND))
                })
                .once();
        });

        let result = client(api_client)
            .update(organization_id, rule, sample_request())
            .await;

        assert!(matches!(result, Err(AccessRuleError::NotFound)));
    }

    #[tokio::test]
    async fn delete_maps_not_found_to_not_found() {
        let organization_id = org_id();
        let rule = rule_id();

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.access_rules_api
                .expect_delete()
                .returning(move |_org_id, _id| Err(api_error(reqwest::StatusCode::NOT_FOUND)))
                .once();
        });

        let result = client(api_client).delete(organization_id, rule).await;

        assert!(matches!(result, Err(AccessRuleError::NotFound)));
    }

    /// The org-scoped calls deliberately do NOT map `404` onto a missing rule - see
    /// [`AccessRuleError::from_by_id_api_error`].
    #[tokio::test]
    async fn list_leaves_not_found_as_api() {
        let organization_id = org_id();

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.access_rules_api
                .expect_get_all()
                .returning(move |_org_id| Err(api_error(reqwest::StatusCode::NOT_FOUND)))
                .once();
        });

        let result = client(api_client).list(organization_id).await;

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
                    Err(bitwarden_api_api::ApiError::Response(
                        bitwarden_api_api::ResponseContent {
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

    /// The regression this exists to prevent: flipping `enabled` must not disturb any other field.
    /// The web client's hand-written equivalent once omitted the two extension fields, so toggling
    /// a rule silently wiped its extension settings.
    #[tokio::test]
    async fn set_enabled_flips_enabled_and_preserves_every_other_field() {
        let organization_id = org_id();
        let rule = rule_id();
        let mut response = sample_response(rule.into(), organization_id.into());
        response.enabled = Some(true);
        response.allows_extensions = Some(true);
        response.max_extension_duration_seconds = Some(3600);
        response.single_active_lease = Some(true);
        response.default_lease_duration_seconds = Some(1800);
        response.max_lease_duration_seconds = Some(7200);
        response.description = Some("Production database access".to_string());

        let view = AccessRuleView::try_from(response.clone()).unwrap();
        let returned = response.clone();

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.access_rules_api
                .expect_put()
                .withf(|_org_id, _id, request| {
                    request.enabled == Some(false)
                        && request.allows_extensions == Some(true)
                        && request.max_extension_duration_seconds == Some(3600)
                        && request.single_active_lease == Some(true)
                        && request.default_lease_duration_seconds == Some(1800)
                        && request.max_lease_duration_seconds == Some(7200)
                        && request.name == "My rule"
                        && request.description.as_deref() == Some("Production database access")
                })
                .returning(move |_org_id, _id, _request| Ok(returned.clone()))
                .once();
        });

        let result = client(api_client)
            .set_enabled(organization_id, view, false)
            .await
            .unwrap();

        assert_eq!(result.id, rule);
    }

    #[tokio::test]
    async fn set_enabled_targets_the_rule_it_was_given() {
        let organization_id = org_id();
        let rule = rule_id();
        let response = sample_response(rule.into(), organization_id.into());
        let view = AccessRuleView::try_from(response.clone()).unwrap();

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.access_rules_api
                .expect_put()
                .withf(move |_org_id, id, _request| *id == uuid::Uuid::from(rule_id()))
                .returning(move |_org_id, _id, _request| Ok(response.clone()))
                .once();
        });

        client(api_client)
            .set_enabled(organization_id, view, true)
            .await
            .unwrap();
    }
}
