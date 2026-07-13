use bitwarden_api_api::models::{AccessRuleRequestModel, AccessRuleResponseModel};
use bitwarden_collections::collection::CollectionId;
use bitwarden_core::{OrganizationId, require};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;

use super::{conditions::AccessCondition, error::AccessRuleError};
use crate::AccessRuleId;

/// A decrypted view of an access rule, as returned by the server.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct AccessRuleView {
    /// The rule's unique identifier.
    pub id: AccessRuleId,
    /// The organization this rule belongs to.
    pub organization_id: OrganizationId,
    /// The rule's display name, shown wherever rules are listed and managed.
    pub name: String,
    /// Optional free-text describing the rule's intent.
    pub description: Option<String>,
    /// When false, the rule is inactive and does not gate access for the collections it governs.
    pub enabled: bool,
    /// The condition tree that decides how access is granted under this rule.
    pub conditions: Vec<AccessCondition>,
    /// When true, the rule enforces a per-cipher singleton (at most one active lease per cipher
    /// across all users).
    pub single_active_lease: bool,
    /// Default lease duration in seconds, used to pre-fill a request opened under this rule. None
    /// means the backend default applies.
    pub default_lease_duration_seconds: Option<i32>,
    /// Hard ceiling on the duration of any single lease granted under this rule, in seconds. None
    /// means no per-rule cap.
    pub max_lease_duration_seconds: Option<i32>,
    /// When true, a member holding an active lease under this rule may extend it once.
    pub allows_extensions: bool,
    /// The longest a single extension may run, in seconds. Set when `allows_extensions` is true.
    pub max_extension_duration_seconds: Option<i32>,
    /// The complete set of collections this rule governs.
    pub collections: Vec<CollectionId>,
    /// When the rule was created (UTC).
    pub creation_date: DateTime<Utc>,
    /// When the rule was last modified (UTC).
    pub revision_date: DateTime<Utc>,
}

/// Request to create or edit an access rule.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct AccessRuleAddEditRequest {
    /// The rule's display name, shown wherever rules are listed and managed. Must be non-empty
    /// (after trimming whitespace) and no more than 256 characters.
    pub name: String,
    /// Optional free-text describing the rule's intent.
    pub description: Option<String>,
    /// When false, the rule is inactive and does not gate access for the collections it governs.
    pub enabled: bool,
    /// The condition tree that decides how access is granted under this rule. Limited to at most
    /// 10 conditions.
    pub conditions: Vec<AccessCondition>,
    /// When true, the rule enforces a per-cipher singleton (at most one active lease per cipher
    /// across all users).
    pub single_active_lease: bool,
    /// Default lease duration in seconds, used to pre-fill a request opened under this rule. None
    /// means the backend default applies.
    pub default_lease_duration_seconds: Option<i32>,
    /// Hard ceiling on the duration of any single lease granted under this rule, in seconds. None
    /// means no per-rule cap.
    pub max_lease_duration_seconds: Option<i32>,
    /// When true, a member holding an active lease under this rule may extend it once. Requires
    /// `max_extension_duration_seconds` to be a positive value.
    pub allows_extensions: bool,
    /// The longest a single extension may run, in seconds. Required to be positive when
    /// `allows_extensions` is true.
    pub max_extension_duration_seconds: Option<i32>,
    /// The complete set of collections this rule governs. The rule's associations are replaced
    /// to match exactly this set; an empty list clears all associations.
    pub collections: Vec<CollectionId>,
}

impl TryFrom<AccessRuleResponseModel> for AccessRuleView {
    type Error = AccessRuleError;

    fn try_from(response: AccessRuleResponseModel) -> Result<Self, Self::Error> {
        let conditions = match response.conditions {
            None => Vec::new(),
            Some(value @ serde_json::Value::Array(_)) => serde_json::from_value(value)
                .map_err(|e| AccessRuleError::InvalidConditions(e.to_string()))?,
            Some(other) => {
                return Err(AccessRuleError::InvalidConditions(format!(
                    "expected `conditions` to be a JSON array, got: {other}"
                )));
            }
        };

        Ok(Self {
            id: AccessRuleId::new(require!(response.id)),
            organization_id: OrganizationId::new(require!(response.organization_id)),
            name: require!(response.name),
            description: response.description,
            // The server defaults an omitted `enabled` to an active rule.
            enabled: response.enabled.unwrap_or(true),
            conditions,
            single_active_lease: response.single_active_lease.unwrap_or(false),
            default_lease_duration_seconds: response.default_lease_duration_seconds,
            max_lease_duration_seconds: response.max_lease_duration_seconds,
            allows_extensions: response.allows_extensions.unwrap_or(false),
            max_extension_duration_seconds: response.max_extension_duration_seconds,
            collections: response
                .collections
                .unwrap_or_default()
                .into_iter()
                .map(CollectionId::new)
                .collect(),
            creation_date: require!(response.creation_date).parse()?,
            revision_date: require!(response.revision_date).parse()?,
        })
    }
}

impl TryFrom<AccessRuleAddEditRequest> for AccessRuleRequestModel {
    type Error = AccessRuleError;

    fn try_from(request: AccessRuleAddEditRequest) -> Result<Self, Self::Error> {
        // The server requires `conditions` to always be present; an empty vec serializes to
        // the empty array it expects.
        let conditions = serde_json::to_value(&request.conditions)
            .map_err(|e| AccessRuleError::InvalidConditions(e.to_string()))?;

        Ok(Self {
            name: request.name.trim().to_string(),
            description: request.description,
            enabled: Some(request.enabled),
            conditions: Some(conditions),
            single_active_lease: Some(request.single_active_lease),
            default_lease_duration_seconds: request.default_lease_duration_seconds,
            max_lease_duration_seconds: request.max_lease_duration_seconds,
            allows_extensions: Some(request.allows_extensions),
            max_extension_duration_seconds: request.max_extension_duration_seconds,
            collections: request
                .collections
                .into_iter()
                .map(uuid::Uuid::from)
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_collections::collection::CollectionId;
    use uuid::Uuid;

    use super::*;

    fn full_response() -> AccessRuleResponseModel {
        AccessRuleResponseModel {
            id: Some(Uuid::new_v4()),
            organization_id: Some(Uuid::new_v4()),
            name: Some("My rule".to_string()),
            description: Some("A description".to_string()),
            enabled: Some(false),
            conditions: Some(serde_json::json!([{ "kind": "human_approval" }])),
            single_active_lease: Some(true),
            default_lease_duration_seconds: Some(60),
            max_lease_duration_seconds: Some(120),
            allows_extensions: Some(true),
            max_extension_duration_seconds: Some(30),
            collections: Some(vec![Uuid::new_v4()]),
            creation_date: Some("2025-01-01T00:00:00Z".to_string()),
            revision_date: Some("2025-01-02T00:00:00Z".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn full_response_converts_to_view() {
        let response = full_response();
        let expected_id = response.id.unwrap();
        let expected_org_id = response.organization_id.unwrap();
        let expected_collection_id = response.collections.as_ref().unwrap()[0];

        let view = AccessRuleView::try_from(response).unwrap();

        assert_eq!(
            view,
            AccessRuleView {
                id: AccessRuleId::new(expected_id),
                organization_id: OrganizationId::new(expected_org_id),
                name: "My rule".to_string(),
                description: Some("A description".to_string()),
                enabled: false,
                conditions: vec![AccessCondition::HumanApproval],
                single_active_lease: true,
                default_lease_duration_seconds: Some(60),
                max_lease_duration_seconds: Some(120),
                allows_extensions: true,
                max_extension_duration_seconds: Some(30),
                collections: vec![CollectionId::new(expected_collection_id)],
                creation_date: "2025-01-01T00:00:00Z".parse().unwrap(),
                revision_date: "2025-01-02T00:00:00Z".parse().unwrap(),
            }
        );
    }

    #[test]
    fn missing_id_is_a_missing_field_error() {
        let mut response = full_response();
        response.id = None;

        let result = AccessRuleView::try_from(response);

        assert!(matches!(result, Err(AccessRuleError::MissingField(_))));
    }

    #[test]
    fn null_conditions_become_empty_vec() {
        let mut response = full_response();
        response.conditions = None;

        let view = AccessRuleView::try_from(response).unwrap();

        assert_eq!(view.conditions, Vec::new());
    }

    #[test]
    fn missing_enabled_defaults_to_true() {
        let mut response = full_response();
        response.enabled = None;

        let view = AccessRuleView::try_from(response).unwrap();

        assert!(view.enabled);
    }

    #[test]
    fn non_array_conditions_is_an_error() {
        let mut response = full_response();
        response.conditions = Some(serde_json::json!({ "not": "an array" }));

        let result = AccessRuleView::try_from(response);

        assert!(matches!(result, Err(AccessRuleError::InvalidConditions(_))));
    }

    #[test]
    fn request_always_sends_conditions_as_an_array() {
        let request = AccessRuleAddEditRequest {
            name: "My rule".to_string(),
            description: None,
            enabled: true,
            conditions: Vec::new(),
            single_active_lease: false,
            default_lease_duration_seconds: None,
            max_lease_duration_seconds: None,
            allows_extensions: false,
            max_extension_duration_seconds: None,
            collections: Vec::new(),
        };

        let model = AccessRuleRequestModel::try_from(request).unwrap();

        assert_eq!(model.conditions, Some(serde_json::json!([])));
    }

    #[test]
    fn request_trims_name_before_sending() {
        let request = AccessRuleAddEditRequest {
            name: "  My rule  ".to_string(),
            description: None,
            enabled: true,
            conditions: Vec::new(),
            single_active_lease: false,
            default_lease_duration_seconds: None,
            max_lease_duration_seconds: None,
            allows_extensions: false,
            max_extension_duration_seconds: None,
            collections: Vec::new(),
        };

        let model = AccessRuleRequestModel::try_from(request).unwrap();

        assert_eq!(model.name, "My rule");
    }
}
