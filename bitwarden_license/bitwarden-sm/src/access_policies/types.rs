use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Core access permissions for a single policy entry.
/// `manage` is `bool` (never `Option<bool>`) to prevent silent downgrade on round-trips.
#[allow(missing_docs)]
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AccessPolicyResponse {
    pub read: bool,
    pub write: bool,
    /// MUST be bool, not Option<bool> — prevents silent downgrade
    pub manage: bool,
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UserAccessPolicyResponse {
    pub organization_user_id: Uuid,
    pub organization_user_name: Option<String>,
    pub current_user: bool,
    #[serde(flatten)]
    pub policy: AccessPolicyResponse,
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct GroupAccessPolicyResponse {
    pub group_id: Uuid,
    pub group_name: Option<String>,
    pub current_user_in_group: bool,
    #[serde(flatten)]
    pub policy: AccessPolicyResponse,
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccountAccessPolicyResponse {
    pub service_account_id: Uuid,
    pub service_account_name: Option<String>,
    #[serde(flatten)]
    pub policy: AccessPolicyResponse,
}

/// Combined response for project or secret access policies.
#[allow(missing_docs)]
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AccessPoliciesResponse {
    pub user_access_policies: Vec<UserAccessPolicyResponse>,
    pub group_access_policies: Vec<GroupAccessPolicyResponse>,
    pub service_account_access_policies: Vec<ServiceAccountAccessPolicyResponse>,
}

/// Request entry for a single access policy on a project, secret, or service account.
/// `manage` is `bool` (never `Option<bool>`) to prevent silent downgrade on round-trips.
#[allow(missing_docs)]
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessPolicyEntry {
    pub grantee_id: Uuid,
    pub read: bool,
    pub write: bool,
    /// MUST be bool, not Option<bool> — prevents silent downgrade
    pub manage: bool,
}

/// Response for a single granted project policy (used on service account granted policies).
#[allow(missing_docs)]
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct GrantedProjectPolicyResponse {
    pub project_id: Uuid,
    pub project_name: Option<String>,
    pub has_permission: bool,
    #[serde(flatten)]
    pub policy: AccessPolicyResponse,
}

/// Response for service account granted policies.
#[allow(missing_docs)]
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct GrantedPoliciesResponse {
    pub granted_project_policies: Vec<GrantedProjectPolicyResponse>,
}

/// A potential grantee (user, group, project, or service account).
#[allow(missing_docs)]
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PotentialGrantee {
    pub id: Uuid,
    pub name: Option<String>,
    pub r#type: Option<String>,
    pub email: Option<String>,
}

/// Response for potential grantees.
#[allow(missing_docs)]
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PotentialGranteesResponse {
    pub data: Vec<PotentialGrantee>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manage_false_is_present_in_serialized_json() {
        let entry = AccessPolicyEntry {
            grantee_id: uuid::Uuid::new_v4(),
            read: true,
            write: true,
            manage: false,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed["manage"],
            serde_json::Value::Bool(false),
            "manage:false must be present in serialized JSON — omission causes server to silently bind false"
        );
    }

    #[test]
    fn manage_true_is_present_in_serialized_json() {
        let entry = AccessPolicyEntry {
            grantee_id: uuid::Uuid::new_v4(),
            read: true,
            write: true,
            manage: true,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["manage"], serde_json::Value::Bool(true),);
    }
}
