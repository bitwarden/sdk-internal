use bitwarden_api_api::models;
use bitwarden_core::client::Client;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::access_policies::{
    get_granted::{GetGrantedPoliciesRequest, get_granted_policies},
    types::GrantedPoliciesResponse,
};

#[derive(Error, Debug)]
pub enum PutGrantedPoliciesError {
    #[error("Internal error: {0}")]
    InternalError(String),
}

/// A single granted project policy entry.
/// `manage` is `bool` (not `Option<bool>`) to prevent silent downgrade on round-trips.
#[allow(missing_docs)]
#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantedProjectEntry {
    pub project_id: Uuid,
    pub read: bool,
    pub write: bool,
    /// MUST be bool, not Option<bool> — prevents silent downgrade
    pub manage: bool,
}

/// Full-replace PUT request for service account granted policies (PUT semantics).
#[allow(missing_docs)]
#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PutGrantedPoliciesRequest {
    pub service_account_id: Uuid,
    pub projects: Vec<GrantedProjectEntry>,
}

pub async fn put_granted_policies(
    client: &Client,
    request: &PutGrantedPoliciesRequest,
) -> Result<GrantedPoliciesResponse, PutGrantedPoliciesError> {
    let config = client.internal.get_api_configurations().await;

    let policy_requests: Vec<_> = request
        .projects
        .iter()
        .map(|p| models::GrantedAccessPolicyRequest {
            granted_id: p.project_id,
            read: p.read,
            write: p.write,
            manage: p.manage,
        })
        .collect();

    let body = models::ServiceAccountGrantedPoliciesRequestModel {
        project_granted_policy_requests: Some(policy_requests),
    };

    config
        .api_client
        .access_policies_api()
        .put_service_account_granted_policies(request.service_account_id, Some(body))
        .await
        .map_err(|e| PutGrantedPoliciesError::InternalError(format!("{e:?}")))?;

    // Re-fetch to return the updated state
    get_granted_policies(
        client,
        &GetGrantedPoliciesRequest {
            service_account_id: request.service_account_id,
        },
    )
    .await
    .map_err(|e| PutGrantedPoliciesError::InternalError(format!("{e:?}")))
}
