use bitwarden_api_api::models;
use bitwarden_core::client::Client;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::access_policies::{
    get_project::{GetProjectAccessPoliciesRequest, get_project_access_policies},
    types::{AccessPoliciesResponse, AccessPolicyEntry},
};

fn to_api_request(p: &AccessPolicyEntry) -> models::AccessPolicyRequest {
    models::AccessPolicyRequest {
        grantee_id: p.grantee_id,
        read: p.read,
        write: p.write,
        manage: p.manage,
    }
}

#[derive(Error, Debug)]
pub enum PutProjectAccessPoliciesError {
    #[error("Internal error: {0}")]
    InternalError(String),
}

/// Request to replace access policies on a project.
///
/// Each field controls a separate server-side replace operation:
/// - `None` → skip this category entirely (no server call, existing policies unchanged)
/// - `Some(vec![])` → replace with empty list (removes all policies in this category)
/// - `Some(vec![...])` → replace with the provided list
///
/// The people PUT (`/projects/{id}/access-policies/people`) is sent when **either**
/// `user_access_policies` or `group_access_policies` is `Some`. Within that PUT,
/// a `None` sub-field defaults to an empty list.
///
/// The SA PUT (`/projects/{id}/access-policies/service-accounts`) is sent only when
/// `service_account_access_policies` is `Some`.
#[allow(missing_docs)]
#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PutProjectAccessPoliciesRequest {
    pub project_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_access_policies: Option<Vec<AccessPolicyEntry>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_access_policies: Option<Vec<AccessPolicyEntry>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account_access_policies: Option<Vec<AccessPolicyEntry>>,
}

pub async fn put_project_access_policies(
    client: &Client,
    request: &PutProjectAccessPoliciesRequest,
) -> Result<AccessPoliciesResponse, PutProjectAccessPoliciesError> {
    let config = client.internal.get_api_configurations().await;

    let send_people =
        request.user_access_policies.is_some() || request.group_access_policies.is_some();
    let send_sa = request.service_account_access_policies.is_some();

    // PUT people policies (users + groups) — only if at least one is Some
    if send_people {
        let user_requests: Vec<_> = request
            .user_access_policies
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(to_api_request)
            .collect();

        let group_requests: Vec<_> = request
            .group_access_policies
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(to_api_request)
            .collect();

        let people_body = models::PeopleAccessPoliciesRequestModel {
            user_access_policy_requests: Some(user_requests),
            group_access_policy_requests: Some(group_requests),
        };

        config
            .api_client
            .access_policies_api()
            .put_project_people_access_policies(request.project_id, Some(people_body))
            .await
            .map_err(|e| PutProjectAccessPoliciesError::InternalError(format!("{e:?}")))?;
    }

    // Non-atomic: people policies may have updated while this call fails
    // PUT service account policies — only if Some
    if send_sa {
        let sa_requests: Vec<_> = request
            .service_account_access_policies
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(to_api_request)
            .collect();

        let sa_body = models::ProjectServiceAccountsAccessPoliciesRequestModel {
            service_account_access_policy_requests: Some(sa_requests),
        };

        config
            .api_client
            .access_policies_api()
            .put_project_service_accounts_access_policies(request.project_id, Some(sa_body))
            .await
            .map_err(|e| PutProjectAccessPoliciesError::InternalError(format!("{e:?}")))?;
    }

    // Re-fetch the current state to return consistent data
    get_project_access_policies(
        client,
        &GetProjectAccessPoliciesRequest {
            project_id: request.project_id,
        },
    )
    .await
    .map_err(|e| PutProjectAccessPoliciesError::InternalError(format!("{e:?}")))
}
