use bitwarden_core::{client::Client, key_management::SymmetricKeyId};
use bitwarden_crypto::{Decryptable, EncString};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::access_policies::types::{
    AccessPolicyResponse, GrantedPoliciesResponse, GrantedProjectPolicyResponse,
};

#[derive(Error, Debug)]
pub enum GetGrantedPoliciesError {
    #[error("Internal error: {0}")]
    InternalError(String),
    #[error("Crypto error: {0}")]
    CryptoError(String),
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetGrantedPoliciesRequest {
    pub service_account_id: Uuid,
}

pub async fn get_granted_policies(
    client: &Client,
    request: &GetGrantedPoliciesRequest,
) -> Result<GrantedPoliciesResponse, GetGrantedPoliciesError> {
    let config = client.internal.get_api_configurations().await;

    let response = config
        .api_client
        .access_policies_api()
        .get_service_account_granted_policies(request.service_account_id)
        .await
        .map_err(|e| GetGrantedPoliciesError::InternalError(format!("{e:?}")))?;

    let org_id = client
        .internal
        .get_access_token_organization()
        .ok_or_else(|| {
            GetGrantedPoliciesError::CryptoError("Not authenticated as a service account".into())
        })?;
    let key_store = client.internal.get_key_store();
    let mut ctx = key_store.context();
    let org_key = SymmetricKeyId::Organization(org_id);

    let granted_project_policies = response
        .granted_project_policies
        .unwrap_or_default()
        .into_iter()
        .filter_map(|details| {
            let policy_model = details.access_policy?;
            let project_id = policy_model.granted_project_id?;
            let decrypted_name = policy_model
                .granted_project_name
                .and_then(|n| n.parse::<EncString>().ok()?.decrypt(&mut ctx, org_key).ok());
            // manage must not default to false — an absent field would silently downgrade a
            // policy that has manage:true in the database. Drop the policy instead so the
            // caller can detect the gap.
            Some(GrantedProjectPolicyResponse {
                project_id,
                project_name: decrypted_name,
                has_permission: details.has_permission.unwrap_or(false),
                policy: AccessPolicyResponse {
                    read: policy_model.read.unwrap_or(false),
                    write: policy_model.write.unwrap_or(false),
                    manage: policy_model.manage?,
                },
            })
        })
        .collect();

    Ok(GrantedPoliciesResponse {
        granted_project_policies,
    })
}
