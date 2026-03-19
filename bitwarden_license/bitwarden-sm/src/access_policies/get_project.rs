use bitwarden_core::{client::Client, key_management::SymmetricKeyId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::access_policies::{conversions, types::AccessPoliciesResponse};

#[derive(Error, Debug)]
pub enum GetProjectAccessPoliciesError {
    #[error("Internal error: {0}")]
    InternalError(String),
    #[error("Crypto error: {0}")]
    CryptoError(String),
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetProjectAccessPoliciesRequest {
    pub project_id: Uuid,
}

pub async fn get_project_access_policies(
    client: &Client,
    request: &GetProjectAccessPoliciesRequest,
) -> Result<AccessPoliciesResponse, GetProjectAccessPoliciesError> {
    let config = client.internal.get_api_configurations().await;

    let people = config
        .api_client
        .access_policies_api()
        .get_project_people_access_policies(request.project_id)
        .await
        .map_err(|e| GetProjectAccessPoliciesError::InternalError(format!("{e:?}")))?;

    let sa = config
        .api_client
        .access_policies_api()
        .get_project_service_accounts_access_policies(request.project_id)
        .await
        .map_err(|e| GetProjectAccessPoliciesError::InternalError(format!("{e:?}")))?;

    let org_id = client
        .internal
        .get_access_token_organization()
        .ok_or_else(|| {
            GetProjectAccessPoliciesError::CryptoError(
                "Not authenticated as a service account".into(),
            )
        })?;
    let key_store = client.internal.get_key_store();
    let mut ctx = key_store.context();
    let org_key = SymmetricKeyId::Organization(org_id);

    let user_access_policies = people
        .user_access_policies
        .unwrap_or_default()
        .into_iter()
        .filter_map(conversions::user_from_api)
        .collect();

    let group_access_policies = people
        .group_access_policies
        .unwrap_or_default()
        .into_iter()
        .filter_map(conversions::group_from_api)
        .collect();

    let service_account_access_policies = sa
        .service_account_access_policies
        .unwrap_or_default()
        .into_iter()
        .filter_map(|p| conversions::service_account_from_api(p, &mut ctx, org_key))
        .collect();

    Ok(AccessPoliciesResponse {
        user_access_policies,
        group_access_policies,
        service_account_access_policies,
    })
}
