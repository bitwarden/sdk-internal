use bitwarden_core::{
    OrganizationId,
    client::Client,
    key_management::{KeyIds, SymmetricKeyId},
};
use bitwarden_crypto::{Decryptable, EncString, KeyStoreContext};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::access_policies::types::{PotentialGrantee, PotentialGranteesResponse};

#[derive(Error, Debug)]
pub enum GetPotentialGranteesError {
    #[error("Internal error: {0}")]
    InternalError(String),
    #[error("Crypto error: {0}")]
    CryptoError(String),
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "camelCase")]
pub enum GranteeType {
    /// Human users and groups
    People,
    /// Projects
    Projects,
    /// Service accounts
    ServiceAccounts,
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetPotentialGranteesRequest {
    pub organization_id: Uuid,
    pub grantee_type: GranteeType,
}

pub async fn get_potential_grantees(
    client: &Client,
    request: &GetPotentialGranteesRequest,
) -> Result<PotentialGranteesResponse, GetPotentialGranteesError> {
    let config = client.internal.get_api_configurations().await;

    let models_data = match request.grantee_type {
        GranteeType::People => config
            .api_client
            .access_policies_api()
            .get_people_potential_grantees(request.organization_id)
            .await
            .map_err(|e| GetPotentialGranteesError::InternalError(format!("{e:?}")))?
            .data
            .unwrap_or_default(),
        GranteeType::Projects => config
            .api_client
            .access_policies_api()
            .get_project_potential_grantees(request.organization_id)
            .await
            .map_err(|e| GetPotentialGranteesError::InternalError(format!("{e:?}")))?
            .data
            .unwrap_or_default(),
        GranteeType::ServiceAccounts => config
            .api_client
            .access_policies_api()
            .get_service_accounts_potential_grantees(request.organization_id)
            .await
            .map_err(|e| GetPotentialGranteesError::InternalError(format!("{e:?}")))?
            .data
            .unwrap_or_default(),
    };

    let needs_decryption = matches!(
        request.grantee_type,
        GranteeType::Projects | GranteeType::ServiceAccounts
    );

    let data = if needs_decryption {
        let key_store = client.internal.get_key_store();
        let mut ctx = key_store.context();
        let org_key = SymmetricKeyId::Organization(OrganizationId::new(request.organization_id));

        models_data
            .into_iter()
            .filter(|g| g.id.is_some())
            .map(|g| {
                let decrypted_name = g
                    .name
                    .map(|n| decrypt_name(&n, &mut ctx, org_key))
                    .transpose()?;
                Ok(PotentialGrantee {
                    id: g.id.expect("filtered by is_some() above"),
                    name: decrypted_name,
                    r#type: g.r#type,
                    email: g.email,
                })
            })
            .collect::<Result<Vec<_>, GetPotentialGranteesError>>()?
    } else {
        models_data
            .into_iter()
            .filter_map(|g| {
                Some(PotentialGrantee {
                    id: g.id?,
                    name: g.name,
                    r#type: g.r#type,
                    email: g.email,
                })
            })
            .collect()
    };

    Ok(PotentialGranteesResponse { data })
}

fn decrypt_name(
    encrypted: &str,
    ctx: &mut KeyStoreContext<KeyIds>,
    key: SymmetricKeyId,
) -> Result<String, GetPotentialGranteesError> {
    encrypted
        .parse::<EncString>()
        .map_err(|e| GetPotentialGranteesError::CryptoError(format!("{e:?}")))?
        .decrypt(ctx, key)
        .map_err(|e| GetPotentialGranteesError::CryptoError(format!("{e:?}")))
}
