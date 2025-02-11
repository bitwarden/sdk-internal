use bitwarden_api_api::models::{
    SecretWithProjectsListResponseModel, SecretsWithProjectsInnerSecret,
};
use bitwarden_core::{
    client::Client,
    key_management::{KeyIds, SymmetricKeyId},
    require,
};
use bitwarden_crypto::{Decryptable, EncString, KeyStoreContext};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::SecretsManagerError;

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretIdentifiersRequest {
    /// Organization to retrieve all the secrets from
    pub organization_id: Uuid,
}

pub(crate) async fn list_secrets(
    client: &Client,
    input: &SecretIdentifiersRequest,
) -> Result<SecretIdentifiersResponse, SecretsManagerError> {
    let config = client.internal.get_api_configurations().await;
    let res = bitwarden_api_api::apis::secrets_api::organizations_organization_id_secrets_get(
        &config.api,
        input.organization_id,
    )
    .await?;

    let key_store = client.internal.get_key_store();

    SecretIdentifiersResponse::process_response(res, &mut key_store.context())
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretIdentifiersByProjectRequest {
    /// Project to retrieve all the secrets from
    pub project_id: Uuid,
}

pub(crate) async fn list_secrets_by_project(
    client: &Client,
    input: &SecretIdentifiersByProjectRequest,
) -> Result<SecretIdentifiersResponse, SecretsManagerError> {
    let config = client.internal.get_api_configurations().await;
    let res = bitwarden_api_api::apis::secrets_api::projects_project_id_secrets_get(
        &config.api,
        input.project_id,
    )
    .await?;

    let key_store = client.internal.get_key_store();

    SecretIdentifiersResponse::process_response(res, &mut key_store.context())
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretIdentifiersResponse {
    pub data: Vec<SecretIdentifierResponse>,
}

impl SecretIdentifiersResponse {
    pub(crate) fn process_response(
        response: SecretWithProjectsListResponseModel,
        ctx: &mut KeyStoreContext<KeyIds>,
    ) -> Result<SecretIdentifiersResponse, SecretsManagerError> {
        Ok(SecretIdentifiersResponse {
            data: response
                .secrets
                .unwrap_or_default()
                .into_iter()
                .map(|r| SecretIdentifierResponse::process_response(r, ctx))
                .collect::<Result<_, _>>()?,
        })
    }
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretIdentifierResponse {
    pub id: Uuid,
    pub organization_id: Uuid,

    pub key: String,
}

impl SecretIdentifierResponse {
    pub(crate) fn process_response(
        response: SecretsWithProjectsInnerSecret,
        ctx: &mut KeyStoreContext<KeyIds>,
    ) -> Result<SecretIdentifierResponse, SecretsManagerError> {
        let organization_id = require!(response.organization_id);
        let enc_key = SymmetricKeyId::Organization(organization_id);

        let key = require!(response.key)
            .parse::<EncString>()?
            .decrypt(ctx, enc_key)?;

        Ok(SecretIdentifierResponse {
            id: require!(response.id),
            organization_id,
            key,
        })
    }
}
