use bitwarden_api_api::models::GetSecretsRequestModel;
use bitwarden_core::Client;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{error::SecretsManagerError, secrets::SecretResponse};

use super::SecretsResponse;

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretGetRequest {
    /// ID of the secret to retrieve
    pub id: Uuid,
}

pub(crate) async fn get_secret(
    client: &Client,
    input: &SecretGetRequest,
) -> Result<SecretResponse, SecretsManagerError> {
    let config = client.internal.get_api_configurations().await;
    let res = bitwarden_api_api::apis::secrets_api::secrets_id_get(&config.api, input.id).await?;

    let key_store = client.internal.get_key_store();

    SecretResponse::process_response(res, &mut key_store.context())
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Request to sync secrets for a specific project
pub struct SecretsByProjectGetRequest {
    /// Project ID to sync secrets from
    pub project_id: Uuid,
}

// get_secrets_full(id: ProjectId);
// return: Vec<{ secrets_name: }>

// get_secrets_by_project_view(id: ProjectId)
// return: Vec<{ secret_id: SecretId, secret_name: &str, revision_date: DateTime<Utc> }>

// get_secret(id: SecretId)

// Will call on initial load to get all the data
pub(crate) async fn get_secrets_by_project(
    client: &Client,
    input: &SecretsByProjectGetRequest,
) -> Result<SecretsResponse, SecretsManagerError> {
    let config = client.internal.get_api_configurations().await;
    // let last_synced_date = input.last_synced_date.map(|date| date.to_rfc3339());

    let secrets_with_project_list =
        bitwarden_api_api::apis::secrets_api::projects_project_id_secrets_get(
            &config.api,
            input.project_id,
            // last_synced_date,
        )
        .await?;

    let secret_ids: Vec<Uuid> = secrets_with_project_list
        .secrets
        .unwrap_or_default()
        .into_iter()
        .map(|s| s.id.unwrap_or_default())
        .collect();

    let request = Some(GetSecretsRequestModel { ids: secret_ids });

    let res =
        bitwarden_api_api::apis::secrets_api::secrets_get_by_ids_post(&config.api, request).await?;

    let key_store = client.internal.get_key_store();

    SecretsResponse::process_response(res, &mut key_store.context())
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretSlimResponse {
    pub id: Uuid,
    pub revision_date: chrono::DateTime<chrono::Utc>,
}

pub(crate) async fn get_secrets_view_by_project(
    client: &Client,
    input: &SecretsByProjectGetRequest,
) -> Result<Vec<SecretSlimResponse>, SecretsManagerError> {
    let config = client.internal.get_api_configurations().await;

    let secrets_with_project_list =
        bitwarden_api_api::apis::secrets_api::projects_project_id_secrets_get(
            &config.api,
            input.project_id,
        )
        .await?;

    secrets_with_project_list
        .secrets
        .unwrap_or_default()
        .into_iter()
        .map(|s| {
            Ok(SecretSlimResponse {
                id: bitwarden_core::require!(s.id),
                revision_date: bitwarden_core::require!(s.revision_date).parse()?,
            })
        })
        .collect()
}
