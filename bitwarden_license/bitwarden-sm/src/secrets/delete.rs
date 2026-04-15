use bitwarden_api_api::models::{
    BulkDeleteResponseModel, BulkDeleteResponseModelListResponseModel,
};
use bitwarden_core::{client::Client, require};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::SecretsManagerError;

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretsDeleteRequest {
    /// IDs of the secrets to delete
    pub ids: Vec<Uuid>,
}

pub(crate) async fn delete_secrets(
    client: &Client,
    input: SecretsDeleteRequest,
) -> Result<SecretsDeleteResponse, SecretsManagerError> {
    let config = client.internal.get_api_configurations();
    let res = config
        .api_client
        .secrets_api()
        .bulk_delete(Some(input.ids))
        .await?;

    SecretsDeleteResponse::process_response(res)
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretsDeleteResponse {
    pub data: Vec<SecretDeleteResponse>,
}

impl SecretsDeleteResponse {
    pub(crate) fn process_response(
        response: BulkDeleteResponseModelListResponseModel,
    ) -> Result<SecretsDeleteResponse, SecretsManagerError> {
        Ok(SecretsDeleteResponse {
            data: response
                .data
                .unwrap_or_default()
                .into_iter()
                .map(SecretDeleteResponse::process_response)
                .collect::<Result<_, _>>()?,
        })
    }
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretDeleteResponse {
    pub id: Uuid,
    pub error: Option<String>,
}

impl SecretDeleteResponse {
    pub(crate) fn process_response(
        response: BulkDeleteResponseModel,
    ) -> Result<SecretDeleteResponse, SecretsManagerError> {
        Ok(SecretDeleteResponse {
            id: require!(response.id),
            error: response.error,
        })
    }
}
