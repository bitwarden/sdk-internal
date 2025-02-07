use bitwarden_api_api::models::GetSecretsRequestModel;
use bitwarden_core::client::Client;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{error::SecretsManagerError, secrets::SecretsResponse};

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretsGetRequest {
    /// IDs of the secrets to retrieve
    pub ids: Vec<Uuid>,
}

pub(crate) async fn get_secrets_by_ids(
    client: &Client,
    input: SecretsGetRequest,
) -> Result<SecretsResponse, SecretsManagerError> {
    let request = Some(GetSecretsRequestModel { ids: input.ids });

    let config = client.internal.get_api_configurations().await;

    let res =
        bitwarden_api_api::apis::secrets_api::secrets_get_by_ids_post(&config.api, request).await?;

    let key_store = client.internal.get_key_store();

    SecretsResponse::process_response(res, &mut key_store.context())
}
