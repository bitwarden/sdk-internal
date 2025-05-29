use bitwarden_core::Client;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{error::SecretsManagerError, secrets::SecretResponse};

#[allow(missing_docs)]
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
