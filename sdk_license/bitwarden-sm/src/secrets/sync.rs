use bitwarden_api_api::models::SecretsSyncResponseModel;
use bitwarden_core::{Client, key_management::KeyIds, require};
use bitwarden_crypto::KeyStoreContext;
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{error::SecretsManagerError, secrets::SecretResponse};

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretsSyncRequest {
    /// Organization to sync secrets from
    pub organization_id: Uuid,
    /// Optional date time a sync last occurred
    pub last_synced_date: Option<DateTime<Utc>>,
}

pub(crate) async fn sync_secrets(
    client: &Client,
    input: &SecretsSyncRequest,
) -> Result<SecretsSyncResponse, SecretsManagerError> {
    let config = client.internal.get_api_configurations().await;
    let last_synced_date = input.last_synced_date.map(|date| date.to_rfc3339());

    let res = config
        .api_client
        .secrets_api()
        .get_secrets_sync(input.organization_id, last_synced_date)
        .await?;

    let key_store = client.internal.get_key_store();

    SecretsSyncResponse::process_response(res, &mut key_store.context())
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretsSyncResponse {
    pub has_changes: bool,
    pub secrets: Option<Vec<SecretResponse>>,
}

impl SecretsSyncResponse {
    pub(crate) fn process_response(
        response: SecretsSyncResponseModel,
        ctx: &mut KeyStoreContext<KeyIds>,
    ) -> Result<SecretsSyncResponse, SecretsManagerError> {
        let has_changes = require!(response.has_changes);

        if has_changes {
            let secrets = require!(response.secrets)
                .data
                .unwrap_or_default()
                .into_iter()
                .map(|r| SecretResponse::process_base_response(r, ctx))
                .collect::<Result<_, _>>()?;
            return Ok(SecretsSyncResponse {
                has_changes,
                secrets: Some(secrets),
            });
        }

        Ok(SecretsSyncResponse {
            has_changes: false,
            secrets: None,
        })
    }
}
