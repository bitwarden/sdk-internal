use bitwarden_core::client::Client;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{error::SecretsManagerError, projects::ProjectResponse};

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectGetRequest {
    /// ID of the project to retrieve
    pub id: Uuid,
}

pub(crate) async fn get_project(
    client: &Client,
    input: &ProjectGetRequest,
) -> Result<ProjectResponse, SecretsManagerError> {
    let config = client.internal.get_api_configurations().await;

    let res = bitwarden_api_api::apis::projects_api::projects_id_get(&config.api, input.id).await?;

    let key_store = client.internal.get_key_store();

    ProjectResponse::process_response(res, &mut key_store.context())
}
