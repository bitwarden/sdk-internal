use bitwarden_api_api::models::ProjectResponseModelListResponseModel;
use bitwarden_core::{client::Client, key_management::KeyIds};
use bitwarden_crypto::KeyStoreContext;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{error::SecretsManagerError, projects::ProjectResponse};

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectsListRequest {
    /// Organization to retrieve all the projects from
    pub organization_id: Uuid,
}

pub(crate) async fn list_projects(
    client: &Client,
    input: &ProjectsListRequest,
) -> Result<ProjectsResponse, SecretsManagerError> {
    let config = client.internal.get_api_configurations().await;
    let res = bitwarden_api_api::apis::projects_api::organizations_organization_id_projects_get(
        &config.api,
        input.organization_id,
    )
    .await?;

    let key_store = client.internal.get_key_store();

    ProjectsResponse::process_response(res, &mut key_store.context())
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectsResponse {
    pub data: Vec<ProjectResponse>,
}

impl ProjectsResponse {
    pub(crate) fn process_response(
        response: ProjectResponseModelListResponseModel,
        ctx: &mut KeyStoreContext<KeyIds>,
    ) -> Result<Self, SecretsManagerError> {
        let data = response.data.unwrap_or_default();

        Ok(ProjectsResponse {
            data: data
                .into_iter()
                .map(|r| ProjectResponse::process_response(r, ctx))
                .collect::<Result<_, _>>()?,
        })
    }
}
