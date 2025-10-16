use bitwarden_api_api::models::ProjectResponseModel;
use bitwarden_core::{
    OrganizationId,
    key_management::{KeyIds, SymmetricKeyId},
    require,
};
use bitwarden_crypto::{Decryptable, EncString, KeyStoreContext};
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::SecretsManagerError;

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectResponse {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub name: String,
    pub creation_date: DateTime<Utc>,
    pub revision_date: DateTime<Utc>,
}

impl ProjectResponse {
    pub(crate) fn process_response(
        response: ProjectResponseModel,
        ctx: &mut KeyStoreContext<KeyIds>,
    ) -> Result<Self, SecretsManagerError> {
        let organization_id = require!(response.organization_id);
        let key = SymmetricKeyId::Organization(OrganizationId::new(organization_id));

        let name = require!(response.name)
            .parse::<EncString>()?
            .decrypt(ctx, key)?;

        Ok(ProjectResponse {
            id: require!(response.id),
            organization_id,
            name,

            creation_date: require!(response.creation_date).parse()?,
            revision_date: require!(response.revision_date).parse()?,
        })
    }
}
