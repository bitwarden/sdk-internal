use bitwarden_api_api::models::{
    DomainsResponseModel, ProfileOrganizationResponseModel, ProfileResponseModel, SyncResponseModel,
};
use bitwarden_collections::{collection::Collection, error::CollectionsParseError};
use bitwarden_core::{
    Client, MissingFieldError, OrganizationId, UserId,
    client::encryption_settings::EncryptionSettingsError, require,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Cipher, Folder, GlobalDomains, VaultParseError};

#[derive(Debug, Error)]
pub enum SyncError {
    #[error(transparent)]
    Api(#[from] bitwarden_core::ApiError),
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    #[error(transparent)]
    VaultParse(#[from] VaultParseError),
    #[error(transparent)]
    CollectionParse(#[from] CollectionsParseError),
    #[error(transparent)]
    EncryptionSettings(#[from] EncryptionSettingsError),
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SyncRequest {
    /// Exclude the subdomains from the response, defaults to false
    pub exclude_subdomains: Option<bool>,
}

pub(crate) async fn sync(client: &Client, input: &SyncRequest) -> Result<SyncResponse, SyncError> {
    let config = client.internal.get_api_configurations().await;
    let sync = config
        .api_client
        .sync_api()
        .get(input.exclude_subdomains)
        .await
        .map_err(|e| SyncError::Api(e.into()))?;

    let org_keys: Vec<_> = require!(sync.profile.as_ref())
        .organizations
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter_map(|o| o.id.zip(o.key.as_deref().and_then(|k| k.parse().ok())))
        .map(|(id, key)| (OrganizationId::new(id), key))
        .collect();

    client.internal.initialize_org_crypto(org_keys)?;

    SyncResponse::process_response(sync)
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileResponse {
    pub id: UserId,
    pub name: String,
    pub email: String,

    //key: String,
    //private_key: String,
    pub organizations: Vec<ProfileOrganizationResponse>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileOrganizationResponse {
    pub id: OrganizationId,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DomainResponse {
    pub equivalent_domains: Vec<Vec<String>>,
    pub global_equivalent_domains: Vec<GlobalDomains>,
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SyncResponse {
    /// Data about the user, including their encryption keys and the organizations they are a part
    /// of
    pub profile: ProfileResponse,
    pub folders: Vec<Folder>,
    pub collections: Vec<Collection>,
    /// List of ciphers accessible by the user
    pub ciphers: Vec<Cipher>,
    pub domains: Option<DomainResponse>,
    //pub policies: Vec<Policy>,
    //pub sends: Vec<Send>,
}

impl SyncResponse {
    pub(crate) fn process_response(response: SyncResponseModel) -> Result<SyncResponse, SyncError> {
        let profile = require!(response.profile);
        let ciphers = require!(response.ciphers);

        fn try_into_iter<In, InItem, Out, OutItem>(iter: In) -> Result<Out, InItem::Error>
        where
            In: IntoIterator<Item = InItem>,
            InItem: TryInto<OutItem>,
            Out: FromIterator<OutItem>,
        {
            iter.into_iter().map(|i| i.try_into()).collect()
        }

        Ok(SyncResponse {
            profile: ProfileResponse::process_response(*profile)?,
            folders: try_into_iter(require!(response.folders))?,
            collections: try_into_iter(require!(response.collections))?,
            ciphers: try_into_iter(ciphers)?,
            domains: response.domains.map(|d| (*d).try_into()).transpose()?,
            //policies: try_into_iter(require!(response.policies))?,
            //sends: try_into_iter(require!(response.sends))?,
        })
    }
}

impl ProfileOrganizationResponse {
    fn process_response(
        response: ProfileOrganizationResponseModel,
    ) -> Result<ProfileOrganizationResponse, MissingFieldError> {
        Ok(ProfileOrganizationResponse {
            id: OrganizationId::new(require!(response.id)),
        })
    }
}

impl ProfileResponse {
    fn process_response(
        response: ProfileResponseModel,
    ) -> Result<ProfileResponse, MissingFieldError> {
        Ok(ProfileResponse {
            id: UserId::new(require!(response.id)),
            name: require!(response.name),
            email: require!(response.email),
            //key: response.key,
            //private_key: response.private_key,
            organizations: response
                .organizations
                .unwrap_or_default()
                .into_iter()
                .map(ProfileOrganizationResponse::process_response)
                .collect::<Result<_, _>>()?,
        })
    }
}

impl TryFrom<DomainsResponseModel> for DomainResponse {
    type Error = SyncError;

    fn try_from(value: DomainsResponseModel) -> Result<Self, Self::Error> {
        Ok(Self {
            equivalent_domains: value.equivalent_domains.unwrap_or_default(),
            global_equivalent_domains: value
                .global_equivalent_domains
                .unwrap_or_default()
                .into_iter()
                .map(|s| s.try_into())
                .collect::<Result<Vec<GlobalDomains>, _>>()?,
        })
    }
}
