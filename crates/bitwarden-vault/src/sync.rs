use bitwarden_api_api::models::{
    DomainsResponseModel, ProfileOrganizationResponseModel, ProfileResponseModel, SyncResponseModel,
};
use bitwarden_collections::{collection::Collection, error::CollectionsParseError};
use bitwarden_core::{
    client::encryption_settings::EncryptionSettingsError,
    key_management::{MasterPasswordError, MasterPasswordUnlockData},
    require, Client, MissingFieldError, NotAuthenticatedError, OrganizationId, UserId,
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
    #[error(transparent)]
    MasterPassword(#[from] MasterPasswordError),
    #[error(transparent)]
    NotAuthenticatedError(#[from] NotAuthenticatedError),
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
    let sync = bitwarden_api_api::apis::sync_api::sync_get(&config.api, input.exclude_subdomains)
        .await
        .map_err(|e| SyncError::Api(e.into()))?;

    if let Some(master_password_unlock_response) = sync
        .user_decryption
        .as_deref()
        .and_then(|d| d.master_password_unlock.as_deref())
    {
        let master_password_unlock =
            MasterPasswordUnlockData::try_from(master_password_unlock_response.clone())?;

        client.internal.update_kdf(master_password_unlock.kdf)?;
    }

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

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use bitwarden_api_api::models::{
        KdfType, MasterPasswordUnlockKdfResponseModel, MasterPasswordUnlockResponseModel,
        UserDecryptionResponseModel,
    };
    use bitwarden_core::{
        client::test_accounts::{test_bitwarden_com_account, TestAccount},
        key_management::{crypto::InitUserCryptoMethod, SymmetricKeyId},
        ClientSettings, DeviceType,
    };
    use bitwarden_crypto::{Kdf, UnsignedSharedKey};
    use bitwarden_test::start_api_mock;
    use wiremock::{matchers, Mock, MockServer, Request, ResponseTemplate};

    use super::*;

    const USER_NAME: &str = "Test User";
    const USER_EMAIL: &str = "test@example.com";

    fn create_profile_response(user_id: Uuid) -> ProfileResponseModel {
        ProfileResponseModel {
            id: Some(user_id),
            name: Some(USER_NAME.to_string()),
            email: Some(USER_EMAIL.to_string()),
            organizations: Some(vec![]),
            ..ProfileResponseModel::new()
        }
    }

    fn create_sync_response(user_id: Uuid) -> SyncResponseModel {
        SyncResponseModel {
            profile: Some(Box::new(create_profile_response(user_id))),
            folders: Some(vec![]),
            collections: Some(vec![]),
            ciphers: Some(vec![]),
            ..SyncResponseModel::new()
        }
    }

    fn create_test_account() -> (TestAccount, Uuid, Uuid, UnsignedSharedKey) {
        let test_account = test_bitwarden_com_account();
        let user_id = test_account.user.user_id.unwrap();
        let organization_keys = test_account
            .org
            .as_ref()
            .map(|org| org.organization_keys.clone())
            .unwrap();
        let organization_id = *organization_keys.keys().next().unwrap();
        let organization_key = organization_keys.get(&organization_id).unwrap().clone();

        (test_account, user_id, organization_id, organization_key)
    }

    async fn setup_sync_client(
        response: SyncResponseModel,
        test_account: TestAccount,
    ) -> (MockServer, Client) {
        let (server, api_config) = start_api_mock(vec![Mock::given(matchers::path("/sync"))
            .respond_with(move |_: &Request| {
                ResponseTemplate::new(200).set_body_json(response.to_owned())
            })
            .expect(1)])
        .await;

        let client = Client::new(Some(ClientSettings {
            identity_url: api_config.base_path.clone(),
            api_url: api_config.base_path,
            user_agent: api_config.user_agent.unwrap(),
            device_type: DeviceType::SDK,
        }));

        client
            .crypto()
            .initialize_user_crypto(test_account.user)
            .await
            .unwrap();

        (server, client)
    }

    #[tokio::test]
    async fn test_sync_user_empty_vault_no_organizations() {
        let (test_account, user_id, organization_id, ..) = create_test_account();
        let (_server, client) =
            setup_sync_client(create_sync_response(user_id), test_account).await;

        let sync_request = SyncRequest {
            exclude_subdomains: Some(false),
        };

        let sync_response = sync(&client, &sync_request).await;
        assert!(sync_response.is_ok());

        let sync_response = sync_response.unwrap();
        assert_eq!(sync_response.profile.id, user_id);
        assert_eq!(sync_response.profile.name, USER_NAME);
        assert_eq!(sync_response.profile.email, USER_EMAIL);
        assert!(sync_response.profile.organizations.is_empty());
        assert!(sync_response.ciphers.is_empty());
        assert!(sync_response.folders.is_empty());
        assert!(sync_response.collections.is_empty());
        assert!(sync_response.domains.is_none());
        assert!(!client
            .internal
            .get_key_store()
            .context()
            .has_symmetric_key(SymmetricKeyId::Organization(organization_id)));
    }

    #[tokio::test]
    async fn test_sync_user_with_organization() {
        let (test_account, user_id, organization_id, organization_key) = create_test_account();

        let response = SyncResponseModel {
            profile: Some(Box::new(ProfileResponseModel {
                organizations: Some(vec![ProfileOrganizationResponseModel {
                    id: Some(organization_id),
                    key: Some(organization_key.to_string()),
                    ..ProfileOrganizationResponseModel::new()
                }]),
                ..create_profile_response(user_id)
            })),
            ..create_sync_response(user_id)
        };

        let (_server, client) = setup_sync_client(response, test_account).await;

        let sync_request = SyncRequest {
            exclude_subdomains: Some(false),
        };

        let sync_response = sync(&client, &sync_request).await;
        assert!(sync_response.is_ok());

        let sync_response = sync_response.unwrap();
        assert_eq!(sync_response.profile.id, user_id);
        assert_eq!(sync_response.profile.name, USER_NAME);
        assert_eq!(sync_response.profile.email, USER_EMAIL);
        assert_eq!(sync_response.profile.organizations.len(), 1);
        let organization = sync_response.profile.organizations.first().unwrap();
        assert_eq!(organization.id, organization_id);
        assert!(sync_response.ciphers.is_empty());
        assert!(sync_response.folders.is_empty());
        assert!(sync_response.collections.is_empty());
        assert!(sync_response.domains.is_none());
        assert!(client
            .internal
            .get_key_store()
            .context()
            .has_symmetric_key(SymmetricKeyId::Organization(organization_id)));
    }

    #[tokio::test]
    async fn test_sync_user_with_decryption_options_master_password_unlock() {
        let (mut test_account, user_id, ..) = create_test_account();

        test_account.user.kdf_params = Kdf::PBKDF2 {
            iterations: NonZeroU32::new(600_000).unwrap(),
        };

        let InitUserCryptoMethod::Password { user_key, .. } = &test_account.user.method else {
            panic!("incorrect init user crypto method");
        };

        let response = SyncResponseModel {
            user_decryption: Some(Box::new(UserDecryptionResponseModel {
                master_password_unlock: Some(Box::new(MasterPasswordUnlockResponseModel {
                    kdf: Box::new(MasterPasswordUnlockKdfResponseModel {
                        kdf_type: KdfType::Argon2id,
                        iterations: 4,
                        memory: Some(65),
                        parallelism: Some(5),
                    }),
                    salt: Some(USER_EMAIL.to_string()),
                    master_key_encrypted_user_key: Some(user_key.to_string()),
                })),
            })),
            ..create_sync_response(user_id)
        };

        let (_server, client) = setup_sync_client(response, test_account).await;

        let sync_request = SyncRequest {
            exclude_subdomains: Some(false),
        };

        let sync_response = sync(&client, &sync_request).await;
        assert!(sync_response.is_ok());

        assert_eq!(
            client.internal.get_kdf().unwrap(),
            Kdf::Argon2id {
                iterations: NonZeroU32::new(4).unwrap(),
                memory: NonZeroU32::new(65).unwrap(),
                parallelism: NonZeroU32::new(5).unwrap(),
            }
        );
    }
}
