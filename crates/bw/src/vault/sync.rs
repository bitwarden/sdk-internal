use bitwarden_api_api::models::{
    DomainsResponseModel, ProfileOrganizationResponseModel, ProfileResponseModel, SyncResponseModel,
};
use bitwarden_collections::{collection::Collection, error::CollectionsParseError};
use bitwarden_core::{
    Client, MissingFieldError, NotAuthenticatedError, OrganizationId, UserId,
    client::encryption_settings::EncryptionSettingsError,
    key_management::{MasterPasswordError, UserDecryptionData},
    require,
};
use bitwarden_vault::{Cipher, Folder, GlobalDomains, VaultParseError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

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
    NotAuthenticated(#[from] NotAuthenticatedError),
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

    let master_password_unlock = sync
        .user_decryption
        .as_deref()
        .map(UserDecryptionData::try_from)
        .transpose()?
        .and_then(|user_decryption| user_decryption.master_password_unlock);
    if let Some(master_password_unlock) = master_password_unlock {
        client
            .internal
            .set_user_master_password_unlock(master_password_unlock)?;
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
        ClientSettings, DeviceType,
        key_management::{
            MasterPasswordUnlockData, SymmetricKeyId, UserKeyState,
            account_cryptographic_state::WrappedAccountCryptographicState,
            crypto::{InitOrgCryptoRequest, InitUserCryptoMethod, InitUserCryptoRequest},
        },
    };
    use bitwarden_crypto::{EncString, Kdf, UnsignedSharedKey};
    use bitwarden_test::{MemoryRepository, start_api_mock};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate, matchers};

    use super::*;

    const TEST_USER_NAME: &str = "Test User";
    const TEST_USER_EMAIL: &str = "test@bitwarden.com";
    const TEST_USER_PASSWORD: &str = "asdfasdfasdf";
    const TEST_USER_ID: &str = "060000fb-0922-4dd3-b170-6e15cb5df8c8";
    const TEST_ACCOUNT_USER_KEY: &str = "2.Q/2PhzcC7GdeiMHhWguYAQ==|GpqzVdr0go0ug5cZh1n+uixeBC3oC90CIe0hd/HWA/pTRDZ8ane4fmsEIcuc8eMKUt55Y2q/fbNzsYu41YTZzzsJUSeqVjT8/iTQtgnNdpo=|dwI+uyvZ1h/iZ03VQ+/wrGEFYVewBUUl/syYgjsNMbE=";
    const TEST_ACCOUNT_PRIVATE_KEY: &str = "2.yN7l00BOlUE0Sb0M//Q53w==|EwKG/BduQRQ33Izqc/ogoBROIoI5dmgrxSo82sgzgAMIBt3A2FZ9vPRMY+GWT85JiqytDitGR3TqwnFUBhKUpRRAq4x7rA6A1arHrFp5Tp1p21O3SfjtvB3quiOKbqWk6ZaU1Np9HwqwAecddFcB0YyBEiRX3VwF2pgpAdiPbSMuvo2qIgyob0CUoC/h4Bz1be7Qa7B0Xw9/fMKkB1LpOm925lzqosyMQM62YpMGkjMsbZz0uPopu32fxzDWSPr+kekNNyLt9InGhTpxLmq1go/pXR2uw5dfpXc5yuta7DB0EGBwnQ8Vl5HPdDooqOTD9I1jE0mRyuBpWTTI3FRnu3JUh3rIyGBJhUmHqGZvw2CKdqHCIrQeQkkEYqOeJRJVdBjhv5KGJifqT3BFRwX/YFJIChAQpebNQKXe/0kPivWokHWwXlDB7S7mBZzhaAPidZvnuIhalE2qmTypDwHy22FyqV58T8MGGMchcASDi/QXI6kcdpJzPXSeU9o+NC68QDlOIrMVxKFeE7w7PvVmAaxEo0YwmuAzzKy9QpdlK0aab/xEi8V4iXj4hGepqAvHkXIQd+r3FNeiLfllkb61p6WTjr5urcmDQMR94/wYoilpG5OlybHdbhsYHvIzYoLrC7fzl630gcO6t4nM24vdB6Ymg9BVpEgKRAxSbE62Tqacxqnz9AcmgItb48NiR/He3n3ydGjPYuKk/ihZMgEwAEZvSlNxYONSbYrIGDtOY+8Nbt6KiH3l06wjZW8tcmFeVlWv+tWotnTY9IqlAfvNVTjtsobqtQnvsiDjdEVtNy/s2ci5TH+NdZluca2OVEr91Wayxh70kpM6ib4UGbfdmGgCo74gtKvKSJU0rTHakQ5L9JlaSDD5FamBRyI0qfL43Ad9qOUZ8DaffDCyuaVyuqk7cz9HwmEmvWU3VQ+5t06n/5kRDXttcw8w+3qClEEdGo1KeENcnXCB32dQe3tDTFpuAIMLqwXs6FhpawfZ5kPYvLPczGWaqftIs/RXJ/EltGc0ugw2dmTLpoQhCqrcKEBDoYVk0LDZKsnzitOGdi9mOWse7Se8798ib1UsHFUjGzISEt6upestxOeupSTOh0v4+AjXbDzRUyogHww3V+Bqg71bkcMxtB+WM+pn1XNbVTyl9NR040nhP7KEf6e9ruXAtmrBC2ah5cFEpLIot77VFZ9ilLuitSz+7T8n1yAh1IEG6xxXxninAZIzi2qGbH69O5RSpOJuJTv17zTLJQIIc781JwQ2TTwTGnx5wZLbffhCasowJKd2EVcyMJyhz6ru0PvXWJ4hUdkARJs3Xu8dus9a86N8Xk6aAPzBDqzYb1vyFIfBxP0oO8xFHgd30Cgmz8UrSE3qeWRrF8ftrI6xQnFjHBGWD/JWSvd6YMcQED0aVuQkuNW9ST/DzQThPzRfPUoiL10yAmV7Ytu4fR3x2sF0Yfi87YhHFuCMpV/DsqxmUizyiJuD938eRcH8hzR/VO53Qo3UIsqOLcyXtTv6THjSlTopQ+JOLOnHm1w8dzYbLN44OG44rRsbihMUQp+wUZ6bsI8rrOnm9WErzkbQFbrfAINdoCiNa6cimYIjvvnMTaFWNymqY1vZxGztQiMiHiHYwTfwHTXrb9j0uPM=|09J28iXv9oWzYtzK2LBT6Yht4IT4MijEkk0fwFdrVQ4=";
    const TEST_ACCOUNT_ORGANIZATION_ID: &str = "1bc9ac1e-f5aa-45f2-94bf-b181009709b8";
    const TEST_ACCOUNT_ORGANIZATION_KEY: &str = "4.rY01mZFXHOsBAg5Fq4gyXuklWfm6mQASm42DJpx05a+e2mmp+P5W6r54WU2hlREX0uoTxyP91bKKwickSPdCQQ58J45LXHdr9t2uzOYyjVzpzebFcdMw1eElR9W2DW8wEk9+mvtWvKwu7yTebzND+46y1nRMoFydi5zPVLSlJEf81qZZ4Uh1UUMLwXz+NRWfixnGXgq2wRq1bH0n3mqDhayiG4LJKgGdDjWXC8W8MMXDYx24SIJrJu9KiNEMprJE+XVF9nQVNijNAjlWBqkDpsfaWTUfeVLRLctfAqW1blsmIv4RQ91PupYJZDNc8nO9ZTF3TEVM+2KHoxzDJrLs2Q==";

    fn create_profile_response(user_id: UserId) -> ProfileResponseModel {
        ProfileResponseModel {
            id: Some(user_id.into()),
            name: Some(TEST_USER_NAME.to_string()),
            email: Some(TEST_USER_EMAIL.to_string()),
            organizations: Some(vec![]),
            ..ProfileResponseModel::new()
        }
    }

    fn create_sync_response(user_id: UserId) -> SyncResponseModel {
        SyncResponseModel {
            profile: Some(Box::new(create_profile_response(user_id))),
            folders: Some(vec![]),
            collections: Some(vec![]),
            ciphers: Some(vec![]),
            ..SyncResponseModel::new()
        }
    }

    async fn setup_sync_client(
        response: SyncResponseModel,
        user_crypto_request: InitUserCryptoRequest,
        org_crypto_request: Option<InitOrgCryptoRequest>,
    ) -> (MockServer, Client) {
        let (server, api_config) = start_api_mock(vec![
            Mock::given(matchers::path("/sync"))
                .respond_with(move |_: &Request| {
                    ResponseTemplate::new(200).set_body_json(response.to_owned())
                })
                .expect(1),
        ])
        .await;

        let client = Client::new(Some(ClientSettings {
            identity_url: api_config.base_path.clone(),
            api_url: api_config.base_path,
            user_agent: api_config.user_agent.unwrap(),
            device_type: DeviceType::SDK,
            device_identifier: None,
            bitwarden_client_version: None,
            bitwarden_package_type: None,
        }));

        let repository = MemoryRepository::<UserKeyState>::default();
        client
            .platform()
            .state()
            .register_client_managed(std::sync::Arc::new(repository));

        client
            .crypto()
            .initialize_user_crypto(user_crypto_request)
            .await
            .unwrap();

        if let Some(org_crypto_request) = org_crypto_request {
            client
                .crypto()
                .initialize_org_crypto(org_crypto_request)
                .await
                .unwrap();
        }

        (server, client)
    }

    fn make_user_crypto_request() -> InitUserCryptoRequest {
        InitUserCryptoRequest {
            user_id: Some(TEST_USER_ID.parse().unwrap()),
            kdf_params: Kdf::default_pbkdf2(),
            email: TEST_USER_EMAIL.to_string(),
            account_cryptographic_state: WrappedAccountCryptographicState::V1 {
                private_key: TEST_ACCOUNT_PRIVATE_KEY.parse().unwrap(),
            },
            method: InitUserCryptoMethod::MasterPasswordUnlock {
                password: TEST_USER_PASSWORD.to_string(),
                master_password_unlock: MasterPasswordUnlockData {
                    kdf: Kdf::default_pbkdf2(),
                    master_key_wrapped_user_key: TEST_ACCOUNT_USER_KEY.parse().unwrap(),
                    salt: TEST_USER_EMAIL.to_string(),
                },
            },
        }
    }

    #[tokio::test]
    async fn test_sync_user_empty_vault_no_organizations() {
        let user_id: UserId = TEST_USER_ID.parse().unwrap();
        let organization_id: OrganizationId = TEST_ACCOUNT_ORGANIZATION_ID
            .parse()
            .expect("Invalid organization ID");
        let user_crypto_request = make_user_crypto_request();
        let (_server, client) =
            setup_sync_client(create_sync_response(user_id), user_crypto_request, None).await;

        let sync_request = SyncRequest {
            exclude_subdomains: Some(false),
        };

        let sync_response = sync(&client, &sync_request).await;
        assert!(sync_response.is_ok());

        let sync_response = sync_response.unwrap();
        assert_eq!(sync_response.profile.id, user_id);
        assert_eq!(sync_response.profile.name, TEST_USER_NAME);
        assert_eq!(sync_response.profile.email, TEST_USER_EMAIL);
        assert!(sync_response.profile.organizations.is_empty());
        assert!(sync_response.ciphers.is_empty());
        assert!(sync_response.folders.is_empty());
        assert!(sync_response.collections.is_empty());
        assert!(sync_response.domains.is_none());
        assert!(
            !client
                .internal
                .get_key_store()
                .context()
                .has_symmetric_key(SymmetricKeyId::Organization(organization_id))
        );
    }

    #[tokio::test]
    async fn test_sync_user_with_organization() {
        let user_id = UserId::new(uuid::uuid!(TEST_USER_ID));
        let organization_id: OrganizationId = TEST_ACCOUNT_ORGANIZATION_ID
            .parse()
            .expect("Invalid organization ID");
        let organization_key: UnsignedSharedKey = TEST_ACCOUNT_ORGANIZATION_KEY
            .parse()
            .expect("Invalid organization key");
        let user_crypto_request = make_user_crypto_request();
        let response = SyncResponseModel {
            profile: Some(Box::new(ProfileResponseModel {
                organizations: Some(vec![ProfileOrganizationResponseModel {
                    id: Some(organization_id.into()),
                    key: Some(organization_key.to_string()),
                    ..ProfileOrganizationResponseModel::new()
                }]),
                ..create_profile_response(user_id)
            })),
            ..create_sync_response(user_id)
        };
        let (_server, client) = setup_sync_client(response, user_crypto_request, None).await;

        let sync_request = SyncRequest {
            exclude_subdomains: Some(false),
        };

        let sync_response = sync(&client, &sync_request).await;
        assert!(sync_response.is_ok());

        let sync_response = sync_response.unwrap();
        assert_eq!(sync_response.profile.id, user_id);
        assert_eq!(sync_response.profile.name, TEST_USER_NAME);
        assert_eq!(sync_response.profile.email, TEST_USER_EMAIL);
        assert_eq!(sync_response.profile.organizations.len(), 1);
        let organization = sync_response.profile.organizations.first().unwrap();
        assert_eq!(organization.id, organization_id);
        assert!(sync_response.ciphers.is_empty());
        assert!(sync_response.folders.is_empty());
        assert!(sync_response.collections.is_empty());
        assert!(sync_response.domains.is_none());
        assert!(
            client
                .internal
                .get_key_store()
                .context()
                .has_symmetric_key(SymmetricKeyId::Organization(organization_id))
        );
    }

    #[tokio::test]
    async fn test_sync_user_with_decryption_options_master_password_unlock() {
        let user_id = UserId::new(uuid::uuid!(TEST_USER_ID));
        let user_key: EncString = TEST_ACCOUNT_USER_KEY.parse().expect("Invalid user key");
        let user_crypto_request = make_user_crypto_request();
        let response = SyncResponseModel {
            user_decryption: Some(Box::new(UserDecryptionResponseModel {
                master_password_unlock: Some(Box::new(MasterPasswordUnlockResponseModel {
                    kdf: Box::new(MasterPasswordUnlockKdfResponseModel {
                        kdf_type: KdfType::Argon2id,
                        iterations: 4,
                        memory: Some(65),
                        parallelism: Some(5),
                    }),
                    salt: Some(TEST_USER_EMAIL.to_string()),
                    master_key_encrypted_user_key: Some(user_key.to_string()),
                })),
                web_authn_prf_options: None,
                v2_upgrade_token: None,
            })),
            ..create_sync_response(user_id)
        };
        let (_server, client) = setup_sync_client(response, user_crypto_request, None).await;

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
