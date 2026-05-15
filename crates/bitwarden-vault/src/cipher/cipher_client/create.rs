use bitwarden_api_api::models::{CipherCreateRequestModel, CipherRequestModel};
use bitwarden_collections::collection::CollectionId;
use bitwarden_core::{ApiError, MissingFieldError, NotAuthenticatedError, OrganizationId, require};
use bitwarden_crypto::CryptoError;
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{RepositoryError, RepositoryOption};
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use super::{CiphersClient, EncryptionContext};
use crate::{
    Cipher, CipherRepromptType, CipherView, EncryptError, FieldView, FolderId, VaultParseError,
    cipher::cipher::PartialCipher, cipher_view_type::CipherViewType,
};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum CreateCipherError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    BlobEncryption(#[from] crate::blob::BlobEncryptionError),
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    VaultParse(#[from] VaultParseError),
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    #[error(transparent)]
    NotAuthenticated(#[from] NotAuthenticatedError),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

impl<T> From<bitwarden_api_api::apis::Error<T>> for CreateCipherError {
    fn from(val: bitwarden_api_api::apis::Error<T>) -> Self {
        Self::Api(val.into())
    }
}

impl From<EncryptError> for CreateCipherError {
    fn from(e: EncryptError) -> Self {
        match e {
            EncryptError::Crypto(c) => Self::Crypto(c),
            EncryptError::BlobEncryption(b) => Self::BlobEncryption(b),
            EncryptError::MissingUserId => Self::NotAuthenticated(NotAuthenticatedError),
        }
    }
}

/// Request to add a cipher.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct CipherCreateRequest {
    pub organization_id: Option<OrganizationId>,
    pub collection_ids: Vec<CollectionId>,
    pub folder_id: Option<FolderId>,
    pub name: String,
    pub notes: Option<String>,
    pub favorite: bool,
    pub reprompt: CipherRepromptType,
    pub r#type: CipherViewType,
    pub fields: Vec<FieldView>,
}

/// Internal helper to convert a [`CipherCreateRequest`] into a [`CipherView`]
/// so the existing `CipherView` encryption pipeline can be reused.
///
/// This conversion is lossy and intended for use only within the internal create flow.
/// Placeholder values are generated to satisfy the CipherView contract; they have
/// no meaning outside of this flow.
pub(crate) fn convert_request_to_cipher_view(r: CipherCreateRequest) -> CipherView {
    // `creation_date` / `revision_date` are overwritten by the server on
    // merge; `Utc::now()` is a safe placeholder.
    let now = chrono::Utc::now();
    CipherView {
        id: None,
        organization_id: r.organization_id,
        folder_id: r.folder_id,
        collection_ids: r.collection_ids,
        key: None,
        name: r.name,
        notes: r.notes,
        r#type: r.r#type.get_cipher_type(),
        login: r.r#type.as_login_view().cloned(),
        identity: r.r#type.as_identity_view().cloned(),
        card: r.r#type.as_card_view().cloned(),
        secure_note: r.r#type.as_secure_note_view().cloned(),
        ssh_key: r.r#type.as_ssh_key_view().cloned(),
        bank_account: r.r#type.as_bank_account_view().cloned(),
        drivers_license: r.r#type.as_drivers_license_view().cloned(),
        passport: r.r#type.as_passport_view().cloned(),
        favorite: r.favorite,
        reprompt: r.reprompt,
        organization_use_totp: false,
        edit: true,
        permissions: None,
        view_password: true,
        local_data: None,
        attachments: None,
        attachment_decryption_failures: None,
        fields: Some(r.fields),
        password_history: None,
        creation_date: now,
        deleted_date: None,
        revision_date: now,
        archived_date: None,
    }
}

#[allow(deprecated)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CiphersClient {
    /// Creates a new [Cipher] and saves it to the server.
    pub async fn create(
        &self,
        request: CipherCreateRequest,
    ) -> Result<CipherView, CreateCipherError> {
        let repository = self.repository.require()?;
        let api_client = &self.api_configurations.api_client;

        let view: CipherView = convert_request_to_cipher_view(request);
        let collection_ids = view.collection_ids.clone();

        let EncryptionContext {
            cipher,
            encrypted_for,
        } = self.encrypt(view).await?;

        let mut cipher_request: CipherRequestModel = cipher.try_into()?;
        cipher_request.encrypted_for = Some(encrypted_for.into());

        let mut cipher: Cipher;
        if !collection_ids.is_empty() {
            cipher = api_client
                .ciphers_api()
                .post_create(Some(CipherCreateRequestModel {
                    collection_ids: Some(collection_ids.iter().cloned().map(Into::into).collect()),
                    cipher: Box::new(cipher_request),
                }))
                .await
                .map_err(ApiError::from)?
                .merge_with_cipher(None)?;
            cipher.collection_ids = collection_ids;
            repository.set(require!(cipher.id), cipher.clone()).await?;
        } else {
            cipher = api_client
                .ciphers_api()
                .post(Some(cipher_request))
                .await
                .map_err(ApiError::from)?
                .merge_with_cipher(None)?;
            repository.set(require!(cipher.id), cipher.clone()).await?;
        }

        Ok(self.key_store.decrypt(&cipher)?)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use bitwarden_api_api::{apis::ApiClient, models::CipherResponseModel};
    use bitwarden_core::{
        client::ApiConfigurations,
        key_management::{
            BLOB_SECURITY_VERSION, KeySlotIds, create_test_crypto_with_user_and_org_key,
            create_test_crypto_with_user_key,
        },
    };
    use bitwarden_crypto::{KeyStore, SymmetricCryptoKey};
    use bitwarden_state::repository::Repository;
    use bitwarden_test::MemoryRepository;
    use chrono::Utc;

    use super::*;
    use crate::{CipherId, LoginView};

    const TEST_CIPHER_ID: &str = "5faa9684-c793-4a2d-8a12-b33900187097";
    const TEST_COLLECTION_ID: &str = "73546b86-8802-4449-ad2a-69ea981b4ffd";
    const TEST_USER_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
    const TEST_ORG_ID: &str = "1bc9ac1e-f5aa-45f2-94bf-b181009709b8";

    fn generate_test_cipher_create_request() -> CipherCreateRequest {
        CipherCreateRequest {
            name: "Test Login".to_string(),
            notes: Some("Test notes".to_string()),
            r#type: CipherViewType::Login(LoginView {
                username: Some("test@example.com".to_string()),
                password: Some("password123".to_string()),
                password_revision_date: None,
                uris: None,
                totp: None,
                autofill_on_page_load: None,
                fido2_credentials: None,
            }),
            organization_id: Default::default(),
            folder_id: Default::default(),
            favorite: Default::default(),
            reprompt: Default::default(),
            fields: Default::default(),
            collection_ids: vec![],
        }
    }

    async fn create_test_client(
        api_client: ApiClient,
        key_store: KeyStore<KeySlotIds>,
        flags: HashMap<String, bool>,
    ) -> (CiphersClient, Arc<MemoryRepository<Cipher>>) {
        let repository = Arc::new(MemoryRepository::<Cipher>::default());
        let core_client = bitwarden_core::Client::new_test(None);
        core_client
            .internal
            .init_user_id(TEST_USER_ID.parse().unwrap())
            .await
            .unwrap();
        if !flags.is_empty() {
            core_client.internal.load_flags(flags).await;
        }
        #[allow(deprecated)]
        let client = CiphersClient {
            key_store,
            api_configurations: Arc::new(ApiConfigurations::from_api_client(api_client)),
            repository: Some(repository.clone() as Arc<dyn Repository<Cipher>>),
            client: core_client,
        };
        (client, repository)
    }

    #[tokio::test]
    async fn test_create_cipher() {
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.ciphers_api
                .expect_post()
                .returning(move |body| {
                    let body = body.unwrap();
                    Ok(CipherResponseModel {
                        object: Some("cipher".to_string()),
                        id: Some(cipher_id.into()),
                        name: Some(body.name.clone()),
                        r#type: body.r#type,
                        organization_id: body
                            .organization_id
                            .as_ref()
                            .and_then(|id| uuid::Uuid::parse_str(id).ok()),
                        folder_id: body
                            .folder_id
                            .as_ref()
                            .and_then(|id| uuid::Uuid::parse_str(id).ok()),
                        favorite: body.favorite,
                        reprompt: body.reprompt,
                        key: body.key.clone(),
                        notes: body.notes.clone(),
                        view_password: Some(true),
                        edit: Some(true),
                        organization_use_totp: Some(true),
                        revision_date: Some("2025-01-01T00:00:00Z".to_string()),
                        creation_date: Some("2025-01-01T00:00:00Z".to_string()),
                        deleted_date: None,
                        login: body.login,
                        card: body.card,
                        identity: body.identity,
                        secure_note: body.secure_note,
                        ssh_key: body.ssh_key,
                        bank_account: body.bank_account,
                        drivers_license: body.drivers_license,
                        passport: body.passport,
                        fields: body.fields,
                        password_history: body.password_history,
                        attachments: None,
                        permissions: None,
                        data: None,
                        archived_date: None,
                    })
                })
                .once();
        });

        let store =
            create_test_crypto_with_user_key(SymmetricCryptoKey::make_aes256_cbc_hmac_key());
        let (client, repository) = create_test_client(api_client, store, HashMap::new()).await;

        let result = client
            .create(generate_test_cipher_create_request())
            .await
            .unwrap();

        assert_eq!(result.id, Some(cipher_id));
        assert_eq!(result.name, "Test Login");
        assert_eq!(
            result.login,
            Some(LoginView {
                username: Some("test@example.com".to_string()),
                password: Some("password123".to_string()),
                password_revision_date: None,
                uris: None,
                totp: None,
                autofill_on_page_load: None,
                fido2_credentials: None,
            })
        );

        // Confirm the cipher was stored in the repository
        let stored_cipher_view: CipherView = client
            .key_store
            .decrypt(&repository.get(cipher_id).await.unwrap().unwrap())
            .unwrap();
        assert_eq!(stored_cipher_view.id, result.id);
        assert_eq!(stored_cipher_view.name, result.name);
        assert_eq!(stored_cipher_view.r#type, result.r#type);
        assert!(stored_cipher_view.login.is_some());
        assert_eq!(stored_cipher_view.favorite, result.favorite);
    }

    #[tokio::test]
    async fn test_create_cipher_http_error() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.ciphers_api
                .expect_post()
                .returning(move |_body| Err(std::io::Error::other("Simulated error").into()));
        });

        let store =
            create_test_crypto_with_user_key(SymmetricCryptoKey::make_aes256_cbc_hmac_key());
        let (client, _) = create_test_client(api_client, store, HashMap::new()).await;

        let result = client.create(generate_test_cipher_create_request()).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CreateCipherError::Api(_)));
    }

    #[tokio::test]
    async fn test_create_org_cipher() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.ciphers_api
                .expect_post_create()
                .returning(move |body| {
                    let request_body = body.unwrap();

                    Ok(CipherResponseModel {
                        id: Some(TEST_CIPHER_ID.try_into().unwrap()),
                        organization_id: request_body
                            .cipher
                            .organization_id
                            .and_then(|id| id.parse().ok()),
                        name: Some(request_body.cipher.name.clone()),
                        r#type: request_body.cipher.r#type,
                        creation_date: Some(Utc::now().to_string()),
                        revision_date: Some(Utc::now().to_string()),
                        ..Default::default()
                    })
                })
                .once();
        });

        let store = create_test_crypto_with_user_and_org_key(
            SymmetricCryptoKey::make_aes256_cbc_hmac_key(),
            TEST_ORG_ID.parse().unwrap(),
            SymmetricCryptoKey::make_aes256_cbc_hmac_key(),
        );
        let (client, repository) = create_test_client(api_client, store, HashMap::new()).await;

        let request = CipherCreateRequest {
            organization_id: Some(TEST_ORG_ID.parse().unwrap()),
            collection_ids: vec![TEST_COLLECTION_ID.parse().unwrap()],
            folder_id: None,
            name: "Test Cipher".into(),
            notes: None,
            favorite: false,
            reprompt: CipherRepromptType::None,
            r#type: CipherViewType::Login(LoginView {
                username: None,
                password: None,
                password_revision_date: None,
                uris: None,
                totp: None,
                autofill_on_page_load: None,
                fido2_credentials: None,
            }),
            fields: vec![],
        };

        let response = client.create(request).await.unwrap();

        let cipher: Cipher = repository
            .get(TEST_CIPHER_ID.parse().unwrap())
            .await
            .unwrap()
            .unwrap();
        let cipher_view: CipherView = client.key_store.decrypt(&cipher).unwrap();

        assert_eq!(response.id, cipher_view.id);
        assert_eq!(response.organization_id, cipher_view.organization_id);

        assert_eq!(response.id, Some(TEST_CIPHER_ID.parse().unwrap()));
        assert_eq!(response.organization_id, Some(TEST_ORG_ID.parse().unwrap()));
    }

    #[tokio::test]
    async fn test_create_cipher_blob_encryption() {
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.ciphers_api
                .expect_post()
                .returning(move |body| {
                    let body = body.unwrap();
                    Ok(CipherResponseModel {
                        id: Some(cipher_id.into()),
                        name: Some(body.name.clone()),
                        r#type: body.r#type,
                        key: body.key.clone(),
                        data: body.data.clone(),
                        view_password: Some(true),
                        edit: Some(true),
                        organization_use_totp: Some(false),
                        revision_date: Some("2025-01-01T00:00:00Z".to_string()),
                        creation_date: Some("2025-01-01T00:00:00Z".to_string()),
                        ..Default::default()
                    })
                })
                .once();
        });

        let store =
            create_test_crypto_with_user_key(SymmetricCryptoKey::make_aes256_cbc_hmac_key());
        store.set_security_state_version(BLOB_SECURITY_VERSION);
        let flags = HashMap::from([("enableCipherKeyEncryption".to_owned(), true)]);
        let (client, repository) = create_test_client(api_client, store, flags).await;

        client
            .create(generate_test_cipher_create_request())
            .await
            .unwrap();

        let stored: Cipher = repository.get(cipher_id).await.unwrap().unwrap();
        assert!(crate::blob::is_blob_encrypted(&stored));
    }
}
