use bitwarden_api_api::models::{CipherCreateRequestModel, CipherRequestModel};
use bitwarden_collections::collection::CollectionId;
use bitwarden_core::{
    ApiError, MissingFieldError, NotAuthenticatedError, OrganizationId, UserId,
    key_management::{KeyIds, SymmetricKeyId},
    require,
};
use bitwarden_crypto::{
    CompositeEncryptable, CryptoError, EncString, IdentifyKey, KeyStore, KeyStoreContext,
    PrimitiveEncryptable,
};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{Repository, RepositoryError};
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use super::CiphersClient;
use crate::{
    Cipher, CipherRepromptType, CipherView, FieldView, FolderId, VaultParseError,
    cipher_view_type::CipherViewType,
};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum CreateCipherError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
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

/// Request to add a cipher.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct CipherCreateRequest {
    pub organization_id: Option<OrganizationId>,
    pub folder_id: Option<FolderId>,
    pub name: String,
    pub notes: Option<String>,
    pub favorite: bool,
    pub reprompt: CipherRepromptType,
    pub r#type: CipherViewType,
    pub fields: Vec<FieldView>,
}

/// Used as an intermediary between the public-facing [CipherCreateRequest], and the encrypted
/// value. This allows us to manage the cipher key creation internally.
#[derive(Clone, Debug)]
pub(crate) struct CipherCreateRequestInternal {
    create_request: CipherCreateRequest,
    key: Option<EncString>,
}

impl From<CipherCreateRequest> for CipherCreateRequestInternal {
    fn from(create_request: CipherCreateRequest) -> Self {
        Self {
            create_request,
            key: None,
        }
    }
}

impl CipherCreateRequestInternal {
    /// Generate a new key for the cipher, re-encrypting internal data, if necessary, and stores the
    /// encrypted key to the cipher data.
    pub(crate) fn generate_cipher_key(
        &mut self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<(), CryptoError> {
        let old_key = Cipher::decrypt_cipher_key(ctx, key, &self.key)?;

        let new_key = ctx.generate_symmetric_key();
        self.create_request
            .r#type
            .as_login_view_mut()
            .map(|l| l.reencrypt_fido2_credentials(ctx, old_key, new_key))
            .transpose()?;

        self.key = Some(ctx.wrap_symmetric_key(key, new_key)?);
        Ok(())
    }

    fn generate_checksums(&mut self) {
        if let Some(login) = &mut self.create_request.r#type.as_login_view_mut() {
            login.generate_checksums();
        }
    }
}

impl CompositeEncryptable<KeyIds, SymmetricKeyId, CipherRequestModel>
    for CipherCreateRequestInternal
{
    fn encrypt_composite(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<CipherRequestModel, CryptoError> {
        // Clone self so we can generating the checksums before encrypting.
        let mut cipher_data = (*self).clone();
        cipher_data.generate_checksums();

        let cipher_key = Cipher::decrypt_cipher_key(ctx, key, &cipher_data.key)?;

        let cipher_request = CipherRequestModel {
            encrypted_for: None,
            r#type: Some(cipher_data.create_request.r#type.get_cipher_type().into()),
            organization_id: cipher_data
                .create_request
                .organization_id
                .map(|id| id.to_string()),
            folder_id: cipher_data
                .create_request
                .folder_id
                .map(|id| id.to_string()),
            favorite: Some(cipher_data.create_request.favorite),
            reprompt: Some(cipher_data.create_request.reprompt.into()),
            key: cipher_data.key.map(|k| k.to_string()),
            name: cipher_data
                .create_request
                .name
                .encrypt(ctx, cipher_key)?
                .to_string(),
            notes: cipher_data
                .create_request
                .notes
                .as_ref()
                .map(|n| n.encrypt(ctx, cipher_key))
                .transpose()?
                .map(|n| n.to_string()),
            login: cipher_data
                .create_request
                .r#type
                .as_login_view()
                .as_ref()
                .map(|l| l.encrypt_composite(ctx, cipher_key))
                .transpose()?
                .map(|l| Box::new(l.into())),
            card: cipher_data
                .create_request
                .r#type
                .as_card_view()
                .as_ref()
                .map(|c| c.encrypt_composite(ctx, cipher_key))
                .transpose()?
                .map(|c| Box::new(c.into())),
            identity: cipher_data
                .create_request
                .r#type
                .as_identity_view()
                .as_ref()
                .map(|i| i.encrypt_composite(ctx, cipher_key))
                .transpose()?
                .map(|i| Box::new(i.into())),
            secure_note: cipher_data
                .create_request
                .r#type
                .as_secure_note_view()
                .as_ref()
                .map(|s| s.encrypt_composite(ctx, cipher_key))
                .transpose()?
                .map(|s| Box::new(s.into())),
            ssh_key: cipher_data
                .create_request
                .r#type
                .as_ssh_key_view()
                .as_ref()
                .map(|s| s.encrypt_composite(ctx, cipher_key))
                .transpose()?
                .map(|s| Box::new(s.into())),
            fields: Some(
                cipher_data
                    .create_request
                    .fields
                    .iter()
                    .map(|f| f.encrypt_composite(ctx, cipher_key))
                    .map(|f| f.map(|f| f.into()))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            password_history: None,
            attachments: None,
            attachments2: None,
            last_known_revision_date: None,
            archived_date: None,
            data: None,
        };

        Ok(cipher_request)
    }
}

impl IdentifyKey<SymmetricKeyId> for CipherCreateRequestInternal {
    fn key_identifier(&self) -> SymmetricKeyId {
        match self.create_request.organization_id {
            Some(organization_id) => SymmetricKeyId::Organization(organization_id),
            None => SymmetricKeyId::User,
        }
    }
}

async fn create_cipher<R: Repository<Cipher> + ?Sized>(
    key_store: &KeyStore<KeyIds>,
    api_client: &bitwarden_api_api::apis::ApiClient,
    repository: &R,
    encrypted_for: UserId,
    request: CipherCreateRequestInternal,
    collection_ids: Vec<CollectionId>,
    as_admin: bool,
) -> Result<CipherView, CreateCipherError> {
    let mut cipher_request = key_store.encrypt(request)?;
    cipher_request.encrypted_for = Some(encrypted_for.into());

    let cipher: Cipher;
    if as_admin && cipher_request.organization_id.is_some() {
        cipher = api_client
            .ciphers_api()
            .post_admin(Some(CipherCreateRequestModel {
                collection_ids: Some(collection_ids.into_iter().map(Into::into).collect()),
                cipher: Box::new(cipher_request),
            }))
            .await?
            .try_into()?;
    } else if !collection_ids.is_empty() {
        cipher = api_client
            .ciphers_api()
            .post_create(Some(CipherCreateRequestModel {
                collection_ids: Some(collection_ids.into_iter().map(Into::into).collect()),
                cipher: Box::new(cipher_request),
            }))
            .await
            .map_err(ApiError::from)?
            .try_into()?;
        repository
            .set(require!(cipher.id).to_string(), cipher.clone())
            .await?;
    } else {
        cipher = api_client
            .ciphers_api()
            .post(Some(cipher_request))
            .await
            .map_err(ApiError::from)?
            .try_into()?;
        repository
            .set(require!(cipher.id).to_string(), cipher.clone())
            .await?;
    }

    Ok(key_store.decrypt(&cipher)?)
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CiphersClient {
    async fn create_cipher(
        &self,
        request: CipherCreateRequest,
        collection_ids: Vec<CollectionId>,
        as_admin: bool,
    ) -> Result<CipherView, CreateCipherError> {
        let key_store = self.client.internal.get_key_store();
        let config = self.client.internal.get_api_configurations().await;
        let repository = self.get_repository()?;
        let mut internal_request: CipherCreateRequestInternal = request.into();

        let user_id = self
            .client
            .internal
            .get_user_id()
            .ok_or(NotAuthenticatedError)?;

        // TODO: Once this flag is removed, the key generation logic should
        // be moved closer to the actual encryption logic.
        if self
            .client
            .internal
            .get_flags()
            .enable_cipher_key_encryption
        {
            let key = internal_request.key_identifier();
            internal_request.generate_cipher_key(&mut key_store.context(), key)?;
        }

        create_cipher(
            key_store,
            &config.api_client,
            repository.as_ref(),
            user_id,
            internal_request,
            collection_ids,
            as_admin,
        )
        .await
    }

    /// Creates a new [Cipher] and save it to the server.
    pub async fn create(
        &self,
        request: CipherCreateRequest,
        collection_ids: Vec<CollectionId>,
    ) -> Result<CipherView, CreateCipherError> {
        self.create_cipher(request, collection_ids, false).await
    }

    /// Creates a new [Cipher] for an organization, using the admin server endpoints endpoints.
    pub async fn create_as_admin(
        &self,
        request: CipherCreateRequest,
        collection_ids: Vec<CollectionId>,
    ) -> Result<CipherView, CreateCipherError> {
        self.create_cipher(request, collection_ids, false).await
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{apis::ApiClient, models::CipherResponseModel};
    use bitwarden_crypto::SymmetricCryptoKey;
    use bitwarden_test::MemoryRepository;

    use super::*;
    use crate::{CipherId, LoginView};

    const TEST_CIPHER_ID: &str = "5faa9684-c793-4a2d-8a12-b33900187097";
    const TEST_USER_ID: &str = "550e8400-e29b-41d4-a716-446655440000";

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
        }
    }

    #[tokio::test]
    async fn test_create_cipher() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        #[allow(deprecated)]
        let _ = store.context_mut().set_symmetric_key(
            SymmetricKeyId::User,
            SymmetricCryptoKey::make_aes256_cbc_hmac_key(),
        );

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

        let repository = MemoryRepository::<Cipher>::default();
        let request = generate_test_cipher_create_request();

        let result = create_cipher(
            &store,
            &api_client,
            &repository,
            TEST_USER_ID.parse().unwrap(),
            request.into(),
            vec![],
            false,
        )
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
        let stored_cipher_view: CipherView = store
            .decrypt(
                &repository
                    .get(cipher_id.to_string())
                    .await
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(stored_cipher_view.id, result.id);
        assert_eq!(stored_cipher_view.name, result.name);
        assert_eq!(stored_cipher_view.r#type, result.r#type);
        assert!(stored_cipher_view.login.is_some());
        assert_eq!(stored_cipher_view.favorite, result.favorite);
    }

    #[tokio::test]
    async fn test_create_cipher_http_error() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        #[allow(deprecated)]
        let _ = store.context_mut().set_symmetric_key(
            SymmetricKeyId::User,
            SymmetricCryptoKey::make_aes256_cbc_hmac_key(),
        );

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.ciphers_api.expect_post().returning(move |_body| {
                Err(bitwarden_api_api::apis::Error::Io(std::io::Error::other(
                    "Simulated error",
                )))
            });
        });

        let repository = MemoryRepository::<Cipher>::default();

        let request = generate_test_cipher_create_request();

        let result = create_cipher(
            &store,
            &api_client,
            &repository,
            TEST_USER_ID.parse().unwrap(),
            request.into(),
            vec![],
            false,
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CreateCipherError::Api(_)));
    }
}
