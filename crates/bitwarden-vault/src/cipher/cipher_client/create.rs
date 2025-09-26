use bitwarden_api_api::{apis::ciphers_api, models::CipherRequestModel};
use bitwarden_core::{
    key_management::{KeyIds, SymmetricKeyId},
    require, ApiError, MissingFieldError, NotAuthenticatedError, OrganizationId, UserId,
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
    cipher_view_type::{CipherViewType, CipherViewTypeExt},
    Cipher, CipherRepromptType, CipherType, CipherView, FieldView, FolderId, VaultParseError,
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

/// Request to add a cipher.
#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct CipherCreateRequest {
    /// The ID of the user that is encrypting the cipher - this should always match the user
    /// calling the API.
    pub organization_id: Option<OrganizationId>,
    pub folder_id: Option<FolderId>,
    pub name: String,
    pub notes: Option<String>,
    pub r#type: CipherType,
    pub favorite: bool,
    pub reprompt: CipherRepromptType,
    pub type_data: Option<CipherViewType>,
    pub fields: Vec<FieldView>,
    pub key: Option<EncString>,
}

impl CipherCreateRequest {
    /// Generate a new key for the cipher, re-encrypting internal data, if necessary, and stores the
    /// encrypted key to the cipher data.
    pub fn generate_cipher_key(
        &mut self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<(), CryptoError> {
        let old_key = Cipher::decrypt_cipher_key(ctx, key, &self.key)?;

        const NEW_KEY_ID: SymmetricKeyId = SymmetricKeyId::Local("new_cipher_key");

        let new_key = ctx.generate_symmetric_key(NEW_KEY_ID)?;
        self.type_data
            .as_login_view_mut()
            .map(|l| l.reencrypt_fido2_credentials(ctx, old_key, new_key))
            .transpose()?;

        self.key = Some(ctx.wrap_symmetric_key(key, new_key)?);
        Ok(())
    }
}

impl CompositeEncryptable<KeyIds, SymmetricKeyId, CipherRequestModel> for CipherCreateRequest {
    fn encrypt_composite(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<CipherRequestModel, CryptoError> {
        let cipher_key = Cipher::decrypt_cipher_key(ctx, key, &self.key)?;

        let cipher_request = CipherRequestModel {
            encrypted_for: None,
            r#type: Some(self.r#type.into()),
            organization_id: self.organization_id.map(|id| id.to_string()),
            folder_id: self.folder_id.map(|id| id.to_string()),
            favorite: Some(self.favorite),
            reprompt: Some(self.reprompt.into()),
            key: None,
            name: self.name.encrypt(ctx, cipher_key)?.to_string(),
            notes: self
                .notes
                .as_ref()
                .map(|n| n.encrypt(ctx, cipher_key))
                .transpose()?
                .map(|n| n.to_string()),
            login: self
                .type_data
                .as_login_view()
                .as_ref()
                .map(|l| l.encrypt_composite(ctx, cipher_key))
                .transpose()?
                .map(|l| Box::new(l.into())),
            card: self
                .type_data
                .as_card_view()
                .as_ref()
                .map(|c| c.encrypt_composite(ctx, cipher_key))
                .transpose()?
                .map(|c| Box::new(c.into())),
            identity: self
                .type_data
                .as_identity_view()
                .as_ref()
                .map(|i| i.encrypt_composite(ctx, cipher_key))
                .transpose()?
                .map(|i| Box::new(i.into())),
            secure_note: self
                .type_data
                .as_secure_note_view()
                .as_ref()
                .map(|s| s.encrypt_composite(ctx, cipher_key))
                .transpose()?
                .map(|s| Box::new(s.into())),
            ssh_key: self
                .type_data
                .as_ssh_key_view()
                .as_ref()
                .map(|s| s.encrypt_composite(ctx, cipher_key))
                .transpose()?
                .map(|s| Box::new(s.into())),
            fields: Some(
                self.fields
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

impl IdentifyKey<SymmetricKeyId> for CipherCreateRequest {
    fn key_identifier(&self) -> SymmetricKeyId {
        match self.organization_id {
            Some(organization_id) => SymmetricKeyId::Organization(organization_id),
            None => SymmetricKeyId::User,
        }
    }
}

async fn create_cipher<R: Repository<Cipher> + ?Sized>(
    key_store: &KeyStore<KeyIds>,
    api_config: &bitwarden_api_api::apis::configuration::Configuration,
    repository: &R,
    encrypted_for: UserId,
    request: CipherCreateRequest,
) -> Result<CipherView, CreateCipherError> {
    let mut cipher_request = key_store.encrypt(request)?;
    cipher_request.encrypted_for = Some(encrypted_for.into());

    let resp = ciphers_api::ciphers_post(api_config, Some(cipher_request))
        .await
        .map_err(ApiError::from)?;
    let cipher: Cipher = resp.try_into()?;
    repository
        .set(require!(cipher.id).to_string(), cipher.clone())
        .await?;
    Ok(key_store.decrypt(&cipher)?)
}

impl CiphersClient {
    /// Create a new [Cipher] and save it to the server.
    pub async fn create(
        &self,
        mut request: CipherCreateRequest,
    ) -> Result<CipherView, CreateCipherError> {
        let key_store = self.client.internal.get_key_store();
        let config = self.client.internal.get_api_configurations().await;
        let repository = self.get_repository()?;

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
            let key = request.key_identifier();
            request.generate_cipher_key(&mut key_store.context(), key)?;
        }

        create_cipher(
            key_store,
            &config.api,
            repository.as_ref(),
            user_id,
            request,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::models::CipherResponseModel;
    use bitwarden_crypto::SymmetricCryptoKey;
    use bitwarden_test::{start_api_mock, MemoryRepository};
    use wiremock::{matchers, Mock, Request, ResponseTemplate};

    use super::*;
    use crate::{CipherId, CipherType, LoginView};

    const TEST_CIPHER_ID: &str = "5faa9684-c793-4a2d-8a12-b33900187097";
    const TEST_USER_ID: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn generate_test_cipher_create_request() -> CipherCreateRequest {
        CipherCreateRequest {
            name: "Test Login".to_string(),
            notes: Some("Test notes".to_string()),
            r#type: CipherType::Login,
            type_data: Some(CipherViewType::Login(LoginView {
                username: Some("test@example.com".to_string()),
                password: Some("password123".to_string()),
                password_revision_date: None,
                uris: None,
                totp: None,
                autofill_on_page_load: None,
                fido2_credentials: None,
            })),
            ..Default::default()
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

        let (_server, api_config) = start_api_mock(vec![Mock::given(matchers::path("/ciphers"))
            .respond_with(move |req: &Request| {
                let body: CipherRequestModel = req.body_json().unwrap();
                ResponseTemplate::new(201).set_body_json(CipherResponseModel {
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
            .expect(1)])
        .await;

        let repository = MemoryRepository::<Cipher>::default();
        let request = generate_test_cipher_create_request();

        let result = create_cipher(
            &store,
            &api_config,
            &repository,
            TEST_USER_ID.parse().unwrap(),
            request,
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
        let (_server, api_config) = start_api_mock(vec![
            Mock::given(matchers::path("/ciphers")).respond_with(ResponseTemplate::new(500))
        ])
        .await;
        let repository = MemoryRepository::<Cipher>::default();

        let request = generate_test_cipher_create_request();

        let result = create_cipher(
            &store,
            &api_config,
            &repository,
            TEST_USER_ID.parse().unwrap(),
            request,
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CreateCipherError::Api(_)));
    }
}
