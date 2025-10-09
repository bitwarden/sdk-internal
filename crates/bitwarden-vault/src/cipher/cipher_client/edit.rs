use std::collections::HashMap;

use bitwarden_api_api::models::CipherRequestModel;
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
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use super::CiphersClient;
use crate::{
    Cipher, CipherId, CipherRepromptType, CipherType, CipherView, FieldType, FieldView, FolderId,
    ItemNotFoundError, PasswordHistoryView, VaultParseError, cipher_view_type::CipherViewType,
};

/// Maximum number of password history entries to retain
const MAX_PASSWORD_HISTORY_ENTRIES: usize = 5;

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum EditCipherError {
    #[error(transparent)]
    ItemNotFound(#[from] ItemNotFoundError),
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
    #[error(transparent)]
    Uuid(#[from] uuid::Error),
}

/// Request to edit a cipher.
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct CipherEditRequest {
    pub id: CipherId,

    pub organization_id: Option<OrganizationId>,
    pub folder_id: Option<FolderId>,
    pub favorite: bool,
    pub reprompt: CipherRepromptType,
    pub name: String,
    pub notes: Option<String>,
    pub fields: Vec<FieldView>,
    pub r#type: CipherViewType,
    pub revision_date: DateTime<Utc>,
    pub archived_date: Option<DateTime<Utc>>,
    pub key: Option<EncString>,
}

impl TryFrom<CipherView> for CipherEditRequest {
    type Error = MissingFieldError;

    fn try_from(value: CipherView) -> Result<Self, Self::Error> {
        let type_data = match value.r#type {
            CipherType::Login => value.login.map(CipherViewType::Login),
            CipherType::SecureNote => value.secure_note.map(CipherViewType::SecureNote),
            CipherType::Card => value.card.map(CipherViewType::Card),
            CipherType::Identity => value.identity.map(CipherViewType::Identity),
            CipherType::SshKey => value.ssh_key.map(CipherViewType::SshKey),
        };
        Ok(Self {
            id: value.id.ok_or(MissingFieldError("id"))?,
            organization_id: value.organization_id,
            folder_id: value.folder_id,
            favorite: value.favorite,
            reprompt: value.reprompt,
            key: value.key,
            name: value.name,
            notes: value.notes,
            fields: value.fields.unwrap_or_default(),
            r#type: require!(type_data),
            revision_date: value.revision_date,
            archived_date: value.archived_date,
        })
    }
}

impl CipherEditRequest {
    fn generate_password_history(
        &mut self,
        original_cipher: &CipherView,
    ) -> Vec<PasswordHistoryView> {
        let changes = self
            .detect_login_password_changes(original_cipher)
            .into_iter()
            .chain(self.detect_hidden_field_changes(original_cipher));
        let history: Vec<_> = changes
            .rev()
            .chain(original_cipher.password_history.iter().flatten().cloned())
            .take(MAX_PASSWORD_HISTORY_ENTRIES)
            .collect();

        history
    }

    fn detect_login_password_changes(
        &mut self,
        original_cipher: &CipherView,
    ) -> Vec<PasswordHistoryView> {
        if !matches!(self.r#type, CipherViewType::Login(_))
            || original_cipher.r#type != CipherType::Login
        {
            return vec![];
        }

        let (Some(original_login), Some(current_login)) = (
            original_cipher.login.as_ref(),
            self.r#type.as_login_view_mut(),
        ) else {
            return vec![];
        };

        let original_password = original_login.password.as_deref().unwrap_or("");
        let current_password = current_login.password.as_deref().unwrap_or("");

        if original_password.is_empty() {
            // No original password - set revision date only if adding new password
            if !current_password.is_empty() {
                current_login.password_revision_date = Some(Utc::now());
            }
            vec![]
        } else if original_password == current_password {
            // Password unchanged - preserve original revision date
            current_login.password_revision_date = original_login.password_revision_date;
            vec![]
        } else {
            // Password changed - update revision date and track change
            current_login.password_revision_date = Some(Utc::now());
            vec![PasswordHistoryView::new_password(original_password)]
        }
    }

    fn detect_hidden_field_changes(
        &self,
        original_cipher: &CipherView,
    ) -> Vec<PasswordHistoryView> {
        let original_fields =
            Self::extract_hidden_fields(original_cipher.fields.as_deref().unwrap_or_default());
        let current_fields = Self::extract_hidden_fields(&self.fields);

        original_fields
            .into_iter()
            .filter_map(|(field_name, original_value)| {
                let current_value = current_fields.get(&field_name);
                if current_value != Some(&original_value) {
                    Some(PasswordHistoryView::new_field(&field_name, &original_value))
                } else {
                    None
                }
            })
            .collect()
    }

    fn extract_hidden_fields(fields: &[FieldView]) -> HashMap<String, String> {
        fields
            .iter()
            .filter_map(|f| match (&f.r#type, &f.name, &f.value) {
                (FieldType::Hidden, Some(name), Some(value))
                    if !name.is_empty() && !value.is_empty() =>
                {
                    Some((name.clone(), value.clone()))
                }
                _ => None,
            })
            .collect()
    }

    fn generate_checksums(&mut self) {
        if let Some(login) = &mut self.r#type.as_login_view_mut() {
            login.generate_checksums();
        }
    }
}

impl CompositeEncryptable<KeyIds, SymmetricKeyId, CipherRequestModel> for CipherEditRequest {
    fn encrypt_composite(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<CipherRequestModel, CryptoError> {
        let mut cipher_data = (*self).clone();
        cipher_data.generate_checksums();

        let cipher_key = Cipher::decrypt_cipher_key(ctx, key, &self.key)?;

        let cipher_request = CipherRequestModel {
            encrypted_for: None,
            r#type: Some(cipher_data.r#type.get_cipher_type().into()),
            organization_id: cipher_data.organization_id.map(|id| id.to_string()),
            folder_id: cipher_data.folder_id.map(|id| id.to_string()),
            favorite: Some(cipher_data.favorite),
            reprompt: Some(cipher_data.reprompt.into()),
            key: cipher_data.key.map(|k| k.to_string()),
            name: cipher_data.name.encrypt(ctx, cipher_key)?.to_string(),
            notes: cipher_data
                .notes
                .as_ref()
                .map(|n| n.encrypt(ctx, cipher_key))
                .transpose()?
                .map(|n| n.to_string()),
            fields: Some(
                cipher_data
                    .fields
                    .encrypt_composite(ctx, cipher_key)?
                    .into_iter()
                    .map(|f| f.into())
                    .collect(),
            ),
            password_history: None, // TODO: Need to calculate this and re-encrypt after encryption.
            attachments: None,
            attachments2: None,
            login: cipher_data
                .r#type
                .as_login_view()
                .map(|l| l.encrypt_composite(ctx, cipher_key))
                .transpose()?
                .map(|l| Box::new(l.into())),
            card: cipher_data
                .r#type
                .as_card_view()
                .map(|c| c.encrypt_composite(ctx, cipher_key))
                .transpose()?
                .map(|c| Box::new(c.into())),
            identity: cipher_data
                .r#type
                .as_identity_view()
                .map(|i| i.encrypt_composite(ctx, cipher_key))
                .transpose()?
                .map(|c| Box::new(c.into())),

            secure_note: cipher_data
                .r#type
                .as_secure_note_view()
                .map(|i| i.encrypt_composite(ctx, cipher_key))
                .transpose()?
                .map(|c| Box::new(c.into())),
            ssh_key: cipher_data
                .r#type
                .as_ssh_key_view()
                .map(|i| i.encrypt_composite(ctx, cipher_key))
                .transpose()?
                .map(|c| Box::new(c.into())),

            last_known_revision_date: Some(cipher_data.revision_date.to_rfc3339()),
            archived_date: cipher_data.archived_date.map(|d| d.to_rfc3339()),
            data: None,
        };

        Ok(cipher_request)
    }
}

impl IdentifyKey<SymmetricKeyId> for CipherEditRequest {
    fn key_identifier(&self) -> SymmetricKeyId {
        match self.organization_id {
            Some(organization_id) => SymmetricKeyId::Organization(organization_id),
            None => SymmetricKeyId::User,
        }
    }
}

async fn edit_cipher<R: Repository<Cipher> + ?Sized>(
    key_store: &KeyStore<KeyIds>,
    api_client: &bitwarden_api_api::apis::ApiClient,
    repository: &R,
    encrypted_for: UserId,
    mut request: CipherEditRequest,
) -> Result<CipherView, EditCipherError> {
    let cipher_id = request.id;

    let original_cipher = repository
        .get(cipher_id.to_string())
        .await?
        .ok_or(ItemNotFoundError)?;
    let original_cipher_view: CipherView = key_store.decrypt(&original_cipher)?;

    // Update password history
    let password_history = request.generate_password_history(&original_cipher_view);
    let enc_password_history =
        password_history.encrypt_composite(&mut key_store.context(), request.key_identifier())?;

    let mut cipher_request = key_store.encrypt(request)?;
    cipher_request.encrypted_for = Some(encrypted_for.into());
    cipher_request.password_history =
        Some(enc_password_history.into_iter().map(Into::into).collect());

    let response = api_client
        .ciphers_api()
        .put(cipher_id.into(), Some(cipher_request))
        .await
        .map_err(ApiError::from)?;

    let cipher: Cipher = response.try_into()?;

    debug_assert!(cipher.id.unwrap_or_default() == cipher_id);

    repository
        .set(cipher_id.to_string(), cipher.clone())
        .await?;

    Ok(key_store.decrypt(&cipher)?)
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CiphersClient {
    /// Edit an existing [Cipher] and save it to the server.
    pub async fn edit(&self, request: CipherEditRequest) -> Result<CipherView, EditCipherError> {
        let key_store = self.client.internal.get_key_store();
        let config = self.client.internal.get_api_configurations().await;
        let repository = self.get_repository()?;

        let user_id = self
            .client
            .internal
            .get_user_id()
            .ok_or(NotAuthenticatedError)?;

        edit_cipher(
            key_store,
            &config.api_client,
            repository.as_ref(),
            user_id,
            request,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{apis::ApiClient, models::CipherResponseModel};
    use bitwarden_core::key_management::SymmetricKeyId;
    use bitwarden_crypto::{KeyStore, PrimitiveEncryptable, SymmetricCryptoKey};
    use bitwarden_test::MemoryRepository;
    use chrono::TimeZone;

    use super::*;
    use crate::{
        Cipher, CipherId, CipherRepromptType, CipherType, Login, LoginView, PasswordHistoryView,
    };

    const TEST_CIPHER_ID: &str = "5faa9684-c793-4a2d-8a12-b33900187097";
    const TEST_USER_ID: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn generate_test_cipher() -> CipherView {
        CipherView {
            id: Some(TEST_CIPHER_ID.parse().unwrap()),
            organization_id: None,
            folder_id: None,
            collection_ids: vec![],
            key: None,
            name: "Test Login".to_string(),
            notes: None,
            r#type: CipherType::Login,
            login: Some(LoginView {
                username: Some("test@example.com".to_string()),
                password: Some("password123".to_string()),
                password_revision_date: None,
                uris: None,
                totp: None,
                autofill_on_page_load: None,
                fido2_credentials: None,
            }),
            identity: None,
            card: None,
            secure_note: None,
            ssh_key: None,
            favorite: false,
            reprompt: CipherRepromptType::None,
            organization_use_totp: true,
            edit: true,
            permissions: None,
            view_password: true,
            local_data: None,
            attachments: None,
            fields: None,
            password_history: None,
            creation_date: "2025-01-01T00:00:00Z".parse().unwrap(),
            deleted_date: None,
            revision_date: "2025-01-01T00:00:00Z".parse().unwrap(),
            archived_date: None,
        }
    }

    fn create_test_login_cipher(password: &str) -> CipherView {
        let mut cipher_view = generate_test_cipher();
        if let Some(ref mut login) = cipher_view.login {
            login.password = Some(password.to_string());
        }
        cipher_view
    }

    async fn repository_add_cipher(
        repository: &MemoryRepository<Cipher>,
        store: &KeyStore<KeyIds>,
        cipher_id: CipherId,
        name: &str,
    ) {
        let mut ctx = store.context();

        repository
            .set(
                cipher_id.to_string(),
                Cipher {
                    id: Some(cipher_id),
                    organization_id: None,
                    folder_id: None,
                    collection_ids: vec![],
                    key: None,
                    name: name.encrypt(&mut ctx, SymmetricKeyId::User).unwrap(),
                    notes: None,
                    r#type: CipherType::Login,
                    login: Some(Login {
                        username: Some("test@example.com")
                            .map(|u| u.encrypt(&mut ctx, SymmetricKeyId::User))
                            .transpose()
                            .unwrap(),
                        password: Some("password123")
                            .map(|p| p.encrypt(&mut ctx, SymmetricKeyId::User))
                            .transpose()
                            .unwrap(),
                        password_revision_date: None,
                        uris: None,
                        totp: None,
                        autofill_on_page_load: None,
                        fido2_credentials: None,
                    }),
                    identity: None,
                    card: None,
                    secure_note: None,
                    ssh_key: None,
                    favorite: false,
                    reprompt: CipherRepromptType::None,
                    organization_use_totp: true,
                    edit: true,
                    permissions: None,
                    view_password: true,
                    local_data: None,
                    attachments: None,
                    fields: None,
                    password_history: None,
                    creation_date: "2024-01-01T00:00:00Z".parse().unwrap(),
                    deleted_date: None,
                    revision_date: "2024-01-01T00:00:00Z".parse().unwrap(),
                    archived_date: None,
                },
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_edit_cipher() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        #[allow(deprecated)]
        let _ = store.context_mut().set_symmetric_key(
            SymmetricKeyId::User,
            SymmetricCryptoKey::make_aes256_cbc_hmac_key(),
        );

        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.ciphers_api
                .expect_put()
                .returning(move |_id, body| {
                    let body = body.unwrap();
                    Ok(CipherResponseModel {
                        object: Some("cipher".to_string()),
                        id: Some(cipher_id.into()),
                        name: Some(body.name),
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
                        key: body.key,
                        notes: body.notes,
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
        repository_add_cipher(&repository, &store, cipher_id, "old_name").await;
        let cipher_view = generate_test_cipher();

        let request = cipher_view.try_into().unwrap();

        let result = edit_cipher(
            &store,
            &api_client,
            &repository,
            TEST_USER_ID.parse().unwrap(),
            request,
        )
        .await
        .unwrap();

        assert_eq!(result.id, Some(cipher_id));
        assert_eq!(result.name, "Test Login");
    }

    #[tokio::test]
    async fn test_edit_cipher_does_not_exist() {
        let store: KeyStore<KeyIds> = KeyStore::default();

        let repository = MemoryRepository::<Cipher>::default();

        let cipher_view = generate_test_cipher();
        let api_client = ApiClient::new_mocked(|_| {});

        let request = cipher_view.try_into().unwrap();

        let result = edit_cipher(
            &store,
            &api_client,
            &repository,
            TEST_USER_ID.parse().unwrap(),
            request,
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EditCipherError::ItemNotFound(_)
        ));
    }

    #[tokio::test]
    async fn test_edit_cipher_http_error() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        #[allow(deprecated)]
        let _ = store.context_mut().set_symmetric_key(
            SymmetricKeyId::User,
            SymmetricCryptoKey::make_aes256_cbc_hmac_key(),
        );

        let cipher_id: CipherId = "5faa9684-c793-4a2d-8a12-b33900187097".parse().unwrap();

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.ciphers_api.expect_put().returning(move |_id, _body| {
                Err(bitwarden_api_api::apis::Error::Io(std::io::Error::other(
                    "Simulated error",
                )))
            });
        });

        let repository = MemoryRepository::<Cipher>::default();
        repository_add_cipher(&repository, &store, cipher_id, "old_name").await;
        let cipher_view = generate_test_cipher();

        let request = cipher_view.try_into().unwrap();

        let result = edit_cipher(
            &store,
            &api_client,
            &repository,
            TEST_USER_ID.parse().unwrap(),
            request,
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), EditCipherError::Api(_)));
    }

    #[test]
    fn test_password_history_on_password_change() {
        let original_cipher = create_test_login_cipher("old_password");
        let mut edit_request =
            CipherEditRequest::try_from(create_test_login_cipher("new_password")).unwrap();

        let start = Utc::now();
        let history = edit_request.generate_password_history(&original_cipher);
        let end = Utc::now();

        assert_eq!(history.len(), 1);
        assert!(
            history[0].last_used_date > start && history[0].last_used_date < end,
            "last_used_date was not set properly"
        );
        assert_eq!(history[0].password, "old_password");
    }

    #[test]
    fn test_password_history_on_unchanged_password() {
        let original_cipher = create_test_login_cipher("same_password");
        let mut edit_request =
            CipherEditRequest::try_from(create_test_login_cipher("same_password")).unwrap();

        let password_history = edit_request.generate_password_history(&original_cipher);

        assert!(password_history.is_empty());
    }

    #[test]
    fn test_password_history_is_preserved() {
        let mut original_cipher = create_test_login_cipher("same_password");
        original_cipher.password_history = Some(
            (0..4)
                .map(|i| PasswordHistoryView {
                    password: format!("old_password_{}", i),
                    last_used_date: Utc.with_ymd_and_hms(2025, i + 1, i + 1, i, i, i).unwrap(),
                })
                .collect(),
        );

        let mut edit_request =
            CipherEditRequest::try_from(create_test_login_cipher("same_password")).unwrap();

        let history = edit_request.generate_password_history(&original_cipher);

        assert_eq!(history[0].password, "old_password_0");
        assert_eq!(
            history[0].last_used_date,
            Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap()
        );
        assert_eq!(history[1].password, "old_password_1");
        assert_eq!(
            history[1].last_used_date,
            Utc.with_ymd_and_hms(2025, 2, 2, 1, 1, 1).unwrap()
        );
        assert_eq!(history[2].password, "old_password_2");
        assert_eq!(
            history[2].last_used_date,
            Utc.with_ymd_and_hms(2025, 3, 3, 2, 2, 2).unwrap()
        );
        assert_eq!(history[3].password, "old_password_3");
        assert_eq!(
            history[3].last_used_date,
            Utc.with_ymd_and_hms(2025, 4, 4, 3, 3, 3).unwrap()
        );
    }

    #[test]
    fn test_password_history_with_hidden_fields() {
        let mut original_cipher = create_test_login_cipher("password");
        original_cipher.fields = Some(vec![FieldView {
            name: Some("Secret Key".to_string()),
            value: Some("old_secret_value".to_string()),
            r#type: FieldType::Hidden,
            linked_id: None,
        }]);

        let mut new_cipher = create_test_login_cipher("password");
        new_cipher.fields = Some(vec![FieldView {
            name: Some("Secret Key".to_string()),
            value: Some("new_secret_value".to_string()),
            r#type: FieldType::Hidden,
            linked_id: None,
        }]);

        let mut edit_request = CipherEditRequest::try_from(new_cipher).unwrap();

        let history = edit_request.generate_password_history(&original_cipher);

        assert_eq!(history.len(), 1);
        assert_eq!(history[0].password, "Secret Key: old_secret_value");
    }

    #[test]
    fn test_password_history_length_limit() {
        let mut original_cipher = create_test_login_cipher("password");
        original_cipher.password_history = Some(
            (0..10)
                .map(|i| PasswordHistoryView {
                    password: format!("old_password_{}", i),
                    last_used_date: Utc::now(),
                })
                .collect(),
        );

        // Create edit request with new password (no existing history)
        let mut edit_request =
            CipherEditRequest::try_from(create_test_login_cipher("new_password")).unwrap();

        let history = edit_request.generate_password_history(&original_cipher);

        assert_eq!(history.len(), MAX_PASSWORD_HISTORY_ENTRIES);
        // Most recent change (original password) should be first
        assert_eq!(history[0].password, "password");

        assert_eq!(history[1].password, "old_password_0");
        assert_eq!(history[2].password, "old_password_1");
        assert_eq!(history[3].password, "old_password_2");
        assert_eq!(history[4].password, "old_password_3");
    }
}
