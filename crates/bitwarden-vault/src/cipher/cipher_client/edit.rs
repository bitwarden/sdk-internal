use bitwarden_api_api::models::{CipherCollectionsRequestModel, CipherRequestModel};
use bitwarden_collections::collection::CollectionId;
use bitwarden_core::{
    ApiError, MissingFieldError, NotAuthenticatedError, OrganizationId, UserId,
    key_management::KeySlotIds, require,
};
use bitwarden_crypto::{CryptoError, EncString, IdentifyKey, KeyStore};
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
    AttachmentView, Cipher, CipherId, CipherRepromptType, CipherType, CipherView, FieldView,
    FolderId, ItemNotFoundError, VaultParseError,
    cipher::cipher::{PartialCipher, StrictDecrypt},
    cipher_view_type::CipherViewType,
};

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

impl<T> From<bitwarden_api_api::apis::Error<T>> for EditCipherError {
    fn from(val: bitwarden_api_api::apis::Error<T>) -> Self {
        Self::Api(val.into())
    }
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
    pub attachments: Vec<AttachmentView>,
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
            CipherType::BankAccount => value.bank_account.map(CipherViewType::BankAccount),
            CipherType::DriversLicense => value.drivers_license.map(CipherViewType::DriversLicense),
            CipherType::Passport => value.passport.map(CipherViewType::Passport),
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
            attachments: value.attachments.unwrap_or_default(),
            revision_date: value.revision_date,
            archived_date: value.archived_date,
        })
    }
}

/// Internal helper to convert a [`CipherEditRequest`] into a [`CipherView`]
/// so the existing `CipherView` encryption pipeline can be reused.
///
/// This conversion is lossy and intended for use only within the edit flow,
/// as the `CipherView` produced will not have all fields populated (e.g. `collection_ids`).
pub(crate) fn convert_request_to_cipher_view(r: CipherEditRequest) -> CipherView {
    CipherView {
        id: Some(r.id),
        organization_id: r.organization_id,
        folder_id: r.folder_id,
        // `collection_ids` is empty because collections are updated via a separate endpoint.
        collection_ids: vec![],
        key: r.key,
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
        attachments: Some(r.attachments),
        attachment_decryption_failures: None,
        fields: Some(r.fields),
        password_history: None,
        // `creation_date` is overwritten by the server on merge
        creation_date: Utc::now(),
        deleted_date: None,
        revision_date: r.revision_date,
        archived_date: r.archived_date,
    }
}

async fn edit_cipher<R: Repository<Cipher> + ?Sized>(
    key_store: &KeyStore<KeySlotIds>,
    api_client: &bitwarden_api_api::apis::ApiClient,
    repository: &R,
    encrypted_for: UserId,
    request: CipherEditRequest,
    use_strict_decryption: bool,
    enable_cipher_key_encryption: bool,
) -> Result<CipherView, EditCipherError> {
    let cipher_id = request.id;

    let original_cipher = repository.get(cipher_id).await?.ok_or(ItemNotFoundError)?;
    let original_cipher_view: CipherView = if use_strict_decryption {
        key_store.decrypt(&StrictDecrypt(original_cipher.clone()))?
    } else {
        key_store.decrypt(&original_cipher)?
    };

    let mut view: CipherView = convert_request_to_cipher_view(request);
    view.update_password_history(&original_cipher_view);

    // TODO: Once this flag is removed, the key generation logic should be
    // moved directly into the CompositeEncryptable implementation.
    if view.key.is_none() && enable_cipher_key_encryption {
        let key = view.key_identifier();
        view.generate_cipher_key(&mut key_store.context(), key)?;
    }

    let cipher: Cipher = key_store.encrypt(view)?;
    let mut cipher_request: CipherRequestModel = cipher.try_into()?;
    cipher_request.encrypted_for = Some(encrypted_for.into());

    let cipher: Cipher = api_client
        .ciphers_api()
        .put(cipher_id.into(), Some(cipher_request))
        .await
        .map_err(ApiError::from)?
        .merge_with_cipher(Some(original_cipher))?;
    debug_assert!(cipher.id.unwrap_or_default() == cipher_id);
    repository.set(cipher_id, cipher.clone()).await?;

    if use_strict_decryption {
        Ok(key_store.decrypt(&StrictDecrypt(cipher))?)
    } else {
        Ok(key_store.decrypt(&cipher)?)
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CiphersClient {
    /// Edit an existing [Cipher] and save it to the server.
    pub async fn edit(&self, request: CipherEditRequest) -> Result<CipherView, EditCipherError> {
        let key_store = self.client.internal.get_key_store();
        let config = self.client.internal.get_api_configurations();
        let repository = self.get_repository()?;

        let user_id = self
            .client
            .internal
            .get_user_id()
            .ok_or(NotAuthenticatedError)?;

        let enable_cipher_key_encryption = self
            .client
            .internal
            .get_flags()
            .await
            .enable_cipher_key_encryption;

        edit_cipher(
            key_store,
            &config.api_client,
            repository.as_ref(),
            user_id,
            request,
            self.is_strict_decrypt().await,
            enable_cipher_key_encryption,
        )
        .await
    }

    /// Adds the cipher matched by [CipherId] to any number of collections on the server.
    pub async fn update_collection(
        &self,
        cipher_id: CipherId,
        collection_ids: Vec<CollectionId>,
        is_admin: bool,
    ) -> Result<CipherView, EditCipherError> {
        let req = CipherCollectionsRequestModel {
            collection_ids: collection_ids
                .into_iter()
                .map(|id| id.to_string())
                .collect(),
        };
        let repository = self.get_repository()?;

        let api_config = self.client.internal.get_api_configurations();
        let api = api_config.api_client.ciphers_api();
        let orig_cipher = repository.get(cipher_id).await?;
        let cipher = if is_admin {
            api.put_collections_admin(&cipher_id.to_string(), Some(req))
                .await?
                .merge_with_cipher(orig_cipher)?
        } else {
            let response: Cipher = api
                .put_collections(cipher_id.into(), Some(req))
                .await?
                .merge_with_cipher(orig_cipher)?;
            repository.set(cipher_id, response.clone()).await?;
            response
        };

        Ok(self
            .decrypt(cipher)
            .await
            .map_err(|_| CryptoError::KeyDecrypt)?)
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{apis::ApiClient, models::CipherResponseModel};
    use bitwarden_core::key_management::SymmetricKeySlotId;
    use bitwarden_crypto::{KeyStore, PrimitiveEncryptable, SymmetricKeyAlgorithm};
    use bitwarden_test::MemoryRepository;
    use chrono::TimeZone;

    use super::*;
    use crate::{
        Cipher, CipherId, CipherRepromptType, CipherType, FieldType, Login, LoginView,
        PasswordHistoryView, password_history::MAX_PASSWORD_HISTORY_ENTRIES,
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
            bank_account: None,
            passport: None,
            drivers_license: None,
            favorite: false,
            reprompt: CipherRepromptType::None,
            organization_use_totp: true,
            edit: true,
            permissions: None,
            view_password: true,
            local_data: None,
            attachments: None,
            attachment_decryption_failures: None,
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
        store: &KeyStore<KeySlotIds>,
        cipher_id: CipherId,
        name: &str,
    ) {
        let cipher = {
            let mut ctx = store.context();

            Cipher {
                id: Some(cipher_id),
                organization_id: None,
                folder_id: None,
                collection_ids: vec![],
                key: None,
                name: name.encrypt(&mut ctx, SymmetricKeySlotId::User).unwrap(),
                notes: None,
                r#type: CipherType::Login,
                login: Some(Login {
                    username: Some("test@example.com")
                        .map(|u| u.encrypt(&mut ctx, SymmetricKeySlotId::User))
                        .transpose()
                        .unwrap(),
                    password: Some("password123")
                        .map(|p| p.encrypt(&mut ctx, SymmetricKeySlotId::User))
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
                bank_account: None,
                drivers_license: None,
                passport: None,
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
                data: None,
            }
        };

        repository.set(cipher_id, cipher).await.unwrap();
    }

    #[tokio::test]
    async fn test_edit_cipher() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        {
            let mut ctx = store.context_mut();
            let local_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            ctx.persist_symmetric_key(local_key_id, SymmetricKeySlotId::User)
                .unwrap();
        }

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

        let collection_id: CollectionId = "a4e13cc0-1234-5678-abcd-b181009709b8".parse().unwrap();

        let repository = MemoryRepository::<Cipher>::default();
        repository_add_cipher(&repository, &store, cipher_id, "old_name").await;
        // Update the stored cipher to include a collection_id so we can verify it is preserved.
        let mut stored = repository.get(cipher_id).await.unwrap().unwrap();
        stored.collection_ids = vec![collection_id];
        repository.set(cipher_id, stored).await.unwrap();

        let cipher_view = generate_test_cipher();

        let request = cipher_view.try_into().unwrap();

        let result = edit_cipher(
            &store,
            &api_client,
            &repository,
            TEST_USER_ID.parse().unwrap(),
            request,
            false,
            false,
        )
        .await
        .unwrap();

        assert_eq!(result.id, Some(cipher_id));
        assert_eq!(result.name, "Test Login");
        // collection_ids must be preserved even though CipherResponseModel omits them.
        assert_eq!(result.collection_ids, vec![collection_id]);
    }

    #[tokio::test]
    async fn test_edit_cipher_does_not_exist() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();

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
            false,
            false,
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
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        {
            let mut ctx = store.context_mut();
            let local_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            ctx.persist_symmetric_key(local_key_id, SymmetricKeySlotId::User)
                .unwrap();
        }

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
            false,
            false,
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), EditCipherError::Api(_)));
    }

    /// Build the edit-side view the way the flow does: request → view, then
    /// fold in password history against the decrypted original.
    fn edit_view_with_history(new_cipher: CipherView, original: &CipherView) -> CipherView {
        let mut view: CipherView =
            convert_request_to_cipher_view(CipherEditRequest::try_from(new_cipher).unwrap());
        view.update_password_history(original);
        view
    }

    #[test]
    fn test_password_history_on_password_change() {
        let original_cipher = create_test_login_cipher("old_password");

        let start = Utc::now();
        let view =
            edit_view_with_history(create_test_login_cipher("new_password"), &original_cipher);
        let end = Utc::now();
        let history = view.password_history.unwrap_or_default();

        assert_eq!(history.len(), 1);
        assert!(
            history[0].last_used_date >= start && history[0].last_used_date <= end,
            "last_used_date was not set properly"
        );
        assert_eq!(history[0].password, "old_password");
    }

    #[test]
    fn test_password_history_on_unchanged_password() {
        let original_cipher = create_test_login_cipher("same_password");
        let view =
            edit_view_with_history(create_test_login_cipher("same_password"), &original_cipher);

        assert!(view.password_history.unwrap_or_default().is_empty());
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

        let view =
            edit_view_with_history(create_test_login_cipher("same_password"), &original_cipher);
        let history = view.password_history.unwrap_or_default();

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

        let view = edit_view_with_history(new_cipher, &original_cipher);
        let history = view.password_history.unwrap_or_default();

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

        let view =
            edit_view_with_history(create_test_login_cipher("new_password"), &original_cipher);
        let history = view.password_history.unwrap_or_default();

        assert_eq!(history.len(), MAX_PASSWORD_HISTORY_ENTRIES);
        // Most recent change (original password) should be first
        assert_eq!(history[0].password, "password");

        assert_eq!(history[1].password, "old_password_0");
        assert_eq!(history[2].password, "old_password_1");
        assert_eq!(history[3].password, "old_password_2");
        assert_eq!(history[4].password, "old_password_3");
    }
}
