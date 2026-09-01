use bitwarden_api_api::models::{
    CipherCollectionsRequestModel, CipherPartialRequestModel, CipherRequestModel,
};
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
    cipher::cipher::{EncryptMode, PartialCipher, StrictDecrypt},
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
    /// The stored cipher is PAM-gated, so local state holds only its partial copy and an edit
    /// built on it would drop the item's password history and mis-stamp its revision date.
    #[error(
        "Cannot edit a PAM-gated cipher from local state; use `edit_gated` with a full original \
         obtained under an active lease"
    )]
    GatedCipher,
    /// `edit_gated` was handed a partial view as the original.
    #[error("Editing a PAM-gated cipher requires a full original; the supplied view is partial")]
    PartialOriginal,
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

/// Request to update the subset of cipher fields that a user without edit
/// permissions is still allowed to change (`folder_id` and `favorite`).
///
/// Backed by the `PUT /ciphers/{id}/partial` server endpoint, which authorizes
/// based on view (not edit) access.
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct CipherPartialEditRequest {
    pub id: CipherId,
    pub folder_id: Option<FolderId>,
    pub favorite: bool,
}

/// Internal helper to convert a [`CipherEditRequest`] into a [`CipherView`]
/// so the existing `CipherView` encryption pipeline can be reused.
///
/// This conversion is lossy and intended for use only within the edit flow,
/// as the `CipherView` produced will not have all fields populated (e.g. `collection_ids`).
pub(crate) fn convert_request_to_cipher_view(r: CipherEditRequest) -> CipherView {
    CipherView {
        partial: false,
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

// `use_strict_decryption`, `enable_cipher_key_encryption`, and `use_blob` are
// short-lived feature-rollout flags that will be removed once their migrations
// complete, at which point the argument count drops back under the limit.
#[allow(clippy::too_many_arguments)]
async fn edit_cipher<R: Repository<Cipher> + ?Sized>(
    key_store: &KeyStore<KeySlotIds>,
    api_client: &bitwarden_api_api::apis::ApiClient,
    repository: &R,
    encrypted_for: UserId,
    request: CipherEditRequest,
    use_strict_decryption: bool,
    enable_cipher_key_encryption: bool,
    use_blob: bool,
) -> Result<CipherView, EditCipherError> {
    let cipher_id = request.id;

    let original_cipher = repository.get(cipher_id).await?.ok_or(ItemNotFoundError)?;

    // A PAM-gated cipher is only ever stored partial — the server withholds its secrets from
    // every bulk read and from write-returns alike — so the original below would carry blanks
    // where the withheld fields belong. `update_password_history` would then drop the item's
    // whole history (a partial view has none to chain) and stamp a fresh `password_revision_date`,
    // and the PUT would persist both. Refuse rather than corrupt; `edit_gated` takes the full
    // original from a lease-authorised read.
    if original_cipher.partial_data.is_some() {
        return Err(EditCipherError::GatedCipher);
    }

    let original_cipher_view: CipherView = if use_strict_decryption {
        key_store.decrypt(&StrictDecrypt(original_cipher.clone()))?
    } else {
        key_store.decrypt(&original_cipher)?
    };

    submit_cipher_edit(
        key_store,
        api_client,
        repository,
        encrypted_for,
        request,
        &original_cipher_view,
        original_cipher,
        use_strict_decryption,
        enable_cipher_key_encryption,
        use_blob,
    )
    .await
}

/// The body both edit paths share: request → view, fold in password history against
/// `original_cipher_view`, encrypt, PUT, and merge the write-return over `stored_cipher` before
/// persisting it.
///
/// The paths differ only in where the original comes from — local state for [`edit_cipher`], the
/// caller for [`edit_gated_cipher`], because a gated cipher has no full copy in state — so that is
/// all either one is left holding.
// `use_strict_decryption`, `enable_cipher_key_encryption`, and `use_blob` are
// short-lived feature-rollout flags that will be removed once their migrations
// complete, at which point the argument count drops back under the limit.
#[allow(clippy::too_many_arguments)]
async fn submit_cipher_edit<R: Repository<Cipher> + ?Sized>(
    key_store: &KeyStore<KeySlotIds>,
    api_client: &bitwarden_api_api::apis::ApiClient,
    repository: &R,
    encrypted_for: UserId,
    request: CipherEditRequest,
    original_cipher_view: &CipherView,
    stored_cipher: Cipher,
    use_strict_decryption: bool,
    enable_cipher_key_encryption: bool,
    use_blob: bool,
) -> Result<CipherView, EditCipherError> {
    let cipher_id = request.id;
    let stored_gated = stored_cipher.partial_data.is_some();

    let mut view: CipherView = convert_request_to_cipher_view(request);
    view.update_password_history(original_cipher_view);

    // TODO: Once this flag is removed, the key generation logic should be
    // moved directly into the CompositeEncryptable implementation.
    if view.key.is_none() && enable_cipher_key_encryption {
        let key = view.key_identifier();
        view.upgrade_to_cipher_key_encryption(&mut key_store.context(), key)?;
    }

    let encrypted_by_key_id = key_store
        .context()
        .get_symmetric_key_id(view.key_identifier())
        .map(|id| id.to_string());

    let mode = if use_blob {
        EncryptMode::Blob(view)
    } else {
        EncryptMode::Legacy(view)
    };

    let cipher: Cipher = key_store.encrypt(mode)?;
    let mut cipher_request: CipherRequestModel = cipher.try_into()?;
    cipher_request.encrypted_for = Some(encrypted_for.into());
    cipher_request.encrypted_by_key_id = encrypted_by_key_id;

    let cipher: Cipher = api_client
        .ciphers_api()
        .put(cipher_id.into(), Some(cipher_request))
        .await?
        .merge_with_cipher(Some(stored_cipher))?;
    debug_assert!(cipher.id.unwrap_or_default() == cipher_id);

    // Never let a write-return un-gate the stored copy. The server withholds secrets from a gated
    // write-return, so a full response here should be impossible — but persisting one would put
    // lease-scoped secrets into durable state, outliving the lease that justified them. Skip the
    // write and let the next sync reconcile: the server already applied the change, so reporting
    // a failure would be the worse lie.
    //
    // A no-op for [`edit_cipher`], which refuses a gated cipher outright, so nothing it stores is
    // ever gated to begin with.
    if !stored_gated || cipher.partial_data.is_some() {
        repository.set(cipher_id, cipher.clone()).await?;
    }

    Ok(if use_strict_decryption {
        key_store.decrypt(&StrictDecrypt(cipher))?
    } else {
        key_store.decrypt(&cipher)?
    })
}

/// Edit a PAM-gated cipher against a full original supplied by the caller.
///
/// [`edit_cipher`] reads its original out of the repository, which for a gated cipher only ever
/// holds the partial copy. This path takes the full view the caller obtained from a
/// lease-authorised single-cipher read instead, so password history carries forward correctly.
/// It mirrors the admin edit path, which takes its original as an argument for the same reason:
/// no usable copy exists in local state.
// `use_strict_decryption`, `enable_cipher_key_encryption`, and `use_blob` are
// short-lived feature-rollout flags that will be removed once their migrations
// complete, at which point the argument count drops back under the limit.
#[allow(clippy::too_many_arguments)]
async fn edit_gated_cipher<R: Repository<Cipher> + ?Sized>(
    key_store: &KeyStore<KeySlotIds>,
    api_client: &bitwarden_api_api::apis::ApiClient,
    repository: &R,
    encrypted_for: UserId,
    request: CipherEditRequest,
    original_cipher_view: CipherView,
    use_strict_decryption: bool,
    enable_cipher_key_encryption: bool,
    use_blob: bool,
) -> Result<CipherView, EditCipherError> {
    let cipher_id = request.id;

    // The point of this path is the full original. A partial one lands us back in exactly the
    // case `edit_cipher` refuses, only with the blanks handed in by the caller.
    if original_cipher_view.partial {
        return Err(EditCipherError::PartialOriginal);
    }

    // Read for `local_data`, which the response model does not carry, and for the gating the
    // shared body checks before it persists the write-return.
    let stored_cipher = repository.get(cipher_id).await?.ok_or(ItemNotFoundError)?;

    submit_cipher_edit(
        key_store,
        api_client,
        repository,
        encrypted_for,
        request,
        &original_cipher_view,
        stored_cipher,
        use_strict_decryption,
        enable_cipher_key_encryption,
        use_blob,
    )
    .await
}

/// Update only the cipher fields available to users without edit permissions
/// (`folder_id` and `favorite`) via the server's partial-update endpoint.
async fn partial_edit_cipher<R: Repository<Cipher> + ?Sized>(
    key_store: &KeyStore<KeySlotIds>,
    api_client: &bitwarden_api_api::apis::ApiClient,
    repository: &R,
    request: CipherPartialEditRequest,
    use_strict_decryption: bool,
) -> Result<CipherView, EditCipherError> {
    let cipher_id = request.id;

    let original_cipher = repository.get(cipher_id).await?.ok_or(ItemNotFoundError)?;

    let partial_request = CipherPartialRequestModel {
        folder_id: request.folder_id.map(|id| id.to_string()),
        favorite: Some(request.favorite),
    };

    let cipher: Cipher = api_client
        .ciphers_api()
        .put_partial(cipher_id.into(), Some(partial_request))
        .await?
        .merge_with_cipher(Some(original_cipher))?;
    debug_assert!(cipher.id.unwrap_or_default() == cipher_id);
    repository.set(cipher_id, cipher.clone()).await?;

    Ok(if use_strict_decryption {
        key_store.decrypt(&StrictDecrypt(cipher))?
    } else {
        key_store.decrypt(&cipher)?
    })
}

#[allow(deprecated)]
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

        let enable_cipher_key_encryption =
            self.client.flags().get().await.enable_cipher_key_encryption;

        let use_blob = self.should_use_blob_encryption(request.organization_id);

        edit_cipher(
            key_store,
            &config.api_client,
            repository.as_ref(),
            user_id,
            request,
            self.is_strict_decrypt().await,
            enable_cipher_key_encryption,
            use_blob,
        )
        .await
    }

    /// Edit a PAM-gated [`Cipher`] whose secrets were revealed under an active lease.
    ///
    /// [`CiphersClient::edit`] builds its original from local state, which for a gated cipher only
    /// ever holds the partial copy, and so refuses. Pass the full view obtained from the
    /// lease-authorised read as `original_cipher_view` — it is what password history is diffed
    /// against.
    ///
    /// The returned view reflects what was persisted, so it is partial: the server withholds
    /// secrets from a gated write-return. The caller keeps its own full copy in memory.
    pub async fn edit_gated(
        &self,
        request: CipherEditRequest,
        original_cipher_view: CipherView,
    ) -> Result<CipherView, EditCipherError> {
        let key_store = self.client.internal.get_key_store();
        let config = self.client.internal.get_api_configurations();
        let repository = self.get_repository()?;

        let user_id = self
            .client
            .internal
            .get_user_id()
            .ok_or(NotAuthenticatedError)?;

        let enable_cipher_key_encryption =
            self.client.flags().get().await.enable_cipher_key_encryption;

        let use_blob = self.should_use_blob_encryption(request.organization_id);

        edit_gated_cipher(
            key_store,
            &config.api_client,
            repository.as_ref(),
            user_id,
            request,
            original_cipher_view,
            self.is_strict_decrypt().await,
            enable_cipher_key_encryption,
            use_blob,
        )
        .await
    }

    /// Update only `folder_id` and `favorite` on an existing [Cipher].
    ///
    /// Intended for users who do not have edit permissions on the cipher, but
    /// are still allowed to change these personal organization fields.
    pub async fn edit_partial(
        &self,
        request: CipherPartialEditRequest,
    ) -> Result<CipherView, EditCipherError> {
        let key_store = self.client.internal.get_key_store();
        let config = self.client.internal.get_api_configurations();
        let repository = self.get_repository()?;

        partial_edit_cipher(
            key_store,
            &config.api_client,
            repository.as_ref(),
            request,
            self.is_strict_decrypt().await,
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
            let cipher_response = api
                .put_collections_v_next(cipher_id.into(), Some(req))
                .await?
                .cipher
                .map(|c| *c)
                .ok_or(MissingFieldError("cipher"))?;
            let response: Cipher = cipher_response.merge_with_cipher(orig_cipher)?;
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
    use bitwarden_core::key_management::{
        SymmetricKeySlotId, create_test_crypto_with_user_and_org_key,
    };
    use bitwarden_crypto::{
        KeyStore, PrimitiveEncryptable, SymmetricCryptoKey, SymmetricKeyAlgorithm,
    };
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
            partial: false,
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
                partial_data: None,
                id: Some(cipher_id),
                organization_id: None,
                folder_id: None,
                collection_ids: vec![],
                key: None,
                name: Some(name.encrypt(&mut ctx, SymmetricKeySlotId::User).unwrap()),
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
                        name: body.name,
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
                        partial_data: None,
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
            false,
        )
        .await
        .unwrap();

        assert_eq!(result.id, Some(cipher_id));
        assert_eq!(result.name, "Test Login");
        // collection_ids must be preserved even though CipherResponseModel omits them.
        assert_eq!(result.collection_ids, vec![collection_id]);
    }

    /// Fixed org id + key for the PAM-gated fixtures — a partial is always org-owned — with a
    /// `partial_data` envelope encrypted under that key. Same vectors as the ones pinned in
    /// `cipher.rs`, so both sides exercise identical ciphertext.
    const GATED_ORG_UUID: &str = "3cf0d3ba-3ded-4bf3-a51c-b03fd9ac6e07";
    const GATED_ORG_KEY_B64: &str =
        "w2LO+nwV4oxwswVYCxlOfRUseXfvU03VzvKQHrqeklPgiMZrspUe6sOBToCnDn9Ay0tuCBn8ykVVRb7PWhub2Q==";
    const GATED_LOGIN_ENVELOPE: &str = r#"{"name":"2.qip4DSwdOzU2KwY3jgDjUg==|CsGRQgTwAzmszz+dkk5xIg==|rmW/mlnHq2MulR9uNKclD+1UBFLfOimedkq5tPRSLOc=","uris":[{"uri":"2.2na8mpfA1B1OBTUHkDz+fw==|yTWB1nEf3EHIZgsDINM8JnTYyxf7KVZvXraIGAVOiEg=|i2swsODSjEMRaYNnBHAigdphZBBUg2lkPNo763fX12w=","uriChecksum":null,"match":null}]}"#;

    fn gated_key_store() -> (OrganizationId, KeyStore<KeySlotIds>) {
        let org: OrganizationId = GATED_ORG_UUID.parse().unwrap();
        let org_key: SymmetricCryptoKey = GATED_ORG_KEY_B64.to_string().try_into().unwrap();
        let key_store = create_test_crypto_with_user_and_org_key(
            SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
            org,
            org_key,
        );
        (org, key_store)
    }

    /// The copy local state holds for a gated cipher: the reduced envelope and nothing else.
    fn gated_stored_cipher(cipher_id: CipherId, organization_id: OrganizationId) -> Cipher {
        Cipher {
            partial_data: Some(GATED_LOGIN_ENVELOPE.to_string()),
            id: Some(cipher_id),
            organization_id: Some(organization_id),
            folder_id: None,
            collection_ids: vec![],
            key: None,
            name: None,
            notes: None,
            r#type: CipherType::Login,
            login: None,
            identity: None,
            card: None,
            secure_note: None,
            ssh_key: None,
            bank_account: None,
            drivers_license: None,
            passport: None,
            favorite: false,
            reprompt: CipherRepromptType::None,
            organization_use_totp: false,
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
    }

    /// The full original a caller obtains from a lease-authorised read: one prior history entry
    /// and the password this edit replaces.
    fn gated_original_view(organization_id: OrganizationId) -> CipherView {
        let mut view = create_test_login_cipher("old_password");
        view.organization_id = Some(organization_id);
        view.password_history = Some(vec![PasswordHistoryView {
            password: "older_password".to_string(),
            last_used_date: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
        }]);
        view
    }

    /// The regular edit path builds its original from local state, which for a gated cipher only
    /// ever holds the partial copy. Editing on that would blank every withheld field and drop the
    /// item's password history, so it must refuse — before it reaches the server.
    #[tokio::test]
    async fn test_edit_refuses_a_gated_stored_cipher() {
        let (org, store) = gated_key_store();
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();

        // Deliberately no `expect_put`: the guard has to fire before any request is built.
        let api_client = ApiClient::new_mocked(|_mock| {});

        let repository = MemoryRepository::<Cipher>::default();
        repository
            .set(cipher_id, gated_stored_cipher(cipher_id, org))
            .await
            .unwrap();

        let mut cipher_view = generate_test_cipher();
        cipher_view.organization_id = Some(org);

        let result = edit_cipher(
            &store,
            &api_client,
            &repository,
            TEST_USER_ID.parse().unwrap(),
            cipher_view.try_into().unwrap(),
            false,
            false,
            false,
        )
        .await;

        assert!(matches!(result, Err(EditCipherError::GatedCipher)));
    }

    /// Handing the gated path the partial view the caller already had puts us back in exactly the
    /// case the regular path refuses, with the blanks supplied by the caller instead of by state.
    #[tokio::test]
    async fn test_edit_gated_refuses_a_partial_original() {
        let (org, store) = gated_key_store();
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let api_client = ApiClient::new_mocked(|_mock| {});

        let repository = MemoryRepository::<Cipher>::default();
        repository
            .set(cipher_id, gated_stored_cipher(cipher_id, org))
            .await
            .unwrap();

        let mut cipher_view = generate_test_cipher();
        cipher_view.organization_id = Some(org);
        let mut original = cipher_view.clone();
        original.partial = true;

        let result = edit_gated_cipher(
            &store,
            &api_client,
            &repository,
            TEST_USER_ID.parse().unwrap(),
            cipher_view.try_into().unwrap(),
            original,
            false,
            false,
            false,
        )
        .await;

        assert!(matches!(result, Err(EditCipherError::PartialOriginal)));
    }

    /// The whole reason this path exists: password history is diffed against the caller's full
    /// original, not against the partial copy in state. The partial has no history at all, so a
    /// wrong original shows up as a short array in the request body.
    #[tokio::test]
    async fn test_edit_gated_carries_history_from_the_supplied_original() {
        let (org, store) = gated_key_store();
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.ciphers_api
                .expect_put()
                .returning(move |_id, body| {
                    let body = body.unwrap();
                    // The original's one prior entry, plus the entry for the password this edit
                    // replaces. Building on the partial copy would have sent none of either.
                    assert_eq!(body.password_history.as_ref().map(|h| h.len()), Some(2));
                    Ok(gated_response_model(cipher_id, org, body.r#type))
                })
                .once();
        });

        let repository = MemoryRepository::<Cipher>::default();
        repository
            .set(cipher_id, gated_stored_cipher(cipher_id, org))
            .await
            .unwrap();

        let mut cipher_view = create_test_login_cipher("new_password");
        cipher_view.organization_id = Some(org);

        let result = edit_gated_cipher(
            &store,
            &api_client,
            &repository,
            TEST_USER_ID.parse().unwrap(),
            cipher_view.try_into().unwrap(),
            gated_original_view(org),
            false,
            false,
            false,
        )
        .await
        .unwrap();

        // The server withholds secrets from a gated write-return, so what comes back — and what
        // is persisted — is still the reduced shape.
        assert!(result.partial);
        let stored = repository.get(cipher_id).await.unwrap().unwrap();
        assert!(stored.partial_data.is_some());
    }

    /// Defence in depth for the durable-state property: the server strips a gated write-return, so
    /// a full one should be unreachable — but were it ever to arrive, persisting it would put
    /// lease-scoped secrets on disk, outliving the lease that justified them.
    #[tokio::test]
    async fn test_edit_gated_does_not_persist_a_full_write_return() {
        let (org, store) = gated_key_store();
        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.ciphers_api
                .expect_put()
                .returning(move |_id, body| {
                    let body = body.unwrap();
                    // A server that has not been taught to strip write-returns.
                    Ok(CipherResponseModel {
                        partial_data: None,
                        name: body.name,
                        login: body.login,
                        ..gated_response_model(cipher_id, org, body.r#type)
                    })
                })
                .once();
        });

        let repository = MemoryRepository::<Cipher>::default();
        repository
            .set(cipher_id, gated_stored_cipher(cipher_id, org))
            .await
            .unwrap();

        let mut cipher_view = create_test_login_cipher("new_password");
        cipher_view.organization_id = Some(org);

        let result = edit_gated_cipher(
            &store,
            &api_client,
            &repository,
            TEST_USER_ID.parse().unwrap(),
            cipher_view.try_into().unwrap(),
            gated_original_view(org),
            false,
            false,
            false,
        )
        .await
        .unwrap();

        // The caller still gets the full view in memory — it is the write to disk that is refused.
        assert!(!result.partial);
        let stored = repository.get(cipher_id).await.unwrap().unwrap();
        assert!(stored.partial_data.is_some(), "local state must stay gated");
        assert!(
            stored.login.is_none(),
            "no secret field may reach local state"
        );
    }

    /// A gated write-return: metadata and the reduced envelope, every secret field withheld.
    fn gated_response_model(
        cipher_id: CipherId,
        organization_id: OrganizationId,
        r#type: Option<bitwarden_api_api::models::CipherType>,
    ) -> CipherResponseModel {
        CipherResponseModel {
            object: Some("cipher".to_string()),
            id: Some(cipher_id.into()),
            organization_id: Some(organization_id.into()),
            r#type,
            partial_data: Some(GATED_LOGIN_ENVELOPE.to_string()),
            name: None,
            notes: None,
            login: None,
            card: None,
            identity: None,
            secure_note: None,
            ssh_key: None,
            bank_account: None,
            drivers_license: None,
            passport: None,
            fields: None,
            password_history: None,
            attachments: None,
            permissions: None,
            data: None,
            folder_id: None,
            favorite: Some(false),
            reprompt: None,
            key: None,
            view_password: Some(true),
            edit: Some(true),
            organization_use_totp: Some(false),
            revision_date: Some("2025-01-01T00:00:00Z".to_string()),
            creation_date: Some("2025-01-01T00:00:00Z".to_string()),
            deleted_date: None,
            archived_date: None,
        }
    }

    #[tokio::test]
    async fn test_edit_partial_cipher() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        {
            let mut ctx = store.context_mut();
            let local_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            ctx.persist_symmetric_key(local_key_id, SymmetricKeySlotId::User)
                .unwrap();
        }

        let cipher_id: CipherId = TEST_CIPHER_ID.parse().unwrap();
        let new_folder_id: FolderId = "9b1e7c8f-3a04-4d2e-9d1e-b18100abcdef".parse().unwrap();

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.ciphers_api
                .expect_put_partial()
                .returning(move |id, body| {
                    let body = body.unwrap();
                    let expected_id: uuid::Uuid = cipher_id.into();
                    assert_eq!(id, expected_id);
                    assert_eq!(body.favorite, Some(true));
                    assert_eq!(
                        body.folder_id.as_deref(),
                        Some(new_folder_id.to_string().as_str())
                    );
                    Ok(CipherResponseModel {
                        object: Some("cipher".to_string()),
                        id: Some(cipher_id.into()),
                        name: Some(
                            "2.+oPT8B4xJhyhQRe1VkIx0A==|PBtC/bZkggXR+fSnL/pG7g==|UkjRD0VpnUYkjRC/05ZLdEBAmRbr3qWRyJey2bUvR9w=".to_string(),
                        ),
                        r#type: Some(bitwarden_api_api::models::CipherType::Login),
                        organization_id: None,
                        folder_id: Some(new_folder_id.into()),
                        favorite: Some(true),
                        reprompt: Some(bitwarden_api_api::models::CipherRepromptType::None),
                        key: None,
                        notes: None,
                        view_password: Some(true),
                        edit: Some(false),
                        organization_use_totp: Some(true),
                        revision_date: Some("2025-01-02T00:00:00Z".to_string()),
                        creation_date: Some("2024-01-01T00:00:00Z".to_string()),
                        deleted_date: None,
                        login: None,
                        card: None,
                        identity: None,
                        secure_note: None,
                        ssh_key: None,
                        bank_account: None,
                        drivers_license: None,
                        passport: None,
                        fields: None,
                        password_history: None,
                        attachments: None,
                        permissions: None,
                        data: None,
                        partial_data: None,
                        archived_date: None,
                    })
                })
                .once();
        });

        let collection_id: CollectionId = "a4e13cc0-1234-5678-abcd-b181009709b8".parse().unwrap();

        let repository = MemoryRepository::<Cipher>::default();
        repository_add_cipher(&repository, &store, cipher_id, "stored_name").await;
        // Stamp a collection id to verify it is preserved across partial edit.
        let mut stored = repository.get(cipher_id).await.unwrap().unwrap();
        stored.collection_ids = vec![collection_id];
        repository.set(cipher_id, stored).await.unwrap();

        let request = CipherPartialEditRequest {
            id: cipher_id,
            folder_id: Some(new_folder_id),
            favorite: true,
        };

        let result = partial_edit_cipher(&store, &api_client, &repository, request, false)
            .await
            .unwrap();

        assert_eq!(result.id, Some(cipher_id));
        assert_eq!(result.folder_id, Some(new_folder_id));
        assert!(result.favorite);
        // Partial endpoint omits collection_ids; they must be preserved from the original.
        assert_eq!(result.collection_ids, vec![collection_id]);
    }

    #[tokio::test]
    async fn test_edit_partial_cipher_does_not_exist() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();

        let repository = MemoryRepository::<Cipher>::default();
        let api_client = ApiClient::new_mocked(|_| {});

        let request = CipherPartialEditRequest {
            id: TEST_CIPHER_ID.parse().unwrap(),
            folder_id: None,
            favorite: false,
        };

        let result = partial_edit_cipher(&store, &api_client, &repository, request, false).await;

        assert!(matches!(
            result.unwrap_err(),
            EditCipherError::ItemNotFound(_)
        ));
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
            mock.ciphers_api
                .expect_put()
                .returning(move |_id, _body| Err(std::io::Error::other("Simulated error").into()));
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

    mod blob_encrypt {
        use bitwarden_core::key_management::create_test_crypto_with_user_key;
        use bitwarden_crypto::SymmetricCryptoKey;

        use super::*;
        use crate::cipher::blob::try_parse_blob;

        /// `EncryptMode::Blob(CipherView)` clears `password_history` from the
        /// wire-shaped `Cipher` — history must travel inside the sealed blob,
        /// not as a top-level encrypted field.
        #[test]
        fn password_history_lives_inside_blob_not_on_wire() {
            let store = create_test_crypto_with_user_key(SymmetricCryptoKey::make(
                SymmetricKeyAlgorithm::Aes256CbcHmac,
            ));

            let original = create_test_login_cipher("old_password");
            let mut view = create_test_login_cipher("new_password");
            view.update_password_history(&original);
            // Sanity: the in-flight view captured the old password.
            assert_eq!(view.password_history.as_ref().unwrap().len(), 1);

            let cipher: Cipher = store.encrypt(EncryptMode::Blob(view)).unwrap();

            assert!(try_parse_blob(&cipher).is_some());
            assert!(
                cipher.password_history.is_none(),
                "password history must live inside the blob, not on the wire",
            );
            assert!(cipher.login.is_none());
            assert!(cipher.notes.is_none());
        }

        /// End-to-end: a password change picked up by `update_password_history`
        /// is sealed inside the blob and unsealed back out by
        /// `BlobAwareDecrypt`.
        #[test]
        fn password_history_round_trips_through_the_blob() {
            let store = create_test_crypto_with_user_key(SymmetricCryptoKey::make(
                SymmetricKeyAlgorithm::Aes256CbcHmac,
            ));

            let original = create_test_login_cipher("old_password");
            let mut view = create_test_login_cipher("new_password");
            view.update_password_history(&original);

            let cipher: Cipher = store.encrypt(EncryptMode::Blob(view)).unwrap();
            let restored: CipherView = store.decrypt(&cipher).unwrap();

            let history = restored
                .password_history
                .expect("history should round-trip through the blob");
            assert_eq!(history.len(), 1);
            assert_eq!(history[0].password, "old_password");
        }
    }
}
