//! [`CiphersClient`] operations that take and return the fully decrypted [`CipherViewV2`] model.
//!
//! Each `_v2` method converts its input to the [`CipherView`] model, runs the operation of the same
//! name without the suffix, and converts the result back.

use bitwarden_collections::collection::CollectionId;
use bitwarden_core::{
    OrganizationId,
    key_management::{KeySlotIds, SymmetricKeySlotId},
};
use bitwarden_crypto::{CryptoError, KeyStoreContext, SymmetricCryptoKey};
#[cfg(feature = "wasm")]
use bitwarden_encoding::B64;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use super::{
    CiphersClient,
    create::{CipherCreateRequest, CreateCipherError},
    edit::{CipherEditRequest, CipherPartialEditRequest, EditCipherError},
    get::GetCipherError,
    restore::RestoreCipherError,
};
#[cfg(feature = "wasm")]
use crate::Fido2CredentialFullView;
use crate::{
    AttachmentViewV2, BankAccountView, CardView, Cipher, CipherError, CipherId, CipherListViewV2,
    CipherRepromptType, CipherViewType, CipherViewV2, DecryptCipherListResultV2,
    DriversLicenseView, EncryptionContext, FieldView, FolderId, IdentityView, LoginViewV2,
    PassportView, SecureNoteView, SshKeyView,
    cipher::cipher_view_v2::{DecryptedCipher, view_to_v1, view_to_v2},
};

/// The type-specific data of a [`CipherCreateRequestV2`] or [`CipherEditRequestV2`].
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[allow(missing_docs, clippy::large_enum_variant)]
pub enum CipherViewTypeV2 {
    Login(LoginViewV2),
    Card(CardView),
    Identity(IdentityView),
    SecureNote(SecureNoteView),
    SshKey(SshKeyView),
    BankAccount(BankAccountView),
    Passport(PassportView),
    DriversLicense(DriversLicenseView),
}

impl CipherViewTypeV2 {
    fn to_v1(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        cipher_key: SymmetricKeySlotId,
    ) -> Result<CipherViewType, CryptoError> {
        Ok(match self {
            Self::Login(l) => CipherViewType::Login(l.to_v1(ctx, cipher_key)?),
            Self::Card(c) => CipherViewType::Card(c.clone()),
            Self::Identity(i) => CipherViewType::Identity(i.clone()),
            Self::SecureNote(s) => CipherViewType::SecureNote(s.clone()),
            Self::SshKey(s) => CipherViewType::SshKey(s.clone()),
            Self::BankAccount(b) => CipherViewType::BankAccount(b.clone()),
            Self::Passport(p) => CipherViewType::Passport(p.clone()),
            Self::DriversLicense(d) => CipherViewType::DriversLicense(d.clone()),
        })
    }
}

fn wrapping_key(organization_id: Option<OrganizationId>) -> SymmetricKeySlotId {
    match organization_id {
        Some(id) => SymmetricKeySlotId::Organization(id),
        None => SymmetricKeySlotId::User,
    }
}

/// Request to add a cipher, with fully decrypted type data. See [`CipherCreateRequest`].
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[allow(missing_docs)]
pub struct CipherCreateRequestV2 {
    pub organization_id: Option<OrganizationId>,
    pub collection_ids: Vec<CollectionId>,
    pub folder_id: Option<FolderId>,
    pub name: String,
    pub notes: Option<String>,
    pub favorite: bool,
    pub reprompt: CipherRepromptType,
    pub r#type: CipherViewTypeV2,
    pub fields: Vec<FieldView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archived_date: Option<DateTime<Utc>>,
}

impl CipherCreateRequestV2 {
    /// A new cipher has no cipher key yet, so its FIDO2 credentials are encrypted under the user
    /// or organization key.
    pub(crate) fn into_v1(
        self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
    ) -> Result<CipherCreateRequest, CryptoError> {
        Ok(CipherCreateRequest {
            r#type: self.r#type.to_v1(ctx, wrapping_key(self.organization_id))?,
            organization_id: self.organization_id,
            collection_ids: self.collection_ids,
            folder_id: self.folder_id,
            name: self.name,
            notes: self.notes,
            favorite: self.favorite,
            reprompt: self.reprompt,
            fields: self.fields,
            archived_date: self.archived_date,
        })
    }
}

/// Request to edit a cipher, with fully decrypted type data, attachments and cipher key. See
/// [`CipherEditRequest`].
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[allow(missing_docs)]
pub struct CipherEditRequestV2 {
    pub id: CipherId,

    pub organization_id: Option<OrganizationId>,
    pub folder_id: Option<FolderId>,
    pub favorite: bool,
    pub reprompt: CipherRepromptType,
    pub name: String,
    pub notes: Option<String>,
    pub fields: Vec<FieldView>,
    pub r#type: CipherViewTypeV2,
    pub revision_date: DateTime<Utc>,
    pub archived_date: Option<DateTime<Utc>>,
    pub attachments: Vec<AttachmentViewV2>,
    #[cfg_attr(feature = "wasm", tsify(type = "SymmetricKey | undefined"))]
    pub key: Option<SymmetricCryptoKey>,
}

impl CipherEditRequestV2 {
    pub(crate) fn into_v1(
        self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
    ) -> Result<CipherEditRequest, CryptoError> {
        let wrapping_key = wrapping_key(self.organization_id);
        let (key, cipher_key) = match &self.key {
            Some(k) => {
                let slot = ctx.add_local_symmetric_key(k.clone());
                (Some(ctx.wrap_symmetric_key(wrapping_key, slot)?), slot)
            }
            None => (None, wrapping_key),
        };
        Ok(CipherEditRequest {
            r#type: self.r#type.to_v1(ctx, cipher_key)?,
            attachments: self
                .attachments
                .iter()
                .map(|a| a.to_v1(ctx, cipher_key))
                .collect::<Result<_, _>>()?,
            key,
            id: self.id,
            organization_id: self.organization_id,
            folder_id: self.folder_id,
            favorite: self.favorite,
            reprompt: self.reprompt,
            name: self.name,
            notes: self.notes,
            fields: self.fields,
            revision_date: self.revision_date,
            archived_date: self.archived_date,
        })
    }
}

/// The result of decrypting a list of ciphers into [`CipherViewV2`].
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct DecryptCipherResultV2 {
    /// The decrypted `CipherViewV2` objects.
    pub successes: Vec<CipherViewV2>,
    /// The original `Cipher` objects that failed to decrypt.
    pub failures: Vec<Cipher>,
}

/// The result of fetching and decrypting all ciphers for an organization into
/// [`CipherListViewV2`].
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct ListOrganizationCiphersResultV2 {
    /// All encrypted ciphers returned from the API.
    pub ciphers: Vec<Cipher>,
    /// Successfully decrypted `CipherListViewV2` objects.
    pub list_views: Vec<CipherListViewV2>,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CiphersClient {
    /// [`CiphersClient::create`] for the [`CipherViewV2`] model.
    pub async fn create_v2(
        &self,
        request: CipherCreateRequestV2,
    ) -> Result<CipherViewV2, CreateCipherError> {
        let key_store = &self.key_store;
        let request = request.into_v1(&mut key_store.context())?;
        let view = self.create(request).await?;
        Ok(view_to_v2(key_store, &view)?)
    }

    /// [`CiphersClient::edit`] for the [`CipherViewV2`] model.
    pub async fn edit_v2(
        &self,
        request: CipherEditRequestV2,
    ) -> Result<CipherViewV2, EditCipherError> {
        let key_store = &self.key_store;
        let request = request.into_v1(&mut key_store.context())?;
        let view = self.edit(request).await?;
        Ok(view_to_v2(key_store, &view)?)
    }

    /// [`CiphersClient::edit_gated`] for the [`CipherViewV2`] model.
    pub async fn edit_gated_v2(
        &self,
        request: CipherEditRequestV2,
        original_cipher_view: CipherViewV2,
    ) -> Result<CipherViewV2, EditCipherError> {
        let key_store = &self.key_store;
        let request = request.into_v1(&mut key_store.context())?;
        let original_cipher_view = view_to_v1(key_store, &original_cipher_view)?;
        let view = self.edit_gated(request, original_cipher_view).await?;
        Ok(view_to_v2(key_store, &view)?)
    }

    /// [`CiphersClient::edit_partial`] for the [`CipherViewV2`] model.
    pub async fn edit_partial_v2(
        &self,
        request: CipherPartialEditRequest,
    ) -> Result<CipherViewV2, EditCipherError> {
        let view = self.edit_partial(request).await?;
        Ok(view_to_v2(&self.key_store, &view)?)
    }

    /// [`CiphersClient::update_collection`] for the [`CipherViewV2`] model.
    pub async fn update_collection_v2(
        &self,
        cipher_id: CipherId,
        collection_ids: Vec<CollectionId>,
        is_admin: bool,
    ) -> Result<CipherViewV2, EditCipherError> {
        let view = self
            .update_collection(cipher_id, collection_ids, is_admin)
            .await?;
        Ok(view_to_v2(&self.key_store, &view)?)
    }

    /// [`CiphersClient::list`] for the [`CipherViewV2`] model.
    pub async fn list_v2(&self) -> Result<DecryptCipherListResultV2, GetCipherError> {
        let ciphers = self.get_repository()?.list().await?;
        let (successes, failures) = CipherListViewV2::decrypt_ciphers_with_failures(
            &self.key_store,
            &ciphers,
            self.is_strict_decrypt().await,
        );
        Ok(DecryptCipherListResultV2 {
            successes,
            failures,
        })
    }

    /// [`CiphersClient::get_all`] for the [`CipherViewV2`] model.
    pub async fn get_all_v2(&self) -> Result<DecryptCipherResultV2, GetCipherError> {
        let ciphers = self.get_repository()?.list().await?;
        let (successes, failures) = CipherViewV2::decrypt_ciphers_with_failures(
            &self.key_store,
            &ciphers,
            self.is_strict_decrypt().await,
        );
        Ok(DecryptCipherResultV2 {
            successes,
            failures,
        })
    }

    /// [`CiphersClient::get`] for the [`CipherViewV2`] model.
    pub async fn get_v2(&self, cipher_id: &str) -> Result<CipherViewV2, GetCipherError> {
        let view = self.get(cipher_id).await?;
        Ok(view_to_v2(&self.key_store, &view)?)
    }

    /// [`CiphersClient::restore`] for the [`CipherViewV2`] model.
    pub async fn restore_v2(
        &self,
        cipher_id: CipherId,
    ) -> Result<CipherViewV2, RestoreCipherError> {
        let view = self.restore(cipher_id).await?;
        Ok(view_to_v2(&self.key_store, &view)?)
    }

    /// [`CiphersClient::restore_many`] for the [`CipherViewV2`] model.
    pub async fn restore_many_v2(
        &self,
        cipher_ids: Vec<CipherId>,
    ) -> Result<DecryptCipherListResultV2, RestoreCipherError> {
        let api_client = &self.api_configurations.api_client;
        let ciphers =
            super::restore::restore_many_ciphers(cipher_ids, api_client, &*self.get_repository()?)
                .await?;
        let (successes, failures) = CipherListViewV2::decrypt_ciphers_with_failures(
            &self.key_store,
            &ciphers,
            self.is_strict_decrypt().await,
        );
        Ok(DecryptCipherListResultV2 {
            successes,
            failures,
        })
    }

    /// [`CiphersClient::share_cipher`] for the [`CipherViewV2`] model.
    pub async fn share_cipher_v2(
        &self,
        cipher_view: CipherViewV2,
        organization_id: OrganizationId,
        collection_ids: Vec<CollectionId>,
        original_cipher_view: Option<CipherViewV2>,
    ) -> Result<CipherViewV2, CipherError> {
        let key_store = &self.key_store;
        let cipher_view = view_to_v1(key_store, &cipher_view)?;
        let original_cipher_view = original_cipher_view
            .map(|v| view_to_v1(key_store, &v))
            .transpose()?;
        let view = self
            .share_cipher(
                cipher_view,
                organization_id,
                collection_ids,
                original_cipher_view,
            )
            .await?;
        Ok(view_to_v2(key_store, &view)?)
    }

    /// [`CiphersClient::prepare_ciphers_for_bulk_share`] for the [`CipherViewV2`] model.
    #[cfg(feature = "uniffi")]
    pub async fn prepare_ciphers_for_bulk_share_v2(
        &self,
        cipher_views: Vec<CipherViewV2>,
        organization_id: OrganizationId,
        collection_ids: Vec<CollectionId>,
    ) -> Result<Vec<EncryptionContext>, CipherError> {
        let cipher_views = self.views_to_v1(&cipher_views)?;
        self.prepare_ciphers_for_bulk_share(cipher_views, organization_id, collection_ids)
            .await
    }

    /// [`CiphersClient::share_ciphers_bulk`] for the [`CipherViewV2`] model.
    pub async fn share_ciphers_bulk_v2(
        &self,
        cipher_views: Vec<CipherViewV2>,
        organization_id: OrganizationId,
        collection_ids: Vec<CollectionId>,
    ) -> Result<Vec<CipherViewV2>, CipherError> {
        let cipher_views = self.views_to_v1(&cipher_views)?;
        let views = self
            .share_ciphers_bulk(cipher_views, organization_id, collection_ids)
            .await?;
        let key_store = &self.key_store;
        Ok(views
            .iter()
            .map(|v| view_to_v2(key_store, v))
            .collect::<Result<_, _>>()?)
    }

    /// [`CiphersClient::encrypt_cipher_for_rotation`] for the [`CipherViewV2`] model.
    #[cfg(feature = "wasm")]
    pub async fn encrypt_cipher_for_rotation_v2(
        &self,
        cipher_view: CipherViewV2,
        new_key: B64,
    ) -> Result<EncryptionContext, CipherError> {
        let cipher_view = view_to_v1(&self.key_store, &cipher_view)?;
        self.encrypt_cipher_for_rotation(cipher_view, new_key).await
    }

    /// [`CiphersClient::encrypt_list`] for the [`CipherViewV2`] model.
    #[cfg(feature = "wasm")]
    pub async fn encrypt_list_v2(
        &self,
        cipher_views: Vec<CipherViewV2>,
    ) -> Result<Vec<EncryptionContext>, crate::EncryptError> {
        let cipher_views = self.views_to_v1(&cipher_views)?;
        self.encrypt_list(cipher_views).await
    }

    /// [`CiphersClient::decrypt_list_full_with_failures`] for the [`CipherViewV2`] model.
    #[cfg(feature = "wasm")]
    pub async fn decrypt_list_full_with_failures_v2(
        &self,
        ciphers: Vec<Cipher>,
    ) -> DecryptCipherResultV2 {
        let (successes, failures) = CipherViewV2::decrypt_ciphers_with_failures(
            &self.key_store,
            &ciphers,
            self.is_strict_decrypt().await,
        );
        DecryptCipherResultV2 {
            successes,
            failures,
        }
    }

    /// Replace the FIDO2 credentials of a login [`CipherViewV2`].
    #[cfg(feature = "wasm")]
    pub fn set_fido2_credentials_v2(
        &self,
        cipher_view: CipherViewV2,
        fido2_credentials: Vec<Fido2CredentialFullView>,
    ) -> Result<CipherViewV2, CipherError> {
        let key_store = &self.key_store;
        let cipher_view = view_to_v1(key_store, &cipher_view)?;
        let view = self.set_fido2_credentials(cipher_view, fido2_credentials)?;
        Ok(view_to_v2(key_store, &view)?)
    }

    /// [`CiphersClient::move_to_organization`] for the [`CipherViewV2`] model.
    pub fn move_to_organization_v2(
        &self,
        cipher_view: CipherViewV2,
        organization_id: OrganizationId,
    ) -> Result<CipherViewV2, CipherError> {
        let key_store = &self.key_store;
        let cipher_view = view_to_v1(key_store, &cipher_view)?;
        let view = self.move_to_organization(cipher_view, organization_id)?;
        Ok(view_to_v2(key_store, &view)?)
    }
}

impl CiphersClient {
    fn views_to_v1(&self, views: &[CipherViewV2]) -> Result<Vec<crate::CipherView>, CryptoError> {
        let key_store = &self.key_store;
        views.iter().map(|v| view_to_v1(key_store, v)).collect()
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::key_management::create_test_crypto_with_user_and_org_key;
    use bitwarden_crypto::{Decryptable, SymmetricKeyAlgorithm};

    use super::*;
    use crate::{Cipher, Fido2CredentialFullView, cipher::cipher_view_v2::tests::cipher_view_v2};

    const TEST_ORG_ID: &str = "1bc9ac1e-f5aa-45f2-94bf-b181009709b8";

    fn edit_request(organization_id: Option<OrganizationId>) -> CipherEditRequestV2 {
        let view = cipher_view_v2(Some(SymmetricCryptoKey::make(
            SymmetricKeyAlgorithm::Aes256CbcHmac,
        )));
        CipherEditRequestV2 {
            id: view.id.unwrap(),
            organization_id,
            folder_id: None,
            favorite: false,
            reprompt: CipherRepromptType::None,
            name: view.name,
            notes: None,
            fields: vec![],
            r#type: CipherViewTypeV2::Login(view.login.unwrap()),
            revision_date: view.revision_date,
            archived_date: None,
            attachments: view.attachments.unwrap(),
            key: view.key,
        }
    }

    #[test]
    fn edit_request_wraps_nested_values() {
        let org_id: OrganizationId = TEST_ORG_ID.parse().unwrap();
        let store = create_test_crypto_with_user_and_org_key(
            SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
            org_id,
            SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
        );
        let request = edit_request(Some(org_id));
        let v1 = request.clone().into_v1(&mut store.context()).unwrap();

        let mut ctx = store.context();
        let cipher_key =
            Cipher::decrypt_cipher_key(&mut ctx, SymmetricKeySlotId::Organization(org_id), &v1.key)
                .unwrap();
        let attachment_key = ctx
            .unwrap_symmetric_key(cipher_key, v1.attachments[0].key.as_ref().unwrap())
            .unwrap();
        #[allow(deprecated)]
        let attachment_key = ctx.dangerous_get_symmetric_key(attachment_key).unwrap();
        assert_eq!(attachment_key, request.attachments[0].key.as_ref().unwrap());

        let CipherViewType::Login(login) = v1.r#type else {
            panic!("expected a login");
        };
        let creds: Vec<Fido2CredentialFullView> = login
            .fido2_credentials
            .unwrap()
            .decrypt(&mut ctx, cipher_key)
            .unwrap();
        assert_eq!(creds[0].key_value, "key-value");
    }

    #[test]
    fn create_request_encrypts_fido2_under_the_user_key() {
        let store = create_test_crypto_with_user_and_org_key(
            SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
            TEST_ORG_ID.parse().unwrap(),
            SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
        );
        let view = cipher_view_v2(None);
        let request = CipherCreateRequestV2 {
            organization_id: None,
            collection_ids: vec![],
            folder_id: None,
            name: view.name,
            notes: None,
            favorite: false,
            reprompt: CipherRepromptType::None,
            r#type: CipherViewTypeV2::Login(view.login.unwrap()),
            fields: vec![],
            archived_date: None,
        };
        let v1 = request.into_v1(&mut store.context()).unwrap();

        let CipherViewType::Login(login) = v1.r#type else {
            panic!("expected a login");
        };
        let creds: Vec<Fido2CredentialFullView> = login
            .fido2_credentials
            .unwrap()
            .decrypt(&mut store.context(), SymmetricKeySlotId::User)
            .unwrap();
        assert_eq!(creds[0].credential_id, "cred-123");
    }
}
