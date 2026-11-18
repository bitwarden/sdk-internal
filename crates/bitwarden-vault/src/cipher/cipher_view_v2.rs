//! Fully decrypted variants of the cipher view types.
//!
//! [`CipherView`] and [`CipherListView`] keep a few nested values encrypted: the cipher key, the
//! attachment keys, the FIDO2 credentials and, on the list view, the TOTP secret. The `V2` types in
//! this module hold the same data with those values decrypted.
//!
//! The `V2` types are built on top of the [`CipherView`] model. Decryption runs the regular
//! decryption and then unwraps the nested values with the cipher key. Encryption wraps the nested
//! values under the cipher key again and then runs the regular encryption, so both models write
//! the same [`Cipher`] format.

use bitwarden_collections::collection::CollectionId;
use bitwarden_core::{
    OrganizationId,
    key_management::{KeySlotIds, SymmetricKeySlotId},
};
use bitwarden_crypto::{
    CompositeEncryptable, CryptoError, Decryptable, EncString, IdentifyKey, KeyStore,
    KeyStoreContext, SymmetricCryptoKey,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;

use super::{
    attachment::AttachmentView,
    bank_account::{BankAccountListView, BankAccountView},
    card::{CardListView, CardView},
    cipher::{
        CipherListViewType, CipherRepromptType, CipherType, CopyableCipherFields, StrictDecrypt,
    },
    cipher_permissions::CipherPermissions,
    drivers_license::DriversLicenseView,
    field,
    identity::IdentityView,
    local_data::LocalDataView,
    login::{
        Fido2CredentialFullView, Fido2CredentialListView, LoginListView, LoginUriView, LoginView,
    },
    passport::PassportView,
    secure_note::SecureNoteView,
    ssh_key::SshKeyView,
};
use crate::{Cipher, CipherId, CipherListView, CipherView, FolderId, PasswordHistoryView};

/// A decrypted FIDO2 credential, including the private key.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[allow(missing_docs)]
pub struct Fido2CredentialViewV2 {
    pub credential_id: String,
    pub key_type: String,
    pub key_algorithm: String,
    pub key_curve: String,
    /// The raw private key material for this passkey credential.
    /// Callers that receive `Fido2CredentialViewV2` over a binding boundary should
    /// treat this field with the same care as any private key material.
    pub key_value: String,
    pub rp_id: String,
    pub user_handle: Option<String>,
    pub user_name: Option<String>,
    pub counter: String,
    pub rp_name: Option<String>,
    pub user_display_name: Option<String>,
    pub discoverable: String,
    pub creation_date: DateTime<Utc>,
}

/// A decrypted login, with decrypted FIDO2 credentials.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[allow(missing_docs)]
pub struct LoginViewV2 {
    pub username: Option<String>,
    pub password: Option<String>,
    pub password_revision_date: Option<DateTime<Utc>>,
    pub uris: Option<Vec<LoginUriView>>,
    pub totp: Option<String>,
    pub autofill_on_page_load: Option<bool>,
    pub fido2_credentials: Option<Vec<Fido2CredentialViewV2>>,
}

/// A decrypted attachment, with the decrypted attachment key.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[allow(missing_docs)]
pub struct AttachmentViewV2 {
    pub id: Option<String>,
    pub url: Option<String>,
    pub size: Option<String>,
    pub size_name: Option<String>,
    pub file_name: Option<String>,
    #[cfg_attr(feature = "wasm", tsify(type = "SymmetricKey | undefined"))]
    pub key: Option<SymmetricCryptoKey>,
}

/// A fully decrypted cipher. See the [module documentation](self).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[allow(missing_docs)]
pub struct CipherViewV2 {
    pub id: Option<CipherId>,
    pub organization_id: Option<OrganizationId>,
    pub folder_id: Option<FolderId>,
    pub collection_ids: Vec<CollectionId>,

    /// The decrypted cipher key, when the cipher has its own key.
    #[cfg_attr(feature = "wasm", tsify(type = "SymmetricKey | undefined"))]
    pub key: Option<SymmetricCryptoKey>,

    pub name: String,
    pub notes: Option<String>,

    pub r#type: CipherType,
    pub login: Option<LoginViewV2>,
    pub identity: Option<IdentityView>,
    pub card: Option<CardView>,
    pub secure_note: Option<SecureNoteView>,
    pub ssh_key: Option<SshKeyView>,
    pub bank_account: Option<BankAccountView>,
    pub drivers_license: Option<DriversLicenseView>,
    pub passport: Option<PassportView>,

    pub favorite: bool,
    pub reprompt: CipherRepromptType,
    pub organization_use_totp: bool,
    pub edit: bool,
    pub permissions: Option<CipherPermissions>,
    pub view_password: bool,
    pub local_data: Option<LocalDataView>,

    pub attachments: Option<Vec<AttachmentViewV2>>,
    /// Attachments that failed to decrypt. Only present when there are decryption failures.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachment_decryption_failures: Option<Vec<AttachmentViewV2>>,
    pub fields: Option<Vec<field::FieldView>>,
    pub password_history: Option<Vec<PasswordHistoryView>>,
    pub creation_date: DateTime<Utc>,
    pub deleted_date: Option<DateTime<Utc>>,
    pub revision_date: DateTime<Utc>,
    pub archived_date: Option<DateTime<Utc>>,

    /// True when this view was produced from a server-restricted (PAM-gated) cipher. See
    /// [`CipherView::partial`].
    #[serde(default)]
    pub partial: bool,
}

/// A login list view with the decrypted TOTP secret.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[allow(missing_docs)]
pub struct LoginListViewV2 {
    pub fido2_credentials: Option<Vec<Fido2CredentialListView>>,
    pub has_fido2: bool,
    pub username: Option<String>,
    pub totp: Option<String>,
    pub uris: Option<Vec<LoginUriView>>,
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub enum CipherListViewTypeV2 {
    Login(LoginListViewV2),
    SecureNote,
    Card(CardListView),
    Identity,
    SshKey,
    BankAccount(BankAccountListView),
    Passport,
    DriversLicense,
}

/// A fully decrypted cipher list view. See the [module documentation](self).
#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct CipherListViewV2 {
    pub id: Option<CipherId>,
    pub organization_id: Option<OrganizationId>,
    pub folder_id: Option<FolderId>,
    pub collection_ids: Vec<CollectionId>,

    pub name: String,
    pub subtitle: String,

    pub r#type: CipherListViewTypeV2,

    pub favorite: bool,
    pub reprompt: CipherRepromptType,
    pub organization_use_totp: bool,
    pub edit: bool,
    pub permissions: Option<CipherPermissions>,

    pub view_password: bool,

    /// The number of attachments
    pub attachments: u32,
    /// Indicates if the cipher has old attachments that need to be re-uploaded
    pub has_old_attachments: bool,

    pub creation_date: DateTime<Utc>,
    pub deleted_date: Option<DateTime<Utc>>,
    pub revision_date: DateTime<Utc>,
    pub archived_date: Option<DateTime<Utc>>,

    /// Hints for the presentation layer for which fields can be copied.
    pub copyable_fields: Vec<CopyableCipherFields>,

    pub local_data: Option<LocalDataView>,

    /// True when this view was produced from a server-restricted (PAM-gated) cipher. See
    /// [`CipherListView::partial`].
    #[serde(default)]
    pub partial: bool,

    /// Decrypted cipher notes for search indexing.
    #[cfg(feature = "wasm")]
    pub notes: Option<String>,
    /// Decrypted cipher fields for search indexing.
    /// Only includes name and value (for text fields only).
    #[cfg(feature = "wasm")]
    pub fields: Option<Vec<field::FieldListView>>,
    /// Decrypted attachment filenames for search indexing.
    #[cfg(feature = "wasm")]
    pub attachment_names: Option<Vec<String>>,
}

/// The result of decrypting a list of ciphers into [`CipherListViewV2`].
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct DecryptCipherListResultV2 {
    /// The decrypted `CipherListViewV2` objects.
    pub successes: Vec<CipherListViewV2>,
    /// The original `Cipher` objects that failed to decrypt.
    pub failures: Vec<Cipher>,
}

impl From<Fido2CredentialFullView> for Fido2CredentialViewV2 {
    fn from(v: Fido2CredentialFullView) -> Self {
        Self {
            credential_id: v.credential_id,
            key_type: v.key_type,
            key_algorithm: v.key_algorithm,
            key_curve: v.key_curve,
            key_value: v.key_value,
            rp_id: v.rp_id,
            user_handle: v.user_handle,
            user_name: v.user_name,
            counter: v.counter,
            rp_name: v.rp_name,
            user_display_name: v.user_display_name,
            discoverable: v.discoverable,
            creation_date: v.creation_date,
        }
    }
}

impl From<Fido2CredentialViewV2> for Fido2CredentialFullView {
    fn from(v: Fido2CredentialViewV2) -> Self {
        Self {
            credential_id: v.credential_id,
            key_type: v.key_type,
            key_algorithm: v.key_algorithm,
            key_curve: v.key_curve,
            key_value: v.key_value,
            rp_id: v.rp_id,
            user_handle: v.user_handle,
            user_name: v.user_name,
            counter: v.counter,
            rp_name: v.rp_name,
            user_display_name: v.user_display_name,
            discoverable: v.discoverable,
            creation_date: v.creation_date,
        }
    }
}

impl From<&Fido2CredentialViewV2> for Fido2CredentialListView {
    fn from(v: &Fido2CredentialViewV2) -> Self {
        Self {
            credential_id: v.credential_id.clone(),
            rp_id: v.rp_id.clone(),
            user_handle: v.user_handle.clone(),
            user_name: v.user_name.clone(),
            user_display_name: v.user_display_name.clone(),
            counter: v.counter.clone(),
        }
    }
}

impl IdentifyKey<SymmetricKeySlotId> for CipherViewV2 {
    fn key_identifier(&self) -> SymmetricKeySlotId {
        match self.organization_id {
            Some(organization_id) => SymmetricKeySlotId::Organization(organization_id),
            None => SymmetricKeySlotId::User,
        }
    }
}

#[allow(deprecated)]
fn export_key(
    ctx: &KeyStoreContext<KeySlotIds>,
    slot: SymmetricKeySlotId,
) -> Result<SymmetricCryptoKey, CryptoError> {
    Ok(ctx.dangerous_get_symmetric_key(slot)?.clone())
}

fn unwrap_key(
    ctx: &mut KeyStoreContext<KeySlotIds>,
    wrapping_key: SymmetricKeySlotId,
    wrapped: &EncString,
) -> Result<SymmetricCryptoKey, CryptoError> {
    let slot = ctx.unwrap_symmetric_key(wrapping_key, wrapped)?;
    export_key(ctx, slot)
}

fn wrap_key(
    ctx: &mut KeyStoreContext<KeySlotIds>,
    wrapping_key: SymmetricKeySlotId,
    key: &SymmetricCryptoKey,
) -> Result<EncString, CryptoError> {
    let slot = ctx.add_local_symmetric_key(key.clone());
    ctx.wrap_symmetric_key(wrapping_key, slot)
}

impl AttachmentView {
    /// Unwraps the attachment key. Fails if the key does not unwrap under `cipher_key`.
    fn into_v2(
        self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        cipher_key: SymmetricKeySlotId,
    ) -> Result<AttachmentViewV2, CryptoError> {
        Ok(AttachmentViewV2 {
            key: self
                .key
                .as_ref()
                .map(|k| unwrap_key(ctx, cipher_key, k))
                .transpose()?,
            id: self.id,
            url: self.url,
            size: self.size,
            size_name: self.size_name,
            file_name: self.file_name,
        })
    }

    /// Converts an attachment that failed to decrypt. The key is kept when it unwraps.
    fn failure_into_v2(
        self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        cipher_key: SymmetricKeySlotId,
    ) -> AttachmentViewV2 {
        AttachmentViewV2 {
            key: self
                .key
                .as_ref()
                .and_then(|k| unwrap_key(ctx, cipher_key, k).ok()),
            id: self.id,
            url: self.url,
            size: self.size,
            size_name: self.size_name,
            file_name: None,
        }
    }
}

impl AttachmentViewV2 {
    pub(crate) fn to_v1(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        cipher_key: SymmetricKeySlotId,
    ) -> Result<AttachmentView, CryptoError> {
        Ok(AttachmentView {
            id: self.id.clone(),
            url: self.url.clone(),
            size: self.size.clone(),
            size_name: self.size_name.clone(),
            file_name: self.file_name.clone(),
            key: self
                .key
                .as_ref()
                .map(|k| wrap_key(ctx, cipher_key, k))
                .transpose()?,
            #[cfg(feature = "wasm")]
            decrypted_key: self.key.as_ref().map(|k| k.to_base64().to_string()),
        })
    }
}

impl LoginView {
    fn into_v2(
        self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        cipher_key: SymmetricKeySlotId,
    ) -> Result<LoginViewV2, CryptoError> {
        let fido2_credentials: Option<Vec<Fido2CredentialFullView>> = self
            .fido2_credentials
            .as_ref()
            .map(|c| c.decrypt(ctx, cipher_key))
            .transpose()?;
        Ok(LoginViewV2 {
            username: self.username,
            password: self.password,
            password_revision_date: self.password_revision_date,
            uris: self.uris,
            totp: self.totp,
            autofill_on_page_load: self.autofill_on_page_load,
            fido2_credentials: fido2_credentials
                .map(|c| c.into_iter().map(Fido2CredentialViewV2::from).collect()),
        })
    }
}

impl LoginViewV2 {
    pub(crate) fn to_v1(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        cipher_key: SymmetricKeySlotId,
    ) -> Result<LoginView, CryptoError> {
        Ok(LoginView {
            username: self.username.clone(),
            password: self.password.clone(),
            password_revision_date: self.password_revision_date,
            uris: self.uris.clone(),
            totp: self.totp.clone(),
            autofill_on_page_load: self.autofill_on_page_load,
            fido2_credentials: self
                .fido2_credentials
                .as_ref()
                .map(|creds| {
                    creds
                        .iter()
                        .cloned()
                        .map(Fido2CredentialFullView::from)
                        .collect::<Vec<_>>()
                        .encrypt_composite(ctx, cipher_key)
                })
                .transpose()?,
        })
    }
}

impl CipherView {
    /// Converts this view into a [`CipherViewV2`] by unwrapping the cipher key, the attachment
    /// keys and the FIDO2 credentials.
    ///
    /// * `wrapping_key` - The key the cipher key is wrapped under, normally the user or
    ///   organization key from [`IdentifyKey::key_identifier`].
    ///
    /// An attachment whose key does not unwrap is moved to
    /// [`CipherViewV2::attachment_decryption_failures`], without its file name and key.
    pub fn to_v2(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        wrapping_key: SymmetricKeySlotId,
    ) -> Result<CipherViewV2, CryptoError> {
        let view = self.clone();
        let cipher_key = Cipher::decrypt_cipher_key(ctx, wrapping_key, &view.key)?;
        let key = view
            .key
            .as_ref()
            .map(|_| export_key(ctx, cipher_key))
            .transpose()?;

        let has_failure_list = view.attachment_decryption_failures.is_some();
        let mut failures: Vec<AttachmentViewV2> = view
            .attachment_decryption_failures
            .into_iter()
            .flatten()
            .map(|a| a.failure_into_v2(ctx, cipher_key))
            .collect();
        let attachments = view.attachments.map(|attachments| {
            attachments
                .into_iter()
                .filter_map(|a| match a.clone().into_v2(ctx, cipher_key) {
                    Ok(v2) => Some(v2),
                    Err(e) => {
                        tracing::warn!(attachment_id = ?a.id, error = %e, "Failed to unwrap attachment key");
                        failures.push(a.failure_into_v2(ctx, cipher_key));
                        None
                    }
                })
                .collect()
        });

        Ok(CipherViewV2 {
            id: view.id,
            organization_id: view.organization_id,
            folder_id: view.folder_id,
            collection_ids: view.collection_ids,
            key,
            name: view.name,
            notes: view.notes,
            r#type: view.r#type,
            login: view.login.map(|l| l.into_v2(ctx, cipher_key)).transpose()?,
            identity: view.identity,
            card: view.card,
            secure_note: view.secure_note,
            ssh_key: view.ssh_key,
            bank_account: view.bank_account,
            drivers_license: view.drivers_license,
            passport: view.passport,
            favorite: view.favorite,
            reprompt: view.reprompt,
            organization_use_totp: view.organization_use_totp,
            edit: view.edit,
            permissions: view.permissions,
            view_password: view.view_password,
            local_data: view.local_data,
            attachments,
            attachment_decryption_failures: (has_failure_list || !failures.is_empty())
                .then_some(failures),
            fields: view.fields,
            password_history: view.password_history,
            creation_date: view.creation_date,
            deleted_date: view.deleted_date,
            revision_date: view.revision_date,
            archived_date: view.archived_date,
            partial: view.partial,
        })
    }
}

impl CipherViewV2 {
    /// Converts this view into a [`CipherView`] by wrapping the cipher key under `wrapping_key`,
    /// and the attachment keys and FIDO2 credentials under the cipher key.
    ///
    /// * `wrapping_key` - The key to wrap the cipher key under, normally the user or organization
    ///   key from [`IdentifyKey::key_identifier`].
    pub fn to_v1(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        wrapping_key: SymmetricKeySlotId,
    ) -> Result<CipherView, CryptoError> {
        let (key, cipher_key) = match &self.key {
            Some(k) => {
                let slot = ctx.add_local_symmetric_key(k.clone());
                (Some(ctx.wrap_symmetric_key(wrapping_key, slot)?), slot)
            }
            None => (None, wrapping_key),
        };

        let convert_attachments =
            |list: &Option<Vec<AttachmentViewV2>>, ctx: &mut KeyStoreContext<KeySlotIds>| {
                list.as_ref()
                    .map(|l| {
                        l.iter()
                            .map(|a| a.to_v1(ctx, cipher_key))
                            .collect::<Result<Vec<_>, _>>()
                    })
                    .transpose()
            };

        Ok(CipherView {
            id: self.id,
            organization_id: self.organization_id,
            folder_id: self.folder_id,
            collection_ids: self.collection_ids.clone(),
            key,
            name: self.name.clone(),
            notes: self.notes.clone(),
            r#type: self.r#type,
            login: self
                .login
                .as_ref()
                .map(|l| l.to_v1(ctx, cipher_key))
                .transpose()?,
            identity: self.identity.clone(),
            card: self.card.clone(),
            secure_note: self.secure_note.clone(),
            ssh_key: self.ssh_key.clone(),
            bank_account: self.bank_account.clone(),
            drivers_license: self.drivers_license.clone(),
            passport: self.passport.clone(),
            favorite: self.favorite,
            reprompt: self.reprompt,
            organization_use_totp: self.organization_use_totp,
            edit: self.edit,
            permissions: self.permissions,
            view_password: self.view_password,
            local_data: self.local_data.clone(),
            attachments: convert_attachments(&self.attachments, ctx)?,
            attachment_decryption_failures: convert_attachments(
                &self.attachment_decryption_failures,
                ctx,
            )?,
            fields: self.fields.clone(),
            password_history: self.password_history.clone(),
            creation_date: self.creation_date,
            deleted_date: self.deleted_date,
            revision_date: self.revision_date,
            archived_date: self.archived_date,
            partial: self.partial,
        })
    }
}

impl CipherListView {
    /// Converts this list view into a [`CipherListViewV2`] by decrypting the TOTP secret.
    ///
    /// When `strict` is false a TOTP secret that fails to decrypt is dropped, otherwise the error
    /// is returned. This matches the lenient and strict cipher decryption modes.
    fn into_v2(
        self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        wrapping_key: SymmetricKeySlotId,
        strict: bool,
    ) -> Result<CipherListViewV2, CryptoError> {
        let r#type = match self.r#type {
            CipherListViewType::Login(login) => {
                let totp = match &login.totp {
                    Some(totp) => {
                        let cipher_key = Cipher::decrypt_cipher_key(ctx, wrapping_key, &self.key)?;
                        let decrypted: Result<String, CryptoError> = totp.decrypt(ctx, cipher_key);
                        if strict {
                            Some(decrypted?)
                        } else {
                            decrypted.ok()
                        }
                    }
                    None => None,
                };
                let LoginListView {
                    fido2_credentials,
                    has_fido2,
                    username,
                    uris,
                    ..
                } = login;
                CipherListViewTypeV2::Login(LoginListViewV2 {
                    fido2_credentials,
                    has_fido2,
                    username,
                    totp,
                    uris,
                })
            }
            CipherListViewType::SecureNote => CipherListViewTypeV2::SecureNote,
            CipherListViewType::Card(card) => CipherListViewTypeV2::Card(card),
            CipherListViewType::Identity => CipherListViewTypeV2::Identity,
            CipherListViewType::SshKey => CipherListViewTypeV2::SshKey,
            CipherListViewType::BankAccount(b) => CipherListViewTypeV2::BankAccount(b),
            CipherListViewType::Passport => CipherListViewTypeV2::Passport,
            CipherListViewType::DriversLicense => CipherListViewTypeV2::DriversLicense,
        };

        Ok(CipherListViewV2 {
            id: self.id,
            organization_id: self.organization_id,
            folder_id: self.folder_id,
            collection_ids: self.collection_ids,
            name: self.name,
            subtitle: self.subtitle,
            r#type,
            favorite: self.favorite,
            reprompt: self.reprompt,
            organization_use_totp: self.organization_use_totp,
            edit: self.edit,
            permissions: self.permissions,
            view_password: self.view_password,
            attachments: self.attachments,
            has_old_attachments: self.has_old_attachments,
            creation_date: self.creation_date,
            deleted_date: self.deleted_date,
            revision_date: self.revision_date,
            archived_date: self.archived_date,
            copyable_fields: self.copyable_fields,
            local_data: self.local_data,
            partial: self.partial,
            #[cfg(feature = "wasm")]
            notes: self.notes,
            #[cfg(feature = "wasm")]
            fields: self.fields,
            #[cfg(feature = "wasm")]
            attachment_names: self.attachment_names,
        })
    }
}

impl CipherListViewV2 {
    /// Returns the decrypted TOTP secret of a login, if any.
    pub(crate) fn totp(&self) -> Option<&str> {
        match &self.r#type {
            CipherListViewTypeV2::Login(LoginListViewV2 { totp, .. }) => totp.as_deref(),
            _ => None,
        }
    }
}

impl Decryptable<KeySlotIds, SymmetricKeySlotId, CipherViewV2> for Cipher {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        key: SymmetricKeySlotId,
    ) -> Result<CipherViewV2, CryptoError> {
        let view: CipherView = self.decrypt(ctx, key)?;
        view.to_v2(ctx, key)
    }
}

impl Decryptable<KeySlotIds, SymmetricKeySlotId, CipherViewV2> for StrictDecrypt<Cipher> {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        key: SymmetricKeySlotId,
    ) -> Result<CipherViewV2, CryptoError> {
        let view: CipherView = self.decrypt(ctx, key)?;
        view.to_v2(ctx, key)
    }
}

impl Decryptable<KeySlotIds, SymmetricKeySlotId, CipherListViewV2> for Cipher {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        key: SymmetricKeySlotId,
    ) -> Result<CipherListViewV2, CryptoError> {
        let view: CipherListView = self.decrypt(ctx, key)?;
        view.into_v2(ctx, key, false)
    }
}

impl Decryptable<KeySlotIds, SymmetricKeySlotId, CipherListViewV2> for StrictDecrypt<Cipher> {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        key: SymmetricKeySlotId,
    ) -> Result<CipherListViewV2, CryptoError> {
        let view: CipherListView = self.decrypt(ctx, key)?;
        view.into_v2(ctx, key, true)
    }
}

/// A view that a [`Cipher`] decrypts into, using either the lenient or the strict decryption.
pub(crate) trait DecryptedCipher: Sized + Send + Sync {
    /// Decrypts a single cipher.
    fn decrypt_cipher(
        store: &KeyStore<KeySlotIds>,
        cipher: &Cipher,
        strict: bool,
    ) -> Result<Self, CryptoError>;

    /// Decrypts all ciphers, failing on the first cipher that does not decrypt.
    fn decrypt_ciphers(
        store: &KeyStore<KeySlotIds>,
        ciphers: &[Cipher],
        strict: bool,
    ) -> Result<Vec<Self>, CryptoError>;

    /// Decrypts all ciphers, returning the decrypted views and the ciphers that failed.
    fn decrypt_ciphers_with_failures(
        store: &KeyStore<KeySlotIds>,
        ciphers: &[Cipher],
        strict: bool,
    ) -> (Vec<Self>, Vec<Cipher>);
}

impl<V> DecryptedCipher for V
where
    V: Send + Sync,
    Cipher: Decryptable<KeySlotIds, SymmetricKeySlotId, V>,
    StrictDecrypt<Cipher>: Decryptable<KeySlotIds, SymmetricKeySlotId, V>,
{
    fn decrypt_cipher(
        store: &KeyStore<KeySlotIds>,
        cipher: &Cipher,
        strict: bool,
    ) -> Result<Self, CryptoError> {
        if strict {
            store.decrypt(&StrictDecrypt(cipher.clone()))
        } else {
            store.decrypt(cipher)
        }
    }

    fn decrypt_ciphers(
        store: &KeyStore<KeySlotIds>,
        ciphers: &[Cipher],
        strict: bool,
    ) -> Result<Vec<Self>, CryptoError> {
        if strict {
            let wrapped: Vec<_> = ciphers.iter().cloned().map(StrictDecrypt).collect();
            store.decrypt_list(&wrapped)
        } else {
            store.decrypt_list(ciphers)
        }
    }

    fn decrypt_ciphers_with_failures(
        store: &KeyStore<KeySlotIds>,
        ciphers: &[Cipher],
        strict: bool,
    ) -> (Vec<Self>, Vec<Cipher>) {
        if strict {
            let wrapped: Vec<_> = ciphers.iter().cloned().map(StrictDecrypt).collect();
            let (successes, failures) = store.decrypt_list_with_failures(&wrapped);
            (
                successes,
                failures.into_iter().map(|f| f.0.clone()).collect(),
            )
        } else {
            let (successes, failures) = store.decrypt_list_with_failures(ciphers);
            (successes, failures.into_iter().cloned().collect())
        }
    }
}

/// Converts a [`CipherView`] to a [`CipherViewV2`], unwrapping the cipher key under the view's
/// user or organization key.
pub(crate) fn view_to_v2(
    store: &KeyStore<KeySlotIds>,
    view: &CipherView,
) -> Result<CipherViewV2, CryptoError> {
    view.to_v2(&mut store.context(), view.key_identifier())
}

/// Converts a [`CipherViewV2`] to a [`CipherView`], wrapping the cipher key under the view's user
/// or organization key.
pub(crate) fn view_to_v1(
    store: &KeyStore<KeySlotIds>,
    view: &CipherViewV2,
) -> Result<CipherView, CryptoError> {
    view.to_v1(&mut store.context(), view.key_identifier())
}

#[cfg(test)]
pub(crate) mod tests {
    use bitwarden_core::key_management::create_test_crypto_with_user_key;
    use bitwarden_crypto::{PrimitiveEncryptable, SymmetricKeyAlgorithm};

    use super::*;
    use crate::{CipherType, EncryptMode, Fido2Credential};

    fn fido2_credential() -> Fido2CredentialViewV2 {
        Fido2CredentialViewV2 {
            credential_id: "cred-123".to_string(),
            key_type: "public-key".to_string(),
            key_algorithm: "ECDSA".to_string(),
            key_curve: "P-256".to_string(),
            key_value: "key-value".to_string(),
            rp_id: "example.com".to_string(),
            user_handle: None,
            user_name: None,
            counter: "0".to_string(),
            rp_name: None,
            user_display_name: None,
            discoverable: "true".to_string(),
            creation_date: "2024-06-07T14:12:36.150Z".parse().unwrap(),
        }
    }

    pub(crate) fn cipher_view_v2(key: Option<SymmetricCryptoKey>) -> CipherViewV2 {
        CipherViewV2 {
            id: Some("fd411a1a-fec8-4070-985d-0e6560860e69".parse().unwrap()),
            organization_id: None,
            folder_id: None,
            collection_ids: vec![],
            key,
            name: "My login".to_string(),
            notes: None,
            r#type: CipherType::Login,
            login: Some(LoginViewV2 {
                username: Some("user".to_string()),
                password: Some("password".to_string()),
                password_revision_date: None,
                uris: None,
                totp: Some("JBSWY3DPEHPK3PXP".to_string()),
                autofill_on_page_load: None,
                fido2_credentials: Some(vec![fido2_credential()]),
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
            attachments: Some(vec![AttachmentViewV2 {
                id: Some("attachment-id".to_string()),
                url: None,
                size: Some("100".to_string()),
                size_name: Some("100 Bytes".to_string()),
                file_name: Some("file.txt".to_string()),
                key: Some(SymmetricCryptoKey::make(
                    SymmetricKeyAlgorithm::Aes256CbcHmac,
                )),
            }]),
            attachment_decryption_failures: Some(vec![]),
            fields: None,
            password_history: None,
            creation_date: "2024-01-01T00:00:00Z".parse().unwrap(),
            deleted_date: None,
            revision_date: "2024-01-01T00:00:00Z".parse().unwrap(),
            archived_date: None,
            partial: false,
        }
    }

    fn key_store() -> KeyStore<KeySlotIds> {
        create_test_crypto_with_user_key(SymmetricCryptoKey::make(
            SymmetricKeyAlgorithm::Aes256CbcHmac,
        ))
    }

    /// Encrypts a [`CipherViewV2`] the same way `CiphersClient::encrypt_v2` does.
    fn encrypt(store: &KeyStore<KeySlotIds>, view: &CipherViewV2, blob: bool) -> Cipher {
        let v1 = view_to_v1(store, view).unwrap();
        let mode = if blob {
            EncryptMode::Blob(v1)
        } else {
            EncryptMode::Legacy(v1)
        };
        store.encrypt(mode).unwrap()
    }

    #[test]
    fn round_trips_through_cipher() {
        let store = key_store();
        for blob in [false, true] {
            let view = cipher_view_v2(Some(SymmetricCryptoKey::make(
                SymmetricKeyAlgorithm::Aes256CbcHmac,
            )));
            let cipher = encrypt(&store, &view, blob);

            let lenient: CipherViewV2 = store.decrypt(&cipher).unwrap();
            assert_eq!(lenient, view, "lenient, blob: {blob}");
            let strict: CipherViewV2 = store.decrypt(&StrictDecrypt(cipher)).unwrap();
            assert_eq!(strict, view, "strict, blob: {blob}");
        }
    }

    #[test]
    fn round_trips_without_cipher_key() {
        let store = key_store();
        let view = cipher_view_v2(None);
        let cipher = encrypt(&store, &view, false);
        assert!(cipher.key.is_none());

        let decrypted: CipherViewV2 = store.decrypt(&cipher).unwrap();
        assert_eq!(decrypted, view);
    }

    #[test]
    fn to_v1_wraps_nested_values_under_the_cipher_key() {
        let store = key_store();
        let view = cipher_view_v2(Some(SymmetricCryptoKey::make(
            SymmetricKeyAlgorithm::Aes256CbcHmac,
        )));
        let v1 = view_to_v1(&store, &view).unwrap();

        let mut ctx = store.context();
        let cipher_key =
            Cipher::decrypt_cipher_key(&mut ctx, SymmetricKeySlotId::User, &v1.key).unwrap();
        assert_eq!(
            export_key(&ctx, cipher_key).unwrap(),
            *view.key.as_ref().unwrap()
        );

        let attachment_key = v1.attachments.as_ref().unwrap()[0].key.as_ref().unwrap();
        assert_eq!(
            unwrap_key(&mut ctx, cipher_key, attachment_key).unwrap(),
            *view.attachments.as_ref().unwrap()[0].key.as_ref().unwrap()
        );

        let creds: Vec<Fido2CredentialFullView> = v1
            .login
            .as_ref()
            .unwrap()
            .fido2_credentials
            .as_ref()
            .unwrap()
            .decrypt(&mut ctx, cipher_key)
            .unwrap();
        assert_eq!(creds[0].key_value, "key-value");

        // The original model round-trips back to the same V2 view.
        assert_eq!(v1.to_v2(&mut ctx, SymmetricKeySlotId::User).unwrap(), view);
    }

    #[test]
    fn list_view_has_decrypted_totp() {
        let store = key_store();
        for blob in [false, true] {
            let view = cipher_view_v2(Some(SymmetricCryptoKey::make(
                SymmetricKeyAlgorithm::Aes256CbcHmac,
            )));
            let cipher = encrypt(&store, &view, blob);

            let list: CipherListViewV2 = store.decrypt(&cipher).unwrap();
            assert_eq!(list.totp(), Some("JBSWY3DPEHPK3PXP"), "blob: {blob}");
            assert_eq!(list.name, "My login");
            let CipherListViewTypeV2::Login(login) = &list.r#type else {
                panic!("expected a login");
            };
            assert!(login.has_fido2);
            assert_eq!(
                login.fido2_credentials.as_ref().unwrap()[0].credential_id,
                "cred-123"
            );
        }
    }

    /// Builds a legacy-format cipher whose `field` is encrypted under an unrelated key, so the
    /// regular [`CipherView`] decryption passes it through but it cannot be decrypted.
    fn cipher_with_foreign_key(store: &KeyStore<KeySlotIds>, field: &str) -> Cipher {
        let view = cipher_view_v2(None);
        let mut cipher = encrypt(store, &view, false);
        let mut ctx = store.context();
        let foreign = ctx.generate_symmetric_key();
        let login = cipher.login.as_mut().unwrap();
        match field {
            "totp" => {
                login.totp = Some("JBSWY3DPEHPK3PXP".encrypt(&mut ctx, foreign).unwrap());
            }
            "fido2" => {
                let full = Fido2CredentialFullView::from(fido2_credential());
                let creds: Vec<Fido2Credential> =
                    vec![full].encrypt_composite(&mut ctx, foreign).unwrap();
                login.fido2_credentials = Some(creds);
            }
            "attachment" => {
                let attachment_key = ctx.generate_symmetric_key();
                cipher.attachments.as_mut().unwrap()[0].key =
                    Some(ctx.wrap_symmetric_key(foreign, attachment_key).unwrap());
            }
            _ => unreachable!(),
        }
        cipher
    }

    /// Pins how the V2 decryption handles a FIDO2 credential that does not decrypt: the whole
    /// cipher fails to decrypt in both modes, while [`CipherView`] decrypts it.
    #[test]
    fn undecryptable_fido2_credential_fails_the_cipher() {
        let store = key_store();
        let cipher = cipher_with_foreign_key(&store, "fido2");

        let _: CipherView = store.decrypt(&cipher).unwrap();
        let lenient: Result<CipherViewV2, _> = store.decrypt(&cipher);
        assert!(lenient.is_err());
        let strict: Result<CipherViewV2, _> = store.decrypt(&StrictDecrypt(cipher.clone()));
        assert!(strict.is_err());

        // A list view does not carry the credential secrets, so it still decrypts.
        let list: CipherListViewV2 = store.decrypt(&cipher).unwrap();
        assert_eq!(list.name, "My login");
    }

    /// Pins how the V2 decryption handles an attachment key that does not unwrap: the attachment
    /// is reported in `attachment_decryption_failures` without a file name or key.
    #[test]
    fn undecryptable_attachment_key_is_reported_as_failure() {
        let store = key_store();
        let cipher = cipher_with_foreign_key(&store, "attachment");

        for strict in [false, true] {
            let view: CipherViewV2 = if strict {
                store.decrypt(&StrictDecrypt(cipher.clone())).unwrap()
            } else {
                store.decrypt(&cipher).unwrap()
            };
            assert_eq!(view.attachments, Some(vec![]), "strict: {strict}");
            let failures = view.attachment_decryption_failures.unwrap();
            assert_eq!(failures.len(), 1);
            assert_eq!(failures[0].id.as_deref(), Some("attachment-id"));
            assert_eq!(failures[0].file_name, None);
            assert_eq!(failures[0].key, None);
        }
    }

    /// Pins how the V2 list decryption handles a TOTP secret that does not decrypt: the lenient
    /// mode drops it, the strict mode fails the cipher.
    #[test]
    fn undecryptable_totp_in_list_view() {
        let store = key_store();
        let cipher = cipher_with_foreign_key(&store, "totp");

        let lenient: CipherListViewV2 = store.decrypt(&cipher).unwrap();
        assert_eq!(lenient.totp(), None);
        let strict: Result<CipherListViewV2, _> = store.decrypt(&StrictDecrypt(cipher));
        assert!(strict.is_err());
    }

    #[test]
    fn decrypt_ciphers_with_failures_returns_failed_ciphers() {
        let store = key_store();
        let good = encrypt(&store, &cipher_view_v2(None), false);
        let bad = cipher_with_foreign_key(&store, "fido2");

        for strict in [false, true] {
            let (successes, failures) = CipherViewV2::decrypt_ciphers_with_failures(
                &store,
                &[good.clone(), bad.clone()],
                strict,
            );
            assert_eq!(successes.len(), 1);
            assert_eq!(failures.len(), 1);
            assert_eq!(
                failures[0]
                    .login
                    .as_ref()
                    .unwrap()
                    .totp
                    .as_ref()
                    .unwrap()
                    .to_string(),
                bad.login
                    .as_ref()
                    .unwrap()
                    .totp
                    .as_ref()
                    .unwrap()
                    .to_string()
            );
        }
    }
}
