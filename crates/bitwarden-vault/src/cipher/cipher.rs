use bitwarden_api_api::models::CipherDetailsResponseModel;
use bitwarden_core::{
    key_management::{KeyIds, SymmetricKeyId},
    require, MissingFieldError, VaultLockedError,
};
use bitwarden_crypto::{
    CryptoError, Decryptable, EncString, Encryptable, IdentifyKey, KeyStoreContext,
};
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use thiserror::Error;
use uuid::Uuid;

use super::{
    attachment, card,
    cipher_permissions::CipherPermissions,
    field, identity,
    local_data::{LocalData, LocalDataView},
    login::LoginListView,
    secure_note, ssh_key,
};
use crate::{
    password_history, Fido2CredentialFullView, Fido2CredentialView, Login, LoginView,
    VaultParseError,
};

#[derive(Debug, Error)]
pub enum CipherError {
    #[error(transparent)]
    MissingFieldError(#[from] MissingFieldError),
    #[error(transparent)]
    VaultLocked(#[from] VaultLockedError),
    #[error(transparent)]
    CryptoError(#[from] CryptoError),
    #[error("This cipher contains attachments without keys. Those attachments will need to be reuploaded to complete the operation")]
    AttachmentsWithoutKeys,
}

#[derive(Clone, Copy, Serialize_repr, Deserialize_repr, Debug, JsonSchema, PartialEq)]
#[repr(u8)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum CipherType {
    Login = 1,
    SecureNote = 2,
    Card = 3,
    Identity = 4,
    SshKey = 5,
}

#[derive(Clone, Copy, Serialize_repr, Deserialize_repr, Debug, JsonSchema, PartialEq)]
#[repr(u8)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum CipherRepromptType {
    None = 0,
    Password = 1,
}

#[derive(Serialize, Deserialize, Debug, JsonSchema, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct Cipher {
    pub id: Option<Uuid>,
    pub organization_id: Option<Uuid>,
    pub folder_id: Option<Uuid>,
    pub collection_ids: Vec<Uuid>,

    /// More recent ciphers uses individual encryption keys to encrypt the other fields of the
    /// Cipher.
    pub key: Option<EncString>,

    pub name: EncString,
    pub notes: Option<EncString>,

    pub r#type: CipherType,
    pub login: Option<Login>,
    pub identity: Option<identity::Identity>,
    pub card: Option<card::Card>,
    pub secure_note: Option<secure_note::SecureNote>,
    pub ssh_key: Option<ssh_key::SshKey>,

    pub favorite: bool,
    pub reprompt: CipherRepromptType,
    pub organization_use_totp: bool,
    pub edit: bool,
    pub permissions: Option<CipherPermissions>,
    pub view_password: bool,
    pub local_data: Option<LocalData>,

    pub attachments: Option<Vec<attachment::Attachment>>,
    pub fields: Option<Vec<field::Field>>,
    pub password_history: Option<Vec<password_history::PasswordHistory>>,

    pub creation_date: DateTime<Utc>,
    pub deleted_date: Option<DateTime<Utc>>,
    pub revision_date: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Debug, JsonSchema, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CipherView {
    pub id: Option<Uuid>,
    pub organization_id: Option<Uuid>,
    pub folder_id: Option<Uuid>,
    pub collection_ids: Vec<Uuid>,

    /// Temporary, required to support re-encrypting existing items.
    pub key: Option<EncString>,

    pub name: String,
    pub notes: Option<String>,

    pub r#type: CipherType,
    pub login: Option<LoginView>,
    pub identity: Option<identity::IdentityView>,
    pub card: Option<card::CardView>,
    pub secure_note: Option<secure_note::SecureNoteView>,
    pub ssh_key: Option<ssh_key::SshKeyView>,

    pub favorite: bool,
    pub reprompt: CipherRepromptType,
    pub organization_use_totp: bool,
    pub edit: bool,
    pub permissions: Option<CipherPermissions>,
    pub view_password: bool,
    pub local_data: Option<LocalDataView>,

    pub attachments: Option<Vec<attachment::AttachmentView>>,
    pub fields: Option<Vec<field::FieldView>>,
    pub password_history: Option<Vec<password_history::PasswordHistoryView>>,

    pub creation_date: DateTime<Utc>,
    pub deleted_date: Option<DateTime<Utc>>,
    pub revision_date: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum CipherListViewType {
    Login(LoginListView),
    SecureNote,
    Card,
    Identity,
    SshKey,
}

#[derive(Serialize, Deserialize, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CipherListView {
    pub id: Option<Uuid>,
    pub organization_id: Option<Uuid>,
    pub folder_id: Option<Uuid>,
    pub collection_ids: Vec<Uuid>,

    /// Temporary, required to support calculating TOTP from CipherListView.
    pub key: Option<EncString>,

    pub name: String,
    pub subtitle: String,

    pub r#type: CipherListViewType,

    pub favorite: bool,
    pub reprompt: CipherRepromptType,
    pub organization_use_totp: bool,
    pub edit: bool,
    pub permissions: Option<CipherPermissions>,

    pub view_password: bool,

    /// The number of attachments
    pub attachments: u32,

    pub creation_date: DateTime<Utc>,
    pub deleted_date: Option<DateTime<Utc>>,
    pub revision_date: DateTime<Utc>,
}

impl CipherListView {
    pub(crate) fn get_totp_key(
        self,
        ctx: &mut KeyStoreContext<KeyIds>,
    ) -> Result<Option<String>, CryptoError> {
        let key = self.key_identifier();
        let ciphers_key = Cipher::decrypt_cipher_key(ctx, key, &self.key)?;

        let totp = match self.r#type {
            CipherListViewType::Login(LoginListView { totp, .. }) => {
                totp.map(|t| t.decrypt(ctx, ciphers_key)).transpose()?
            }
            _ => None,
        };

        Ok(totp)
    }
}

impl Encryptable<KeyIds, SymmetricKeyId, Cipher> for CipherView {
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<Cipher, CryptoError> {
        let ciphers_key = Cipher::decrypt_cipher_key(ctx, key, &self.key)?;

        let mut cipher_view = self.clone();

        // For compatibility reasons, we only create checksums for ciphers that have a key
        if cipher_view.key.is_some() {
            cipher_view.generate_checksums();
        }

        Ok(Cipher {
            id: cipher_view.id,
            organization_id: cipher_view.organization_id,
            folder_id: cipher_view.folder_id,
            collection_ids: cipher_view.collection_ids,
            key: cipher_view.key,
            name: cipher_view.name.encrypt(ctx, ciphers_key)?,
            notes: cipher_view.notes.encrypt(ctx, ciphers_key)?,
            r#type: cipher_view.r#type,
            login: cipher_view.login.encrypt(ctx, ciphers_key)?,
            identity: cipher_view.identity.encrypt(ctx, ciphers_key)?,
            card: cipher_view.card.encrypt(ctx, ciphers_key)?,
            secure_note: cipher_view.secure_note.encrypt(ctx, ciphers_key)?,
            ssh_key: cipher_view.ssh_key.encrypt(ctx, ciphers_key)?,
            favorite: cipher_view.favorite,
            reprompt: cipher_view.reprompt,
            organization_use_totp: cipher_view.organization_use_totp,
            edit: cipher_view.edit,
            view_password: cipher_view.view_password,
            local_data: cipher_view.local_data.encrypt(ctx, ciphers_key)?,
            attachments: cipher_view.attachments.encrypt(ctx, ciphers_key)?,
            fields: cipher_view.fields.encrypt(ctx, ciphers_key)?,
            password_history: cipher_view.password_history.encrypt(ctx, ciphers_key)?,
            creation_date: cipher_view.creation_date,
            deleted_date: cipher_view.deleted_date,
            revision_date: cipher_view.revision_date,
            permissions: cipher_view.permissions,
        })
    }
}

impl Decryptable<KeyIds, SymmetricKeyId, CipherView> for Cipher {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<CipherView, CryptoError> {
        let ciphers_key = Cipher::decrypt_cipher_key(ctx, key, &self.key)?;

        let mut cipher = CipherView {
            id: self.id,
            organization_id: self.organization_id,
            folder_id: self.folder_id,
            collection_ids: self.collection_ids.clone(),
            key: self.key.clone(),
            name: self.name.decrypt(ctx, ciphers_key).ok().unwrap_or_default(),
            notes: self.notes.decrypt(ctx, ciphers_key).ok().flatten(),
            r#type: self.r#type,
            login: self.login.decrypt(ctx, ciphers_key).ok().flatten(),
            identity: self.identity.decrypt(ctx, ciphers_key).ok().flatten(),
            card: self.card.decrypt(ctx, ciphers_key).ok().flatten(),
            secure_note: self.secure_note.decrypt(ctx, ciphers_key).ok().flatten(),
            ssh_key: self.ssh_key.decrypt(ctx, ciphers_key).ok().flatten(),
            favorite: self.favorite,
            reprompt: self.reprompt,
            organization_use_totp: self.organization_use_totp,
            edit: self.edit,
            permissions: self.permissions,
            view_password: self.view_password,
            local_data: self.local_data.decrypt(ctx, ciphers_key).ok().flatten(),
            attachments: self.attachments.decrypt(ctx, ciphers_key).ok().flatten(),
            fields: self.fields.decrypt(ctx, ciphers_key).ok().flatten(),
            password_history: self
                .password_history
                .decrypt(ctx, ciphers_key)
                .ok()
                .flatten(),
            creation_date: self.creation_date,
            deleted_date: self.deleted_date,
            revision_date: self.revision_date,
        };

        // For compatibility we only remove URLs with invalid checksums if the cipher has a key
        if cipher.key.is_some() {
            cipher.remove_invalid_checksums();
        }

        Ok(cipher)
    }
}

impl Cipher {
    /// Decrypt the individual encryption key for this cipher into the provided [KeyStoreContext]
    /// and return it's identifier. Note that some ciphers do not have individual encryption
    /// keys, in which case this will return the provided key identifier instead
    ///
    /// # Arguments
    ///
    /// * `ctx` - The key store context where the cipher key will be decrypted, if it exists
    /// * `key` - The key to use to decrypt the cipher key, this should be the user or organization
    ///   key
    /// * `ciphers_key` - The encrypted cipher key
    pub(super) fn decrypt_cipher_key(
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
        ciphers_key: &Option<EncString>,
    ) -> Result<SymmetricKeyId, CryptoError> {
        const CIPHER_KEY: SymmetricKeyId = SymmetricKeyId::Local("cipher_key");
        match ciphers_key {
            Some(ciphers_key) => {
                ctx.decrypt_symmetric_key_with_symmetric_key(key, CIPHER_KEY, ciphers_key)
            }
            None => Ok(key),
        }
    }

    fn get_decrypted_subtitle(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<String, CryptoError> {
        Ok(match self.r#type {
            CipherType::Login => {
                let Some(login) = &self.login else {
                    return Ok(String::new());
                };
                login.username.decrypt(ctx, key)?.unwrap_or_default()
            }
            CipherType::SecureNote => String::new(),
            CipherType::Card => {
                let Some(card) = &self.card else {
                    return Ok(String::new());
                };

                build_subtitle_card(
                    card.brand
                        .as_ref()
                        .map(|b| b.decrypt(ctx, key))
                        .transpose()?,
                    card.number
                        .as_ref()
                        .map(|n| n.decrypt(ctx, key))
                        .transpose()?,
                )
            }
            CipherType::Identity => {
                let Some(identity) = &self.identity else {
                    return Ok(String::new());
                };

                build_subtitle_identity(
                    identity
                        .first_name
                        .as_ref()
                        .map(|f| f.decrypt(ctx, key))
                        .transpose()?,
                    identity
                        .last_name
                        .as_ref()
                        .map(|l| l.decrypt(ctx, key))
                        .transpose()?,
                )
            }
            CipherType::SshKey => {
                let Some(ssh_key) = &self.ssh_key else {
                    return Ok(String::new());
                };

                Some(ssh_key.fingerprint.clone())
                    .as_ref()
                    .map(|c| c.decrypt(ctx, key))
                    .transpose()?
                    .unwrap_or_default()
            }
        })
    }
}

/// Builds the subtitle for a card cipher
fn build_subtitle_card(brand: Option<String>, number: Option<String>) -> String {
    // Attempt to pre-allocate the string with the expected max-size
    let mut subtitle =
        String::with_capacity(brand.as_ref().map(|b| b.len()).unwrap_or_default() + 8);

    if let Some(brand) = brand {
        subtitle.push_str(&brand);
    }

    if let Some(number) = number {
        let number_len = number.len();
        if number_len > 4 {
            if !subtitle.is_empty() {
                subtitle.push_str(", ");
            }

            // On AMEX cards we show 5 digits instead of 4
            let digit_count = match &number[0..2] {
                "34" | "37" => 5,
                _ => 4,
            };

            subtitle.push('*');
            subtitle.push_str(&number[(number_len - digit_count)..]);
        }
    }

    subtitle
}

/// Builds the subtitle for a card cipher
fn build_subtitle_identity(first_name: Option<String>, last_name: Option<String>) -> String {
    let len = match (first_name.as_ref(), last_name.as_ref()) {
        (Some(first_name), Some(last_name)) => first_name.len() + last_name.len() + 1,
        (Some(first_name), None) => first_name.len(),
        (None, Some(last_name)) => last_name.len(),
        (None, None) => 0,
    };

    let mut subtitle = String::with_capacity(len);

    if let Some(first_name) = &first_name {
        subtitle.push_str(first_name);
    }

    if let Some(last_name) = &last_name {
        if !subtitle.is_empty() {
            subtitle.push(' ');
        }
        subtitle.push_str(last_name);
    }

    subtitle
}

impl CipherView {
    pub fn generate_cipher_key(
        &mut self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<(), CryptoError> {
        let old_ciphers_key = Cipher::decrypt_cipher_key(ctx, key, &self.key)?;

        const NEW_KEY: SymmetricKeyId = SymmetricKeyId::Local("new_cipher_key");

        let new_key = ctx.generate_symmetric_key(NEW_KEY)?;

        self.reencrypt_attachment_keys(ctx, old_ciphers_key, new_key)?;
        self.reencrypt_fido2_credentials(ctx, old_ciphers_key, new_key)?;

        self.key = Some(ctx.encrypt_symmetric_key_with_symmetric_key(key, new_key)?);
        Ok(())
    }

    pub fn generate_checksums(&mut self) {
        if let Some(uris) = self.login.as_mut().and_then(|l| l.uris.as_mut()) {
            for uri in uris {
                uri.generate_checksum();
            }
        }
    }

    pub fn remove_invalid_checksums(&mut self) {
        if let Some(uris) = self.login.as_mut().and_then(|l| l.uris.as_mut()) {
            uris.retain(|u| u.is_checksum_valid());
        }
    }

    fn reencrypt_attachment_keys(
        &mut self,
        ctx: &mut KeyStoreContext<KeyIds>,
        old_key: SymmetricKeyId,
        new_key: SymmetricKeyId,
    ) -> Result<(), CryptoError> {
        if let Some(attachments) = &mut self.attachments {
            for attachment in attachments {
                if let Some(attachment_key) = &mut attachment.key {
                    let dec_attachment_key: Vec<u8> = attachment_key.decrypt(ctx, old_key)?;
                    *attachment_key = dec_attachment_key.encrypt(ctx, new_key)?;
                }
            }
        }
        Ok(())
    }

    pub fn decrypt_fido2_credentials(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
    ) -> Result<Vec<Fido2CredentialView>, CryptoError> {
        let key = self.key_identifier();
        let ciphers_key = Cipher::decrypt_cipher_key(ctx, key, &self.key)?;

        Ok(self
            .login
            .as_ref()
            .and_then(|l| l.fido2_credentials.as_ref())
            .map(|f| f.decrypt(ctx, ciphers_key))
            .transpose()?
            .unwrap_or_default())
    }

    fn reencrypt_fido2_credentials(
        &mut self,
        ctx: &mut KeyStoreContext<KeyIds>,
        old_key: SymmetricKeyId,
        new_key: SymmetricKeyId,
    ) -> Result<(), CryptoError> {
        if let Some(login) = self.login.as_mut() {
            if let Some(fido2_credentials) = &mut login.fido2_credentials {
                let dec_fido2_credentials: Vec<Fido2CredentialFullView> =
                    fido2_credentials.decrypt(ctx, old_key)?;
                *fido2_credentials = dec_fido2_credentials.encrypt(ctx, new_key)?;
            }
        }
        Ok(())
    }

    pub fn move_to_organization(
        &mut self,
        ctx: &mut KeyStoreContext<KeyIds>,
        organization_id: Uuid,
    ) -> Result<(), CipherError> {
        let old_key = self.key_identifier();
        let new_key = SymmetricKeyId::Organization(organization_id);

        // If any attachment is missing a key we can't reencrypt the attachment keys
        if self.attachments.iter().flatten().any(|a| a.key.is_none()) {
            return Err(CipherError::AttachmentsWithoutKeys);
        }

        // If the cipher has a key, we need to re-encrypt it with the new organization key
        if let Some(cipher_key) = &mut self.key {
            let dec_cipher_key: Vec<u8> = cipher_key.decrypt(ctx, old_key)?;
            *cipher_key = dec_cipher_key.encrypt(ctx, new_key)?;
        } else {
            // If the cipher does not have a key, we need to reencrypt all attachment keys
            self.reencrypt_attachment_keys(ctx, old_key, new_key)?;
            self.reencrypt_fido2_credentials(ctx, old_key, new_key)?;
        }

        self.organization_id = Some(organization_id);
        Ok(())
    }

    pub fn set_new_fido2_credentials(
        &mut self,
        ctx: &mut KeyStoreContext<KeyIds>,
        creds: Vec<Fido2CredentialFullView>,
    ) -> Result<(), CipherError> {
        let key = self.key_identifier();

        let ciphers_key = Cipher::decrypt_cipher_key(ctx, key, &self.key)?;

        require!(self.login.as_mut()).fido2_credentials = Some(creds.encrypt(ctx, ciphers_key)?);

        Ok(())
    }

    pub fn get_fido2_credentials(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
    ) -> Result<Vec<Fido2CredentialFullView>, CipherError> {
        let key = self.key_identifier();

        let ciphers_key = Cipher::decrypt_cipher_key(ctx, key, &self.key)?;

        let login = require!(self.login.as_ref());
        let creds = require!(login.fido2_credentials.as_ref());
        let res = creds.decrypt(ctx, ciphers_key)?;
        Ok(res)
    }
}

impl Decryptable<KeyIds, SymmetricKeyId, CipherListView> for Cipher {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<CipherListView, CryptoError> {
        let ciphers_key = Cipher::decrypt_cipher_key(ctx, key, &self.key)?;

        Ok(CipherListView {
            id: self.id,
            organization_id: self.organization_id,
            folder_id: self.folder_id,
            collection_ids: self.collection_ids.clone(),
            key: self.key.clone(),
            name: self.name.decrypt(ctx, ciphers_key).ok().unwrap_or_default(),
            subtitle: self
                .get_decrypted_subtitle(ctx, ciphers_key)
                .ok()
                .unwrap_or_default(),
            r#type: match self.r#type {
                CipherType::Login => {
                    let login = self
                        .login
                        .as_ref()
                        .ok_or(CryptoError::MissingField("login"))?;
                    CipherListViewType::Login(login.decrypt(ctx, ciphers_key)?)
                }
                CipherType::SecureNote => CipherListViewType::SecureNote,
                CipherType::Card => CipherListViewType::Card,
                CipherType::Identity => CipherListViewType::Identity,
                CipherType::SshKey => CipherListViewType::SshKey,
            },
            favorite: self.favorite,
            reprompt: self.reprompt,
            organization_use_totp: self.organization_use_totp,
            edit: self.edit,
            permissions: self.permissions,
            view_password: self.view_password,
            attachments: self
                .attachments
                .as_ref()
                .map(|a| a.len() as u32)
                .unwrap_or(0),
            creation_date: self.creation_date,
            deleted_date: self.deleted_date,
            revision_date: self.revision_date,
        })
    }
}

impl IdentifyKey<SymmetricKeyId> for Cipher {
    fn key_identifier(&self) -> SymmetricKeyId {
        match self.organization_id {
            Some(organization_id) => SymmetricKeyId::Organization(organization_id),
            None => SymmetricKeyId::User,
        }
    }
}

impl IdentifyKey<SymmetricKeyId> for CipherView {
    fn key_identifier(&self) -> SymmetricKeyId {
        match self.organization_id {
            Some(organization_id) => SymmetricKeyId::Organization(organization_id),
            None => SymmetricKeyId::User,
        }
    }
}

impl IdentifyKey<SymmetricKeyId> for CipherListView {
    fn key_identifier(&self) -> SymmetricKeyId {
        match self.organization_id {
            Some(organization_id) => SymmetricKeyId::Organization(organization_id),
            None => SymmetricKeyId::User,
        }
    }
}

impl TryFrom<CipherDetailsResponseModel> for Cipher {
    type Error = VaultParseError;

    fn try_from(cipher: CipherDetailsResponseModel) -> Result<Self, Self::Error> {
        Ok(Self {
            id: cipher.id,
            organization_id: cipher.organization_id,
            folder_id: cipher.folder_id,
            collection_ids: cipher.collection_ids.unwrap_or_default(),
            name: require!(EncString::try_from_optional(cipher.name)?),
            notes: EncString::try_from_optional(cipher.notes)?,
            r#type: require!(cipher.r#type).into(),
            login: cipher.login.map(|l| (*l).try_into()).transpose()?,
            identity: cipher.identity.map(|i| (*i).try_into()).transpose()?,
            card: cipher.card.map(|c| (*c).try_into()).transpose()?,
            secure_note: cipher.secure_note.map(|s| (*s).try_into()).transpose()?,
            // TODO: add ssh_key when api bindings have been updated
            ssh_key: None,
            favorite: cipher.favorite.unwrap_or(false),
            reprompt: cipher
                .reprompt
                .map(|r| r.into())
                .unwrap_or(CipherRepromptType::None),
            organization_use_totp: cipher.organization_use_totp.unwrap_or(true),
            edit: cipher.edit.unwrap_or(true),
            // TODO: add permissions when api bindings have been updated
            permissions: None,
            view_password: cipher.view_password.unwrap_or(true),
            local_data: None, // Not sent from server
            attachments: cipher
                .attachments
                .map(|a| a.into_iter().map(|a| a.try_into()).collect())
                .transpose()?,
            fields: cipher
                .fields
                .map(|f| f.into_iter().map(|f| f.try_into()).collect())
                .transpose()?,
            password_history: cipher
                .password_history
                .map(|p| p.into_iter().map(|p| p.try_into()).collect())
                .transpose()?,
            creation_date: require!(cipher.creation_date).parse()?,
            deleted_date: cipher.deleted_date.map(|d| d.parse()).transpose()?,
            revision_date: require!(cipher.revision_date).parse()?,
            key: EncString::try_from_optional(cipher.key)?,
        })
    }
}

impl From<bitwarden_api_api::models::CipherType> for CipherType {
    fn from(t: bitwarden_api_api::models::CipherType) -> Self {
        match t {
            bitwarden_api_api::models::CipherType::Login => CipherType::Login,
            bitwarden_api_api::models::CipherType::SecureNote => CipherType::SecureNote,
            bitwarden_api_api::models::CipherType::Card => CipherType::Card,
            bitwarden_api_api::models::CipherType::Identity => CipherType::Identity,
            bitwarden_api_api::models::CipherType::SSHKey => CipherType::SshKey,
        }
    }
}

impl From<bitwarden_api_api::models::CipherRepromptType> for CipherRepromptType {
    fn from(t: bitwarden_api_api::models::CipherRepromptType) -> Self {
        match t {
            bitwarden_api_api::models::CipherRepromptType::None => CipherRepromptType::None,
            bitwarden_api_api::models::CipherRepromptType::Password => CipherRepromptType::Password,
        }
    }
}

#[cfg(test)]
mod tests {

    use attachment::AttachmentView;
    use bitwarden_core::key_management::{
        create_test_crypto_with_user_and_org_key, create_test_crypto_with_user_key,
    };
    use bitwarden_crypto::SymmetricCryptoKey;
    use ssh_key::SshKey;

    use super::*;
    use crate::{login::Fido2CredentialListView, Fido2Credential};

    fn generate_cipher() -> CipherView {
        let test_id: uuid::Uuid = "fd411a1a-fec8-4070-985d-0e6560860e69".parse().unwrap();
        CipherView {
            r#type: CipherType::Login,
            login: Some(LoginView {
                username: Some("test_username".to_string()),
                password: Some("test_password".to_string()),
                password_revision_date: None,
                uris: None,
                totp: None,
                autofill_on_page_load: None,
                fido2_credentials: None,
            }),
            id: Some(test_id),
            organization_id: None,
            folder_id: None,
            collection_ids: vec![],
            key: None,
            name: "My test login".to_string(),
            notes: None,
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
            creation_date: "2024-01-30T17:55:36.150Z".parse().unwrap(),
            deleted_date: None,
            revision_date: "2024-01-30T17:55:36.150Z".parse().unwrap(),
        }
    }

    fn generate_fido2(ctx: &mut KeyStoreContext<KeyIds>, key: SymmetricKeyId) -> Fido2Credential {
        Fido2Credential {
            credential_id: "123".to_string().encrypt(ctx, key).unwrap(),
            key_type: "public-key".to_string().encrypt(ctx, key).unwrap(),
            key_algorithm: "ECDSA".to_string().encrypt(ctx, key).unwrap(),
            key_curve: "P-256".to_string().encrypt(ctx, key).unwrap(),
            key_value: "123".to_string().encrypt(ctx, key).unwrap(),
            rp_id: "123".to_string().encrypt(ctx, key).unwrap(),
            user_handle: None,
            user_name: None,
            counter: "123".to_string().encrypt(ctx, key).unwrap(),
            rp_name: None,
            user_display_name: None,
            discoverable: "true".to_string().encrypt(ctx, key).unwrap(),
            creation_date: "2024-06-07T14:12:36.150Z".parse().unwrap(),
        }
    }

    #[test]
    fn test_decrypt_cipher_list_view() {
        let key: SymmetricCryptoKey = "w2LO+nwV4oxwswVYCxlOfRUseXfvU03VzvKQHrqeklPgiMZrspUe6sOBToCnDn9Ay0tuCBn8ykVVRb7PWhub2Q==".to_string().try_into().unwrap();
        let key_store = create_test_crypto_with_user_key(key);

        let cipher = Cipher {
            id: Some("090c19ea-a61a-4df6-8963-262b97bc6266".parse().unwrap()),
            organization_id: None,
            folder_id: None,
            collection_ids: vec![],
            key: None,
            name: "2.d3rzo0P8rxV9Hs1m1BmAjw==|JOwna6i0zs+K7ZghwrZRuw==|SJqKreLag1ID+g6H1OdmQr0T5zTrVWKzD6hGy3fDqB0=".parse().unwrap(),
            notes: None,
            r#type: CipherType::Login,
            login: Some(Login {
                username: Some("2.EBNGgnaMHeO/kYnI3A0jiA==|9YXlrgABP71ebZ5umurCJQ==|GDk5jxiqTYaU7e2AStCFGX+a1kgCIk8j0NEli7Jn0L4=".parse().unwrap()),
                password: Some("2.M7ZJ7EuFDXCq66gDTIyRIg==|B1V+jroo6+m/dpHx6g8DxA==|PIXPBCwyJ1ady36a7jbcLg346pm/7N/06W4UZxc1TUo=".parse().unwrap()),
                password_revision_date: None,
                uris: None,
                totp: Some("2.hqdioUAc81FsKQmO1XuLQg==|oDRdsJrQjoFu9NrFVy8tcJBAFKBx95gHaXZnWdXbKpsxWnOr2sKipIG43pKKUFuq|3gKZMiboceIB5SLVOULKg2iuyu6xzos22dfJbvx0EHk=".parse().unwrap()),
                autofill_on_page_load: None,
                fido2_credentials: Some(vec![generate_fido2(&mut key_store.context(), SymmetricKeyId::User)]),
            }),
            identity: None,
            card: None,
            secure_note: None,
            ssh_key: None,
            favorite: false,
            reprompt: CipherRepromptType::None,
            organization_use_totp: false,
            edit: true,
            permissions: Some(CipherPermissions {
                delete: false,
                restore: false
            }),
            view_password: true,
            local_data: None,
            attachments: None,
            fields: None,
            password_history: None,
            creation_date: "2024-01-30T17:55:36.150Z".parse().unwrap(),
            deleted_date: None,
            revision_date: "2024-01-30T17:55:36.150Z".parse().unwrap(),
        };

        let view: CipherListView = key_store.decrypt(&cipher).unwrap();

        assert_eq!(
            view,
            CipherListView {
                id: cipher.id,
                organization_id: cipher.organization_id,
                folder_id: cipher.folder_id,
                collection_ids: cipher.collection_ids,
                key: cipher.key,
                name: "My test login".to_string(),
                subtitle: "test_username".to_string(),
                r#type: CipherListViewType::Login(LoginListView {
                    fido2_credentials: Some(vec![Fido2CredentialListView {
                        credential_id: "123".to_string(),
                        rp_id: "123".to_string(),
                        user_handle: None,
                        user_name: None,
                        user_display_name: None,
                    }]),
                    has_fido2: true,
                    username: Some("test_username".to_string()),
                    totp: cipher.login.as_ref().unwrap().totp.clone(),
                    uris: None,
                }),
                favorite: cipher.favorite,
                reprompt: cipher.reprompt,
                organization_use_totp: cipher.organization_use_totp,
                edit: cipher.edit,
                permissions: cipher.permissions,
                view_password: cipher.view_password,
                attachments: 0,
                creation_date: cipher.creation_date,
                deleted_date: cipher.deleted_date,
                revision_date: cipher.revision_date
            }
        )
    }

    #[test]
    fn test_generate_cipher_key() {
        let key = SymmetricCryptoKey::generate(rand::thread_rng());
        let key_store = create_test_crypto_with_user_key(key);

        let original_cipher = generate_cipher();

        // Check that the cipher gets encrypted correctly without it's own key
        let cipher = generate_cipher();
        let no_key_cipher_enc = key_store.encrypt(cipher).unwrap();
        let no_key_cipher_dec: CipherView = key_store.decrypt(&no_key_cipher_enc).unwrap();
        assert!(no_key_cipher_dec.key.is_none());
        assert_eq!(no_key_cipher_dec.name, original_cipher.name);

        let mut cipher = generate_cipher();
        cipher
            .generate_cipher_key(&mut key_store.context(), cipher.key_identifier())
            .unwrap();

        // Check that the cipher gets encrypted correctly when it's assigned it's own key
        let key_cipher_enc = key_store.encrypt(cipher).unwrap();
        let key_cipher_dec: CipherView = key_store.decrypt(&key_cipher_enc).unwrap();
        assert!(key_cipher_dec.key.is_some());
        assert_eq!(key_cipher_dec.name, original_cipher.name);
    }

    #[test]
    fn test_generate_cipher_key_when_a_cipher_key_already_exists() {
        let key = SymmetricCryptoKey::generate(rand::thread_rng());
        let key_store = create_test_crypto_with_user_key(key);

        let mut original_cipher = generate_cipher();
        {
            const CIPHER_KEY: SymmetricKeyId = SymmetricKeyId::Local("test_cipher_key");
            let mut ctx = key_store.context();
            let cipher_key = ctx.generate_symmetric_key(CIPHER_KEY).unwrap();

            original_cipher.key = Some(
                ctx.encrypt_symmetric_key_with_symmetric_key(SymmetricKeyId::User, cipher_key)
                    .unwrap(),
            );
        }

        original_cipher
            .generate_cipher_key(&mut key_store.context(), original_cipher.key_identifier())
            .unwrap();

        // Make sure that the cipher key is decryptable
        let _: Vec<u8> = original_cipher
            .key
            .unwrap()
            .decrypt(&mut key_store.context(), SymmetricKeyId::User)
            .unwrap();
    }

    #[test]
    fn test_generate_cipher_key_ignores_attachments_without_key() {
        let key = SymmetricCryptoKey::generate(rand::thread_rng());
        let key_store = create_test_crypto_with_user_key(key);

        let mut cipher = generate_cipher();
        let attachment = AttachmentView {
            id: None,
            url: None,
            size: None,
            size_name: None,
            file_name: Some("Attachment test name".into()),
            key: None,
        };
        cipher.attachments = Some(vec![attachment]);

        cipher
            .generate_cipher_key(&mut key_store.context(), cipher.key_identifier())
            .unwrap();
        assert!(cipher.attachments.unwrap()[0].key.is_none());
    }

    #[test]
    fn test_move_user_cipher_to_org() {
        let org = uuid::Uuid::new_v4();
        let key = SymmetricCryptoKey::generate(rand::thread_rng());
        let org_key = SymmetricCryptoKey::generate(rand::thread_rng());
        let key_store = create_test_crypto_with_user_and_org_key(key, org, org_key);

        // Create a cipher with a user key
        let mut cipher = generate_cipher();
        cipher
            .generate_cipher_key(&mut key_store.context(), cipher.key_identifier())
            .unwrap();

        cipher
            .move_to_organization(&mut key_store.context(), org)
            .unwrap();
        assert_eq!(cipher.organization_id, Some(org));

        // Check that the cipher can be encrypted/decrypted with the new org key
        let cipher_enc = key_store.encrypt(cipher).unwrap();
        let cipher_dec: CipherView = key_store.decrypt(&cipher_enc).unwrap();

        assert_eq!(cipher_dec.name, "My test login");
    }

    #[test]
    fn test_move_user_cipher_to_org_manually() {
        let org = uuid::Uuid::new_v4();
        let key = SymmetricCryptoKey::generate(rand::thread_rng());
        let org_key = SymmetricCryptoKey::generate(rand::thread_rng());
        let key_store = create_test_crypto_with_user_and_org_key(key, org, org_key);

        // Create a cipher with a user key
        let mut cipher = generate_cipher();
        cipher
            .generate_cipher_key(&mut key_store.context(), cipher.key_identifier())
            .unwrap();

        cipher.organization_id = Some(org);

        // Check that the cipher can not be encrypted, as the
        // cipher key is tied to the user key and not the org key
        assert!(key_store.encrypt(cipher).is_err());
    }

    #[test]
    fn test_move_user_cipher_with_attachment_without_key_to_org() {
        let org = uuid::Uuid::new_v4();
        let key = SymmetricCryptoKey::generate(rand::thread_rng());
        let org_key = SymmetricCryptoKey::generate(rand::thread_rng());
        let key_store = create_test_crypto_with_user_and_org_key(key, org, org_key);

        let mut cipher = generate_cipher();
        let attachment = AttachmentView {
            id: None,
            url: None,
            size: None,
            size_name: None,
            file_name: Some("Attachment test name".into()),
            key: None,
        };
        cipher.attachments = Some(vec![attachment]);

        // Neither cipher nor attachment have keys, so the cipher can't be moved
        assert!(cipher
            .move_to_organization(&mut key_store.context(), org)
            .is_err());
    }

    #[test]
    fn test_move_user_cipher_with_attachment_with_key_to_org() {
        let org = uuid::Uuid::new_v4();
        let key = SymmetricCryptoKey::generate(rand::thread_rng());
        let org_key = SymmetricCryptoKey::generate(rand::thread_rng());
        let key_store = create_test_crypto_with_user_and_org_key(key, org, org_key);
        let org_key = SymmetricKeyId::Organization(org);

        // Attachment has a key that is encrypted with the user key, as the cipher has no key itself
        let (attachment_key_enc, attachment_key_val) = {
            let mut ctx = key_store.context();
            let attachment_key = ctx
                .generate_symmetric_key(SymmetricKeyId::Local("test_attachment_key"))
                .unwrap();
            let attachment_key_enc = ctx
                .encrypt_symmetric_key_with_symmetric_key(SymmetricKeyId::User, attachment_key)
                .unwrap();
            #[allow(deprecated)]
            let attachment_key_val = ctx
                .dangerous_get_symmetric_key(attachment_key)
                .unwrap()
                .clone();

            (attachment_key_enc, attachment_key_val)
        };

        let mut cipher = generate_cipher();
        let attachment = AttachmentView {
            id: None,
            url: None,
            size: None,
            size_name: None,
            file_name: Some("Attachment test name".into()),
            key: Some(attachment_key_enc),
        };
        cipher.attachments = Some(vec![attachment]);
        let cred = generate_fido2(&mut key_store.context(), SymmetricKeyId::User);
        cipher.login.as_mut().unwrap().fido2_credentials = Some(vec![cred]);

        cipher
            .move_to_organization(&mut key_store.context(), org)
            .unwrap();

        assert!(cipher.key.is_none());

        // Check that the attachment key has been re-encrypted with the org key,
        // and the value matches with the original attachment key
        let new_attachment_key = cipher.attachments.unwrap()[0].key.clone().unwrap();
        let new_attachment_key_dec: Vec<_> = new_attachment_key
            .decrypt(&mut key_store.context(), org_key)
            .unwrap();
        let new_attachment_key_dec: SymmetricCryptoKey = new_attachment_key_dec.try_into().unwrap();

        assert_eq!(new_attachment_key_dec.to_vec(), attachment_key_val.to_vec());

        let cred2: Fido2CredentialFullView = cipher
            .login
            .unwrap()
            .fido2_credentials
            .unwrap()
            .first()
            .unwrap()
            .decrypt(&mut key_store.context(), org_key)
            .unwrap();

        assert_eq!(cred2.credential_id, "123");
    }

    #[test]
    fn test_move_user_cipher_with_key_with_attachment_with_key_to_org() {
        let org = uuid::Uuid::new_v4();
        let key = SymmetricCryptoKey::generate(rand::thread_rng());
        let org_key = SymmetricCryptoKey::generate(rand::thread_rng());
        let key_store = create_test_crypto_with_user_and_org_key(key, org, org_key);
        let org_key = SymmetricKeyId::Organization(org);

        let mut ctx = key_store.context();

        let cipher_key = ctx
            .generate_symmetric_key(SymmetricKeyId::Local("test_cipher_key"))
            .unwrap();
        let cipher_key_enc = ctx
            .encrypt_symmetric_key_with_symmetric_key(SymmetricKeyId::User, cipher_key)
            .unwrap();

        // Attachment has a key that is encrypted with the cipher key
        let attachment_key = ctx
            .generate_symmetric_key(SymmetricKeyId::Local("test_attachment_key"))
            .unwrap();
        let attachment_key_enc = ctx
            .encrypt_symmetric_key_with_symmetric_key(cipher_key, attachment_key)
            .unwrap();

        let mut cipher = generate_cipher();
        cipher.key = Some(cipher_key_enc);

        let attachment = AttachmentView {
            id: None,
            url: None,
            size: None,
            size_name: None,
            file_name: Some("Attachment test name".into()),
            key: Some(attachment_key_enc.clone()),
        };
        cipher.attachments = Some(vec![attachment]);

        let cred = generate_fido2(&mut ctx, cipher_key);
        cipher.login.as_mut().unwrap().fido2_credentials = Some(vec![cred.clone()]);

        cipher.move_to_organization(&mut ctx, org).unwrap();

        // Check that the cipher key has been re-encrypted with the org key,
        let new_cipher_key_dec: Vec<_> = cipher
            .key
            .clone()
            .unwrap()
            .decrypt(&mut ctx, org_key)
            .unwrap();

        let new_cipher_key_dec: SymmetricCryptoKey = new_cipher_key_dec.try_into().unwrap();

        #[allow(deprecated)]
        let cipher_key_val = ctx.dangerous_get_symmetric_key(cipher_key).unwrap();

        assert_eq!(new_cipher_key_dec.to_vec(), cipher_key_val.to_vec());

        // Check that the attachment key hasn't changed
        assert_eq!(
            cipher.attachments.unwrap()[0]
                .key
                .as_ref()
                .unwrap()
                .to_string(),
            attachment_key_enc.to_string()
        );

        let cred2: Fido2Credential = cipher
            .login
            .unwrap()
            .fido2_credentials
            .unwrap()
            .first()
            .unwrap()
            .clone();

        assert_eq!(
            cred2.credential_id.to_string(),
            cred.credential_id.to_string()
        );
    }

    #[test]
    fn test_build_subtitle_card_visa() {
        let brand = Some("Visa".to_owned());
        let number = Some("4111111111111111".to_owned());

        let subtitle = build_subtitle_card(brand, number);
        assert_eq!(subtitle, "Visa, *1111");
    }

    #[test]
    fn test_build_subtitle_card_mastercard() {
        let brand = Some("Mastercard".to_owned());
        let number = Some("5555555555554444".to_owned());

        let subtitle = build_subtitle_card(brand, number);
        assert_eq!(subtitle, "Mastercard, *4444");
    }

    #[test]
    fn test_build_subtitle_card_amex() {
        let brand = Some("Amex".to_owned());
        let number = Some("378282246310005".to_owned());

        let subtitle = build_subtitle_card(brand, number);
        assert_eq!(subtitle, "Amex, *10005");
    }

    #[test]
    fn test_build_subtitle_card_underflow() {
        let brand = Some("Mastercard".to_owned());
        let number = Some("4".to_owned());

        let subtitle = build_subtitle_card(brand, number);
        assert_eq!(subtitle, "Mastercard");
    }

    #[test]
    fn test_build_subtitle_card_only_brand() {
        let brand = Some("Mastercard".to_owned());
        let number = None;

        let subtitle = build_subtitle_card(brand, number);
        assert_eq!(subtitle, "Mastercard");
    }

    #[test]
    fn test_build_subtitle_card_only_card() {
        let brand = None;
        let number = Some("5555555555554444".to_owned());

        let subtitle = build_subtitle_card(brand, number);
        assert_eq!(subtitle, "*4444");
    }

    #[test]
    fn test_build_subtitle_identity() {
        let first_name = Some("John".to_owned());
        let last_name = Some("Doe".to_owned());

        let subtitle = build_subtitle_identity(first_name, last_name);
        assert_eq!(subtitle, "John Doe");
    }

    #[test]
    fn test_build_subtitle_identity_only_first() {
        let first_name = Some("John".to_owned());
        let last_name = None;

        let subtitle = build_subtitle_identity(first_name, last_name);
        assert_eq!(subtitle, "John");
    }

    #[test]
    fn test_build_subtitle_identity_only_last() {
        let first_name = None;
        let last_name = Some("Doe".to_owned());

        let subtitle = build_subtitle_identity(first_name, last_name);
        assert_eq!(subtitle, "Doe");
    }

    #[test]
    fn test_build_subtitle_identity_none() {
        let first_name = None;
        let last_name = None;

        let subtitle = build_subtitle_identity(first_name, last_name);
        assert_eq!(subtitle, "");
    }

    #[test]
    fn test_subtitle_ssh_key() {
        let key = SymmetricCryptoKey::try_from("hvBMMb1t79YssFZkpetYsM3deyVuQv4r88Uj9gvYe0+G8EwxvW3v1iywVmSl61iwzd17JW5C/ivzxSP2C9h7Tw==".to_string()).unwrap();
        let key_store = create_test_crypto_with_user_key(key);
        let key = SymmetricKeyId::User;
        let mut ctx = key_store.context();

        let original_subtitle = "SHA256:1JjFjvPRkj1Gbf2qRP1dgHiIzEuNAEvp+92x99jw3K0".to_string();
        let fingerprint_encrypted = original_subtitle.to_owned().encrypt(&mut ctx, key).unwrap();
        let private_key_encrypted = "".to_string().encrypt(&mut ctx, key).unwrap();
        let public_key_encrypted = "".to_string().encrypt(&mut ctx, key).unwrap();
        let ssh_key_cipher = Cipher {
            id: Some("090c19ea-a61a-4df6-8963-262b97bc6266".parse().unwrap()),
            organization_id: None,
            folder_id: None,
            collection_ids: vec![],
            r#type: CipherType::SshKey,
            key: None,
            name: "My test ssh key"
                .to_string()
                .encrypt(&mut ctx, key)
                .unwrap(),
            notes: None,
            login: None,
            identity: None,
            card: None,
            secure_note: None,
            ssh_key: Some(SshKey {
                private_key: private_key_encrypted,
                public_key: public_key_encrypted,
                fingerprint: fingerprint_encrypted,
            }),
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
            creation_date: "2024-01-01T00:00:00.000Z".parse().unwrap(),
            deleted_date: None,
            revision_date: "2024-01-01T00:00:00.000Z".parse().unwrap(),
        };
        let subtitle = ssh_key_cipher
            .get_decrypted_subtitle(&mut ctx, key)
            .unwrap();
        assert_eq!(subtitle, original_subtitle);
    }
}
