use bitwarden_api_api::models::{CipherLoginModel, CipherLoginUriModel};
use bitwarden_core::{
    key_management::{KeyIds, SymmetricKeyId},
    require,
};
use bitwarden_crypto::{
    CompositeEncryptable, CryptoError, Decryptable, EncString, KeyStoreContext,
    PrimitiveEncryptable,
};
use bitwarden_encoding::B64;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use super::cipher::CipherKind;
use crate::{Cipher, VaultParseError, cipher::cipher::CopyableCipherFields};

#[allow(missing_docs)]
#[derive(Clone, Copy, Serialize_repr, Deserialize_repr, Debug, PartialEq)]
#[repr(u8)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub enum UriMatchType {
    Domain = 0,
    Host = 1,
    StartsWith = 2,
    Exact = 3,
    RegularExpression = 4,
    Never = 5,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct LoginUri {
    pub uri: Option<EncString>,
    pub r#match: Option<UriMatchType>,
    pub uri_checksum: Option<EncString>,
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct LoginUriView {
    pub uri: Option<String>,
    pub r#match: Option<UriMatchType>,
    pub uri_checksum: Option<String>,
}

impl LoginUriView {
    pub(crate) fn is_checksum_valid(&self) -> bool {
        let Some(uri) = &self.uri else {
            return false;
        };
        let Some(cs) = &self.uri_checksum else {
            return false;
        };
        let Ok(cs) = B64::try_from(cs.as_str()) else {
            return false;
        };

        use sha2::Digest;
        let uri_hash = sha2::Sha256::new().chain_update(uri.as_bytes()).finalize();

        uri_hash.as_slice() == cs.as_bytes()
    }

    pub(crate) fn generate_checksum(&mut self) {
        if let Some(uri) = &self.uri {
            use sha2::Digest;
            let uri_hash = sha2::Sha256::new().chain_update(uri.as_bytes()).finalize();
            let uri_hash = B64::from(uri_hash.as_slice()).to_string();
            self.uri_checksum = Some(uri_hash);
        }
    }
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct Fido2Credential {
    pub credential_id: EncString,
    pub key_type: EncString,
    pub key_algorithm: EncString,
    pub key_curve: EncString,
    pub key_value: EncString,
    pub rp_id: EncString,
    pub user_handle: Option<EncString>,
    pub user_name: Option<EncString>,
    pub counter: EncString,
    pub rp_name: Option<EncString>,
    pub user_display_name: Option<EncString>,
    pub discoverable: EncString,
    pub creation_date: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct Fido2CredentialListView {
    pub credential_id: String,
    pub rp_id: String,
    pub user_handle: Option<String>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    pub counter: String,
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct Fido2CredentialView {
    pub credential_id: String,
    pub key_type: String,
    pub key_algorithm: String,
    pub key_curve: String,
    // This value doesn't need to be returned to the client
    // so we keep it encrypted until we need it
    pub key_value: EncString,
    pub rp_id: String,
    pub user_handle: Option<String>,
    pub user_name: Option<String>,
    pub counter: String,
    pub rp_name: Option<String>,
    pub user_display_name: Option<String>,
    pub discoverable: String,
    pub creation_date: DateTime<Utc>,
}

// This is mostly a copy of the Fido2CredentialView, but with the key exposed
// Only meant to be used internally and not exposed to the outside world
#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct Fido2CredentialFullView {
    pub credential_id: String,
    pub key_type: String,
    pub key_algorithm: String,
    pub key_curve: String,
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

// This is mostly a copy of the Fido2CredentialView, meant to be exposed to the clients
// to let them select where to store the new credential. Note that it doesn't contain
// the encrypted key as that is only filled when the cipher is selected
#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct Fido2CredentialNewView {
    pub credential_id: String,
    pub key_type: String,
    pub key_algorithm: String,
    pub key_curve: String,
    pub rp_id: String,
    pub user_handle: Option<String>,
    pub user_name: Option<String>,
    pub counter: String,
    pub rp_name: Option<String>,
    pub user_display_name: Option<String>,
    pub creation_date: DateTime<Utc>,
}

impl From<Fido2CredentialFullView> for Fido2CredentialNewView {
    fn from(value: Fido2CredentialFullView) -> Self {
        Fido2CredentialNewView {
            credential_id: value.credential_id,
            key_type: value.key_type,
            key_algorithm: value.key_algorithm,
            key_curve: value.key_curve,
            rp_id: value.rp_id,
            user_handle: value.user_handle,
            user_name: value.user_name,
            counter: value.counter,
            rp_name: value.rp_name,
            user_display_name: value.user_display_name,
            creation_date: value.creation_date,
        }
    }
}

impl CompositeEncryptable<KeyIds, SymmetricKeyId, Fido2Credential> for Fido2CredentialFullView {
    fn encrypt_composite(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<Fido2Credential, CryptoError> {
        Ok(Fido2Credential {
            credential_id: self.credential_id.encrypt(ctx, key)?,
            key_type: self.key_type.encrypt(ctx, key)?,
            key_algorithm: self.key_algorithm.encrypt(ctx, key)?,
            key_curve: self.key_curve.encrypt(ctx, key)?,
            key_value: self.key_value.encrypt(ctx, key)?,
            rp_id: self.rp_id.encrypt(ctx, key)?,
            user_handle: self
                .user_handle
                .as_ref()
                .map(|h| h.encrypt(ctx, key))
                .transpose()?,
            user_name: self.user_name.encrypt(ctx, key)?,
            counter: self.counter.encrypt(ctx, key)?,
            rp_name: self.rp_name.encrypt(ctx, key)?,
            user_display_name: self.user_display_name.encrypt(ctx, key)?,
            discoverable: self.discoverable.encrypt(ctx, key)?,
            creation_date: self.creation_date,
        })
    }
}

impl Decryptable<KeyIds, SymmetricKeyId, Fido2CredentialFullView> for Fido2Credential {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<Fido2CredentialFullView, CryptoError> {
        Ok(Fido2CredentialFullView {
            credential_id: self.credential_id.decrypt(ctx, key)?,
            key_type: self.key_type.decrypt(ctx, key)?,
            key_algorithm: self.key_algorithm.decrypt(ctx, key)?,
            key_curve: self.key_curve.decrypt(ctx, key)?,
            key_value: self.key_value.decrypt(ctx, key)?,
            rp_id: self.rp_id.decrypt(ctx, key)?,
            user_handle: self.user_handle.decrypt(ctx, key)?,
            user_name: self.user_name.decrypt(ctx, key)?,
            counter: self.counter.decrypt(ctx, key)?,
            rp_name: self.rp_name.decrypt(ctx, key)?,
            user_display_name: self.user_display_name.decrypt(ctx, key)?,
            discoverable: self.discoverable.decrypt(ctx, key)?,
            creation_date: self.creation_date,
        })
    }
}

impl Decryptable<KeyIds, SymmetricKeyId, Fido2CredentialFullView> for Fido2CredentialView {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<Fido2CredentialFullView, CryptoError> {
        Ok(Fido2CredentialFullView {
            credential_id: self.credential_id.clone(),
            key_type: self.key_type.clone(),
            key_algorithm: self.key_algorithm.clone(),
            key_curve: self.key_curve.clone(),
            key_value: self.key_value.decrypt(ctx, key)?,
            rp_id: self.rp_id.clone(),
            user_handle: self.user_handle.clone(),
            user_name: self.user_name.clone(),
            counter: self.counter.clone(),
            rp_name: self.rp_name.clone(),
            user_display_name: self.user_display_name.clone(),
            discoverable: self.discoverable.clone(),
            creation_date: self.creation_date,
        })
    }
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct Login {
    pub username: Option<EncString>,
    pub password: Option<EncString>,
    pub password_revision_date: Option<DateTime<Utc>>,

    pub uris: Option<Vec<LoginUri>>,
    pub totp: Option<EncString>,
    pub autofill_on_page_load: Option<bool>,

    pub fido2_credentials: Option<Vec<Fido2Credential>>,
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct LoginView {
    pub username: Option<String>,
    pub password: Option<String>,
    pub password_revision_date: Option<DateTime<Utc>>,

    pub uris: Option<Vec<LoginUriView>>,
    pub totp: Option<String>,
    pub autofill_on_page_load: Option<bool>,

    // TODO: Remove this once the SDK supports state
    pub fido2_credentials: Option<Vec<Fido2Credential>>,
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct LoginListView {
    pub fido2_credentials: Option<Vec<Fido2CredentialListView>>,
    pub has_fido2: bool,
    pub username: Option<String>,
    /// The TOTP key is not decrypted. Useable as is with [`crate::generate_totp_cipher_view`].
    pub totp: Option<EncString>,
    pub uris: Option<Vec<LoginUriView>>,
}

impl CompositeEncryptable<KeyIds, SymmetricKeyId, LoginUri> for LoginUriView {
    fn encrypt_composite(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<LoginUri, CryptoError> {
        Ok(LoginUri {
            uri: self.uri.encrypt(ctx, key)?,
            r#match: self.r#match,
            uri_checksum: self.uri_checksum.encrypt(ctx, key)?,
        })
    }
}

impl CompositeEncryptable<KeyIds, SymmetricKeyId, Login> for LoginView {
    fn encrypt_composite(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<Login, CryptoError> {
        Ok(Login {
            username: self.username.encrypt(ctx, key)?,
            password: self.password.encrypt(ctx, key)?,
            password_revision_date: self.password_revision_date,
            uris: self.uris.encrypt_composite(ctx, key)?,
            totp: self.totp.encrypt(ctx, key)?,
            autofill_on_page_load: self.autofill_on_page_load,
            fido2_credentials: self.fido2_credentials.clone(),
        })
    }
}

impl Decryptable<KeyIds, SymmetricKeyId, LoginUriView> for LoginUri {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<LoginUriView, CryptoError> {
        Ok(LoginUriView {
            uri: self.uri.decrypt(ctx, key)?,
            r#match: self.r#match,
            uri_checksum: self.uri_checksum.decrypt(ctx, key)?,
        })
    }
}

impl Decryptable<KeyIds, SymmetricKeyId, LoginView> for Login {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<LoginView, CryptoError> {
        Ok(LoginView {
            username: self.username.decrypt(ctx, key).ok().flatten(),
            password: self.password.decrypt(ctx, key).ok().flatten(),
            password_revision_date: self.password_revision_date,
            uris: self.uris.decrypt(ctx, key).ok().flatten(),
            totp: self.totp.decrypt(ctx, key).ok().flatten(),
            autofill_on_page_load: self.autofill_on_page_load,
            fido2_credentials: self.fido2_credentials.clone(),
        })
    }
}

impl Decryptable<KeyIds, SymmetricKeyId, LoginListView> for Login {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<LoginListView, CryptoError> {
        Ok(LoginListView {
            fido2_credentials: self
                .fido2_credentials
                .as_ref()
                .map(|fido2_credentials| fido2_credentials.decrypt(ctx, key))
                .transpose()?,
            has_fido2: self.fido2_credentials.is_some(),
            username: self.username.decrypt(ctx, key).ok().flatten(),
            totp: self.totp.clone(),
            uris: self.uris.decrypt(ctx, key).ok().flatten(),
        })
    }
}

impl CompositeEncryptable<KeyIds, SymmetricKeyId, Fido2Credential> for Fido2CredentialView {
    fn encrypt_composite(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<Fido2Credential, CryptoError> {
        Ok(Fido2Credential {
            credential_id: self.credential_id.encrypt(ctx, key)?,
            key_type: self.key_type.encrypt(ctx, key)?,
            key_algorithm: self.key_algorithm.encrypt(ctx, key)?,
            key_curve: self.key_curve.encrypt(ctx, key)?,
            key_value: self.key_value.clone(),
            rp_id: self.rp_id.encrypt(ctx, key)?,
            user_handle: self
                .user_handle
                .as_ref()
                .map(|h| h.encrypt(ctx, key))
                .transpose()?,
            user_name: self
                .user_name
                .as_ref()
                .map(|n| n.encrypt(ctx, key))
                .transpose()?,
            counter: self.counter.encrypt(ctx, key)?,
            rp_name: self.rp_name.encrypt(ctx, key)?,
            user_display_name: self.user_display_name.encrypt(ctx, key)?,
            discoverable: self.discoverable.encrypt(ctx, key)?,
            creation_date: self.creation_date,
        })
    }
}

impl Decryptable<KeyIds, SymmetricKeyId, Fido2CredentialView> for Fido2Credential {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<Fido2CredentialView, CryptoError> {
        Ok(Fido2CredentialView {
            credential_id: self.credential_id.decrypt(ctx, key)?,
            key_type: self.key_type.decrypt(ctx, key)?,
            key_algorithm: self.key_algorithm.decrypt(ctx, key)?,
            key_curve: self.key_curve.decrypt(ctx, key)?,
            key_value: self.key_value.clone(),
            rp_id: self.rp_id.decrypt(ctx, key)?,
            user_handle: self.user_handle.decrypt(ctx, key)?,
            user_name: self.user_name.decrypt(ctx, key)?,
            counter: self.counter.decrypt(ctx, key)?,
            rp_name: self.rp_name.decrypt(ctx, key)?,
            user_display_name: self.user_display_name.decrypt(ctx, key)?,
            discoverable: self.discoverable.decrypt(ctx, key)?,
            creation_date: self.creation_date,
        })
    }
}

impl Decryptable<KeyIds, SymmetricKeyId, Fido2CredentialListView> for Fido2Credential {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<Fido2CredentialListView, CryptoError> {
        Ok(Fido2CredentialListView {
            credential_id: self.credential_id.decrypt(ctx, key)?,
            rp_id: self.rp_id.decrypt(ctx, key)?,
            user_handle: self.user_handle.decrypt(ctx, key)?,
            user_name: self.user_name.decrypt(ctx, key)?,
            user_display_name: self.user_display_name.decrypt(ctx, key)?,
            counter: self.counter.decrypt(ctx, key)?,
        })
    }
}

impl TryFrom<CipherLoginModel> for Login {
    type Error = VaultParseError;

    fn try_from(login: CipherLoginModel) -> Result<Self, Self::Error> {
        Ok(Self {
            username: EncString::try_from_optional(login.username)?,
            password: EncString::try_from_optional(login.password)?,
            password_revision_date: login
                .password_revision_date
                .map(|d| d.parse())
                .transpose()?,
            uris: login
                .uris
                .map(|v| v.into_iter().map(|u| u.try_into()).collect())
                .transpose()?,
            totp: EncString::try_from_optional(login.totp)?,
            autofill_on_page_load: login.autofill_on_page_load,
            fido2_credentials: login
                .fido2_credentials
                .map(|v| v.into_iter().map(|c| c.try_into()).collect())
                .transpose()?,
        })
    }
}

impl TryFrom<CipherLoginUriModel> for LoginUri {
    type Error = VaultParseError;

    fn try_from(uri: CipherLoginUriModel) -> Result<Self, Self::Error> {
        Ok(Self {
            uri: EncString::try_from_optional(uri.uri)?,
            r#match: uri.r#match.map(|m| m.into()),
            uri_checksum: EncString::try_from_optional(uri.uri_checksum)?,
        })
    }
}

impl From<bitwarden_api_api::models::UriMatchType> for UriMatchType {
    fn from(value: bitwarden_api_api::models::UriMatchType) -> Self {
        match value {
            bitwarden_api_api::models::UriMatchType::Domain => Self::Domain,
            bitwarden_api_api::models::UriMatchType::Host => Self::Host,
            bitwarden_api_api::models::UriMatchType::StartsWith => Self::StartsWith,
            bitwarden_api_api::models::UriMatchType::Exact => Self::Exact,
            bitwarden_api_api::models::UriMatchType::RegularExpression => Self::RegularExpression,
            bitwarden_api_api::models::UriMatchType::Never => Self::Never,
        }
    }
}

impl TryFrom<bitwarden_api_api::models::CipherFido2CredentialModel> for Fido2Credential {
    type Error = VaultParseError;

    fn try_from(
        value: bitwarden_api_api::models::CipherFido2CredentialModel,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            credential_id: require!(value.credential_id).parse()?,
            key_type: require!(value.key_type).parse()?,
            key_algorithm: require!(value.key_algorithm).parse()?,
            key_curve: require!(value.key_curve).parse()?,
            key_value: require!(value.key_value).parse()?,
            rp_id: require!(value.rp_id).parse()?,
            user_handle: EncString::try_from_optional(value.user_handle)
                .ok()
                .flatten(),
            user_name: EncString::try_from_optional(value.user_name).ok().flatten(),
            counter: require!(value.counter).parse()?,
            rp_name: EncString::try_from_optional(value.rp_name).ok().flatten(),
            user_display_name: EncString::try_from_optional(value.user_display_name)
                .ok()
                .flatten(),
            discoverable: require!(value.discoverable).parse()?,
            creation_date: value.creation_date.parse()?,
        })
    }
}

impl CipherKind for Login {
    fn decrypt_subtitle(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<String, CryptoError> {
        let username: Option<String> = self.username.decrypt(ctx, key)?;

        Ok(username.unwrap_or_default())
    }

    fn get_copyable_fields(&self, _: Option<&Cipher>) -> Vec<CopyableCipherFields> {
        [
            self.username
                .as_ref()
                .map(|_| CopyableCipherFields::LoginUsername),
            self.password
                .as_ref()
                .map(|_| CopyableCipherFields::LoginPassword),
            self.totp.as_ref().map(|_| CopyableCipherFields::LoginTotp),
        ]
        .into_iter()
        .flatten()
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        Login,
        cipher::cipher::{CipherKind, CopyableCipherFields},
    };

    #[test]
    fn test_valid_checksum() {
        let uri = super::LoginUriView {
            uri: Some("https://example.com".to_string()),
            r#match: Some(super::UriMatchType::Domain),
            uri_checksum: Some("EAaArVRs5qV39C9S3zO0z9ynVoWeZkuNfeMpsVDQnOk=".to_string()),
        };
        assert!(uri.is_checksum_valid());
    }

    #[test]
    fn test_invalid_checksum() {
        let uri = super::LoginUriView {
            uri: Some("https://example.com".to_string()),
            r#match: Some(super::UriMatchType::Domain),
            uri_checksum: Some("UtSgIv8LYfEdOu7yqjF7qXWhmouYGYC8RSr7/ryZg5Q=".to_string()),
        };
        assert!(!uri.is_checksum_valid());
    }

    #[test]
    fn test_missing_checksum() {
        let uri = super::LoginUriView {
            uri: Some("https://example.com".to_string()),
            r#match: Some(super::UriMatchType::Domain),
            uri_checksum: None,
        };
        assert!(!uri.is_checksum_valid());
    }

    #[test]
    fn test_generate_checksum() {
        let mut uri = super::LoginUriView {
            uri: Some("https://test.com".to_string()),
            r#match: Some(super::UriMatchType::Domain),
            uri_checksum: None,
        };

        uri.generate_checksum();

        assert_eq!(
            uri.uri_checksum.unwrap().as_str(),
            "OWk2vQvwYD1nhLZdA+ltrpBWbDa2JmHyjUEWxRZSS8w="
        );
    }

    #[test]
    fn test_get_copyable_fields_login_password() {
        let login_with_password = Login {
            username: None,
            password: Some("2.38t4E88QbQEkBdK+oZNHFg==|B3BiDcG3ZfEkD2BK+FMytQ==|2Dw1/f+LCfkCmCj4gKOxOu6CRnZj93qaBYUqbzy/reU=".parse().unwrap()),
            password_revision_date: None,
            uris: None,
            totp: None,
            autofill_on_page_load: None,
            fido2_credentials: None,
        };

        let copyable_fields = login_with_password.get_copyable_fields(None);
        assert_eq!(copyable_fields, vec![CopyableCipherFields::LoginPassword]);
    }

    #[test]
    fn test_get_copyable_fields_login_username() {
        let login_with_username = Login {
            username: Some("2.38t4E88QbQEkBdK+oZNHFg==|B3BiDcG3ZfEkD2BK+FMytQ==|2Dw1/f+LCfkCmCj4gKOxOu6CRnZj93qaBYUqbzy/reU=".parse().unwrap()),
            password: None,
            password_revision_date: None,
            uris: None,
            totp: None,
            autofill_on_page_load: None,
            fido2_credentials: None,
        };

        let copyable_fields = login_with_username.get_copyable_fields(None);
        assert_eq!(copyable_fields, vec![CopyableCipherFields::LoginUsername]);
    }

    #[test]
    fn test_get_copyable_fields_login_everything() {
        let login = Login {
            username: Some("2.38t4E88QbQEkBdK+oZNHFg==|B3BiDcG3ZfEkD2BK+FMytQ==|2Dw1/f+LCfkCmCj4gKOxOu6CRnZj93qaBYUqbzy/reU=".parse().unwrap()),
            password: Some("2.38t4E88QbQEkBdK+oZNHFg==|B3BiDcG3ZfEkD2BK+FMytQ==|2Dw1/f+LCfkCmCj4gKOxOu6CRnZj93qaBYUqbzy/reU=".parse().unwrap()),
            password_revision_date: None,
            uris: None,
            totp: Some("2.38t4E88QbQEkBdK+oZNHFg==|B3BiDcG3ZfEkD2BK+FMytQ==|2Dw1/f+LCfkCmCj4gKOxOu6CRnZj93qaBYUqbzy/reU=".parse().unwrap()),
            autofill_on_page_load: None,
            fido2_credentials: None,
        };

        let copyable_fields = login.get_copyable_fields(None);
        assert_eq!(
            copyable_fields,
            vec![
                CopyableCipherFields::LoginUsername,
                CopyableCipherFields::LoginPassword,
                CopyableCipherFields::LoginTotp
            ]
        );
    }
}
