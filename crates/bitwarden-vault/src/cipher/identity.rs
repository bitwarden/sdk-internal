use bitwarden_api_api::models::CipherIdentityModel;
use bitwarden_core::key_management::{KeyIds, SymmetricKeyId};
use bitwarden_crypto::{ContentFormat, CryptoError, Decryptable, EncString, Encryptable, KeyStoreContext};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::VaultParseError;

#[derive(Serialize, Deserialize, Debug, JsonSchema, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct Identity {
    pub title: Option<EncString>,
    pub first_name: Option<EncString>,
    pub middle_name: Option<EncString>,
    pub last_name: Option<EncString>,
    pub address1: Option<EncString>,
    pub address2: Option<EncString>,
    pub address3: Option<EncString>,
    pub city: Option<EncString>,
    pub state: Option<EncString>,
    pub postal_code: Option<EncString>,
    pub country: Option<EncString>,
    pub company: Option<EncString>,
    pub email: Option<EncString>,
    pub phone: Option<EncString>,
    pub ssn: Option<EncString>,
    pub username: Option<EncString>,
    pub passport_number: Option<EncString>,
    pub license_number: Option<EncString>,
}

#[derive(Serialize, Deserialize, Debug, JsonSchema, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct IdentityView {
    pub title: Option<String>,
    pub first_name: Option<String>,
    pub middle_name: Option<String>,
    pub last_name: Option<String>,
    pub address1: Option<String>,
    pub address2: Option<String>,
    pub address3: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
    pub company: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub ssn: Option<String>,
    pub username: Option<String>,
    pub passport_number: Option<String>,
    pub license_number: Option<String>,
}

impl Encryptable<KeyIds, SymmetricKeyId, Identity> for IdentityView {
    fn encrypt(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
        _content_format: ContentFormat,
    ) -> Result<Identity, CryptoError> {
        Ok(Identity {
            title: self.title.encrypt(ctx, key, ContentFormat::Utf8)?,
            first_name: self.first_name.encrypt(ctx, key, ContentFormat::Utf8)?,
            middle_name: self.middle_name.encrypt(ctx, key, ContentFormat::Utf8)?,
            last_name: self.last_name.encrypt(ctx, key, ContentFormat::Utf8)?,
            address1: self.address1.encrypt(ctx, key, ContentFormat::Utf8)?,
            address2: self.address2.encrypt(ctx, key, ContentFormat::Utf8)?,
            address3: self.address3.encrypt(ctx, key, ContentFormat::Utf8)?,
            city: self.city.encrypt(ctx, key, ContentFormat::Utf8)?,
            state: self.state.encrypt(ctx, key, ContentFormat::Utf8)?,
            postal_code: self.postal_code.encrypt(ctx, key, ContentFormat::Utf8)?,
            country: self.country.encrypt(ctx, key, ContentFormat::Utf8)?,
            company: self.company.encrypt(ctx, key, ContentFormat::Utf8)?,
            email: self.email.encrypt(ctx, key, ContentFormat::Utf8)?,
            phone: self.phone.encrypt(ctx, key, ContentFormat::Utf8)?,
            ssn: self.ssn.encrypt(ctx, key, ContentFormat::Utf8)?,
            username: self.username.encrypt(ctx, key, ContentFormat::Utf8)?,
            passport_number: self.passport_number.encrypt(ctx, key, ContentFormat::Utf8)?,
            license_number: self.license_number.encrypt(ctx, key, ContentFormat::Utf8)?,
        })
    }
}

impl Decryptable<KeyIds, SymmetricKeyId, IdentityView> for Identity {
    fn decrypt(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<IdentityView, CryptoError> {
        Ok(IdentityView {
            title: self.title.decrypt(ctx, key).ok().flatten(),
            first_name: self.first_name.decrypt(ctx, key).ok().flatten(),
            middle_name: self.middle_name.decrypt(ctx, key).ok().flatten(),
            last_name: self.last_name.decrypt(ctx, key).ok().flatten(),
            address1: self.address1.decrypt(ctx, key).ok().flatten(),
            address2: self.address2.decrypt(ctx, key).ok().flatten(),
            address3: self.address3.decrypt(ctx, key).ok().flatten(),
            city: self.city.decrypt(ctx, key).ok().flatten(),
            state: self.state.decrypt(ctx, key).ok().flatten(),
            postal_code: self.postal_code.decrypt(ctx, key).ok().flatten(),
            country: self.country.decrypt(ctx, key).ok().flatten(),
            company: self.company.decrypt(ctx, key).ok().flatten(),
            email: self.email.decrypt(ctx, key).ok().flatten(),
            phone: self.phone.decrypt(ctx, key).ok().flatten(),
            ssn: self.ssn.decrypt(ctx, key).ok().flatten(),
            username: self.username.decrypt(ctx, key).ok().flatten(),
            passport_number: self.passport_number.decrypt(ctx, key).ok().flatten(),
            license_number: self.license_number.decrypt(ctx, key).ok().flatten(),
        })
    }
}

impl TryFrom<CipherIdentityModel> for Identity {
    type Error = VaultParseError;

    fn try_from(identity: CipherIdentityModel) -> Result<Self, Self::Error> {
        Ok(Self {
            title: EncString::try_from_optional(identity.title)?,
            first_name: EncString::try_from_optional(identity.first_name)?,
            middle_name: EncString::try_from_optional(identity.middle_name)?,
            last_name: EncString::try_from_optional(identity.last_name)?,
            address1: EncString::try_from_optional(identity.address1)?,
            address2: EncString::try_from_optional(identity.address2)?,
            address3: EncString::try_from_optional(identity.address3)?,
            city: EncString::try_from_optional(identity.city)?,
            state: EncString::try_from_optional(identity.state)?,
            postal_code: EncString::try_from_optional(identity.postal_code)?,
            country: EncString::try_from_optional(identity.country)?,
            company: EncString::try_from_optional(identity.company)?,
            email: EncString::try_from_optional(identity.email)?,
            phone: EncString::try_from_optional(identity.phone)?,
            ssn: EncString::try_from_optional(identity.ssn)?,
            username: EncString::try_from_optional(identity.username)?,
            passport_number: EncString::try_from_optional(identity.passport_number)?,
            license_number: EncString::try_from_optional(identity.license_number)?,
        })
    }
}
