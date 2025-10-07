use bitwarden_api_api::models::CipherIdentityModel;
use bitwarden_core::key_management::{KeyIds, SymmetricKeyId};
use bitwarden_crypto::{
    CompositeEncryptable, CryptoError, Decryptable, EncString, KeyStoreContext,
    PrimitiveEncryptable,
};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;

use super::cipher::CipherKind;
use crate::{Cipher, VaultParseError, cipher::cipher::CopyableCipherFields};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
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

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
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

impl CompositeEncryptable<KeyIds, SymmetricKeyId, Identity> for IdentityView {
    fn encrypt_composite(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<Identity, CryptoError> {
        Ok(Identity {
            title: self.title.encrypt(ctx, key)?,
            first_name: self.first_name.encrypt(ctx, key)?,
            middle_name: self.middle_name.encrypt(ctx, key)?,
            last_name: self.last_name.encrypt(ctx, key)?,
            address1: self.address1.encrypt(ctx, key)?,
            address2: self.address2.encrypt(ctx, key)?,
            address3: self.address3.encrypt(ctx, key)?,
            city: self.city.encrypt(ctx, key)?,
            state: self.state.encrypt(ctx, key)?,
            postal_code: self.postal_code.encrypt(ctx, key)?,
            country: self.country.encrypt(ctx, key)?,
            company: self.company.encrypt(ctx, key)?,
            email: self.email.encrypt(ctx, key)?,
            phone: self.phone.encrypt(ctx, key)?,
            ssn: self.ssn.encrypt(ctx, key)?,
            username: self.username.encrypt(ctx, key)?,
            passport_number: self.passport_number.encrypt(ctx, key)?,
            license_number: self.license_number.encrypt(ctx, key)?,
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

impl CipherKind for Identity {
    fn decrypt_subtitle(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<String, CryptoError> {
        let first_name = self
            .first_name
            .as_ref()
            .map(|f| f.decrypt(ctx, key))
            .transpose()?;
        let last_name = self
            .last_name
            .as_ref()
            .map(|l| l.decrypt(ctx, key))
            .transpose()?;

        Ok(build_subtitle_identity(first_name, last_name))
    }

    fn get_copyable_fields(&self, _: Option<&Cipher>) -> Vec<CopyableCipherFields> {
        [
            self.username
                .as_ref()
                .map(|_| CopyableCipherFields::IdentityUsername),
            self.email
                .as_ref()
                .map(|_| CopyableCipherFields::IdentityEmail),
            self.phone
                .as_ref()
                .map(|_| CopyableCipherFields::IdentityPhone),
            self.address1
                .as_ref()
                .or(self.address2.as_ref())
                .or(self.address3.as_ref())
                .or(self.city.as_ref())
                .or(self.state.as_ref())
                .or(self.postal_code.as_ref())
                .map(|_| CopyableCipherFields::IdentityAddress),
        ]
        .into_iter()
        .flatten()
        .collect()
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::cipher::CopyableCipherFields;

    fn create_identity() -> Identity {
        Identity {
            title: None,
            first_name: None,
            middle_name: None,
            last_name: None,
            address1: None,
            address2: None,
            address3: None,
            city: None,
            state: None,
            postal_code: None,
            country: None,
            company: None,
            email: None,
            phone: None,
            ssn: None,
            username: None,
            passport_number: None,
            license_number: None,
        }
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
    fn test_get_copyable_fields_identity_empty() {
        let identity = create_identity();

        let copyable_fields = identity.get_copyable_fields(None);
        assert_eq!(copyable_fields, vec![]);
    }

    #[test]
    fn test_get_copyable_fields_identity_has_username() {
        let mut identity = create_identity();
        identity.username = Some("2.yXXpPbsf6NZhLVkNe/i4Bw==|ol/HTI++aMO1peBBBhSR7Q==|awNmmj31efIXTzaru42/Ay+bQ6V+1MrKxXh1Uo5gca8=".parse().unwrap());

        let copyable_fields = identity.get_copyable_fields(None);
        assert_eq!(
            copyable_fields,
            vec![CopyableCipherFields::IdentityUsername]
        );
    }

    #[test]
    fn test_get_copyable_fields_identity_has_email() {
        let mut identity = create_identity();
        identity.email = Some("2.yXXpPbsf6NZhLVkNe/i4Bw==|ol/HTI++aMO1peBBBhSR7Q==|awNmmj31efIXTzaru42/Ay+bQ6V+1MrKxXh1Uo5gca8=".parse().unwrap());

        let copyable_fields = identity.get_copyable_fields(None);
        assert_eq!(copyable_fields, vec![CopyableCipherFields::IdentityEmail]);
    }

    #[test]
    fn test_get_copyable_fields_identity_has_phone() {
        let mut identity = create_identity();
        identity.phone = Some("2.yXXpPbsf6NZhLVkNe/i4Bw==|ol/HTI++aMO1peBBBhSR7Q==|awNmmj31efIXTzaru42/Ay+bQ6V+1MrKxXh1Uo5gca8=".parse().unwrap());

        let copyable_fields = identity.get_copyable_fields(None);
        assert_eq!(copyable_fields, vec![CopyableCipherFields::IdentityPhone]);
    }

    #[test]
    fn test_get_copyable_fields_identity_has_address() {
        let mut identity = create_identity();

        identity.address1 = Some("2.yXXpPbsf6NZhLVkNe/i4Bw==|ol/HTI++aMO1peBBBhSR7Q==|awNmmj31efIXTzaru42/Ay+bQ6V+1MrKxXh1Uo5gca8=".parse().unwrap());

        let mut copyable_fields = identity.get_copyable_fields(None);

        assert_eq!(copyable_fields, vec![CopyableCipherFields::IdentityAddress]);

        identity.state = Some("2.yXXpPbsf6NZhLVkNe/i4Bw==|ol/HTI++aMO1peBBBhSR7Q==|awNmmj31efIXTzaru42/Ay+bQ6V+1MrKxXh1Uo5gca8=".parse().unwrap());
        identity.address1 = None;

        copyable_fields = identity.get_copyable_fields(None);
        assert_eq!(copyable_fields, vec![CopyableCipherFields::IdentityAddress]);
    }
}
