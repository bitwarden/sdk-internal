use bitwarden_core::key_management::{KeyIds, SymmetricKeyId};
use bitwarden_crypto::{CompositeEncryptable, CryptoError, Decryptable, KeyStoreContext};

use super::v1::*;
use crate::{
    CipherView, PasswordHistoryView,
    cipher::{
        card::CardView,
        cipher::CipherType,
        field::FieldView,
        identity::IdentityView,
        login::{Fido2CredentialFullView, LoginUriView, LoginView},
        secure_note::SecureNoteView,
        ssh_key::SshKeyView,
    },
};

fn none_if_empty<T>(v: Vec<T>) -> Option<Vec<T>> {
    if v.is_empty() { None } else { Some(v) }
}

// --- CardView <-> CardDataV1 ---

impl From<&CardView> for CardDataV1 {
    fn from(view: &CardView) -> Self {
        Self {
            cardholder_name: view.cardholder_name.clone(),
            exp_month: view.exp_month.clone(),
            exp_year: view.exp_year.clone(),
            code: view.code.clone(),
            brand: view.brand.clone(),
            number: view.number.clone(),
        }
    }
}

impl From<&CardDataV1> for CardView {
    fn from(data: &CardDataV1) -> Self {
        Self {
            cardholder_name: data.cardholder_name.clone(),
            exp_month: data.exp_month.clone(),
            exp_year: data.exp_year.clone(),
            code: data.code.clone(),
            brand: data.brand.clone(),
            number: data.number.clone(),
        }
    }
}

// --- IdentityView <-> IdentityDataV1 ---

impl From<&IdentityView> for IdentityDataV1 {
    fn from(view: &IdentityView) -> Self {
        Self {
            title: view.title.clone(),
            first_name: view.first_name.clone(),
            middle_name: view.middle_name.clone(),
            last_name: view.last_name.clone(),
            address1: view.address1.clone(),
            address2: view.address2.clone(),
            address3: view.address3.clone(),
            city: view.city.clone(),
            state: view.state.clone(),
            postal_code: view.postal_code.clone(),
            country: view.country.clone(),
            company: view.company.clone(),
            email: view.email.clone(),
            phone: view.phone.clone(),
            ssn: view.ssn.clone(),
            username: view.username.clone(),
            passport_number: view.passport_number.clone(),
            license_number: view.license_number.clone(),
        }
    }
}

impl From<&IdentityDataV1> for IdentityView {
    fn from(data: &IdentityDataV1) -> Self {
        Self {
            title: data.title.clone(),
            first_name: data.first_name.clone(),
            middle_name: data.middle_name.clone(),
            last_name: data.last_name.clone(),
            address1: data.address1.clone(),
            address2: data.address2.clone(),
            address3: data.address3.clone(),
            city: data.city.clone(),
            state: data.state.clone(),
            postal_code: data.postal_code.clone(),
            country: data.country.clone(),
            company: data.company.clone(),
            email: data.email.clone(),
            phone: data.phone.clone(),
            ssn: data.ssn.clone(),
            username: data.username.clone(),
            passport_number: data.passport_number.clone(),
            license_number: data.license_number.clone(),
        }
    }
}

// --- SecureNoteView <-> SecureNoteDataV1 ---

impl From<&SecureNoteView> for SecureNoteDataV1 {
    fn from(view: &SecureNoteView) -> Self {
        Self {
            r#type: view.r#type,
        }
    }
}

impl From<&SecureNoteDataV1> for SecureNoteView {
    fn from(data: &SecureNoteDataV1) -> Self {
        Self {
            r#type: data.r#type,
        }
    }
}

// --- SshKeyView <-> SshKeyDataV1 ---

impl From<&SshKeyView> for SshKeyDataV1 {
    fn from(view: &SshKeyView) -> Self {
        Self {
            private_key: view.private_key.clone(),
            public_key: view.public_key.clone(),
            fingerprint: view.fingerprint.clone(),
        }
    }
}

impl From<&SshKeyDataV1> for SshKeyView {
    fn from(data: &SshKeyDataV1) -> Self {
        Self {
            private_key: data.private_key.clone(),
            public_key: data.public_key.clone(),
            fingerprint: data.fingerprint.clone(),
        }
    }
}

// --- FieldView <-> FieldDataV1 ---

impl From<&FieldView> for FieldDataV1 {
    fn from(view: &FieldView) -> Self {
        Self {
            name: view.name.clone(),
            value: view.value.clone(),
            r#type: view.r#type,
            linked_id: view.linked_id,
        }
    }
}

impl From<&FieldDataV1> for FieldView {
    fn from(data: &FieldDataV1) -> Self {
        Self {
            name: data.name.clone(),
            value: data.value.clone(),
            r#type: data.r#type,
            linked_id: data.linked_id,
        }
    }
}

// --- PasswordHistoryView <-> PasswordHistoryDataV1 ---

impl From<&PasswordHistoryView> for PasswordHistoryDataV1 {
    fn from(view: &PasswordHistoryView) -> Self {
        Self {
            password: view.password.clone(),
            last_used_date: view.last_used_date,
        }
    }
}

impl From<&PasswordHistoryDataV1> for PasswordHistoryView {
    fn from(data: &PasswordHistoryDataV1) -> Self {
        Self {
            password: data.password.clone(),
            last_used_date: data.last_used_date,
        }
    }
}

// --- LoginUriView <-> LoginUriDataV1 ---

impl From<&LoginUriView> for LoginUriDataV1 {
    fn from(view: &LoginUriView) -> Self {
        Self {
            uri: view.uri.clone(),
            r#match: view.r#match,
        }
    }
}

impl From<&LoginUriDataV1> for LoginUriView {
    fn from(data: &LoginUriDataV1) -> Self {
        Self {
            uri: data.uri.clone(),
            r#match: data.r#match,
            uri_checksum: None,
        }
    }
}

// --- Fido2CredentialFullView <-> Fido2CredentialDataV1 ---

impl From<&Fido2CredentialFullView> for Fido2CredentialDataV1 {
    fn from(view: &Fido2CredentialFullView) -> Self {
        Self {
            credential_id: view.credential_id.clone(),
            key_type: view.key_type.clone(),
            key_algorithm: view.key_algorithm.clone(),
            key_curve: view.key_curve.clone(),
            key_value: view.key_value.clone(),
            rp_id: view.rp_id.clone(),
            user_handle: view.user_handle.clone(),
            user_name: view.user_name.clone(),
            counter: view.counter.parse().unwrap_or(0),
            rp_name: view.rp_name.clone(),
            user_display_name: view.user_display_name.clone(),
            discoverable: view.discoverable == "true",
            creation_date: view.creation_date,
        }
    }
}

impl From<&Fido2CredentialDataV1> for Fido2CredentialFullView {
    fn from(data: &Fido2CredentialDataV1) -> Self {
        Self {
            credential_id: data.credential_id.clone(),
            key_type: data.key_type.clone(),
            key_algorithm: data.key_algorithm.clone(),
            key_curve: data.key_curve.clone(),
            key_value: data.key_value.clone(),
            rp_id: data.rp_id.clone(),
            user_handle: data.user_handle.clone(),
            user_name: data.user_name.clone(),
            counter: data.counter.to_string(),
            rp_name: data.rp_name.clone(),
            user_display_name: data.user_display_name.clone(),
            discoverable: data.discoverable.to_string(),
            creation_date: data.creation_date,
        }
    }
}

// --- Top-level CipherBlobV1 conversions ---

impl CipherBlobV1 {
    pub(crate) fn from_cipher_view(
        view: &CipherView,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<Self, CryptoError> {
        let type_data = match view.r#type {
            CipherType::Login => {
                let login = view
                    .login
                    .as_ref()
                    .ok_or(CryptoError::MissingField("login"))?;

                let fido2_credentials: Vec<Fido2CredentialDataV1> = login
                    .fido2_credentials
                    .as_ref()
                    .map(|creds| -> Result<Vec<_>, CryptoError> {
                        let full_views: Vec<Fido2CredentialFullView> = creds.decrypt(ctx, key)?;
                        Ok(full_views.iter().map(Fido2CredentialDataV1::from).collect())
                    })
                    .transpose()?
                    .unwrap_or_default();

                CipherTypeDataV1::Login(LoginDataV1 {
                    username: login.username.clone(),
                    password: login.password.clone(),
                    password_revision_date: login.password_revision_date,
                    uris: login
                        .uris
                        .as_ref()
                        .map(|u| u.iter().map(LoginUriDataV1::from).collect())
                        .unwrap_or_default(),
                    totp: login.totp.clone(),
                    autofill_on_page_load: login.autofill_on_page_load,
                    fido2_credentials,
                })
            }
            CipherType::Card => {
                let card = view
                    .card
                    .as_ref()
                    .ok_or(CryptoError::MissingField("card"))?;
                CipherTypeDataV1::Card(CardDataV1::from(card))
            }
            CipherType::Identity => {
                let identity = view
                    .identity
                    .as_ref()
                    .ok_or(CryptoError::MissingField("identity"))?;
                CipherTypeDataV1::Identity(IdentityDataV1::from(identity))
            }
            CipherType::SecureNote => {
                let secure_note = view
                    .secure_note
                    .as_ref()
                    .ok_or(CryptoError::MissingField("secure_note"))?;
                CipherTypeDataV1::SecureNote(SecureNoteDataV1::from(secure_note))
            }
            CipherType::SshKey => {
                let ssh_key = view
                    .ssh_key
                    .as_ref()
                    .ok_or(CryptoError::MissingField("ssh_key"))?;
                CipherTypeDataV1::SshKey(SshKeyDataV1::from(ssh_key))
            }
        };

        Ok(Self {
            name: view.name.clone(),
            notes: view.notes.clone(),
            type_data,
            fields: view
                .fields
                .as_ref()
                .map(|f| f.iter().map(FieldDataV1::from).collect())
                .unwrap_or_default(),
            password_history: view
                .password_history
                .as_ref()
                .map(|h| h.iter().map(PasswordHistoryDataV1::from).collect())
                .unwrap_or_default(),
        })
    }

    pub(crate) fn apply_to_cipher_view(
        &self,
        view: &mut CipherView,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<(), CryptoError> {
        view.name = self.name.clone();
        view.notes = self.notes.clone();
        view.fields = none_if_empty(self.fields.iter().map(FieldView::from).collect());
        view.password_history = none_if_empty(
            self.password_history
                .iter()
                .map(PasswordHistoryView::from)
                .collect(),
        );

        match &self.type_data {
            CipherTypeDataV1::Login(login_data) => {
                let fido2_credentials = if login_data.fido2_credentials.is_empty() {
                    None
                } else {
                    let full_views: Vec<Fido2CredentialFullView> = login_data
                        .fido2_credentials
                        .iter()
                        .map(Fido2CredentialFullView::from)
                        .collect();
                    Some(full_views.encrypt_composite(ctx, key)?)
                };

                view.r#type = CipherType::Login;
                view.login = Some(LoginView {
                    username: login_data.username.clone(),
                    password: login_data.password.clone(),
                    password_revision_date: login_data.password_revision_date,
                    uris: none_if_empty(login_data.uris.iter().map(LoginUriView::from).collect()),
                    totp: login_data.totp.clone(),
                    autofill_on_page_load: login_data.autofill_on_page_load,
                    fido2_credentials,
                });
                view.card = None;
                view.identity = None;
                view.secure_note = None;
                view.ssh_key = None;
            }
            CipherTypeDataV1::Card(card_data) => {
                view.r#type = CipherType::Card;
                view.card = Some(CardView::from(card_data));
                view.login = None;
                view.identity = None;
                view.secure_note = None;
                view.ssh_key = None;
            }
            CipherTypeDataV1::Identity(identity_data) => {
                view.r#type = CipherType::Identity;
                view.identity = Some(IdentityView::from(identity_data));
                view.login = None;
                view.card = None;
                view.secure_note = None;
                view.ssh_key = None;
            }
            CipherTypeDataV1::SecureNote(secure_note_data) => {
                view.r#type = CipherType::SecureNote;
                view.secure_note = Some(SecureNoteView::from(secure_note_data));
                view.login = None;
                view.card = None;
                view.identity = None;
                view.ssh_key = None;
            }
            CipherTypeDataV1::SshKey(ssh_key_data) => {
                view.r#type = CipherType::SshKey;
                view.ssh_key = Some(SshKeyView::from(ssh_key_data));
                view.login = None;
                view.card = None;
                view.identity = None;
                view.secure_note = None;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::key_management::{
        KeyIds, SymmetricKeyId, create_test_crypto_with_user_key,
    };
    use bitwarden_crypto::{CompositeEncryptable, Decryptable, SymmetricCryptoKey};
    use chrono::{TimeZone, Utc};

    use super::*;
    use crate::cipher::{
        cipher::{CipherRepromptType, CipherType},
        field::FieldType,
        linked_id::{LinkedIdType, LoginLinkedIdType},
        login::{Fido2Credential, UriMatchType},
        secure_note::SecureNoteType,
    };

    // --- Simple sub-type round-trip tests ---

    #[test]
    fn test_card_round_trip() {
        let view = CardView {
            cardholder_name: Some("John Doe".to_string()),
            exp_month: Some("12".to_string()),
            exp_year: Some("2028".to_string()),
            code: Some("123".to_string()),
            brand: Some("Visa".to_string()),
            number: Some("4111111111111111".to_string()),
        };

        let data = CardDataV1::from(&view);
        let round_tripped = CardView::from(&data);

        assert_eq!(view.cardholder_name, round_tripped.cardholder_name);
        assert_eq!(view.exp_month, round_tripped.exp_month);
        assert_eq!(view.exp_year, round_tripped.exp_year);
        assert_eq!(view.code, round_tripped.code);
        assert_eq!(view.brand, round_tripped.brand);
        assert_eq!(view.number, round_tripped.number);
    }

    #[test]
    fn test_identity_round_trip() {
        let view = IdentityView {
            title: Some("Mr".to_string()),
            first_name: Some("John".to_string()),
            middle_name: Some("Michael".to_string()),
            last_name: Some("Doe".to_string()),
            address1: Some("123 Main St".to_string()),
            address2: Some("Apt 4B".to_string()),
            address3: None,
            city: Some("New York".to_string()),
            state: Some("NY".to_string()),
            postal_code: Some("10001".to_string()),
            country: Some("US".to_string()),
            company: Some("Acme Corp".to_string()),
            email: Some("john@example.com".to_string()),
            phone: Some("555-0123".to_string()),
            ssn: Some("123-45-6789".to_string()),
            username: Some("johndoe".to_string()),
            passport_number: Some("P12345678".to_string()),
            license_number: None,
        };

        let data = IdentityDataV1::from(&view);
        let round_tripped = IdentityView::from(&data);

        assert_eq!(view.title, round_tripped.title);
        assert_eq!(view.first_name, round_tripped.first_name);
        assert_eq!(view.middle_name, round_tripped.middle_name);
        assert_eq!(view.last_name, round_tripped.last_name);
        assert_eq!(view.address1, round_tripped.address1);
        assert_eq!(view.address2, round_tripped.address2);
        assert_eq!(view.address3, round_tripped.address3);
        assert_eq!(view.city, round_tripped.city);
        assert_eq!(view.state, round_tripped.state);
        assert_eq!(view.postal_code, round_tripped.postal_code);
        assert_eq!(view.country, round_tripped.country);
        assert_eq!(view.company, round_tripped.company);
        assert_eq!(view.email, round_tripped.email);
        assert_eq!(view.phone, round_tripped.phone);
        assert_eq!(view.ssn, round_tripped.ssn);
        assert_eq!(view.username, round_tripped.username);
        assert_eq!(view.passport_number, round_tripped.passport_number);
        assert_eq!(view.license_number, round_tripped.license_number);
    }

    #[test]
    fn test_secure_note_round_trip() {
        let view = SecureNoteView {
            r#type: SecureNoteType::Generic,
        };

        let data = SecureNoteDataV1::from(&view);
        let round_tripped = SecureNoteView::from(&data);

        assert_eq!(view.r#type, round_tripped.r#type);
    }

    #[test]
    fn test_ssh_key_round_trip() {
        let view = SshKeyView {
            private_key: "-----BEGIN OPENSSH PRIVATE KEY-----".to_string(),
            public_key: "ssh-ed25519 AAAA".to_string(),
            fingerprint: "SHA256:abc123".to_string(),
        };

        let data = SshKeyDataV1::from(&view);
        let round_tripped = SshKeyView::from(&data);

        assert_eq!(view.private_key, round_tripped.private_key);
        assert_eq!(view.public_key, round_tripped.public_key);
        assert_eq!(view.fingerprint, round_tripped.fingerprint);
    }

    #[test]
    fn test_field_round_trip() {
        let view = FieldView {
            name: Some("Custom Field".to_string()),
            value: Some("custom-value".to_string()),
            r#type: FieldType::Linked,
            linked_id: Some(LinkedIdType::Login(LoginLinkedIdType::Username)),
        };

        let data = FieldDataV1::from(&view);
        let round_tripped = FieldView::from(&data);

        assert_eq!(view.name, round_tripped.name);
        assert_eq!(view.value, round_tripped.value);
        assert_eq!(view.r#type, round_tripped.r#type);
        assert_eq!(view.linked_id, round_tripped.linked_id);
    }

    #[test]
    fn test_password_history_round_trip() {
        let view = PasswordHistoryView {
            password: "old-password".to_string(),
            last_used_date: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
        };

        let data = PasswordHistoryDataV1::from(&view);
        let round_tripped = PasswordHistoryView::from(&data);

        assert_eq!(view.password, round_tripped.password);
        assert_eq!(view.last_used_date, round_tripped.last_used_date);
    }

    // --- LoginUri checksum tests ---

    #[test]
    fn test_login_uri_view_to_data_drops_checksum() {
        let view = LoginUriView {
            uri: Some("https://example.com".to_string()),
            r#match: Some(UriMatchType::Domain),
            uri_checksum: Some("some-checksum-value".to_string()),
        };

        let data = LoginUriDataV1::from(&view);

        assert_eq!(data.uri, Some("https://example.com".to_string()));
        assert_eq!(data.r#match, Some(UriMatchType::Domain));
    }

    #[test]
    fn test_login_uri_data_to_view_sets_checksum_none() {
        let data = LoginUriDataV1 {
            uri: Some("https://example.com".to_string()),
            r#match: Some(UriMatchType::Domain),
        };

        let view = LoginUriView::from(&data);

        assert_eq!(view.uri, Some("https://example.com".to_string()));
        assert_eq!(view.r#match, Some(UriMatchType::Domain));
        assert_eq!(view.uri_checksum, None);
    }

    // --- Fido2 counter/discoverable parsing tests ---

    #[test]
    fn test_fido2_counter_parsing() {
        let full_view = Fido2CredentialFullView {
            credential_id: "cred-id".to_string(),
            key_type: "public-key".to_string(),
            key_algorithm: "ECDSA".to_string(),
            key_curve: "P-256".to_string(),
            key_value: "key-value".to_string(),
            rp_id: "example.com".to_string(),
            user_handle: None,
            user_name: None,
            counter: "42".to_string(),
            rp_name: None,
            user_display_name: None,
            discoverable: "true".to_string(),
            creation_date: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
        };

        let data = Fido2CredentialDataV1::from(&full_view);
        assert_eq!(data.counter, 42);
        assert!(data.discoverable);

        let round_tripped = Fido2CredentialFullView::from(&data);
        assert_eq!(round_tripped.counter, "42");
        assert_eq!(round_tripped.discoverable, "true");
    }

    #[test]
    fn test_fido2_counter_zero() {
        let full_view = Fido2CredentialFullView {
            credential_id: "cred-id".to_string(),
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
            discoverable: "false".to_string(),
            creation_date: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
        };

        let data = Fido2CredentialDataV1::from(&full_view);
        assert_eq!(data.counter, 0);
        assert!(!data.discoverable);

        let round_tripped = Fido2CredentialFullView::from(&data);
        assert_eq!(round_tripped.counter, "0");
        assert_eq!(round_tripped.discoverable, "false");
    }

    #[test]
    fn test_fido2_counter_invalid_defaults_to_zero() {
        let full_view = Fido2CredentialFullView {
            credential_id: "cred-id".to_string(),
            key_type: "public-key".to_string(),
            key_algorithm: "ECDSA".to_string(),
            key_curve: "P-256".to_string(),
            key_value: "key-value".to_string(),
            rp_id: "example.com".to_string(),
            user_handle: None,
            user_name: None,
            counter: "not-a-number".to_string(),
            rp_name: None,
            user_display_name: None,
            discoverable: "true".to_string(),
            creation_date: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
        };

        let data = Fido2CredentialDataV1::from(&full_view);
        assert_eq!(data.counter, 0);
    }

    // --- Option<Vec> normalization tests ---

    #[test]
    fn test_none_if_empty() {
        let empty: Vec<i32> = vec![];
        assert_eq!(none_if_empty(empty), None);

        let non_empty = vec![1, 2, 3];
        assert_eq!(none_if_empty(non_empty), Some(vec![1, 2, 3]));
    }

    // --- Full CipherBlobV1 round-trip tests with crypto ---

    fn create_test_key_store() -> (bitwarden_crypto::KeyStore<KeyIds>, SymmetricKeyId) {
        let key = SymmetricCryptoKey::try_from(
            "hvBMMb1t79YssFZkpetYsM3deyVuQv4r88Uj9gvYe0+G8EwxvW3v1iywVmSl61iwzd17JW5C/ivzxSP2C9h7Tw==".to_string(),
        )
        .unwrap();
        let key_store = create_test_crypto_with_user_key(key);
        (key_store, SymmetricKeyId::User)
    }

    fn create_shell_cipher_view(cipher_type: CipherType) -> CipherView {
        CipherView {
            id: None,
            organization_id: None,
            folder_id: None,
            collection_ids: vec![],
            key: None,
            name: String::new(),
            notes: None,
            r#type: cipher_type,
            login: None,
            identity: None,
            card: None,
            secure_note: None,
            ssh_key: None,
            favorite: false,
            reprompt: CipherRepromptType::None,
            organization_use_totp: false,
            edit: true,
            permissions: None,
            view_password: true,
            local_data: None,
            attachments: None,
            attachment_decryption_failures: None,
            fields: None,
            password_history: None,
            creation_date: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            deleted_date: None,
            revision_date: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            archived_date: None,
        }
    }

    #[test]
    fn test_secure_note_cipher_round_trip() {
        let (key_store, key_id) = create_test_key_store();
        let mut ctx = key_store.context_mut();

        let original = CipherView {
            name: "My Secure Note".to_string(),
            notes: Some("Secret notes".to_string()),
            r#type: CipherType::SecureNote,
            secure_note: Some(SecureNoteView {
                r#type: SecureNoteType::Generic,
            }),
            fields: Some(vec![FieldView {
                name: Some("field1".to_string()),
                value: Some("value1".to_string()),
                r#type: FieldType::Text,
                linked_id: None,
            }]),
            password_history: Some(vec![PasswordHistoryView {
                password: "old-pass".to_string(),
                last_used_date: Utc.with_ymd_and_hms(2023, 6, 1, 0, 0, 0).unwrap(),
            }]),
            ..create_shell_cipher_view(CipherType::SecureNote)
        };

        let blob = CipherBlobV1::from_cipher_view(&original, &mut ctx, key_id).unwrap();
        let mut restored = create_shell_cipher_view(CipherType::SecureNote);
        blob.apply_to_cipher_view(&mut restored, &mut ctx, key_id)
            .unwrap();

        assert_eq!(restored.name, original.name);
        assert_eq!(restored.notes, original.notes);
        assert_eq!(restored.r#type, CipherType::SecureNote);
        assert!(restored.secure_note.is_some());
        assert!(restored.login.is_none());
        assert!(restored.card.is_none());
        assert!(restored.identity.is_none());
        assert!(restored.ssh_key.is_none());
        assert_eq!(restored.fields.as_ref().unwrap().len(), 1);
        assert_eq!(
            restored.fields.as_ref().unwrap()[0].name,
            Some("field1".to_string())
        );
        assert_eq!(restored.password_history.as_ref().unwrap().len(), 1);
        assert_eq!(
            restored.password_history.as_ref().unwrap()[0].password,
            "old-pass"
        );
    }

    #[test]
    fn test_card_cipher_round_trip() {
        let (key_store, key_id) = create_test_key_store();
        let mut ctx = key_store.context_mut();

        let original = CipherView {
            name: "My Card".to_string(),
            notes: None,
            r#type: CipherType::Card,
            card: Some(CardView {
                cardholder_name: Some("John Doe".to_string()),
                exp_month: Some("12".to_string()),
                exp_year: Some("2028".to_string()),
                code: Some("123".to_string()),
                brand: Some("Visa".to_string()),
                number: Some("4111111111111111".to_string()),
            }),
            ..create_shell_cipher_view(CipherType::Card)
        };

        let blob = CipherBlobV1::from_cipher_view(&original, &mut ctx, key_id).unwrap();
        let mut restored = create_shell_cipher_view(CipherType::Card);
        blob.apply_to_cipher_view(&mut restored, &mut ctx, key_id)
            .unwrap();

        assert_eq!(restored.name, "My Card");
        assert_eq!(restored.r#type, CipherType::Card);
        let card = restored.card.unwrap();
        assert_eq!(card.cardholder_name, Some("John Doe".to_string()));
        assert_eq!(card.number, Some("4111111111111111".to_string()));
        assert!(restored.login.is_none());
    }

    #[test]
    fn test_identity_cipher_round_trip() {
        let (key_store, key_id) = create_test_key_store();
        let mut ctx = key_store.context_mut();

        let original = CipherView {
            name: "My Identity".to_string(),
            notes: Some("Identity notes".to_string()),
            r#type: CipherType::Identity,
            identity: Some(IdentityView {
                title: Some("Mr".to_string()),
                first_name: Some("John".to_string()),
                middle_name: None,
                last_name: Some("Doe".to_string()),
                address1: Some("123 Main St".to_string()),
                address2: None,
                address3: None,
                city: Some("NYC".to_string()),
                state: Some("NY".to_string()),
                postal_code: Some("10001".to_string()),
                country: Some("US".to_string()),
                company: None,
                email: Some("john@example.com".to_string()),
                phone: None,
                ssn: None,
                username: Some("johndoe".to_string()),
                passport_number: None,
                license_number: None,
            }),
            ..create_shell_cipher_view(CipherType::Identity)
        };

        let blob = CipherBlobV1::from_cipher_view(&original, &mut ctx, key_id).unwrap();
        let mut restored = create_shell_cipher_view(CipherType::Identity);
        blob.apply_to_cipher_view(&mut restored, &mut ctx, key_id)
            .unwrap();

        assert_eq!(restored.name, "My Identity");
        assert_eq!(restored.r#type, CipherType::Identity);
        let identity = restored.identity.unwrap();
        assert_eq!(identity.first_name, Some("John".to_string()));
        assert_eq!(identity.last_name, Some("Doe".to_string()));
        assert_eq!(identity.email, Some("john@example.com".to_string()));
        assert!(restored.login.is_none());
        assert!(restored.card.is_none());
    }

    #[test]
    fn test_ssh_key_cipher_round_trip() {
        let (key_store, key_id) = create_test_key_store();
        let mut ctx = key_store.context_mut();

        let original = CipherView {
            name: "My SSH Key".to_string(),
            notes: None,
            r#type: CipherType::SshKey,
            ssh_key: Some(SshKeyView {
                private_key: "-----BEGIN OPENSSH PRIVATE KEY-----".to_string(),
                public_key: "ssh-ed25519 AAAA".to_string(),
                fingerprint: "SHA256:abc123".to_string(),
            }),
            ..create_shell_cipher_view(CipherType::SshKey)
        };

        let blob = CipherBlobV1::from_cipher_view(&original, &mut ctx, key_id).unwrap();
        let mut restored = create_shell_cipher_view(CipherType::SshKey);
        blob.apply_to_cipher_view(&mut restored, &mut ctx, key_id)
            .unwrap();

        assert_eq!(restored.name, "My SSH Key");
        assert_eq!(restored.r#type, CipherType::SshKey);
        let ssh_key = restored.ssh_key.unwrap();
        assert_eq!(ssh_key.private_key, "-----BEGIN OPENSSH PRIVATE KEY-----");
        assert_eq!(ssh_key.public_key, "ssh-ed25519 AAAA");
        assert!(restored.login.is_none());
    }

    #[test]
    fn test_login_cipher_round_trip() {
        let (key_store, key_id) = create_test_key_store();
        let mut ctx = key_store.context_mut();

        // Create fido2 credentials by encrypting a FullView
        let fido2_full = Fido2CredentialFullView {
            credential_id: "cred-123".to_string(),
            key_type: "public-key".to_string(),
            key_algorithm: "ECDSA".to_string(),
            key_curve: "P-256".to_string(),
            key_value: "key-value-base64".to_string(),
            rp_id: "example.com".to_string(),
            user_handle: Some("user-handle".to_string()),
            user_name: Some("testuser".to_string()),
            counter: "42".to_string(),
            rp_name: Some("Example".to_string()),
            user_display_name: Some("Test User".to_string()),
            discoverable: "true".to_string(),
            creation_date: Utc.with_ymd_and_hms(2024, 6, 1, 10, 30, 0).unwrap(),
        };
        let encrypted_fido2: Fido2Credential =
            fido2_full.encrypt_composite(&mut ctx, key_id).unwrap();

        let original = CipherView {
            name: "My Login".to_string(),
            notes: Some("Login notes".to_string()),
            r#type: CipherType::Login,
            login: Some(LoginView {
                username: Some("testuser@example.com".to_string()),
                password: Some("p@ssw0rd123".to_string()),
                password_revision_date: Some(Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap()),
                uris: Some(vec![LoginUriView {
                    uri: Some("https://example.com/login".to_string()),
                    r#match: Some(UriMatchType::Domain),
                    uri_checksum: Some("some-checksum".to_string()),
                }]),
                totp: Some("otpauth://totp/test?secret=JBSWY3DPEHPK3PXP".to_string()),
                autofill_on_page_load: Some(true),
                fido2_credentials: Some(vec![encrypted_fido2]),
            }),
            fields: Some(vec![FieldView {
                name: Some("Custom Field".to_string()),
                value: Some("custom-value".to_string()),
                r#type: FieldType::Linked,
                linked_id: Some(LinkedIdType::Login(LoginLinkedIdType::Username)),
            }]),
            password_history: Some(vec![PasswordHistoryView {
                password: "old-password-1".to_string(),
                last_used_date: Utc.with_ymd_and_hms(2023, 12, 1, 8, 0, 0).unwrap(),
            }]),
            ..create_shell_cipher_view(CipherType::Login)
        };

        let blob = CipherBlobV1::from_cipher_view(&original, &mut ctx, key_id).unwrap();

        // Verify blob intermediate state
        assert_eq!(blob.name, "My Login");
        assert_eq!(blob.notes, Some("Login notes".to_string()));
        if let CipherTypeDataV1::Login(ref login_data) = blob.type_data {
            assert_eq!(
                login_data.username,
                Some("testuser@example.com".to_string())
            );
            assert_eq!(login_data.fido2_credentials.len(), 1);
            assert_eq!(login_data.fido2_credentials[0].counter, 42);
            assert!(login_data.fido2_credentials[0].discoverable);
            // URI checksum should be dropped
            assert_eq!(login_data.uris.len(), 1);
        } else {
            panic!("Expected Login type data");
        }

        // Round-trip back
        let mut restored = create_shell_cipher_view(CipherType::Login);
        blob.apply_to_cipher_view(&mut restored, &mut ctx, key_id)
            .unwrap();

        assert_eq!(restored.name, "My Login");
        assert_eq!(restored.notes, Some("Login notes".to_string()));
        assert_eq!(restored.r#type, CipherType::Login);

        let login = restored.login.unwrap();
        assert_eq!(login.username, Some("testuser@example.com".to_string()));
        assert_eq!(login.password, Some("p@ssw0rd123".to_string()));
        assert_eq!(
            login.totp,
            Some("otpauth://totp/test?secret=JBSWY3DPEHPK3PXP".to_string())
        );
        assert_eq!(login.autofill_on_page_load, Some(true));

        // URIs should round-trip but checksum is None
        let uris = login.uris.unwrap();
        assert_eq!(uris.len(), 1);
        assert_eq!(uris[0].uri, Some("https://example.com/login".to_string()));
        assert_eq!(uris[0].r#match, Some(UriMatchType::Domain));
        assert_eq!(uris[0].uri_checksum, None);

        // Fido2 credentials should be re-encrypted
        let fido2 = login.fido2_credentials.unwrap();
        assert_eq!(fido2.len(), 1);
        // Decrypt to verify content survived the round-trip
        let decrypted: Fido2CredentialFullView = fido2[0].decrypt(&mut ctx, key_id).unwrap();
        assert_eq!(decrypted.credential_id, "cred-123");
        assert_eq!(decrypted.counter, "42");
        assert_eq!(decrypted.discoverable, "true");
        assert_eq!(decrypted.rp_id, "example.com");

        // Fields and password history
        assert_eq!(restored.fields.as_ref().unwrap().len(), 1);
        assert_eq!(restored.password_history.as_ref().unwrap().len(), 1);

        assert!(restored.card.is_none());
        assert!(restored.identity.is_none());
        assert!(restored.secure_note.is_none());
        assert!(restored.ssh_key.is_none());
    }

    #[test]
    fn test_option_vec_normalization_none_to_empty_to_none() {
        let (key_store, key_id) = create_test_key_store();
        let mut ctx = key_store.context_mut();

        // CipherView with None fields and password_history
        let original = CipherView {
            name: "Minimal Note".to_string(),
            notes: None,
            r#type: CipherType::SecureNote,
            secure_note: Some(SecureNoteView {
                r#type: SecureNoteType::Generic,
            }),
            fields: None,
            password_history: None,
            ..create_shell_cipher_view(CipherType::SecureNote)
        };

        let blob = CipherBlobV1::from_cipher_view(&original, &mut ctx, key_id).unwrap();

        // None -> empty Vec in blob
        assert!(blob.fields.is_empty());
        assert!(blob.password_history.is_empty());

        // Empty Vec -> None in restored view
        let mut restored = create_shell_cipher_view(CipherType::SecureNote);
        blob.apply_to_cipher_view(&mut restored, &mut ctx, key_id)
            .unwrap();
        assert!(restored.fields.is_none());
        assert!(restored.password_history.is_none());
    }

    #[test]
    fn test_login_none_uris_and_fido2_normalization() {
        let (key_store, key_id) = create_test_key_store();
        let mut ctx = key_store.context_mut();

        let original = CipherView {
            name: "Simple Login".to_string(),
            notes: None,
            r#type: CipherType::Login,
            login: Some(LoginView {
                username: Some("user".to_string()),
                password: None,
                password_revision_date: None,
                uris: None,
                totp: None,
                autofill_on_page_load: None,
                fido2_credentials: None,
            }),
            ..create_shell_cipher_view(CipherType::Login)
        };

        let blob = CipherBlobV1::from_cipher_view(&original, &mut ctx, key_id).unwrap();

        if let CipherTypeDataV1::Login(ref login_data) = blob.type_data {
            assert!(login_data.uris.is_empty());
            assert!(login_data.fido2_credentials.is_empty());
        } else {
            panic!("Expected Login type data");
        }

        let mut restored = create_shell_cipher_view(CipherType::Login);
        blob.apply_to_cipher_view(&mut restored, &mut ctx, key_id)
            .unwrap();

        let login = restored.login.unwrap();
        assert!(login.uris.is_none());
        assert!(login.fido2_credentials.is_none());
    }
}
