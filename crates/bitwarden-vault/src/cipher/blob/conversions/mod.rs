use bitwarden_core::key_management::{KeySlotIds, SymmetricKeySlotId};
use bitwarden_crypto::{
    CompositeEncryptable, CryptoError, Decryptable, KeyStoreContext, PrimitiveEncryptable,
};

use super::v1::*;
#[cfg(feature = "wasm")]
use crate::cipher::field::FieldListView;
use crate::{
    CipherListView, CipherView, PasswordHistoryView,
    cipher::{
        bank_account::BankAccountView,
        card::{CardListView, CardView, build_subtitle_card},
        cipher::{CipherListViewType, CipherType, CopyableCipherFields},
        drivers_license::DriversLicenseView,
        field::FieldView,
        identity::{IdentityView, build_subtitle_identity},
        login::{
            Fido2CredentialFullView, Fido2CredentialListView, LoginListView, LoginUriView,
            LoginView,
        },
        passport::PassportView,
        secure_note::SecureNoteView,
        ssh_key::SshKeyView,
    },
};

fn none_if_empty<T>(v: Vec<T>) -> Option<Vec<T>> {
    if v.is_empty() { None } else { Some(v) }
}

/// Generates bidirectional `From` impls between two types that share
/// identical field names. Every field is `.clone()`d.
macro_rules! impl_bidirectional_from {
    ($type_a:ty, $type_b:ty, [$($field:ident),+ $(,)?]) => {
        impl From<&$type_a> for $type_b {
            fn from(src: &$type_a) -> Self {
                Self { $($field: src.$field.clone()),+ }
            }
        }
        impl From<&$type_b> for $type_a {
            fn from(src: &$type_b) -> Self {
                Self { $($field: src.$field.clone()),+ }
            }
        }
    };
}

impl_bidirectional_from!(FieldView, FieldDataV1, [name, value, r#type, linked_id,]);

impl_bidirectional_from!(
    PasswordHistoryView,
    PasswordHistoryDataV1,
    [password, last_used_date,]
);

mod bank_account;
mod card;
mod drivers_license;
mod identity;
mod login;
mod passport;
mod secure_note;
mod ssh_key;

impl CipherBlobV1 {
    pub(crate) fn from_cipher_view(
        view: &CipherView,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        key: SymmetricKeySlotId,
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
            CipherType::BankAccount => {
                let bank_account = view
                    .bank_account
                    .as_ref()
                    .ok_or(CryptoError::MissingField("bank_account"))?;
                CipherTypeDataV1::BankAccount(BankAccountDataV1::from(bank_account))
            }
            CipherType::DriversLicense => {
                let drivers_license = view
                    .drivers_license
                    .as_ref()
                    .ok_or(CryptoError::MissingField("drivers_license"))?;
                CipherTypeDataV1::DriversLicense(DriversLicenseDataV1::from(drivers_license))
            }
            CipherType::Passport => {
                let passport = view
                    .passport
                    .as_ref()
                    .ok_or(CryptoError::MissingField("passport"))?;
                CipherTypeDataV1::Passport(PassportDataV1::from(passport))
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
        ctx: &mut KeyStoreContext<KeySlotIds>,
        key: SymmetricKeySlotId,
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

        view.login = None;
        view.card = None;
        view.identity = None;
        view.secure_note = None;
        view.ssh_key = None;
        view.bank_account = None;
        view.drivers_license = None;
        view.passport = None;

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
            }
            CipherTypeDataV1::Card(card_data) => {
                view.r#type = CipherType::Card;
                view.card = Some(CardView::from(card_data));
            }
            CipherTypeDataV1::Identity(identity_data) => {
                view.r#type = CipherType::Identity;
                view.identity = Some(IdentityView::from(identity_data));
            }
            CipherTypeDataV1::SecureNote(secure_note_data) => {
                view.r#type = CipherType::SecureNote;
                view.secure_note = Some(SecureNoteView::from(secure_note_data));
            }
            CipherTypeDataV1::SshKey(ssh_key_data) => {
                view.r#type = CipherType::SshKey;
                view.ssh_key = Some(SshKeyView::from(ssh_key_data));
            }
            CipherTypeDataV1::BankAccount(bank_account_data) => {
                view.r#type = CipherType::BankAccount;
                view.bank_account = Some(BankAccountView::from(bank_account_data));
            }
            CipherTypeDataV1::DriversLicense(drivers_license_data) => {
                view.r#type = CipherType::DriversLicense;
                view.drivers_license = Some(DriversLicenseView::from(drivers_license_data));
            }
            CipherTypeDataV1::Passport(passport_data) => {
                view.r#type = CipherType::Passport;
                view.passport = Some(PassportView::from(passport_data));
            }
        }

        Ok(())
    }

    /// Populates a [`CipherListView`] from this blob: name/notes/fields plus the type-specific
    /// list-view payload, subtitle, and copyable_fields. Mirrors `apply_to_cipher_view`.
    ///
    /// `LoginListView::totp` is re-encrypted with `cipher_key` to honor the contract that the
    /// TOTP value stays encrypted for lazy decryption via `generate_totp_cipher_view`.
    pub(crate) fn apply_to_cipher_list_view(
        &self,
        view: &mut CipherListView,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        cipher_key: SymmetricKeySlotId,
    ) -> Result<(), CryptoError> {
        view.name = self.name.clone();
        #[cfg(feature = "wasm")]
        {
            view.notes = self.notes.clone();
            view.fields = none_if_empty(
                self.fields
                    .iter()
                    .map(|f| FieldListView::from(FieldView::from(f)))
                    .collect(),
            );
        }

        match &self.type_data {
            CipherTypeDataV1::Login(login_data) => {
                let totp_enc = login_data
                    .totp
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .map(|t| t.encrypt(ctx, cipher_key))
                    .transpose()?;
                let fido2_credentials = if login_data.fido2_credentials.is_empty() {
                    None
                } else {
                    Some(
                        login_data
                            .fido2_credentials
                            .iter()
                            .map(|c| Fido2CredentialListView {
                                credential_id: c.credential_id.clone(),
                                rp_id: c.rp_id.clone(),
                                user_handle: c.user_handle.clone(),
                                user_name: c.user_name.clone(),
                                user_display_name: c.user_display_name.clone(),
                                counter: c.counter.to_string(),
                            })
                            .collect(),
                    )
                };
                let has_fido2 = !login_data.fido2_credentials.is_empty();
                let uris = none_if_empty(login_data.uris.iter().map(LoginUriView::from).collect());
                view.subtitle = login_data.username.clone().unwrap_or_default();
                view.copyable_fields = [
                    login_data
                        .username
                        .as_ref()
                        .map(|_| CopyableCipherFields::LoginUsername),
                    login_data
                        .password
                        .as_ref()
                        .map(|_| CopyableCipherFields::LoginPassword),
                    login_data
                        .totp
                        .as_ref()
                        .map(|_| CopyableCipherFields::LoginTotp),
                ]
                .into_iter()
                .flatten()
                .collect();
                view.r#type = CipherListViewType::Login(LoginListView {
                    fido2_credentials,
                    has_fido2,
                    username: login_data.username.clone(),
                    totp: totp_enc,
                    uris,
                });
            }
            CipherTypeDataV1::Card(card_data) => {
                view.subtitle =
                    build_subtitle_card(card_data.brand.clone(), card_data.number.clone());
                view.copyable_fields = [
                    card_data
                        .number
                        .as_ref()
                        .map(|_| CopyableCipherFields::CardNumber),
                    card_data
                        .code
                        .as_ref()
                        .map(|_| CopyableCipherFields::CardSecurityCode),
                ]
                .into_iter()
                .flatten()
                .collect();
                view.r#type = CipherListViewType::Card(CardListView {
                    brand: card_data.brand.clone(),
                });
            }
            CipherTypeDataV1::Identity(identity_data) => {
                view.subtitle = build_subtitle_identity(
                    identity_data.first_name.clone(),
                    identity_data.last_name.clone(),
                );
                view.copyable_fields = [
                    identity_data
                        .username
                        .as_ref()
                        .map(|_| CopyableCipherFields::IdentityUsername),
                    identity_data
                        .email
                        .as_ref()
                        .map(|_| CopyableCipherFields::IdentityEmail),
                    identity_data
                        .phone
                        .as_ref()
                        .map(|_| CopyableCipherFields::IdentityPhone),
                    identity_data
                        .address1
                        .as_ref()
                        .or(identity_data.address2.as_ref())
                        .or(identity_data.address3.as_ref())
                        .or(identity_data.city.as_ref())
                        .or(identity_data.state.as_ref())
                        .or(identity_data.postal_code.as_ref())
                        .map(|_| CopyableCipherFields::IdentityAddress),
                ]
                .into_iter()
                .flatten()
                .collect();
                view.r#type = CipherListViewType::Identity;
            }
            CipherTypeDataV1::SecureNote(_) => {
                view.subtitle = String::new();
                view.copyable_fields = if self.notes.is_some() {
                    vec![CopyableCipherFields::SecureNotes]
                } else {
                    Vec::new()
                };
                view.r#type = CipherListViewType::SecureNote;
            }
            CipherTypeDataV1::SshKey(ssh_data) => {
                view.subtitle = ssh_data.fingerprint.clone();
                view.copyable_fields = vec![CopyableCipherFields::SshKey];
                view.r#type = CipherListViewType::SshKey;
            }
            CipherTypeDataV1::BankAccount(bank_data) => {
                view.subtitle = bank_data.bank_name.clone().unwrap_or_default();
                view.copyable_fields = [
                    bank_data
                        .account_number
                        .as_ref()
                        .map(|_| CopyableCipherFields::BankAccountAccountNumber),
                    bank_data
                        .routing_number
                        .as_ref()
                        .map(|_| CopyableCipherFields::BankAccountRoutingNumber),
                    bank_data
                        .pin
                        .as_ref()
                        .map(|_| CopyableCipherFields::BankAccountPin),
                    bank_data
                        .iban
                        .as_ref()
                        .map(|_| CopyableCipherFields::BankAccountIban),
                ]
                .into_iter()
                .flatten()
                .collect();
                view.r#type = CipherListViewType::BankAccount;
            }
            CipherTypeDataV1::Passport(passport_data) => {
                let parts: Vec<String> = [
                    passport_data.given_name.clone(),
                    passport_data.surname.clone(),
                ]
                .into_iter()
                .flatten()
                .filter(|s| !s.is_empty())
                .collect();
                view.subtitle = parts.join(" ");
                view.copyable_fields = if passport_data.passport_number.is_some() {
                    vec![CopyableCipherFields::PassportPassportNumber]
                } else {
                    Vec::new()
                };
                view.r#type = CipherListViewType::Passport;
            }
            CipherTypeDataV1::DriversLicense(dl_data) => {
                let parts: Vec<String> = [dl_data.first_name.clone(), dl_data.last_name.clone()]
                    .into_iter()
                    .flatten()
                    .filter(|s| !s.is_empty())
                    .collect();
                view.subtitle = parts.join(" ");
                view.copyable_fields = if dl_data.license_number.is_some() {
                    vec![CopyableCipherFields::DriversLicenseLicenseNumber]
                } else {
                    Vec::new()
                };
                view.r#type = CipherListViewType::DriversLicense;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use bitwarden_core::key_management::{
        KeySlotIds, SymmetricKeySlotId, create_test_crypto_with_user_key,
    };
    use bitwarden_crypto::{KeyStore, SymmetricCryptoKey};
    use chrono::{TimeZone, Utc};

    use crate::{
        CipherView,
        cipher::cipher::{CipherRepromptType, CipherType},
    };

    pub(crate) fn create_test_key_store() -> (KeyStore<KeySlotIds>, SymmetricKeySlotId) {
        let key = SymmetricCryptoKey::try_from(
            "hvBMMb1t79YssFZkpetYsM3deyVuQv4r88Uj9gvYe0+G8EwxvW3v1iywVmSl61iwzd17JW5C/ivzxSP2C9h7Tw==".to_string(),
        )
        .unwrap();
        let key_store = create_test_crypto_with_user_key(key);
        (key_store, SymmetricKeySlotId::User)
    }

    pub(crate) fn create_shell_cipher_view(cipher_type: CipherType) -> CipherView {
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
            attachment_decryption_failures: None,
            fields: None,
            password_history: None,
            creation_date: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            deleted_date: None,
            revision_date: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            archived_date: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CipherBlobV1, CipherTypeDataV1, test_support::*};
    use crate::cipher::{
        cipher::CipherType,
        login::LoginView,
        secure_note::{SecureNoteType, SecureNoteView},
    };

    #[test]
    fn test_option_vec_normalization_none_to_empty_to_none() {
        let (key_store, key_id) = create_test_key_store();
        let mut ctx = key_store.context_mut();

        let original = crate::CipherView {
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

        assert!(blob.fields.is_empty());
        assert!(blob.password_history.is_empty());

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

        let original = crate::CipherView {
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
