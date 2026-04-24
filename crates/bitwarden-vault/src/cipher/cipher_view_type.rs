use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;

use crate::{
    BankAccountView, CardView, DriversLicenseView, IdentityView, LoginView, PassportView,
    SecureNoteView, SshKeyView,
};

/// Represents the inner data of a cipher view.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[allow(missing_docs, clippy::large_enum_variant)]
pub enum CipherViewType {
    Login(LoginView),
    Card(CardView),
    Identity(IdentityView),
    SecureNote(SecureNoteView),
    SshKey(SshKeyView),
    BankAccount(BankAccountView),
    Passport(PassportView),
    DriversLicense(DriversLicenseView),
}

impl CipherViewType {
    /// Returns the corresponding [crate::CipherType] for this view type.
    pub fn get_cipher_type(&self) -> crate::CipherType {
        match self {
            CipherViewType::Login(_) => crate::CipherType::Login,
            CipherViewType::Card(_) => crate::CipherType::Card,
            CipherViewType::Identity(_) => crate::CipherType::Identity,
            CipherViewType::SecureNote(_) => crate::CipherType::SecureNote,
            CipherViewType::SshKey(_) => crate::CipherType::SshKey,
            CipherViewType::BankAccount(_) => crate::CipherType::BankAccount,
            CipherViewType::Passport(_) => crate::CipherType::Passport,
            CipherViewType::DriversLicense(_) => crate::CipherType::DriversLicense,
        }
    }
}

#[allow(unused)]
impl CipherViewType {
    pub(crate) fn as_login_view_mut(&mut self) -> Option<&mut LoginView> {
        match self {
            CipherViewType::Login(l) => Some(l),
            _ => None,
        }
    }

    pub(crate) fn as_card_view_mut(&mut self) -> Option<&mut CardView> {
        match self {
            CipherViewType::Card(c) => Some(c),
            _ => None,
        }
    }

    pub(crate) fn as_identity_view_mut(&mut self) -> Option<&mut IdentityView> {
        match self {
            CipherViewType::Identity(i) => Some(i),
            _ => None,
        }
    }

    pub(crate) fn as_secure_note_view_mut(&mut self) -> Option<&mut SecureNoteView> {
        match self {
            CipherViewType::SecureNote(s) => Some(s),
            _ => None,
        }
    }

    pub(crate) fn as_ssh_key_view_mut(&mut self) -> Option<&mut SshKeyView> {
        match self {
            CipherViewType::SshKey(s) => Some(s),
            _ => None,
        }
    }

    pub(crate) fn as_bank_account_view_mut(&mut self) -> Option<&mut BankAccountView> {
        match self {
            CipherViewType::BankAccount(b) => Some(b),
            _ => None,
        }
    }

    pub(crate) fn as_passport_view_mut(&mut self) -> Option<&mut PassportView> {
        match self {
            CipherViewType::Passport(p) => Some(p),
            _ => None,
        }
    }

    pub(crate) fn as_drivers_license_view_mut(&mut self) -> Option<&mut DriversLicenseView> {
        match self {
            CipherViewType::DriversLicense(d) => Some(d),
            _ => None,
        }
    }

    pub(crate) fn as_login_view(&self) -> Option<&LoginView> {
        match self {
            CipherViewType::Login(l) => Some(l),
            _ => None,
        }
    }

    pub(crate) fn as_card_view(&self) -> Option<&CardView> {
        match self {
            CipherViewType::Card(c) => Some(c),
            _ => None,
        }
    }

    pub(crate) fn as_identity_view(&self) -> Option<&IdentityView> {
        match self {
            CipherViewType::Identity(i) => Some(i),
            _ => None,
        }
    }

    pub(crate) fn as_secure_note_view(&self) -> Option<&SecureNoteView> {
        match self {
            CipherViewType::SecureNote(s) => Some(s),
            _ => None,
        }
    }

    pub(crate) fn as_ssh_key_view(&self) -> Option<&SshKeyView> {
        match self {
            CipherViewType::SshKey(s) => Some(s),
            _ => None,
        }
    }

    pub(crate) fn as_bank_account_view(&self) -> Option<&BankAccountView> {
        match self {
            CipherViewType::BankAccount(b) => Some(b),
            _ => None,
        }
    }

    pub(crate) fn as_passport_view(&self) -> Option<&PassportView> {
        match self {
            CipherViewType::Passport(p) => Some(p),
            _ => None,
        }
    }

    pub(crate) fn as_drivers_license_view(&self) -> Option<&DriversLicenseView> {
        match self {
            CipherViewType::DriversLicense(d) => Some(d),
            _ => None,
        }
    }
}
