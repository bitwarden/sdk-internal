use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;

use crate::{CardView, IdentityView, LoginView, SecureNoteView, SshKeyView};

/// Represents the inner data of a cipher view.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[expect(missing_docs, clippy::large_enum_variant)]
pub enum CipherViewType {
    Login(LoginView),
    Card(CardView),
    Identity(IdentityView),
    SecureNote(SecureNoteView),
    SshKey(SshKeyView),
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
        }
    }
}

#[expect(unused)]
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
}
