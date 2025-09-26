use serde::{Deserialize, Serialize};
use tsify::Tsify;

use crate::{CardView, IdentityView, LoginView, SecureNoteView, SshKeyView};

/// Represents the inner data of a cipher view.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[allow(missing_docs)]
pub enum CipherViewType {
    Login(LoginView),
    Card(CardView),
    Identity(IdentityView),
    SecureNote(SecureNoteView),
    SshKey(SshKeyView),
}

/// Extension trait to provide type-safe accessors for the different cipher view types.
#[allow(private_bounds)]
pub trait CipherViewTypeExt
where
    Self: LockedTrait,
{
    fn as_login_view_mut(&mut self) -> Option<&mut LoginView>;
    fn as_card_view_mut(&mut self) -> Option<&mut CardView>;
    fn as_identity_view_mut(&mut self) -> Option<&mut IdentityView>;
    fn as_secure_note_view_mut(&mut self) -> Option<&mut SecureNoteView>;
    fn as_ssh_key_view_mut(&mut self) -> Option<&mut SshKeyView>;
    fn as_login_view(&self) -> Option<&LoginView>;
    fn as_card_view(&self) -> Option<&CardView>;
    fn as_identity_view(&self) -> Option<&IdentityView>;
    fn as_secure_note_view(&self) -> Option<&SecureNoteView>;
    fn as_ssh_key_view(&self) -> Option<&SshKeyView>;
}

impl CipherViewTypeExt for Option<CipherViewType> {
    fn as_login_view_mut(&mut self) -> Option<&mut LoginView> {
        self.as_mut()
            .map(|inner| inner.as_login_view_mut())
            .flatten()
    }
    fn as_card_view_mut(&mut self) -> Option<&mut CardView> {
        self.as_mut()
            .map(|inner| inner.as_card_view_mut())
            .flatten()
    }

    fn as_identity_view_mut(&mut self) -> Option<&mut IdentityView> {
        self.as_mut()
            .map(|inner| inner.as_identity_view_mut())
            .flatten()
    }

    fn as_secure_note_view_mut(&mut self) -> Option<&mut SecureNoteView> {
        self.as_mut()
            .map(|inner| inner.as_secure_note_view_mut())
            .flatten()
    }

    fn as_ssh_key_view_mut(&mut self) -> Option<&mut SshKeyView> {
        self.as_mut()
            .map(|inner| inner.as_ssh_key_view_mut())
            .flatten()
    }

    fn as_login_view(&self) -> Option<&LoginView> {
        self.as_ref().map(|inner| inner.as_login_view()).flatten()
    }

    fn as_card_view(&self) -> Option<&CardView> {
        self.as_ref().map(|inner| inner.as_card_view()).flatten()
    }

    fn as_identity_view(&self) -> Option<&IdentityView> {
        self.as_ref()
            .map(|inner| inner.as_identity_view())
            .flatten()
    }

    fn as_secure_note_view(&self) -> Option<&SecureNoteView> {
        self.as_ref()
            .map(|inner| inner.as_secure_note_view())
            .flatten()
    }

    fn as_ssh_key_view(&self) -> Option<&SshKeyView> {
        self.as_ref().map(|inner| inner.as_ssh_key_view()).flatten()
    }
}

trait LockedTrait {}
impl LockedTrait for CipherViewType {}
impl LockedTrait for Option<CipherViewType> {}
impl CipherViewTypeExt for CipherViewType {
    fn as_login_view_mut(&mut self) -> Option<&mut LoginView> {
        match self {
            CipherViewType::Login(l) => Some(l),
            _ => None,
        }
    }

    fn as_card_view_mut(&mut self) -> Option<&mut CardView> {
        match self {
            CipherViewType::Card(c) => Some(c),
            _ => None,
        }
    }

    fn as_identity_view_mut(&mut self) -> Option<&mut IdentityView> {
        match self {
            CipherViewType::Identity(i) => Some(i),
            _ => None,
        }
    }

    fn as_secure_note_view_mut(&mut self) -> Option<&mut SecureNoteView> {
        match self {
            CipherViewType::SecureNote(s) => Some(s),
            _ => None,
        }
    }

    fn as_ssh_key_view_mut(&mut self) -> Option<&mut SshKeyView> {
        match self {
            CipherViewType::SshKey(s) => Some(s),
            _ => None,
        }
    }
    fn as_login_view(&self) -> Option<&LoginView> {
        match self {
            CipherViewType::Login(l) => Some(l),
            _ => None,
        }
    }

    fn as_card_view(&self) -> Option<&CardView> {
        match self {
            CipherViewType::Card(c) => Some(c),
            _ => None,
        }
    }

    fn as_identity_view(&self) -> Option<&IdentityView> {
        match self {
            CipherViewType::Identity(i) => Some(i),
            _ => None,
        }
    }

    fn as_secure_note_view(&self) -> Option<&SecureNoteView> {
        match self {
            CipherViewType::SecureNote(s) => Some(s),
            _ => None,
        }
    }

    fn as_ssh_key_view(&self) -> Option<&SshKeyView> {
        match self {
            CipherViewType::SshKey(s) => Some(s),
            _ => None,
        }
    }
}
