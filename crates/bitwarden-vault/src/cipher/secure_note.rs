use bitwarden_api_api::models::CipherSecureNoteModel;
use bitwarden_core::{
    key_management::{KeyIds, SymmetricKeyId},
    require,
};
use bitwarden_crypto::{CompositeEncryptable, CryptoError, Decryptable, KeyStoreContext};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{
    Cipher, VaultParseError,
    cipher::cipher::{CipherKind, CopyableCipherFields},
};

#[allow(missing_docs)]
#[derive(Clone, Copy, Serialize_repr, Deserialize_repr, Debug)]
#[repr(u8)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub enum SecureNoteType {
    Generic = 0,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct SecureNote {
    r#type: SecureNoteType,
}

#[allow(missing_docs)]
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct SecureNoteView {
    pub r#type: SecureNoteType,
}

impl CompositeEncryptable<KeyIds, SymmetricKeyId, SecureNote> for SecureNoteView {
    fn encrypt_composite(
        &self,
        _ctx: &mut KeyStoreContext<KeyIds>,
        _key: SymmetricKeyId,
    ) -> Result<SecureNote, CryptoError> {
        Ok(SecureNote {
            r#type: self.r#type,
        })
    }
}

impl Decryptable<KeyIds, SymmetricKeyId, SecureNoteView> for SecureNote {
    fn decrypt(
        &self,
        _ctx: &mut KeyStoreContext<KeyIds>,
        _key: SymmetricKeyId,
    ) -> Result<SecureNoteView, CryptoError> {
        Ok(SecureNoteView {
            r#type: self.r#type,
        })
    }
}

impl TryFrom<CipherSecureNoteModel> for SecureNote {
    type Error = VaultParseError;

    fn try_from(model: CipherSecureNoteModel) -> Result<Self, Self::Error> {
        Ok(Self {
            r#type: require!(model.r#type).into(),
        })
    }
}

impl From<bitwarden_api_api::models::SecureNoteType> for SecureNoteType {
    fn from(model: bitwarden_api_api::models::SecureNoteType) -> Self {
        match model {
            bitwarden_api_api::models::SecureNoteType::Generic => SecureNoteType::Generic,
        }
    }
}

impl CipherKind for SecureNote {
    fn get_copyable_fields(&self, cipher: Option<&Cipher>) -> Vec<CopyableCipherFields> {
        [cipher
            .and_then(|c| c.notes.as_ref())
            .map(|_| CopyableCipherFields::SecureNotes)]
        .into_iter()
        .flatten()
        .collect()
    }

    fn decrypt_subtitle(
        &self,
        _ctx: &mut KeyStoreContext<KeyIds>,
        _key: SymmetricKeyId,
    ) -> Result<String, CryptoError> {
        Ok(String::new())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        CipherRepromptType, CipherType, SecureNoteType,
        cipher::cipher::{Cipher, CipherKind, CopyableCipherFields},
        secure_note::SecureNote,
    };

    fn create_cipher_for_note(note: SecureNote) -> Cipher {
        Cipher {
            id: Some("090c19ea-a61a-4df6-8963-262b97bc6266".parse().unwrap()),
            organization_id: None,
            folder_id: None,
            collection_ids: vec![],
            r#type: CipherType::Login,
            key: None,
            name: "2.iovOJUb186UXu+0AlQggjw==|LeWZhrT0B7rqFtDufOJMlJsftwmMGuaoBxf/Cig4D4A9XHhUqacd8uOYP7M5bd/k|++gmrHIyt8hvvPP9dwFS/CGd+POfzmeXzKOsuyJpDDc=".parse().unwrap(),
            notes: None,
            login: None,
            identity: None,
            card: None,
            secure_note: Some(note),
            ssh_key: None,
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
            archived_date: None,
        }
    }

    #[test]
    fn test_get_copyable_fields_secure_note_empty() {
        let secure_note = SecureNote {
            r#type: SecureNoteType::Generic,
        };

        let cipher = create_cipher_for_note(secure_note.clone());

        let copyable_fields = secure_note.get_copyable_fields(Some(&cipher));
        assert_eq!(copyable_fields, vec![]);
    }

    #[test]
    fn test_get_copyable_fields_secure_note_has_notes() {
        let secure_note = SecureNote {
            r#type: SecureNoteType::Generic,
        };

        let mut cipher = create_cipher_for_note(secure_note.clone());
        cipher.notes = Some("2.iovOJUb186UXu+0AlQggjw==|LeWZhrT0B7rqFtDufOJMlJsftwmMGuaoBxf/Cig4D4A9XHhUqacd8uOYP7M5bd/k|++gmrHIyt8hvvPP9dwFS/CGd+POfzmeXzKOsuyJpDDc=".parse().unwrap());

        let copyable_fields = secure_note.get_copyable_fields(Some(&cipher));
        assert_eq!(copyable_fields, vec![CopyableCipherFields::SecureNotes]);
    }

    #[test]
    fn test_get_copyable_fields_secure_no_cipher() {
        let secure_note = SecureNote {
            r#type: SecureNoteType::Generic,
        };

        let copyable_fields = secure_note.get_copyable_fields(None);
        assert_eq!(copyable_fields, vec![]);
    }
}
