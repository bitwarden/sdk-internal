mod sealed;
#[allow(dead_code)]
mod v1;

use bitwarden_crypto::{
    generate_versioned_sealable,
    safe::{DataEnvelopeNamespace, SealableData, SealableVersionedData},
};
#[allow(unused_imports)]
use sealed::{SealedCipherBlob, SealedCipherBlobError};
use serde::{Deserialize, Serialize};
use v1::CipherBlobV1;

generate_versioned_sealable!(
    CipherBlob,
    DataEnvelopeNamespace::VaultItem,
    [CipherBlobV1 => "1"]
);

#[allow(dead_code)]
pub(crate) type CipherBlobLatest = CipherBlobV1;

#[cfg(test)]
mod tests {
    use super::{CipherBlob, v1::*};
    use crate::cipher::secure_note::SecureNoteType;

    #[test]
    fn test_versioned_enum_format() {
        let blob = CipherBlobV1 {
            name: "Test".to_string(),
            notes: None,
            type_data: CipherTypeDataV1::SecureNote(SecureNoteDataV1 {
                r#type: SecureNoteType::Generic,
            }),
            fields: Vec::new(),
            password_history: Vec::new(),
        };
        let versioned: CipherBlob = blob.into();
        let json = serde_json::to_value(&versioned).unwrap();

        assert_eq!(json["version"], "1");
        assert!(json["content"].is_object());
        assert_eq!(json["content"]["name"], "Test");
    }

    #[test]
    fn test_from_conversion() {
        let blob = CipherBlobV1 {
            name: "Test".to_string(),
            notes: None,
            type_data: CipherTypeDataV1::SecureNote(SecureNoteDataV1 {
                r#type: SecureNoteType::Generic,
            }),
            fields: Vec::new(),
            password_history: Vec::new(),
        };
        let versioned: CipherBlob = blob.clone().into();
        assert_eq!(versioned, CipherBlob::CipherBlobV1(blob));
    }
}
