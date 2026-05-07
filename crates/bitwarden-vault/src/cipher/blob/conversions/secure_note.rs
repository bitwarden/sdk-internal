use super::{SecureNoteDataV1, SecureNoteView};

impl_bidirectional_from!(SecureNoteView, SecureNoteDataV1, [r#type]);

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::super::{CipherBlobV1, test_support::*};
    use crate::{
        PasswordHistoryView,
        cipher::{
            cipher::CipherType,
            field::{FieldType, FieldView},
            secure_note::{SecureNoteType, SecureNoteView},
        },
    };

    #[test]
    fn test_secure_note_cipher_round_trip() {
        let (key_store, key_id) = create_test_key_store();
        let mut ctx = key_store.context_mut();

        let original = crate::CipherView {
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
}
