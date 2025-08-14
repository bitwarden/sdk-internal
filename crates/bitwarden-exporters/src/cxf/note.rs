use credential_exchange_format::NoteCredential;

/// Extract note content from a CXF Note credential
/// The way notes are handled (in import.rs) depends on their context:
/// - If part of an item, use parent type and map content to Cipher::notes
/// - If standalone, map to SecureNote
///
/// That's why we only have this small utility function and tests here.
pub(super) fn extract_note_content(note: &NoteCredential) -> String {
    note.content.value.0.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_note_content_with_content() {
        let note = NoteCredential {
            content: "This is a test note with important information."
                .to_owned()
                .into(),
        };

        let content = extract_note_content(&note);
        assert_eq!(
            content,
            "This is a test note with important information.".to_string()
        );
    }

    #[test]
    fn test_extract_note_content_empty_string() {
        let note = NoteCredential {
            content: "".to_owned().into(),
        };

        let content = extract_note_content(&note);
        assert_eq!(content, "".to_string());
    }

    #[test]
    fn test_extract_note_content_multiline() {
        let note = NoteCredential {
            content: "Line 1\nLine 2\nLine 3".to_owned().into(),
        };

        let content = extract_note_content(&note);
        assert_eq!(content, "Line 1\nLine 2\nLine 3".to_string());
    }

    #[test]
    fn test_extract_note_content_special_characters() {
        let note = NoteCredential {
            content: "Note with emojis 🔐 and special chars: @#$%^&*()"
                .to_owned()
                .into(),
        };

        let content = extract_note_content(&note);
        assert_eq!(
            content,
            "Note with emojis 🔐 and special chars: @#$%^&*()".to_string()
        );
    }

    #[test]
    fn test_extract_note_content_very_long() {
        let long_content = "A".repeat(10000);
        let note = NoteCredential {
            content: long_content.clone().into(),
        };

        let content = extract_note_content(&note);
        assert_eq!(content, long_content);
    }

    #[test]
    fn test_standalone_note_credential() {
        use credential_exchange_format::{Credential, Item};

        use crate::{cxf::import::parse_item, CipherType, ImportingCipher};

        let item = Item {
            id: [0, 1, 2, 3, 4, 5, 6].as_ref().into(),
            creation_at: Some(1706613834),
            modified_at: Some(1706623773),
            title: "My Important Note".to_string(),
            subtitle: None,
            favorite: None,
            credentials: vec![Credential::Note(Box::new(NoteCredential {
                content:
                    "This is a standalone secure note with important information.\nLine 2\nLine 3"
                        .to_string()
                        .into(),
            }))],
            tags: None,
            extensions: None,
            scope: None,
        };

        let ciphers: Vec<ImportingCipher> = parse_item(item);
        assert_eq!(ciphers.len(), 1);
        let cipher = ciphers.first().unwrap();

        assert_eq!(cipher.folder_id, None);
        assert_eq!(cipher.name, "My Important Note");
        assert_eq!(
            cipher.notes,
            Some(
                "This is a standalone secure note with important information.\nLine 2\nLine 3"
                    .to_string()
            )
        );

        match &cipher.r#type {
            CipherType::SecureNote(_) => (), // Successfully created a SecureNote
            _ => panic!("Expected SecureNote"),
        };

        assert_eq!(cipher.fields.len(), 0); // Notes don't have custom fields
    }
}
