use credential_exchange_format::NoteCredential;

/// Extract note content from a CXF Note credential
/// The way notes are handled (in import.rs) depends on their context:
/// - If part of an item, use parent type and map content to Cipher::notes
/// - If standalone, map to SecureNote
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
    fn test_cxf_example_note_integration() {
        use std::fs;

        use crate::{cxf::import::parse_cxf_spec, CipherType};

        // Read the actual CXF example file
        let cxf_data = fs::read_to_string("resources/cxf_example.json")
            .expect("Should be able to read cxf_example.json");

        let items = parse_cxf_spec(cxf_data).expect("Should parse CXF data successfully");

        // Find the note item (Home alarm)
        let note_cipher = items
            .iter()
            .find(|cipher| cipher.name == "Home alarm")
            .expect("Should find Home alarm note item");

        // Validate it's a SecureNote cipher
        match &note_cipher.r#type {
            CipherType::SecureNote(_) => (), // Successfully identified as SecureNote
            _ => panic!("Expected SecureNote for standalone note credential"),
        }

        // Validate the note content
        assert_eq!(
            note_cipher.notes,
            Some("some instructionts to enable/disable the alarm".to_string())
        );

        // Should have no custom fields since it's a standalone note
        assert_eq!(note_cipher.fields.len(), 0);

        // Validate basic properties
        assert_eq!(note_cipher.name, "Home alarm");
        assert_eq!(note_cipher.folder_id, None);
        assert!(!note_cipher.favorite);
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

    // TODO: Consider moving this logic to import.rs since it's more about how notes are handled
    // during the import process
    #[test]
    fn test_note_as_part_of_login() {
        use credential_exchange_format::{BasicAuthCredential, Credential, Item};

        use crate::{cxf::import::parse_item, CipherType, ImportingCipher};

        let item = Item {
            id: [0, 1, 2, 3, 4, 5, 6].as_ref().into(),
            creation_at: Some(1706613834),
            modified_at: Some(1706623773),
            title: "Login with Note".to_string(),
            subtitle: None,
            favorite: None,
            credentials: vec![
                Credential::BasicAuth(Box::new(BasicAuthCredential {
                    username: Some("testuser".to_string().into()),
                    password: Some("testpass".to_string().into()),
                })),
                Credential::Note(Box::new(NoteCredential {
                    content: "This note should be added to the login cipher."
                        .to_string()
                        .into(),
                })),
            ],
            tags: None,
            extensions: None,
            scope: None,
        };

        let ciphers: Vec<ImportingCipher> = parse_item(item);
        assert_eq!(ciphers.len(), 1); // Should create only one cipher (Login with note content)
        let cipher = ciphers.first().unwrap();

        assert_eq!(cipher.name, "Login with Note");
        assert_eq!(
            cipher.notes,
            Some("This note should be added to the login cipher.".to_string())
        );

        match &cipher.r#type {
            CipherType::Login(_) => (), // Should be a Login cipher
            _ => panic!("Expected Login cipher with note content"),
        };
    }

    #[test]
    fn test_note_as_part_of_api_key() {
        use credential_exchange_format::{ApiKeyCredential, Credential, Item};

        use crate::{cxf::import::parse_item, CipherType, ImportingCipher};

        let item = Item {
            id: [0, 1, 2, 3, 4, 5, 6].as_ref().into(),
            creation_at: Some(1706613834),
            modified_at: Some(1706623773),
            title: "API Key with Note".to_string(),
            subtitle: None,
            favorite: None,
            credentials: vec![
                Credential::ApiKey(Box::new(ApiKeyCredential {
                    key: Some("api-key-12345".to_string().into()),
                    username: Some("api-user".to_string().into()),
                    key_type: Some("Bearer".to_string().into()),
                    url: None,
                    valid_from: None,
                    expiry_date: None,
                })),
                Credential::Note(Box::new(NoteCredential {
                    content: "This note should be added to the API key cipher."
                        .to_string()
                        .into(),
                })),
            ],
            tags: None,
            extensions: None,
            scope: None,
        };

        let ciphers: Vec<ImportingCipher> = parse_item(item);
        assert_eq!(ciphers.len(), 1); // Should create only one cipher (SecureNote with note content)
        let cipher = ciphers.first().unwrap();

        assert_eq!(cipher.name, "API Key with Note");
        assert_eq!(
            cipher.notes,
            Some("This note should be added to the API key cipher.".to_string())
        );

        match &cipher.r#type {
            CipherType::SecureNote(_) => (), // Should be a SecureNote cipher
            _ => panic!("Expected SecureNote cipher with note content"),
        };

        // Should have API key fields
        assert!(!cipher.fields.is_empty());
    }
}
