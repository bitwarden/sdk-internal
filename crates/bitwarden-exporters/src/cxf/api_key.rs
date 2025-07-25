use bitwarden_vault::FieldType;
use credential_exchange_format::ApiKeyCredential;

use crate::Field;

/// Convert API key credentials to custom fields following the CXF mapping convention
/// According to the mapping specification:
/// - key: EditableField<"concealed-string"> → CustomField, hidden
/// - username: EditableField<"string"> → Login::username / CustomField
/// - keyType: EditableField<"string"> → CustomField
/// - url: EditableField<"string"> → Login::uris / CustomField
/// - validFrom: EditableField<"date"> → CustomField
/// - expiryDate: EditableField<"date"> → CustomField
pub fn api_key_to_fields(api_key: &ApiKeyCredential) -> Vec<Field> {
    let mut fields = Vec::new();

    // Key: Hidden field (concealed-string)
    if let Some(key) = &api_key.key {
        fields.push(Field {
            name: Some("API Key".to_string()),
            value: Some(key.value.0.clone()),
            r#type: FieldType::Hidden as u8,
            linked_id: None,
        });
    }

    // Username: Text field
    if let Some(username) = &api_key.username {
        fields.push(Field {
            name: Some("Username".to_string()),
            value: Some(username.value.0.clone()),
            r#type: FieldType::Text as u8,
            linked_id: None,
        });
    }

    // Key Type: Text field
    if let Some(key_type) = &api_key.key_type {
        fields.push(Field {
            name: Some("Key Type".to_string()),
            value: Some(key_type.value.0.clone()),
            r#type: FieldType::Text as u8,
            linked_id: None,
        });
    }

    // URL: Text field
    if let Some(url) = &api_key.url {
        fields.push(Field {
            name: Some("URL".to_string()),
            value: Some(url.value.0.clone()),
            r#type: FieldType::Text as u8,
            linked_id: None,
        });
    }

    // Valid From: Text field (date stored as string)
    if let Some(valid_from) = &api_key.valid_from {
        fields.push(Field {
            name: Some("Valid From".to_string()),
            value: Some(valid_from.value.0.to_string()),
            r#type: FieldType::Text as u8,
            linked_id: None,
        });
    }

    // Expiry Date: Text field (date stored as string)
    if let Some(expiry_date) = &api_key.expiry_date {
        fields.push(Field {
            name: Some("Expiry Date".to_string()),
            value: Some(expiry_date.value.0.to_string()),
            r#type: FieldType::Text as u8,
            linked_id: None,
        });
    }

    fields
}

#[cfg(test)]
mod tests {
    use bitwarden_vault::FieldType;
    use credential_exchange_format::{
        EditableField, EditableFieldConcealedString, EditableFieldDate, EditableFieldString,
    };
    use chrono::NaiveDate;

    use super::*;

    fn create_api_key_credential(
        key: Option<&str>,
        username: Option<&str>,
        key_type: Option<&str>,
        url: Option<&str>,
        valid_from: Option<&str>,
        expiry_date: Option<&str>,
    ) -> ApiKeyCredential {
        ApiKeyCredential {
            key: key.map(|k| EditableField {
                id: None,
                value: EditableFieldConcealedString(k.to_string()),
                label: None,
                extensions: None,
            }),
            username: username.map(|u| EditableField {
                id: None,
                value: EditableFieldString(u.to_string()),
                label: None,
                extensions: None,
            }),
            key_type: key_type.map(|kt| EditableField {
                id: None,
                value: EditableFieldString(kt.to_string()),
                label: None,
                extensions: None,
            }),
            url: url.map(|u| EditableField {
                id: None,
                value: EditableFieldString(u.to_string()),
                label: None,
                extensions: None,
            }),
            valid_from: valid_from.map(|vf| EditableField {
                id: None,
                value: EditableFieldDate(NaiveDate::parse_from_str(vf, "%Y-%m-%d").unwrap()),
                label: None,
                extensions: None,
            }),
            expiry_date: expiry_date.map(|ed| EditableField {
                id: None,
                value: EditableFieldDate(NaiveDate::parse_from_str(ed, "%Y-%m-%d").unwrap()),
                label: None,
                extensions: None,
            }),
        }
    }

    #[test]
    fn test_api_key_to_fields_all_fields() {
        let api_key = create_api_key_credential(
            Some("AIzaSyAyRofL-VJHZofHc-qOSkqVOdhvgQoJADk"),
            Some("john_doe"),
            Some("Bearer"),
            Some("https://api.example.com"),
            Some("2025-01-01"),
            Some("2026-01-01"),
        );

        let fields = api_key_to_fields(&api_key);

        assert_eq!(fields.len(), 6);

        // API Key field (should be hidden)
        assert_eq!(fields[0].name, Some("API Key".to_string()));
        assert_eq!(
            fields[0].value,
            Some("AIzaSyAyRofL-VJHZofHc-qOSkqVOdhvgQoJADk".to_string())
        );
        assert_eq!(fields[0].r#type, FieldType::Hidden as u8);

        // Username field
        assert_eq!(fields[1].name, Some("Username".to_string()));
        assert_eq!(fields[1].value, Some("john_doe".to_string()));
        assert_eq!(fields[1].r#type, FieldType::Text as u8);

        // Key Type field
        assert_eq!(fields[2].name, Some("Key Type".to_string()));
        assert_eq!(fields[2].value, Some("Bearer".to_string()));
        assert_eq!(fields[2].r#type, FieldType::Text as u8);

        // URL field
        assert_eq!(fields[3].name, Some("URL".to_string()));
        assert_eq!(fields[3].value, Some("https://api.example.com".to_string()));
        assert_eq!(fields[3].r#type, FieldType::Text as u8);

        // Valid From field
        assert_eq!(fields[4].name, Some("Valid From".to_string()));
        assert_eq!(fields[4].value, Some("2025-01-01".to_string()));
        assert_eq!(fields[4].r#type, FieldType::Text as u8);

        // Expiry Date field
        assert_eq!(fields[5].name, Some("Expiry Date".to_string()));
        assert_eq!(fields[5].value, Some("2026-01-01".to_string()));
        assert_eq!(fields[5].r#type, FieldType::Text as u8);
    }

    #[test]
    fn test_api_key_to_fields_minimal() {
        let api_key = create_api_key_credential(
            Some("test-api-key"),
            None,
            None,
            None,
            None,
            None,
        );

        let fields = api_key_to_fields(&api_key);

        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, Some("API Key".to_string()));
        assert_eq!(fields[0].value, Some("test-api-key".to_string()));
        assert_eq!(fields[0].r#type, FieldType::Hidden as u8);
    }

    #[test]
    fn test_api_key_to_fields_empty() {
        let api_key = create_api_key_credential(None, None, None, None, None, None);

        let fields = api_key_to_fields(&api_key);

        assert_eq!(fields.len(), 0);
    }

    #[test]
    fn test_api_key_to_fields_partial() {
        let api_key = create_api_key_credential(
            Some("secret-key"),
            Some("test_user"),
            Some("API_KEY"),
            None,
            None,
            None,
        );

        let fields = api_key_to_fields(&api_key);

        assert_eq!(fields.len(), 3);

        // Check that we have the expected fields
        let field_names: Vec<String> = fields
            .iter()
            .filter_map(|f| f.name.clone())
            .collect();

        assert!(field_names.contains(&"API Key".to_string()));
        assert!(field_names.contains(&"Username".to_string()));
        assert!(field_names.contains(&"Key Type".to_string()));
    }
}