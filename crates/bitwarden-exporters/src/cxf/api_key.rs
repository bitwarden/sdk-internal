use credential_exchange_format::ApiKeyCredential;

use crate::{cxf::editable_field::create_field, Field};

/// Convert API key credentials to custom fields
pub fn api_key_to_fields(api_key: &ApiKeyCredential) -> Vec<Field> {
    [
        api_key.key.as_ref().map(|key| create_field("API Key", key)),
        api_key
            .username
            .as_ref()
            .map(|username| create_field("Username", username)),
        api_key
            .key_type
            .as_ref()
            .map(|key_type| create_field("Key Type", key_type)),
        api_key.url.as_ref().map(|url| create_field("URL", url)),
        api_key
            .valid_from
            .as_ref()
            .map(|valid_from| create_field("Valid From", valid_from)),
        api_key
            .expiry_date
            .as_ref()
            .map(|expiry_date| create_field("Expiry Date", expiry_date)),
    ]
    .into_iter()
    .flatten()
    .collect()
}

#[cfg(test)]
mod tests {
    use bitwarden_vault::FieldType;
    use chrono::NaiveDate;
    use credential_exchange_format::{EditableFieldConcealedString, EditableFieldDate};

    use super::*;

    #[test]
    fn test_api_key_to_fields_all_fields() {
        let api_key = ApiKeyCredential {
            key: Some(
                EditableFieldConcealedString("AIzaSyAyRofL-VJHZofHc-qOSkqVOdhvgQoJADk".to_string())
                    .into(),
            ),
            username: Some("john_doe".to_string().into()),
            key_type: Some("Bearer".to_string().into()),
            url: Some("https://api.example.com".to_string().into()),
            valid_from: Some(
                EditableFieldDate(NaiveDate::from_ymd_opt(2025, 1, 1).unwrap()).into(),
            ),
            expiry_date: Some(
                EditableFieldDate(NaiveDate::from_ymd_opt(2026, 1, 1).unwrap()).into(),
            ),
        };

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
        let api_key = ApiKeyCredential {
            key: Some("test-api-key".to_string().into()),
            username: None,
            key_type: None,
            url: None,
            valid_from: None,
            expiry_date: None,
        };

        let fields = api_key_to_fields(&api_key);

        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, Some("API Key".to_string()));
        assert_eq!(fields[0].value, Some("test-api-key".to_string()));
        assert_eq!(fields[0].r#type, FieldType::Hidden as u8);
    }

    #[test]
    fn test_api_key_to_fields_empty() {
        let api_key = ApiKeyCredential {
            key: None,
            username: None,
            key_type: None,
            url: None,
            valid_from: None,
            expiry_date: None,
        };

        let fields = api_key_to_fields(&api_key);

        assert_eq!(fields.len(), 0);
    }

    #[test]
    fn test_api_key_to_fields_partial() {
        let api_key = ApiKeyCredential {
            key: Some("secret-key".to_string().into()),
            username: Some("test_user".to_string().into()),
            key_type: Some("API_KEY".to_string().into()),
            url: None,
            valid_from: None,
            expiry_date: None,
        };

        let fields = api_key_to_fields(&api_key);

        assert_eq!(fields.len(), 3);

        // Check that we have the expected fields
        let field_names: Vec<String> = fields.iter().filter_map(|f| f.name.clone()).collect();

        assert!(field_names.contains(&"API Key".to_string()));
        assert!(field_names.contains(&"Username".to_string()));
        assert!(field_names.contains(&"Key Type".to_string()));
    }
}
