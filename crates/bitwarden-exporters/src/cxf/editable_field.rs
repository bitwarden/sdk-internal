use bitwarden_vault::FieldType;
use credential_exchange_format::{
    EditableField, EditableFieldBoolean, EditableFieldConcealedString, EditableFieldCountryCode,
    EditableFieldDate, EditableFieldString, EditableFieldWifiNetworkSecurityType,
    EditableFieldYearMonth,
};

use crate::Field;

/// Helper function to create a Field from any EditableField type
pub(super) fn create_field<T>(name: impl Into<String>, field: &T) -> Field
where
    T: EditableFieldToField,
{
    Field {
        name: Some(name.into()),
        value: Some(field.field_value()),
        r#type: T::FIELD_TYPE as u8,
        linked_id: None,
    }
}

/// Trait to convert CXP EditableField types to Bitwarden Field values and types
pub(super) trait EditableFieldToField {
    const FIELD_TYPE: FieldType;

    fn field_value(&self) -> String;
}

impl EditableFieldToField for EditableField<EditableFieldString> {
    const FIELD_TYPE: FieldType = FieldType::Text;

    fn field_value(&self) -> String {
        self.value.0.clone()
    }
}

impl EditableFieldToField for EditableField<EditableFieldConcealedString> {
    const FIELD_TYPE: FieldType = FieldType::Hidden;

    fn field_value(&self) -> String {
        self.value.0.clone()
    }
}

impl EditableFieldToField for EditableField<EditableFieldBoolean> {
    const FIELD_TYPE: FieldType = FieldType::Boolean;

    fn field_value(&self) -> String {
        self.value.0.to_string()
    }
}

impl EditableFieldToField for EditableField<EditableFieldWifiNetworkSecurityType> {
    const FIELD_TYPE: FieldType = FieldType::Text;

    fn field_value(&self) -> String {
        security_type_to_string(&self.value).to_string()
    }
}

impl EditableFieldToField for EditableField<EditableFieldCountryCode> {
    const FIELD_TYPE: FieldType = FieldType::Text;

    fn field_value(&self) -> String {
        self.value.0.clone()
    }
}

impl EditableFieldToField for EditableField<EditableFieldDate> {
    const FIELD_TYPE: FieldType = FieldType::Text;

    fn field_value(&self) -> String {
        self.value.0.to_string()
    }
}

impl EditableFieldToField for EditableField<EditableFieldYearMonth> {
    const FIELD_TYPE: FieldType = FieldType::Text;

    fn field_value(&self) -> String {
        format!(
            "{:04}-{:02}",
            self.value.year,
            self.value.month.number_from_month()
        )
    }
}

/// Convert WiFi security type enum to human-readable string
fn security_type_to_string(security_type: &EditableFieldWifiNetworkSecurityType) -> &str {
    use EditableFieldWifiNetworkSecurityType::*;
    match security_type {
        Unsecured => "Unsecured",
        WpaPersonal => "WPA Personal",
        Wpa2Personal => "WPA2 Personal",
        Wpa3Personal => "WPA3 Personal",
        Wep => "WEP",
        Other(s) => s,
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_field_string() {
        let editable_field = EditableField {
            id: None,
            label: None,
            value: EditableFieldString("Test Value".to_string()),
            extensions: None,
        };

        let field = create_field("Test Name", &editable_field);

        assert_eq!(
            field,
            Field {
                name: Some("Test Name".to_string()),
                value: Some("Test Value".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            }
        );
    }

    #[test]
    fn test_create_field_concealed_string() {
        let editable_field = EditableField {
            id: None,
            label: None,
            value: EditableFieldConcealedString("Secret123".to_string()),
            extensions: None,
        };

        let field = create_field("Password", &editable_field);

        assert_eq!(
            field,
            Field {
                name: Some("Password".to_string()),
                value: Some("Secret123".to_string()),
                r#type: FieldType::Hidden as u8,
                linked_id: None,
            }
        );
    }

    #[test]
    fn test_create_field_boolean_true() {
        let editable_field = EditableField {
            id: None,
            label: None,
            value: EditableFieldBoolean(true),
            extensions: None,
        };

        let field = create_field("Is Enabled", &editable_field);

        assert_eq!(
            field,
            Field {
                name: Some("Is Enabled".to_string()),
                value: Some("true".to_string()),
                r#type: FieldType::Boolean as u8,
                linked_id: None,
            }
        );
    }

    #[test]
    fn test_create_field_boolean_false() {
        let editable_field = EditableField {
            id: None,
            label: None,
            value: EditableFieldBoolean(false),
            extensions: None,
        };

        let field = create_field("Is Hidden", &editable_field);

        assert_eq!(
            field,
            Field {
                name: Some("Is Hidden".to_string()),
                value: Some("false".to_string()),
                r#type: FieldType::Boolean as u8,
                linked_id: None,
            }
        );
    }

    #[test]
    fn test_create_field_wifi_security() {
        let editable_field = EditableField {
            id: None,
            label: None,
            value: EditableFieldWifiNetworkSecurityType::Wpa3Personal,
            extensions: None,
        };

        let field = create_field("WiFi Security", &editable_field);

        assert_eq!(
            field,
            Field {
                name: Some("WiFi Security".to_string()),
                value: Some("WPA3 Personal".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            }
        );
    }

    #[test]
    fn test_security_type_to_string() {
        assert_eq!(
            security_type_to_string(&EditableFieldWifiNetworkSecurityType::Unsecured),
            "Unsecured"
        );
        assert_eq!(
            security_type_to_string(&EditableFieldWifiNetworkSecurityType::WpaPersonal),
            "WPA Personal"
        );
        assert_eq!(
            security_type_to_string(&EditableFieldWifiNetworkSecurityType::Wpa2Personal),
            "WPA2 Personal"
        );
        assert_eq!(
            security_type_to_string(&EditableFieldWifiNetworkSecurityType::Wpa3Personal),
            "WPA3 Personal"
        );
        assert_eq!(
            security_type_to_string(&EditableFieldWifiNetworkSecurityType::Wep),
            "WEP"
        );

        let custom_security = "WPA2 Enterprise";
        assert_eq!(
            security_type_to_string(&EditableFieldWifiNetworkSecurityType::Other(
                custom_security.to_string()
            )),
            custom_security
        );
    }

    #[test]
    fn test_create_field_date() {
        use chrono::NaiveDate;

        let editable_field = EditableField {
            id: None,
            label: None,
            value: EditableFieldDate(NaiveDate::from_ymd_opt(2025, 1, 15).unwrap()),
            extensions: None,
        };

        let field = create_field("Expiry Date".to_string(), &editable_field);

        assert_eq!(
            field,
            Field {
                name: Some("Expiry Date".to_string()),
                value: Some("2025-01-15".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            }
        );
    }

    #[test]
    fn test_create_field_year_month() {
        use chrono::Month;

        let editable_field = EditableField {
            id: None,
            label: None,
            value: EditableFieldYearMonth {
                year: 2025,
                month: Month::December,
            },
            extensions: None,
        };

        let field = create_field("Card Expiry", &editable_field);

        assert_eq!(
            field,
            Field {
                name: Some("Card Expiry".to_string()),
                value: Some("2025-12".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            }
        );
    }
}
