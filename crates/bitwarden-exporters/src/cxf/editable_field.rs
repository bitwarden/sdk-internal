use bitwarden_vault::FieldType;
use credential_exchange_format::{
    EditableField, EditableFieldBoolean, EditableFieldConcealedString, EditableFieldCountryCode,
    EditableFieldDate, EditableFieldString, EditableFieldSubdivisionCode, EditableFieldValue,
    EditableFieldWifiNetworkSecurityType, EditableFieldYearMonth,
};

use crate::Field;

/// Helper function to create a Field from any EditableField type
pub(super) fn create_field<T>(field: &T, overridden_name: Option<impl Into<String>>) -> Field
where
    T: EditableFieldToField,
{
    let field_name = overridden_name
        .map(Into::into)
        .or_else(|| field.label().clone());

    Field {
        name: field_name,
        value: Some(field.field_value()),
        r#type: T::FIELD_TYPE as u8,
        linked_id: None,
    }
}


/// Helper function to create an EditableField with common properties
fn create_editable_field<T>(name: String, value: T) -> EditableField<T> {
    EditableField {
        id: None,
        label: Some(name),
        value,
        extensions: None,
    }
}

/// Convert Bitwarden Field to CXF EditableFieldValue with proper type mapping
pub(super) fn field_to_editable_field_value(field: Field) -> Option<EditableFieldValue> {
    let name = field.name?;

    match field.r#type {
        x if x == FieldType::Text as u8 => field.value.map(|value| {
            EditableFieldValue::String(create_editable_field(name, EditableFieldString(value)))
        }),

        x if x == FieldType::Hidden as u8 => field.value.map(|value| {
            EditableFieldValue::ConcealedString(create_editable_field(
                name,
                EditableFieldConcealedString(value),
            ))
        }),

        x if x == FieldType::Boolean as u8 => field.value?.parse::<bool>().ok().map(|bool_value| {
            EditableFieldValue::Boolean(create_editable_field(
                name,
                EditableFieldBoolean(bool_value),
            ))
        }),

        x if x == FieldType::Linked as u8 => {
            let value = field
                .value
                .or_else(|| field.linked_id.map(|id| id.to_string()))?;
            Some(EditableFieldValue::String(create_editable_field(
                name,
                EditableFieldString(value),
            )))
        }

        _ => field.value.map(|value| {
            EditableFieldValue::String(create_editable_field(name, EditableFieldString(value)))
        }),
    }
}

/// Trait to define field type and value conversion for inner field types
pub(super) trait InnerFieldType {
    const FIELD_TYPE: FieldType;

    fn to_field_value(&self) -> String;
}

impl InnerFieldType for EditableFieldString {
    const FIELD_TYPE: FieldType = FieldType::Text;

    fn to_field_value(&self) -> String {
        self.0.clone()
    }
}

impl InnerFieldType for EditableFieldConcealedString {
    const FIELD_TYPE: FieldType = FieldType::Hidden;

    fn to_field_value(&self) -> String {
        self.0.clone()
    }
}

impl InnerFieldType for EditableFieldBoolean {
    const FIELD_TYPE: FieldType = FieldType::Boolean;

    fn to_field_value(&self) -> String {
        self.0.to_string()
    }
}

impl InnerFieldType for EditableFieldWifiNetworkSecurityType {
    const FIELD_TYPE: FieldType = FieldType::Text;

    fn to_field_value(&self) -> String {
        security_type_to_string(self).to_string()
    }
}

impl InnerFieldType for EditableFieldCountryCode {
    const FIELD_TYPE: FieldType = FieldType::Text;

    fn to_field_value(&self) -> String {
        self.0.clone()
    }
}

impl InnerFieldType for EditableFieldDate {
    const FIELD_TYPE: FieldType = FieldType::Text;

    fn to_field_value(&self) -> String {
        self.0.to_string()
    }
}

impl InnerFieldType for EditableFieldYearMonth {
    const FIELD_TYPE: FieldType = FieldType::Text;

    fn to_field_value(&self) -> String {
        format!("{:04}-{:02}", self.year, self.month.number_from_month())
    }
}

impl InnerFieldType for EditableFieldSubdivisionCode {
    const FIELD_TYPE: FieldType = FieldType::Text;

    fn to_field_value(&self) -> String {
        self.0.clone()
    }
}

/// Trait to convert CXP EditableField types to Bitwarden Field values and types
pub(super) trait EditableFieldToField {
    const FIELD_TYPE: FieldType;

    fn field_value(&self) -> String;
    fn label(&self) -> &Option<String>;
}

impl<T> EditableFieldToField for EditableField<T>
where
    T: InnerFieldType,
{
    const FIELD_TYPE: FieldType = T::FIELD_TYPE;

    fn field_value(&self) -> String {
        self.value.to_field_value()
    }

    fn label(&self) -> &Option<String> {
        &self.label
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

        let field = create_field(&editable_field, Some("Test Name"));

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

        let field = create_field(&editable_field, Some("Password"));

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

        let field = create_field(&editable_field, Some("Is Enabled"));

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

        let field = create_field(&editable_field, Some("Is Hidden"));

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

        let field = create_field(&editable_field, Some("WiFi Security"));

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

        let field = create_field(&editable_field, Some("Expiry Date".to_string()));

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

        let field = create_field(&editable_field, Some("Card Expiry"));

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

    #[test]
    fn test_create_field_with_none_name_uses_label() {
        let editable_field = EditableField {
            id: None,
            label: Some("Label From Field".to_string()),
            value: EditableFieldString("Test Value".to_string()),
            extensions: None,
        };

        let field = create_field(&editable_field, None::<String>);

        assert_eq!(
            field,
            Field {
                name: Some("Label From Field".to_string()),
                value: Some("Test Value".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            }
        );
    }

    #[test]
    fn test_create_field_with_none_name_and_none_label() {
        let editable_field = EditableField {
            id: None,
            label: None,
            value: EditableFieldString("Test Value".to_string()),
            extensions: None,
        };

        let field = create_field(&editable_field, None::<String>);

        assert_eq!(
            field,
            Field {
                name: None,
                value: Some("Test Value".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            }
        );
    }
}
