use bitwarden_vault::FieldType;
use credential_exchange_format::{
    EditableField, EditableFieldBoolean, EditableFieldConcealedString, EditableFieldString,
    EditableFieldWifiNetworkSecurityType,
};

use crate::Field;

/// Helper function to create a Field from any EditableField type
pub(super) fn create_field<T>(name: String, field: &T) -> Field
where
    T: EditableFieldToField,
{
    Field {
        name: Some(name),
        value: Some(field.field_value()),
        r#type: field.field_type() as u8,
        linked_id: None,
    }
}

/// Trait to convert EditableField types to Field values and types
pub(super) trait EditableFieldToField {
    fn field_value(&self) -> String;
    fn field_type(&self) -> FieldType;
}

impl EditableFieldToField for EditableField<EditableFieldString> {
    fn field_value(&self) -> String {
        self.value.0.clone()
    }

    fn field_type(&self) -> FieldType {
        FieldType::Text
    }
}

impl EditableFieldToField for EditableField<EditableFieldConcealedString> {
    fn field_value(&self) -> String {
        self.value.0.clone()
    }

    fn field_type(&self) -> FieldType {
        FieldType::Hidden
    }
}

impl EditableFieldToField for EditableField<EditableFieldBoolean> {
    fn field_value(&self) -> String {
        if self.value.0 { "true" } else { "false" }.to_string()
    }

    fn field_type(&self) -> FieldType {
        FieldType::Boolean
    }
}

impl EditableFieldToField for EditableField<EditableFieldWifiNetworkSecurityType> {
    fn field_value(&self) -> String {
        security_type_to_string(&self.value).to_string()
    }

    fn field_type(&self) -> FieldType {
        FieldType::Text
    }
}

/// Convert WiFi security type enum to human-readable string
fn security_type_to_string(security_type: &EditableFieldWifiNetworkSecurityType) -> &str {
    match security_type {
        EditableFieldWifiNetworkSecurityType::Unsecured => "Unsecured",
        EditableFieldWifiNetworkSecurityType::WpaPersonal => "WPA Personal",
        EditableFieldWifiNetworkSecurityType::Wpa2Personal => "WPA2 Personal",
        EditableFieldWifiNetworkSecurityType::Wpa3Personal => "WPA3 Personal",
        EditableFieldWifiNetworkSecurityType::Wep => "WEP",
        EditableFieldWifiNetworkSecurityType::Other(s) => s,
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

        let field = create_field("Test Name".to_string(), &editable_field);

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

        let field = create_field("Password".to_string(), &editable_field);

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

        let field = create_field("Is Enabled".to_string(), &editable_field);

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

        let field = create_field("Is Hidden".to_string(), &editable_field);

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

        let field = create_field("WiFi Security".to_string(), &editable_field);

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
}
