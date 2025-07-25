use bitwarden_vault::FieldType;
use credential_exchange_format::WifiCredential;

use crate::Field;

/// Convert WiFi credentials to custom fields following the CXF mapping convention
pub fn wifi_to_fields(wifi: &WifiCredential) -> Vec<Field> {
    let mut fields = Vec::new();

    // SSID: Text field
    if let Some(ssid) = &wifi.ssid {
        fields.push(Field {
            name: Some("SSID".to_string()),
            value: Some(ssid.value.0.clone()),
            r#type: FieldType::Text as u8,
            linked_id: None,
        });
    }

    // Passphrase: Hidden field (concealed-string)
    if let Some(passphrase) = &wifi.passphrase {
        fields.push(Field {
            name: Some("Passphrase".to_string()),
            value: Some(passphrase.value.0.clone()),
            r#type: FieldType::Hidden as u8,
            linked_id: None,
        });
    }

    // Network Security Type: Text field
    if let Some(security) = &wifi.network_security_type {
        let security_str = match &security.value {
            credential_exchange_format::EditableFieldWifiNetworkSecurityType::Unsecured => {
                "Unsecured"
            }
            credential_exchange_format::EditableFieldWifiNetworkSecurityType::WpaPersonal => {
                "WPA Personal"
            }
            credential_exchange_format::EditableFieldWifiNetworkSecurityType::Wpa2Personal => {
                "WPA2 Personal"
            }
            credential_exchange_format::EditableFieldWifiNetworkSecurityType::Wpa3Personal => {
                "WPA3 Personal"
            }
            credential_exchange_format::EditableFieldWifiNetworkSecurityType::Wep => "WEP",
            credential_exchange_format::EditableFieldWifiNetworkSecurityType::Other(s) => s,
        };
        fields.push(Field {
            name: Some("Network Security Type".to_string()),
            value: Some(security_str.to_string()),
            r#type: FieldType::Text as u8,
            linked_id: None,
        });
    }

    // Hidden: Boolean field
    if let Some(hidden) = &wifi.hidden {
        fields.push(Field {
            name: Some("Hidden".to_string()),
            value: Some(if hidden.value.0 { "true" } else { "false" }.to_string()),
            r#type: FieldType::Boolean as u8,
            linked_id: None,
        });
    }

    fields
}

#[cfg(test)]
mod tests {
    use bitwarden_vault::FieldType;
    use credential_exchange_format::{
        EditableField, EditableFieldBoolean, EditableFieldConcealedString, EditableFieldString,
        EditableFieldWifiNetworkSecurityType,
    };

    use super::*;

    /// Helper function to create a Field for testing
    fn create_field(name: &str, value: &str, field_type: FieldType) -> Field {
        Field {
            name: Some(name.to_string()),
            value: Some(value.to_string()),
            r#type: field_type as u8,
            linked_id: None,
        }
    }

    fn create_wifi_credential(
        ssid: Option<&str>,
        passphrase: Option<&str>,
        security_type: Option<EditableFieldWifiNetworkSecurityType>,
        hidden: Option<bool>,
    ) -> WifiCredential {
        WifiCredential {
            ssid: ssid.map(|s| EditableField {
                id: None,
                value: EditableFieldString(s.to_string()),
                label: None,
                extensions: None,
            }),
            passphrase: passphrase.map(|p| EditableField {
                id: None,
                value: EditableFieldConcealedString(p.to_string()),
                label: None,
                extensions: None,
            }),
            network_security_type: security_type.map(|st| EditableField {
                id: None,
                value: st,
                label: None,
                extensions: None,
            }),
            hidden: hidden.map(|h| EditableField {
                id: None,
                value: EditableFieldBoolean(h),
                label: None,
                extensions: None,
            }),
        }
    }

    #[test]
    fn test_wifi_to_fields_all_fields() {
        let wifi = create_wifi_credential(
            Some("MyWiFi"),
            Some("secret123"),
            Some(EditableFieldWifiNetworkSecurityType::Wpa2Personal),
            Some(false),
        );

        let fields = wifi_to_fields(&wifi);

        assert_eq!(
            fields,
            vec![
                create_field("SSID", "MyWiFi", FieldType::Text),
                create_field("Passphrase", "secret123", FieldType::Hidden),
                create_field("Network Security Type", "WPA2 Personal", FieldType::Text),
                create_field("Hidden", "false", FieldType::Boolean),
            ]
        );
    }

    #[test]
    fn test_wifi_to_fields_minimal() {
        let wifi = create_wifi_credential(Some("BasicWiFi"), None, None, None);

        let fields = wifi_to_fields(&wifi);

        assert_eq!(
            fields,
            vec![create_field("SSID", "BasicWiFi", FieldType::Text)]
        );
    }

    #[test]
    fn test_wifi_to_fields_empty() {
        let wifi = create_wifi_credential(None, None, None, None);

        let fields = wifi_to_fields(&wifi);

        assert_eq!(fields, vec![]);
    }

    #[test]
    fn test_wifi_to_fields_wpa3_security() {
        let wifi = create_wifi_credential(
            Some("SecureWiFi"),
            Some("password123"),
            Some(EditableFieldWifiNetworkSecurityType::Wpa3Personal),
            Some(true),
        );

        let fields = wifi_to_fields(&wifi);

        assert_eq!(
            fields,
            vec![
                create_field("SSID", "SecureWiFi", FieldType::Text),
                create_field("Passphrase", "password123", FieldType::Hidden),
                create_field("Network Security Type", "WPA3 Personal", FieldType::Text),
                create_field("Hidden", "true", FieldType::Boolean),
            ]
        );
    }

    #[test]
    fn test_wifi_to_fields_unsecured() {
        let wifi = create_wifi_credential(
            Some("OpenWiFi"),
            None,
            Some(EditableFieldWifiNetworkSecurityType::Unsecured),
            None,
        );

        let fields = wifi_to_fields(&wifi);

        assert_eq!(
            fields,
            vec![
                create_field("SSID", "OpenWiFi", FieldType::Text),
                create_field("Network Security Type", "Unsecured", FieldType::Text),
            ]
        );
    }

    #[test]
    fn test_wifi_to_fields_wep_security() {
        let wifi = create_wifi_credential(
            Some("LegacyWiFi"),
            Some("wepkey123"),
            Some(EditableFieldWifiNetworkSecurityType::Wep),
            None,
        );

        let fields = wifi_to_fields(&wifi);

        assert_eq!(
            fields,
            vec![
                create_field("SSID", "LegacyWiFi", FieldType::Text),
                create_field("Passphrase", "wepkey123", FieldType::Hidden),
                create_field("Network Security Type", "WEP", FieldType::Text),
            ]
        );
    }
}
