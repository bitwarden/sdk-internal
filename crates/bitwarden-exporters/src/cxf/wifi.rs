use credential_exchange_format::WifiCredential;

use crate::{cxf::editable_field::create_field, Field};

/// Convert WiFi credentials to custom fields following the CXF mapping convention
pub fn wifi_to_fields(wifi: &WifiCredential) -> Vec<Field> {
    [
        // SSID: Text field
        wifi.ssid
            .as_ref()
            .map(|ssid| create_field("SSID".into(), ssid)),
        // Passphrase: Hidden field (concealed-string)
        wifi.passphrase
            .as_ref()
            .map(|passphrase| create_field("Passphrase".into(), passphrase)),
        // Network Security Type: Text field
        wifi.network_security_type
            .as_ref()
            .map(|security| create_field("Network Security Type".into(), security)),
        // Hidden: Boolean field
        wifi.hidden
            .as_ref()
            .map(|hidden| create_field("Hidden".into(), hidden)),
    ]
    .into_iter()
    .flatten()
    .collect()
}

#[cfg(test)]
mod tests {
    use bitwarden_vault::FieldType;
    use credential_exchange_format::EditableFieldWifiNetworkSecurityType;

    use super::*;

    #[test]
    fn test_wifi_to_fields_all_fields() {
        use credential_exchange_format::{
            EditableFieldBoolean, EditableFieldConcealedString, EditableFieldString,
        };

        let wifi = WifiCredential {
            ssid: Some(EditableFieldString("MyWiFi".to_string()).into()),
            passphrase: Some(EditableFieldConcealedString("secret123".to_string()).into()),
            network_security_type: Some(EditableFieldWifiNetworkSecurityType::Wpa2Personal.into()),
            hidden: Some(EditableFieldBoolean(false).into()),
        };

        let fields = wifi_to_fields(&wifi);

        assert_eq!(
            fields,
            vec![
                Field {
                    name: Some("SSID".to_string()),
                    value: Some("MyWiFi".to_string()),
                    r#type: FieldType::Text as u8,
                    linked_id: None,
                },
                Field {
                    name: Some("Passphrase".to_string()),
                    value: Some("secret123".to_string()),
                    r#type: FieldType::Hidden as u8,
                    linked_id: None,
                },
                Field {
                    name: Some("Network Security Type".to_string()),
                    value: Some("WPA2 Personal".to_string()),
                    r#type: FieldType::Text as u8,
                    linked_id: None,
                },
                Field {
                    name: Some("Hidden".to_string()),
                    value: Some("false".to_string()),
                    r#type: FieldType::Boolean as u8,
                    linked_id: None,
                },
            ]
        );
    }

    #[test]
    fn test_wifi_to_fields_minimal() {
        use credential_exchange_format::EditableFieldString;

        let wifi = WifiCredential {
            ssid: Some(EditableFieldString("BasicWiFi".to_string()).into()),
            passphrase: None,
            network_security_type: None,
            hidden: None,
        };

        let fields = wifi_to_fields(&wifi);

        assert_eq!(
            fields,
            vec![Field {
                name: Some("SSID".to_string()),
                value: Some("BasicWiFi".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            }]
        );
    }

    #[test]
    fn test_wifi_to_fields_empty() {
        let wifi = WifiCredential {
            ssid: None,
            passphrase: None,
            network_security_type: None,
            hidden: None,
        };

        let fields = wifi_to_fields(&wifi);

        assert_eq!(fields, vec![]);
    }

    #[test]
    fn test_wifi_to_fields_wpa3_security() {
        use credential_exchange_format::{
            EditableFieldBoolean, EditableFieldConcealedString, EditableFieldString,
        };

        let wifi = WifiCredential {
            ssid: Some(EditableFieldString("SecureWiFi".to_string()).into()),
            passphrase: Some(EditableFieldConcealedString("password123".to_string()).into()),
            network_security_type: Some(EditableFieldWifiNetworkSecurityType::Wpa3Personal.into()),
            hidden: Some(EditableFieldBoolean(true).into()),
        };

        let fields = wifi_to_fields(&wifi);

        assert_eq!(
            fields,
            vec![
                Field {
                    name: Some("SSID".to_string()),
                    value: Some("SecureWiFi".to_string()),
                    r#type: FieldType::Text as u8,
                    linked_id: None,
                },
                Field {
                    name: Some("Passphrase".to_string()),
                    value: Some("password123".to_string()),
                    r#type: FieldType::Hidden as u8,
                    linked_id: None,
                },
                Field {
                    name: Some("Network Security Type".to_string()),
                    value: Some("WPA3 Personal".to_string()),
                    r#type: FieldType::Text as u8,
                    linked_id: None,
                },
                Field {
                    name: Some("Hidden".to_string()),
                    value: Some("true".to_string()),
                    r#type: FieldType::Boolean as u8,
                    linked_id: None,
                },
            ]
        );
    }

    #[test]
    fn test_wifi_to_fields_unsecured() {
        use credential_exchange_format::EditableFieldString;

        let wifi = WifiCredential {
            ssid: Some(EditableFieldString("OpenWiFi".to_string()).into()),
            passphrase: None,
            network_security_type: Some(EditableFieldWifiNetworkSecurityType::Unsecured.into()),
            hidden: None,
        };

        let fields = wifi_to_fields(&wifi);

        assert_eq!(
            fields,
            vec![
                Field {
                    name: Some("SSID".to_string()),
                    value: Some("OpenWiFi".to_string()),
                    r#type: FieldType::Text as u8,
                    linked_id: None,
                },
                Field {
                    name: Some("Network Security Type".to_string()),
                    value: Some("Unsecured".to_string()),
                    r#type: FieldType::Text as u8,
                    linked_id: None,
                },
            ]
        );
    }

    #[test]
    fn test_wifi_to_fields_wep_security() {
        use credential_exchange_format::{EditableFieldConcealedString, EditableFieldString};

        let wifi = WifiCredential {
            ssid: Some(EditableFieldString("LegacyWiFi".to_string()).into()),
            passphrase: Some(EditableFieldConcealedString("wepkey123".to_string()).into()),
            network_security_type: Some(EditableFieldWifiNetworkSecurityType::Wep.into()),
            hidden: None,
        };

        let fields = wifi_to_fields(&wifi);

        assert_eq!(
            fields,
            vec![
                Field {
                    name: Some("SSID".to_string()),
                    value: Some("LegacyWiFi".to_string()),
                    r#type: FieldType::Text as u8,
                    linked_id: None,
                },
                Field {
                    name: Some("Passphrase".to_string()),
                    value: Some("wepkey123".to_string()),
                    r#type: FieldType::Hidden as u8,
                    linked_id: None,
                },
                Field {
                    name: Some("Network Security Type".to_string()),
                    value: Some("WEP".to_string()),
                    r#type: FieldType::Text as u8,
                    linked_id: None,
                },
            ]
        );
    }
}
