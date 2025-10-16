use credential_exchange_format::WifiCredential;

use crate::{Field, cxf::editable_field::create_field};

/// Convert WiFi credentials to custom fields following the CXF mapping convention
pub(super) fn wifi_to_fields(wifi: &WifiCredential) -> Vec<Field> {
    [
        // SSID: Text field
        wifi.ssid
            .as_ref()
            .map(|ssid| create_field(ssid, Some("SSID"))),
        // Passphrase: Hidden field (concealed-string)
        wifi.passphrase
            .as_ref()
            .map(|passphrase| create_field(passphrase, Some("Passphrase"))),
        // Network Security Type: Text field
        wifi.network_security_type
            .as_ref()
            .map(|security| create_field(security, Some("Network Security Type"))),
        // Hidden: Boolean field
        wifi.hidden
            .as_ref()
            .map(|hidden| create_field(hidden, Some("Hidden"))),
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
        let wifi = WifiCredential {
            ssid: Some("MyWiFi".to_owned().into()),
            passphrase: Some("secret123".to_owned().into()),
            network_security_type: Some(EditableFieldWifiNetworkSecurityType::Wpa2Personal.into()),
            hidden: Some(false.into()),
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
        let wifi = WifiCredential {
            ssid: Some("BasicWiFi".to_owned().into()),
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
        let wifi = WifiCredential {
            ssid: Some("SecureWiFi".to_owned().into()),
            passphrase: Some("password123".to_owned().into()),
            network_security_type: Some(EditableFieldWifiNetworkSecurityType::Wpa3Personal.into()),
            hidden: Some(true.into()),
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
        let wifi = WifiCredential {
            ssid: Some("OpenWiFi".to_owned().into()),
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
        let wifi = WifiCredential {
            ssid: Some("LegacyWiFi".to_owned().into()),
            passphrase: Some("wepkey123".to_owned().into()),
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
