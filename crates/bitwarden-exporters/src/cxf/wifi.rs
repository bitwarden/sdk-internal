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
        use credential_exchange_format::{
            EditableFieldBoolean, EditableFieldConcealedString, EditableFieldString,
        };

        WifiCredential {
            ssid: ssid.map(|s| EditableFieldString(s.to_string()).into()),
            passphrase: passphrase.map(|p| EditableFieldConcealedString(p.to_string()).into()),
            network_security_type: security_type.map(|st| st.into()),
            hidden: hidden.map(|h| EditableFieldBoolean(h).into()),
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
