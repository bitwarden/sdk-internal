use credential_exchange_format::WifiCredential;

pub fn wifi_to_notes(wifi: &WifiCredential) -> String {
    let mut lines = Vec::new();

    if let Some(ssid) = &wifi.ssid {
        lines.push(format!("ssid: {}", ssid.value.0));
    }
    if let Some(passphrase) = &wifi.passphrase {
        lines.push(format!("passphrase: {}", passphrase.value.0));
    }
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
        lines.push(format!("network_security_type: {}", security_str));
    }
    if let Some(hidden) = &wifi.hidden {
        lines.push(format!(
            "hidden: {}",
            if hidden.value.0 { "true" } else { "false" }
        ));
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use credential_exchange_format::{
        EditableField, EditableFieldBoolean, EditableFieldConcealedString, EditableFieldString,
        EditableFieldWifiNetworkSecurityType,
    };

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
    fn test_wifi_to_notes_all_fields() {
        let wifi = create_wifi_credential(
            Some("MyWiFi"),
            Some("secret123"),
            Some(EditableFieldWifiNetworkSecurityType::Wpa2Personal),
            Some(false),
        );

        let result = wifi_to_notes(&wifi);
        let expected = "ssid: MyWiFi\npassphrase: secret123\nnetwork_security_type: WPA2 Personal\nhidden: false";

        assert_eq!(result, expected);
    }

    #[test]
    fn test_wifi_to_notes_minimal_fields() {
        let wifi = create_wifi_credential(Some("BasicWiFi"), None, None, None);

        let result = wifi_to_notes(&wifi);
        let expected = "ssid: BasicWiFi";

        assert_eq!(result, expected);
    }

    #[test]
    fn test_wifi_to_notes_empty_wifi() {
        let wifi = create_wifi_credential(None, None, None, None);

        let result = wifi_to_notes(&wifi);

        assert_eq!(result, "");
    }

    #[test]
    fn test_wifi_to_notes_hidden_true() {
        let wifi = create_wifi_credential(
            Some("HiddenNetwork"),
            Some("password"),
            Some(EditableFieldWifiNetworkSecurityType::WpaPersonal),
            Some(true),
        );

        let result = wifi_to_notes(&wifi);
        let expected = "ssid: HiddenNetwork\npassphrase: password\nnetwork_security_type: WPA Personal\nhidden: true";

        assert_eq!(result, expected);
    }

    #[test]
    fn test_wifi_to_notes_all_security_types() {
        let security_types = vec![
            (EditableFieldWifiNetworkSecurityType::Unsecured, "Unsecured"),
            (
                EditableFieldWifiNetworkSecurityType::WpaPersonal,
                "WPA Personal",
            ),
            (
                EditableFieldWifiNetworkSecurityType::Wpa2Personal,
                "WPA2 Personal",
            ),
            (
                EditableFieldWifiNetworkSecurityType::Wpa3Personal,
                "WPA3 Personal",
            ),
            (EditableFieldWifiNetworkSecurityType::Wep, "WEP"),
            (
                EditableFieldWifiNetworkSecurityType::Other("Custom".to_string()),
                "Custom",
            ),
        ];

        for (security_type, expected_str) in security_types {
            let wifi = create_wifi_credential(Some("TestNet"), None, Some(security_type), None);

            let result = wifi_to_notes(&wifi);
            let expected = format!("ssid: TestNet\nnetwork_security_type: {}", expected_str);

            assert_eq!(
                result, expected,
                "Failed for security type: {:?}",
                expected_str
            );
        }
    }

    #[test]
    fn test_wifi_to_notes_special_characters() {
        let wifi = create_wifi_credential(
            Some("WiFi with spaces & symbols!"),
            Some("p@ssw0rd#123"),
            Some(EditableFieldWifiNetworkSecurityType::Other(
                "Custom-WPA".to_string(),
            )),
            Some(false),
        );

        let result = wifi_to_notes(&wifi);
        let expected = "ssid: WiFi with spaces & symbols!\npassphrase: p@ssw0rd#123\nnetwork_security_type: Custom-WPA\nhidden: false";

        assert_eq!(result, expected);
    }

    #[test]
    fn test_wifi_to_notes_only_passphrase() {
        let wifi = create_wifi_credential(None, Some("onlypassword"), None, None);

        let result = wifi_to_notes(&wifi);
        let expected = "passphrase: onlypassword";

        assert_eq!(result, expected);
    }

    #[test]
    fn test_wifi_to_notes_only_hidden() {
        let wifi = create_wifi_credential(None, None, None, Some(true));

        let result = wifi_to_notes(&wifi);
        let expected = "hidden: true";

        assert_eq!(result, expected);
    }

    #[test]
    fn test_wifi_to_notes_empty() {
        let wifi = create_wifi_credential(None, None, None, None);

        let result = wifi_to_notes(&wifi);
        let expected = "";

        assert_eq!(result, expected);
    }
}
