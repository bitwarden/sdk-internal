//! Sample file integration tests for CXF import functionality
//!
//! These tests validate the parsing of a Dashlane export.

#[cfg(test)]
mod tests {
    use crate::{
        Card, CipherType, Field, Identity, ImportingCipher, Login, LoginUri, SecureNote,
        SecureNoteType,
        cxf::{CxfError, parse_cxf},
    };

    fn load_file() -> Result<Vec<ImportingCipher>, CxfError> {
        use std::fs;

        // Read the actual Dashlane example file
        let cxf_data = fs::read_to_string("resources/dashlane_export.json").unwrap();

        let items = parse_cxf(cxf_data)?;

        Ok(items)
    }

    #[test]
    fn test_import_dashlane() {
        let result = load_file().unwrap();

        assert_eq!(
            result,
            vec![
                // Credit Card
                ImportingCipher {
                    folder_id: None,
                    name: "Dashlane CC".to_string(),
                    notes: None,
                    r#type: CipherType::Card(Box::new(Card {
                        cardholder_name: Some("Dashlane CC".to_string()),
                        exp_month: Some("10".to_string()),
                        exp_year: Some("2028".to_string()),
                        code: Some("999".to_string()),
                        brand: None,
                        number: Some("4111111111111111".to_string()),
                    })),
                    favorite: false,
                    reprompt: 0,
                    fields: vec![],
                    revision_date: "2056-09-03T20:11:08Z".parse().unwrap(),
                    creation_date: "2056-09-03T20:11:08Z".parse().unwrap(),
                    deleted_date: None,
                },
                // Basic Auth w/ TOTP
                ImportingCipher {
                    folder_id: None,
                    name: "adobe.com".to_string(),
                    notes: None,
                    r#type: CipherType::Login(Box::new(Login {
                        username: Some("dashlane@dashlane.com".to_string()),
                        password: Some("asdfgh".to_string()),
                        login_uris: vec![LoginUri {
                            uri: Some("adobe.com".to_string()),
                            r#match: None
                        }],
                        totp: Some("otpauth://totp?secret=JBSWY3DPEHPK3PXP".to_string()),
                        fido2_credentials: None,
                    })),
                    favorite: false,
                    reprompt: 0,
                    fields: vec![],
                    revision_date: "2056-09-03T20:11:08Z".parse().unwrap(),
                    creation_date: "2056-09-03T20:11:08Z".parse().unwrap(),
                    deleted_date: None,
                },
                // Secure note
                ImportingCipher {
                    folder_id: None,
                    name: "Dashlane note".to_string(),
                    notes: Some("Dashlane note content".to_string()),
                    r#type: CipherType::SecureNote(Box::new(SecureNote {
                        r#type: SecureNoteType::Generic,
                    })),
                    favorite: false,
                    reprompt: 0,
                    fields: vec![],
                    revision_date: "2056-09-03T20:11:08Z".parse().unwrap(),
                    creation_date: "2056-09-03T20:11:08Z".parse().unwrap(),
                    deleted_date: None,
                },
                // Address
                ImportingCipher {
                    folder_id: None,
                    name: "Dashlane address".to_string(),
                    notes: None,
                    r#type: CipherType::Identity(Box::new(Identity {
                        title: None,
                        first_name: None,
                        middle_name: None,
                        last_name: None,
                        address1: Some("Addy1".to_string()),
                        address2: None,
                        address3: None,
                        city: Some("City".to_string()),
                        state: None,
                        postal_code: Some("12345".to_string()),
                        country: None,
                        company: None,
                        email: None,
                        phone: None,
                        ssn: None,
                        username: None,
                        passport_number: None,
                        license_number: None,
                    })),
                    favorite: false,
                    reprompt: 0,
                    fields: vec![],
                    revision_date: "2056-09-03T20:11:08Z".parse().unwrap(),
                    creation_date: "2056-09-03T20:11:08Z".parse().unwrap(),
                    deleted_date: None,
                },
                // ID Card
                ImportingCipher {
                    folder_id: None,
                    name: "".to_string(),
                    notes: None,
                    r#type: CipherType::Identity(Box::new(Identity {
                        title: None,
                        first_name: None,
                        middle_name: None,
                        last_name: None,
                        address1: None,
                        address2: None,
                        address3: None,
                        city: None,
                        state: None,
                        postal_code: None,
                        country: None,
                        company: None,
                        email: None,
                        phone: None,
                        ssn: None,
                        username: None,
                        passport_number: Some("LicenseNumber".to_string()),
                        license_number: None,
                    })),
                    favorite: false,
                    reprompt: 0,
                    fields: vec![
                        Field {
                            name: Some("Issue Date".to_string()),
                            value: Some("2025-10-09".to_string()),
                            r#type: 0,
                            linked_id: None,
                        },
                        Field {
                            name: Some("Expiry Date".to_string()),
                            value: Some("2025-10-10".to_string()),
                            r#type: 0,
                            linked_id: None,
                        }
                    ],
                    revision_date: "2056-09-03T20:11:08Z".parse().unwrap(),
                    creation_date: "2056-09-03T20:11:08Z".parse().unwrap(),
                    deleted_date: None,
                },
                // Passport
                ImportingCipher {
                    folder_id: None,
                    name: "".to_string(),
                    notes: None,
                    r#type: CipherType::Identity(Box::new(Identity {
                        title: None,
                        first_name: None,
                        middle_name: None,
                        last_name: None,
                        address1: None,
                        address2: None,
                        address3: None,
                        city: None,
                        state: None,
                        postal_code: None,
                        country: None,
                        company: None,
                        email: None,
                        phone: None,
                        ssn: None,
                        username: None,
                        passport_number: Some("PassportNumber".to_string()),
                        license_number: None,
                    })),
                    favorite: false,
                    reprompt: 0,
                    fields: vec![
                        Field {
                            name: Some("Issue Date".to_string()),
                            value: Some("2025-10-09".to_string()),
                            r#type: 0,
                            linked_id: None,
                        },
                        Field {
                            name: Some("Expiry Date".to_string()),
                            value: Some("2025-10-10".to_string()),
                            r#type: 0,
                            linked_id: None,
                        },
                        Field {
                            name: Some("Issuing Authority".to_string()),
                            value: Some("PassportIssuer".to_string()),
                            r#type: 0,
                            linked_id: None,
                        },
                    ],
                    revision_date: "2056-09-03T20:11:08Z".parse().unwrap(),
                    creation_date: "2056-09-03T20:11:08Z".parse().unwrap(),
                    deleted_date: None,
                },
                // Drivers license
                ImportingCipher {
                    folder_id: None,
                    name: "".to_string(),
                    notes: None,
                    r#type: CipherType::Identity(Box::new(Identity {
                        title: None,
                        first_name: None,
                        middle_name: None,
                        last_name: None,
                        address1: None,
                        address2: None,
                        address3: None,
                        city: None,
                        state: None,
                        postal_code: None,
                        country: None,
                        company: None,
                        email: None,
                        phone: None,
                        ssn: None,
                        username: None,
                        passport_number: None,
                        license_number: Some("LicenseNumber".to_string()),
                    })),
                    favorite: false,
                    reprompt: 0,
                    fields: vec![
                        Field {
                            name: Some("Issue Date".to_string()),
                            value: Some("2025-10-09".to_string()),
                            r#type: 0,
                            linked_id: None,
                        },
                        Field {
                            name: Some("Expiry Date".to_string()),
                            value: Some("2025-10-10".to_string()),
                            r#type: 0,
                            linked_id: None,
                        },
                    ],
                    revision_date: "2056-09-03T20:11:08Z".parse().unwrap(),
                    creation_date: "2056-09-03T20:11:08Z".parse().unwrap(),
                    deleted_date: None,
                },
                // SSN
                ImportingCipher {
                    folder_id: None,
                    name: "".to_string(),
                    notes: None,
                    r#type: CipherType::Identity(Box::new(Identity {
                        title: None,
                        first_name: None,
                        middle_name: None,
                        last_name: None,
                        address1: None,
                        address2: None,
                        address3: None,
                        city: None,
                        state: None,
                        postal_code: None,
                        country: None,
                        company: None,
                        email: None,
                        phone: None,
                        ssn: Some("SSN".to_string()),
                        username: None,
                        passport_number: None,
                        license_number: None,
                    })),
                    favorite: false,
                    reprompt: 0,
                    fields: vec![],
                    revision_date: "2056-09-03T20:11:08Z".parse().unwrap(),
                    creation_date: "2056-09-03T20:11:08Z".parse().unwrap(),
                    deleted_date: None,
                },
                // Tax ID
                ImportingCipher {
                    folder_id: None,
                    name: "".to_string(),
                    notes: None,
                    r#type: CipherType::Identity(Box::new(Identity {
                        title: None,
                        first_name: None,
                        middle_name: None,
                        last_name: None,
                        address1: None,
                        address2: None,
                        address3: None,
                        city: None,
                        state: None,
                        postal_code: None,
                        country: None,
                        company: None,
                        email: None,
                        phone: None,
                        ssn: None,
                        username: None,
                        passport_number: Some("TaxNumber".to_string()),
                        license_number: None,
                    })),
                    favorite: false,
                    reprompt: 0,
                    fields: vec![],
                    revision_date: "2056-09-03T20:11:08Z".parse().unwrap(),
                    creation_date: "2056-09-03T20:11:08Z".parse().unwrap(),
                    deleted_date: None,
                },
                // Wifi
                ImportingCipher {
                    folder_id: None,
                    name: "WifiOrg".to_string(),
                    notes: None,
                    r#type: CipherType::SecureNote(Box::new(SecureNote {
                        r#type: SecureNoteType::Generic
                    })),
                    favorite: false,
                    reprompt: 0,
                    fields: vec![
                        Field {
                            name: Some("SSID".to_string()),
                            value: Some("Dashlane WiFi".to_string()),
                            r#type: 0,
                            linked_id: None,
                        },
                        Field {
                            name: Some("Passphrase".to_string()),
                            value: Some("123456".to_string()),
                            r#type: 1,
                            linked_id: None,
                        },
                        Field {
                            name: Some("Hidden".to_string()),
                            value: Some("false".to_string()),
                            r#type: 2,
                            linked_id: None,
                        }
                    ],
                    revision_date: "2056-09-03T20:11:08Z".parse().unwrap(),
                    creation_date: "2056-09-03T20:11:08Z".parse().unwrap(),
                    deleted_date: None,
                },
                // Company
                ImportingCipher {
                    folder_id: None,
                    name: "Dashlane company".to_string(),
                    notes: None,
                    r#type: CipherType::Identity(Box::new(Identity {
                        title: None,
                        first_name: Some("Dashlane".to_string()),
                        middle_name: None,
                        last_name: Some("company".to_string()),
                        address1: None,
                        address2: None,
                        address3: None,
                        city: None,
                        state: None,
                        postal_code: None,
                        country: None,
                        company: None,
                        email: None,
                        phone: None,
                        ssn: None,
                        username: None,
                        passport_number: None,
                        license_number: None,
                    })),
                    favorite: false,
                    reprompt: 0,
                    fields: vec![Field {
                        name: Some("Issuing Authority".to_string()),
                        value: Some("Company title".to_string()),
                        r#type: 0,
                        linked_id: None,
                    }],
                    revision_date: "2056-09-03T20:11:08Z".parse().unwrap(),
                    creation_date: "2056-09-03T20:11:08Z".parse().unwrap(),
                    deleted_date: None,
                },
                // Person name
                ImportingCipher {
                    folder_id: None,
                    name: "Dashlane Person".to_string(),
                    notes: None,
                    r#type: CipherType::Identity(Box::new(Identity {
                        title: Some("mr".to_string()),
                        first_name: Some("Dashlane Person".to_string()),
                        middle_name: Some("M".to_string()),
                        last_name: None,
                        address1: None,
                        address2: None,
                        address3: None,
                        city: None,
                        state: None,
                        postal_code: None,
                        country: None,
                        company: None,
                        email: None,
                        phone: None,
                        ssn: None,
                        username: None,
                        passport_number: None,
                        license_number: None,
                    })),
                    favorite: false,
                    reprompt: 0,
                    fields: vec![Field {
                        name: Some("Informal Given Name".to_string()),
                        value: Some("DashlaneUsername".to_string()),
                        r#type: 0,
                        linked_id: None,
                    }],
                    revision_date: "2056-09-03T20:11:08Z".parse().unwrap(),
                    creation_date: "2056-09-03T20:11:08Z".parse().unwrap(),
                    deleted_date: None,
                }
            ]
        )
    }
}
