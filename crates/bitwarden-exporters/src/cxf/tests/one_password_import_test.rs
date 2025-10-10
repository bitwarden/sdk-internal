//! Sample file integration tests for CXF import functionality
//!
//! These tests validate the parsing of a 1password export.

#[cfg(test)]
mod tests {

    use crate::{
        Card, CipherType, Field, Identity, ImportingCipher, Login, LoginUri, SecureNote,
        SecureNoteType,
        cxf::{CxfError, parse_cxf},
    };

    fn load_file() -> Result<Vec<ImportingCipher>, CxfError> {
        use std::fs;

        // Read the actual 1password example file
        let cxf_data = fs::read_to_string("resources/1p_export.json").unwrap();

        let items = parse_cxf(cxf_data)?;

        Ok(items)
    }

    #[test]
    fn test_import_1password() {
        let result = load_file().unwrap();

        assert_eq!(
            result,
            vec![
                ImportingCipher {
                    folder_id: None,
                    name: "John doe".to_string(),
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
                        license_number: None
                    })),
                    favorite: false,
                    reprompt: 0,
                    fields: vec![],
                    revision_date: "2056-09-03T20:11:08Z".parse().unwrap(),
                    creation_date: "2056-09-03T20:11:08Z".parse().unwrap(),
                    deleted_date: None,
                },
                ImportingCipher {
                    folder_id: None,
                    name: "John doe".to_string(),
                    notes: None,
                    r#type: CipherType::Identity(Box::new(Identity {
                        title: None,
                        first_name: Some("John".to_string()),
                        middle_name: None,
                        last_name: Some("Doe".to_string()),
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
                        license_number: None
                    })),
                    favorite: false,
                    reprompt: 0,
                    fields: vec![],
                    revision_date: "2056-09-03T20:11:08Z".parse().unwrap(),
                    creation_date: "2056-09-03T20:11:08Z".parse().unwrap(),
                    deleted_date: None,
                },
                ImportingCipher {
                    folder_id: None,
                    name: "John doe".to_string(),
                    notes: None,
                    r#type: CipherType::SecureNote(Box::new(SecureNote {
                        r#type: SecureNoteType::Generic
                    })),
                    favorite: false,
                    reprompt: 0,
                    fields: vec![
                        Field { name: Some("initial".to_string()), value: Some("JD".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("gender".to_string()), value: Some("".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("birth date".to_string()), value: Some("".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("occupation".to_string()), value: Some("".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("company".to_string()), value: Some("".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("department".to_string()), value: Some("".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("job title".to_string()), value: Some("Dr.".to_string()), r#type: 0, linked_id: None }
                    ],
                    revision_date: "2056-09-03T20:11:08Z".parse().unwrap(),
                    creation_date: "2056-09-03T20:11:08Z".parse().unwrap(),
                    deleted_date: None,
                },
                ImportingCipher {
                    folder_id: None,
                    name: "Facebook".to_string(),
                    notes: None,
                    r#type: CipherType::Login(Box::new(Login {
                        username: Some("johndoe".to_string()),
                        password: Some("securepassword123".to_string()),
                        login_uris: vec![LoginUri { uri: Some("https://facebook.com".to_string()), r#match: None }],
                        totp: None,
                        fido2_credentials: None
                    })),
                    favorite: false,
                    reprompt: 0,
                    fields: vec![],
                    revision_date: "2056-09-03T20:02:09Z".parse().unwrap(),
                    creation_date: "2056-09-03T19:58:21Z".parse().unwrap(),
                    deleted_date: None,
                },
                ImportingCipher {
                    folder_id: None,
                    name: "Facebook".to_string(),
                    notes: None,
                    r#type: CipherType::SecureNote(Box::new(SecureNote {
                        r#type: SecureNoteType::Generic
                    })),
                    favorite: false,
                    reprompt: 0,
                    fields: vec![
                        Field { name: Some("First name".to_string()), value: Some("Jane".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("Last name".to_string()), value: Some("Doe".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("Birth Date".to_string()), value: Some("631195260".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("Mother's maiden name (security question)".to_string()), value: Some("Smith".to_string()), r#type: 0, linked_id: None }
                    ],
                    revision_date: "2056-09-03T20:02:09Z".parse().unwrap(),
                    creation_date: "2056-09-03T19:58:21Z".parse().unwrap(),
                    deleted_date: None,
                },
                ImportingCipher {
                    folder_id: None,
                    name: "Address".to_string(),
                    notes: None,
                    r#type: CipherType::Identity(Box::new(Identity {
                        title: None,
                        first_name: None,
                        middle_name: None,
                        last_name: None,
                        address1: Some("123 Main Stree".to_string()),
                        address2: None,
                        address3: None,
                        city: Some("Springfield".to_string()),
                        state: Some("CA".to_string()),
                        postal_code: Some("12345".to_string()),
                        country: Some("US".to_string()),
                        company: None,
                        email: None,
                        phone: None,
                        ssn: None,
                        username: None,
                        passport_number: None,
                        license_number: None
                    })),
                    favorite: false,
                    reprompt: 0,
                    fields: vec![],
                    revision_date: "2056-09-03T20:11:20Z".parse().unwrap(),
                    creation_date: "2056-09-03T20:09:29Z".parse().unwrap(),
                    deleted_date: None,
                },
                ImportingCipher {
                    folder_id: None,
                    name: "Address".to_string(),
                    notes: None,
                    r#type: CipherType::Identity(Box::new(Identity {
                        title: None,
                        first_name: Some("".to_string()),
                        middle_name: None,
                        last_name: Some("".to_string()),
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
                        license_number: None
                    })),
                    favorite: false,
                    reprompt: 0,
                    fields: vec![],
                    revision_date: "2056-09-03T20:11:20Z".parse().unwrap(),
                    creation_date: "2056-09-03T20:09:29Z".parse().unwrap(),
                    deleted_date: None,
                },
                ImportingCipher {
                    folder_id: None,
                    name: "Address".to_string(),
                    notes: None,
                    r#type: CipherType::SecureNote(Box::new(SecureNote {
                        r#type: SecureNoteType::Generic
                    })),
                    favorite: false,
                    reprompt: 0,
                    fields: vec![
                        Field { name: Some("initial".to_string()), value: Some("".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("gender".to_string()), value: Some("".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("birth date".to_string()), value: Some("".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("occupation".to_string()), value: Some("".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("company".to_string()), value: Some("".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("department".to_string()), value: Some("".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("job title".to_string()), value: Some("".to_string()), r#type: 0, linked_id: None }
                    ],
                    revision_date: "2056-09-03T20:11:20Z".parse().unwrap(),
                    creation_date: "2056-09-03T20:09:29Z".parse().unwrap(),
                    deleted_date: None,
                },
                ImportingCipher {
                    folder_id: None,
                    name: "Social Security Number".to_string(),
                    notes: None,
                    r#type: CipherType::Identity(Box::new(Identity {
                        title: None,
                        first_name: Some("Jane".to_string()),
                        middle_name: None,
                        last_name: Some("Doe".to_string()),
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
                        passport_number: Some("ID123456789".to_string()),
                        license_number: None
                    })),
                    favorite: false,
                    reprompt: 0,
                    fields: vec![],
                    revision_date: "2056-09-03T20:13:34Z".parse().unwrap(),
                    creation_date: "2056-09-03T20:13:34Z".parse().unwrap(),
                    deleted_date: None,
                },
                ImportingCipher {
                    folder_id: None,
                    name: "Home Wifi".to_string(),
                    notes: None,
                    r#type: CipherType::SecureNote(Box::new(SecureNote {
                        r#type: SecureNoteType::Generic
                    })),
                    favorite: false,
                    reprompt: 0,
                    fields: vec![
                        Field { name: Some("SSID".to_string()), value: Some("Home_Network".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("Passphrase".to_string()), value: Some("mypassword123".to_string()), r#type: 1, linked_id: None },
                        Field { name: Some("Network Security Type".to_string()), value: Some("WPA2 Personal".to_string()), r#type: 0, linked_id: None }
                    ],
                    revision_date: "2056-09-03T20:04:46Z".parse().unwrap(),
                    creation_date: "2056-09-03T20:04:46Z".parse().unwrap(),
                    deleted_date: None,
                },
                ImportingCipher {
                    folder_id: None,
                    name: "Home Wifi".to_string(),
                    notes: None,
                    r#type: CipherType::SecureNote(Box::new(SecureNote {
                        r#type: SecureNoteType::Generic
                    })),
                    favorite: false,
                    reprompt: 0,
                    fields: vec![
                        Field { name: Some("base station name".to_string()), value: Some("".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("base station password".to_string()), value: Some("".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("server / IP address".to_string()), value: Some("".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("AirPort ID".to_string()), value: Some("".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("attached storage password".to_string()), value: Some("".to_string()), r#type: 0, linked_id: None }
                    ],
                    revision_date: "2056-09-03T20:04:46Z".parse().unwrap(),
                    creation_date: "2056-09-03T20:04:46Z".parse().unwrap(),
                    deleted_date: None,
                },
                ImportingCipher {
                    folder_id: None,
                    name: "Personal Credit Card".to_string(),
                    notes: None,
                    r#type: CipherType::Card(Box::new(Card {
                        cardholder_name: Some("John doe".to_string()),
                        exp_month: Some("8".to_string()),
                        exp_year: Some("2027".to_string()),
                        code: Some("123".to_string()),
                        brand: Some("Visa".to_string()),
                        number: Some("4111111111111111".to_string())
                    })),
                    favorite: false,
                    reprompt: 0,
                    fields: vec![Field { name: Some("Valid From".to_string()), value: Some("2024-02".to_string()), r#type: 0, linked_id: None }],
                    revision_date: "2056-09-03T20:03:40Z".parse().unwrap(),
                    creation_date: "2056-09-03T20:03:40Z".parse().unwrap(),
                    deleted_date: None,
                },
                ImportingCipher {
                    folder_id: None,
                    name: "Personal Credit Card".to_string(),
                    notes: None,
                    r#type: CipherType::SecureNote(Box::new(SecureNote {
                        r#type: SecureNoteType::Generic
                    })),
                    favorite: false,
                    reprompt: 0,
                    fields: vec![
                        Field { name: Some("issuing bank".to_string()), value: Some("".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("phone (local)".to_string()), value: Some("".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("phone (toll free)".to_string()), value: Some("".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("phone (intl)".to_string()), value: Some("".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("website".to_string()), value: Some("".to_string()), r#type: 0, linked_id: None }
                    ],
                    revision_date: "2056-09-03T20:03:40Z".parse().unwrap(),
                    creation_date: "2056-09-03T20:03:40Z".parse().unwrap(),
                    deleted_date: None,
                },
                ImportingCipher {
                    folder_id: None,
                    name: "Passport".to_string(),
                    notes: None,
                    r#type: CipherType::Identity(Box::new(Identity {
                        title: None,
                        first_name: Some("John".to_string()),
                        middle_name: None,
                        last_name: Some("Doe".to_string()),
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
                        passport_number: Some("A12345678".to_string()),
                        license_number: None
                    })),
                    favorite: false,
                    reprompt: 0,
                    fields: vec![
                        Field { name: Some("Issuing Country".to_string()), value: Some("US".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("Nationality".to_string()), value: Some("American".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("Birth Date".to_string()), value: Some("1990-01-01".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("Birth Place".to_string()), value: Some("Los Angeles, USA".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("Sex".to_string()), value: Some("M".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("Issue Date".to_string()), value: Some("2015-06-15".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("Expiry Date".to_string()), value: Some("2025-06-15".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("Issuing Authority".to_string()), value: Some("U.S. Department of State".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("Passport Type".to_string()), value: Some("Regular".to_string()), r#type: 0, linked_id: None }
                    ],
                    revision_date: "2056-09-03T20:16:07Z".parse().unwrap(),
                    creation_date: "2056-09-03T20:16:07Z".parse().unwrap(),
                    deleted_date: None,
                },
                ImportingCipher {
                    folder_id: None,
                    name: "Driver License".to_string(),
                    notes: None,
                    r#type: CipherType::Identity(Box::new(Identity {
                        title: None,
                        first_name: Some("John".to_string()),
                        middle_name: None,
                        last_name: Some("Doe".to_string()),
                        address1: None,
                        address2: None,
                        address3: None,
                        city: None,
                        state: Some("CA".to_string()),
                        postal_code: None,
                        country: Some("US".to_string()),
                        company: None,
                        email: None,
                        phone: None,
                        ssn: None,
                        username: None,
                        passport_number: None,
                        license_number: Some("D12345678".to_string())
                    })),
                    favorite: false,
                    reprompt: 0,
                    fields: vec![
                        Field { name: Some("Birth Date".to_string()), value: Some("1990-05-15".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("License Class".to_string()), value: Some("C".to_string()), r#type: 0, linked_id: None }
                    ],
                    revision_date: "2056-09-03T20:07:51Z".parse().unwrap(),
                    creation_date: "2056-09-03T20:07:51Z".parse().unwrap(),
                    deleted_date: None,
                },
                ImportingCipher {
                    folder_id: None,
                    name: "Driver License".to_string(),
                    notes: None,
                    r#type: CipherType::SecureNote(Box::new(SecureNote {
                        r#type: SecureNoteType::Generic
                    })),
                    favorite: false,
                    reprompt: 0,
                    fields: vec![
                        Field { name: Some("address".to_string()), value: Some("".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("gender".to_string()), value: Some("".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("height".to_string()), value: Some("".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("conditions / restrictions".to_string()), value: Some("".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("expiry date".to_string()), value: Some("203006".to_string()), r#type: 0, linked_id: None }
                    ],
                    revision_date: "2056-09-03T20:07:51Z".parse().unwrap(),
                    creation_date: "2056-09-03T20:07:51Z".parse().unwrap(),
                    deleted_date: None,
                },
                ImportingCipher {
                    folder_id: None,
                    name: "EXPORTER".to_string(),
                    notes: Some("It’s you! 🖐 Select Edit to fill in more details, like your address and contact information.".to_string()),
                    r#type: CipherType::Identity(Box::new(Identity {
                        title: None,
                        first_name: None,
                        middle_name: None,
                        last_name: None,
                        address1: Some("".to_string()),
                        address2: None,
                        address3: None,
                        city: Some("".to_string()),
                        state: Some("".to_string()),
                        postal_code: Some("".to_string()),
                        country: Some("".to_string()),
                        company: None,
                        email: None,
                        phone: None,
                        ssn: None,
                        username: None,
                        passport_number: None,
                        license_number: None
                    })),
                    favorite: false,
                    reprompt: 0,
                    fields: vec![],
                    revision_date: "2056-09-04T14:11:48Z".parse().unwrap(),
                    creation_date: "2056-09-04T14:11:48Z".parse().unwrap(),
                    deleted_date: None,
                },
                ImportingCipher {
                    folder_id: None,
                    name: "EXPORTER".to_string(),
                    notes: Some("It’s you! 🖐 Select Edit to fill in more details, like your address and contact information.".to_string()),
                    r#type: CipherType::Identity(Box::new(Identity {
                        title: None,
                        first_name: Some("EXPORTER".to_string()),
                        middle_name: None,
                        last_name: Some("".to_string()),
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
                        license_number: None
                    })),
                    favorite: false,
                    reprompt: 0,
                    fields: vec![],
                    revision_date: "2056-09-04T14:11:48Z".parse().unwrap(),
                    creation_date: "2056-09-04T14:11:48Z".parse().unwrap(),
                    deleted_date: None,
                },
                ImportingCipher {
                    folder_id: None,
                    name: "EXPORTER".to_string(),
                    notes: Some("It’s you! 🖐 Select Edit to fill in more details, like your address and contact information.".to_string()),
                    r#type: CipherType::SecureNote(Box::new(SecureNote {
                        r#type: SecureNoteType::Generic
                    })),
                    favorite: false,
                    reprompt: 0,
                    fields: vec![
                        Field { name: Some("initial".to_string()), value: Some("".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("gender".to_string()), value: Some("".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("birth date".to_string()), value: Some("".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("occupation".to_string()), value: Some("".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("company".to_string()), value: Some("".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("department".to_string()), value: Some("".to_string()), r#type: 0, linked_id: None },
                        Field { name: Some("job title".to_string()), value: Some("".to_string()), r#type: 0, linked_id: None }
                    ],
                    revision_date: "2056-09-04T14:11:48Z".parse().unwrap(),
                    creation_date: "2056-09-04T14:11:48Z".parse().unwrap(),
                    deleted_date: None,
                },
                ImportingCipher {
                    folder_id: None,
                    name: "Home Alarm".to_string(),
                    notes: Some("Some instructions to enable/disable the alarm".to_string()),
                    r#type: CipherType::SecureNote(Box::new(SecureNote {
                        r#type: SecureNoteType::Generic
                    })),
                    favorite: false,
                    reprompt: 0,
                    fields: vec![],
                    revision_date: "2056-09-03T20:05:13Z".parse().unwrap(),
                    creation_date: "2056-09-03T20:05:13Z".parse().unwrap(),
                    deleted_date: None,
                }
            ]
        );
    }
}
