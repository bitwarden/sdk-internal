//! Sample file integration tests for CXF import functionality
//!
//! These tests validate the parsing of real CXF sample files against the specification.

use super::import::parse_item;
use crate::{cxf::CxfError, CipherType, ImportingCipher};

/// Parse CXF payload in the format compatible with the CXF specification (At the
/// Header-level).
fn parse_cxf_spec(payload: String) -> Result<Vec<ImportingCipher>, CxfError> {
    use credential_exchange_format::Header;

    let header: Header = serde_json::from_str(&payload)?;

    let items: Vec<ImportingCipher> = header
        .accounts
        .into_iter()
        .flat_map(|account| account.items.into_iter().flat_map(parse_item))
        .collect();

    Ok(items)
}

fn load_sample_cxf() -> Result<Vec<ImportingCipher>, CxfError> {
    use std::fs;

    // Read the actual CXF example file
    let cxf_data = fs::read_to_string("resources/cxf_example.json")
        .expect("Should be able to read cxf_example.json");

    let items = parse_cxf_spec(cxf_data)?;

    Ok(items)
}

#[cfg(test)]
mod tests {
    use bitwarden_vault::FieldType;

    use super::*;
    use crate::{Field, Identity};

    #[test]
    fn test_load_cxf_example_without_crashing() {
        let result = load_sample_cxf();
        assert!(result.is_ok());
    }

    #[test]
    fn test_cxf_sample_totp_mapping() {
        let items = load_sample_cxf().expect("Should load sample CXF data");

        // Find the item with TOTP - should be the "GitHub Login" item
        let totp_item = items
            .iter()
            .find(|item| item.name == "GitHub Login")
            .expect("Should find GitHub Login item");

        // Verify it's a Login type with TOTP
        match &totp_item.r#type {
            CipherType::Login(login) => {
                // Verify the TOTP field is properly mapped
                assert!(login.totp.is_some());
                let totp_uri = login.totp.as_ref().unwrap();

                // Verify it's a proper otpauth URI
                assert!(totp_uri.starts_with("otpauth://totp/"));

                // Verify it contains the expected components from the CXF sample:
                // - secret: "JBSWY3DPEHPK3PXP"
                // - issuer: "Google"
                // - algorithm: "sha256" (non-default, should appear as SHA256)
                // - username: "jane.smith@example.com" (in the URI label)
                // - period: 30 (default, so should NOT appear in URI)
                // - digits: 6 (default, so should NOT appear in URI)
                assert!(totp_uri.contains("secret=JBSWY3DPEHPK3PXP"));
                assert!(totp_uri.contains("issuer=Google"));
                assert!(totp_uri.contains("algorithm=SHA256"));
                assert!(totp_uri.contains("Google:jane%2Esmith%40example%2Ecom"));

                // Should NOT contain default values
                assert!(!totp_uri.contains("period=30"));
                assert!(!totp_uri.contains("digits=6"));

                // Verify the Login structure is complete
                assert!(login.username.is_some()); // From basic auth credential
                assert!(login.password.is_some()); // From basic auth credential
                assert!(!login.login_uris.is_empty()); // From item scope
                assert!(login.totp.is_some()); // From TOTP credential

                // Expected URI format using official Bitwarden TOTP implementation:
                // otpauth://totp/Google:jane%2Esmith%40example%2Ecom?secret=JBSWY3DPEHPK3PXP&
                // issuer=Google&algorithm=SHA256
            }
            _ => panic!("GitHub Login item should be a Login type"),
        }
    }

    #[test]
    fn test_cxf_sample_note_integration() {
        let items = load_sample_cxf().expect("Should load sample CXF data");

        // Find the note item (Home alarm)
        let note_cipher = items
            .iter()
            .find(|cipher| cipher.name == "Home alarm")
            .expect("Should find Home alarm note item");

        // Validate it's a SecureNote cipher
        match &note_cipher.r#type {
            CipherType::SecureNote(_) => (), // Successfully identified as SecureNote
            _ => panic!("Expected SecureNote for standalone note credential"),
        }

        // Validate the note content
        assert_eq!(
            note_cipher.notes,
            Some("some instructionts to enable/disable the alarm".to_string())
        );

        // Should have no custom fields since it's a standalone note
        assert_eq!(note_cipher.fields.len(), 0);

        // Validate basic properties
        assert_eq!(note_cipher.name, "Home alarm");
        assert_eq!(note_cipher.folder_id, None);
        assert!(!note_cipher.favorite);
    }

    #[test]
    fn test_cxf_sample_address_complete_mapping() {
        let ciphers = load_sample_cxf().expect("Should load sample CXF data");

        // Find the address cipher from cxf_example.json
        let address_cipher = ciphers
            .iter()
            .find(|c| c.name == "House Address")
            .expect("Should find House Address item");

        // Verify it's an Identity cipher
        let identity = if let CipherType::Identity(identity) = &address_cipher.r#type {
            identity
        } else {
            panic!("Expected Identity cipher for address")
        };

        // Verify all address field mappings from cxf_example.json
        let expected_identity = Identity {
            address1: Some("123 Main Street".to_string()),
            city: Some("Springfield".to_string()),
            state: Some("CA".to_string()),
            country: Some("US".to_string()),
            phone: Some("+1-555-123-4567".to_string()),
            postal_code: Some("12345".to_string()),
            ..Default::default()
        };

        assert_eq!(**identity, expected_identity);

        // Verify no unmapped fields (address has no custom fields)
        assert_eq!(address_cipher.fields.len(), 0);
    }

    #[test]
    fn test_cxf_sample_passport_complete_mapping() {
        let ciphers = load_sample_cxf().expect("Should load sample CXF data");

        // Find the passport cipher from cxf_example.json
        let passport_cipher = ciphers
            .iter()
            .find(|c| c.name == "Passport")
            .expect("Should find Passport item");

        // Verify it's an Identity cipher
        let identity = if let CipherType::Identity(identity) = &passport_cipher.r#type {
            identity
        } else {
            panic!("Expected Identity cipher for passport")
        };

        // Verify Identity field mappings from cxf_example.json
        let expected_identity = Identity {
            passport_number: Some("A12345678".to_string()),
            first_name: Some("John".to_string()),
            last_name: Some("Doe".to_string()),
            ssn: Some("ID123456789".to_string()),
            country: None,
            ..Default::default()
        };

        assert_eq!(**identity, expected_identity);

        // Verify custom fields preserve unmapped data
        let expected_fields = vec![
            Field {
                name: Some("Issuing Country".to_string()),
                value: Some("US".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            },
            Field {
                name: Some("Nationality".to_string()),
                value: Some("American".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            },
            Field {
                name: Some("Birth Date".to_string()),
                value: Some("1990-01-01".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            },
            Field {
                name: Some("Birth Place".to_string()),
                value: Some("Los Angeles, USA".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            },
            Field {
                name: Some("Sex".to_string()),
                value: Some("M".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            },
            Field {
                name: Some("Issue Date".to_string()),
                value: Some("2015-06-15".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            },
            Field {
                name: Some("Expiry Date".to_string()),
                value: Some("2025-06-15".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            },
            Field {
                name: Some("Issuing Authority".to_string()),
                value: Some("U.S. Department of State".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            },
            Field {
                name: Some("Passport Type".to_string()),
                value: Some("Regular".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            },
        ];

        assert_eq!(passport_cipher.fields, expected_fields);
    }

    #[test]
    fn test_cxf_sample_person_name_complete_mapping() {
        let ciphers = load_sample_cxf().expect("Should load sample CXF data");

        // Find the person name cipher from cxf_example.json
        let person_name_cipher = ciphers
            .iter()
            .find(|c| c.name == "John Doe")
            .expect("Should find John Doe item");

        // Verify it's an Identity cipher
        let identity = if let CipherType::Identity(identity) = &person_name_cipher.r#type {
            identity
        } else {
            panic!("Expected Identity cipher for person name")
        };

        // Verify Identity field mappings from cxf_example.json
        let expected_identity = Identity {
            title: Some("Dr.".to_string()),
            first_name: Some("John".to_string()),
            middle_name: Some("Michael".to_string()),
            last_name: Some("van Doe Smith".to_string()), // Combined surname
            company: Some("PhD".to_string()),             // credentials → company
            ..Default::default()
        };

        assert_eq!(**identity, expected_identity);

        // Verify custom fields preserve unmapped data
        let expected_fields = vec![
            Field {
                name: Some("Informal Given Name".to_string()),
                value: Some("Johnny".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            },
            Field {
                name: Some("Generation".to_string()),
                value: Some("III".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            },
        ];

        assert_eq!(person_name_cipher.fields, expected_fields);
    }

    #[test]
    fn test_cxf_sample_drivers_license_complete_mapping() {
        let ciphers = load_sample_cxf().expect("Should load sample CXF data");

        // Find the drivers license cipher from cxf_example.json
        let drivers_license_cipher = ciphers
            .iter()
            .find(|c| c.name == "Driver License")
            .expect("Should find Driver License item");

        // Verify it's an Identity cipher
        let identity = if let CipherType::Identity(identity) = &drivers_license_cipher.r#type {
            identity
        } else {
            panic!("Expected Identity cipher for drivers license")
        };

        // Verify Identity field mappings from cxf_example.json
        let expected_identity = Identity {
            license_number: Some("D12345678".to_string()),
            first_name: Some("John".to_string()),
            last_name: Some("Doe".to_string()),
            state: Some("CA".to_string()),
            country: Some("US".to_string()),
            company: None, // issuingAuthority is now custom field
            ..Default::default()
        };

        assert_eq!(**identity, expected_identity);

        // Verify custom fields preserve unmapped data
        let expected_fields = vec![
            Field {
                name: Some("Birth Date".to_string()),
                value: Some("1990-05-15".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            },
            Field {
                name: Some("Issue Date".to_string()),
                value: Some("2020-06-01".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            },
            Field {
                name: Some("Expiry Date".to_string()),
                value: Some("2030-06-01".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            },
            Field {
                name: Some("Issuing Authority".to_string()),
                value: Some("Department of Motor Vehicles".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            },
            Field {
                name: Some("License Class".to_string()),
                value: Some("C".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            },
        ];

        assert_eq!(drivers_license_cipher.fields, expected_fields);
    }

    #[test]
    fn test_cxf_sample_identity_document_complete_mapping() {
        let ciphers = load_sample_cxf().expect("Should load sample CXF data");

        // Find the identity document cipher from cxf_example.json
        let identity_document_cipher = ciphers
            .iter()
            .find(|c| c.name == "ID card")
            .expect("Should find ID card item");

        // Verify it's an Identity cipher
        let identity = if let CipherType::Identity(identity) = &identity_document_cipher.r#type {
            identity
        } else {
            panic!("Expected Identity cipher for identity document")
        };

        // Verify Identity field mappings from cxf_example.json
        let expected_identity = Identity {
            passport_number: Some("123456789".to_string()), // documentNumber → passport_number
            first_name: Some("Jane".to_string()),           // fullName split
            last_name: Some("Doe".to_string()),             // fullName split
            ssn: Some("ID123456789".to_string()),           // identificationNumber → ssn
            country: None,                                  // issuingCountry goes to custom fields
            ..Default::default()                            // All other fields should remain None
        };

        assert_eq!(**identity, expected_identity);

        // Verify custom fields preserve unmapped data
        assert!(
            identity_document_cipher.fields.len() >= 6,
            "Should have multiple custom fields"
        );

        // Verify custom fields preserve unmapped data
        let expected_fields = vec![
            Field {
                name: Some("Issuing Country".to_string()),
                value: Some("US".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            },
            Field {
                name: Some("Nationality".to_string()),
                value: Some("American".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            },
            Field {
                name: Some("Birth Date".to_string()),
                value: Some("1990-04-15".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            },
            Field {
                name: Some("Birth Place".to_string()),
                value: Some("New York, USA".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            },
            Field {
                name: Some("Sex".to_string()),
                value: Some("F".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            },
            Field {
                name: Some("Issue Date".to_string()),
                value: Some("2020-01-01".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            },
            Field {
                name: Some("Expiry Date".to_string()),
                value: Some("2030-01-01".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            },
            Field {
                name: Some("Issuing Authority".to_string()),
                value: Some("Department of State".to_string()),
                r#type: FieldType::Text as u8,
                linked_id: None,
            },
        ];

        assert_eq!(identity_document_cipher.fields, expected_fields);
    }
}
