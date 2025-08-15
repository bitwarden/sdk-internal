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
    use super::*;

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
        let identity = match &address_cipher.r#type {
            CipherType::Identity(identity) => identity,
            _ => panic!("Expected Identity cipher for address"),
        };

        // Verify all address field mappings from cxf_example.json
        assert_eq!(identity.address1, Some("123 Main Street".to_string()));
        assert_eq!(identity.city, Some("Springfield".to_string()));
        assert_eq!(identity.state, Some("CA".to_string()));
        assert_eq!(identity.country, Some("US".to_string()));
        assert_eq!(identity.phone, Some("+1-555-123-4567".to_string()));
        assert_eq!(identity.postal_code, Some("12345".to_string()));

        // Verify no unmapped fields (address has no custom fields)
        assert_eq!(address_cipher.fields.len(), 0);

        // Verify unused Identity fields remain None
        assert_eq!(identity.first_name, None);
        assert_eq!(identity.passport_number, None);
        assert_eq!(identity.license_number, None);
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
        let identity = match &passport_cipher.r#type {
            CipherType::Identity(identity) => identity,
            _ => panic!("Expected Identity cipher for passport"),
        };

        // Verify Identity field mappings from cxf_example.json
        assert_eq!(identity.passport_number, Some("A12345678".to_string()));
        assert_eq!(identity.first_name, Some("John".to_string()));
        assert_eq!(identity.last_name, Some("Doe".to_string()));
        assert_eq!(identity.ssn, Some("ID123456789".to_string()));
        assert_eq!(identity.country, None); // Now custom field per mapping

        // Verify custom fields preserve all unmapped data
        assert!(
            passport_cipher.fields.len() >= 4,
            "Should have multiple custom fields"
        );

        // Check specific custom fields
        let issuing_country = passport_cipher
            .fields
            .iter()
            .find(|f| f.name.as_deref() == Some("Issuing Country"))
            .expect("Should have Issuing Country");
        assert_eq!(issuing_country.value, Some("US".to_string()));

        let nationality = passport_cipher
            .fields
            .iter()
            .find(|f| f.name.as_deref() == Some("Nationality"))
            .expect("Should have Nationality");
        assert_eq!(nationality.value, Some("American".to_string()));

        // Verify unused Identity fields remain None
        assert_eq!(identity.address1, None);
        assert_eq!(identity.license_number, None);
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
        let identity = match &person_name_cipher.r#type {
            CipherType::Identity(identity) => identity,
            _ => panic!("Expected Identity cipher for person name"),
        };

        // Verify Identity field mappings from cxf_example.json
        assert_eq!(identity.title, Some("Dr.".to_string()));
        assert_eq!(identity.first_name, Some("John".to_string()));
        assert_eq!(identity.middle_name, Some("Michael".to_string()));
        assert_eq!(identity.last_name, Some("van Doe Smith".to_string())); // Combined surname
        assert_eq!(identity.company, Some("PhD".to_string())); // credentials → company

        // Verify custom fields preserve unmapped data
        assert!(
            person_name_cipher.fields.len() >= 2,
            "Should have custom fields"
        );

        let informal_given = person_name_cipher
            .fields
            .iter()
            .find(|f| f.name.as_deref() == Some("Informal Given Name"))
            .expect("Should have Informal Given Name");
        assert_eq!(informal_given.value, Some("Johnny".to_string()));

        let generation = person_name_cipher
            .fields
            .iter()
            .find(|f| f.name.as_deref() == Some("Generation"))
            .expect("Should have Generation");
        assert_eq!(generation.value, Some("III".to_string()));

        // Verify unused Identity fields remain None
        assert_eq!(identity.address1, None);
        assert_eq!(identity.passport_number, None);
        assert_eq!(identity.license_number, None);
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
        let identity = match &drivers_license_cipher.r#type {
            CipherType::Identity(identity) => identity,
            _ => panic!("Expected Identity cipher for drivers license"),
        };

        // Verify Identity field mappings from cxf_example.json
        assert_eq!(identity.license_number, Some("D12345678".to_string()));
        assert_eq!(identity.first_name, Some("John".to_string()));
        assert_eq!(identity.last_name, Some("Doe".to_string()));
        assert_eq!(identity.state, Some("CA".to_string()));
        assert_eq!(identity.country, Some("US".to_string()));
        assert_eq!(identity.company, None); // issuingAuthority is now custom field

        // Verify custom fields preserve unmapped data
        assert!(
            drivers_license_cipher.fields.len() >= 3,
            "Should have multiple custom fields"
        );

        let issuing_authority = drivers_license_cipher
            .fields
            .iter()
            .find(|f| f.name.as_deref() == Some("Issuing Authority"))
            .expect("Should have Issuing Authority");
        assert_eq!(
            issuing_authority.value,
            Some("Department of Motor Vehicles".to_string())
        );

        let license_class = drivers_license_cipher
            .fields
            .iter()
            .find(|f| f.name.as_deref() == Some("License Class"))
            .expect("Should have License Class");
        assert_eq!(license_class.value, Some("C".to_string()));

        // Verify unused Identity fields remain None
        assert_eq!(identity.title, None);
        assert_eq!(identity.address1, None);
        assert_eq!(identity.passport_number, None);
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
        let identity = match &identity_document_cipher.r#type {
            CipherType::Identity(identity) => identity,
            _ => panic!("Expected Identity cipher for identity document"),
        };

        // Verify Identity field mappings from cxf_example.json
        assert_eq!(identity.passport_number, Some("123456789".to_string())); // documentNumber → passport_number
        assert_eq!(identity.first_name, Some("Jane".to_string())); // fullName split
        assert_eq!(identity.last_name, Some("Doe".to_string())); // fullName split
        assert_eq!(identity.ssn, Some("ID123456789".to_string())); // identificationNumber → ssn
        assert_eq!(identity.country, None); // issuingCountry goes to custom fields

        // Verify custom fields preserve unmapped data
        assert!(
            identity_document_cipher.fields.len() >= 6,
            "Should have multiple custom fields"
        );

        // Check specific custom fields
        let issuing_country = identity_document_cipher
            .fields
            .iter()
            .find(|f| f.name.as_deref() == Some("Issuing Country"))
            .expect("Should have Issuing Country");
        assert_eq!(issuing_country.value, Some("US".to_string()));

        let nationality = identity_document_cipher
            .fields
            .iter()
            .find(|f| f.name.as_deref() == Some("Nationality"))
            .expect("Should have Nationality");
        assert_eq!(nationality.value, Some("American".to_string()));

        let birth_place = identity_document_cipher
            .fields
            .iter()
            .find(|f| f.name.as_deref() == Some("Birth Place"))
            .expect("Should have Birth Place");
        assert_eq!(birth_place.value, Some("New York, USA".to_string()));

        let issuing_authority = identity_document_cipher
            .fields
            .iter()
            .find(|f| f.name.as_deref() == Some("Issuing Authority"))
            .expect("Should have Issuing Authority");
        assert_eq!(
            issuing_authority.value,
            Some("Department of State".to_string())
        );

        // Verify unused Identity fields remain None
        assert_eq!(identity.title, None);
        assert_eq!(identity.address1, None);
        assert_eq!(identity.license_number, None);
        assert_eq!(identity.company, None);
    }
}
