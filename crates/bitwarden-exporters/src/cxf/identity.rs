use credential_exchange_format::{
    AddressCredential, DriversLicenseCredential, IdentityDocumentCredential, PassportCredential,
    PersonNameCredential,
};

use crate::{cxf::editable_field::create_field, Field, Identity};

/// Convert address credentials to Identity (no custom fields needed for address)
/// According to the mapping specification:
/// - streetAddress: EditableField<"string"> → Identity::address1
/// - city: EditableField<"string"> → Identity::city
/// - territory: EditableField<"subdivision-code"> → Identity::state
/// - country: EditableField<"country-code"> → Identity::country
/// - tel: EditableField<"string"> → Identity::phone
/// - postalCode: EditableField<"string"> → Identity::postal_code
pub fn address_to_identity(address: &AddressCredential) -> (Identity, Vec<Field>) {
    let identity = Identity {
        address1: address.street_address.as_ref().map(|s| s.value.0.clone()),
        city: address.city.as_ref().map(|c| c.value.0.clone()),
        state: address.territory.as_ref().map(|t| t.value.0.clone()),
        postal_code: address.postal_code.as_ref().map(|p| p.value.0.clone()),
        country: address.country.as_ref().map(|c| c.value.0.clone()),
        phone: address.tel.as_ref().map(|t| t.value.0.clone()),
        ..Default::default()
    };

    // Address credentials don't have unmapped fields, so no custom fields needed
    (identity, vec![])
}

/// Convert passport credentials to Identity and custom fields
/// According to CXF mapping document:
/// - passportNumber: EditableField<"string"> → Identity::passport_number
/// - nationalIdentificationNumber: EditableField<"string"> → Identity::ssn
/// - fullName: EditableField<"string"> → Identity::first_name + last_name (split)
/// - All other fields → CustomFields
pub fn passport_to_identity(passport: &PassportCredential) -> (Identity, Vec<Field>) {
    // Split full name into first and last name if available
    let (first_name, last_name) = if let Some(full_name) = &passport.full_name {
        let name_parts: Vec<&str> = full_name.value.0.split_whitespace().collect();
        match name_parts.len() {
            0 => (None, None),
            1 => (Some(name_parts[0].to_string()), None),
            _ => {
                let first = name_parts[0].to_string();
                let last = name_parts[1..].join(" ");
                (Some(first), Some(last))
            }
        }
    } else {
        (None, None)
    };

    let identity = Identity {
        first_name,
        last_name,
        // Map nationalIdentificationNumber to ssn as closest available field
        ssn: passport
            .national_identification_number
            .as_ref()
            .map(|n| n.value.0.clone()),
        passport_number: passport.passport_number.as_ref().map(|p| p.value.0.clone()),
        ..Default::default()
    };

    // Create custom fields for unmapped data according to CXF mapping document
    let custom_fields = [
        passport
            .issuing_country
            .as_ref()
            .map(|issuing_country| create_field("Issuing Country", issuing_country)),
        passport
            .nationality
            .as_ref()
            .map(|nationality| create_field("Nationality", nationality)),
        passport
            .birth_date
            .as_ref()
            .map(|birth_date| create_field("Birth Date", birth_date)),
        passport
            .birth_place
            .as_ref()
            .map(|birth_place| create_field("Birth Place", birth_place)),
        passport.sex.as_ref().map(|sex| create_field("Sex", sex)),
        passport
            .issue_date
            .as_ref()
            .map(|issue_date| create_field("Issue Date", issue_date)),
        passport
            .expiry_date
            .as_ref()
            .map(|expiry_date| create_field("Expiry Date", expiry_date)),
        passport
            .issuing_authority
            .as_ref()
            .map(|issuing_authority| create_field("Issuing Authority", issuing_authority)),
        passport
            .passport_type
            .as_ref()
            .map(|passport_type| create_field("Passport Type", passport_type)),
    ]
    .into_iter()
    .flatten()
    .collect();

    (identity, custom_fields)
}

/// Convert person name credentials to Identity and custom fields
/// According to CXF mapping:
/// - title: EditableField<"string"> → Identity::title
/// - given: EditableField<"string"> → Identity::first_name
/// - given2: EditableField<"string"> → Identity::middle_name
/// - surname: EditableField<"string"> → Identity::last_name
/// - surnamePrefix + surname + surname2: combine for complete last name
/// - credentials: EditableField<"string"> → Identity::company (as professional credentials)
/// - Other fields → CustomFields
pub fn person_name_to_identity(person_name: &PersonNameCredential) -> (Identity, Vec<Field>) {
    // Construct complete last name from surnamePrefix, surname, and surname2
    let last_name = {
        let mut parts = Vec::new();

        if let Some(prefix) = &person_name.surname_prefix {
            parts.push(prefix.value.0.clone());
        }
        if let Some(surname) = &person_name.surname {
            parts.push(surname.value.0.clone());
        }
        if let Some(surname2) = &person_name.surname2 {
            parts.push(surname2.value.0.clone());
        }

        if parts.is_empty() {
            None
        } else {
            Some(parts.join(" "))
        }
    };

    let identity = Identity {
        title: person_name.title.as_ref().map(|t| t.value.0.clone()),
        first_name: person_name.given.as_ref().map(|g| g.value.0.clone()),
        middle_name: person_name.given2.as_ref().map(|g2| g2.value.0.clone()),
        last_name,
        // Map credentials (e.g., "PhD") to company field as professional qualifications
        company: person_name.credentials.as_ref().map(|c| c.value.0.clone()),
        ..Default::default()
    };

    // Create custom fields for unmapped data
    let custom_fields = [
        person_name
            .given_informal
            .as_ref()
            .map(|given_informal| create_field("Informal Given Name", given_informal)),
        person_name
            .generation
            .as_ref()
            .map(|generation| create_field("Generation", generation)),
    ]
    .into_iter()
    .flatten()
    .collect();

    (identity, custom_fields)
}

/// Convert drivers license credentials to Identity and custom fields
/// According to CXF mapping document:
/// - licenseNumber: EditableField<"string"> → Identity::license_number
/// - fullName: EditableField<"string"> → Identity::first_name + last_name (split)
/// - territory: EditableField<"subdivision-code"> → Identity::state
/// - country: EditableField<"country-code"> → Identity::country
/// - All other fields → CustomFields
pub fn drivers_license_to_identity(
    drivers_license: &DriversLicenseCredential,
) -> (Identity, Vec<Field>) {
    // Split full name into first and last name if available
    let (first_name, last_name) = if let Some(full_name) = &drivers_license.full_name {
        let name_parts: Vec<&str> = full_name.value.0.split_whitespace().collect();
        match name_parts.len() {
            0 => (None, None),
            1 => (Some(name_parts[0].to_string()), None),
            _ => {
                let first = name_parts[0].to_string();
                let last = name_parts[1..].join(" ");
                (Some(first), Some(last))
            }
        }
    } else {
        (None, None)
    };

    let identity = Identity {
        first_name,
        last_name,
        // Map territory (state/province) to state field
        state: drivers_license
            .territory
            .as_ref()
            .map(|t| t.value.0.clone()),
        // Map country to country field
        country: drivers_license.country.as_ref().map(|c| c.value.0.clone()),
        license_number: drivers_license
            .license_number
            .as_ref()
            .map(|l| l.value.0.clone()),
        ..Default::default()
    };

    // Create custom fields for unmapped data according to CXF mapping document
    let custom_fields = [
        drivers_license
            .birth_date
            .as_ref()
            .map(|birth_date| create_field("Birth Date", birth_date)),
        drivers_license
            .issue_date
            .as_ref()
            .map(|issue_date| create_field("Issue Date", issue_date)),
        drivers_license
            .expiry_date
            .as_ref()
            .map(|expiry_date| create_field("Expiry Date", expiry_date)),
        drivers_license
            .issuing_authority
            .as_ref()
            .map(|issuing_authority| create_field("Issuing Authority", issuing_authority)),
        drivers_license
            .license_class
            .as_ref()
            .map(|license_class| create_field("License Class", license_class)),
    ]
    .into_iter()
    .flatten()
    .collect();

    (identity, custom_fields)
}

/// Convert identity document credentials to Identity and custom fields
/// According to CXF mapping document: IdentityDocument ↔︎ Identity
/// Fields are mapped similarly to passport but for general identity documents
/// - documentNumber: EditableField<"string"> → Identity::passport_number (reusing for general
///   document number)
/// - identificationNumber: EditableField<"string"> → Identity::ssn
/// - fullName: EditableField<"string"> → Identity::first_name + last_name (split)
/// - All other fields → CustomFields
pub fn identity_document_to_identity(
    identity_document: &IdentityDocumentCredential,
) -> (Identity, Vec<Field>) {
    // Split full name into first and last name if available
    let (first_name, last_name) = if let Some(full_name) = &identity_document.full_name {
        let name_parts: Vec<&str> = full_name.value.0.split_whitespace().collect();
        match name_parts.len() {
            0 => (None, None),
            1 => (Some(name_parts[0].to_string()), None),
            _ => {
                let first = name_parts[0].to_string();
                let last = name_parts[1..].join(" ");
                (Some(first), Some(last))
            }
        }
    } else {
        (None, None)
    };

    let identity = Identity {
        first_name,
        last_name,
        // Map identificationNumber to ssn
        ssn: identity_document
            .identification_number
            .as_ref()
            .map(|n| n.value.0.clone()),
        // Map documentNumber to passport_number (reusing for document number)
        passport_number: identity_document
            .document_number
            .as_ref()
            .map(|d| d.value.0.clone()),
        ..Default::default()
    };

    // Create custom fields for unmapped data according to CXF mapping document
    let custom_fields = [
        identity_document
            .issuing_country
            .as_ref()
            .map(|issuing_country| create_field("Issuing Country", issuing_country)),
        identity_document
            .nationality
            .as_ref()
            .map(|nationality| create_field("Nationality", nationality)),
        identity_document
            .birth_date
            .as_ref()
            .map(|birth_date| create_field("Birth Date", birth_date)),
        identity_document
            .birth_place
            .as_ref()
            .map(|birth_place| create_field("Birth Place", birth_place)),
        identity_document
            .sex
            .as_ref()
            .map(|sex| create_field("Sex", sex)),
        identity_document
            .issue_date
            .as_ref()
            .map(|issue_date| create_field("Issue Date", issue_date)),
        identity_document
            .expiry_date
            .as_ref()
            .map(|expiry_date| create_field("Expiry Date", expiry_date)),
        identity_document
            .issuing_authority
            .as_ref()
            .map(|issuing_authority| create_field("Issuing Authority", issuing_authority)),
    ]
    .into_iter()
    .flatten()
    .collect();
    // Note: identity-document doesn't have a document_type field in the CXF example

    (identity, custom_fields)
}

#[cfg(test)]
mod tests {
    use std::fs;

    // Tests only use the public parse_cxf function, no direct function imports needed
    use crate::cxf::import::parse_cxf_spec;

    fn load_sample_cxf() -> Result<Vec<crate::ImportingCipher>, crate::cxf::CxfError> {
        // Read the actual CXF example file
        let cxf_data = fs::read_to_string("resources/cxf_example.json")
            .expect("Should be able to read cxf_example.json");

        parse_cxf_spec(cxf_data)
    }

    #[test]
    fn test_address_complete_mapping() {
        // Test both unit logic and real data integration
        let result = load_sample_cxf();
        assert!(result.is_ok());
        let ciphers = result.unwrap();

        // Find the address cipher from cxf_example.json
        let address_cipher = ciphers
            .iter()
            .find(|c| c.name == "House Address")
            .expect("Should find House Address item");

        // Verify it's an Identity cipher
        let identity = match &address_cipher.r#type {
            crate::CipherType::Identity(identity) => identity,
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
    fn test_passport_complete_mapping() {
        // Test both unit logic and real data integration
        let result = load_sample_cxf();
        assert!(result.is_ok());
        let ciphers = result.unwrap();

        // Find the passport cipher from cxf_example.json
        let passport_cipher = ciphers
            .iter()
            .find(|c| c.name == "Passport")
            .expect("Should find Passport item");

        // Verify it's an Identity cipher
        let identity = match &passport_cipher.r#type {
            crate::CipherType::Identity(identity) => identity,
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
    fn test_person_name_complete_mapping() {
        // Test both unit logic and real data integration
        let result = load_sample_cxf();
        assert!(result.is_ok());
        let ciphers = result.unwrap();

        // Find the person name cipher from cxf_example.json
        let person_name_cipher = ciphers
            .iter()
            .find(|c| c.name == "John Doe")
            .expect("Should find John Doe item");

        // Verify it's an Identity cipher
        let identity = match &person_name_cipher.r#type {
            crate::CipherType::Identity(identity) => identity,
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
    fn test_drivers_license_complete_mapping() {
        // Test both unit logic and real data integration
        let result = load_sample_cxf();
        assert!(result.is_ok());
        let ciphers = result.unwrap();

        // Find the drivers license cipher from cxf_example.json
        let drivers_license_cipher = ciphers
            .iter()
            .find(|c| c.name == "Driver License")
            .expect("Should find Driver License item");

        // Verify it's an Identity cipher
        let identity = match &drivers_license_cipher.r#type {
            crate::CipherType::Identity(identity) => identity,
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
    fn test_identity_document_complete_mapping() {
        // Test both unit logic and real data integration
        let result = load_sample_cxf();
        assert!(result.is_ok());
        let ciphers = result.unwrap();

        // Find the identity document cipher from cxf_example.json
        let identity_document_cipher = ciphers
            .iter()
            .find(|c| c.name == "ID card")
            .expect("Should find ID card item");

        // Verify it's an Identity cipher
        let identity = match &identity_document_cipher.r#type {
            crate::CipherType::Identity(identity) => identity,
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
