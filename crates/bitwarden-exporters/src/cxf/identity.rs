use bitwarden_vault::FieldType;
use credential_exchange_format::{
    AddressCredential, DriversLicenseCredential, PassportCredential, PersonNameCredential,
};

use crate::{Field, Identity};

use credential_exchange_format::{
    EditableField, EditableFieldCountryCode, EditableFieldDate, EditableFieldString,
};

/// Helper function to create a custom field from an EditableField<EditableFieldString>
fn create_text_field_from_string(
    editable_field: Option<&EditableField<EditableFieldString>>,
    field_name: &str,
) -> Option<Field> {
    editable_field.map(|field| Field {
        name: Some(field_name.to_string()),
        value: Some(field.value.0.clone()),
        r#type: FieldType::Text as u8,
        linked_id: None,
    })
}

/// Helper function to create a custom field from an EditableField<EditableFieldCountryCode>
fn create_text_field_from_country_code(
    editable_field: Option<&EditableField<EditableFieldCountryCode>>,
    field_name: &str,
) -> Option<Field> {
    editable_field.map(|field| Field {
        name: Some(field_name.to_string()),
        value: Some(field.value.0.clone()),
        r#type: FieldType::Text as u8,
        linked_id: None,
    })
}

/// Helper function to create a custom field from an EditableField<EditableFieldDate>
fn create_text_field_from_date(
    editable_field: Option<&EditableField<EditableFieldDate>>,
    field_name: &str,
) -> Option<Field> {
    editable_field.map(|field| Field {
        name: Some(field_name.to_string()),
        value: Some(field.value.0.to_string()),
        r#type: FieldType::Text as u8,
        linked_id: None,
    })
}

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
        title: None,
        first_name: None,
        middle_name: None,
        last_name: None,
        address1: address.street_address.as_ref().map(|s| s.value.0.clone()),
        address2: None,
        address3: None,
        city: address.city.as_ref().map(|c| c.value.0.clone()),
        state: address.territory.as_ref().map(|t| t.value.0.clone()),
        postal_code: address.postal_code.as_ref().map(|p| p.value.0.clone()),
        country: address.country.as_ref().map(|c| c.value.0.clone()),
        company: None,
        email: None,
        phone: address.tel.as_ref().map(|t| t.value.0.clone()),
        ssn: None,
        username: None,
        passport_number: None,
        license_number: None,
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
        title: None,
        first_name,
        middle_name: None,
        last_name,
        address1: None,
        address2: None,
        address3: None,
        city: None,
        state: None,
        postal_code: None,
        country: None, // According to mapping doc, issuingCountry should be CustomField
        company: None,
        email: None,
        phone: None,
        // Map nationalIdentificationNumber to ssn as closest available field
        ssn: passport
            .national_identification_number
            .as_ref()
            .map(|n| n.value.0.clone()),
        username: None,
        passport_number: passport.passport_number.as_ref().map(|p| p.value.0.clone()),
        license_number: None,
    };

    // Create custom fields for unmapped data according to CXF mapping document
    let mut custom_fields = Vec::new();

    if let Some(field) =
        create_text_field_from_country_code(passport.issuing_country.as_ref(), "Issuing Country")
    {
        custom_fields.push(field);
    }
    if let Some(field) = create_text_field_from_string(passport.nationality.as_ref(), "Nationality")
    {
        custom_fields.push(field);
    }
    if let Some(field) = create_text_field_from_date(passport.birth_date.as_ref(), "Birth Date") {
        custom_fields.push(field);
    }
    if let Some(field) = create_text_field_from_string(passport.birth_place.as_ref(), "Birth Place")
    {
        custom_fields.push(field);
    }
    if let Some(field) = create_text_field_from_string(passport.sex.as_ref(), "Sex") {
        custom_fields.push(field);
    }
    if let Some(field) = create_text_field_from_date(passport.issue_date.as_ref(), "Issue Date") {
        custom_fields.push(field);
    }
    if let Some(field) = create_text_field_from_date(passport.expiry_date.as_ref(), "Expiry Date") {
        custom_fields.push(field);
    }
    if let Some(field) =
        create_text_field_from_string(passport.issuing_authority.as_ref(), "Issuing Authority")
    {
        custom_fields.push(field);
    }
    if let Some(field) =
        create_text_field_from_string(passport.passport_type.as_ref(), "Passport Type")
    {
        custom_fields.push(field);
    }

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
        address1: None,
        address2: None,
        address3: None,
        city: None,
        state: None,
        postal_code: None,
        country: None,
        // Map credentials (e.g., "PhD") to company field as professional qualifications
        company: person_name.credentials.as_ref().map(|c| c.value.0.clone()),
        email: None,
        phone: None,
        ssn: None,
        username: None,
        passport_number: None,
        license_number: None,
    };

    // Create custom fields for unmapped data
    let mut custom_fields = Vec::new();

    if let Some(field) =
        create_text_field_from_string(person_name.given_informal.as_ref(), "Informal Given Name")
    {
        custom_fields.push(field);
    }
    if let Some(field) =
        create_text_field_from_string(person_name.generation.as_ref(), "Generation")
    {
        custom_fields.push(field);
    }

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
        title: None,
        first_name,
        middle_name: None,
        last_name,
        address1: None,
        address2: None,
        address3: None,
        city: None,
        // Map territory (state/province) to state field
        state: drivers_license
            .territory
            .as_ref()
            .map(|t| t.value.0.clone()),
        postal_code: None,
        // Map country to country field
        country: drivers_license.country.as_ref().map(|c| c.value.0.clone()),
        company: None, // According to mapping doc, issuingAuthority should be CustomField
        email: None,
        phone: None,
        ssn: None,
        username: None,
        passport_number: None,
        license_number: drivers_license
            .license_number
            .as_ref()
            .map(|l| l.value.0.clone()),
    };

    // Create custom fields for unmapped data according to CXF mapping document
    let mut custom_fields = Vec::new();

    if let Some(field) =
        create_text_field_from_date(drivers_license.birth_date.as_ref(), "Birth Date")
    {
        custom_fields.push(field);
    }
    if let Some(field) =
        create_text_field_from_date(drivers_license.issue_date.as_ref(), "Issue Date")
    {
        custom_fields.push(field);
    }
    if let Some(field) =
        create_text_field_from_date(drivers_license.expiry_date.as_ref(), "Expiry Date")
    {
        custom_fields.push(field);
    }
    if let Some(field) = create_text_field_from_string(
        drivers_license.issuing_authority.as_ref(),
        "Issuing Authority",
    ) {
        custom_fields.push(field);
    }
    if let Some(field) =
        create_text_field_from_string(drivers_license.license_class.as_ref(), "License Class")
    {
        custom_fields.push(field);
    }

    (identity, custom_fields)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use credential_exchange_format::{
        EditableField, EditableFieldCountryCode, EditableFieldString, EditableFieldSubdivisionCode,
    };

    use crate::cxf::import::parse_cxf;

    use super::*;

    fn load_sample_cxf() -> Result<Vec<crate::ImportingCipher>, crate::cxf::CxfError> {
        // Read the actual CXF example file
        let cxf_data = fs::read_to_string("resources/cxf_example.json")
            .expect("Should be able to read cxf_example.json");

        // Workaround for library bug: the example file has "integrityHash" but the library expects
        // "integrationHash"
        let fixed_cxf_data = cxf_data.replace("\"integrityHash\":", "\"integrationHash\":");

        parse_cxf(fixed_cxf_data)
    }

    fn create_address_credential(
        street_address: Option<&str>,
        city: Option<&str>,
        territory: Option<&str>,
        country: Option<&str>,
        tel: Option<&str>,
        postal_code: Option<&str>,
    ) -> AddressCredential {
        AddressCredential {
            street_address: street_address.map(|s| EditableField {
                id: None,
                value: EditableFieldString(s.to_string()),
                label: None,
                extensions: None,
            }),
            city: city.map(|c| EditableField {
                id: None,
                value: EditableFieldString(c.to_string()),
                label: None,
                extensions: None,
            }),
            territory: territory.map(|t| EditableField {
                id: None,
                value: EditableFieldSubdivisionCode(t.to_string()),
                label: None,
                extensions: None,
            }),
            country: country.map(|c| EditableField {
                id: None,
                value: EditableFieldCountryCode(c.to_string()),
                label: None,
                extensions: None,
            }),
            tel: tel.map(|t| EditableField {
                id: None,
                value: EditableFieldString(t.to_string()),
                label: None,
                extensions: None,
            }),
            postal_code: postal_code.map(|p| EditableField {
                id: None,
                value: EditableFieldString(p.to_string()),
                label: None,
                extensions: None,
            }),
        }
    }

    #[test]
    fn test_address_to_identity_full() {
        let address = create_address_credential(
            Some("123 Main Street"),
            Some("Springfield"),
            Some("CA"),
            Some("US"),
            Some("+1-555-123-4567"),
            Some("12345"),
        );

        let (identity, custom_fields) = address_to_identity(&address);

        assert_eq!(identity.address1, Some("123 Main Street".to_string()));
        assert_eq!(identity.city, Some("Springfield".to_string()));
        assert_eq!(identity.state, Some("CA".to_string()));
        assert_eq!(identity.country, Some("US".to_string()));
        assert_eq!(identity.phone, Some("+1-555-123-4567".to_string()));
        assert_eq!(identity.postal_code, Some("12345".to_string()));

        // Address has no custom fields
        assert_eq!(custom_fields.len(), 0);
    }

    fn create_passport_credential(
        passport_number: Option<&str>,
        issuing_country: Option<&str>,
    ) -> PassportCredential {
        PassportCredential {
            passport_number: passport_number.map(|p| EditableField {
                id: None,
                value: EditableFieldString(p.to_string()),
                label: None,
                extensions: None,
            }),
            issuing_country: issuing_country.map(|c| EditableField {
                id: None,
                value: EditableFieldCountryCode(c.to_string()),
                label: None,
                extensions: None,
            }),
            passport_type: None,
            full_name: None,
            birth_date: None,
            issue_date: None,
            expiry_date: None,
            birth_place: None,
            issuing_authority: None,
            national_identification_number: None,
            nationality: None,
            sex: None,
        }
    }

    fn create_person_name_credential(
        title: Option<&str>,
        given: Option<&str>,
        given2: Option<&str>,
        surname: Option<&str>,
    ) -> PersonNameCredential {
        PersonNameCredential {
            title: title.map(|t| EditableField {
                id: None,
                value: EditableFieldString(t.to_string()),
                label: None,
                extensions: None,
            }),
            given: given.map(|g| EditableField {
                id: None,
                value: EditableFieldString(g.to_string()),
                label: None,
                extensions: None,
            }),
            given2: given2.map(|g2| EditableField {
                id: None,
                value: EditableFieldString(g2.to_string()),
                label: None,
                extensions: None,
            }),
            surname: surname.map(|s| EditableField {
                id: None,
                value: EditableFieldString(s.to_string()),
                label: None,
                extensions: None,
            }),
            given_informal: None,
            surname_prefix: None,
            surname2: None,
            credentials: None,
            generation: None,
        }
    }

    fn create_drivers_license_credential(
        license_number: Option<&str>,
        full_name: Option<&str>,
    ) -> DriversLicenseCredential {
        DriversLicenseCredential {
            license_number: license_number.map(|l| EditableField {
                id: None,
                value: EditableFieldString(l.to_string()),
                label: None,
                extensions: None,
            }),
            full_name: full_name.map(|f| EditableField {
                id: None,
                value: EditableFieldString(f.to_string()),
                label: None,
                extensions: None,
            }),
            birth_date: None,
            issue_date: None,
            expiry_date: None,
            issuing_authority: None,
            license_class: None,
            country: None,
            territory: None,
        }
    }

    #[test]
    fn test_passport_to_identity() {
        let passport = create_passport_credential(Some("A12345678"), Some("US"));

        let (identity, custom_fields) = passport_to_identity(&passport);

        assert_eq!(identity.passport_number, Some("A12345678".to_string()));
        assert_eq!(identity.country, None); // Now custom field according to mapping

        // Verify other fields are None
        assert_eq!(identity.title, None);
        assert_eq!(identity.first_name, None);
        assert_eq!(identity.address1, None);

        // Should have issuing country as custom field
        assert_eq!(custom_fields.len(), 1);
        assert_eq!(custom_fields[0].name, Some("Issuing Country".to_string()));
        assert_eq!(custom_fields[0].value, Some("US".to_string()));
        assert_eq!(custom_fields[0].r#type, FieldType::Text as u8);
    }

    #[test]
    fn test_person_name_to_identity() {
        let person_name =
            create_person_name_credential(Some("Dr."), Some("John"), Some("Michael"), Some("Doe"));

        let (identity, custom_fields) = person_name_to_identity(&person_name);

        assert_eq!(identity.title, Some("Dr.".to_string()));
        assert_eq!(identity.first_name, Some("John".to_string()));
        assert_eq!(identity.middle_name, Some("Michael".to_string()));
        assert_eq!(identity.last_name, Some("Doe".to_string()));

        // Verify other fields are None
        assert_eq!(identity.address1, None);
        assert_eq!(identity.passport_number, None);

        // No unmapped fields in this test, so no custom fields
        assert_eq!(custom_fields.len(), 0);
    }

    #[test]
    fn test_drivers_license_to_identity() {
        let drivers_license =
            create_drivers_license_credential(Some("D123456789"), Some("John Doe"));

        let (identity, custom_fields) = drivers_license_to_identity(&drivers_license);

        assert_eq!(identity.license_number, Some("D123456789".to_string()));
        assert_eq!(identity.first_name, Some("John".to_string()));
        assert_eq!(identity.last_name, Some("Doe".to_string()));

        // Verify other fields are None
        assert_eq!(identity.title, None);
        assert_eq!(identity.address1, None);
        assert_eq!(identity.company, None); // Now custom field according to mapping

        // No unmapped fields in this test, so no custom fields
        assert_eq!(custom_fields.len(), 0);
    }

    #[test]
    fn test_drivers_license_full_name_parsing() {
        // Test single name
        let dl_single = create_drivers_license_credential(None, Some("John"));
        let (identity, _) = drivers_license_to_identity(&dl_single);
        assert_eq!(identity.first_name, Some("John".to_string()));
        assert_eq!(identity.last_name, None);

        // Test three names
        let dl_three = create_drivers_license_credential(None, Some("John Michael Doe"));
        let (identity, _) = drivers_license_to_identity(&dl_three);
        assert_eq!(identity.first_name, Some("John".to_string()));
        assert_eq!(identity.last_name, Some("Michael Doe".to_string()));

        // Test empty name
        let dl_empty = create_drivers_license_credential(None, Some(""));
        let (identity, _) = drivers_license_to_identity(&dl_empty);
        assert_eq!(identity.first_name, None);
        assert_eq!(identity.last_name, None);
    }

    #[test]
    fn test_address_integration_complete_data_mapping() {
        let result = load_sample_cxf();
        assert!(result.is_ok());

        let ciphers = result.unwrap();

        // Find the address cipher - should be titled "House Address"
        let address_cipher = ciphers
            .iter()
            .find(|c| c.name == "House Address")
            .expect("Should find House Address item");

        // Verify it's an Identity cipher
        let identity = match &address_cipher.r#type {
            crate::CipherType::Identity(identity) => identity,
            _ => panic!("Expected Identity cipher for address"),
        };

        // Verify ALL the address fields from cxf_example.json are mapped
        // streetAddress → address1
        assert_eq!(identity.address1, Some("123 Main Street".to_string()));
        // city → city
        assert_eq!(identity.city, Some("Springfield".to_string()));
        // territory → state
        assert_eq!(identity.state, Some("CA".to_string()));
        // country → country
        assert_eq!(identity.country, Some("US".to_string()));
        // tel → phone
        assert_eq!(identity.phone, Some("+1-555-123-4567".to_string()));
        // postalCode → postal_code
        assert_eq!(identity.postal_code, Some("12345".to_string()));
    }

    #[test]
    fn test_passport_integration_complete_data_mapping() {
        let result = load_sample_cxf();
        assert!(result.is_ok());

        let ciphers = result.unwrap();

        // Find the passport cipher - should be titled "Passport"
        let passport_cipher = ciphers
            .iter()
            .find(|c| c.name == "Passport")
            .expect("Should find Passport item");

        // Verify it's an Identity cipher
        let identity = match &passport_cipher.r#type {
            crate::CipherType::Identity(identity) => identity,
            _ => panic!("Expected Identity cipher for passport"),
        };

        // Verify passport fields from cxf_example.json
        // passportNumber → passport_number
        assert_eq!(identity.passport_number, Some("A12345678".to_string()));
        // nationalIdentificationNumber → ssn
        assert_eq!(identity.ssn, Some("ID123456789".to_string()));
        // fullName → first_name + last_name (split)
        assert_eq!(identity.first_name, Some("John".to_string()));
        assert_eq!(identity.last_name, Some("Doe".to_string()));
    }

    #[test]
    fn test_person_name_integration_complete_data_mapping() {
        let result = load_sample_cxf();
        assert!(result.is_ok());

        let ciphers = result.unwrap();

        // Find the person name cipher - should be titled "John Doe"
        let person_name_cipher = ciphers
            .iter()
            .find(|c| c.name == "John Doe")
            .expect("Should find John Doe item");

        // Verify it's an Identity cipher
        let identity = match &person_name_cipher.r#type {
            crate::CipherType::Identity(identity) => identity,
            _ => panic!("Expected Identity cipher for person name"),
        };

        // Verify ALL person name fields from cxf_example.json
        // title → title
        assert_eq!(identity.title, Some("Dr.".to_string()));
        // given → first_name
        assert_eq!(identity.first_name, Some("John".to_string()));
        // given2 → middle_name
        assert_eq!(identity.middle_name, Some("Michael".to_string()));
        // surname → last_name (now includes surnamePrefix + surname + surname2)
        assert_eq!(identity.last_name, Some("van Doe Smith".to_string()));
        // credentials → company
        assert_eq!(identity.company, Some("PhD".to_string()));

        // These should remain None for person-name-only credentials
        assert_eq!(identity.address1, None);
        assert_eq!(identity.passport_number, None);
        assert_eq!(identity.license_number, None);
        assert_eq!(identity.phone, None);
        assert_eq!(identity.country, None);
    }

    #[test]
    fn test_drivers_license_integration_complete_data_mapping() {
        let result = load_sample_cxf();
        assert!(result.is_ok());

        let ciphers = result.unwrap();

        // Find the drivers license cipher - should be titled "Driver License"
        let drivers_license_cipher = ciphers
            .iter()
            .find(|c| c.name == "Driver License")
            .expect("Should find Driver License item");

        // Verify it's an Identity cipher
        let identity = match &drivers_license_cipher.r#type {
            crate::CipherType::Identity(identity) => identity,
            _ => panic!("Expected Identity cipher for drivers license"),
        };

        // Verify mapped fields according to CXF mapping document
        assert_eq!(identity.license_number, Some("D12345678".to_string()));
        assert_eq!(identity.first_name, Some("John".to_string()));
        assert_eq!(identity.last_name, Some("Doe".to_string()));
        assert_eq!(identity.state, Some("CA".to_string())); // territory → state
        assert_eq!(identity.country, Some("US".to_string())); // country → country

        // issuingAuthority is now a custom field according to mapping document
        assert_eq!(identity.company, None);

        // These should remain None for drivers-license-only credentials
        assert_eq!(identity.address1, None);
        assert_eq!(identity.passport_number, None);
        assert_eq!(identity.phone, None);
        assert_eq!(identity.email, None);
    }

    #[test]
    fn test_address_json_field_mapping() {
        // Read the raw JSON file
        let cxf_data = fs::read_to_string("resources/cxf_example.json")
            .expect("Should be able to read cxf_example.json");
        let fixed_cxf_data = cxf_data.replace("\"integrityHash\":", "\"integrationHash\":");

        // Parse as generic JSON to inspect raw values
        let json: serde_json::Value = serde_json::from_str(&fixed_cxf_data).unwrap();

        // Find the address item
        let address_item = json["accounts"][0]["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["title"] == "House Address")
            .expect("Should find House Address item");

        let address_cred = &address_item["credentials"][0];
        assert_eq!(address_cred["type"], "address");

        // Extract all raw field values from JSON
        let street_address = address_cred["streetAddress"]["value"].as_str().unwrap();
        let postal_code = address_cred["postalCode"]["value"].as_str().unwrap();
        let city = address_cred["city"]["value"].as_str().unwrap();
        let territory = address_cred["territory"]["value"].as_str().unwrap();
        let country = address_cred["country"]["value"].as_str().unwrap();
        let tel = address_cred["tel"]["value"].as_str().unwrap();

        // Now test our mapping
        let result = load_sample_cxf().unwrap();
        let address_cipher = result
            .iter()
            .find(|c| c.name == "House Address")
            .expect("Should find mapped House Address");

        let identity = match &address_cipher.r#type {
            crate::CipherType::Identity(identity) => identity,
            _ => panic!("Expected Identity cipher"),
        };

        // Verify EVERY field is correctly mapped
        assert_eq!(
            identity.address1.as_deref(),
            Some(street_address),
            "streetAddress not mapped correctly"
        );
        assert_eq!(
            identity.postal_code.as_deref(),
            Some(postal_code),
            "postalCode not mapped correctly"
        );
        assert_eq!(
            identity.city.as_deref(),
            Some(city),
            "city not mapped correctly"
        );
        assert_eq!(
            identity.state.as_deref(),
            Some(territory),
            "territory not mapped correctly"
        );
        assert_eq!(
            identity.country.as_deref(),
            Some(country),
            "country not mapped correctly"
        );
        assert_eq!(
            identity.phone.as_deref(),
            Some(tel),
            "tel not mapped correctly"
        );
    }

    #[test]
    fn test_passport_json_field_mapping() {
        let cxf_data = fs::read_to_string("resources/cxf_example.json")
            .expect("Should be able to read cxf_example.json");
        let fixed_cxf_data = cxf_data.replace("\"integrityHash\":", "\"integrationHash\":");

        let json: serde_json::Value = serde_json::from_str(&fixed_cxf_data).unwrap();

        let passport_item = json["accounts"][0]["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["title"] == "Passport")
            .expect("Should find Passport item");

        let passport_cred = &passport_item["credentials"][0];
        assert_eq!(passport_cred["type"], "passport");

        // Extract ALL raw field values from JSON
        let issuing_country = passport_cred["issuingCountry"]["value"].as_str().unwrap();
        let passport_type = passport_cred["passportType"]["value"].as_str().unwrap();
        let passport_number = passport_cred["passportNumber"]["value"].as_str().unwrap();
        let national_id = passport_cred["nationalIdentificationNumber"]["value"]
            .as_str()
            .unwrap();
        let nationality = passport_cred["nationality"]["value"].as_str().unwrap();
        let full_name = passport_cred["fullName"]["value"].as_str().unwrap();
        let birth_date = passport_cred["birthDate"]["value"].as_str().unwrap();
        let birth_place = passport_cred["birthPlace"]["value"].as_str().unwrap();

        // Test our mapping
        let result = load_sample_cxf().unwrap();
        let passport_cipher = result
            .iter()
            .find(|c| c.name == "Passport")
            .expect("Should find mapped Passport");

        let identity = match &passport_cipher.r#type {
            crate::CipherType::Identity(identity) => identity,
            _ => panic!("Expected Identity cipher"),
        };

        assert_eq!(
            identity.passport_number.as_deref(),
            Some(passport_number),
            "passportNumber not mapped correctly"
        );

        // Verify fullName is now properly split and mapped
        assert_eq!(
            identity.first_name.as_deref(),
            Some("John"),
            "fullName first name not extracted correctly"
        );
        assert_eq!(
            identity.last_name.as_deref(),
            Some("Doe"),
            "fullName last name not extracted correctly"
        );

        // Verify nationalIdentificationNumber is mapped to ssn
        assert_eq!(
            identity.ssn.as_deref(),
            Some(national_id),
            "nationalIdentificationNumber not mapped to ssn"
        );

        // Verify that unmapped data is preserved in custom fields
        // Note: We can't easily test custom fields here because this test only checks Identity,
        // but custom fields are stored in ImportingCipher.fields. The data should be preserved
        // in custom fields: passportType, nationality, birthDate, birthPlace
    }

    #[test]
    fn test_person_name_json_field_mapping() {
        let cxf_data = fs::read_to_string("resources/cxf_example.json")
            .expect("Should be able to read cxf_example.json");
        let fixed_cxf_data = cxf_data.replace("\"integrityHash\":", "\"integrationHash\":");

        let json: serde_json::Value = serde_json::from_str(&fixed_cxf_data).unwrap();

        let person_name_item = json["accounts"][0]["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["title"] == "John Doe")
            .expect("Should find John Doe item");

        let person_name_cred = &person_name_item["credentials"][0];
        assert_eq!(person_name_cred["type"], "person-name");

        // Extract ALL raw field values from JSON
        let title = person_name_cred["title"]["value"].as_str().unwrap();
        let given = person_name_cred["given"]["value"].as_str().unwrap();
        let given_informal = person_name_cred["givenInformal"]["value"].as_str().unwrap();
        let given2 = person_name_cred["given2"]["value"].as_str().unwrap();
        let surname_prefix = person_name_cred["surnamePrefix"]["value"].as_str().unwrap();
        let surname = person_name_cred["surname"]["value"].as_str().unwrap();
        let surname2 = person_name_cred["surname2"]["value"].as_str().unwrap();
        let credentials = person_name_cred["credentials"]["value"].as_str().unwrap();

        // Test our mapping
        let result = load_sample_cxf().unwrap();
        let person_name_cipher = result
            .iter()
            .find(|c| c.name == "John Doe")
            .expect("Should find mapped John Doe");

        let identity = match &person_name_cipher.r#type {
            crate::CipherType::Identity(identity) => identity,
            _ => panic!("Expected Identity cipher"),
        };

        // Verify mapped fields
        assert_eq!(
            identity.title.as_deref(),
            Some(title),
            "title not mapped correctly"
        );
        assert_eq!(
            identity.first_name.as_deref(),
            Some(given),
            "given not mapped correctly"
        );
        assert_eq!(
            identity.middle_name.as_deref(),
            Some(given2),
            "given2 not mapped correctly"
        );

        // Verify complete last name construction (surnamePrefix + surname + surname2)
        assert_eq!(
            identity.last_name.as_deref(),
            Some("van Doe Smith"),
            "complete surname not constructed correctly"
        );

        // Verify credentials are mapped to company field
        assert_eq!(
            identity.company.as_deref(),
            Some(credentials),
            "credentials not mapped to company"
        );

        // Verify that unmapped data is preserved in custom fields
        // Note: We can't easily test custom fields here because this test only checks Identity,
        // but custom fields are stored in ImportingCipher.fields. The data should be preserved
        // in custom fields: givenInformal
    }

    #[test]
    fn test_drivers_license_json_field_mapping() {
        let cxf_data = fs::read_to_string("resources/cxf_example.json")
            .expect("Should be able to read cxf_example.json");
        let fixed_cxf_data = cxf_data.replace("\"integrityHash\":", "\"integrationHash\":");

        let json: serde_json::Value = serde_json::from_str(&fixed_cxf_data).unwrap();

        let drivers_license_item = json["accounts"][0]["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["title"] == "Driver License")
            .expect("Should find Driver License item");

        let drivers_license_cred = &drivers_license_item["credentials"][0];
        assert_eq!(drivers_license_cred["type"], "drivers-license");

        // Extract ALL raw field values from JSON
        let full_name = drivers_license_cred["fullName"]["value"].as_str().unwrap();
        let birth_date = drivers_license_cred["birthDate"]["value"].as_str().unwrap();
        let issue_date = drivers_license_cred["issueDate"]["value"].as_str().unwrap();
        let expiry_date = drivers_license_cred["expiryDate"]["value"]
            .as_str()
            .unwrap();
        let issuing_authority = drivers_license_cred["issuingAuthority"]["value"]
            .as_str()
            .unwrap();
        let territory = drivers_license_cred["territory"]["value"].as_str().unwrap();
        let country = drivers_license_cred["country"]["value"].as_str().unwrap();
        let license_number = drivers_license_cred["licenseNumber"]["value"]
            .as_str()
            .unwrap();

        // Test our mapping
        let result = load_sample_cxf().unwrap();
        let drivers_license_cipher = result
            .iter()
            .find(|c| c.name == "Driver License")
            .expect("Should find mapped Driver License");

        let identity = match &drivers_license_cipher.r#type {
            crate::CipherType::Identity(identity) => identity,
            _ => panic!("Expected Identity cipher"),
        };

        // Verify mapped fields - now includes all major fields
        assert_eq!(
            identity.license_number.as_deref(),
            Some(license_number),
            "licenseNumber not mapped correctly"
        );
        assert_eq!(
            identity.first_name.as_deref(),
            Some("John"),
            "fullName first name not extracted correctly"
        );
        assert_eq!(
            identity.last_name.as_deref(),
            Some("Doe"),
            "fullName last name not extracted correctly"
        );

        // Verify new mappings
        assert_eq!(
            identity.state.as_deref(),
            Some(territory),
            "territory not mapped to state"
        );
        assert_eq!(
            identity.country.as_deref(),
            Some(country),
            "country not mapped correctly"
        );
        // issuingAuthority is now a custom field according to mapping document
        assert_eq!(identity.company, None);

        // Verify that unmapped data is preserved in custom fields
        // Note: We can't easily test custom fields here because this test only checks Identity,
        // but custom fields are stored in ImportingCipher.fields. The data should be preserved
        // in custom fields: birthDate, issueDate, expiryDate
    }
}
