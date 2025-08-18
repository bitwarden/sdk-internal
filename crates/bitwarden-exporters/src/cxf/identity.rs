use credential_exchange_format::{
    AddressCredential, DriversLicenseCredential, EditableField, EditableFieldString,
    IdentityDocumentCredential, PassportCredential, PersonNameCredential,
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
pub(super) fn address_to_identity(address: AddressCredential) -> (Identity, Vec<Field>) {
    let identity = Identity {
        address1: address.street_address.map(Into::into),
        city: address.city.map(Into::into),
        state: address.territory.map(Into::into),
        postal_code: address.postal_code.map(Into::into),
        country: address.country.map(Into::into),
        phone: address.tel.map(Into::into),
        ..Default::default()
    };

    (identity, vec![])
}

/// Convert passport credentials to Identity and custom fields
/// According to CXF mapping document:
/// - passportNumber: EditableField<"string"> → Identity::passport_number
/// - nationalIdentificationNumber: EditableField<"string"> → Identity::ssn
/// - fullName: EditableField<"string"> → Identity::first_name + last_name (split)
/// - All other fields → CustomFields
pub(super) fn passport_to_identity(passport: PassportCredential) -> (Identity, Vec<Field>) {
    // Split full name into first and last name if available
    let (first_name, last_name) = split_name(&passport.full_name);

    let identity = Identity {
        first_name,
        last_name,
        // Map nationalIdentificationNumber to ssn as closest available field
        ssn: passport.national_identification_number.map(Into::into),
        passport_number: passport.passport_number.map(Into::into),
        ..Default::default()
    };

    // Create custom fields for unmapped data according to CXF mapping document
    let custom_fields = [
        passport
            .issuing_country
            .map(|issuing_country| create_field("Issuing Country", &issuing_country)),
        passport
            .nationality
            .map(|nationality| create_field("Nationality", &nationality)),
        passport
            .birth_date
            .map(|birth_date| create_field("Birth Date", &birth_date)),
        passport
            .birth_place
            .map(|birth_place| create_field("Birth Place", &birth_place)),
        passport.sex.map(|sex| create_field("Sex", &sex)),
        passport
            .issue_date
            .map(|issue_date| create_field("Issue Date", &issue_date)),
        passport
            .expiry_date
            .map(|expiry_date| create_field("Expiry Date", &expiry_date)),
        passport
            .issuing_authority
            .map(|issuing_authority| create_field("Issuing Authority", &issuing_authority)),
        passport
            .passport_type
            .map(|passport_type| create_field("Passport Type", &passport_type)),
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
pub(super) fn person_name_to_identity(person_name: PersonNameCredential) -> (Identity, Vec<Field>) {
    // Construct complete last name from surnamePrefix, surname, and surname2
    let last_name = [
        person_name.surname_prefix.as_ref(),
        person_name.surname.as_ref(),
        person_name.surname2.as_ref(),
    ]
    .into_iter()
    .flatten()
    .map(|field| field.value.0.clone())
    .collect::<Vec<_>>()
    .into_iter()
    .reduce(|acc, part| format!("{acc} {part}"));

    let identity = Identity {
        title: person_name.title.map(Into::into),
        first_name: person_name.given.map(Into::into),
        middle_name: person_name.given2.map(Into::into),
        last_name,
        // Map credentials (e.g., "PhD") to company field as professional qualifications
        company: person_name.credentials.map(Into::into),
        ..Default::default()
    };

    // Create custom fields for unmapped data
    let custom_fields = [
        person_name
            .given_informal
            .map(|given_informal| create_field("Informal Given Name", &given_informal)),
        person_name
            .generation
            .map(|generation| create_field("Generation", &generation)),
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
pub(super) fn drivers_license_to_identity(
    drivers_license: DriversLicenseCredential,
) -> (Identity, Vec<Field>) {
    // Split full name into first and last name if available
    let (first_name, last_name) = split_name(&drivers_license.full_name);

    let identity = Identity {
        first_name,
        last_name,
        // Map territory (state/province) to state field
        state: drivers_license.territory.map(Into::into),
        // Map country to country field
        country: drivers_license.country.map(Into::into),
        license_number: drivers_license.license_number.map(Into::into),
        ..Default::default()
    };

    // Create custom fields for unmapped data according to CXF mapping document
    let custom_fields = [
        drivers_license
            .birth_date
            .map(|birth_date| create_field("Birth Date", &birth_date)),
        drivers_license
            .issue_date
            .map(|issue_date| create_field("Issue Date", &issue_date)),
        drivers_license
            .expiry_date
            .map(|expiry_date| create_field("Expiry Date", &expiry_date)),
        drivers_license
            .issuing_authority
            .map(|issuing_authority| create_field("Issuing Authority", &issuing_authority)),
        drivers_license
            .license_class
            .map(|license_class| create_field("License Class", &license_class)),
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
pub(super) fn identity_document_to_identity(
    identity_document: IdentityDocumentCredential,
) -> (Identity, Vec<Field>) {
    // Split full name into first and last name if available
    let (first_name, last_name) = split_name(&identity_document.full_name);

    let identity = Identity {
        first_name,
        last_name,
        // Map identificationNumber to ssn
        ssn: identity_document.identification_number.map(Into::into),
        // Map documentNumber to passport_number (reusing for document number)
        passport_number: identity_document.document_number.map(Into::into),
        ..Default::default()
    };

    // Create custom fields for unmapped data according to CXF mapping document
    let custom_fields = [
        identity_document
            .issuing_country
            .map(|issuing_country| create_field("Issuing Country", &issuing_country)),
        identity_document
            .nationality
            .map(|nationality| create_field("Nationality", &nationality)),
        identity_document
            .birth_date
            .map(|birth_date| create_field("Birth Date", &birth_date)),
        identity_document
            .birth_place
            .map(|birth_place| create_field("Birth Place", &birth_place)),
        identity_document.sex.map(|sex| create_field("Sex", &sex)),
        identity_document
            .issue_date
            .map(|issue_date| create_field("Issue Date", &issue_date)),
        identity_document
            .expiry_date
            .map(|expiry_date| create_field("Expiry Date", &expiry_date)),
        identity_document
            .issuing_authority
            .map(|issuing_authority| create_field("Issuing Authority", &issuing_authority)),
    ]
    .into_iter()
    .flatten()
    .collect();

    (identity, custom_fields)
}

fn split_name(
    full_name: &Option<EditableField<EditableFieldString>>,
) -> (Option<String>, Option<String>) {
    full_name.as_ref().map_or((None, None), |name| {
        let parts: Vec<&str> = name.value.0.split_whitespace().collect();
        match parts.as_slice() {
            [] => (None, None),
            [first] => (Some(first.to_string()), None),
            [first, rest @ ..] => (Some(first.to_string()), Some(rest.join(" "))),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_name_none() {
        let full_name = None;
        let (first, last) = split_name(&full_name);
        assert_eq!(first, None);
        assert_eq!(last, None);
    }

    #[test]
    fn test_split_name_empty_string() {
        let full_name = Some(EditableField {
            value: EditableFieldString("".to_string()),
            label: None,
            id: None,
            extensions: None,
        });
        let (first, last) = split_name(&full_name);
        assert_eq!(first, None);
        assert_eq!(last, None);
    }

    #[test]
    fn test_split_name_whitespace_only() {
        let full_name = Some(EditableField {
            value: EditableFieldString("   \t\n  ".to_string()),
            label: None,
            id: None,
            extensions: None,
        });
        let (first, last) = split_name(&full_name);
        assert_eq!(first, None);
        assert_eq!(last, None);
    }

    #[test]
    fn test_split_name_single_name() {
        let full_name = Some(EditableField {
            value: EditableFieldString("John".to_string()),
            label: None,
            id: None,
            extensions: None,
        });
        let (first, last) = split_name(&full_name);
        assert_eq!(first, Some("John".to_string()));
        assert_eq!(last, None);
    }

    #[test]
    fn test_split_name_single_name_with_whitespace() {
        let full_name = Some(EditableField {
            value: EditableFieldString("  John  ".to_string()),
            label: None,
            id: None,
            extensions: None,
        });
        let (first, last) = split_name(&full_name);
        assert_eq!(first, Some("John".to_string()));
        assert_eq!(last, None);
    }

    #[test]
    fn test_split_name_first_last() {
        let full_name = Some(EditableField {
            value: EditableFieldString("John Doe".to_string()),
            label: None,
            id: None,
            extensions: None,
        });
        let (first, last) = split_name(&full_name);
        assert_eq!(first, Some("John".to_string()));
        assert_eq!(last, Some("Doe".to_string()));
    }

    #[test]
    fn test_split_name_first_middle_last() {
        let full_name = Some(EditableField {
            value: EditableFieldString("John Michael Doe".to_string()),
            label: None,
            id: None,
            extensions: None,
        });
        let (first, last) = split_name(&full_name);
        assert_eq!(first, Some("John".to_string()));
        assert_eq!(last, Some("Michael Doe".to_string()));
    }

    #[test]
    fn test_split_name_multiple_middle_names() {
        let full_name = Some(EditableField {
            value: EditableFieldString("John Michael Andrew Doe".to_string()),
            label: None,
            id: None,
            extensions: None,
        });
        let (first, last) = split_name(&full_name);
        assert_eq!(first, Some("John".to_string()));
        assert_eq!(last, Some("Michael Andrew Doe".to_string()));
    }

    #[test]
    fn test_split_name_complex_surname() {
        let full_name = Some(EditableField {
            value: EditableFieldString("Jane van der Berg".to_string()),
            label: None,
            id: None,
            extensions: None,
        });
        let (first, last) = split_name(&full_name);
        assert_eq!(first, Some("Jane".to_string()));
        assert_eq!(last, Some("van der Berg".to_string()));
    }

    #[test]
    fn test_split_name_hyphenated_surname() {
        let full_name = Some(EditableField {
            value: EditableFieldString("Mary Smith-Johnson".to_string()),
            label: None,
            id: None,
            extensions: None,
        });
        let (first, last) = split_name(&full_name);
        assert_eq!(first, Some("Mary".to_string()));
        assert_eq!(last, Some("Smith-Johnson".to_string()));
    }

    #[test]
    fn test_split_name_extra_whitespace() {
        let full_name = Some(EditableField {
            value: EditableFieldString("  John   Michael   Doe  ".to_string()),
            label: None,
            id: None,
            extensions: None,
        });
        let (first, last) = split_name(&full_name);
        assert_eq!(first, Some("John".to_string()));
        assert_eq!(last, Some("Michael Doe".to_string()));
    }

    #[test]
    fn test_split_name_special_characters() {
        let full_name = Some(EditableField {
            value: EditableFieldString("José María González".to_string()),
            label: None,
            id: None,
            extensions: None,
        });
        let (first, last) = split_name(&full_name);
        assert_eq!(first, Some("José".to_string()));
        assert_eq!(last, Some("María González".to_string()));
    }

    #[test]
    fn test_split_name_single_character_names() {
        let full_name = Some(EditableField {
            value: EditableFieldString("A B C".to_string()),
            label: None,
            id: None,
            extensions: None,
        });
        let (first, last) = split_name(&full_name);
        assert_eq!(first, Some("A".to_string()));
        assert_eq!(last, Some("B C".to_string()));
    }
}
