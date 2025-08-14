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
pub(super) fn address_to_identity(address: &AddressCredential) -> (Identity, Vec<Field>) {
    let identity = Identity {
        address1: address.street_address.as_ref().map(|s| s.value.0.clone()),
        city: address.city.as_ref().map(|c| c.value.0.clone()),
        state: address.territory.as_ref().map(|t| t.value.0.clone()),
        postal_code: address.postal_code.as_ref().map(|p| p.value.0.clone()),
        country: address.country.as_ref().map(|c| c.value.0.clone()),
        phone: address.tel.as_ref().map(|t| t.value.0.clone()),
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
pub(super) fn passport_to_identity(passport: &PassportCredential) -> (Identity, Vec<Field>) {
    // Split full name into first and last name if available

    let (first_name, last_name) = split_name(&passport.full_name);

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
pub(super) fn person_name_to_identity(
    person_name: &PersonNameCredential,
) -> (Identity, Vec<Field>) {
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
    .reduce(|acc, part| format!("{} {}", acc, part));

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
pub(super) fn drivers_license_to_identity(
    drivers_license: &DriversLicenseCredential,
) -> (Identity, Vec<Field>) {
    // Split full name into first and last name if available
    let (first_name, last_name) = split_name(&drivers_license.full_name);

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
pub(super) fn identity_document_to_identity(
    identity_document: &IdentityDocumentCredential,
) -> (Identity, Vec<Field>) {
    // Split full name into first and last name if available
    let (first_name, last_name) = split_name(&identity_document.full_name);

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
