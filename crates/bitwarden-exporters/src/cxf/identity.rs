use credential_exchange_format::{
    AddressCredential, Credential, CustomFieldsCredential, DriversLicenseCredential, EditableField,
    EditableFieldString, EditableFieldValue, IdentityDocumentCredential, PassportCredential,
    PersonNameCredential,
};

use crate::{
    Field, Identity,
    cxf::editable_field::{create_editable_field, create_field},
};

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
            .map(|issuing_country| create_field(&issuing_country, Some("Issuing Country"))),
        passport
            .nationality
            .map(|nationality| create_field(&nationality, Some("Nationality"))),
        passport
            .birth_date
            .map(|birth_date| create_field(&birth_date, Some("Birth Date"))),
        passport
            .birth_place
            .map(|birth_place| create_field(&birth_place, Some("Birth Place"))),
        passport.sex.map(|sex| create_field(&sex, Some("Sex"))),
        passport
            .issue_date
            .map(|issue_date| create_field(&issue_date, Some("Issue Date"))),
        passport
            .expiry_date
            .map(|expiry_date| create_field(&expiry_date, Some("Expiry Date"))),
        passport
            .issuing_authority
            .map(|issuing_authority| create_field(&issuing_authority, Some("Issuing Authority"))),
        passport
            .passport_type
            .map(|passport_type| create_field(&passport_type, Some("Passport Type"))),
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
            .map(|given_informal| create_field(&given_informal, Some("Informal Given Name"))),
        person_name
            .generation
            .map(|generation| create_field(&generation, Some("Generation"))),
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
            .map(|birth_date| create_field(&birth_date, Some("Birth Date"))),
        drivers_license
            .issue_date
            .map(|issue_date| create_field(&issue_date, Some("Issue Date"))),
        drivers_license
            .expiry_date
            .map(|expiry_date| create_field(&expiry_date, Some("Expiry Date"))),
        drivers_license
            .issuing_authority
            .map(|issuing_authority| create_field(&issuing_authority, Some("Issuing Authority"))),
        drivers_license
            .license_class
            .map(|license_class| create_field(&license_class, Some("License Class"))),
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
            .map(|issuing_country| create_field(&issuing_country, Some("Issuing Country"))),
        identity_document
            .nationality
            .map(|nationality| create_field(&nationality, Some("Nationality"))),
        identity_document
            .birth_date
            .map(|birth_date| create_field(&birth_date, Some("Birth Date"))),
        identity_document
            .birth_place
            .map(|birth_place| create_field(&birth_place, Some("Birth Place"))),
        identity_document
            .sex
            .map(|sex| create_field(&sex, Some("Sex"))),
        identity_document
            .issue_date
            .map(|issue_date| create_field(&issue_date, Some("Issue Date"))),
        identity_document
            .expiry_date
            .map(|expiry_date| create_field(&expiry_date, Some("Expiry Date"))),
        identity_document
            .issuing_authority
            .map(|issuing_authority| create_field(&issuing_authority, Some("Issuing Authority"))),
    ]
    .into_iter()
    .flatten()
    .collect();

    (identity, custom_fields)
}

fn to_editable_field<T, U>(field: &Option<T>) -> Option<EditableField<U>>
where
    T: Clone + Into<EditableField<U>>,
{
    field.clone().map(|v| v.into())
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

impl From<&Identity> for PersonNameCredential {
    fn from(identity: &Identity) -> Self {
        PersonNameCredential {
            title: to_editable_field(&identity.title),
            given: to_editable_field(&identity.first_name),
            given_informal: None,
            given2: to_editable_field(&identity.middle_name),
            surname_prefix: None,
            surname: to_editable_field(&identity.last_name),
            surname2: None,
            credentials: to_editable_field(&identity.company),
            generation: None,
            // Note: Can't use ..Default::default() - not implemented in current CXF version
        }
    }
}

impl From<&Identity> for AddressCredential {
    fn from(identity: &Identity) -> Self {
        // Combine address lines with newlines as per CXF spec
        let street_address = {
            let address_lines: Vec<&str> =
                [&identity.address1, &identity.address2, &identity.address3]
                    .into_iter()
                    .filter_map(|addr| addr.as_deref())
                    .collect();

            if address_lines.is_empty() {
                None
            } else {
                Some(address_lines.join("\n"))
            }
        };

        AddressCredential {
            street_address: street_address.map(|v| v.into()),
            city: to_editable_field(&identity.city),
            territory: to_editable_field(&identity.state),
            country: to_editable_field(&identity.country),
            tel: to_editable_field(&identity.phone),
            postal_code: to_editable_field(&identity.postal_code),
        }
    }
}

impl From<&Identity> for PassportCredential {
    fn from(identity: &Identity) -> Self {
        let full_name = combine_name(
            &identity.first_name,
            &identity.middle_name,
            &identity.last_name,
        );

        PassportCredential {
            issuing_country: to_editable_field(&identity.country),
            nationality: None,
            full_name: full_name.map(|v| v.into()),
            birth_date: None,
            birth_place: None,
            sex: None,
            issue_date: None,
            expiry_date: None,
            issuing_authority: None,
            passport_type: None,
            passport_number: to_editable_field(&identity.passport_number),
            national_identification_number: to_editable_field(&identity.ssn),
            // Note: Can't use ..Default::default() - not implemented in current CXF version
        }
    }
}

impl From<&Identity> for DriversLicenseCredential {
    fn from(identity: &Identity) -> Self {
        let full_name = combine_name(
            &identity.first_name,
            &identity.middle_name,
            &identity.last_name,
        );

        DriversLicenseCredential {
            full_name: full_name.map(|v| v.into()),
            birth_date: None,
            issue_date: None,
            expiry_date: None,
            issuing_authority: None,
            territory: to_editable_field(&identity.state),
            country: to_editable_field(&identity.country),
            license_number: to_editable_field(&identity.license_number),
            license_class: None,
            // Note: Can't use ..Default::default() - not implemented in current CXF version
        }
    }
}

impl From<&Identity> for IdentityDocumentCredential {
    fn from(identity: &Identity) -> Self {
        let full_name = combine_name(
            &identity.first_name,
            &identity.middle_name,
            &identity.last_name,
        );

        IdentityDocumentCredential {
            issuing_country: to_editable_field(&identity.country),
            document_number: None,
            identification_number: to_editable_field(&identity.ssn),
            nationality: None,
            full_name: full_name.map(|v| v.into()),
            birth_date: None,
            birth_place: None,
            sex: None,
            issue_date: None,
            expiry_date: None,
            issuing_authority: None,
            // Note: Can't use ..Default::default() - not implemented in current CXF version
        }
    }
}

impl From<Identity> for Vec<Credential> {
    fn from(identity: Identity) -> Self {
        let mut credentials = vec![];

        // Helper to check if any name fields are present
        let has_name_fields = identity.title.is_some()
            || identity.first_name.is_some()
            || identity.middle_name.is_some()
            || identity.last_name.is_some()
            || identity.company.is_some();

        // Helper to check if any address fields are present
        let has_address_fields = identity.address1.is_some()
            || identity.city.is_some()
            || identity.state.is_some()
            || identity.country.is_some()
            || identity.phone.is_some()
            || identity.postal_code.is_some();

        // Create PersonName credential only if name-related fields are present
        if has_name_fields {
            credentials.push(Credential::PersonName(Box::new((&identity).into())));
        }

        // Create Address credential only if address fields are present
        if has_address_fields {
            credentials.push(Credential::Address(Box::new((&identity).into())));
        }

        // Create Passport credential if passport number is present
        if identity.passport_number.is_some() {
            credentials.push(Credential::Passport(Box::new((&identity).into())));
        }

        // Create DriversLicense credential if license number is present
        if identity.license_number.is_some() {
            credentials.push(Credential::DriversLicense(Box::new((&identity).into())));
        }

        // Create IdentityDocument credential if SSN is present
        if identity.ssn.is_some() {
            credentials.push(Credential::IdentityDocument(Box::new((&identity).into())));
        }

        // Handle unmapped Identity fields as custom fields
        let custom_fields: Vec<EditableFieldValue> = [
            identity.email.as_ref().map(|email| {
                EditableFieldValue::String(create_editable_field(
                    "Email".to_string(),
                    EditableFieldString(email.clone()),
                ))
            }),
            identity.username.as_ref().map(|username| {
                EditableFieldValue::String(create_editable_field(
                    "Username".to_string(),
                    EditableFieldString(username.clone()),
                ))
            }),
        ]
        .into_iter()
        .flatten()
        .collect();

        // Add CustomFields credential if there are any unmapped fields
        if !custom_fields.is_empty() {
            credentials.push(Credential::CustomFields(Box::new(CustomFieldsCredential {
                id: None,
                label: None,
                fields: custom_fields,
                extensions: vec![],
            })));
        }

        credentials
    }
}

pub(crate) fn combine_name(
    first: &Option<String>,
    middle: &Option<String>,
    last: &Option<String>,
) -> Option<String> {
    let parts: Vec<&str> = [first.as_deref(), middle.as_deref(), last.as_deref()]
        .into_iter()
        .flatten()
        .collect();

    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use credential_exchange_format::Credential;

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

    #[test]
    fn test_identity_to_credentials() {
        let identity = Identity {
            title: Some("Dr.".to_string()),
            first_name: Some("John".to_string()),
            middle_name: Some("Michael".to_string()),
            last_name: Some("Doe".to_string()),
            address1: Some("123 Main St".to_string()),
            address2: Some("Apt 456".to_string()),
            address3: None,
            city: Some("Anytown".to_string()),
            state: Some("CA".to_string()),
            postal_code: Some("12345".to_string()),
            country: Some("US".to_string()),
            company: Some("PhD".to_string()),
            email: Some("john@example.com".to_string()),
            phone: Some("+1234567890".to_string()),
            ssn: Some("123-45-6789".to_string()),
            username: Some("johndoe".to_string()),
            passport_number: Some("P123456789".to_string()),
            license_number: Some("DL123456".to_string()),
        };

        let credentials: Vec<Credential> = identity.into();

        // Should create PersonName, Address, Passport, DriversLicense, IdentityDocument, and
        // CustomFields credentials
        assert_eq!(credentials.len(), 6);

        // Check PersonName credential
        if let Credential::PersonName(person_name) = &credentials[0] {
            assert_eq!(person_name.title.as_ref().unwrap().value.0, "Dr.");
            assert_eq!(person_name.given.as_ref().unwrap().value.0, "John");
            assert_eq!(person_name.given2.as_ref().unwrap().value.0, "Michael");
            assert_eq!(person_name.surname.as_ref().unwrap().value.0, "Doe");
            assert_eq!(person_name.credentials.as_ref().unwrap().value.0, "PhD");
        } else {
            panic!("Expected PersonName credential");
        }

        // Check Address credential
        if let Credential::Address(address) = &credentials[1] {
            assert_eq!(
                address.street_address.as_ref().unwrap().value.0,
                "123 Main St\nApt 456"
            );
            assert_eq!(address.city.as_ref().unwrap().value.0, "Anytown");
            assert_eq!(address.territory.as_ref().unwrap().value.0, "CA");
            assert_eq!(address.country.as_ref().unwrap().value.0, "US");
            assert_eq!(address.tel.as_ref().unwrap().value.0, "+1234567890");
            assert_eq!(address.postal_code.as_ref().unwrap().value.0, "12345");
        } else {
            panic!("Expected Address credential");
        }

        // Check Passport credential
        if let Credential::Passport(passport) = &credentials[2] {
            assert_eq!(
                passport.passport_number.as_ref().unwrap().value.0,
                "P123456789"
            );
            assert_eq!(
                passport.full_name.as_ref().unwrap().value.0,
                "John Michael Doe"
            );
            assert_eq!(
                passport
                    .national_identification_number
                    .as_ref()
                    .unwrap()
                    .value
                    .0,
                "123-45-6789"
            );
            assert_eq!(passport.issuing_country.as_ref().unwrap().value.0, "US");
        } else {
            panic!("Expected Passport credential");
        }

        // Check DriversLicense credential
        if let Credential::DriversLicense(license) = &credentials[3] {
            assert_eq!(license.license_number.as_ref().unwrap().value.0, "DL123456");
            assert_eq!(
                license.full_name.as_ref().unwrap().value.0,
                "John Michael Doe"
            );
            assert_eq!(license.territory.as_ref().unwrap().value.0, "CA");
            assert_eq!(license.country.as_ref().unwrap().value.0, "US");
        } else {
            panic!("Expected DriversLicense credential");
        }

        // Check IdentityDocument credential
        if let Credential::IdentityDocument(identity_doc) = &credentials[4] {
            assert_eq!(
                identity_doc.identification_number.as_ref().unwrap().value.0,
                "123-45-6789"
            );
            assert_eq!(
                identity_doc.full_name.as_ref().unwrap().value.0,
                "John Michael Doe"
            );
        } else {
            panic!("Expected IdentityDocument credential");
        }

        // Check CustomFields credential
        if let Credential::CustomFields(custom_fields) = &credentials[5] {
            assert_eq!(custom_fields.fields.len(), 2); // email, username

            // Check email field
            let email_field = &custom_fields.fields[0];
            if let EditableFieldValue::String(email_field) = email_field {
                assert_eq!(email_field.label.as_ref().unwrap(), "Email");
                assert_eq!(email_field.value.0, "john@example.com");
            } else {
                panic!("Expected email field to be of type String");
            }

            // Check username field
            let username_field = &custom_fields.fields[1];
            if let EditableFieldValue::String(username_field) = username_field {
                assert_eq!(username_field.label.as_ref().unwrap(), "Username");
                assert_eq!(username_field.value.0, "johndoe");
            } else {
                panic!("Expected username field to be of type String");
            }
        } else {
            panic!("Expected CustomFields credential");
        }
    }

    #[test]
    fn test_identity_minimal_fields() {
        let identity = Identity {
            first_name: Some("Jane".to_string()),
            last_name: Some("Smith".to_string()),
            ..Default::default()
        };

        let credentials: Vec<Credential> = identity.into();

        // Should only create PersonName credential
        assert_eq!(credentials.len(), 1);

        if let Credential::PersonName(person_name) = &credentials[0] {
            assert_eq!(person_name.given.as_ref().unwrap().value.0, "Jane");
            assert_eq!(person_name.surname.as_ref().unwrap().value.0, "Smith");
            assert!(person_name.title.is_none());
            assert!(person_name.given2.is_none());
        } else {
            panic!("Expected PersonName credential");
        }
    }

    #[test]
    fn test_identity_license_only() {
        let identity = Identity {
            first_name: Some("Alice".to_string()),
            license_number: Some("LIC123456".to_string()),
            state: Some("NY".to_string()),
            ..Default::default()
        };

        let credentials: Vec<Credential> = identity.into();

        // Should create PersonName, Address (due to state), and DriversLicense credentials
        assert_eq!(credentials.len(), 3);

        // Check PersonName credential
        if let Credential::PersonName(person_name) = &credentials[0] {
            assert_eq!(person_name.given.as_ref().unwrap().value.0, "Alice");
        } else {
            panic!("Expected PersonName credential");
        }

        // Check Address credential
        if let Credential::Address(address) = &credentials[1] {
            assert_eq!(address.territory.as_ref().unwrap().value.0, "NY");
        } else {
            panic!("Expected Address credential");
        }

        // Check DriversLicense credential
        if let Credential::DriversLicense(license) = &credentials[2] {
            assert_eq!(
                license.license_number.as_ref().unwrap().value.0,
                "LIC123456"
            );
            assert_eq!(license.full_name.as_ref().unwrap().value.0, "Alice");
            assert_eq!(license.territory.as_ref().unwrap().value.0, "NY");
        } else {
            panic!("Expected DriversLicense credential");
        }
    }

    #[test]
    fn test_identity_ssn_only() {
        let identity = Identity {
            first_name: Some("Bob".to_string()),
            ssn: Some("987-65-4321".to_string()),
            ..Default::default()
        };

        let credentials: Vec<Credential> = identity.into();

        // Should create PersonName and IdentityDocument credentials
        assert_eq!(credentials.len(), 2);

        if let Credential::IdentityDocument(identity_doc) = &credentials[1] {
            assert_eq!(
                identity_doc.identification_number.as_ref().unwrap().value.0,
                "987-65-4321"
            );
            assert_eq!(identity_doc.full_name.as_ref().unwrap().value.0, "Bob");
        } else {
            panic!("Expected IdentityDocument credential");
        }
    }

    #[test]
    fn test_identity_empty() {
        let identity = Identity::default();

        let credentials: Vec<Credential> = identity.into();

        // Should create no credentials for completely empty identity
        assert_eq!(credentials.len(), 0);
    }

    #[test]
    fn test_combine_name_helper() {
        assert_eq!(
            combine_name(
                &Some("John".to_string()),
                &Some("Michael".to_string()),
                &Some("Doe".to_string())
            ),
            Some("John Michael Doe".to_string())
        );

        assert_eq!(
            combine_name(&Some("Jane".to_string()), &None, &Some("Smith".to_string())),
            Some("Jane Smith".to_string())
        );

        assert_eq!(
            combine_name(&Some("Bob".to_string()), &None, &None),
            Some("Bob".to_string())
        );

        assert_eq!(combine_name(&None, &None, &None), None);
    }
}
