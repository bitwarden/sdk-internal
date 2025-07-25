use credential_exchange_format::AddressCredential;

use crate::Identity;

/// Convert address credentials to Identity following the CXF mapping convention
/// According to the mapping specification:
/// - streetAddress: EditableField<"string"> → Identity::address1
/// - city: EditableField<"string"> → Identity::city
/// - territory: EditableField<"subdivision-code"> → Identity::state
/// - country: EditableField<"country-code"> → Identity::country
/// - tel: EditableField<"string"> → Identity::phone
/// - postalCode: EditableField<"string"> → Identity::postal_code (not in mapping but common field)
pub fn address_to_identity(address: &AddressCredential) -> Identity {
    Identity {
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
    }
}

#[cfg(test)]
mod tests {
    use credential_exchange_format::{
        EditableField, EditableFieldCountryCode, EditableFieldString, EditableFieldSubdivisionCode,
    };

    use super::*;

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

        let identity = address_to_identity(&address);

        assert_eq!(identity.address1, Some("123 Main Street".to_string()));
        assert_eq!(identity.city, Some("Springfield".to_string()));
        assert_eq!(identity.state, Some("CA".to_string()));
        assert_eq!(identity.country, Some("US".to_string()));
        assert_eq!(identity.phone, Some("+1-555-123-4567".to_string()));
        assert_eq!(identity.postal_code, Some("12345".to_string()));

        // Verify unmapped fields are None
        assert_eq!(identity.title, None);
        assert_eq!(identity.first_name, None);
        assert_eq!(identity.middle_name, None);
        assert_eq!(identity.last_name, None);
        assert_eq!(identity.address2, None);
        assert_eq!(identity.address3, None);
        assert_eq!(identity.company, None);
        assert_eq!(identity.email, None);
        assert_eq!(identity.ssn, None);
        assert_eq!(identity.username, None);
        assert_eq!(identity.passport_number, None);
        assert_eq!(identity.license_number, None);
    }

    #[test]
    fn test_address_to_identity_minimal() {
        let address = create_address_credential(Some("456 Oak St"), None, None, None, None, None);

        let identity = address_to_identity(&address);

        assert_eq!(identity.address1, Some("456 Oak St".to_string()));
        assert_eq!(identity.city, None);
        assert_eq!(identity.state, None);
        assert_eq!(identity.country, None);
        assert_eq!(identity.phone, None);
        assert_eq!(identity.postal_code, None);
    }

    #[test]
    fn test_address_to_identity_empty() {
        let address = create_address_credential(None, None, None, None, None, None);

        let identity = address_to_identity(&address);

        assert_eq!(identity.address1, None);
        assert_eq!(identity.city, None);
        assert_eq!(identity.state, None);
        assert_eq!(identity.country, None);
        assert_eq!(identity.phone, None);
        assert_eq!(identity.postal_code, None);
    }

    #[test]
    fn test_address_to_identity_partial() {
        let address = create_address_credential(
            Some("789 Pine Ave"),
            Some("Portland"),
            Some("OR"),
            None,
            Some("555-0123"),
            None,
        );

        let identity = address_to_identity(&address);

        assert_eq!(identity.address1, Some("789 Pine Ave".to_string()));
        assert_eq!(identity.city, Some("Portland".to_string()));
        assert_eq!(identity.state, Some("OR".to_string()));
        assert_eq!(identity.country, None);
        assert_eq!(identity.phone, Some("555-0123".to_string()));
        assert_eq!(identity.postal_code, None);
    }
}
