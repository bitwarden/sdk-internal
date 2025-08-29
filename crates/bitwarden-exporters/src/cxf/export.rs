use bitwarden_vault::{Totp, TotpAlgorithm};
use credential_exchange_format::{
    Account as CxfAccount, AddressCredential, Credential, DriversLicenseCredential,
    IdentityDocumentCredential, Item, NoteCredential, OTPHashAlgorithm, PassportCredential,
    PersonNameCredential, TotpCredential,
};
use uuid::Uuid;
#[cfg(feature = "wasm")]
use {tsify::Tsify, wasm_bindgen::prelude::*};

use crate::{cxf::CxfError, Cipher, CipherType, Identity, Login};

/// Temporary struct to hold metadata related to current account
///
/// Eventually the SDK itself should have this state and we get rid of this struct.
#[derive(Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(serde::Serialize, serde::Deserialize, Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub struct Account {
    id: Uuid,
    email: String,
    name: Option<String>,
}

/// Builds a Credential Exchange Format (CXF) payload
pub(crate) fn build_cxf(account: Account, ciphers: Vec<Cipher>) -> Result<String, CxfError> {
    let items: Vec<Item> = ciphers
        .into_iter()
        .flat_map(|cipher| cipher.try_into())
        .collect();

    let account = CxfAccount {
        id: account.id.as_bytes().as_slice().into(),
        username: "".to_owned(),
        email: account.email,
        full_name: account.name,
        collections: vec![], // TODO: Add support for folders
        items,
        extensions: None,
    };

    Ok(serde_json::to_string(&account)?)
}

impl TryFrom<Cipher> for Item {
    type Error = CxfError;

    fn try_from(value: Cipher) -> Result<Self, Self::Error> {
        let mut credentials: Vec<Credential> = value.r#type.clone().into();

        if let Some(note) = value.notes {
            credentials.push(Credential::Note(Box::new(NoteCredential {
                content: note.into(),
            })));
        }

        Ok(Self {
            id: value.id.as_bytes().as_slice().into(),
            creation_at: Some(value.creation_date.timestamp() as u64),
            modified_at: Some(value.revision_date.timestamp() as u64),
            title: value.name,
            subtitle: None,
            favorite: Some(value.favorite),
            credentials,
            tags: None,
            extensions: None,
            scope: match value.r#type {
                CipherType::Login(login) => Some((*login).into()),
                _ => None,
            },
        })
    }
}

impl From<CipherType> for Vec<Credential> {
    fn from(value: CipherType) -> Self {
        match value {
            CipherType::Login(login) => (*login).into(),
            CipherType::Card(card) => (*card).into(),
            CipherType::Identity(identity) => (*identity).into(),
            // Secure Notes only contains a note field which is handled by `TryFrom<Cipher> for
            // Item`.
            CipherType::SecureNote(_) => vec![],
            // TODO(PM-15448): Add support for SSH Keys.
            CipherType::SshKey(_) => vec![],
        }
    }
}

/// Convert a `Login` struct into the appropriate `Credential`s.
impl From<Login> for Vec<Credential> {
    fn from(login: Login) -> Self {
        let mut credentials = vec![];

        if login.username.is_some() || login.password.is_some() || !login.login_uris.is_empty() {
            credentials.push(Credential::BasicAuth(Box::new(login.clone().into())));
        }

        if let Some(totp) = login.totp.and_then(|t| t.parse::<Totp>().ok()) {
            credentials.push(Credential::Totp(Box::new(convert_totp(totp))));
        }

        if let Some(fido2_credentials) = login.fido2_credentials {
            credentials.extend(
                fido2_credentials
                    .into_iter()
                    .filter_map(|fido2_credential| fido2_credential.try_into().ok())
                    .map(|c| Credential::Passkey(Box::new(c))),
            );
        }

        credentials
    }
}

/// Convert a `Totp` struct into a `TotpCredential` struct
fn convert_totp(totp: Totp) -> TotpCredential {
    // TODO(PM-15389): Properly set username/issuer.
    TotpCredential {
        secret: totp.secret.into(),
        period: totp.period as u8,
        digits: totp.digits as u8,
        username: totp.account,
        algorithm: match totp.algorithm {
            TotpAlgorithm::Sha1 => OTPHashAlgorithm::Sha1,
            TotpAlgorithm::Sha256 => OTPHashAlgorithm::Sha256,
            TotpAlgorithm::Sha512 => OTPHashAlgorithm::Sha512,
            TotpAlgorithm::Steam => OTPHashAlgorithm::Unknown("steam".to_string()),
        },
        issuer: totp.issuer,
    }
}

impl From<Identity> for Vec<Credential> {
    fn from(identity: Identity) -> Self {
        let mut credentials = vec![];

        // Store combined name for reuse
        let combined_full_name = combine_name(
            &identity.first_name,
            &identity.middle_name,
            &identity.last_name,
        );

        // Always create PersonName credential for name fields
        let person_name = PersonNameCredential {
            title: identity.title.clone().map(|v| v.into()),
            given: identity.first_name.clone().map(|v| v.into()),
            given_informal: None,
            given2: identity.middle_name.clone().map(|v| v.into()),
            surname_prefix: None,
            surname: identity.last_name.clone().map(|v| v.into()),
            surname2: None,
            credentials: identity.company.clone().map(|v| v.into()),
            generation: None,
        };

        credentials.push(Credential::PersonName(Box::new(person_name)));

        // Create Address credential if any address fields are present
        if identity.address1.is_some()
            || identity.city.is_some()
            || identity.state.is_some()
            || identity.country.is_some()
            || identity.phone.is_some()
            || identity.postal_code.is_some()
        {
            let address = AddressCredential {
                street_address: identity.address1.clone().map(|v| v.into()),
                city: identity.city.clone().map(|v| v.into()),
                territory: identity.state.clone().map(|v| v.into()),
                country: identity.country.clone().map(|v| v.into()),
                tel: identity.phone.clone().map(|v| v.into()),
                postal_code: identity.postal_code.clone().map(|v| v.into()),
            };

            credentials.push(Credential::Address(Box::new(address)));
        }

        // Create Passport credential if passport number is present
        if let Some(ref passport_number) = identity.passport_number {
            let passport = PassportCredential {
                issuing_country: identity.country.clone().map(|v| v.into()),
                nationality: None,
                full_name: combined_full_name.clone().map(|v| v.into()),
                birth_date: None,
                birth_place: None,
                sex: None,
                issue_date: None,
                expiry_date: None,
                issuing_authority: None,
                passport_type: None,
                passport_number: Some(passport_number.clone().into()),
                national_identification_number: identity.ssn.clone().map(|v| v.into()),
            };

            credentials.push(Credential::Passport(Box::new(passport)));
        }

        // Create DriversLicense credential if license number is present
        if let Some(ref license_number) = identity.license_number {
            let drivers_license = DriversLicenseCredential {
                full_name: combined_full_name.clone().map(|v| v.into()),
                birth_date: None,
                issue_date: None,
                expiry_date: None,
                issuing_authority: None,
                territory: identity.state.clone().map(|v| v.into()),
                country: identity.country.clone().map(|v| v.into()),
                license_number: Some(license_number.clone().into()),
                license_class: None,
            };

            credentials.push(Credential::DriversLicense(Box::new(drivers_license)));
        }

        // Create IdentityDocument credential if SSN is present but no passport or license number
        if identity.ssn.is_some()
            && identity.passport_number.is_none()
            && identity.license_number.is_none()
        {
            let identity_document = IdentityDocumentCredential {
                issuing_country: identity.country.clone().map(|v| v.into()),
                document_number: None,
                identification_number: identity.ssn.clone().map(|v| v.into()),
                nationality: None,
                full_name: combined_full_name.map(|v| v.into()),
                birth_date: None,
                birth_place: None,
                sex: None,
                issue_date: None,
                expiry_date: None,
                issuing_authority: None,
            };

            credentials.push(Credential::IdentityDocument(Box::new(identity_document)));
        }

        credentials
    }
}

fn combine_name(
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

    use super::*;
    use crate::{Fido2Credential, Field, Identity, LoginUri};

    #[test]
    fn test_convert_totp() {
        let totp = Totp {
            account: Some("test-account@example.com".to_string()),
            algorithm: TotpAlgorithm::Sha1,
            digits: 4,
            issuer: Some("test-issuer".to_string()),
            period: 60,
            secret: "secret".as_bytes().to_vec(),
        };

        let credential = convert_totp(totp);
        assert_eq!(String::from(credential.secret), "ONSWG4TFOQ");
        assert_eq!(credential.period, 60);
        assert_eq!(credential.digits, 4);
        assert_eq!(credential.username.unwrap(), "test-account@example.com");
        assert_eq!(credential.algorithm, OTPHashAlgorithm::Sha1);
        assert_eq!(credential.issuer, Some("test-issuer".to_string()));
    }

    #[test]
    fn test_login_to_item() {
        let cipher = Cipher {
            id: "25c8c414-b446-48e9-a1bd-b10700bbd740".parse().unwrap(),
            folder_id: Some("942e2984-1b9a-453b-b039-b107012713b9".parse().unwrap()),

            name: "Bitwarden".to_string(),
            notes: Some("My note".to_string()),

            r#type: CipherType::Login(Box::new(Login {
                username: Some("test@bitwarden.com".to_string()),
                password: Some("asdfasdfasdf".to_string()),
                login_uris: vec![LoginUri {
                    uri: Some("https://vault.bitwarden.com".to_string()),
                    r#match: None,
                }],
                totp: Some("JBSWY3DPEHPK3PXP".to_string()),
                fido2_credentials: Some(vec![Fido2Credential {
                    credential_id: "e8d88789-e916-e196-3cbd-81dafae71bbc".to_string(),
                    key_type: "public-key".to_string(),
                    key_algorithm: "ECDSA".to_string(),
                    key_curve: "P-256".to_string(),
                    key_value: "AAECAwQFBg".to_string(),
                    rp_id: "123".to_string(),
                    user_handle: Some("AAECAwQFBg".to_string()),
                    user_name: None,
                    counter: 0,
                    rp_name: None,
                    user_display_name: None,
                    discoverable: "true".to_string(),
                    creation_date: "2024-06-07T14:12:36.150Z".parse().unwrap(),
                }]),
            })),

            favorite: true,
            reprompt: 0,

            fields: vec![
                Field {
                    name: Some("Text".to_string()),
                    value: Some("A".to_string()),
                    r#type: 0,
                    linked_id: None,
                },
                Field {
                    name: Some("Hidden".to_string()),
                    value: Some("B".to_string()),
                    r#type: 1,
                    linked_id: None,
                },
                Field {
                    name: Some("Boolean (true)".to_string()),
                    value: Some("true".to_string()),
                    r#type: 2,
                    linked_id: None,
                },
                Field {
                    name: Some("Boolean (false)".to_string()),
                    value: Some("false".to_string()),
                    r#type: 2,
                    linked_id: None,
                },
                Field {
                    name: Some("Linked".to_string()),
                    value: None,
                    r#type: 3,
                    linked_id: Some(101),
                },
            ],

            revision_date: "2024-01-30T14:09:33.753Z".parse().unwrap(),
            creation_date: "2024-01-30T11:23:54.416Z".parse().unwrap(),
            deleted_date: None,
        };

        let item: Item = cipher.try_into().unwrap();

        assert_eq!(item.id.to_string(), "JcjEFLRGSOmhvbEHALvXQA");
        assert_eq!(item.creation_at, Some(1706613834));
        assert_eq!(item.modified_at, Some(1706623773));
        assert_eq!(item.title, "Bitwarden");
        assert_eq!(item.subtitle, None);
        assert_eq!(item.tags, None);
        assert_eq!(
            item.scope.unwrap().urls,
            vec!["https://vault.bitwarden.com".to_string()]
        );
        assert!(item.extensions.is_none());

        assert_eq!(item.credentials.len(), 4);

        let credential = &item.credentials[0];

        match credential {
            Credential::BasicAuth(basic_auth) => {
                let username = basic_auth.username.as_ref().unwrap();
                assert_eq!(username.value.0, "test@bitwarden.com");
                assert!(username.label.is_none());

                let password = basic_auth.password.as_ref().unwrap();
                assert_eq!(password.value.0, "asdfasdfasdf");
                assert!(password.label.is_none());
            }
            _ => panic!("Expected Credential::BasicAuth"),
        }

        let credential = &item.credentials[1];

        match credential {
            Credential::Totp(totp) => {
                assert_eq!(String::from(totp.secret.clone()), "JBSWY3DPEHPK3PXP");
                assert_eq!(totp.period, 30);
                assert_eq!(totp.digits, 6);
                assert_eq!(totp.username, None);
                assert_eq!(totp.algorithm, OTPHashAlgorithm::Sha1);
                assert!(totp.issuer.is_none());
            }
            _ => panic!("Expected Credential::Passkey"),
        }

        let credential = &item.credentials[2];

        match credential {
            Credential::Passkey(passkey) => {
                assert_eq!(passkey.credential_id.to_string(), "6NiHiekW4ZY8vYHa-ucbvA");
                assert_eq!(passkey.rp_id, "123");
                assert_eq!(passkey.username, "");
                assert_eq!(passkey.user_display_name, "");
                assert_eq!(String::from(passkey.user_handle.clone()), "AAECAwQFBg");
                assert_eq!(String::from(passkey.key.clone()), "AAECAwQFBg");
                assert!(passkey.fido2_extensions.is_none());
            }
            _ => panic!("Expected Credential::Passkey"),
        }

        let credential = &item.credentials[3];

        match credential {
            Credential::Note(n) => {
                assert_eq!(n.content.value.0, "My note");
            }
            _ => panic!("Expected Credential::Passkey"),
        }
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

        // Should create PersonName, Address, Passport, and DriversLicense credentials
        assert_eq!(credentials.len(), 4);

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
                "123 Main St"
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
