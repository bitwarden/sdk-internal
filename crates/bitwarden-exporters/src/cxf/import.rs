use chrono::{DateTime, Utc};
use credential_exchange_format::{
    Account as CxfAccount, AddressCredential, ApiKeyCredential, BasicAuthCredential, Credential,
    CreditCardCredential, DriversLicenseCredential, IdentityDocumentCredential, Item,
    NoteCredential, PasskeyCredential, PassportCredential, PersonNameCredential, TotpCredential,
    WifiCredential,
};

use crate::{
    cxf::{
        api_key::api_key_to_fields,
        card::to_card,
        identity::{
            address_to_identity, drivers_license_to_identity, identity_document_to_identity,
            passport_to_identity, person_name_to_identity,
        },
        login::to_login,
        note::extract_note_content,
        wifi::wifi_to_fields,
        CxfError,
    },
    CipherType, Field, ImportingCipher, SecureNote, SecureNoteType,
};

/**
 * Parse CXF payload in the format compatible with Apple (At the Account-level)
 */
pub(crate) fn parse_cxf(payload: String) -> Result<Vec<ImportingCipher>, CxfError> {
    let account: CxfAccount = serde_json::from_str(&payload)?;

    let items: Vec<ImportingCipher> = account.items.into_iter().flat_map(parse_item).collect();

    Ok(items)
}

/// Convert a CXF timestamp to a [`DateTime<Utc>`].
///
/// If the timestamp is None, the current time is used.
fn convert_date(ts: Option<u64>) -> DateTime<Utc> {
    ts.and_then(|ts| DateTime::from_timestamp(ts as i64, 0))
        .unwrap_or(Utc::now())
}

pub(super) fn parse_item(value: Item) -> Vec<ImportingCipher> {
    let grouped = group_credentials_by_type(value.credentials);

    let creation_date = convert_date(value.creation_at);
    let revision_date = convert_date(value.modified_at);

    let mut output = vec![];

    let scope = value.scope.as_ref();

    // Extract note content if present (to be added to parent cipher)
    let note_content = grouped.note.first().map(extract_note_content);

    // Helper to add ciphers with consistent boilerplate
    let mut add_item = |t: CipherType, fields: Vec<Field>| {
        output.push(ImportingCipher {
            folder_id: None, // TODO: Handle folders
            name: value.title.clone(),
            notes: note_content.clone(),
            r#type: t,
            favorite: false,
            reprompt: 0,
            fields,
            revision_date,
            creation_date,
            deleted_date: None,
        })
    };

    // Login credentials
    if !grouped.basic_auth.is_empty() || !grouped.passkey.is_empty() || !grouped.totp.is_empty() {
        let basic_auth = grouped.basic_auth.first();
        let passkey = grouped.passkey.first();
        let totp = grouped.totp.first();

        let login = to_login(creation_date, basic_auth, passkey, totp, scope);
        add_item(CipherType::Login(Box::new(login)), vec![]);
    }

    // Credit Card credentials
    if let Some(credit_card) = grouped.credit_card.first() {
        let (card, fields) = to_card(credit_card);

        add_item(CipherType::Card(Box::new(card)), fields);
    }

    // Helper for creating SecureNote cipher type
    let secure_note_type = || {
        CipherType::SecureNote(Box::new(SecureNote {
            r#type: SecureNoteType::Generic,
        }))
    };

    // API Key credentials -> Secure Note
    if let Some(api_key) = grouped.api_key.first() {
        let fields = api_key_to_fields(api_key);
        add_item(secure_note_type(), fields);
    }

    // WiFi credentials -> Secure Note
    if let Some(wifi) = grouped.wifi.first() {
        let fields = wifi_to_fields(wifi);
        add_item(secure_note_type(), fields);
    }

    // Identity credentials (address, passport, person name, drivers license, identity document)
    [
        grouped.address.first().map(address_to_identity),
        grouped.passport.first().map(passport_to_identity),
        grouped.person_name.first().map(person_name_to_identity),
        grouped
            .drivers_license
            .first()
            .map(drivers_license_to_identity),
        grouped
            .identity_document
            .first()
            .map(identity_document_to_identity),
    ]
    .into_iter()
    .flatten()
    .for_each(|(identity, custom_fields)| {
        add_item(CipherType::Identity(Box::new(identity)), custom_fields);
    });

    // Standalone Note credentials -> Secure Note (only if no other credentials exist)
    if !grouped.note.is_empty() && output.is_empty() {
        let standalone_note_content = grouped.note.first().map(extract_note_content);
        output.push(ImportingCipher {
            folder_id: None, // TODO: Handle folders
            name: value.title.clone(),
            notes: standalone_note_content,
            r#type: secure_note_type(),
            favorite: false,
            reprompt: 0,
            fields: vec![],
            revision_date,
            creation_date,
            deleted_date: None,
        });
    }

    output
}

/// Group credentials by type.
///
/// The Credential Exchange protocol allows multiple identical credentials to be stored in a single
/// item. Currently we only support one of each type and grouping allows an easy way to fetch the
/// first of each type. Eventually we should add support for handling multiple credentials of the
/// same type.
fn group_credentials_by_type(credentials: Vec<Credential>) -> GroupedCredentials {
    fn filter_credentials<T>(
        credentials: &[Credential],
        f: impl Fn(&Credential) -> Option<&T>,
    ) -> Vec<T>
    where
        T: Clone,
    {
        credentials.iter().filter_map(f).cloned().collect()
    }

    GroupedCredentials {
        api_key: filter_credentials(&credentials, |c| match c {
            Credential::ApiKey(api_key) => Some(api_key.as_ref()),
            _ => None,
        }),
        basic_auth: filter_credentials(&credentials, |c| match c {
            Credential::BasicAuth(basic_auth) => Some(basic_auth.as_ref()),
            _ => None,
        }),
        passkey: filter_credentials(&credentials, |c| match c {
            Credential::Passkey(passkey) => Some(passkey.as_ref()),
            _ => None,
        }),
        credit_card: filter_credentials(&credentials, |c| match c {
            Credential::CreditCard(credit_card) => Some(credit_card.as_ref()),
            _ => None,
        }),
        totp: filter_credentials(&credentials, |c| match c {
            Credential::Totp(totp) => Some(totp.as_ref()),
            _ => None,
        }),
        wifi: filter_credentials(&credentials, |c| match c {
            Credential::Wifi(wifi) => Some(wifi.as_ref()),
            _ => None,
        }),
        address: filter_credentials(&credentials, |c| match c {
            Credential::Address(address) => Some(address.as_ref()),
            _ => None,
        }),
        passport: filter_credentials(&credentials, |c| match c {
            Credential::Passport(passport) => Some(passport.as_ref()),
            _ => None,
        }),
        person_name: filter_credentials(&credentials, |c| match c {
            Credential::PersonName(person_name) => Some(person_name.as_ref()),
            _ => None,
        }),
        drivers_license: filter_credentials(&credentials, |c| match c {
            Credential::DriversLicense(drivers_license) => Some(drivers_license.as_ref()),
            _ => None,
        }),
        identity_document: filter_credentials(&credentials, |c| match c {
            Credential::IdentityDocument(identity_document) => Some(identity_document.as_ref()),
            _ => None,
        }),
        note: filter_credentials(&credentials, |c| match c {
            Credential::Note(note) => Some(note.as_ref()),
            _ => None,
        }),
    }
}

struct GroupedCredentials {
    api_key: Vec<ApiKeyCredential>,
    basic_auth: Vec<BasicAuthCredential>,
    passkey: Vec<PasskeyCredential>,
    credit_card: Vec<CreditCardCredential>,
    totp: Vec<TotpCredential>,
    wifi: Vec<WifiCredential>,
    address: Vec<AddressCredential>,
    passport: Vec<PassportCredential>,
    person_name: Vec<PersonNameCredential>,
    drivers_license: Vec<DriversLicenseCredential>,
    identity_document: Vec<IdentityDocumentCredential>,
    note: Vec<NoteCredential>,
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use chrono::{Duration, Month};
    use credential_exchange_format::{CreditCardCredential, EditableFieldYearMonth};

    use super::*;

    /**
     * Parse CXF payload in the format compatible with the CXF specification (At the
     * Header-level).
     */
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

    #[test]
    fn test_load_cxf_example_without_crashing() {
        let result = load_sample_cxf();
        assert!(result.is_ok());
    }

    #[test]
    fn test_convert_date() {
        let timestamp: u64 = 1706613834;
        let datetime = convert_date(Some(timestamp));
        assert_eq!(
            datetime,
            "2024-01-30T11:23:54Z".parse::<DateTime<Utc>>().unwrap()
        );
    }

    #[test]
    fn test_convert_date_none() {
        let datetime = convert_date(None);
        assert!(datetime > Utc::now() - Duration::seconds(1));
        assert!(datetime <= Utc::now());
    }

    #[test]
    fn test_parse_empty_item() {
        let item = Item {
            id: [0, 1, 2, 3, 4, 5, 6].as_ref().into(),
            creation_at: Some(1706613834),
            modified_at: Some(1706623773),
            title: "Bitwarden".to_string(),
            subtitle: None,
            favorite: None,
            credentials: vec![],
            tags: None,
            extensions: None,
            scope: None,
        };

        let ciphers: Vec<ImportingCipher> = parse_item(item);
        assert_eq!(ciphers.len(), 0);
    }

    #[test]
    fn test_parse_passkey() {
        let item = Item {
            id: URL_SAFE_NO_PAD
                .decode("Njk1RERENTItNkQ0Ny00NERBLTlFN0EtNDM1MjNEQjYzNjVF")
                .unwrap()
                .as_slice()
                .into(),
            creation_at: Some(1732181986),
            modified_at: Some(1732182026),
            title: "opotonniee.github.io".to_string(),
            subtitle: None,
            favorite: None,
            credentials: vec![Credential::Passkey(Box::new(PasskeyCredential {
                credential_id: URL_SAFE_NO_PAD
                    .decode("6NiHiekW4ZY8vYHa-ucbvA")
                    .unwrap()
                    .as_slice()
                    .into(),
                rp_id: "opotonniee.github.io".to_string(),
                username: "alex muller".to_string(),
                user_display_name: "alex muller".to_string(),
                user_handle: URL_SAFE_NO_PAD
                    .decode("YWxleCBtdWxsZXI")
                    .unwrap()
                    .as_slice()
                    .into(),
                key: URL_SAFE_NO_PAD
                    .decode("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgPzvtWYWmIsvqqr3LsZB0K-cbjuhJSGTGziL1LksHAPShRANCAAT-vqHTyEDS9QBNNi2BNLyu6TunubJT_L3G3i7KLpEDhMD15hi24IjGBH0QylJIrvlT4JN2tdRGF436XGc-VoAl")
                    .unwrap()
                    .as_slice()
                    .into(),
                fido2_extensions: None,
            }))],
            tags: None,
            extensions: None,
            scope: None,
        };

        let ciphers: Vec<ImportingCipher> = parse_item(item);
        assert_eq!(ciphers.len(), 1);
        let cipher = ciphers.first().unwrap();

        assert_eq!(cipher.folder_id, None);
        assert_eq!(cipher.name, "opotonniee.github.io");

        let login = match &cipher.r#type {
            CipherType::Login(login) => login,
            _ => panic!("Expected login"),
        };

        assert_eq!(login.username, None);
        assert_eq!(login.password, None);
        assert_eq!(login.login_uris.len(), 0);
        assert_eq!(login.totp, None);

        let passkey = login.fido2_credentials.as_ref().unwrap().first().unwrap();
        assert_eq!(passkey.credential_id, "b64.6NiHiekW4ZY8vYHa-ucbvA");
        assert_eq!(passkey.key_type, "public-key");
        assert_eq!(passkey.key_algorithm, "ECDSA");
        assert_eq!(passkey.key_curve, "P-256");
        assert_eq!(
            passkey.key_value,
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgPzvtWYWmIsvqqr3LsZB0K-cbjuhJSGTGziL1LksHAPShRANCAAT-vqHTyEDS9QBNNi2BNLyu6TunubJT_L3G3i7KLpEDhMD15hi24IjGBH0QylJIrvlT4JN2tdRGF436XGc-VoAl"
        );
        assert_eq!(passkey.rp_id, "opotonniee.github.io");
        assert_eq!(
            passkey.user_handle.as_ref().map(|h| h.to_string()).unwrap(),
            "YWxleCBtdWxsZXI"
        );
        assert_eq!(passkey.user_name, Some("alex muller".to_string()));
        assert_eq!(passkey.counter, 0);
        assert_eq!(passkey.rp_name, Some("opotonniee.github.io".to_string()));
        assert_eq!(passkey.user_display_name, Some("alex muller".to_string()));
        assert_eq!(passkey.discoverable, "true");
        assert_eq!(
            passkey.creation_date,
            "2024-11-21T09:39:46Z".parse::<DateTime<Utc>>().unwrap()
        );
    }

    #[test]
    fn test_credit_card() {
        let item = Item {
            id: [0, 1, 2, 3, 4, 5, 6].as_ref().into(),
            creation_at: Some(1706613834),
            modified_at: Some(1706623773),
            title: "My MasterCard".to_string(),
            subtitle: None,
            favorite: None,
            credentials: vec![Credential::CreditCard(Box::new(CreditCardCredential {
                number: Some("1234 5678 9012 3456".to_string().into()),
                full_name: Some("John Doe".to_string().into()),
                card_type: Some("MasterCard".to_string().into()),
                verification_number: Some("123".to_string().into()),
                pin: None,
                expiry_date: Some(
                    EditableFieldYearMonth {
                        year: 2026,
                        month: Month::January,
                    }
                    .into(),
                ),
                valid_from: None,
            }))],
            tags: None,
            extensions: None,
            scope: None,
        };

        let ciphers: Vec<ImportingCipher> = parse_item(item);
        assert_eq!(ciphers.len(), 1);
        let cipher = ciphers.first().unwrap();

        assert_eq!(cipher.folder_id, None);
        assert_eq!(cipher.name, "My MasterCard");

        let card = match &cipher.r#type {
            CipherType::Card(card) => card,
            _ => panic!("Expected card"),
        };

        assert_eq!(card.cardholder_name, Some("John Doe".to_string()));
        assert_eq!(card.exp_month, Some("1".to_string()));
        assert_eq!(card.exp_year, Some("2026".to_string()));
        assert_eq!(card.code, Some("123".to_string()));
        assert_eq!(card.brand, Some("Mastercard".to_string()));
        assert_eq!(card.number, Some("1234 5678 9012 3456".to_string()));
    }

    #[test]
    fn test_totp() {
        use credential_exchange_format::{OTPHashAlgorithm, TotpCredential};

        let item = Item {
            id: [0, 1, 2, 3, 4, 5, 6].as_ref().into(),
            creation_at: Some(1706613834),
            modified_at: Some(1706623773),
            title: "My TOTP".to_string(),
            subtitle: None,
            favorite: None,
            credentials: vec![Credential::Totp(Box::new(TotpCredential {
                secret: "Hello World!".as_bytes().to_vec().into(),
                period: 30,
                digits: 6,
                username: Some("test@example.com".to_string()),
                algorithm: OTPHashAlgorithm::Sha1,
                issuer: Some("Example Service".to_string()),
            }))],
            tags: None,
            extensions: None,
            scope: None,
        };

        let ciphers: Vec<ImportingCipher> = parse_item(item);
        assert_eq!(ciphers.len(), 1);
        let cipher = ciphers.first().unwrap();

        assert_eq!(cipher.folder_id, None);
        assert_eq!(cipher.name, "My TOTP");
        assert_eq!(cipher.notes, None);
        assert!(!cipher.favorite);
        assert_eq!(cipher.reprompt, 0);
        assert_eq!(cipher.fields, vec![]);

        let login = match &cipher.r#type {
            CipherType::Login(login) => login,
            _ => panic!("Expected login cipher for TOTP"),
        };

        // TOTP should be mapped to login.totp as otpauth URI
        assert!(login.totp.is_some());
        let otpauth = login.totp.as_ref().unwrap();

        // Verify the otpauth URI format and content
        assert!(
            otpauth.starts_with("otpauth://totp/Example%20Service:test%40example%2Ecom?secret=")
        );
        assert!(otpauth.contains("&issuer=Example%20Service"));

        // Default values should not be present in URI
        assert!(!otpauth.contains("&period=30"));
        assert!(!otpauth.contains("&digits=6"));
        assert!(!otpauth.contains("&algorithm=SHA1"));

        // Other login fields should be None since only TOTP was provided
        assert_eq!(login.username, None);
        assert_eq!(login.password, None);
        assert_eq!(login.login_uris, vec![]);
    }

    #[test]
    fn test_totp_combined_with_basic_auth() {
        use credential_exchange_format::{BasicAuthCredential, OTPHashAlgorithm, TotpCredential};

        let item = Item {
            id: [0, 1, 2, 3, 4, 5, 6].as_ref().into(),
            creation_at: Some(1706613834),
            modified_at: Some(1706623773),
            title: "Login with TOTP".to_string(),
            subtitle: None,
            favorite: None,
            credentials: vec![
                Credential::BasicAuth(Box::new(BasicAuthCredential {
                    username: Some("myuser".to_string().into()),
                    password: Some("mypass".to_string().into()),
                })),
                Credential::Totp(Box::new(TotpCredential {
                    secret: "totpkey".as_bytes().to_vec().into(),
                    period: 30,
                    digits: 6,
                    username: Some("totpuser".to_string()),
                    algorithm: OTPHashAlgorithm::Sha1,
                    issuer: Some("Service".to_string()),
                })),
            ],
            tags: None,
            extensions: None,
            scope: None,
        };

        let ciphers: Vec<ImportingCipher> = parse_item(item);
        assert_eq!(ciphers.len(), 1);
        let cipher = ciphers.first().unwrap();

        let login = match &cipher.r#type {
            CipherType::Login(login) => login,
            _ => panic!("Expected login cipher"),
        };

        // Should have both basic auth and TOTP
        assert_eq!(login.username, Some("myuser".to_string()));
        assert_eq!(login.password, Some("mypass".to_string()));
        assert!(login.totp.is_some());

        let otpauth = login.totp.as_ref().unwrap();
        assert!(otpauth.starts_with("otpauth://totp/Service:totpuser?secret="));
        assert!(otpauth.contains("&issuer=Service"));
    }

    // Sample file integration tests - testing with cxf_example.json

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

    // Note integration tests

    #[test]
    fn test_note_as_part_of_login() {
        use credential_exchange_format::{BasicAuthCredential, Credential, Item, NoteCredential};

        let item = Item {
            id: [0, 1, 2, 3, 4, 5, 6].as_ref().into(),
            creation_at: Some(1706613834),
            modified_at: Some(1706623773),
            title: "Login with Note".to_string(),
            subtitle: None,
            favorite: None,
            credentials: vec![
                Credential::BasicAuth(Box::new(BasicAuthCredential {
                    username: Some("testuser".to_string().into()),
                    password: Some("testpass".to_string().into()),
                })),
                Credential::Note(Box::new(NoteCredential {
                    content: "This note should be added to the login cipher."
                        .to_string()
                        .into(),
                })),
            ],
            tags: None,
            extensions: None,
            scope: None,
        };

        let ciphers: Vec<ImportingCipher> = parse_item(item);
        assert_eq!(ciphers.len(), 1); // Should create only one cipher (Login with note content)
        let cipher = ciphers.first().unwrap();

        assert_eq!(cipher.name, "Login with Note");
        assert_eq!(
            cipher.notes,
            Some("This note should be added to the login cipher.".to_string())
        );

        match &cipher.r#type {
            CipherType::Login(_) => (), // Should be a Login cipher
            _ => panic!("Expected Login cipher with note content"),
        };
    }

    #[test]
    fn test_note_as_part_of_api_key() {
        use credential_exchange_format::{ApiKeyCredential, Credential, Item, NoteCredential};

        let item = Item {
            id: [0, 1, 2, 3, 4, 5, 6].as_ref().into(),
            creation_at: Some(1706613834),
            modified_at: Some(1706623773),
            title: "API Key with Note".to_string(),
            subtitle: None,
            favorite: None,
            credentials: vec![
                Credential::ApiKey(Box::new(ApiKeyCredential {
                    key: Some("api-key-12345".to_string().into()),
                    username: Some("api-user".to_string().into()),
                    key_type: Some("Bearer".to_string().into()),
                    url: None,
                    valid_from: None,
                    expiry_date: None,
                })),
                Credential::Note(Box::new(NoteCredential {
                    content: "This note should be added to the API key cipher."
                        .to_string()
                        .into(),
                })),
            ],
            tags: None,
            extensions: None,
            scope: None,
        };

        let ciphers: Vec<ImportingCipher> = parse_item(item);
        assert_eq!(ciphers.len(), 1); // Should create only one cipher (SecureNote with note content)
        let cipher = ciphers.first().unwrap();

        assert_eq!(cipher.name, "API Key with Note");
        assert_eq!(
            cipher.notes,
            Some("This note should be added to the API key cipher.".to_string())
        );

        match &cipher.r#type {
            CipherType::SecureNote(_) => (), // Should be a SecureNote cipher
            _ => panic!("Expected SecureNote cipher with note content"),
        };

        // Should have API key fields
        assert!(!cipher.fields.is_empty());
    }

    #[test]
    fn test_note_as_part_of_credit_card() {
        use chrono::Month;
        use credential_exchange_format::{Credential, CreditCardCredential, Item, NoteCredential};

        let item = Item {
            id: [0, 1, 2, 3, 4, 5, 6].as_ref().into(),
            creation_at: Some(1706613834),
            modified_at: Some(1706623773),
            title: "Credit Card with Note".to_string(),
            subtitle: None,
            favorite: None,
            credentials: vec![
                Credential::CreditCard(Box::new(CreditCardCredential {
                    number: Some("1234 5678 9012 3456".to_string().into()),
                    full_name: Some("John Doe".to_string().into()),
                    card_type: Some("Visa".to_string().into()),
                    verification_number: Some("123".to_string().into()),
                    pin: None,
                    expiry_date: Some(
                        credential_exchange_format::EditableFieldYearMonth {
                            year: 2026,
                            month: Month::December,
                        }
                        .into(),
                    ),
                    valid_from: None,
                })),
                Credential::Note(Box::new(NoteCredential {
                    content: "This note should be added to the credit card cipher."
                        .to_string()
                        .into(),
                })),
            ],
            tags: None,
            extensions: None,
            scope: None,
        };

        let ciphers: Vec<ImportingCipher> = parse_item(item);
        assert_eq!(ciphers.len(), 1); // Should create only one cipher (Card with note content)
        let cipher = ciphers.first().unwrap();

        assert_eq!(cipher.name, "Credit Card with Note");
        assert_eq!(
            cipher.notes,
            Some("This note should be added to the credit card cipher.".to_string())
        );

        match &cipher.r#type {
            CipherType::Card(_) => (), // Should be a Card cipher
            _ => panic!("Expected Card cipher with note content"),
        };
    }

    #[test]
    fn test_note_as_part_of_wifi() {
        use credential_exchange_format::{
            Credential, EditableFieldWifiNetworkSecurityType, Item, NoteCredential, WifiCredential,
        };

        let item = Item {
            id: [0, 1, 2, 3, 4, 5, 6].as_ref().into(),
            creation_at: Some(1706613834),
            modified_at: Some(1706623773),
            title: "WiFi with Note".to_string(),
            subtitle: None,
            favorite: None,
            credentials: vec![
                Credential::Wifi(Box::new(WifiCredential {
                    ssid: Some("MyNetwork".to_string().into()),
                    passphrase: Some("password123".to_string().into()),
                    network_security_type: Some(
                        EditableFieldWifiNetworkSecurityType::Wpa3Personal.into(),
                    ),
                    hidden: Some(false.into()),
                })),
                Credential::Note(Box::new(NoteCredential {
                    content: "This note should be added to the WiFi cipher."
                        .to_string()
                        .into(),
                })),
            ],
            tags: None,
            extensions: None,
            scope: None,
        };

        let ciphers: Vec<ImportingCipher> = parse_item(item);
        assert_eq!(ciphers.len(), 1); // Should create only one cipher (SecureNote with note content)
        let cipher = ciphers.first().unwrap();

        assert_eq!(cipher.name, "WiFi with Note");
        assert_eq!(
            cipher.notes,
            Some("This note should be added to the WiFi cipher.".to_string())
        );

        match &cipher.r#type {
            CipherType::SecureNote(_) => (), // Should be a SecureNote cipher
            _ => panic!("Expected SecureNote cipher with note content"),
        };

        // Should have WiFi fields
        assert!(!cipher.fields.is_empty());
    }

    #[test]
    fn test_note_as_part_of_identity() {
        use credential_exchange_format::{AddressCredential, Credential, Item, NoteCredential};

        let item = Item {
            id: [0, 1, 2, 3, 4, 5, 6].as_ref().into(),
            creation_at: Some(1706613834),
            modified_at: Some(1706623773),
            title: "Address with Note".to_string(),
            subtitle: None,
            favorite: None,
            credentials: vec![
                Credential::Address(Box::new(AddressCredential {
                    street_address: Some("123 Main St".to_string().into()),
                    city: Some("Springfield".to_string().into()),
                    territory: Some("CA".to_string().into()),
                    postal_code: Some("12345".to_string().into()),
                    country: Some("US".to_string().into()),
                    tel: Some("+1-555-123-4567".to_string().into()),
                })),
                Credential::Note(Box::new(NoteCredential {
                    content: "This note should be added to the address identity cipher."
                        .to_string()
                        .into(),
                })),
            ],
            tags: None,
            extensions: None,
            scope: None,
        };

        let ciphers: Vec<ImportingCipher> = parse_item(item);
        assert_eq!(ciphers.len(), 1); // Should create only one cipher (Identity with note content)
        let cipher = ciphers.first().unwrap();

        assert_eq!(cipher.name, "Address with Note");
        assert_eq!(
            cipher.notes,
            Some("This note should be added to the address identity cipher.".to_string())
        );

        match &cipher.r#type {
            CipherType::Identity(_) => (), // Should be an Identity cipher
            _ => panic!("Expected Identity cipher"),
        };
    }
}
