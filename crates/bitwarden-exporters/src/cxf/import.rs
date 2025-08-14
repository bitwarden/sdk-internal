use chrono::{DateTime, Utc};
use credential_exchange_format::{
    Account as CxfAccount, ApiKeyCredential, BasicAuthCredential, Credential, CreditCardCredential,
    Item, PasskeyCredential, TotpCredential, WifiCredential,
};

use crate::{
    cxf::{
        api_key::api_key_to_fields,
        login::{to_fields, to_login},
        wifi::wifi_to_fields,
        CxfError,
    },
    CipherType, ImportingCipher, SecureNote, SecureNoteType,
};

/**
 * Parse CXF payload in the format compatible with Apple (At the Account-level)
 */
pub(crate) fn parse_cxf(payload: String) -> Result<Vec<ImportingCipher>, CxfError> {
    let account: CxfAccount = serde_json::from_str(&payload)?;

    let items: Vec<ImportingCipher> = account.items.into_iter().flat_map(parse_item).collect();

    Ok(items)
}

/**
 * Parse CXF payload in the format compatible with the CXF specification (At the
 * Header-level).
 */
#[allow(dead_code)]
pub(crate) fn parse_cxf_spec(payload: String) -> Result<Vec<ImportingCipher>, CxfError> {
    use credential_exchange_format::Header;

    let header: Header = serde_json::from_str(&payload)?;

    let items: Vec<ImportingCipher> = header
        .accounts
        .into_iter()
        .flat_map(|account| account.items.into_iter().flat_map(parse_item))
        .collect();

    Ok(items)
}

/// Convert a CXF timestamp to a [`DateTime<Utc>`].
///
/// If the timestamp is None, the current time is used.
fn convert_date(ts: Option<u64>) -> DateTime<Utc> {
    ts.and_then(|ts| DateTime::from_timestamp(ts as i64, 0))
        .unwrap_or(Utc::now())
}

fn parse_item(value: Item) -> Vec<ImportingCipher> {
    let grouped = group_credentials_by_type(value.credentials);

    let creation_date = convert_date(value.creation_at);
    let revision_date = convert_date(value.modified_at);

    let mut output = vec![];

    let scope = value.scope.as_ref();

    // Login credentials (including TOTP)
    if !grouped.basic_auth.is_empty() || !grouped.passkey.is_empty() || !grouped.totp.is_empty() {
        let basic_auth = grouped.basic_auth.first();
        let passkey = grouped.passkey.first();
        let totp = grouped.totp.first();

        let login = to_login(creation_date, basic_auth, passkey, totp, scope);

        output.push(ImportingCipher {
            folder_id: None, // TODO: Handle folders
            name: value.title.clone(),
            notes: None,
            r#type: CipherType::Login(Box::new(login)),
            favorite: false,
            reprompt: 0,
            fields: vec![],
            revision_date,
            creation_date,
            deleted_date: None,
        })
    }

    if !grouped.credit_card.is_empty() {
        let credit_card = grouped
            .credit_card
            .first()
            .expect("Credit card is not empty");

        output.push(ImportingCipher {
            folder_id: None, // TODO: Handle folders
            name: value.title.clone(),
            notes: None,
            r#type: CipherType::Card(Box::new(credit_card.into())),
            favorite: false,
            reprompt: 0,
            fields: scope.map(to_fields).unwrap_or_default(),
            revision_date,
            creation_date,
            deleted_date: None,
        })
    }

    // API Key credentials -> Secure Note
    if let Some(api_key) = grouped.api_key.first() {
        let fields = api_key_to_fields(api_key);

        output.push(ImportingCipher {
            folder_id: None, // TODO: Handle folders
            name: value.title.clone(),
            notes: None,
            r#type: CipherType::SecureNote(Box::new(SecureNote {
                r#type: SecureNoteType::Generic,
            })),
            favorite: false,
            reprompt: 0,
            fields,
            revision_date,
            creation_date,
            deleted_date: None,
        })
    }

    // WiFi credentials -> Secure Note
    if let Some(wifi) = grouped.wifi.first() {
        let fields = wifi_to_fields(wifi);

        output.push(ImportingCipher {
            folder_id: None, // TODO: Handle folders
            name: value.title.clone(),
            notes: None,
            r#type: CipherType::SecureNote(Box::new(SecureNote {
                r#type: SecureNoteType::Generic,
            })),
            favorite: false,
            reprompt: 0,
            fields,
            revision_date,
            creation_date,
            deleted_date: None,
        })
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
    }
}

struct GroupedCredentials {
    api_key: Vec<ApiKeyCredential>,
    basic_auth: Vec<BasicAuthCredential>,
    passkey: Vec<PasskeyCredential>,
    credit_card: Vec<CreditCardCredential>,
    totp: Vec<TotpCredential>,
    wifi: Vec<WifiCredential>,
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use chrono::{Duration, Month};
    use credential_exchange_format::{CreditCardCredential, EditableFieldYearMonth};

    use super::*;

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
    fn test_totp_with_custom_parameters() {
        use credential_exchange_format::{OTPHashAlgorithm, TotpCredential};

        let item = Item {
            id: [0, 1, 2, 3, 4, 5, 6].as_ref().into(),
            creation_at: Some(1706613834),
            modified_at: Some(1706623773),
            title: "Custom TOTP".to_string(),
            subtitle: None,
            favorite: None,
            credentials: vec![Credential::Totp(Box::new(TotpCredential {
                secret: "secret123".as_bytes().to_vec().into(),
                period: 60,
                digits: 8,
                username: Some("user".to_string()),
                algorithm: OTPHashAlgorithm::Sha256,
                issuer: None,
            }))],
            tags: None,
            extensions: None,
            scope: None,
        };

        let ciphers: Vec<ImportingCipher> = parse_item(item);
        assert_eq!(ciphers.len(), 1);
        let cipher = ciphers.first().unwrap();

        let login = match &cipher.r#type {
            CipherType::Login(login) => login,
            _ => panic!("Expected login cipher for TOTP"),
        };

        let otpauth = login.totp.as_ref().unwrap();

        // Should have custom parameters
        assert!(otpauth.contains("&period=60"));
        assert!(otpauth.contains("&digits=8"));
        assert!(otpauth.contains("&algorithm=SHA256"));

        // Should not have issuer parameter since issuer is None
        assert!(!otpauth.contains("&issuer="));

        // Should have label with just username
        assert!(otpauth.starts_with("otpauth://totp/user?secret="));
    }

    #[test]
    fn test_totp_steam() {
        use credential_exchange_format::{OTPHashAlgorithm, TotpCredential};

        let item = Item {
            id: [0, 1, 2, 3, 4, 5, 6].as_ref().into(),
            creation_at: Some(1706613834),
            modified_at: Some(1706623773),
            title: "Steam TOTP".to_string(),
            subtitle: None,
            favorite: None,
            credentials: vec![Credential::Totp(Box::new(TotpCredential {
                secret: "steamkey".as_bytes().to_vec().into(),
                period: 30,
                digits: 5,
                username: Some("steamuser".to_string()),
                algorithm: OTPHashAlgorithm::Unknown("steam".to_string()),
                issuer: Some("Steam".to_string()),
            }))],
            tags: None,
            extensions: None,
            scope: None,
        };

        let ciphers: Vec<ImportingCipher> = parse_item(item);
        let cipher = ciphers.first().unwrap();

        let login = match &cipher.r#type {
            CipherType::Login(login) => login,
            _ => panic!("Expected login cipher for TOTP"),
        };

        let otpauth = login.totp.as_ref().unwrap();

        // Steam should use special format
        assert!(otpauth.starts_with("steam://"));
        assert!(!otpauth.contains("otpauth://"));
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
}
