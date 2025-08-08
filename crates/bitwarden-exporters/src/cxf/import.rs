use chrono::{DateTime, Utc};
use credential_exchange_format::{
    Account as CxfAccount, ApiKeyCredential, BasicAuthCredential, Credential, CreditCardCredential,
    Item, PasskeyCredential, WifiCredential,
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

fn parse_item(value: Item) -> Vec<ImportingCipher> {
    let grouped = group_credentials_by_type(value.credentials);

    let creation_date = convert_date(value.creation_at);
    let revision_date = convert_date(value.modified_at);

    let mut output = vec![];

    let scope = value.scope.as_ref();

    // Login credentials
    if !grouped.basic_auth.is_empty() || !grouped.passkey.is_empty() {
        let basic_auth = grouped.basic_auth.first();
        let passkey = grouped.passkey.first();

        let login = to_login(creation_date, basic_auth, passkey, scope);

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
    wifi: Vec<WifiCredential>,
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use chrono::{Duration, Month};
    use credential_exchange_format::{CreditCardCredential, EditableFieldYearMonth};

    use super::*;

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
}
