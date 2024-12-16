use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use credential_exchange_types::format::{
    Account as CxpAccount, BasicAuthCredential, Credential, Item, ItemType, PasskeyCredential,
};

use crate::{cxp::CxpError, CipherType, Fido2Credential, ImportingCipher, Login, LoginUri};

pub(crate) fn parse_cxf(payload: String) -> Result<Vec<ImportingCipher>, CxpError> {
    let account: CxpAccount = serde_json::from_str(&payload)?;

    let items: Vec<ImportingCipher> = account.items.into_iter().flat_map(parse_item).collect();

    Ok(items)
}

/// Convert a CXP timestamp to a DateTime<Utc>.
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

    match value.ty {
        ItemType::Login => {
            let basic_auth = grouped.basic_auth.first();
            let passkey = grouped.passkey.first();

            let login = Login {
                username: basic_auth.and_then(|v| v.username.as_ref().map(|u| u.value.clone())),
                password: basic_auth.and_then(|v| v.password.as_ref().map(|u| u.value.clone())),
                login_uris: basic_auth
                    .map(|v| {
                        v.urls
                            .iter()
                            .map(|u| LoginUri {
                                uri: Some(u.clone()),
                                r#match: None,
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
                totp: None,
                fido2_credentials: passkey.map(|p| {
                    vec![Fido2Credential {
                        credential_id: format!("b64.{}", p.credential_id),
                        key_type: "public-key".to_string(),
                        key_algorithm: "ECDSA".to_string(),
                        key_curve: "P-256".to_string(),
                        key_value: URL_SAFE_NO_PAD.encode(&p.key),
                        rp_id: p.rp_id.clone(),
                        user_handle: Some(p.user_handle.to_string()),
                        user_name: Some(p.user_name.clone()),
                        counter: 0,
                        rp_name: Some(p.rp_id.clone()),
                        user_display_name: Some(p.user_display_name.clone()),
                        discoverable: "true".to_string(),
                        creation_date,
                    }]
                }),
            };

            vec![ImportingCipher {
                folder_id: None, // TODO: Handle folders
                name: value.title,
                notes: None,
                r#type: CipherType::Login(Box::new(login)),
                favorite: false,
                reprompt: 0,
                fields: vec![],
                revision_date,
                creation_date,
                deleted_date: None,
            }]
        }
        _ => vec![],
    }
}

/// Group credentials by type.
///
/// The Credential Exchange protocol allows multiple identical credentials to be stored in a single
/// item. Currently we only support one of each type and grouping allows an easy way to fetch the
/// first of each type. Eventually we should add support for handling multiple credentials of the
/// same type.
fn group_credentials_by_type(credentials: Vec<Credential>) -> GroupedCredentials {
    GroupedCredentials {
        basic_auth: credentials
            .iter()
            .filter_map(|c| match c {
                Credential::BasicAuth(basic_auth) => Some(*basic_auth.clone()),
                _ => None,
            })
            .collect(),
        passkey: credentials
            .iter()
            .filter_map(|c| match c {
                Credential::Passkey(passkey) => Some(*passkey.clone()),
                _ => None,
            })
            .collect(),
    }
}

struct GroupedCredentials {
    basic_auth: Vec<BasicAuthCredential>,
    passkey: Vec<PasskeyCredential>,
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

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
    fn test_parse_item() {
        let item = Item {
            id: [0, 1, 2, 3, 4, 5, 6].as_ref().into(),
            creation_at: Some(1706613834),
            modified_at: Some(1706623773),
            ty: ItemType::Login,
            title: "Bitwarden".to_string(),
            subtitle: None,
            favorite: None,
            credentials: vec![],
            tags: None,
            extensions: None,
        };

        let ciphers: Vec<ImportingCipher> = parse_item(item);
        assert_eq!(ciphers.len(), 1);
        let cipher = ciphers.first().unwrap();

        assert_eq!(cipher.folder_id, None);
        assert_eq!(cipher.name, "Bitwarden");
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
            ty: ItemType::Login,
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
                user_name: "alex muller".to_string(),
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
}
