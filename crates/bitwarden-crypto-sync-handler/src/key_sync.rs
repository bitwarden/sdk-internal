//! Fills the key management state from the Key Service, as an alternative to taking it from the
//! Identity token response at login.
//!
//! ```text
//!   GET /v1/keys/own ───────┐
//!                           ├─▶ KeyServiceData ─▶ CryptoSyncData ─▶ handle_crypto_sync ─▶ state bridge
//!   GET /v1/unlock-methods ─┘
//! ```
//!
//! Only the master password unlock method is read. Key Connector, trusted device and PRF passkey
//! unlock methods are left to the existing flows.

use bitwarden_api_api::models::{
    PrivateKeysResponseModel, PublicKeyEncryptionKeyPairResponseModel, SecurityStateModel,
    SignatureKeyPairResponseModel, V2UpgradeTokenResponseModel,
};
use bitwarden_core::{
    Client,
    key_management::{
        MasterPasswordUnlockData, V2UpgradeToken, V2UpgradeTokenError,
        account_cryptographic_state::{
            AccountKeysResponseParseError, WrappedAccountCryptographicState,
        },
    },
};
use bitwarden_crypto::{EncString, Kdf, KeyId};
use bitwarden_error::bitwarden_error;
use serde::{Deserialize, de::DeserializeOwned};

use crate::{
    CryptoSyncData, CryptoSyncUserDecryption,
    crypto_sync_handler::handle_crypto_sync,
    key_service_api::{
        KeyServiceApiError, OwnKeyAttributes, Resource, UnlockMethodAttributes, get_own_keys,
        get_unlock_methods,
    },
};

const PRIVATE_KEY_TYPE: &str = "private-key";
const SIGNING_KEY_TYPE: &str = "signing-key";
const SECURITY_STATE_TYPE: &str = "security-state";
const KDF_TYPE: &str = "kdf";
const MASTER_PASSWORD_KIND: &str = "master-password";
const RAW_MASTER_PASSWORD_TYPE: &str = "raw";

/// The only security version a signed security state is issued for.
const SECURITY_VERSION_V2: i32 = 2;

/// Errors returned when the key sync fails. Nothing is written to state when it does.
#[derive(Debug, thiserror::Error)]
#[bitwarden_error(flat)]
pub enum KeySyncError {
    /// The key sync writes through the state bridge, which the client has not registered.
    #[error("No state bridge is registered")]
    StateBridgeMissing,
    /// A Key Service request failed.
    #[error(transparent)]
    Api(#[from] KeyServiceApiError),
    /// A Key Service response could not be turned into key management state.
    #[error(transparent)]
    Parse(#[from] KeySyncParseError),
}

/// Errors returned when Key Service resources cannot be converted into [`CryptoSyncData`].
#[derive(Debug, thiserror::Error)]
pub enum KeySyncParseError {
    /// The Key Service returned more than one resource where the account has one.
    #[error("Key Service returned more than one {0}")]
    Duplicate(&'static str),
    /// A resource's `data` is not the JSON its type describes.
    #[error("Key Service returned malformed {0} data")]
    MalformedData(&'static str, #[source] serde_json::Error),
    /// The master password unlock method uses an envelope this client cannot read.
    #[error("Key Service returned an unsupported master password envelope")]
    UnsupportedMasterPasswordEnvelope,
    /// The master password unlock method carries a malformed wrapped user key.
    #[error("Key Service returned a malformed master password wrapped user key")]
    MasterPasswordWrappedKey,
    /// A key id is not a valid key id.
    #[error("Key Service returned a malformed key id")]
    KeyId(#[source] bitwarden_crypto::CryptoError),
    /// The V2 upgrade token could not be parsed.
    #[error("Key Service returned a malformed V2 upgrade token")]
    V2UpgradeToken(#[source] V2UpgradeTokenError),
    /// The private key, signing key and security state don't form a valid account state.
    #[error("Key Service returned an inconsistent account cryptographic state")]
    AccountCryptographicState(#[source] AccountKeysResponseParseError),
}

/// Reads the user's keys and unlock methods from the Key Service and writes them to state.
pub(crate) async fn sync_keys(client: &Client) -> Result<(), KeySyncError> {
    if !client.km_state_bridge().is_bridge_registered() {
        return Err(KeySyncError::StateBridgeMissing);
    }

    let configurations = client.internal.get_api_configurations();
    let data = KeyServiceData {
        own_keys: get_own_keys(&configurations.api_config).await?,
        unlock_methods: get_unlock_methods(&configurations.api_config).await?,
    };

    // Parsed in full before anything is written, so a malformed response leaves state untouched.
    let crypto_sync_data = CryptoSyncData::try_from(&data)?;
    handle_crypto_sync(client, &crypto_sync_data).await;

    Ok(())
}

/// The Key Service resources the key sync reads.
pub(crate) struct KeyServiceData {
    pub(crate) own_keys: Vec<Resource<OwnKeyAttributes>>,
    pub(crate) unlock_methods: Vec<Resource<UnlockMethodAttributes>>,
}

/// `private-key` data:
/// `{"type":"legacy-compat-private-key-envelope","wrappedKey","publicKey","signedKey"}`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PrivateKeyData {
    wrapped_key: String,
    public_key: String,
    signed_key: Option<String>,
}

/// `signing-key` data: `{"type":"legacy-compat-signing-key-envelope","wrappedKey","publicKey"}`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigningKeyData {
    wrapped_key: String,
    public_key: String,
}

/// `security-state` data: `{"securityState"}`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SecurityStateData {
    security_state: String,
}

/// `kdf` data, also nested in the master password unlock method, e.g.
/// `{"type":"argon2id","iterations":3,"memory":64,"parallelism":4}`.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum KdfData {
    Pbkdf2 {
        iterations: std::num::NonZeroU32,
    },
    Argon2id {
        iterations: std::num::NonZeroU32,
        memory: std::num::NonZeroU32,
        parallelism: std::num::NonZeroU32,
    },
}

impl From<KdfData> for Kdf {
    fn from(kdf: KdfData) -> Self {
        match kdf {
            KdfData::Pbkdf2 { iterations } => Kdf::PBKDF2 { iterations },
            KdfData::Argon2id {
                iterations,
                memory,
                parallelism,
            } => Kdf::Argon2id {
                iterations,
                memory,
                parallelism,
            },
        }
    }
}

/// `master-password` data: `{"type":"raw","wrappedKey","kdf","salt","v2UpgradeToken"}`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MasterPasswordData {
    #[serde(rename = "type")]
    envelope_type: String,
    wrapped_key: String,
    kdf: KdfData,
    salt: String,
    v2_upgrade_token: Option<V2UpgradeTokenData>,
}

/// `{"wrappedUserKey1","wrappedUserKey2"}`
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct V2UpgradeTokenData {
    wrapped_user_key_1: String,
    wrapped_user_key_2: String,
}

impl TryFrom<&KeyServiceData> for CryptoSyncData {
    type Error = KeySyncParseError;

    fn try_from(data: &KeyServiceData) -> Result<Self, Self::Error> {
        let private_key = single(&data.own_keys, PRIVATE_KEY_TYPE, |key| {
            key.resource_type == PRIVATE_KEY_TYPE
        })?;
        let master_password = single(&data.unlock_methods, MASTER_PASSWORD_KIND, |method| {
            method.attributes.kind == MASTER_PASSWORD_KIND
        })?;

        let master_password_data = master_password
            .map(|method| parse_data::<MasterPasswordData>(&method.data, MASTER_PASSWORD_KIND))
            .transpose()?;

        let contained_key_id =
            parse_key_id(master_password.and_then(|method| method.contained_key_id.as_deref()))?;
        let sealed_by_key_id =
            parse_key_id(private_key.and_then(|key| key.sealed_by_key_id.as_deref()))?;

        // The master password names the key it seals; without one, the private key names its
        // sealer.
        let user_key_id = contained_key_id.clone().or(sealed_by_key_id);

        let (master_password_unlock, v2_upgrade_token) = match master_password_data {
            Some(data) => master_password_unlock(data, contained_key_id)?,
            None => (None, None),
        };

        let kdf = single(&data.own_keys, KDF_TYPE, |key| {
            key.resource_type == KDF_TYPE
        })?
        .map(|key| parse_data::<KdfData>(&key.data, KDF_TYPE))
        .transpose()?
        .map(Kdf::from);

        Ok(Self {
            user_decryption: Some(CryptoSyncUserDecryption {
                master_password_unlock,
                v2_upgrade_token,
                // PRF passkeys are left to the full sync, which knows their credential ids.
                web_authn_prf_options: None,
                user_key_id,
                kdf,
            }),
            account_cryptographic_state: account_cryptographic_state(&data.own_keys, private_key)?,
        })
    }
}

/// Builds the master password unlock data and the V2 upgrade token it carries.
fn master_password_unlock(
    data: MasterPasswordData,
    contained_key_id: Option<KeyId>,
) -> Result<(Option<MasterPasswordUnlockData>, Option<V2UpgradeToken>), KeySyncParseError> {
    if data.envelope_type != RAW_MASTER_PASSWORD_TYPE {
        return Err(KeySyncParseError::UnsupportedMasterPasswordEnvelope);
    }

    let master_key_wrapped_user_key = EncString::parse_strict(&data.wrapped_key)
        .map_err(|_| KeySyncParseError::MasterPasswordWrappedKey)?;

    // Reuses the sync response's parsing, so both sources accept exactly the same tokens.
    let v2_upgrade_token = data
        .v2_upgrade_token
        .map(|token| {
            V2UpgradeToken::try_from(&V2UpgradeTokenResponseModel {
                wrapped_user_key1: Some(token.wrapped_user_key_1),
                wrapped_user_key2: Some(token.wrapped_user_key_2),
            })
        })
        .transpose()
        .map_err(KeySyncParseError::V2UpgradeToken)?;

    let unlock = MasterPasswordUnlockData {
        kdf: data.kdf.into(),
        master_key_wrapped_user_key,
        salt: data.salt,
        contained_key_id,
    };

    Ok((Some(unlock), v2_upgrade_token))
}

/// Builds the account cryptographic state from the private key, signing key and security state.
///
/// Reuses the sync response's parsing, so a V2 private key without its signing key, signed public
/// key and security state is refused the same way.
fn account_cryptographic_state(
    own_keys: &[Resource<OwnKeyAttributes>],
    private_key: Option<&OwnKeyAttributes>,
) -> Result<Option<WrappedAccountCryptographicState>, KeySyncParseError> {
    // Accounts without keys yet, e.g. a just-provisioned SSO user, have no state to write.
    let Some(private_key) = private_key else {
        return Ok(None);
    };
    let private_key = parse_data::<PrivateKeyData>(&private_key.data, PRIVATE_KEY_TYPE)?;

    let signing_key = single(own_keys, SIGNING_KEY_TYPE, |key| {
        key.resource_type == SIGNING_KEY_TYPE
    })?
    .map(|key| parse_data::<SigningKeyData>(&key.data, SIGNING_KEY_TYPE))
    .transpose()?;

    let security_state = single(own_keys, SECURITY_STATE_TYPE, |key| {
        key.resource_type == SECURITY_STATE_TYPE
    })?
    .map(|key| parse_data::<SecurityStateData>(&key.data, SECURITY_STATE_TYPE))
    .transpose()?;

    let response = PrivateKeysResponseModel {
        object: None,
        public_key_encryption_key_pair: Box::new(PublicKeyEncryptionKeyPairResponseModel {
            object: None,
            wrapped_private_key: Some(private_key.wrapped_key),
            public_key: Some(private_key.public_key),
            signed_public_key: private_key.signed_key,
        }),
        signature_key_pair: signing_key.map(|key| {
            Box::new(SignatureKeyPairResponseModel {
                object: None,
                wrapped_signing_key: Some(key.wrapped_key),
                verifying_key: Some(key.public_key),
            })
        }),
        security_state: security_state.map(|state| {
            Box::new(SecurityStateModel {
                security_state: Some(state.security_state),
                security_version: SECURITY_VERSION_V2,
            })
        }),
    };

    WrappedAccountCryptographicState::try_from(&response)
        .map(Some)
        .map_err(KeySyncParseError::AccountCryptographicState)
}

/// Returns the attributes of the one resource that matches, if any.
fn single<'a, T>(
    resources: &'a [Resource<T>],
    name: &'static str,
    matches: impl Fn(&Resource<T>) -> bool,
) -> Result<Option<&'a T>, KeySyncParseError> {
    let mut found = resources.iter().filter(|resource| matches(resource));
    let first = found.next();

    if found.next().is_some() {
        return Err(KeySyncParseError::Duplicate(name));
    }

    Ok(first.map(|resource| &resource.attributes))
}

/// Parses an optional key id.
fn parse_key_id(key_id: Option<&str>) -> Result<Option<KeyId>, KeySyncParseError> {
    key_id
        .map(str::parse)
        .transpose()
        .map_err(KeySyncParseError::KeyId)
}

/// Parses a resource's `data` JSON string.
fn parse_data<T: DeserializeOwned>(data: &str, name: &'static str) -> Result<T, KeySyncParseError> {
    serde_json::from_str(data).map_err(|e| KeySyncParseError::MalformedData(name, e))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use bitwarden_core::{
        ClientSettings, DeviceType, key_management::state_bridge::test_support::InMemoryStateBridge,
    };
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use super::*;

    const USER_KEY_ID: &str = "000102030405060708090a0b0c0d0e0f";
    const OTHER_KEY_ID: &str = "0f0e0d0c0b0a09080706050403020100";
    const SALT: &str = "test@example.com";
    const PUBLIC_KEY: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz/+1jPJ1HqcaCdKrTPms8XJcvnmd9alI42U2XF/4GMNTM5KF1gI6snhR/23ZLatZRFMHoK8ZCMSpGNkjLadArz52ldceTvBOhQUiWylkZQ4NfNa3xIYJubXOmkeDyfNuyLxVZvcZOko9PdT+Qx2QxDrFi2XNo2I7aVFd19/COIEkex4mJ0eA3MHFpKCdxYbcTAsGID8+kVR9L84S1JptZoG8x+iB/D3/Q4y02UsQYpFTu0vbPY84YmW03ngJdxWzS8X4/UJI/jaEn5rO4xlU5QcL0l4IybP5LRpE9XEeUHATKVOG7eNfpe9zDfKV2qQoofQMH9VvkWO4psaWDjBSdwIDAQAB";
    const USER_KEY_WRAPPED: &str = "2.Q/2PhzcC7GdeiMHhWguYAQ==|GpqzVdr0go0ug5cZh1n+uixeBC3oC90CIe0hd/HWA/pTRDZ8ane4fmsEIcuc8eMKUt55Y2q/fbNzsYu41YTZzzsJUSeqVjT8/iTQtgnNdpo=|dwI+uyvZ1h/iZ03VQ+/wrGEFYVewBUUl/syYgjsNMbE=";
    const PRIVATE_KEY_V1: &str = "2.yN7l00BOlUE0Sb0M//Q53w==|EwKG/BduQRQ33Izqc/ogoBROIoI5dmgrxSo82sgzgAMIBt3A2FZ9vPRMY+GWT85JiqytDitGR3TqwnFUBhKUpRRAq4x7rA6A1arHrFp5Tp1p21O3SfjtvB3quiOKbqWk6ZaU1Np9HwqwAecddFcB0YyBEiRX3VwF2pgpAdiPbSMuvo2qIgyob0CUoC/h4Bz1be7Qa7B0Xw9/fMKkB1LpOm925lzqosyMQM62YpMGkjMsbZz0uPopu32fxzDWSPr+kekNNyLt9InGhTpxLmq1go/pXR2uw5dfpXc5yuta7DB0EGBwnQ8Vl5HPdDooqOTD9I1jE0mRyuBpWTTI3FRnu3JUh3rIyGBJhUmHqGZvw2CKdqHCIrQeQkkEYqOeJRJVdBjhv5KGJifqT3BFRwX/YFJIChAQpebNQKXe/0kPivWokHWwXlDB7S7mBZzhaAPidZvnuIhalE2qmTypDwHy22FyqV58T8MGGMchcASDi/QXI6kcdpJzPXSeU9o+NC68QDlOIrMVxKFeE7w7PvVmAaxEo0YwmuAzzKy9QpdlK0aab/xEi8V4iXj4hGepqAvHkXIQd+r3FNeiLfllkb61p6WTjr5urcmDQMR94/wYoilpG5OlybHdbhsYHvIzYoLrC7fzl630gcO6t4nM24vdB6Ymg9BVpEgKRAxSbE62Tqacxqnz9AcmgItb48NiR/He3n3ydGjPYuKk/ihZMgEwAEZvSlNxYONSbYrIGDtOY+8Nbt6KiH3l06wjZW8tcmFeVlWv+tWotnTY9IqlAfvNVTjtsobqtQnvsiDjdEVtNy/s2ci5TH+NdZluca2OVEr91Wayxh70kpM6ib4UGbfdmGgCo74gtKvKSJU0rTHakQ5L9JlaSDD5FamBRyI0qfL43Ad9qOUZ8DaffDCyuaVyuqk7cz9HwmEmvWU3VQ+5t06n/5kRDXttcw8w+3qClEEdGo1KeENcnXCB32dQe3tDTFpuAIMLqwXs6FhpawfZ5kPYvLPczGWaqftIs/RXJ/EltGc0ugw2dmTLpoQhCqrcKEBDoYVk0LDZKsnzitOGdi9mOWse7Se8798ib1UsHFUjGzISEt6upestxOeupSTOh0v4+AjXbDzRUyogHww3V+Bqg71bkcMxtB+WM+pn1XNbVTyl9NR040nhP7KEf6e9ruXAtmrBC2ah5cFEpLIot77VFZ9ilLuitSz+7T8n1yAh1IEG6xxXxninAZIzi2qGbH69O5RSpOJuJTv17zTLJQIIc781JwQ2TTwTGnx5wZLbffhCasowJKd2EVcyMJyhz6ru0PvXWJ4hUdkARJs3Xu8dus9a86N8Xk6aAPzBDqzYb1vyFIfBxP0oO8xFHgd30Cgmz8UrSE3qeWRrF8ftrI6xQnFjHBGWD/JWSvd6YMcQED0aVuQkuNW9ST/DzQThPzRfPUoiL10yAmV7Ytu4fR3x2sF0Yfi87YhHFuCMpV/DsqxmUizyiJuD938eRcH8hzR/VO53Qo3UIsqOLcyXtTv6THjSlTopQ+JOLOnHm1w8dzYbLN44OG44rRsbihMUQp+wUZ6bsI8rrOnm9WErzkbQFbrfAINdoCiNa6cimYIjvvnMTaFWNymqY1vZxGztQiMiHiHYwTfwHTXrb9j0uPM=|09J28iXv9oWzYtzK2LBT6Yht4IT4MijEkk0fwFdrVQ4=";
    const PRIVATE_KEY_V2: &str = "7.g1gdowE6AAEReQMZARwEULFmQoUOmnvQ/mZY+Y6N/fGhBVgYe16rmgYXX3Orgo6y5U5Z8eb+JHTGfcivWQTR+1rVWtHJhEm8G/AtE78Ud3S8qxZmstUKhC5u9xgPvx2e8Fe8QL80Dv0WoEsy0XEb+5EFd8xDlu7OBuCVv2MaoJ/XzAkbpn9IT1vMCPhvRuaktIWMNrQgJ1jnmqjTGObftA02sHnj938tLRNfilw8ln/PBO2GBZQVzTUYfnc+mBeedGyZAxhSxyUwtFB8h3HC/t9BGtLT/bm83Df8rwTc+rGFL5r+T6vczQ+6hvF6kKpUb37XwgLEDsc+J4UTb+4zHaDcTioOYq6Hki8PrsN9PWL57nkhRMi3fKgfz8GDtY+pjp7D9HYV6OMuveSK9l+h16enJwiFDy6XEx+eth4aHPT5hybnOfTWbkEIhUmPD3K2JKvUUxeL9Z6e1EtSylVitO4Lit485KYaY8VASW4MnAzPOUQVwZ4jowHr5X8g0jVtHiLeUuOwDGcqjO/q6//tkiCwjW/W79jk4eqMtqPbOl0XelYVmM4KZCslPZ+2IYS56g/gl8Q2Oj9UGq7QJCsZvV9rBNa4wS3uC9atoWWRqO2PTWkVTurakkK3Fc9VP2bC1lJaWoWVjYpyJJVZh77ktpD3VrFdrT62+de0iaWUAtAr/1ALToNzoTYu3ihyGb6FZMN//XLTKk8GhZGVCluEDClHnziBxCX7Qg/0HRiU7EjsYGhpFnmG2XkvZQb9Pds8gucTbmbUeVfjXZ/IOLm16G/tdit2VIf80zcsvhgxTYys4Cm12N+62fM3aT5L9lqWvBYOMDksy00/3uLPzWbLFWbKItaC1c+bceGS7UDrLim6Pm/Voo2jXCi6EHpXX2/THrJybRDwqmQi7UVWXR3aPx//q9busEXxRyeu0m4lq2AjhQWhOvfPjpJzNX1hRE9Bu7UKYJhUF6DAsXFFKpob0LoARpcjGLFLcO61yV6He2nQFAa+ULXxhrKbISzqO3Q2xMs2p3jQ4Ctm0T+03w9Y5/Yf1qNKaL6AayA2nf0thYgh+OHNEnnkFwvBnTyB5B32E+/cUy7bb3329Pz7h+ruLo5IhGZM5GiEjF4vOSZmZJZ1t2eR4U7oxX0VTpwFPPBUQ3O7A5C2l0g/pGCFda4QlgR5qRA09kaAd9VBSJbQABGH0zWlXNPAjPQ6M9CxxTv9lM/72RSzTvnJqjQNpWGQjYuTi++EN5QZ37Nmlcw9eSa6X1C97ADndWV46dlFowUUDXiczi+Q0bZmFtpvkRg0TWlicS/cURLIfpG7sGwgqIis5R4haQ+RDB1+4oC0xmncWqy7vMESW6trh+icEL2PybwGPnzdngUqEIw5fG9huX3BmxbJjukSjWWk2CH8AaY2lHRXttzpOhpfP9c1cmrwXXUuHwTFMiKdmdwSqGbgebUP25kB9priXO88Jri3Wb739KRV5M2k6/9AspCwpOqlKN6MZm2vElNI+cXSWMHeX3666p4ALr7Vu7+q7iw4s4cO09MMJWsaiTaZBsVRhdoocsej+091JM/yJ29TVDJEMp2vEiia8HQ4k2bH9W9XCB71cpygRMYTFRDJ3Yjly4MYg7whBQnkeu8IYagCY6UZ60V73qhKRZJKuiV6ZTC+objnMPMmi9Kd05WmYFab8ZDP8s4yhU0WJNXdZGwpX7pnoi0T+g/y94sfZNGs5QuKgNEX";
    const SIGNED_PUBLIC_KEY_V2: &str = "hFgepAEnAxg8BFAmkP0QgfdMVbIujX55W/yNOgABOH8BoFkBTqNpYWxnb3JpdGhtAG1jb250ZW50Rm9ybWF0AGlwdWJsaWNLZXlZASYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDP/7WM8nUepxoJ0qtM+azxcly+eZ31qUjjZTZcX/gYw1MzkoXWAjqyeFH/bdktq1lEUwegrxkIxKkY2SMtp0CvPnaV1x5O8E6FBSJbKWRlDg181rfEhgm5tc6aR4PJ827IvFVm9xk6Sj091P5DHZDEOsWLZc2jYjtpUV3X38I4gSR7HiYnR4DcwcWkoJ3FhtxMCwYgPz6RVH0vzhLUmm1mgbzH6IH8Pf9DjLTZSxBikVO7S9s9jzhiZbTeeAl3FbNLxfj9Qkj+NoSfms7jGVTlBwvSXgjJs/ktGkT1cR5QcBMpU4bt41+l73MN8pXapCih9Awf1W+RY7imxpYOMFJ3AgMBAAFYQMq/hT4wod2w8xyoM7D86ctuLNX4ZRo+jRHf2sZfaO7QsvonG/ZYuNKF5fq8wpxMRjfoMvnY2TTShbgzLrW8BA4=";
    const SIGNING_KEY_V2: &str = "7.g1gcowE6AAEReQMYZQRQsWZChQ6ae9D+Zlj5jo398aEFWBj8Gg/gn4tQKWO3nq5e/2p9gkzIrKD829RYT3aEUIDOetEtnFqRuQ3Cz13693WqDnKHM5Buzi6LcTsxo1jphYR7vlE5nYLjCpOCAftPN1oLfs5SCNkwwMENhujpVftfDzciE99aLEJDS9A=";
    const SECURITY_STATE_V2: &str = "hFgepAEnAxg8BFAmkP0QgfdMVbIujX55W/yNOgABOH8CoFgkomhlbnRpdHlJZFBHOOw2BI9OQoNq+Vl1xZZKZ3ZlcnNpb24CWEAlchbJR0vmRfShG8On7Q2gknjkw4Dd6MYBLiH4u+/CmfQdmjNZdf6kozgW/6NXyKVNu8dAsKsin+xxXkDyVZoG";

    /// A resource as the server writes it, with its `data` serialized to a JSON string.
    fn resource(resource_type: &str, attributes: serde_json::Value) -> serde_json::Value {
        json!({ "id": "62bed180-0000-0000-0000-000000000000", "type": resource_type, "attributes": attributes })
    }

    fn own_key(
        resource_type: &str,
        sealed_by_key_id: Option<&str>,
        data: serde_json::Value,
    ) -> serde_json::Value {
        resource(
            resource_type,
            json!({ "keyPurpose": "user-sharing-root", "sealedByKeyId": sealed_by_key_id, "data": data.to_string() }),
        )
    }

    fn private_key(wrapped_key: &str, signed_key: Option<&str>) -> serde_json::Value {
        own_key(
            PRIVATE_KEY_TYPE,
            Some(USER_KEY_ID),
            json!({ "type": "legacy-compat-private-key-envelope", "wrappedKey": wrapped_key, "publicKey": PUBLIC_KEY, "signedKey": signed_key }),
        )
    }

    fn kdf(data: serde_json::Value) -> serde_json::Value {
        own_key(KDF_TYPE, None, data)
    }

    fn master_password(data: serde_json::Value) -> serde_json::Value {
        resource(
            "unlock-method",
            json!({ "kind": MASTER_PASSWORD_KIND, "containedKeyId": USER_KEY_ID, "data": data.to_string() }),
        )
    }

    fn master_password_data() -> serde_json::Value {
        json!({ "type": "raw", "wrappedKey": USER_KEY_WRAPPED, "kdf": { "type": "pbkdf2", "iterations": 600000 }, "salt": SALT })
    }

    fn v2_own_keys() -> Vec<serde_json::Value> {
        vec![
            private_key(PRIVATE_KEY_V2, Some(SIGNED_PUBLIC_KEY_V2)),
            own_key(
                SIGNING_KEY_TYPE,
                Some(USER_KEY_ID),
                json!({ "type": "legacy-compat-signing-key-envelope", "wrappedKey": SIGNING_KEY_V2, "publicKey": "pQEB" }),
            ),
            own_key(
                SECURITY_STATE_TYPE,
                None,
                json!({ "securityState": SECURITY_STATE_V2 }),
            ),
        ]
    }

    fn parse(
        own_keys: Vec<serde_json::Value>,
        unlock_methods: Vec<serde_json::Value>,
    ) -> Result<CryptoSyncData, KeySyncParseError> {
        let data = KeyServiceData {
            own_keys: serde_json::from_value(json!(own_keys)).expect("own keys fixture"),
            unlock_methods: serde_json::from_value(json!(unlock_methods))
                .expect("unlock methods fixture"),
        };
        CryptoSyncData::try_from(&data)
    }

    #[test]
    fn test_master_password_v1_user() {
        let data = parse(
            vec![private_key(PRIVATE_KEY_V1, None)],
            vec![master_password(master_password_data())],
        )
        .unwrap();

        let user_decryption = data.user_decryption.unwrap();
        let unlock = user_decryption.master_password_unlock.unwrap();
        assert_eq!(unlock.salt, SALT);
        assert_eq!(unlock.contained_key_id.unwrap().to_string(), USER_KEY_ID);
        assert!(matches!(unlock.kdf, Kdf::PBKDF2 { iterations } if iterations.get() == 600_000));
        assert_eq!(
            user_decryption.user_key_id.unwrap().to_string(),
            USER_KEY_ID
        );
        assert!(user_decryption.v2_upgrade_token.is_none());
        assert!(matches!(
            data.account_cryptographic_state,
            Some(WrappedAccountCryptographicState::V1 { .. })
        ));
    }

    #[test]
    fn test_v2_user() {
        let data = parse(v2_own_keys(), vec![master_password(master_password_data())]).unwrap();

        assert!(matches!(
            data.account_cryptographic_state,
            Some(WrappedAccountCryptographicState::V2 { .. })
        ));
    }

    #[test]
    fn test_v2_private_key_without_security_state_errors() {
        let mut own_keys = v2_own_keys();
        own_keys.pop();

        assert!(matches!(
            parse(own_keys, vec![]),
            Err(KeySyncParseError::AccountCryptographicState(_))
        ));
    }

    #[test]
    fn test_upgrade_token() {
        let mut mp = master_password_data();
        mp["v2UpgradeToken"] =
            json!({ "wrappedUserKey1": SIGNING_KEY_V2, "wrappedUserKey2": USER_KEY_WRAPPED });

        let data = parse(v2_own_keys(), vec![master_password(mp)]).unwrap();

        assert!(data.user_decryption.unwrap().v2_upgrade_token.is_some());
    }

    #[test]
    fn test_argon2id_kdf() {
        let data = parse(
            vec![kdf(
                json!({ "type": "argon2id", "iterations": 3, "memory": 64, "parallelism": 4 }),
            )],
            vec![],
        )
        .unwrap();

        assert!(matches!(
            data.user_decryption.unwrap().kdf,
            Some(Kdf::Argon2id { iterations, memory, parallelism })
                if iterations.get() == 3 && memory.get() == 64 && parallelism.get() == 4
        ));
    }

    #[test]
    fn test_zero_kdf_iterations_errors() {
        assert!(matches!(
            parse(
                vec![kdf(json!({ "type": "pbkdf2", "iterations": 0 }))],
                vec![]
            ),
            Err(KeySyncParseError::MalformedData(KDF_TYPE, _))
        ));
    }

    /// Trusted device and Key Connector users have no master password, so the user key id comes
    /// from the private key's sealer.
    #[test]
    fn test_without_master_password_takes_key_id_from_private_key() {
        let data = parse(vec![private_key(PRIVATE_KEY_V1, None)], vec![]).unwrap();

        let user_decryption = data.user_decryption.unwrap();
        assert!(user_decryption.master_password_unlock.is_none());
        assert_eq!(
            user_decryption.user_key_id.unwrap().to_string(),
            USER_KEY_ID
        );
    }

    #[test]
    fn test_master_password_key_id_wins() {
        let mut private = private_key(PRIVATE_KEY_V1, None);
        private["attributes"]["sealedByKeyId"] = json!(OTHER_KEY_ID);

        let data = parse(vec![private], vec![master_password(master_password_data())]).unwrap();

        assert_eq!(
            data.user_decryption
                .unwrap()
                .user_key_id
                .unwrap()
                .to_string(),
            USER_KEY_ID
        );
    }

    #[test]
    fn test_other_unlock_methods_are_ignored() {
        let device = resource("unlock-method", json!({ "kind": "device", "data": "{}" }));

        let data = parse(vec![], vec![device]).unwrap();

        assert!(
            data.user_decryption
                .unwrap()
                .master_password_unlock
                .is_none()
        );
        assert!(data.account_cryptographic_state.is_none());
    }

    #[test]
    fn test_unsupported_master_password_envelope_errors() {
        let mut mp = master_password_data();
        mp["type"] = json!("hpke");

        assert!(matches!(
            parse(vec![], vec![master_password(mp)]),
            Err(KeySyncParseError::UnsupportedMasterPasswordEnvelope)
        ));
    }

    #[test]
    fn test_duplicate_private_key_errors() {
        let private = private_key(PRIVATE_KEY_V1, None);

        assert!(matches!(
            parse(vec![private.clone(), private], vec![]),
            Err(KeySyncParseError::Duplicate(PRIVATE_KEY_TYPE))
        ));
    }

    fn client_for(server: &MockServer, bridge: StateBridgeSetup) -> Client {
        let client = Client::new(Some(ClientSettings {
            identity_url: server.uri(),
            api_url: server.uri(),
            user_agent: "Bitwarden Test".into(),
            device_type: DeviceType::SDK,
            device_identifier: None,
            bitwarden_client_version: None,
            bitwarden_package_type: None,
        }));

        if bridge == StateBridgeSetup::Registered {
            client
                .km_state_bridge()
                .register_bridge(Box::new(InMemoryStateBridge::default()));
        }

        client
    }

    #[derive(PartialEq)]
    enum StateBridgeSetup {
        Registered,
        Missing,
    }

    async fn serve(
        server: &MockServer,
        own_keys: serde_json::Value,
        unlock_methods: serde_json::Value,
    ) {
        Mock::given(method("GET"))
            .and(path(crate::key_service_api::OWN_KEYS_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "data": own_keys })))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(crate::key_service_api::UNLOCK_METHODS_PATH))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "data": unlock_methods })),
            )
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn test_sync_keys_writes_state() {
        let server = MockServer::start().await;
        let mut own_keys = v2_own_keys();
        own_keys.push(kdf(json!({ "type": "pbkdf2", "iterations": 600000 })));
        serve(
            &server,
            json!(own_keys),
            json!([master_password(master_password_data())]),
        )
        .await;
        let client = client_for(&server, StateBridgeSetup::Registered);

        sync_keys(&client).await.unwrap();

        let bridge = client.km_state_bridge();
        assert_eq!(
            bridge.get_masterpassword_unlock_data().await.unwrap().salt,
            SALT
        );
        assert!(bridge.get_kdf_config().await.is_some());
        assert_eq!(
            bridge.get_user_key_id().await.unwrap().to_string(),
            USER_KEY_ID
        );
        assert!(matches!(
            bridge.get_account_cryptographic_state().await,
            Some(WrappedAccountCryptographicState::V2 { .. })
        ));
    }

    /// Trusted device users have no master password; their KDF still reaches state.
    #[tokio::test]
    async fn test_sync_keys_writes_kdf_without_master_password() {
        let server = MockServer::start().await;
        serve(
            &server,
            json!([
                private_key(PRIVATE_KEY_V1, None),
                kdf(json!({ "type": "pbkdf2", "iterations": 600000 }))
            ]),
            json!([]),
        )
        .await;
        let client = client_for(&server, StateBridgeSetup::Registered);

        sync_keys(&client).await.unwrap();

        let bridge = client.km_state_bridge();
        assert!(bridge.get_masterpassword_unlock_data().await.is_none());
        assert!(bridge.get_kdf_config().await.is_some());
    }

    #[tokio::test]
    async fn test_sync_keys_server_error_writes_nothing() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let client = client_for(&server, StateBridgeSetup::Registered);

        let result = sync_keys(&client).await;

        assert!(matches!(
            result,
            Err(KeySyncError::Api(KeyServiceApiError::Status(status))) if status.as_u16() == 500
        ));
        assert!(
            client
                .km_state_bridge()
                .get_account_cryptographic_state()
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_sync_keys_without_bridge_errors() {
        let server = MockServer::start().await;
        let client = client_for(&server, StateBridgeSetup::Missing);

        assert!(matches!(
            sync_keys(&client).await,
            Err(KeySyncError::StateBridgeMissing)
        ));
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}
