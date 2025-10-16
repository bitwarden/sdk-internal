use std::{
    collections::HashMap,
    fmt::{self},
    str::FromStr,
};

use bitwarden_core::key_management::KeyIds;
use bitwarden_crypto::{CryptoError, KeyStoreContext};
use bitwarden_error::bitwarden_error;
use chrono::{DateTime, Utc};
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use percent_encoding::{NON_ALPHANUMERIC, percent_decode_str, percent_encode};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use tsify::Tsify;

use crate::CipherListView;

type HmacSha1 = Hmac<sha1::Sha1>;
type HmacSha256 = Hmac<sha2::Sha256>;
type HmacSha512 = Hmac<sha2::Sha512>;

const BASE32_CHARS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const STEAM_CHARS: &str = "23456789BCDFGHJKMNPQRTVWXY";

const DEFAULT_ALGORITHM: TotpAlgorithm = TotpAlgorithm::Sha1;
const DEFAULT_DIGITS: u32 = 6;
const DEFAULT_PERIOD: u32 = 30;

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum TotpError {
    #[error("Invalid otpauth")]
    InvalidOtpauth,
    #[error("Missing secret")]
    MissingSecret,

    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct TotpResponse {
    /// Generated TOTP code
    pub code: String,
    /// Time period
    pub period: u32,
}

/// Generate a OATH or RFC 6238 TOTP code from a provided key.
///
/// <https://datatracker.ietf.org/doc/html/rfc6238>
///
/// Key can be either:
/// - A base32 encoded string
/// - OTP Auth URI
/// - Steam URI
///
/// Supports providing an optional time, and defaults to current system time if none is provided.
///
/// Arguments:
/// - `key` - The key to generate the TOTP code from
/// - `time` - The time in UTC to generate the TOTP code for, defaults to current system time
pub fn generate_totp(key: String, time: Option<DateTime<Utc>>) -> Result<TotpResponse, TotpError> {
    let params: Totp = key.parse()?;

    let time = time.unwrap_or_else(Utc::now);

    let otp = params.derive_otp(time.timestamp());

    Ok(TotpResponse {
        code: otp,
        period: params.period,
    })
}

/// Generate a OATH or RFC 6238 TOTP code from a provided CipherListView.
///
/// See [generate_totp] for more information.
pub fn generate_totp_cipher_view(
    ctx: &mut KeyStoreContext<KeyIds>,
    view: CipherListView,
    time: Option<DateTime<Utc>>,
) -> Result<TotpResponse, TotpError> {
    let key = view.get_totp_key(ctx)?.ok_or(TotpError::MissingSecret)?;

    generate_totp(key, time)
}

#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
    Steam,
}

impl TotpAlgorithm {
    // Derive the HMAC hash for the given algorithm
    fn derive_hash(&self, key: &[u8], time: &[u8]) -> Vec<u8> {
        fn compute_digest<D: Mac>(digest: D, time: &[u8]) -> Vec<u8> {
            digest.chain_update(time).finalize().into_bytes().to_vec()
        }

        match self {
            TotpAlgorithm::Sha1 => compute_digest(
                HmacSha1::new_from_slice(key).expect("hmac new_from_slice should not fail"),
                time,
            ),
            TotpAlgorithm::Sha256 => compute_digest(
                HmacSha256::new_from_slice(key).expect("hmac new_from_slice should not fail"),
                time,
            ),
            TotpAlgorithm::Sha512 => compute_digest(
                HmacSha512::new_from_slice(key).expect("hmac new_from_slice should not fail"),
                time,
            ),
            TotpAlgorithm::Steam => compute_digest(
                HmacSha1::new_from_slice(key).expect("hmac new_from_slice should not fail"),
                time,
            ),
        }
    }
}

impl fmt::Display for TotpAlgorithm {
    /// Display the algorithm as a string
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TotpAlgorithm::Sha1 => "SHA1",
            TotpAlgorithm::Sha256 => "SHA256",
            TotpAlgorithm::Sha512 => "SHA512",
            TotpAlgorithm::Steam => "SHA1",
        })
    }
}

/// TOTP representation broken down into its components.
///
/// Should generally be considered internal to the bitwarden-vault crate. Consumers should use one
/// of the generate functions if they want to generate a TOTP code. Credential Exchange requires
/// access to the individual components.
#[allow(missing_docs)]
#[derive(Debug)]
pub struct Totp {
    pub account: Option<String>,
    pub algorithm: TotpAlgorithm,
    pub digits: u32,
    pub issuer: Option<String>,
    pub period: u32,
    pub secret: Vec<u8>,
}

impl Totp {
    fn derive_otp(&self, time: i64) -> String {
        let time = time / self.period as i64;

        let hash = self
            .algorithm
            .derive_hash(&self.secret, time.to_be_bytes().as_ref());
        let binary = derive_binary(hash);

        if let TotpAlgorithm::Steam = self.algorithm {
            derive_steam_otp(binary, self.digits)
        } else {
            let otp = binary % 10_u32.pow(self.digits);
            format!("{1:00$}", self.digits as usize, otp)
        }
    }
}

impl FromStr for Totp {
    type Err = TotpError;

    /// Parses the provided key and returns the corresponding `Totp`.
    ///
    /// Key can be either:
    /// - A base32 encoded string
    /// - OTP Auth URI
    /// - Steam URI
    fn from_str(key: &str) -> Result<Self, Self::Err> {
        let key = key.to_lowercase();

        let params = if key.starts_with("otpauth://") {
            let url = Url::parse(&key).map_err(|_| TotpError::InvalidOtpauth)?;
            let decoded_path = percent_decode_str(url.path()).decode_utf8_lossy();
            let label = decoded_path.strip_prefix("/");
            let (issuer, account) = match label.and_then(|v| v.split_once(':')) {
                Some((issuer, account)) => (Some(issuer.trim()), Some(account.trim())),
                None => (None, label),
            };

            let parts: HashMap<_, _> = url.query_pairs().collect();

            Totp {
                account: account.map(|s| s.to_string()),
                algorithm: parts
                    .get("algorithm")
                    .and_then(|v| match v.as_ref() {
                        "sha1" => Some(TotpAlgorithm::Sha1),
                        "sha256" => Some(TotpAlgorithm::Sha256),
                        "sha512" => Some(TotpAlgorithm::Sha512),
                        _ => None,
                    })
                    .unwrap_or(DEFAULT_ALGORITHM),
                digits: parts
                    .get("digits")
                    .and_then(|v| v.parse().ok())
                    .map(|v: u32| v.clamp(0, 10))
                    .unwrap_or(DEFAULT_DIGITS),
                issuer: parts
                    .get("issuer")
                    .map(|v| v.to_string())
                    .or(issuer.map(|s| s.to_string())),
                period: parts
                    .get("period")
                    .and_then(|v| v.parse().ok())
                    .map(|v: u32| v.max(1))
                    .unwrap_or(DEFAULT_PERIOD),
                secret: decode_b32(
                    &parts
                        .get("secret")
                        .map(|v| v.to_string())
                        .ok_or(TotpError::MissingSecret)?,
                ),
            }
        } else if let Some(secret) = key.strip_prefix("steam://") {
            Totp {
                account: None,
                algorithm: TotpAlgorithm::Steam,
                digits: 5,
                issuer: None,
                period: DEFAULT_PERIOD,
                secret: decode_b32(secret),
            }
        } else {
            Totp {
                account: None,
                algorithm: DEFAULT_ALGORITHM,
                digits: DEFAULT_DIGITS,
                issuer: None,
                period: DEFAULT_PERIOD,
                secret: decode_b32(&key),
            }
        };

        Ok(params)
    }
}

impl fmt::Display for Totp {
    /// Formats the TOTP as an OTP Auth URI.
    ///
    /// Returns a steam::// URI if the algorithm is Steam.
    /// Otherwise returns an otpauth:// URI according to the Key Uri Format Specification:
    /// <https://docs.yubico.com/yesdk/users-manual/application-oath/uri-string-format.html>
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secret_b32 = BASE32_NOPAD.encode(&self.secret);

        if let TotpAlgorithm::Steam = self.algorithm {
            return write!(f, "steam://{secret_b32}");
        }

        let mut url = Url::parse("otpauth://totp").map_err(|_| fmt::Error)?;

        // Strip out colons from issuer and account
        let issuer = self.issuer.as_ref().map(|issuer| issuer.replace(":", ""));
        let account = self
            .account
            .as_ref()
            .map(|account| account.replace(":", ""));

        let encoded_issuer = issuer
            .as_ref()
            .map(|issuer| percent_encode(issuer.as_bytes(), NON_ALPHANUMERIC));

        let encoded_account = account
            .as_ref()
            .map(|account| percent_encode(account.as_bytes(), NON_ALPHANUMERIC));

        let label = match (&encoded_issuer, &encoded_account) {
            (Some(issuer), Some(account)) => format!("{issuer}:{account}"),
            (None, Some(account)) => account.to_string(),
            _ => String::new(),
        };

        url.set_path(&label);

        let mut query_params = Vec::new();
        query_params.push(format!("secret={secret_b32}"));

        if let Some(issuer) = &encoded_issuer {
            query_params.push(format!("issuer={issuer}"));
        }

        if self.period != DEFAULT_PERIOD {
            query_params.push(format!("period={}", self.period));
        }

        if self.algorithm != DEFAULT_ALGORITHM {
            query_params.push(format!("algorithm={}", self.algorithm));
        }

        if self.digits != DEFAULT_DIGITS {
            query_params.push(format!("digits={}", self.digits));
        }

        url.set_query(Some(&query_params.join("&")));
        url.fmt(f)
    }
}

/// Derive the Steam OTP from the hash with the given number of digits.
fn derive_steam_otp(binary: u32, digits: u32) -> String {
    let mut full_code = binary & 0x7fffffff;

    (0..digits)
        .map(|_| {
            let index = full_code as usize % STEAM_CHARS.len();
            let char = STEAM_CHARS
                .chars()
                .nth(index)
                .expect("Should always be within range");
            full_code /= STEAM_CHARS.len() as u32;
            char
        })
        .collect()
}

/// Derive the OTP from the hash with the given number of digits.
fn derive_binary(hash: Vec<u8>) -> u32 {
    let offset = (hash.last().unwrap_or(&0) & 15) as usize;

    (((hash[offset] & 127) as u32) << 24)
        | ((hash[offset + 1] as u32) << 16)
        | ((hash[offset + 2] as u32) << 8)
        | (hash[offset + 3] as u32)
}

/// This code is migrated from our javascript implementation and is not technically a correct base32
/// decoder since we filter out various characters, and use exact chunking.
fn decode_b32(s: &str) -> Vec<u8> {
    let s = s.to_uppercase();

    let mut bits = String::new();
    for c in s.chars() {
        if let Some(i) = BASE32_CHARS.find(c) {
            bits.push_str(&format!("{i:05b}"));
        }
    }
    let mut bytes = Vec::new();

    for chunk in bits.as_bytes().chunks_exact(8) {
        let byte_str = std::str::from_utf8(chunk).expect("The value is a valid string");
        let byte = u8::from_str_radix(byte_str, 2).expect("The value is a valid binary string");
        bytes.push(byte);
    }

    bytes
}

#[cfg(test)]
mod tests {
    use bitwarden_core::key_management::create_test_crypto_with_user_key;
    use bitwarden_crypto::SymmetricCryptoKey;
    use chrono::Utc;

    use super::*;
    use crate::{
        CipherRepromptType,
        cipher::cipher::{CipherListViewType, CopyableCipherFields},
        login::LoginListView,
    };

    #[test]
    fn test_decode_b32() {
        let res = decode_b32("WQIQ25BRKZYCJVYP");
        assert_eq!(res, vec![180, 17, 13, 116, 49, 86, 112, 36, 215, 15]);

        let res = decode_b32("ABCD123");
        assert_eq!(res, vec![0, 68, 61]);
    }

    #[test]
    fn test_generate_totp() {
        let cases = vec![
            ("WQIQ25BRKZYCJVYP", "194506"), // valid base32
            ("wqiq25brkzycjvyp", "194506"), // lowercase
            ("PIUDISEQYA", "829846"),       // non padded
            ("PIUDISEQYA======", "829846"), // padded
            ("PIUD1IS!EQYA=", "829846"),    // sanitized
            // Steam
            ("steam://HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ", "7W6CJ"),
            ("StEam://HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ", "7W6CJ"),
            ("steam://ABCD123", "N26DF"),
            // Various weird lengths
            ("ddfdf", "932653"),
            ("HJSGFJHDFDJDJKSDFD", "000034"),
            ("xvdsfasdfasdasdghsgsdfg", "403786"),
            ("KAKFJWOSFJ12NWL", "093430"),
        ];

        let time = Some(
            DateTime::parse_from_rfc3339("2023-01-01T00:00:00.000Z")
                .unwrap()
                .with_timezone(&Utc),
        );

        for (key, expected_code) in cases {
            let response = generate_totp(key.to_string(), time).unwrap();

            assert_eq!(response.code, expected_code, "wrong code for key: {key}");
            assert_eq!(response.period, 30);
        }
    }

    #[test]
    fn test_generate_otpauth() {
        let key = "otpauth://totp/test-account?secret=WQIQ25BRKZYCJVYP".to_string();
        let time = Some(
            DateTime::parse_from_rfc3339("2023-01-01T00:00:00.000Z")
                .unwrap()
                .with_timezone(&Utc),
        );
        let response = generate_totp(key, time).unwrap();

        assert_eq!(response.code, "194506".to_string());
        assert_eq!(response.period, 30);
    }

    #[test]
    fn test_generate_otpauth_no_label() {
        let key = "otpauth://totp/?secret=WQIQ25BRKZYCJVYP";
        let totp = Totp::from_str(key).unwrap();

        assert_eq!(totp.account, Some("".to_string()));
        assert_eq!(totp.issuer, None);
    }

    #[test]
    fn test_generate_otpauth_uppercase() {
        let key = "OTPauth://totp/test-account?secret=WQIQ25BRKZYCJVYP".to_string();
        let time = Some(
            DateTime::parse_from_rfc3339("2023-01-01T00:00:00.000Z")
                .unwrap()
                .with_timezone(&Utc),
        );
        let response = generate_totp(key, time).unwrap();

        assert_eq!(response.code, "194506".to_string());
        assert_eq!(response.period, 30);
    }

    #[test]
    fn test_generate_otpauth_period() {
        let key = "otpauth://totp/test-account?secret=WQIQ25BRKZYCJVYP&period=60".to_string();
        let time = Some(
            DateTime::parse_from_rfc3339("2023-01-01T00:00:00.000Z")
                .unwrap()
                .with_timezone(&Utc),
        );
        let response = generate_totp(key, time).unwrap();

        assert_eq!(response.code, "730364".to_string());
        assert_eq!(response.period, 60);
    }

    #[test]
    fn test_generate_otpauth_algorithm_sha256() {
        let key =
            "otpauth://totp/test-account?secret=WQIQ25BRKZYCJVYP&algorithm=SHA256".to_string();
        let time = Some(
            DateTime::parse_from_rfc3339("2023-01-01T00:00:00.000Z")
                .unwrap()
                .with_timezone(&Utc),
        );
        let response = generate_totp(key, time).unwrap();

        assert_eq!(response.code, "842615".to_string());
        assert_eq!(response.period, 30);
    }

    #[test]
    fn test_parse_totp_label_no_issuer() {
        // If there is only one value in the label, it is the account
        let key = "otpauth://totp/test-account@example.com?secret=WQIQ25BRKZYCJVYP";
        let totp = Totp::from_str(key).unwrap();

        assert_eq!(totp.account, Some("test-account@example.com".to_string()));
        assert_eq!(totp.issuer, None);
    }

    #[test]
    fn test_parse_totp_label_with_issuer() {
        // If there are two values in the label, the first is the issuer, the second is the account
        let key = "otpauth://totp/test-issuer:test-account@example.com?secret=WQIQ25BRKZYCJVYP";
        let totp = Totp::from_str(key).unwrap();

        assert_eq!(totp.account, Some("test-account@example.com".to_string()));
        assert_eq!(totp.issuer, Some("test-issuer".to_string()));
    }

    #[test]
    fn test_parse_totp_label_two_issuers() {
        // If the label has an issuer and there is an issuer parameter, the parameter is chosen as
        // the issuer
        let key = "otpauth://totp/test-issuer:test-account@example.com?secret=WQIQ25BRKZYCJVYP&issuer=other-test-issuer";
        let totp = Totp::from_str(key).unwrap();

        assert_eq!(totp.account, Some("test-account@example.com".to_string()));
        assert_eq!(totp.issuer, Some("other-test-issuer".to_string()));
    }

    #[test]
    fn test_parse_totp_label_encoded_colon() {
        // A url-encoded colon is a valid separator
        let key = "otpauth://totp/test-issuer%3Atest-account@example.com?secret=WQIQ25BRKZYCJVYP&issuer=test-issuer";
        let totp = Totp::from_str(key).unwrap();

        assert_eq!(totp.account, Some("test-account@example.com".to_string()));
        assert_eq!(totp.issuer, Some("test-issuer".to_string()));
    }

    #[test]
    fn test_parse_totp_label_encoded_characters() {
        // The account and issuer can both be URL-encoded
        let key = "otpauth://totp/test%20issuer:test-account%40example%2Ecom?secret=WQIQ25BRKZYCJVYP&issuer=test%20issuer";
        let totp = Totp::from_str(key).unwrap();

        assert_eq!(totp.account, Some("test-account@example.com".to_string()));
        assert_eq!(totp.issuer, Some("test issuer".to_string()));
    }

    #[test]
    fn test_parse_totp_label_account_spaces() {
        // The account can have spaces before it
        let key = "otpauth://totp/test-issuer:   test-account@example.com?secret=WQIQ25BRKZYCJVYP&issuer=test-issuer";
        let totp = Totp::from_str(key).unwrap();

        assert_eq!(totp.account, Some("test-account@example.com".to_string()));
        assert_eq!(totp.issuer, Some("test-issuer".to_string()));
    }

    #[test]
    fn test_totp_to_string_strips_colons() {
        let totp = Totp {
            account: Some("test:account@bitwarden.com".to_string()),
            algorithm: DEFAULT_ALGORITHM,
            digits: DEFAULT_DIGITS,
            issuer: Some("Acme:Inc".to_string()),
            period: DEFAULT_PERIOD,
            secret: decode_b32("WQIQ25BRKZYCJVYP"),
        };

        let uri = totp.to_string();

        // Verify colons are stripped from both issuer and account in the URI
        assert!(!uri.contains("Acme:Inc"));
        assert!(!uri.contains("test:account"));

        // Verify that the stripped colons are replaced
        assert!(uri.contains("AcmeInc"));
        assert!(uri.contains("testaccount"));

        let parsed = Totp::from_str(&uri).unwrap();
        // Verify parsed values have colon removed
        assert_eq!(parsed.issuer.unwrap(), "acmeinc");
        assert_eq!(parsed.account.unwrap(), "testaccount@bitwarden.com");
    }

    #[test]
    fn test_totp_to_string_with_defaults() {
        let totp = Totp {
            account: Some("test@bitwarden.com".to_string()),
            algorithm: DEFAULT_ALGORITHM,
            digits: DEFAULT_DIGITS,
            issuer: Some("Example".to_string()),
            period: DEFAULT_PERIOD,
            secret: decode_b32("WQIQ25BRKZYCJVYP"),
        };

        assert_eq!(
            totp.to_string(),
            "otpauth://totp/Example:test%40bitwarden%2Ecom?secret=WQIQ25BRKZYCJVYP&issuer=Example"
        );
    }

    #[test]
    fn test_totp_to_string_with_custom_period() {
        let totp = Totp {
            account: Some("test@bitwarden.com".to_string()),
            algorithm: DEFAULT_ALGORITHM,
            digits: DEFAULT_DIGITS,
            issuer: Some("Example".to_string()),
            period: 60,
            secret: decode_b32("WQIQ25BRKZYCJVYP"),
        };

        assert_eq!(
            totp.to_string(),
            "otpauth://totp/Example:test%40bitwarden%2Ecom?secret=WQIQ25BRKZYCJVYP&issuer=Example&period=60"
        );
    }

    #[test]
    fn test_totp_to_string_sha256() {
        let totp = Totp {
            account: Some("test@bitwarden.com".to_string()),
            algorithm: TotpAlgorithm::Sha256,
            digits: DEFAULT_DIGITS,
            issuer: Some("Example".to_string()),
            period: DEFAULT_PERIOD,
            secret: decode_b32("WQIQ25BRKZYCJVYP"),
        };

        assert_eq!(
            totp.to_string(),
            "otpauth://totp/Example:test%40bitwarden%2Ecom?secret=WQIQ25BRKZYCJVYP&issuer=Example&algorithm=SHA256"
        );
    }

    #[test]
    fn test_totp_to_string_encodes_spaces_in_issuer() {
        let totp = Totp {
            account: Some("test@bitwarden.com".to_string()),
            algorithm: DEFAULT_ALGORITHM,
            digits: DEFAULT_DIGITS,
            issuer: Some("Acme Inc".to_string()),
            period: DEFAULT_PERIOD,
            secret: decode_b32("WQIQ25BRKZYCJVYP"),
        };

        assert_eq!(
            totp.to_string(),
            "otpauth://totp/Acme%20Inc:test%40bitwarden%2Ecom?secret=WQIQ25BRKZYCJVYP&issuer=Acme%20Inc"
        );
    }

    #[test]
    fn test_totp_to_string_encodes_special_characters_in_issuer() {
        let totp = Totp {
            account: Some("test@bitwarden.com".to_string()),
            algorithm: DEFAULT_ALGORITHM,
            digits: DEFAULT_DIGITS,
            issuer: Some("Acme & Inc".to_string()),
            period: DEFAULT_PERIOD,
            secret: decode_b32("WQIQ25BRKZYCJVYP"),
        };

        assert_eq!(
            totp.to_string(),
            "otpauth://totp/Acme%20%26%20Inc:test%40bitwarden%2Ecom?secret=WQIQ25BRKZYCJVYP&issuer=Acme%20%26%20Inc"
        );
    }

    #[test]
    fn test_totp_to_string_no_issuer() {
        let totp = Totp {
            account: Some("test@bitwarden.com".to_string()),
            algorithm: DEFAULT_ALGORITHM,
            digits: DEFAULT_DIGITS,
            issuer: None,
            period: DEFAULT_PERIOD,
            secret: decode_b32("WQIQ25BRKZYCJVYP"),
        };

        assert_eq!(
            totp.to_string(),
            "otpauth://totp/test%40bitwarden%2Ecom?secret=WQIQ25BRKZYCJVYP"
        )
    }

    #[test]
    fn test_totp_to_string_parse_roundtrip_with_special_chars() {
        let original = Totp {
            account: Some("test+acount@bitwarden.com".to_string()),
            algorithm: DEFAULT_ALGORITHM,
            digits: DEFAULT_DIGITS,
            issuer: Some("Acme & Inc".to_string()),
            period: DEFAULT_PERIOD,
            secret: decode_b32("WQIQ25BRKZYCJVYP"),
        };

        let uri = original.to_string();
        let parsed = Totp::from_str(&uri).unwrap();

        assert!(
            parsed
                .account
                .unwrap()
                .eq_ignore_ascii_case(&original.account.unwrap())
        );
        assert!(
            parsed
                .issuer
                .unwrap()
                .eq_ignore_ascii_case(&original.issuer.unwrap())
        );
        assert_eq!(parsed.algorithm, original.algorithm);
        assert_eq!(parsed.digits, original.digits);
        assert_eq!(parsed.period, original.period);
        assert_eq!(parsed.secret, original.secret);
    }

    #[test]
    fn test_display_steam() {
        let totp = Totp {
            account: None,
            algorithm: TotpAlgorithm::Steam,
            digits: 5,
            issuer: None,
            period: DEFAULT_PERIOD,
            secret: vec![1, 2, 3, 4],
        };
        let secret_b32 = BASE32_NOPAD.encode(&totp.secret);
        assert_eq!(totp.to_string(), format!("steam://{secret_b32}"));
    }

    #[test]
    fn test_generate_totp_cipher_view() {
        let view = CipherListView {
            id: Some("090c19ea-a61a-4df6-8963-262b97bc6266".parse().unwrap()),
            organization_id: None,
            folder_id: None,
            collection_ids: vec![],
            key: None,
            name: "My test login".to_string(),
            subtitle: "test_username".to_string(),
            r#type: CipherListViewType::Login(LoginListView{
                fido2_credentials: None,
                has_fido2: true,
                username: None,
                totp: Some("2.hqdioUAc81FsKQmO1XuLQg==|oDRdsJrQjoFu9NrFVy8tcJBAFKBx95gHaXZnWdXbKpsxWnOr2sKipIG43pKKUFuq|3gKZMiboceIB5SLVOULKg2iuyu6xzos22dfJbvx0EHk=".parse().unwrap()),
                uris: None,
            }),
            favorite: false,
            reprompt: CipherRepromptType::None,
            organization_use_totp: true,
            edit: true,
            permissions: None,
            view_password: true,
            attachments: 0,
            has_old_attachments: false,
            creation_date: "2024-01-30T17:55:36.150Z".parse().unwrap(),
            deleted_date: None,
            revision_date: "2024-01-30T17:55:36.150Z".parse().unwrap(),
            copyable_fields: vec![CopyableCipherFields::LoginTotp],
            local_data: None,
            archived_date: None,
        };

        let key = SymmetricCryptoKey::try_from("w2LO+nwV4oxwswVYCxlOfRUseXfvU03VzvKQHrqeklPgiMZrspUe6sOBToCnDn9Ay0tuCBn8ykVVRb7PWhub2Q==".to_string()).unwrap();
        let key_store = create_test_crypto_with_user_key(key);

        let time = DateTime::parse_from_rfc3339("2023-01-01T00:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc);

        let response =
            generate_totp_cipher_view(&mut key_store.context(), view, Some(time)).unwrap();
        assert_eq!(response.code, "559388".to_string());
        assert_eq!(response.period, 30);
    }
}
