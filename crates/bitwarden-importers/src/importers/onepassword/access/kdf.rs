//! HKDF-SHA256, PBES2 (PBKDF2 HS256/HS512), and master-key derivation.

use hkdf::Hkdf;
use hmac::Hmac;
use icu_normalizer::ComposingNormalizer;
use sha2::{Sha256, Sha512};

use super::{account_key::AccountKey, error::OnePasswordError};

/// HKDF-SHA256 producing 32 bytes, with `method` as the `info` parameter.
pub fn hkdf_sha256(method: &str, ikm: &[u8], salt: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; 32];
    hk.expand(method.as_bytes(), &mut okm)
        .expect("okm is a fixed 32 bytes, under HKDF's 255-block limit");
    okm
}

/// PBES2 key derivation dispatching on the JWK method name.
///
/// `PBES2[g]-HS256` uses PBKDF2-HMAC-SHA256, `PBES2[g]-HS512` uses PBKDF2-HMAC-SHA512, both 32
/// bytes.
pub fn pbes2(
    method: &str,
    password: &str,
    salt: &[u8],
    iterations: u32,
) -> Result<[u8; 32], OnePasswordError> {
    let password = password.as_bytes();
    let derived = match method {
        "PBES2-HS256" | "PBES2g-HS256" => {
            pbkdf2::pbkdf2_array::<Hmac<Sha256>, 32>(password, salt, iterations)
        }
        "PBES2-HS512" | "PBES2g-HS512" => {
            pbkdf2::pbkdf2_array::<Hmac<Sha512>, 32>(password, salt, iterations)
        }
        _ => {
            return Err(OnePasswordError::Unsupported(format!(
                "Method '{method}' is not supported"
            )));
        }
    };

    Ok(derived.expect("HMAC accepts any password length"))
}

/// Derives the 32-byte master unlock key (kid `"mp"`).
///
/// `k1 = HKDF(info = algorithm, ikm = salt, salt = lower(username))`; `k2 = PBES2(algorithm,
/// NFC(password), k1, iterations)`; result `= account_key.combine_with(k2)`.
pub fn derive_master_key(
    algorithm: &str,
    iterations: u32,
    salt: &[u8],
    username: &str,
    password: &str,
    account_key: &AccountKey,
) -> Result<[u8; 32], OnePasswordError> {
    let k1 = hkdf_sha256(algorithm, salt, username.to_lowercase().as_bytes());
    let normalized = ComposingNormalizer::new_nfc().normalize(password);
    let k2 = pbes2(algorithm, &normalized, &k1, iterations)?;
    account_key.combine_with(&k2)
}

#[cfg(test)]
mod tests {
    use data_encoding::{BASE64URL_NOPAD, HEXLOWER};

    use super::*;

    #[test]
    fn hkdf_returns_derived_key() {
        let derived = hkdf_sha256("PBES2g-HS256", b"ikm", b"salt");
        assert_eq!(
            BASE64URL_NOPAD.encode(&derived),
            "UybCHXHHQRaFxUUR3G2ZO9CJ0H2eWJ1Ik_MpNQHrHdE"
        );
    }

    #[test]
    fn pbes2_returns_derived_key() {
        let cases = [
            (
                "PBES2g-HS256",
                "B-aZcYDPfxKQTwQQDUBdNIiP32KvbVBqDswjsZb-mdg",
            ),
            (
                "PBES2g-HS512",
                "_vcnaxBwQKCnE7y-yf0-GRzGFTJJ4kWj4aIgh9vmFgY",
            ),
        ];
        for (method, expected) in cases {
            let key = pbes2(method, "password", b"salt", 100).expect("supported method");
            assert_eq!(BASE64URL_NOPAD.encode(&key), expected);
        }
    }

    #[test]
    fn pbes2_throws_on_unsupported_method() {
        let err = pbes2("Unknown", "password", b"salt", 100).expect_err("unsupported");
        assert!(matches!(err, OnePasswordError::Unsupported(_)));
        assert!(err.to_string().contains("is not supported"));
    }

    #[test]
    fn derive_master_key_returns_master_key() {
        let salt = BASE64URL_NOPAD
            .decode(b"i2enf0xq-XPKCFFf5UZqNQ")
            .expect("valid salt");
        let account_key =
            AccountKey::parse("A3-RTN9SA-DY9445Y5FF96X6E7B5GPFA95R9").expect("valid account key");

        let key = derive_master_key(
            "PBES2g-HS256",
            100000,
            &salt,
            "username",
            "password",
            &account_key,
        )
        .expect("derivation succeeds");

        assert_eq!(
            HEXLOWER.encode(&key),
            "09f6cf6acc4f64f2ac6af5d912427253c4dd5e1a48dfc6bfea21df8f6d3a701e"
        );
    }
}
