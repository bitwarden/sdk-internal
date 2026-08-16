//! HKDF-SHA256, PBES2 (PBKDF2-HS256), and master-key derivation.

use std::borrow::Cow;

use data_encoding::BASE64URL_NOPAD;
use hkdf::Hkdf;
use hmac::Hmac;
use icu_normalizer::DecomposingNormalizer;
use sha2::{Digest, Sha256};

use super::{account_key::AccountKey, error::OnePasswordError};

/// HKDF-SHA256 producing 32 bytes, with `method` as the `info` parameter.
pub(super) fn hkdf_sha256(method: &str, ikm: &[u8], salt: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; 32];
    hk.expand(method.as_bytes(), &mut okm)
        .expect("okm is a fixed 32 bytes, under HKDF's 255-block limit");
    okm
}

/// Rejects a PBES2 method this module cannot honour.
///
/// The web client only implements the SHA-256 variants and throws `Invalid PBKDF2 alg` on anything
/// else, so an `*-HS512` method is rejected rather than guessed at. Both the master keyset and the
/// SRP parameters carry one of these, from different responses, so both have to check.
pub(super) fn validate_pbes2(method: &str) -> Result<(), OnePasswordError> {
    match matches!(method, "PBES2-HS256" | "PBES2g-HS256") {
        true => Ok(()),
        false => Err(OnePasswordError::Unsupported(format!(
            "Method '{method}' is not supported"
        ))),
    }
}

/// PBKDF2-HMAC-SHA256 producing 32 bytes. Callers check the method first.
pub(super) fn pbes2(password: &str, salt: &[u8], iterations: u32) -> [u8; 32] {
    pbkdf2::pbkdf2_array::<Hmac<Sha256>, 32>(password.as_bytes(), salt, iterations)
        .expect("HMAC accepts any password length")
}

pub(super) fn normalize_password(password: &str) -> Cow<'_, str> {
    DecomposingNormalizer::new_nfkd().normalize(password.trim())
}

pub(super) fn normalize_username(username: &str) -> String {
    username.trim().to_lowercase()
}

/// The only place the email is decomposed, not just trimmed and lowercased.
pub(super) fn normalize_identity_username(username: &str) -> String {
    DecomposingNormalizer::new_nfkd()
        .normalize(username.trim())
        .to_lowercase()
}

/// The legacy `PBES2-` stand-in for the password, hashed raw and never normalized.
fn legacy_password(username: &str, password: &str) -> String {
    let digest = match password.is_empty() {
        true => String::new(),
        false => BASE64URL_NOPAD.encode(&Sha256::digest(password.as_bytes())),
    };
    format!("{username}:{digest}")
}

/// Derives the 32-byte master unlock key (kid `"mp"`), dispatching on the algorithm prefix the way
/// the web client's `Auk.deriveKdfBytes` does.
pub(super) fn derive_master_key(
    algorithm: &str,
    iterations: u32,
    salt: &[u8],
    username: &str,
    password: &str,
    account_key: &AccountKey,
) -> Result<[u8; 32], OnePasswordError> {
    validate_pbes2(algorithm)?;

    let username = normalize_username(username);

    // The legacy algorithm has never been observed in the wild, but the web client still implements
    // it.
    let is_legacy = algorithm.starts_with("PBES2-");

    let k1;
    let salt = if is_legacy {
        salt
    } else {
        k1 = hkdf_sha256(algorithm, salt, username.as_bytes());
        &k1
    };

    let password = if is_legacy {
        legacy_password(&username, password)
    } else {
        normalize_password(password).into_owned()
    };

    let k2 = pbes2(&password, salt, iterations);

    account_key.combine_with(&k2)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
    use serde::Deserialize;

    use super::*;

    /// Vectors from `fixtures/generate-master-key-vectors.mjs`, which mirrors the 1P web client.
    #[derive(Deserialize)]
    struct Vectors {
        params: VectorParams,
        cases: Vec<Vector>,
    }

    #[derive(Deserialize)]
    struct VectorParams {
        username: String,
        account_key: String,
        salt_b64url: String,
        iterations: u32,
    }

    #[derive(Deserialize)]
    struct Vector {
        name: String,
        password: String,
        password_hex: String,
        normalized_hex: String,
        keys: BTreeMap<String, String>,
    }

    fn vectors() -> Vectors {
        serde_json::from_str(include_str!("fixtures/master-key-vectors.json"))
            .expect("the vectors parse")
    }

    #[test]
    fn vector_passwords_survived_the_trip_through_the_json_file() {
        for case in vectors().cases {
            assert_eq!(
                HEXLOWER.encode(case.password.as_bytes()),
                case.password_hex,
                "{} was rewritten in the fixture",
                case.name
            );
        }
    }

    #[test]
    fn normalize_password_matches_the_web_client() {
        for case in vectors().cases {
            assert_eq!(
                HEXLOWER.encode(normalize_password(&case.password).as_bytes()),
                case.normalized_hex,
                "{}",
                case.name
            );
        }
    }

    fn derive_vector(params: &VectorParams, case: &Vector, algorithm: &str) -> [u8; 32] {
        let salt = BASE64URL_NOPAD
            .decode(params.salt_b64url.as_bytes())
            .expect("valid salt");
        let account_key = AccountKey::parse(&params.account_key).expect("valid account key");

        derive_master_key(
            algorithm,
            params.iterations,
            &salt,
            &params.username,
            &case.password,
            &account_key,
        )
        .expect("derivation succeeds")
    }

    #[test]
    fn derive_master_key_matches_the_web_client() {
        let Vectors { params, cases } = vectors();
        for case in &cases {
            assert!(!case.keys.is_empty(), "{} has no keys", case.name);
            for (algorithm, expected) in &case.keys {
                assert_eq!(
                    &HEXLOWER.encode(&derive_vector(&params, case, algorithm)),
                    expected,
                    "{} with {algorithm}",
                    case.name
                );
            }
        }
    }

    /// `PBES2g-` normalizes, so the same password typed two ways unlocks the same account. The
    /// legacy prefix hashes the raw bytes instead, and stays sensitive to the spelling. Catches
    /// skipping normalization entirely, which is what `compute_x` used to do.
    #[test]
    fn only_the_modern_prefix_is_blind_to_the_unicode_spelling() {
        let Vectors { params, cases } = vectors();
        let find = |name: &str| {
            cases
                .iter()
                .find(|case| case.name == name)
                .unwrap_or_else(|| panic!("{name} is in the fixture"))
        };
        let precomposed = find("precomposed_e_acute");
        let decomposed = find("decomposed_e_acute");

        assert_ne!(precomposed.password_hex, decomposed.password_hex);
        for algorithm in precomposed.keys.keys() {
            let one = derive_vector(&params, precomposed, algorithm);
            let other = derive_vector(&params, decomposed, algorithm);
            match algorithm.starts_with("PBES2g-") {
                true => assert_eq!(one, other, "{algorithm}"),
                false => assert_ne!(one, other, "{algorithm}"),
            }
        }
    }

    #[test]
    fn normalize_username_trims_and_lowercases() {
        assert_eq!(
            normalize_username("  Test.User@Example.COM \n"),
            "test.user@example.com"
        );
    }

    /// Unlike the HKDF salt, the identity also decomposes, and only then lowercases.
    #[test]
    fn normalize_identity_username_also_decomposes() {
        assert_eq!(
            HEXLOWER.encode(normalize_identity_username(" CAF\u{e9}@x.com ").as_bytes()),
            HEXLOWER.encode("cafe\u{301}@x.com".as_bytes())
        );
    }

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
        assert_eq!(
            BASE64URL_NOPAD.encode(&pbes2("password", b"salt", 100)),
            "B-aZcYDPfxKQTwQQDUBdNIiP32KvbVBqDswjsZb-mdg"
        );
    }

    /// The web client throws `Invalid PBKDF2 alg` on these, so we do not guess at them either.
    #[test]
    fn derive_master_key_throws_on_unsupported_method() {
        let account_key =
            AccountKey::parse("A3-RTN9SA-DY9445Y5FF96X6E7B5GPFA95R9").expect("valid account key");
        for algorithm in ["PBES2-HS512", "PBES2g-HS512", "SRPg-4096", "Unknown", ""] {
            let err = derive_master_key(algorithm, 100, b"salt", "user", "pw", &account_key)
                .expect_err("unsupported");
            assert!(matches!(err, OnePasswordError::Unsupported(_)));
            assert!(err.to_string().contains("is not supported"));
        }
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
