//! RSA-OAEP (SHA1/SHA256) decrypt from 1Password's JWK.
//!
//! This module shares its name with the external `rsa` crate, so inside the crate the dependency is
//! reached as `::rsa`.

use ::rsa::{BoxedUint, Oaep, RsaPrivateKey};
use sha1::Sha1;
use sha2::Sha256;

use super::{
    error::OnePasswordError,
    opdata::{Encrypted, decode64_loose},
    wire::RsaKeyJwk,
};

const OAEP_SHA1: &str = "RSA-OAEP";
const OAEP_SHA256: &str = "RSA-OAEP-256";

/// An RSA private key identified by its kid.
pub(super) struct RsaKey {
    pub id: String,
    key: RsaPrivateKey,
}

impl RsaKey {
    /// Builds the private key from the base64 JWK components.
    pub(super) fn parse(jwk: &RsaKeyJwk) -> Result<RsaKey, OnePasswordError> {
        let uint = |s: &str| -> Result<BoxedUint, OnePasswordError> {
            Ok(BoxedUint::from_be_slice_vartime(&decode64_loose(s)?))
        };

        let key = RsaPrivateKey::from_components(
            uint(&jwk.n)?,
            uint(&jwk.e)?,
            uint(&jwk.d)?,
            vec![uint(&jwk.p)?, uint(&jwk.q)?],
        )
        .map_err(|_| OnePasswordError::Internal("invalid RSA key".into()))?;

        Ok(RsaKey {
            id: jwk.kid.clone(),
            key,
        })
    }

    /// Decrypts an envelope encrypted for this key, dispatching on the OAEP scheme.
    pub(super) fn decrypt(&self, encrypted: &Encrypted) -> Result<Vec<u8>, OnePasswordError> {
        if encrypted.key_id != self.id {
            return Err(OnePasswordError::Internal("mismatching key id".into()));
        }

        let result = match encrypted.scheme.as_str() {
            OAEP_SHA1 => self.key.decrypt(Oaep::<Sha1>::new(), &encrypted.ciphertext),
            OAEP_SHA256 => self
                .key
                .decrypt(Oaep::<Sha256>::new(), &encrypted.ciphertext),
            other => {
                return Err(OnePasswordError::Internal(format!(
                    "invalid encryption scheme '{other}'"
                )));
            }
        };

        result.map_err(|_| OnePasswordError::Decryption)
    }
}

#[cfg(test)]
mod tests {
    use data_encoding::BASE64;

    use super::*;

    const SHA1_CIPHERTEXT: &str = "plF49e+3R0IpxBqWinosrPxWS8GdzKULvo4myIS1Gam5LCl1TmvvtntAiwOaL+/x8Ie7JApxksrpzrg9UAIaJeOJcoSzPA/hT4nn2jnglWLt+Dwz6RiEyQXhHqnyEOZ56RhNrVR8qKrnApUX2J/FWmrSYXQduIM2xbbx1LQwCGJJxCHp/pFf3Eb0fwtaw2AB5QEF5uTXOnOY+NYaPUJLKTX63uas+uPGUtdJP66WT15zHEK/WRx4ekafJvIjueSTaiceq+IVXc5niMzTMYvRb5rIEiNm3WSX7EteqaU9T46ytm9748ILQNeuGSjzIqhO4H7mO47/e8wdEh3WZk8Alg==";
    const SHA256_CIPHERTEXT: &str = "R2wRx7neV9M/hMyWhr6heE43Q48xL+6lZuy9k03+G0FVPmXsVPRK4q7nWq6UDVwcj42nxMychMKfurCuecLEd+h5zum9Py9y6r702GnymQAl0ReM6NyjxW2m1YOp6zFVlqa69Tptn+ewOD1Fqr14yJTgVtcSJCKjQxI0ALrFst/tMvOjMFFtYPCsQ3oC0ka7kDnjbikOD0AL7Q6/19Nilr3C/TjQdNRC1Y3c5sKtyDZj++OkwgB2nac1V9IfLbpum5nqQim4UBOwE8f1axTDSYtKLJ31rr+z5bHxraUMzz96BnOmIzsZ2jj0fHrZBsBUs1L5Bg5XmGwHTz01z4HQ9A==";

    fn key(fixture: &str) -> RsaKey {
        let jwk: RsaKeyJwk = serde_json::from_str(fixture).expect("valid jwk");
        RsaKey::parse(&jwk).expect("valid key")
    }

    fn envelope(key_id: &str, scheme: &str, ciphertext: Vec<u8>) -> Encrypted {
        Encrypted {
            key_id: key_id.into(),
            scheme: scheme.into(),
            iv: Vec::new(),
            ciphertext,
        }
    }

    #[test]
    fn parses_sha1_key() {
        assert_eq!(
            key(include_str!("fixtures/rsa-key.json")).id,
            "szerdhg2ww2ahjo4ilz57x7cce"
        );
    }

    #[test]
    fn parses_sha256_key() {
        assert_eq!(
            key(include_str!("fixtures/rsa-key-oaep-256.json")).id,
            "sfaijsnbchbtznlar7mx6yrhae"
        );
    }

    #[test]
    fn decrypts_oaep_sha1() {
        let key = key(include_str!("fixtures/rsa-key.json"));
        let ciphertext = BASE64.decode(SHA1_CIPHERTEXT.as_bytes()).expect("base64");
        let encrypted = envelope("szerdhg2ww2ahjo4ilz57x7cce", "RSA-OAEP", ciphertext);
        let plain = key.decrypt(&encrypted).expect("decrypts");
        assert_eq!(plain, b"All your base are belong to us");
    }

    #[test]
    fn decrypts_oaep_sha256() {
        let key = key(include_str!("fixtures/rsa-key-oaep-256.json"));
        let ciphertext = BASE64.decode(SHA256_CIPHERTEXT.as_bytes()).expect("base64");
        let encrypted = envelope("sfaijsnbchbtznlar7mx6yrhae", "RSA-OAEP-256", ciphertext);
        let plain = key.decrypt(&encrypted).expect("decrypts");
        assert_eq!(plain, b"All your base are belong to us");
    }

    #[test]
    fn rejects_mismatching_key_id() {
        let key = key(include_str!("fixtures/rsa-key.json"));
        let encrypted = envelope("invalid-id", "RSA-OAEP", b"ciphertext".to_vec());
        let err = key.decrypt(&encrypted).expect_err("mismatch");
        assert!(err.to_string().contains("mismatching key id"));
    }
}
