//! AES-256-GCM "opdata" envelope with the tag appended after the ciphertext.
//!
//! Built on the `aes-gcm` crate and validated below against the IEEE 802.1 GCM test vectors. The
//! tag is the trailing 16 bytes of the ciphertext, exactly as `aes-gcm` lays it out.

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Nonce, Payload},
};
use data_encoding::BASE64URL_NOPAD;
use zeroize::Zeroize;

use super::{error::OnePasswordError, wire::EncryptedEnvelope};

const ENCRYPTION_SCHEME: &str = "A256GCM";
const CONTAINER_TYPE: &str = "b5+jwk+json";

/// AES-256-GCM encrypt, returning `ciphertext || tag`.
pub(super) fn encrypt(
    key: &[u8],
    plaintext: &[u8],
    iv: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, OnePasswordError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| OnePasswordError::Internal("the key must be 32 bytes long".into()))?;
    let nonce = Nonce::<Aes256Gcm>::try_from(iv)
        .map_err(|_| OnePasswordError::Internal("the iv must be 12 bytes long".into()))?;
    cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| OnePasswordError::Internal("AES-GCM encryption failed".into()))
}

/// AES-256-GCM decrypt of `ciphertext || tag`.
pub(super) fn decrypt(
    key: &[u8],
    ciphertext: &[u8],
    iv: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, OnePasswordError> {
    if ciphertext.len() < 16 {
        return Err(OnePasswordError::Internal(
            "the ciphertext must be at least 16 bytes long".into(),
        ));
    }
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| OnePasswordError::Internal("the key must be 32 bytes long".into()))?;
    let nonce = Nonce::<Aes256Gcm>::try_from(iv)
        .map_err(|_| OnePasswordError::Internal("the iv must be 12 bytes long".into()))?;
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| OnePasswordError::Internal("the auth tag doesn't match".into()))
}

/// A decoded envelope: base64 fields turned into bytes.
///
/// The envelope's container type (`cty`) is dropped: nothing dispatches on it.
#[derive(Debug)]
pub(super) struct Encrypted {
    pub key_id: String,
    pub scheme: String,
    pub iv: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl Encrypted {
    /// Decodes the base64 `iv`/`data` fields (the `iv` is optional).
    pub(super) fn parse(envelope: &EncryptedEnvelope) -> Result<Encrypted, OnePasswordError> {
        Ok(Encrypted {
            key_id: envelope.kid.clone(),
            scheme: envelope.enc.clone(),
            iv: match &envelope.iv {
                Some(iv) => decode64_loose(iv)?,
                None => Vec::new(),
            },
            ciphertext: decode64_loose(&envelope.data)?,
        })
    }
}

/// A symmetric AES-256-GCM key identified by its kid.
pub(super) struct AesKey {
    pub id: String,
    pub key: Vec<u8>,
}

impl Drop for AesKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl AesKey {
    pub(super) fn new(id: impl Into<String>, key: Vec<u8>) -> AesKey {
        AesKey { id: id.into(), key }
    }

    /// Encrypts `plaintext` into a wire envelope using the given 12-byte IV and empty associated
    /// data.
    pub(super) fn encrypt(
        &self,
        plaintext: &[u8],
        iv: &[u8],
    ) -> Result<EncryptedEnvelope, OnePasswordError> {
        let ciphertext = encrypt(&self.key, plaintext, iv, &[])?;
        Ok(EncryptedEnvelope {
            kid: self.id.clone(),
            enc: ENCRYPTION_SCHEME.to_string(),
            cty: CONTAINER_TYPE.to_string(),
            iv: Some(BASE64URL_NOPAD.encode(iv)),
            data: BASE64URL_NOPAD.encode(&ciphertext),
        })
    }

    /// Decrypts an envelope encrypted for this key, with empty associated data.
    pub(super) fn decrypt(&self, encrypted: &Encrypted) -> Result<Vec<u8>, OnePasswordError> {
        if encrypted.key_id != self.id {
            return Err(OnePasswordError::Internal("mismatching key id".into()));
        }
        if encrypted.scheme != ENCRYPTION_SCHEME {
            return Err(OnePasswordError::Internal(format!(
                "invalid encryption scheme '{}', expected '{ENCRYPTION_SCHEME}'",
                encrypted.scheme
            )));
        }
        decrypt(&self.key, &encrypted.ciphertext, &encrypted.iv, &[])
    }
}

/// Decodes URL-safe, standard, or mixed base64 with or without padding.
pub(super) fn decode64_loose(s: &str) -> Result<Vec<u8>, OnePasswordError> {
    let normalized: String = s
        .trim_end_matches('=')
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    data_encoding::BASE64_NOPAD
        .decode(normalized.as_bytes())
        .map_err(|_| OnePasswordError::Parse)
}

#[cfg(test)]
mod tests {
    use data_encoding::HEXLOWER;

    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        HEXLOWER.decode(s.as_bytes()).expect("valid hex")
    }

    // Test vectors from
    // http://www.ieee802.org/1/files/public/docs2011/bn-randall-test-vectors-0511-v1.pdf
    struct Vector {
        key: &'static str,
        plaintext: &'static str,
        iv: &'static str,
        adata: &'static str,
        ciphertext: &'static str,
        tag: &'static str,
    }

    const VECTORS: &[Vector] = &[
        Vector {
            key: "e3c08a8f06c6e3ad95a70557b23f75483ce33021a9c72b7025666204c69c0b72",
            plaintext: "",
            iv: "12153524c0895e81b2c28465",
            adata: "d609b1f056637a0d46df998d88e5222ab2c2846512153524c0895e8108000f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233340001",
            ciphertext: "",
            tag: "2f0bc5af409e06d609ea8b7d0fa5ea50",
        },
        Vector {
            key: "e3c08a8f06c6e3ad95a70557b23f75483ce33021a9c72b7025666204c69c0b72",
            plaintext: "08000f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a0002",
            iv: "12153524c0895e81b2c28465",
            adata: "d609b1f056637a0d46df998d88e52e00b2c2846512153524c0895e81",
            ciphertext: "e2006eb42f5277022d9b19925bc419d7a592666c925fe2ef718eb4e308efeaa7c5273b394118860a5be2a97f56ab7836",
            tag: "5ca597cdbb3edb8d1a1151ea0af7b436",
        },
        Vector {
            key: "691d3ee909d7f54167fd1ca0b5d769081f2bde1aee655fdbab80bd5295ae6be7",
            plaintext: "08000f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233340004",
            iv: "f0761e8dcd3d000176d457ed",
            adata: "e20106d7cd0df0761e8dcd3d88e54c2a76d457ed",
            ciphertext: "c1623f55730c93533097addad25664966125352b43adacbd61c5ef3ac90b5bee929ce4630ea79f6ce519",
            tag: "12af39c2d1fdc2051f8b7b3c9d397ef2",
        },
    ];

    #[test]
    fn encrypt_returns_ciphertext() {
        for v in VECTORS {
            let out = encrypt(&hex(v.key), &hex(v.plaintext), &hex(v.iv), &hex(v.adata))
                .expect("encrypt succeeds");
            assert_eq!(out, hex(&format!("{}{}", v.ciphertext, v.tag)));
        }
    }

    #[test]
    fn decrypt_returns_plaintext() {
        for v in VECTORS {
            let ciphertext = hex(&format!("{}{}", v.ciphertext, v.tag));
            let out = decrypt(&hex(v.key), &ciphertext, &hex(v.iv), &hex(v.adata))
                .expect("decrypt succeeds");
            assert_eq!(out, hex(v.plaintext));
        }
    }

    #[test]
    fn decrypt_throws_on_modified_ciphertext() {
        let v = &VECTORS[1];
        let mut ciphertext = hex(&format!("{}{}", v.ciphertext, v.tag));
        ciphertext[0] ^= 1;
        let err =
            decrypt(&hex(v.key), &ciphertext, &hex(v.iv), &hex(v.adata)).expect_err("tampered");
        assert!(err.to_string().contains("auth tag"));
    }

    #[test]
    fn rejects_invalid_lengths() {
        let msg = |r: Result<Vec<u8>, OnePasswordError>| r.expect_err("invalid").to_string();
        assert!(msg(encrypt(&[0; 13], &[0; 16], &[0; 12], &[])).contains("key must"));
        assert!(msg(encrypt(&[0; 32], &[0; 16], &[0; 13], &[])).contains("iv must"));
        assert!(msg(decrypt(&[0; 32], &[0; 13], &[0; 12], &[])).contains("ciphertext must"));
        assert!(msg(decrypt(&[0; 13], &[0; 16], &[0; 12], &[])).contains("key must"));
        assert!(msg(decrypt(&[0; 32], &[0; 16], &[0; 13], &[])).contains("iv must"));
    }

    #[test]
    fn decrypts_opdata_envelope() {
        let master_key = hex("44c38e8fedb84a1ab5ba74ed98dde931f6500ae39c1d9c85e20a7268ab2074f0");
        let key = AesKey::new("mp", master_key);

        let envelope: EncryptedEnvelope =
            serde_json::from_str(include_str!("resources/encrypted-aes-key.json"))
                .expect("valid fixture");
        let encrypted = Encrypted::parse(&envelope).expect("decodes envelope");

        let plaintext = String::from_utf8(key.decrypt(&encrypted).expect("decrypts"))
            .expect("plaintext is utf8");
        assert!(plaintext.contains("szerdhg2ww2ahjo4ilz57x7cce"));
    }
}
