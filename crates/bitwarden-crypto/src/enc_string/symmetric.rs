use std::{borrow::Cow, str::FromStr};

use bitwarden_encoding::{B64, FromStrVisitor};
use coset::CborSerializable;
use serde::Deserialize;

use super::{check_length, from_b64, from_b64_vec, split_enc_string};
use crate::{
    Aes256CbcHmacKey, ContentFormat, KeyDecryptable, KeyEncryptable, KeyEncryptableWithContentType,
    SymmetricCryptoKey, Utf8Bytes, XChaCha20Poly1305Key,
    error::{CryptoError, EncStringParseError, Result, UnsupportedOperationError},
};

#[cfg(feature = "wasm")]
#[wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
export type EncString = Tagged<string, "EncString">;
"#;

/// # Encrypted string primitive
///
/// [EncString] is a Bitwarden specific primitive that represents a symmetrically encrypted piece of
/// data, encoded as a string. They are are used together with the [KeyDecryptable] and
/// [KeyEncryptable] traits to encrypt and decrypt data using [SymmetricCryptoKey]s.
///
/// The flexibility of the [EncString] type allows for different encryption algorithms to be used
/// which is represented by the different variants of the enum.
///
/// ## Note
///
/// For backwards compatibility we will rarely if ever be able to remove support for decrypting old
/// variants, but we should be opinionated in which variants are used for encrypting.
///
/// ## Variants
/// - [Aes256Cbc_B64](EncString::Aes256Cbc_B64) - Deprecated and MUST NOT be used for encrypting as
///   it is not authenticated
/// - [Aes256Cbc_HmacSha256_B64](EncString::Aes256Cbc_HmacSha256_B64)
/// - [Cose_Encrypt0_B64](EncString::Cose_Encrypt0_B64) - The preferred variant for encrypting data.
///
/// ## Serialization
///
/// [EncString] implements [ToString] and [FromStr] to allow for easy serialization and uses a
/// custom scheme to represent the different variants.
///
/// The scheme is one of the following schemes:
/// - `[type].[iv]|[data]`
/// - `[type].[iv]|[data]|[mac]`
/// - `[type].[cose_encrypt0_bytes]`
///
/// Where:
/// - `[type]`: is a digit number representing the variant.
/// - `[iv]`: (optional) is the initialization vector used for encryption.
/// - `[data]`: is the encrypted data.
/// - `[mac]`: (optional) is the MAC used to validate the integrity of the data.
/// - `[cose_encrypt0_bytes]`: is the COSE Encrypt0 message, serialized to bytes
#[allow(missing_docs)]
#[derive(Clone, zeroize::ZeroizeOnDrop, PartialEq)]
#[allow(unused, non_camel_case_types)]
pub enum EncString {
    /// 0
    Aes256Cbc_B64 {
        iv: [u8; 16],
        data: Vec<u8>,
    },
    /// 1 was the now removed `AesCbc128_HmacSha256_B64`.
    /// 2
    Aes256Cbc_HmacSha256_B64 {
        iv: [u8; 16],
        mac: [u8; 32],
        data: Vec<u8>,
    },
    // 7 The actual enc type is contained in the cose struct
    Cose_Encrypt0_B64 {
        data: Vec<u8>,
    },
}

/// Deserializes an [EncString] from a string.
impl FromStr for EncString {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (enc_type, parts) = split_enc_string(s);
        match (enc_type, parts.len()) {
            ("0", 2) => {
                let iv = from_b64(parts[0])?;
                let data = from_b64_vec(parts[1])?;

                Ok(EncString::Aes256Cbc_B64 { iv, data })
            }
            ("2", 3) => {
                let iv = from_b64(parts[0])?;
                let data = from_b64_vec(parts[1])?;
                let mac = from_b64(parts[2])?;

                Ok(EncString::Aes256Cbc_HmacSha256_B64 { iv, mac, data })
            }
            ("7", 1) => {
                let buffer = from_b64_vec(parts[0])?;

                Ok(EncString::Cose_Encrypt0_B64 { data: buffer })
            }
            (enc_type, parts) => Err(EncStringParseError::InvalidTypeSymm {
                enc_type: enc_type.to_string(),
                parts,
            }
            .into()),
        }
    }
}

impl EncString {
    /// Synthetic sugar for mapping `Option<String>` to `Result<Option<EncString>>`
    pub fn try_from_optional(s: Option<String>) -> Result<Option<EncString>, CryptoError> {
        s.map(|s| s.parse()).transpose()
    }

    #[allow(missing_docs)]
    pub fn from_buffer(buf: &[u8]) -> Result<Self> {
        if buf.is_empty() {
            return Err(EncStringParseError::NoType.into());
        }
        let enc_type = buf[0];

        match enc_type {
            0 => {
                check_length(buf, 18)?;
                let iv = buf[1..17].try_into().expect("Valid length");
                let data = buf[17..].to_vec();

                Ok(EncString::Aes256Cbc_B64 { iv, data })
            }
            2 => {
                check_length(buf, 50)?;
                let iv = buf[1..17].try_into().expect("Valid length");
                let mac = buf[17..49].try_into().expect("Valid length");
                let data = buf[49..].to_vec();

                Ok(EncString::Aes256Cbc_HmacSha256_B64 { iv, mac, data })
            }
            7 => Ok(EncString::Cose_Encrypt0_B64 {
                data: buf[1..].to_vec(),
            }),
            _ => Err(EncStringParseError::InvalidTypeSymm {
                enc_type: enc_type.to_string(),
                parts: 1,
            }
            .into()),
        }
    }

    #[allow(missing_docs)]
    pub fn to_buffer(&self) -> Result<Vec<u8>> {
        let mut buf;

        match self {
            EncString::Aes256Cbc_B64 { iv, data } => {
                buf = Vec::with_capacity(1 + 16 + data.len());
                buf.push(self.enc_type());
                buf.extend_from_slice(iv);
                buf.extend_from_slice(data);
            }
            EncString::Aes256Cbc_HmacSha256_B64 { iv, mac, data } => {
                buf = Vec::with_capacity(1 + 16 + 32 + data.len());
                buf.push(self.enc_type());
                buf.extend_from_slice(iv);
                buf.extend_from_slice(mac);
                buf.extend_from_slice(data);
            }
            EncString::Cose_Encrypt0_B64 { data } => {
                buf = Vec::with_capacity(1 + data.len());
                buf.push(self.enc_type());
                buf.extend_from_slice(data);
            }
        }

        Ok(buf)
    }
}

// `Display` is not implemented here because printing for debug purposes should be different
// from serializing to a string. For Aes256_Cbc, or Aes256_Cbc_Hmac, `ToString` and `Debug`
// are the same. For `Cose_Encrypt0`, `Debug` will print the decoded COSE message, while
// `ToString` will print the Cose_Encrypt0 bytes, encoded in base64.
#[allow(clippy::to_string_trait_impl)]
impl ToString for EncString {
    fn to_string(&self) -> String {
        fn fmt_parts(enc_type: u8, parts: &[&[u8]]) -> String {
            let encoded_parts: Vec<String> = parts
                .iter()
                .map(|part| B64::from(*part).to_string())
                .collect();
            format!("{}.{}", enc_type, encoded_parts.join("|"))
        }

        let enc_type = self.enc_type();
        match &self {
            EncString::Aes256Cbc_B64 { iv, data } => fmt_parts(enc_type, &[iv, data]),
            EncString::Aes256Cbc_HmacSha256_B64 { iv, mac, data } => {
                fmt_parts(enc_type, &[iv, data, mac])
            }
            EncString::Cose_Encrypt0_B64 { data } => fmt_parts(enc_type, &[data]),
        }
    }
}

impl std::fmt::Debug for EncString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn fmt_parts(
            f: &mut std::fmt::Formatter<'_>,
            enc_type: u8,
            parts: &[&[u8]],
        ) -> std::fmt::Result {
            let encoded_parts: Vec<String> = parts
                .iter()
                .map(|part| B64::from(*part).to_string())
                .collect();
            write!(f, "{}.{}", enc_type, encoded_parts.join("|"))
        }

        let enc_type = self.enc_type();

        match self {
            EncString::Aes256Cbc_B64 { iv, data } => fmt_parts(f, enc_type, &[iv, data]),
            EncString::Aes256Cbc_HmacSha256_B64 { iv, mac, data } => {
                fmt_parts(f, enc_type, &[iv, data, mac])
            }
            EncString::Cose_Encrypt0_B64 { data } => {
                let msg = coset::CoseEncrypt0::from_slice(data.as_slice())
                    .map(|msg| format!("{msg:?}"))
                    .unwrap_or_else(|_| "INVALID_COSE".to_string());
                write!(f, "{enc_type}.{msg}")
            }
        }
    }
}

impl<'de> Deserialize<'de> for EncString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(FromStrVisitor::new())
    }
}

impl serde::Serialize for EncString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl EncString {
    pub(crate) fn encrypt_aes256_hmac(
        data_dec: &[u8],
        key: &Aes256CbcHmacKey,
    ) -> Result<EncString> {
        let (iv, mac, data) =
            crate::aes::encrypt_aes256_hmac(data_dec, &key.mac_key, &key.enc_key)?;
        Ok(EncString::Aes256Cbc_HmacSha256_B64 { iv, mac, data })
    }

    pub(crate) fn encrypt_xchacha20_poly1305(
        data_dec: &[u8],
        key: &XChaCha20Poly1305Key,
        content_format: ContentFormat,
    ) -> Result<EncString> {
        let data = crate::cose::encrypt_xchacha20_poly1305(data_dec, key, content_format)?;
        Ok(EncString::Cose_Encrypt0_B64 { data })
    }

    /// The numerical representation of the encryption type of the [EncString].
    const fn enc_type(&self) -> u8 {
        match self {
            EncString::Aes256Cbc_B64 { .. } => 0,
            EncString::Aes256Cbc_HmacSha256_B64 { .. } => 2,
            EncString::Cose_Encrypt0_B64 { .. } => 7,
        }
    }
}

impl KeyEncryptableWithContentType<SymmetricCryptoKey, EncString> for &[u8] {
    fn encrypt_with_key(
        self,
        key: &SymmetricCryptoKey,
        content_format: ContentFormat,
    ) -> Result<EncString> {
        match key {
            SymmetricCryptoKey::Aes256CbcHmacKey(key) => EncString::encrypt_aes256_hmac(self, key),
            SymmetricCryptoKey::XChaCha20Poly1305Key(inner_key) => {
                EncString::encrypt_xchacha20_poly1305(self, inner_key, content_format)
            }
            SymmetricCryptoKey::Aes256CbcKey(_) => Err(CryptoError::OperationNotSupported(
                UnsupportedOperationError::EncryptionNotImplementedForKey,
            )),
        }
    }
}

impl KeyDecryptable<SymmetricCryptoKey, Vec<u8>> for EncString {
    fn decrypt_with_key(&self, key: &SymmetricCryptoKey) -> Result<Vec<u8>> {
        match (self, key) {
            (EncString::Aes256Cbc_B64 { iv, data }, SymmetricCryptoKey::Aes256CbcKey(key)) => {
                crate::aes::decrypt_aes256(iv, data.clone(), &key.enc_key)
            }
            (
                EncString::Aes256Cbc_HmacSha256_B64 { iv, mac, data },
                SymmetricCryptoKey::Aes256CbcHmacKey(key),
            ) => crate::aes::decrypt_aes256_hmac(iv, mac, data.clone(), &key.mac_key, &key.enc_key),
            (
                EncString::Cose_Encrypt0_B64 { data },
                SymmetricCryptoKey::XChaCha20Poly1305Key(key),
            ) => {
                let (decrypted_message, _) =
                    crate::cose::decrypt_xchacha20_poly1305(data.as_slice(), key)?;
                Ok(decrypted_message)
            }
            _ => Err(CryptoError::WrongKeyType),
        }
    }
}

impl KeyEncryptable<SymmetricCryptoKey, EncString> for String {
    fn encrypt_with_key(self, key: &SymmetricCryptoKey) -> Result<EncString> {
        Utf8Bytes::from(self).encrypt_with_key(key)
    }
}

impl KeyEncryptable<SymmetricCryptoKey, EncString> for &str {
    fn encrypt_with_key(self, key: &SymmetricCryptoKey) -> Result<EncString> {
        Utf8Bytes::from(self).encrypt_with_key(key)
    }
}

impl KeyDecryptable<SymmetricCryptoKey, String> for EncString {
    fn decrypt_with_key(&self, key: &SymmetricCryptoKey) -> Result<String> {
        let dec: Vec<u8> = self.decrypt_with_key(key)?;
        String::from_utf8(dec).map_err(|_| CryptoError::InvalidUtf8String)
    }
}

/// Usually we wouldn't want to expose EncStrings in the API or the schemas.
/// But during the transition phase we will expose endpoints using the EncString type.
impl schemars::JsonSchema for EncString {
    fn schema_name() -> Cow<'static, str> {
        "EncString".into()
    }

    fn json_schema(generator: &mut schemars::generate::SchemaGenerator) -> schemars::Schema {
        generator.subschema_for::<String>()
    }
}

#[cfg(test)]
mod tests {
    use schemars::schema_for;

    use super::EncString;
    use crate::{
        CryptoError, KEY_ID_SIZE, KeyDecryptable, KeyEncryptable, SymmetricCryptoKey,
        derive_symmetric_key,
    };

    fn encrypt_with_xchacha20(plaintext: &str) -> EncString {
        let key_id = [0u8; KEY_ID_SIZE];
        let enc_key = [0u8; 32];
        let key = SymmetricCryptoKey::XChaCha20Poly1305Key(crate::XChaCha20Poly1305Key {
            key_id,
            enc_key: Box::pin(enc_key.into()),
        });

        plaintext.encrypt_with_key(&key).expect("encryption works")
    }

    /// XChaCha20Poly1305 encstrings should be padded in blocks of 32 bytes. This ensures that the
    /// encstring length does not reveal more than the 32-byte range of lengths that the contained
    /// string falls into.
    #[test]
    fn test_xchacha20_encstring_string_padding_block_sizes() {
        let cases = [
            ("", 32),              // empty string, padded to 32
            (&"a".repeat(31), 32), // largest in first block
            (&"a".repeat(32), 64), // smallest in second block
            (&"a".repeat(63), 64), // largest in second block
            (&"a".repeat(64), 96), // smallest in third block
        ];

        let ciphertext_lengths: Vec<_> = cases
            .iter()
            .map(|(plaintext, _)| encrypt_with_xchacha20(plaintext).to_string().len())
            .collect();

        // Block 1: 0-31 (same length)
        assert_eq!(ciphertext_lengths[0], ciphertext_lengths[1]);
        // Block 2: 32-63 (same length, different from block 1)
        assert_ne!(ciphertext_lengths[1], ciphertext_lengths[2]);
        assert_eq!(ciphertext_lengths[2], ciphertext_lengths[3]);
        // Block 3: 64+ (different from block 2)
        assert_ne!(ciphertext_lengths[3], ciphertext_lengths[4]);
    }

    #[test]
    fn test_enc_roundtrip_xchacha20() {
        let key_id = [0u8; KEY_ID_SIZE];
        let enc_key = [0u8; 32];
        let key = SymmetricCryptoKey::XChaCha20Poly1305Key(crate::XChaCha20Poly1305Key {
            key_id,
            enc_key: Box::pin(enc_key.into()),
        });

        let test_string = "encrypted_test_string";
        let cipher = test_string.to_owned().encrypt_with_key(&key).unwrap();
        let decrypted_str: String = cipher.decrypt_with_key(&key).unwrap();
        assert_eq!(decrypted_str, test_string);
    }

    #[test]
    fn test_enc_string_roundtrip() {
        let key = SymmetricCryptoKey::Aes256CbcHmacKey(derive_symmetric_key("test"));

        let test_string = "encrypted_test_string";
        let cipher = test_string.to_string().encrypt_with_key(&key).unwrap();

        let decrypted_str: String = cipher.decrypt_with_key(&key).unwrap();
        assert_eq!(decrypted_str, test_string);
    }

    #[test]
    fn test_enc_roundtrip_xchacha20_empty() {
        let key_id = [0u8; KEY_ID_SIZE];
        let enc_key = [0u8; 32];
        let key = SymmetricCryptoKey::XChaCha20Poly1305Key(crate::XChaCha20Poly1305Key {
            key_id,
            enc_key: Box::pin(enc_key.into()),
        });

        let test_string = "";
        let cipher = test_string.to_owned().encrypt_with_key(&key).unwrap();
        let decrypted_str: String = cipher.decrypt_with_key(&key).unwrap();
        assert_eq!(decrypted_str, test_string);
    }

    #[test]
    fn test_enc_string_roundtrip_empty() {
        let key = SymmetricCryptoKey::Aes256CbcHmacKey(derive_symmetric_key("test"));

        let test_string = "";
        let cipher = test_string.to_string().encrypt_with_key(&key).unwrap();

        let decrypted_str: String = cipher.decrypt_with_key(&key).unwrap();
        assert_eq!(decrypted_str, test_string);
    }

    #[test]
    fn test_enc_string_ref_roundtrip() {
        let key = SymmetricCryptoKey::Aes256CbcHmacKey(derive_symmetric_key("test"));

        let test_string: &'static str = "encrypted_test_string";
        let cipher = test_string.to_string().encrypt_with_key(&key).unwrap();

        let decrypted_str: String = cipher.decrypt_with_key(&key).unwrap();
        assert_eq!(decrypted_str, test_string);
    }

    #[test]
    fn test_enc_string_serialization() {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct Test {
            key: EncString,
        }

        let cipher = "2.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==|Q6PkuT+KX/axrgN9ubD5Ajk2YNwxQkgs3WJM0S0wtG8=";
        let serialized = format!("{{\"key\":\"{cipher}\"}}");

        let t = serde_json::from_str::<Test>(&serialized).unwrap();
        assert_eq!(t.key.enc_type(), 2);
        assert_eq!(t.key.to_string(), cipher);
        assert_eq!(serde_json::to_string(&t).unwrap(), serialized);
    }

    #[test]
    fn test_enc_from_to_buffer() {
        let enc_str: &str = "2.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==|Q6PkuT+KX/axrgN9ubD5Ajk2YNwxQkgs3WJM0S0wtG8=";
        let enc_string: EncString = enc_str.parse().unwrap();

        let enc_buf = enc_string.to_buffer().unwrap();

        assert_eq!(
            enc_buf,
            vec![
                2, 164, 196, 186, 254, 39, 19, 64, 0, 109, 186, 92, 57, 218, 154, 182, 150, 67,
                163, 228, 185, 63, 138, 95, 246, 177, 174, 3, 125, 185, 176, 249, 2, 57, 54, 96,
                220, 49, 66, 72, 44, 221, 98, 76, 209, 45, 48, 180, 111, 93, 118, 241, 43, 16, 211,
                135, 233, 150, 136, 221, 71, 140, 125, 141, 215
            ]
        );

        let enc_string_new = EncString::from_buffer(&enc_buf).unwrap();

        assert_eq!(enc_string_new.to_string(), enc_str)
    }

    #[test]
    fn test_from_str_cbc256() {
        let enc_str = "0.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==";
        let enc_string: EncString = enc_str.parse().unwrap();

        assert_eq!(enc_string.enc_type(), 0);
        if let EncString::Aes256Cbc_B64 { iv, data } = &enc_string {
            assert_eq!(
                iv,
                &[
                    164, 196, 186, 254, 39, 19, 64, 0, 109, 186, 92, 57, 218, 154, 182, 150
                ]
            );
            assert_eq!(
                data,
                &[
                    93, 118, 241, 43, 16, 211, 135, 233, 150, 136, 221, 71, 140, 125, 141, 215
                ]
            );
        } else {
            panic!("Invalid variant")
        };
    }

    #[test]
    fn test_decrypt_cbc256() {
        let key = "hvBMMb1t79YssFZkpetYsM3deyVuQv4r88Uj9gvYe08=".to_string();
        let key = SymmetricCryptoKey::try_from(key).unwrap();

        let enc_str = "0.NQfjHLr6za7VQVAbrpL81w==|wfrjmyJ0bfwkQlySrhw8dA==";
        let enc_string: EncString = enc_str.parse().unwrap();
        assert_eq!(enc_string.enc_type(), 0);

        let dec_str: String = enc_string.decrypt_with_key(&key).unwrap();
        assert_eq!(dec_str, "EncryptMe!");
    }

    #[test]
    fn test_decrypt_downgrade_encstring_prevention() {
        // Simulate a potential downgrade attack by removing the mac portion of the `EncString` and
        // attempt to decrypt it using a `SymmetricCryptoKey` with a mac key.
        let key = "hvBMMb1t79YssFZkpetYsM3deyVuQv4r88Uj9gvYe0+G8EwxvW3v1iywVmSl61iwzd17JW5C/ivzxSP2C9h7Tw==".to_string();
        let key = SymmetricCryptoKey::try_from(key).unwrap();

        // A "downgraded" `EncString` from `EncString::Aes256Cbc_HmacSha256_B64` (2) to
        // `EncString::Aes256Cbc_B64` (0), with the mac portion removed.
        // <enc_string>
        let enc_str = "0.NQfjHLr6za7VQVAbrpL81w==|wfrjmyJ0bfwkQlySrhw8dA==";
        let enc_string: EncString = enc_str.parse().unwrap();
        assert_eq!(enc_string.enc_type(), 0);

        let result: Result<String, CryptoError> = enc_string.decrypt_with_key(&key);
        assert!(matches!(result, Err(CryptoError::WrongKeyType)));
    }

    #[test]
    fn test_from_str_invalid() {
        let enc_str = "8.ABC";
        let enc_string: Result<EncString, _> = enc_str.parse();

        let err = enc_string.unwrap_err();
        assert_eq!(
            err.to_string(),
            "EncString error, Invalid symmetric type, got type 8 with 1 parts"
        );
    }

    #[test]
    fn test_debug_format() {
        let enc_str = "2.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==|Q6PkuT+KX/axrgN9ubD5Ajk2YNwxQkgs3WJM0S0wtG8=";
        let enc_string: EncString = enc_str.parse().unwrap();

        let debug_string = format!("{enc_string:?}");
        assert_eq!(debug_string, enc_str);
    }

    #[test]
    fn test_json_schema() {
        let schema = schema_for!(EncString);

        assert_eq!(
            serde_json::to_string(&schema).unwrap(),
            r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","title":"EncString","type":"string"}"#
        );
    }
}
