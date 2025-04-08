use std::{fmt::Display, str::FromStr};

use base64::{engine::general_purpose::STANDARD, Engine};
use coset::{iana::CoapContentFormat, CborSerializable, ContentType};
use serde::Deserialize;

use super::{check_length, from_b64, from_b64_vec, split_enc_string};
use crate::{
    cose::{self, ContentFormat},
    error::{CryptoError, EncStringParseError, Result, UnsupportedOperation},
    Aes256CbcHmacKey, KeyDecryptable, KeyEncryptable, SymmetricCryptoKey, TypedKeyEncryptable,
    XChaCha20Poly1305Key,
};

#[cfg(feature = "wasm")]
#[wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
export type EncString = string;
"#;

/// # Encrypted string primitive
///
/// [EncString] is a Bitwarden specific primitive that represents a symmetrically encrypted string.
/// They are are used together with the [KeyDecryptable] and [KeyEncryptable] traits to encrypt and
/// decrypt data using [SymmetricCryptoKey]s.
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
/// - [AesCbc256_B64](EncString::AesCbc256_B64)
/// - [AesCbc256_HmacSha256_B64](EncString::AesCbc256_HmacSha256_B64)
///
/// ## Serialization
///
/// [EncString] implements [Display] and [FromStr] to allow for easy serialization and uses a
/// custom scheme to represent the different variants.
///
/// The scheme is one of the following schemes:
/// - `[type].[iv]|[data]`
/// - `[type].[iv]|[data]|[mac]`
///
/// Where:
/// - `[type]`: is a digit number representing the variant.
/// - `[iv]`: (optional) is the initialization vector used for encryption.
/// - `[data]`: is the encrypted data.
/// - `[mac]`: (optional) is the MAC used to validate the integrity of the data.
#[derive(Clone, zeroize::ZeroizeOnDrop, PartialEq)]
#[allow(unused, non_camel_case_types)]
pub enum EncString {
    /// 0
    AesCbc256_B64 {
        iv: [u8; 16],
        data: Vec<u8>,
    },
    /// 1 was the now removed `AesCbc128_HmacSha256_B64`.
    /// 2
    AesCbc256_HmacSha256_B64 {
        iv: [u8; 16],
        mac: [u8; 32],
        data: Vec<u8>,
    },
    // 7 The actual enc type is contained in the cose struct
    XChaCha20_Poly1305_Cose_B64 {
        data: Vec<u8>,
    },
}

/// To avoid printing sensitive information, [EncString] debug prints to `EncString`.
impl std::fmt::Debug for EncString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncString").finish()
    }
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

                Ok(EncString::AesCbc256_B64 { iv, data })
            }
            ("2", 3) => {
                let iv = from_b64(parts[0])?;
                let data = from_b64_vec(parts[1])?;
                let mac = from_b64(parts[2])?;

                Ok(EncString::AesCbc256_HmacSha256_B64 { iv, mac, data })
            }
            ("7", 1) => {
                let buffer = from_b64_vec(parts[0])?;

                Ok(EncString::XChaCha20_Poly1305_Cose_B64 { data: buffer })
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

                Ok(EncString::AesCbc256_B64 { iv, data })
            }
            2 => {
                check_length(buf, 50)?;
                let iv = buf[1..17].try_into().expect("Valid length");
                let mac = buf[17..49].try_into().expect("Valid length");
                let data = buf[49..].to_vec();

                Ok(EncString::AesCbc256_HmacSha256_B64 { iv, mac, data })
            }
            7 => Ok(EncString::XChaCha20_Poly1305_Cose_B64 {
                data: buf[1..].to_vec(),
            }),
            _ => Err(EncStringParseError::InvalidTypeSymm {
                enc_type: enc_type.to_string(),
                parts: 1,
            }
            .into()),
        }
    }

    pub fn to_buffer(&self) -> Result<Vec<u8>> {
        let mut buf;

        match self {
            EncString::AesCbc256_B64 { iv, data } => {
                buf = Vec::with_capacity(1 + 16 + data.len());
                buf.push(self.enc_type());
                buf.extend_from_slice(iv);
                buf.extend_from_slice(data);
            }
            EncString::AesCbc256_HmacSha256_B64 { iv, mac, data } => {
                buf = Vec::with_capacity(1 + 16 + 32 + data.len());
                buf.push(self.enc_type());
                buf.extend_from_slice(iv);
                buf.extend_from_slice(mac);
                buf.extend_from_slice(data);
            }
            EncString::XChaCha20_Poly1305_Cose_B64 { data } => {
                buf = Vec::with_capacity(1 + data.len());
                buf.push(self.enc_type());
                buf.extend_from_slice(data);
            }
        }

        Ok(buf)
    }
}

impl Display for EncString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncString::AesCbc256_B64 { .. } | EncString::AesCbc256_HmacSha256_B64 { .. } => {
                let parts: Vec<&[u8]> = match self {
                    EncString::AesCbc256_B64 { iv, data } => vec![iv, data],
                    EncString::AesCbc256_HmacSha256_B64 { iv, mac, data } => vec![iv, data, mac],
                    _ => unreachable!(),
                };

                let encoded_parts: Vec<String> =
                    parts.iter().map(|part| STANDARD.encode(part)).collect();

                write!(f, "{}.{}", self.enc_type(), encoded_parts.join("|"))?;

                Ok(())
            }
            EncString::XChaCha20_Poly1305_Cose_B64 { data } => {
                if let Ok(msg) = coset::CoseEncrypt0::from_slice(data.as_slice()) {
                    write!(f, "{}.{:?}", self.enc_type(), msg)?;
                } else {
                    write!(f, "{}.INVALID_COSE", self.enc_type())?;
                }

                Ok(())
            }
        }
    }
}

impl<'de> Deserialize<'de> for EncString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(super::FromStrVisitor::new())
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
    const XCHACHA20_TEXT_PAD_BLOCK_SIZE: usize = 24;

    pub(crate) fn encrypt_aes256_hmac(
        data_dec: &[u8],
        key: &Aes256CbcHmacKey,
    ) -> Result<EncString> {
        let (iv, mac, data) =
            crate::aes::encrypt_aes256_hmac(data_dec, &key.mac_key, &key.enc_key)?;
        Ok(EncString::AesCbc256_HmacSha256_B64 { iv, mac, data })
    }

    pub(crate) fn encrypt_xchacha20_poly1305(
        data_dec: &[u8],
        key: &XChaCha20Poly1305Key,
        content_format: ContentFormat,
    ) -> Result<EncString> {
        let mut protected_header = coset::HeaderBuilder::new();
        match content_format {
            ContentFormat::Utf8 => {
                protected_header =
                    protected_header.content_type("application/utf8-padded".to_string());
            }
            ContentFormat::Pkcs8 => {
                protected_header = protected_header.content_format(CoapContentFormat::Pkcs8);
            }
            ContentFormat::CoseKey => {
                protected_header = protected_header.content_format(CoapContentFormat::CoseKey);
            }
            ContentFormat::OctetStream => {
                protected_header = protected_header.content_format(CoapContentFormat::OctetStream);
            }
            ContentFormat::Unknown => todo!(),
            ContentFormat::DomainObject => unreachable!(),
        }

        let mut data = data_dec.to_vec();
        if content_format == ContentFormat::Utf8 {
            // Pad the data to a block size in order to hide plaintext length
            pad_bytes(&mut data, Self::XCHACHA20_TEXT_PAD_BLOCK_SIZE);
        }

        let mut protected_header = protected_header.build();
        protected_header.alg = Some(coset::Algorithm::PrivateUse(cose::XCHACHA20_POLY1305));

        let mut nonce = [0u8; 24];
        let cose_encrypt0 = coset::CoseEncrypt0Builder::new()
            .protected(protected_header)
            .try_create_ciphertext(&data, &[], |data, aad| {
                let ciphertext = crate::xchacha20::encrypt_xchacha20_poly1305(
                    key.enc_key
                        .as_slice()
                        .try_into()
                        .expect("XChaChaPoly1305 key is 32 bytes long"),
                    data,
                    aad,
                );
                nonce.copy_from_slice(ciphertext.nonce.as_slice());
                Ok(ciphertext.ciphertext)
            })
            .map_err(|_a: CryptoError| CryptoError::EncodingError)?
            .unprotected(coset::HeaderBuilder::new().iv(nonce.to_vec()).build())
            .build();

        Ok(EncString::XChaCha20_Poly1305_Cose_B64 {
            data: cose_encrypt0
                .to_vec()
                .map_err(|_| CryptoError::EncodingError)?,
        })
    }

    /// The numerical representation of the encryption type of the [EncString].
    const fn enc_type(&self) -> u8 {
        match self {
            EncString::AesCbc256_B64 { .. } => 0,
            EncString::AesCbc256_HmacSha256_B64 { .. } => 2,
            EncString::XChaCha20_Poly1305_Cose_B64 { .. } => 7,
        }
    }
}

impl KeyEncryptable<SymmetricCryptoKey, EncString> for &[u8] {
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
                UnsupportedOperation::EncryptionNotImplementedForKey,
            )),
        }
    }
}

impl KeyDecryptable<SymmetricCryptoKey, Vec<u8>> for EncString {
    fn decrypt_with_key(&self, key: &SymmetricCryptoKey) -> Result<Vec<u8>> {
        match (self, key) {
            (EncString::AesCbc256_B64 { iv, data }, SymmetricCryptoKey::Aes256CbcKey(key)) => {
                crate::aes::decrypt_aes256(iv, data.clone(), &key.enc_key)
            }
            (
                EncString::AesCbc256_HmacSha256_B64 { iv, mac, data },
                SymmetricCryptoKey::Aes256CbcHmacKey(key),
            ) => crate::aes::decrypt_aes256_hmac(iv, mac, data.clone(), &key.mac_key, &key.enc_key),
            (
                EncString::XChaCha20_Poly1305_Cose_B64 { data },
                SymmetricCryptoKey::XChaCha20Poly1305Key(key),
            ) => {
                // parse cose
                let msg = coset::CoseEncrypt0::from_slice(data.as_slice())
                    .map_err(|_| CryptoError::EncString(EncStringParseError::InvalidEncoding))?;
                let mut decrypted_message = msg
                    .decrypt(&[], |data, aad| {
                        let nonce = msg.unprotected.iv.as_slice();
                        crate::xchacha20::decrypt_xchacha20_poly1305(
                            nonce.try_into().map_err(|_| CryptoError::EncodingError)?,
                            key.enc_key
                                .as_slice()
                                .try_into()
                                .expect("XChaChaPoly1305 key is 32 bytes long"),
                            data,
                            aad,
                        )
                        .map_err(|_| CryptoError::EncodingError)
                    })
                    .map_err(|_| CryptoError::EncodingError)?;

                if let Some(ContentType::Text(content_type)) = msg.protected.header.content_type {
                    if content_type == "application/utf8-padded" {
                        decrypted_message = unpad_bytes(decrypted_message.as_slice()).to_vec();
                    } else {
                        return Err(CryptoError::EncodingError);
                    }
                }

                Ok(decrypted_message)
            }
            _ => Err(CryptoError::WrongKeyType),
        }
    }
}

impl TypedKeyEncryptable<SymmetricCryptoKey, EncString> for String {
    fn encrypt_with_key(self, key: &SymmetricCryptoKey) -> Result<EncString> {
        self.as_bytes().encrypt_with_key(key, ContentFormat::Utf8)
    }
}

impl TypedKeyEncryptable<SymmetricCryptoKey, EncString> for &str {
    fn encrypt_with_key(self, key: &SymmetricCryptoKey) -> Result<EncString> {
        self.as_bytes().encrypt_with_key(key, ContentFormat::Utf8)
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
    fn schema_name() -> String {
        "EncString".to_string()
    }

    fn json_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        generator.subschema_for::<String>()
    }
}

/// Pads bytes to a minimum length using PKCS7-like padding
fn pad_bytes(bytes: &mut Vec<u8>, block_size: usize) {
    let padding_len = block_size - (bytes.len() % block_size);
    let padded_length = padding_len + bytes.len();
    bytes.resize(padded_length, padding_len as u8);
}

// Unpads the bytes
fn unpad_bytes(bytes: &[u8]) -> &[u8] {
    // this unwrap is safe, the input is always at least 1 byte long
    #[allow(clippy::unwrap_used)]
    let pad_len = *bytes.last().unwrap() as usize;
    bytes[..bytes.len() - pad_len].as_ref()
}

#[cfg(test)]
mod tests {
    use generic_array::GenericArray;
    use schemars::schema_for;

    use super::EncString;
    use crate::{
        derive_symmetric_key, CryptoError, KeyDecryptable, SymmetricCryptoKey, TypedKeyEncryptable,
    };

    #[test]
    fn test_enc_roundtrip_xchacha20() {
        let key_id = [0u8; 24];
        let enc_key = [0u8; 32];
        let key = SymmetricCryptoKey::XChaCha20Poly1305Key(crate::XChaCha20Poly1305Key {
            key_id,
            enc_key: Box::pin(*GenericArray::from_slice(enc_key.as_slice())),
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
        let cipher = test_string.to_owned().encrypt_with_key(&key).unwrap();

        let decrypted_str: String = cipher.decrypt_with_key(&key).unwrap();
        assert_eq!(decrypted_str, test_string);
    }

    #[test]
    fn test_enc_string_ref_roundtrip() {
        let key = SymmetricCryptoKey::Aes256CbcHmacKey(derive_symmetric_key("test"));

        let test_string = "encrypted_test_string";
        let cipher = test_string.encrypt_with_key(&key).unwrap();

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
        if let EncString::AesCbc256_B64 { iv, data } = &enc_string {
            assert_eq!(
                iv,
                &[164, 196, 186, 254, 39, 19, 64, 0, 109, 186, 92, 57, 218, 154, 182, 150]
            );
            assert_eq!(
                data,
                &[93, 118, 241, 43, 16, 211, 135, 233, 150, 136, 221, 71, 140, 125, 141, 215]
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

        // A "downgraded" `EncString` from `EncString::AesCbc256_HmacSha256_B64` (2) to
        // `EncString::AesCbc256_B64` (0), with the mac portion removed.
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
        let enc_str  = "2.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==|Q6PkuT+KX/axrgN9ubD5Ajk2YNwxQkgs3WJM0S0wtG8=";
        let enc_string: EncString = enc_str.parse().unwrap();

        let debug_string = format!("{:?}", enc_string);
        assert_eq!(debug_string, "EncString");
    }

    #[test]
    fn test_json_schema() {
        let schema = schema_for!(EncString);

        assert_eq!(
            serde_json::to_string(&schema).unwrap(),
            r#"{"$schema":"http://json-schema.org/draft-07/schema#","title":"EncString","type":"string"}"#
        );
    }
}
