use std::{marker::PhantomData, str::FromStr};

use base64::{engine::general_purpose::STANDARD, Engine};
use ciborium::value::Integer;
use coset::{iana::CoapContentFormat, CborSerializable, ProtectedHeader, RegisteredLabel};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;

use crate::{
    cose::{self, DATA_ENVELOPE_NAMESPACE, SIGNING_NAMESPACE, XCHACHA20_POLY1305},
    error::EncStringParseError,
    safe::DataEnvelopeNamespace,
    ContentFormat, CoseEncrypt0Bytes, CryptoError, FromStrVisitor, KeyIds, SerializedMessage,
    SymmetricCryptoKey, XChaCha20Poly1305Key,
};

use crate::xchacha20;

/// Marker trait for data that can be sealed in a `DataEnvelope`.
pub trait SealableData {}

/// `DataEnvelope` allows sealing structs entire structs to encrypted blobs.
///
/// Sealing a struct results in an encrypted blob, and a content-encryption-key. The
/// content-encryption-key must be provided again when unsealing the data. A content encryption key
/// allows easy key-rotation of the encrypting-key, as now just the content-encryption-keys need to
/// be re-uploaded, instead of all data.
pub struct DataEnvelope<Ids: KeyIds> {
    envelope_data: CoseEncrypt0Bytes,
    _phantom: PhantomData<Ids>,
}

impl<Ids: KeyIds> Clone for DataEnvelope<Ids> {
    fn clone(&self) -> Self {
        DataEnvelope {
            envelope_data: self.envelope_data.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<Ids: KeyIds> DataEnvelope<Ids> {
    /// Seals a struct into an encrypted blob, and stores the content-encryption-key in the provided
    /// context.
    pub fn seal<T>(
        data: T,
        namespace: &DataEnvelopeNamespace,
        cek_keyslot: Ids::Symmetric,
        ctx: &mut crate::store::KeyStoreContext<Ids>,
    ) -> Result<Self, DataEnvelopeError>
    where
        T: Serialize + SealableData,
    {
        let (envelope, cek) = Self::seal_ref(&data, namespace)?;
        #[allow(deprecated)]
        ctx.set_symmetric_key(cek_keyslot, SymmetricCryptoKey::XChaCha20Poly1305Key(cek))
            .map_err(|_| DataEnvelopeError::KeyStoreError("Failed to set symmetric key".into()))?;
        Ok(envelope)
    }

    /// Seals a struct into an encrypted blob, and returns the encrypted blob and the
    /// content-encryption-key.
    fn seal_ref<T>(
        data: &T,
        namespace: &DataEnvelopeNamespace,
    ) -> Result<(DataEnvelope<Ids>, XChaCha20Poly1305Key), DataEnvelopeError>
    where
        T: Serialize + SealableData,
    {
        let cek = SymmetricCryptoKey::make_xchacha20_poly1305_key();
        let cek = match cek {
            SymmetricCryptoKey::XChaCha20Poly1305Key(ref key) => key,
            _ => return Err(DataEnvelopeError::UnsupportedContentFormat),
        };

        let serialized_message = SerializedMessage::encode(&data).map_err(|e| {
            DataEnvelopeError::EncodingError(format!("Failed to encode serialized message: {}", e))
        })?;

        let mut a = coset::HeaderBuilder::new()
            .key_id(cek.key_id.to_vec())
            .content_format(serialized_message.content_type())
            .value(
                DATA_ENVELOPE_NAMESPACE,
                ciborium::Value::Integer(Integer::from(namespace.as_i64())),
            )
            .build();
        a.alg = Some(coset::Algorithm::PrivateUse(XCHACHA20_POLY1305));

        let mut nonce = [0u8; xchacha20::NONCE_SIZE];
        let encrypt0 = coset::CoseEncrypt0Builder::new()
            .protected(a)
            .create_ciphertext(&serialized_message.as_bytes(), &[], |data, aad| {
                let ciphertext =
                    crate::xchacha20::encrypt_xchacha20_poly1305(&(*cek.enc_key).into(), data, aad);
                nonce = ciphertext.nonce();
                ciphertext.encrypted_bytes().to_vec()
            })
            .unprotected(coset::HeaderBuilder::new().iv(nonce.to_vec()).build())
            .build();

        let envelope_data = encrypt0
            .to_vec()
            .map_err(|err| CryptoError::EncString(EncStringParseError::InvalidCoseEncoding(err)))
            .map(CoseEncrypt0Bytes::from)
            .map_err(|_| {
                DataEnvelopeError::EncodingError("Failed to encode COSE Encrypt0".into())
            })?;

        Ok((
            DataEnvelope {
                envelope_data,
                _phantom: PhantomData,
            },
            cek.clone(),
        ))
    }

    /// Unseals the data from the encrypted blob using a content-encryption-key stored in the
    /// context.
    pub fn unseal<T>(
        &self,
        namespace: &DataEnvelopeNamespace,
        cek_keyslot: Ids::Symmetric,
        ctx: &mut crate::store::KeyStoreContext<Ids>,
    ) -> Result<T, DataEnvelopeError>
    where
        T: DeserializeOwned + SealableData,
    {
        #[allow(deprecated)]
        let cek = ctx
            .dangerous_get_symmetric_key(cek_keyslot)
            .map_err(|_| DataEnvelopeError::KeyStoreError("Failed to get symmetric key".into()))?;

        match cek {
            SymmetricCryptoKey::XChaCha20Poly1305Key(ref key) => self.unseal_ref(namespace, key),
            _ => Err(DataEnvelopeError::UnsupportedContentFormat),
        }
    }

    /// Unseals the data from the encrypted blob using the provided content-encryption-key.
    fn unseal_ref<T>(
        &self,
        namespace: &DataEnvelopeNamespace,
        cek: &XChaCha20Poly1305Key,
    ) -> Result<T, DataEnvelopeError>
    where
        T: DeserializeOwned + SealableData,
    {
        let msg = coset::CoseEncrypt0::from_slice(self.envelope_data.as_ref()).map_err(|err| {
            DataEnvelopeError::DecodingError(format!(
                "Failed to decode COSE Encrypt0 message: {}",
                err
            ))
        })?;

        println!("Unsealing data envelope {:?}", msg);

        let Some(ref alg) = msg.protected.header.alg else {
            return Err(DataEnvelopeError::DecryptionError);
        };

        if *alg != coset::Algorithm::PrivateUse(XCHACHA20_POLY1305) {
            return Err(DataEnvelopeError::DecryptionError);
        }

        let content_format = ContentFormat::try_from(&msg.protected.header)
            .map_err(|_| DataEnvelopeError::UnsupportedContentFormat)?;

        if cek.key_id != *msg.protected.header.key_id {
            return Err(DataEnvelopeError::DecryptionError);
        }

        let decrypted_message = msg
            .decrypt(&[], |data, aad| {
                let nonce = msg.unprotected.iv.as_slice();
                crate::xchacha20::decrypt_xchacha20_poly1305(
                    nonce
                        .try_into()
                        .map_err(|_| DataEnvelopeError::DecryptionError)?,
                    &(*cek.enc_key).into(),
                    data,
                    aad,
                )
            })
            .map_err(|_| DataEnvelopeError::DecryptionError)?;

        let content_type = content_type(&msg.protected).unwrap();
        let serialized_message = SerializedMessage::from_bytes(decrypted_message, content_type);
        let res = serialized_message.decode().map_err(|_| {
            DataEnvelopeError::DecodingError("Failed to decode serialized message".into())
        });
        return res;
    }
}

/// Helper function to extract the content type from a `ProtectedHeader`. The content type is a
/// standardized header set on the protected headers of the signature object. Currently we only
/// support registered values, but PrivateUse values are also allowed in the COSE specification.
pub(super) fn content_type(
    protected_header: &ProtectedHeader,
) -> Result<coset::iana::CoapContentFormat, CryptoError> {
    protected_header
        .header
        .content_type
        .as_ref()
        .and_then(|ct| match ct {
            RegisteredLabel::Assigned(content_format) => Some(*content_format),
            _ => None,
        })
        .ok_or_else(|| DataEnvelopeError::DecryptionError.into())
}

impl<Ids: KeyIds> From<&DataEnvelope<Ids>> for Vec<u8> {
    fn from(val: &DataEnvelope<Ids>) -> Self {
        val.envelope_data.to_vec()
    }
}

impl<Ids: KeyIds> From<Vec<u8>> for DataEnvelope<Ids> {
    fn from(data: Vec<u8>) -> Self {
        DataEnvelope {
            envelope_data: CoseEncrypt0Bytes::from(data),
            _phantom: PhantomData,
        }
    }
}

impl<Ids: KeyIds> std::fmt::Debug for DataEnvelope<Ids> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataEnvelope")
            .field("envelope_data", &self.envelope_data)
            .finish()
    }
}

impl<Ids: KeyIds> FromStr for DataEnvelope<Ids> {
    type Err = DataEnvelopeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = STANDARD.decode(s).map_err(|_| {
            DataEnvelopeError::ParsingError("Invalid DataEnvelope Base64 encoding".to_string())
        })?;
        Self::try_from(data).map_err(|_| {
            DataEnvelopeError::ParsingError("Failed to parse DataEnvelope".to_string())
        })
    }
}

impl<Ids: KeyIds> From<DataEnvelope<Ids>> for String {
    fn from(val: DataEnvelope<Ids>) -> Self {
        let serialized: Vec<u8> = (&val).into();
        STANDARD.encode(serialized)
    }
}

impl<'de, Ids: KeyIds> Deserialize<'de> for DataEnvelope<Ids> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(FromStrVisitor::new())
    }
}

impl<Ids: KeyIds> Serialize for DataEnvelope<Ids> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let serialized: Vec<u8> = self.into();
        serializer.serialize_str(&STANDARD.encode(serialized))
    }
}

impl<Ids: KeyIds> std::fmt::Display for DataEnvelope<Ids> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let serialized: Vec<u8> = self.into();
        write!(f, "{}", STANDARD.encode(serialized))
    }
}

/// Error type for `DataEnvelope` operations.
#[derive(Debug, Error)]
pub enum DataEnvelopeError {
    /// Indicates that the content format is not supported.
    #[error("Unsupported content format")]
    UnsupportedContentFormat,
    /// Indicates that there was an error during decoding of the message.
    #[error("Decoding error: {0}")]
    DecodingError(String),
    /// Indicates that there was an error during encoding of the message.
    #[error("Encoding error: {0}")]
    EncodingError(String),
    /// Indicates that there was an error with the key store.
    #[error("KeyStore error: {0}")]
    KeyStoreError(String),
    /// Indicates that there was an error during decryption.
    #[error("Decryption error")]
    DecryptionError,
    /// Indicates that there was an error during encryption.
    #[error("Encryption error")]
    EncryptionError,
    /// Indicates that there was an error parsing the DataEnvelope.
    #[error("Parsing error: {0}")]
    ParsingError(String),
    /// Indicates that the data envelope namespace is invalid.
    #[error("Invalid namespace")]
    InvalidNamespace,
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;
    use crate::traits::tests::TestIds;

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TestData {
        field2: u32,
    }
    impl SealableData for TestData {}

    #[test]
    fn test_data_envelope() {
        // Create an instance of TestData
        let data = TestData { field2: 42 };

        // Seal the data
        let (envelope, cek) =
            DataEnvelope::<TestIds>::seal_ref(&data, &DataEnvelopeNamespace::ExampleNamespace)
                .unwrap();
        let unsealed_data: TestData = envelope
            .unseal_ref(&DataEnvelopeNamespace::ExampleNamespace, &cek)
            .unwrap();

        // Verify that the unsealed data matches the original data
        assert_eq!(unsealed_data, data);
    }
}
