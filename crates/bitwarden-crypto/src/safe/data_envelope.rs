use std::{marker::PhantomData, str::FromStr};

use base64::{engine::general_purpose::STANDARD, Engine};
use coset::iana::CoapContentFormat;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;

use crate::{
    cose, util::FromStrVisitor, CoseEncrypt0Bytes, KeyIds, SerializedMessage, SymmetricCryptoKey,
    XChaCha20Poly1305Key,
};

/// Marker trait for data that can be sealed in a `DataEnvelope`.
pub trait SealableData {}

/// `DataEnvelope` allows sealing structs entire structs to encrypted blobs.
///
/// Sealing a struct results in an encrypted blob, and a content-encryption-key. The
/// content-encryption-key must be provided again when unsealing the data. A content encryption key
/// allows easy key-rotation of the encrypting-key, as now just the content-encryption-keys need to
/// be re-uploaded, instead of all data.
#[derive(PartialEq, Eq)]
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
        cek_keyslot: Ids::Symmetric,
        ctx: &mut crate::store::KeyStoreContext<Ids>,
    ) -> Result<Self, DataEnvelopeError>
    where
        T: Serialize + SealableData,
    {
        let (envelope, cek) = Self::seal_ref(&data)?;
        #[allow(deprecated)]
        ctx.set_symmetric_key(cek_keyslot, SymmetricCryptoKey::XChaCha20Poly1305Key(cek))
            .map_err(|_| DataEnvelopeError::KeyStoreError("Failed to set symmetric key".into()))?;
        Ok(envelope)
    }

    /// Seals a struct into an encrypted blob, and returns the encrypted blob and the
    /// content-encryption-key.
    fn seal_ref<T>(data: &T) -> Result<(DataEnvelope<Ids>, XChaCha20Poly1305Key), DataEnvelopeError>
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

        Ok((
            DataEnvelope {
                envelope_data: cose::encrypt_xchacha20_poly1305(
                    serialized_message.as_bytes(),
                    cek,
                    crate::ContentFormat::Cbor,
                )
                .map_err(|_| DataEnvelopeError::EncryptionError)?,
                _phantom: PhantomData,
            },
            cek.clone(),
        ))
    }

    /// Unseals the data from the encrypted blob using a content-encryption-key stored in the
    /// context.
    pub fn unseal<T>(
        &self,
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
            SymmetricCryptoKey::XChaCha20Poly1305Key(ref key) => self.unseal_ref(key),
            _ => Err(DataEnvelopeError::UnsupportedContentFormat),
        }
    }

    /// Unseals the data from the encrypted blob using the provided content-encryption-key.
    fn unseal_ref<T>(&self, cek: &XChaCha20Poly1305Key) -> Result<T, DataEnvelopeError>
    where
        T: DeserializeOwned + SealableData,
    {
        let (data, content_format) = cose::decrypt_xchacha20_poly1305(&self.envelope_data, cek)
            .map_err(|_| DataEnvelopeError::DecryptionError)?;

        let content_format = match content_format {
            crate::ContentFormat::Cbor => CoapContentFormat::Cbor,
            _ => return Err(DataEnvelopeError::UnsupportedContentFormat),
        };

        let serialized_message = SerializedMessage::from_bytes(data, content_format);
        serialized_message.decode().map_err(|e| {
            DataEnvelopeError::DecodingError(format!("Failed to decode serialized message: {}", e))
        })
    }
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
        let (envelope, cek) = DataEnvelope::<TestIds>::seal_ref(&data).unwrap();
        let unsealed_data: TestData = envelope.unseal_ref(&cek).unwrap();

        // Verify that the unsealed data matches the original data
        assert_eq!(unsealed_data, data);
    }
}
