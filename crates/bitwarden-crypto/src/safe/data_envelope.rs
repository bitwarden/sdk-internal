use std::marker::PhantomData;

use coset::iana::CoapContentFormat;
use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;

use crate::{
    cose, CoseEncrypt0Bytes, KeyIds, SerializedMessage, SymmetricCryptoKey, XChaCha20Poly1305Key,
};

/// Marker trait for data that can be sealed in a `DataEnvelope`.
pub trait SealableData {}

/// `DataEnvelope` allows sealing structs entire structs to encrypted blobs.
///
/// Sealing a struct results in an encrypted blob, and a content-encryption-key. The content-encryption-key must be provided again when unsealing the data.
/// A content encryption key allows easy key-rotation of the encrypting-key, as now just the content-encryption-keys need to be re-uploaded, instead of all data.
pub struct DataEnvelope<Ids: KeyIds> {
    envelope_data: CoseEncrypt0Bytes,
    _phantom: PhantomData<Ids>,
}

impl<Ids: KeyIds> DataEnvelope<Ids> {
    /// Seals a struct into an encrypted blob, and stores the content-encryption-key in the provided context.
    pub fn seal<T>(
        data: T,
        cek_keyslot: Ids::Symmetric,
        ctx: &mut crate::store::KeyStoreContext<Ids>,
    ) -> Result<Self, DataEnvelopError>
    where
        T: Serialize + SealableData,
    {
        let (envelope, cek) = Self::seal_ref(&data)?;
        #[allow(deprecated)]
        ctx.set_symmetric_key(cek_keyslot, SymmetricCryptoKey::XChaCha20Poly1305Key(cek))
            .map_err(|_| DataEnvelopError::KeyStoreError("Failed to set symmetric key".into()))?;
        Ok(envelope)
    }

    /// Seals a struct into an encrypted blob, and returns the encrypted blob and the content-encryption-key.
    fn seal_ref<T>(data: &T) -> Result<(DataEnvelope<Ids>, XChaCha20Poly1305Key), DataEnvelopError>
    where
        T: Serialize + SealableData,
    {
        let cek = SymmetricCryptoKey::make_xchacha20_poly1305_key();
        let cek = match cek {
            SymmetricCryptoKey::XChaCha20Poly1305Key(ref key) => key,
            _ => return Err(DataEnvelopError::UnsupportedContentFormat),
        };

        let serialized_message = SerializedMessage::encode(&data).map_err(|e| {
            DataEnvelopError::EncodingError(format!("Failed to encode serialized message: {}", e))
        })?;

        Ok((
            DataEnvelope {
                envelope_data: cose::encrypt_xchacha20_poly1305(
                    serialized_message.as_bytes(),
                    &cek,
                    crate::ContentFormat::Cbor,
                )
                .unwrap(),
                _phantom: PhantomData,
            },
            cek.clone(),
        ))
    }

    /// Unseals the data from the encrypted blob using a content-encryption-key stored in the context.
    pub fn unseal<T>(
        &self,
        cek_keyslot: Ids::Symmetric,
        ctx: &mut crate::store::KeyStoreContext<Ids>,
    ) -> Result<T, DataEnvelopError>
    where
        T: DeserializeOwned + SealableData,
    {
        #[allow(deprecated)]
        let cek = ctx
            .dangerous_get_symmetric_key(cek_keyslot)
            .map_err(|_| DataEnvelopError::KeyStoreError("Failed to get symmetric key".into()))?;

        match cek {
            SymmetricCryptoKey::XChaCha20Poly1305Key(ref key) => self.unseal_ref(key),
            _ => Err(DataEnvelopError::UnsupportedContentFormat),
        }
    }

    /// Unseals the data from the encrypted blob using the provided content-encryption-key.
    fn unseal_ref<T>(&self, cek: &XChaCha20Poly1305Key) -> Result<T, DataEnvelopError>
    where
        T: DeserializeOwned + SealableData,
    {
        let (data, content_format) =
            cose::decrypt_xchacha20_poly1305(&self.envelope_data, cek).unwrap();

        let content_format = match content_format {
            crate::ContentFormat::Cbor => CoapContentFormat::Cbor,
            _ => return Err(DataEnvelopError::UnsupportedContentFormat),
        };

        let serialized_message = SerializedMessage::from_bytes(data, content_format);
        serialized_message.decode().map_err(|e| {
            DataEnvelopError::DecodingError(format!("Failed to decode serialized message: {}", e))
        })
    }
}

impl<Ids: KeyIds> Into<Vec<u8>> for &DataEnvelope<Ids> {
    fn into(self) -> Vec<u8> {
        self.envelope_data.to_vec()
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

/// Error type for `DataEnvelope` operations.
#[derive(Debug, Error)]
pub enum DataEnvelopError {
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
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use crate::traits::tests::TestIds;

    use super::*;

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
