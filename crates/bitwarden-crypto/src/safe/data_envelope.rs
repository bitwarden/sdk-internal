use std::marker::PhantomData;

use serde::{de::DeserializeOwned, Serialize};

use crate::{
    content_format, cose, xchacha20, CborBytes, CoseEncrypt0Bytes, KeyIds, KeyStoreContext,
    PrimitiveEncryptable, SerializedMessage, SymmetricCryptoKey,
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
    // Seals a struct into an encrypted blob, and writes the generated content-encryption-key to the key store context.
    pub(crate) fn seal<T>(
        data: &T,
        cek_keyslot: Ids::Symmetric,
        mut ctx: &KeyStoreContext<Ids>,
    ) -> Result<DataEnvelope<Ids>, crate::CryptoError>
    where
        T: Serialize + SealableData,
    {
        let cek = match SymmetricCryptoKey::make_xchacha20_poly1305_key() {
            SymmetricCryptoKey::XChaCha20Poly1305Key(key) => key,
            _ => return Err(crate::CryptoError::InvalidKey),
        };

        let serialized_message = SerializedMessage::encode(&data).unwrap();

        let a = cose::encrypt_xchacha20_poly1305(&serialized_message, &cek, serialized_message);

        Ok(DataEnvelope {
            envelope_data: CborBytes::from(buffer).encrypt(&mut ctx, cek_keyslot),
            _phantom: PhantomData,
        })
    }

    pub(crate) fn unseal<T>(
        &self,
        cek_keyslot: Ids::Symmetric,
        mut ctx: &KeyStoreContext<Ids>,
    ) -> Result<T, crate::CryptoError>
    where
        T: DeserializeOwned + SealableData,
    {
        let decrypted_data = self.envelope_data.decrypt(&mut ctx, cek_keyslot)?;
        let cbor_bytes: CborBytes = decrypted_data.into();
        ciborium::from_reader(cbor_bytes.as_ref())
            .map_err(|_| crate::CryptoError::InvalidCborSerialization)
    }
}
