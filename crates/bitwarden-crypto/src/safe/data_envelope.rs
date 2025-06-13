use std::marker::PhantomData;

use coset::CoseEncrypt0;
use serde::{de::DeserializeOwned, Serialize};

use crate::{KeyIds, KeyStoreContext, SymmetricCryptoKey};

/// Marker trait for data that can be sealed in a `DataEnvelope`.
pub(crate) trait SealableData {}

/// `DataEnvelope` allows sealing structs entire structs to encrypted blobs.
///
/// Sealing a struct results in an encrypted blob, and a content-encryption-key. The content-encryption-key must be provided again when unsealing the data.
/// A content encryption key allows easy key-rotation of the encrypting-key, as now just the content-encryption-keys need to be re-uploaded, instead of all data.
pub(crate) struct DataEnvelope<Ids: KeyIds> {
    envelope_data: CoseEncrypt0,
    _phantom: PhantomData<Ids>,
}

impl<Ids: KeyIds> DataEnvelope<Ids> {
    pub(crate) fn seal<T>(
        data: &T,
        mut ctx: &KeyStoreContext<Ids>,
        keyslot_id: Ids::Symmetric,
    ) -> DataEnvelope<Ids>
    where
        T: Serialize + SealableData,
    {
        // Serialize the data
        // Encrypt the serialized data
        unimplemented!()
    }

    pub(crate) fn unseal<T>(&self, mut ctx: &KeyStoreContext<Ids>, keyslot_id: Ids::Symmetric) -> T
    where
        T: DeserializeOwned + SealableData,
    {
        // Decrypt the data using the content-encryption-key
        // Deserialize the decrypted data
        unimplemented!()
    }
}
