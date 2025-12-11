use std::pin::Pin;

use bitwarden_encoding::B64;
use generic_array::GenericArray;
use rand::Rng;
use typenum::U32;

use crate::{EncString, SymmetricCryptoKey, keys::utils::stretch_key};

/// Key connector key, used to protect the [UserKey].
#[derive(Clone, Debug)]
pub struct KeyConnectorKey(pub(super) Pin<Box<GenericArray<u8, U32>>>);

impl KeyConnectorKey {
    /// Generate a new random for KeyConnector.
    pub fn generate(mut rng: impl rand::RngCore) -> Self {
        let mut key = Box::pin(GenericArray::<u8, U32>::default());

        rng.fill(key.as_mut_slice());
        KeyConnectorKey(key)
    }

    #[allow(missing_docs)]
    pub fn to_base64(&self) -> B64 {
        B64::from(self.0.as_slice())
    }

    /// Wraps the user key with this key connector key.
    pub fn encrypt_user_key(
        &self,
        user_key: &SymmetricCryptoKey,
    ) -> crate::error::Result<EncString> {
        let stretched_master_key = stretch_key(&self.0)?;
        let user_key_bytes = user_key.to_encoded();
        EncString::encrypt_aes256_hmac(user_key_bytes.as_ref(), &stretched_master_key)
    }
}
