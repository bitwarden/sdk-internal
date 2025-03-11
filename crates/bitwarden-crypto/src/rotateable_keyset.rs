use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify_next::Tsify;

use crate::{
    rsa::make_key_pair, AsymmetricCryptoKey, AsymmetricEncString, AsymmetricPublicCryptoKey,
    CryptoError, EncString, KeyDecryptable, KeyEncryptable, SymmetricCryptoKey,
};

/// A rotateable keyset is a structure that takes an upstream external key
/// and a downstream encapsulated key. As an example, in TDE, the upstream, external key
/// is the device key, and the downstream encapsulated key is the user key. The keyset
/// can be rotated by having just access to the downstream key, and the downstream key can
/// be accessed by having access to the upstream key.
#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct RotateableKeyset {
    /// External key encrypted private key
    private_key: EncString,

    /// Userkey encrypted private key
    public_key: EncString,

    /// Publickey encrypted user key
    encapsulated_key: AsymmetricEncString,
}

impl RotateableKeyset {
    pub fn new(
        encapsulating_key: &SymmetricCryptoKey,
        encapsulated_key: &SymmetricCryptoKey,
    ) -> Result<Self, CryptoError> {
        let keypair = make_key_pair(encapsulating_key).map_err(|_| CryptoError::InvalidKey)?;
        let spki = STANDARD
            .decode(keypair.public.clone())
            .map_err(|_| CryptoError::InvalidKey)?;
        let encrypted_public_key = keypair.public.encrypt_with_key(encapsulating_key)?;
        let encrypted_private_key = keypair.private;

        let pubkey = AsymmetricPublicCryptoKey::from_der(&spki)?;
        let public_key_encrypted_encapsulated_key =
            AsymmetricEncString::encrypt_rsa2048_oaep_sha1(&encapsulated_key.to_vec(), &pubkey)?;
        Ok(RotateableKeyset {
            private_key: encrypted_private_key,
            public_key: encrypted_public_key,
            encapsulated_key: public_key_encrypted_encapsulated_key,
        })
    }

    pub fn decrypt_encapsulated_key(
        &self,
        encapsulating_key: &SymmetricCryptoKey,
    ) -> Result<SymmetricCryptoKey, CryptoError> {
        let private_key_bytes: Vec<u8> = self.private_key.decrypt_with_key(encapsulating_key)?;
        let private_key = AsymmetricCryptoKey::from_der(&private_key_bytes)?;
        let encapsulated_key: Vec<u8> = self.encapsulated_key.decrypt_with_key(&private_key)?;
        SymmetricCryptoKey::try_from(encapsulated_key)
    }
}

#[cfg(test)]
mod test {
    use super::RotateableKeyset;
    use crate::SymmetricCryptoKey;

    #[test]
    fn test_rotateable_keyset() {
        let key1 = SymmetricCryptoKey::generate(&mut rand::thread_rng());
        let key2 = SymmetricCryptoKey::generate(&mut rand::thread_rng());
        let keyset = RotateableKeyset::new(&key1, &key2).unwrap();
        let decrypted_key = keyset.decrypt_encapsulated_key(&key1).unwrap();
        assert_eq!(key2.to_vec(), decrypted_key.to_vec());
    }
}
