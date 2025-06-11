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
        encapsulating_key_material: &[u8],
        encapsulated_key: &SymmetricCryptoKey,
    ) -> Result<Self, CryptoError> {
        let key = if encapsulating_key_material.len() == 64 {
            SymmetricCryptoKey::try_from(encapsulating_key_material.to_vec())?
        } else {
            return Err(CryptoError::InvalidKey);
        };

        let keypair = make_key_pair(&key).map_err(|_| CryptoError::InvalidKey)?;
        let public_key = STANDARD
            .decode(keypair.public.clone())
            .map_err(|_| CryptoError::InvalidKey)
            .map(|key_bytes| AsymmetricPublicCryptoKey::from_der(&key_bytes))??;
        Ok(RotateableKeyset {
            private_key: keypair.private,
            public_key: keypair.public.encrypt_with_key(&key)?,
            encapsulated_key: AsymmetricEncString::encrypt_rsa2048_oaep_sha1(
                &encapsulated_key.to_vec(),
                &public_key,
            )?,
        })
    }

    pub fn decapsulate_key(
        &self,
        encapsulating_key_material: &[u8],
    ) -> Result<SymmetricCryptoKey, CryptoError> {
        let key = match self.private_key {
            EncString::AesCbc256_HmacSha256_B64 { .. } => {
                if encapsulating_key_material.len() == 64 {
                    SymmetricCryptoKey::try_from(encapsulating_key_material.to_vec())?
                } else {
                    return Err(CryptoError::InvalidKey);
                }
            }
            EncString::AesCbc256_B64 { .. } => return Err(CryptoError::InvalidKey),
        };

        let private_key_bytes: Vec<u8> = self.private_key.decrypt_with_key(&key)?;
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
        let key_material = vec![0; 64];
        let key_to_encapsulate = SymmetricCryptoKey::generate(rand::thread_rng());
        let keyset = RotateableKeyset::new(&key_material, &key_to_encapsulate).unwrap();
        let decrypted_key = keyset.decapsulate_key(&key_material).unwrap();
        assert_eq!(key_to_encapsulate.to_vec(), decrypted_key.to_vec());
    }
}
