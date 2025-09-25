use crate::{util::hkdf_expand, Aes256CbcHmacKey, CryptoError, SymmetricCryptoKey};

pub enum Prf {
    WebauthnPrf,
}

/// Takes the output of a PRF and derives a symmetric key
pub fn derive_symmetric_key_from_prf(
    secret: &[u8],
    prf: &Prf,
) -> Result<SymmetricCryptoKey, CryptoError> {
    match prf {
        Prf::WebauthnPrf => Ok(SymmetricCryptoKey::Aes256CbcHmacKey(Aes256CbcHmacKey {
            enc_key: hkdf_expand(secret, Some("enc"))?,
            mac_key: hkdf_expand(secret, Some("mac"))?,
        })),
    }
}
