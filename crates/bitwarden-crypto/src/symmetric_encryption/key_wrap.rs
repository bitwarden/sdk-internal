use crate::{BitwardenLegacyKeyBytes, ContentFormat, CryptoError, EncString, SymmetricCryptoKey};

pub(crate) fn unwrap_symmetric_key(
    wrapped_key: &EncString,
    wrapping_key: &SymmetricCryptoKey,
) -> Result<SymmetricCryptoKey, CryptoError> {
    let key = match (wrapped_key, wrapping_key) {
        (EncString::Aes256Cbc_B64 { iv, data }, SymmetricCryptoKey::Aes256CbcKey(key)) => {
            SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(
                super::hazmat::aes::decrypt_aes256(iv, data.clone(), &key.enc_key)?,
            ))?
        }
        (
            EncString::Aes256Cbc_HmacSha256_B64 { iv, mac, data },
            SymmetricCryptoKey::Aes256CbcHmacKey(key),
        ) => SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(
            super::hazmat::aes::decrypt_aes256_hmac(
                iv,
                mac,
                data.clone(),
                &key.mac_key,
                &key.enc_key,
            )?,
        ))?,
        (EncString::Cose_Encrypt0_B64 { data }, SymmetricCryptoKey::XChaCha20Poly1305Key(key)) => {
            let (content_bytes, content_format) =
                super::cose::decrypt_xchacha20_poly1305(data, key)?;
            match content_format {
                ContentFormat::BitwardenLegacyKey => {
                    SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(content_bytes))?
                }
                ContentFormat::CoseKey => SymmetricCryptoKey::try_from_cose(&content_bytes)?,
                _ => return Err(CryptoError::InvalidKey),
            }
        }
        _ => return Err(CryptoError::InvalidKey),
    };
    Ok(key)
}
