use crate::{CryptoError, SymmetricCryptoKey, utils::stretch_key};

/// Takes the output of a PRF and derives a symmetric key
pub fn derive_symmetric_key_from_prf(prf: &[u8]) -> Result<SymmetricCryptoKey, CryptoError> {
    let (secret, _) = prf
        .split_at_checked(32)
        .ok_or_else(|| CryptoError::InvalidKeyLen)?;
    let secret: [u8; 32] = secret.try_into().unwrap();
    if secret.iter().all(|b| *b == b'\0') {
        return Err(CryptoError::ZeroNumber);
    }
    Ok(SymmetricCryptoKey::Aes256CbcHmacKey(stretch_key(
        &Box::pin(secret.into()),
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_prf_succeeds() {
        let prf = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ];
        derive_symmetric_key_from_prf(&prf).unwrap();
    }

    #[test]
    fn test_zero_key_fails() {
        let prf = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        let err = derive_symmetric_key_from_prf(&prf).unwrap_err();
        assert!(matches!(err, CryptoError::ZeroNumber));
    }
    #[test]
    fn test_short_prf_fails() {
        let prf = [0, 1, 2, 3, 4, 5, 6, 7, 8];
        let err = derive_symmetric_key_from_prf(&prf).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidKeyLen));
    }
}
