use crate::{CryptoError, SymmetricCryptoKey, utils::stretch_key};

/// Takes the output of a PRF and derives a symmetric key.
///
/// The PRF output must be at least 32 bytes long.
pub fn derive_symmetric_key_from_prf(prf: &[u8]) -> Result<SymmetricCryptoKey, CryptoError> {
    let (secret, _) = prf.split_at_checked(32).ok_or(CryptoError::InvalidKeyLen)?;
    let secret: [u8; 32] = secret.try_into().expect("length to be 32 bytes");
    // Don't allow uninitialized PRFs
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
        let prf = pseudorandom_bytes(32);
        let key = derive_symmetric_key_from_prf(&prf).unwrap();
        assert!(matches!(key, SymmetricCryptoKey::Aes256CbcHmacKey(_)));
    }

    #[test]
    fn test_zero_key_fails() {
        let prf: Vec<u8> = (0..32).map(|_| 0).collect();
        let err = derive_symmetric_key_from_prf(&prf).unwrap_err();
        assert!(matches!(err, CryptoError::ZeroNumber));
    }

    #[test]
    fn test_short_prf_fails() {
        let prf = pseudorandom_bytes(9);
        let err = derive_symmetric_key_from_prf(&prf).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidKeyLen));
    }

    #[test]
    fn test_long_prf_truncated_to_proper_length() {
        let long_prf = pseudorandom_bytes(33);
        let prf = pseudorandom_bytes(32);
        let key1 = derive_symmetric_key_from_prf(&long_prf).unwrap();
        let key2 = derive_symmetric_key_from_prf(&prf).unwrap();
        assert_eq!(key1, key2);
    }

    /// This returns the same bytes deterministically for a given length.
    fn pseudorandom_bytes(len: usize) -> Vec<u8> {
        (0..len).map(|x| (x % 255) as u8).collect()
    }
}
