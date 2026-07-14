use std::pin::Pin;

use hmac::{KeyInit, Mac};
use hybrid_array::Array;
use typenum::U64;
use zeroize::Zeroizing;

use super::Aes256CbcHmacKey;
use crate::util::{PbkdfSha256Hmac, hkdf_expand};

/// Derive a shareable key using hkdf from secret and name.
///
/// A specialized variant of this function was called `CryptoService.makeSendKey` in the Bitwarden
/// `clients` repository.
pub fn derive_shareable_key(
    secret: Zeroizing<[u8; 16]>,
    name: &str,
    info: Option<&str>,
) -> Aes256CbcHmacKey {
    // Because all inputs are fixed size, we can unwrap all errors here without issue
    let res = Zeroizing::new(
        PbkdfSha256Hmac::new_from_slice(format!("bitwarden-{name}").as_bytes())
            .expect("hmac new_from_slice should not fail")
            .chain_update(secret)
            .finalize()
            .into_bytes(),
    );

    let key: Pin<Box<Array<u8, U64>>> = hkdf_expand(&res, info).expect("Input is a valid size");
    Aes256CbcHmacKey::from_bytes(key)
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::derive_shareable_key;
    use crate::SymmetricCryptoKey;

    #[test]
    fn test_derive_shareable_key() {
        let key = derive_shareable_key(Zeroizing::new(*b"&/$%F1a895g67HlX"), "test_key", None);
        assert_eq!(
            SymmetricCryptoKey::Aes256CbcHmacKey(key)
                .to_base64()
                .to_string(),
            "4PV6+PcmF2w7YHRatvyMcVQtI7zvCyssv/wFWmzjiH6Iv9altjmDkuBD1aagLVaLezbthbSe+ktR+U6qswxNnQ=="
        );

        let key = derive_shareable_key(
            Zeroizing::new(*b"67t9b5g67$%Dh89n"),
            "test_key",
            Some("test"),
        );
        assert_eq!(
            SymmetricCryptoKey::Aes256CbcHmacKey(key)
                .to_base64()
                .to_string(),
            "F9jVQmrACGx9VUPjuzfMYDjr726JtL300Y3Yg+VYUnVQtQ1s8oImJ5xtp1KALC9h2nav04++1LDW4iFD+infng=="
        );
    }
}
