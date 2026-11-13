//! XChaCha20-Poly1305.

use crate::{Error, backend};

/// Key length in bytes.
pub const KEY_LEN: usize = 32;
/// Nonce length in bytes.
pub const NONCE_LEN: usize = 24;
/// Authentication tag length in bytes.
pub const TAG_LEN: usize = 16;

/// Encrypts `plaintext` and authenticates it with `aad`. Returns `ciphertext || tag`.
///
/// The caller must never reuse a nonce under the same key.
pub fn encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    backend::xchacha20_poly1305::encrypt(key, nonce, aad, plaintext)
}

/// Verifies and decrypts `ciphertext || tag`.
pub fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    backend::xchacha20_poly1305::decrypt(key, nonce, aad, ciphertext)
}

// The OpenSSL backend does not support this primitive.
#[cfg(all(test, not(bitwarden_crypto_backend = "openssl")))]
mod tests {
    use super::*;
    use crate::test_vectors::{array, bytes};

    const KEY: &str = "0707070707070707070707070707070707070707070707070707070707070707";
    const NONCE: &str = "090909090909090909090909090909090909090909090909";

    #[test]
    fn roundtrip() {
        let ct = encrypt(&array(KEY), &array(NONCE), b"aad", b"plaintext");
        assert_eq!(ct.len(), b"plaintext".len() + TAG_LEN);
        assert_eq!(
            decrypt(&array(KEY), &array(NONCE), b"aad", &ct),
            Ok(b"plaintext".to_vec())
        );
    }

    #[test]
    fn rejects_tampering() {
        let mut ct = encrypt(&array(KEY), &array(NONCE), b"aad", b"plaintext");
        assert_eq!(
            decrypt(&array(KEY), &array(NONCE), b"other", &ct),
            Err(Error::DecryptionFailed)
        );

        ct[0] ^= 1;
        assert_eq!(
            decrypt(&array(KEY), &array(NONCE), b"aad", &ct),
            Err(Error::DecryptionFailed)
        );
        assert_eq!(
            decrypt(&array(KEY), &array(NONCE), b"aad", &ct[..4]),
            Err(Error::DecryptionFailed)
        );
    }

    /// Edge cases under fixed key and nonce: empty plaintext with AAD (tag only), a plaintext one
    /// byte past a block without AAD, and a multi-block plaintext with AAD.
    #[test]
    fn known_answers() {
        const KEY_42: &str = "4242424242424242424242424242424242424242424242424242424242424242";
        const NONCE_24: &str = "242424242424242424242424242424242424242424242424";

        // (aad, plaintext, ciphertext || tag), all hex
        let cases = [
            ("616164", "", "bb3d3db24cbd51fdd25cb14e51c03ed8"),
            (
                "",
                "1111111111111111111111111111111111",
                "b44fc6747f355db7b33e2e2b1f991cdb23a66e8baea84463df6b29df542779ce\
                1d",
            ),
            (
                "616164",
                "54686520717569636b2062726f776e20666f78206a756d7073206f7665722074\
                6865206c617a7920646f67",
                "f136b2451f5125c5c90f5d4861ff63ea549ef69a166a19ed5241893b0e62fbb9\
                7cf4a8b455e122bc18dad68ba7eb2a903d166f31fa83074b716ac9",
            ),
        ];
        let (key, nonce) = (array::<KEY_LEN>(KEY_42), array::<NONCE_LEN>(NONCE_24));
        for (aad, plaintext, expected) in cases {
            let (aad, plaintext) = (bytes(aad), bytes(plaintext));
            let ciphertext = encrypt(&key, &nonce, &aad, &plaintext);
            assert_eq!(hex::encode(&ciphertext), expected);
            assert_eq!(decrypt(&key, &nonce, &aad, &ciphertext), Ok(plaintext));
        }
    }
}

#[cfg(all(test, bitwarden_crypto_backend = "openssl"))]
mod unsupported_on_openssl {
    use super::*;
    use crate::test_vectors::array;

    const KEY: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const NONCE: &str = "000000000000000000000000000000000000000000000000";

    #[test]
    #[should_panic(expected = "XChaCha20-Poly1305 is not available on the OpenSSL backend")]
    fn panics() {
        let _ = decrypt(&array(KEY), &array(NONCE), b"", b"");
    }
}
