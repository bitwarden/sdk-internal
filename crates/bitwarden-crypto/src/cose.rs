//! This file contains private-use constants for COSE encoded key types and algorithms.
//! Standardized values from <https://www.iana.org/assignments/cose/cose.xhtml> should always be preferred
//! unless there is a specific reason to use a private-use value.

use coset::CborSerializable;

use crate::{error::EncStringParseError, CryptoError};

// XChaCha20 <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03> is used over ChaCha20
// to be able to randomly generate nonces, and to not have to worry about key wearout. Since
// the draft was never published as an RFC, we use a private-use value for the algorithm.
pub(crate) const XCHACHA20_POLY1305: i64 = -70000;

pub(crate) fn encrypt_xchacha20_poly1305(
    plaintext: &[u8],
    key: &crate::XChaCha20Poly1305Key,
) -> Result<Vec<u8>, CryptoError> {
    let mut protected_header = coset::HeaderBuilder::new().build();
    protected_header.alg = Some(coset::Algorithm::PrivateUse(XCHACHA20_POLY1305));

    let mut nonce = [0u8; 24];
    let cose_encrypt0 = coset::CoseEncrypt0Builder::new()
        .protected(protected_header)
        .create_ciphertext(plaintext, &[], |data, aad| {
            let ciphertext =
                crate::xchacha20::encrypt_xchacha20_poly1305(&(*key.enc_key).into(), data, aad);
            nonce = ciphertext.nonce();
            ciphertext.encrypted_bytes()
        })
        .unprotected(coset::HeaderBuilder::new().iv(nonce.to_vec()).build())
        .build();

    cose_encrypt0
        .to_vec()
        .map_err(|err| CryptoError::EncString(EncStringParseError::InvalidCoseEncoding(err)))
}
