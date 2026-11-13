use bitwarden_crypto_primitives::rsa::{
    KeySize, OaepHash, PrivateKey as RsaPrivateKey, PublicKey as RsaPublicKey,
};
use bitwarden_encoding::B64;

use crate::{
    CryptoError, EncString, SymmetricCryptoKey,
    error::{Result, RsaError, UnsupportedOperationError},
    slow_crypto_span::{SlowCryptoOp, SlowCryptoSpan, measure},
};

/// RSA Key Pair
///
/// Consists of a public key and an encrypted private key.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct RsaKeyPair {
    /// Base64 encoded DER representation of the public key
    pub public: B64,
    /// Encrypted PKCS8 private key
    pub private: EncString,
}

/// Generate a new RSA key pair of 2048 bits
pub(crate) fn make_key_pair(key: &SymmetricCryptoKey) -> Result<RsaKeyPair> {
    let priv_key = measure(SlowCryptoOp::RsaKeyGeneration, || {
        RsaPrivateKey::generate(KeySize::Rsa2048)
    });
    let pub_key = priv_key.public_key();

    let spki = pub_key
        .to_spki_der()
        .map_err(|_| RsaError::CreatePublicKey)?;

    let pkcs = priv_key
        .to_pkcs8_der()
        .map_err(|_| RsaError::CreatePrivateKey)?;

    let protected = match key {
        SymmetricCryptoKey::Aes256CbcHmacKey(key) => EncString::encrypt_aes256_hmac(&pkcs, key),
        SymmetricCryptoKey::XChaCha20Poly1305Key(_) => Err(CryptoError::OperationNotSupported(
            UnsupportedOperationError::EncryptionNotImplementedForKey,
        )),
        SymmetricCryptoKey::Aes256CbcKey(_) => Err(CryptoError::OperationNotSupported(
            UnsupportedOperationError::EncryptionNotImplementedForKey,
        )),
        SymmetricCryptoKey::Aes256GcmKey(_) => Err(CryptoError::OperationNotSupported(
            UnsupportedOperationError::EncryptionNotImplementedForKey,
        )),
        SymmetricCryptoKey::XAes256GcmKey(_) => Err(CryptoError::OperationNotSupported(
            UnsupportedOperationError::EncryptionNotImplementedForKey,
        )),
    }?;

    Ok(RsaKeyPair {
        public: spki.into(),
        private: protected,
    })
}

/// Encrypt data using RSA-OAEP-SHA1 with a 2048 bit key
pub(super) fn encrypt_rsa2048_oaep_sha1(public_key: &RsaPublicKey, data: &[u8]) -> Result<Vec<u8>> {
    let _span = SlowCryptoSpan::start(SlowCryptoOp::RsaEncrypt);
    public_key
        .encrypt_oaep(OaepHash::Sha1, data)
        .map_err(|e| CryptoError::Rsa(e.into()))
}
