use bitwarden_encoding::B64;
use bitwarden_performance_tracking::PerformanceEventDescriptor;
use rsa::{
    Oaep, RsaPrivateKey, RsaPublicKey,
    pkcs8::{EncodePrivateKey, EncodePublicKey},
};
use sha1::Sha1;

use crate::{
    CryptoError, EncString, SymmetricCryptoKey,
    error::{Result, RsaError, UnsupportedOperationError},
    trace,
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

/// Modulus size of every RSA key pair the SDK generates.
pub(crate) const RSA_KEY_BITS: usize = 2048;

/// Draws an RSA operation on the slow crypto track.
pub(crate) fn rsa_entry(name: &'static str) -> PerformanceEventDescriptor {
    PerformanceEventDescriptor::new(trace::GROUP, trace::RSA_TRACK, name)
}

/// Generate a new RSA key pair of 2048 bits
pub(crate) fn make_key_pair(key: &SymmetricCryptoKey) -> Result<RsaKeyPair> {
    let mut rng = bitwarden_random::rng();
    let priv_key = {
        let _event = rsa_entry("Generate key pair")
            .prop("bits", RSA_KEY_BITS)
            .start();

        RsaPrivateKey::new(&mut rng, RSA_KEY_BITS).expect("failed to generate a key")
    };
    let pub_key = RsaPublicKey::from(&priv_key);

    let spki = pub_key
        .to_public_key_der()
        .map_err(|_| RsaError::CreatePublicKey)?;

    let pkcs = priv_key
        .to_pkcs8_der()
        .map_err(|_| RsaError::CreatePrivateKey)?;

    let protected = match key {
        SymmetricCryptoKey::Aes256CbcHmacKey(key) => {
            EncString::encrypt_aes256_hmac(pkcs.as_bytes(), key)
        }
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
        public: spki.as_ref().into(),
        private: protected,
    })
}

/// Encrypt data using RSA-OAEP-SHA1 with a 2048 bit key
pub(super) fn encrypt_rsa2048_oaep_sha1(public_key: &RsaPublicKey, data: &[u8]) -> Result<Vec<u8>> {
    let mut rng = bitwarden_random::rng();

    let padding = Oaep::<Sha1>::new();
    let mut event = rsa_entry("Encrypt").prop("padding", "OAEP-SHA1").start();

    let result = public_key
        .encrypt(&mut rng, padding, data)
        .map_err(|e| CryptoError::Rsa(e.into()));
    event.record_result(&result);

    result
}
