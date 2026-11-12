//! NIST P-256 keys and ECDH.

use zeroize::Zeroizing;

use crate::{Error, backend};

/// Secret scalar length in bytes.
pub const SCALAR_LEN: usize = 32;
/// Uncompressed SEC1 point length in bytes (`0x04 || x || y`).
pub const SEC1_UNCOMPRESSED_LEN: usize = 65;

/// P-256 secret scalar. Zeroized on drop.
#[derive(Clone)]
pub struct SecretKey(backend::p256::SecretKey);

impl zeroize::ZeroizeOnDrop for SecretKey where backend::p256::SecretKey: zeroize::ZeroizeOnDrop {}

impl SecretKey {
    /// Generates a fresh key.
    pub fn generate() -> Self {
        Self(backend::p256::SecretKey::generate())
    }

    /// Builds a key from a big-endian scalar.
    pub fn from_bytes(scalar: &[u8; SCALAR_LEN]) -> Result<Self, Error> {
        backend::p256::SecretKey::from_bytes(scalar).map(Self)
    }

    /// Returns the big-endian scalar.
    pub fn to_bytes(&self) -> Zeroizing<[u8; SCALAR_LEN]> {
        self.0.to_bytes()
    }

    /// Parses a PKCS#8 `PrivateKeyInfo`.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, Error> {
        backend::p256::SecretKey::from_pkcs8_der(der).map(Self)
    }

    /// Serializes as PKCS#8 `PrivateKeyInfo`.
    pub fn to_pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.0.to_pkcs8_der()
    }

    /// Returns the matching public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public_key())
    }

    /// ECDH with `peer`. Returns the shared point's x-coordinate.
    pub fn diffie_hellman(&self, peer: &PublicKey) -> Zeroizing<[u8; SCALAR_LEN]> {
        self.0.diffie_hellman(&peer.0)
    }
}

/// P-256 public point.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey(backend::p256::PublicKey);

impl PublicKey {
    /// Parses a SEC1 point (compressed or uncompressed).
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, Error> {
        backend::p256::PublicKey::from_sec1_bytes(bytes).map(Self)
    }

    /// Returns the uncompressed SEC1 encoding.
    pub fn to_sec1_uncompressed(&self) -> [u8; SEC1_UNCOMPRESSED_LEN] {
        self.0.to_sec1_uncompressed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdh_agrees() {
        let (a, b) = (SecretKey::generate(), SecretKey::generate());
        assert_eq!(
            *a.diffie_hellman(&b.public_key()),
            *b.diffie_hellman(&a.public_key())
        );
    }

    #[test]
    fn encodings_roundtrip() {
        let key = SecretKey::generate();

        let der = key.to_pkcs8_der().expect("encodes");
        let parsed = SecretKey::from_pkcs8_der(&der).expect("parses");
        assert_eq!(*parsed.to_bytes(), *key.to_bytes());
        assert!(
            SecretKey::from_bytes(&key.to_bytes())
                .expect("valid")
                .public_key()
                == key.public_key()
        );

        let sec1 = key.public_key().to_sec1_uncompressed();
        assert!(PublicKey::from_sec1_bytes(&sec1).expect("valid") == key.public_key());

        assert_eq!(
            SecretKey::from_bytes(&[0; 32]).err(),
            Some(Error::InvalidKey)
        );
        assert_eq!(
            PublicKey::from_sec1_bytes(&[4; 65]).err(),
            Some(Error::InvalidKey)
        );
    }
}
