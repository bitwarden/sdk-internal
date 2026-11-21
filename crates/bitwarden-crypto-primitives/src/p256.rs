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
    use crate::test_vectors::{array, bytes};

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
            SecretKey::from_bytes(&array(
                "0000000000000000000000000000000000000000000000000000000000000000"
            ))
            .err(),
            Some(Error::InvalidKey)
        );
        assert_eq!(
            PublicKey::from_sec1_bytes(&bytes(
                "0404040404040404040404040404040404040404040404040404040404040404\
                0404040404040404040404040404040404040404040404040404040404040404\
                04"
            ))
            .err(),
            Some(Error::InvalidKey)
        );
    }

    /// P-256 group order `n` (SEC 2 §2.4.2).
    const ORDER: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

    /// Scalar 1 yields the generator `G`; `n - 1` is the largest valid scalar; `n` is rejected.
    #[test]
    fn known_answers_scalar_bounds() {
        const ONE: &str = "0000000000000000000000000000000000000000000000000000000000000001";
        /// `n - 1`, the largest valid scalar.
        const ORDER_MINUS_1: &str =
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550";

        assert_eq!(
            hex::encode(
                SecretKey::from_bytes(&array(ONE))
                    .expect("valid")
                    .public_key()
                    .to_sec1_uncompressed()
            ),
            "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2\
            964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51\
            f5"
        );

        assert!(SecretKey::from_bytes(&array(ORDER_MINUS_1)).is_ok());
        assert_eq!(
            SecretKey::from_bytes(&array(ORDER)).err(),
            Some(Error::InvalidKey)
        );
    }

    #[test]
    fn known_answers_fixed_scalars() {
        const SCALAR_42: &str = "4242424242424242424242424242424242424242424242424242424242424242";
        const SCALAR_24: &str = "2424242424242424242424242424242424242424242424242424242424242424";

        let a = SecretKey::from_bytes(&array(SCALAR_42)).expect("valid");
        let b = SecretKey::from_bytes(&array(SCALAR_24)).expect("valid");

        assert_eq!(
            hex::encode(a.public_key().to_sec1_uncompressed()),
            "043ad3861a95621392516bb593ef05583ed2e5866f5cb6260a3017237fd89b90\
            afd0961c7e37075a6791a39c61f56295b02b6d26567b615e60aa41ee1c8e8338\
            8d"
        );
        assert_eq!(
            hex::encode(a.to_pkcs8_der().expect("encodes").as_slice()),
            "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02\
            0101042042424242424242424242424242424242424242424242424242424242\
            42424242a144034200043ad3861a95621392516bb593ef05583ed2e5866f5cb6\
            260a3017237fd89b90afd0961c7e37075a6791a39c61f56295b02b6d26567b61\
            5e60aa41ee1c8e83388d"
        );
        assert_eq!(
            hex::encode(a.diffie_hellman(&b.public_key()).as_slice()),
            "e349cf6859d17371eaad97b5605b346539b69cef845378beaab8c3e54b0d12c7"
        );
    }
}
