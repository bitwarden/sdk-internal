//! ristretto255 group operations (RFC 9496), as used by CPace.

use crate::{Error, backend};

/// A ristretto255 group element.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RistrettoPoint(backend::ristretto255::RistrettoPoint);

impl RistrettoPoint {
    /// Maps 64 uniform bytes to a point (RFC 9496 §4.3.4).
    pub fn from_uniform_bytes(bytes: &[u8; 64]) -> Self {
        Self(backend::ristretto255::RistrettoPoint::from_uniform_bytes(
            bytes,
        ))
    }

    /// Decodes a canonical 32-byte encoding.
    pub fn decompress(bytes: &[u8]) -> Result<Self, Error> {
        backend::ristretto255::RistrettoPoint::decompress(bytes).map(Self)
    }

    /// Returns the canonical 32-byte encoding.
    pub fn compress(&self) -> [u8; 32] {
        self.0.compress()
    }

    /// Returns whether this is the identity element.
    pub fn is_identity(&self) -> bool {
        self.0.is_identity()
    }

    /// Multiplies by the scalar `wide_scalar mod ℓ` (64 bytes, little-endian).
    pub fn mul_wide(&self, wide_scalar: &[u8; 64]) -> Self {
        Self(self.0.mul_wide(wide_scalar))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_multiplication_commutes() {
        let g = RistrettoPoint::from_uniform_bytes(&[1; 64]);
        let (a, b) = ([2; 64], [3; 64]);
        assert!(g.mul_wide(&a).mul_wide(&b) == g.mul_wide(&b).mul_wide(&a));
    }

    #[test]
    fn encoding_roundtrip_and_identity() {
        let g = RistrettoPoint::from_uniform_bytes(&[1; 64]);
        assert!(RistrettoPoint::decompress(&g.compress()).expect("canonical") == g);
        assert!(!g.is_identity());

        let identity = RistrettoPoint::decompress(&[0; 32]).expect("identity encodes as zeros");
        assert!(identity.is_identity());

        assert_eq!(
            RistrettoPoint::decompress(&[0xff; 32]).err(),
            Some(Error::InvalidKey)
        );
        assert_eq!(
            RistrettoPoint::decompress(&[0; 31]).err(),
            Some(Error::InvalidKey)
        );
    }
}
