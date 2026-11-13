//! ristretto255 group operations (RFC 9496), as used by CPace.

use crate::{Error, backend};

/// Compressed point length in bytes.
pub const POINT_LEN: usize = 32;
/// Length in bytes of the uniform input to `from_uniform_bytes` and of wide scalars.
pub const WIDE_LEN: usize = 64;

/// A ristretto255 group element.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RistrettoPoint(backend::ristretto255::RistrettoPoint);

impl RistrettoPoint {
    /// Maps 64 uniform bytes to a point (RFC 9496 §4.3.4).
    pub fn from_uniform_bytes(bytes: &[u8; WIDE_LEN]) -> Self {
        Self(backend::ristretto255::RistrettoPoint::from_uniform_bytes(
            bytes,
        ))
    }

    /// Decodes a canonical 32-byte encoding.
    pub fn decompress(bytes: &[u8]) -> Result<Self, Error> {
        backend::ristretto255::RistrettoPoint::decompress(bytes).map(Self)
    }

    /// Returns the canonical 32-byte encoding.
    pub fn compress(&self) -> [u8; POINT_LEN] {
        self.0.compress()
    }

    /// Returns whether this is the identity element.
    pub fn is_identity(&self) -> bool {
        self.0.is_identity()
    }

    /// Multiplies by the scalar `wide_scalar mod ℓ` (64 bytes, little-endian).
    pub fn mul_wide(&self, wide_scalar: &[u8; WIDE_LEN]) -> Self {
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

    /// RFC 9496 Appendix A.1: the encoding of the basepoint `B`.
    const BASEPOINT: &str = "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76";

    #[test]
    fn known_answers() {
        let point = RistrettoPoint::from_uniform_bytes(&[0x42; WIDE_LEN]);
        assert_eq!(
            hex::encode(point.compress()),
            "441bdd7b3fb1a07d8a8add8ca6ede38cbce78eef2a34323aa4c2cce37db81561"
        );
        assert_eq!(
            hex::encode(point.mul_wide(&[0x24; WIDE_LEN]).compress()),
            "ca2d29b8b09bf24387d77c47cb5495332b44ac465c1a35e5bca5302a77f48239"
        );

        let basepoint =
            RistrettoPoint::decompress(&hex::decode(BASEPOINT).expect("hex")).expect("canonical");
        assert_eq!(hex::encode(basepoint.compress()), BASEPOINT);

        // Scalar 1 (little-endian, wide) is the identity map.
        let mut one = [0u8; WIDE_LEN];
        one[0] = 1;
        assert!(basepoint.mul_wide(&one) == basepoint);
    }
}
