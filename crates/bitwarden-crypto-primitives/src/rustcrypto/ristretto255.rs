use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint as Point},
    scalar::Scalar,
    traits::Identity,
};
use zeroize::Zeroizing;

use crate::{
    Error,
    ristretto255::{POINT_LEN, WIDE_LEN},
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct RistrettoPoint(Point);

impl RistrettoPoint {
    pub(crate) fn from_uniform_bytes(bytes: &[u8; WIDE_LEN]) -> Self {
        Self(Point::from_uniform_bytes(bytes))
    }

    pub(crate) fn decompress(bytes: &[u8]) -> Result<Self, Error> {
        CompressedRistretto::from_slice(bytes)
            .ok()
            .and_then(|c| c.decompress())
            .map(Self)
            .ok_or(Error::InvalidKey)
    }

    pub(crate) fn compress(&self) -> [u8; POINT_LEN] {
        self.0.compress().to_bytes()
    }

    pub(crate) fn is_identity(&self) -> bool {
        self.0 == Point::identity()
    }

    pub(crate) fn mul_wide(&self, wide_scalar: &[u8; WIDE_LEN]) -> Self {
        let scalar = Zeroizing::new(Scalar::from_bytes_mod_order_wide(wide_scalar));
        Self(self.0 * *scalar)
    }
}
