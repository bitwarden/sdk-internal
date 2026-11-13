//! Unsupported: OpenSSL has no ristretto255 group API.

use crate::{
    Error,
    ristretto255::{POINT_LEN, WIDE_LEN},
};

const UNSUPPORTED: &str = "ristretto255 is not available on the OpenSSL backend";

/// Uninhabited: no point can be constructed on this backend.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum RistrettoPoint {}

impl RistrettoPoint {
    pub(crate) fn from_uniform_bytes(_bytes: &[u8; WIDE_LEN]) -> Self {
        unimplemented!("{UNSUPPORTED}")
    }

    pub(crate) fn decompress(_bytes: &[u8]) -> Result<Self, Error> {
        unimplemented!("{UNSUPPORTED}")
    }

    pub(crate) fn compress(&self) -> [u8; POINT_LEN] {
        match *self {}
    }

    pub(crate) fn is_identity(&self) -> bool {
        match *self {}
    }

    pub(crate) fn mul_wide(&self, _wide_scalar: &[u8; WIDE_LEN]) -> Self {
        match *self {}
    }
}
