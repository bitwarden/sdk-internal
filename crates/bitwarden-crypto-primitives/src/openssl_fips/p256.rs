//! Unsupported: P-256 is not available on the OpenSSL backend.

use zeroize::Zeroizing;

use crate::{
    Error,
    p256::{SCALAR_LEN, SEC1_UNCOMPRESSED_LEN},
};

const UNSUPPORTED: &str = "P-256 is not available on the OpenSSL backend";

/// Uninhabited: no key can be constructed on this backend.
#[derive(Clone)]
pub(crate) enum SecretKey {}

// Uninhabited, so there is no key material to wipe.
impl zeroize::ZeroizeOnDrop for SecretKey {}

impl SecretKey {
    pub(crate) fn generate() -> Self {
        unimplemented!("{UNSUPPORTED}")
    }

    pub(crate) fn from_bytes(_scalar: &[u8; SCALAR_LEN]) -> Result<Self, Error> {
        unimplemented!("{UNSUPPORTED}")
    }

    pub(crate) fn to_bytes(&self) -> Zeroizing<[u8; SCALAR_LEN]> {
        match *self {}
    }

    pub(crate) fn from_pkcs8_der(_der: &[u8]) -> Result<Self, Error> {
        unimplemented!("{UNSUPPORTED}")
    }

    pub(crate) fn to_pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        match *self {}
    }

    pub(crate) fn public_key(&self) -> PublicKey {
        match *self {}
    }

    pub(crate) fn diffie_hellman(&self, _peer: &PublicKey) -> Zeroizing<[u8; SCALAR_LEN]> {
        match *self {}
    }
}

/// Uninhabited: no key can be constructed on this backend.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum PublicKey {}

impl PublicKey {
    pub(crate) fn from_sec1_bytes(_bytes: &[u8]) -> Result<Self, Error> {
        unimplemented!("{UNSUPPORTED}")
    }

    pub(crate) fn to_sec1_uncompressed(&self) -> [u8; SEC1_UNCOMPRESSED_LEN] {
        match *self {}
    }
}
