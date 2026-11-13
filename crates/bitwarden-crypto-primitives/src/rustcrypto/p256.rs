use p256::{
    elliptic_curve::{Generate, sec1::ToSec1Point},
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
};
use zeroize::Zeroizing;

use crate::{
    Error,
    p256::{SCALAR_LEN, SEC1_UNCOMPRESSED_LEN},
    random::SystemRng,
};

#[derive(Clone)]
pub(crate) struct SecretKey(p256::SecretKey);

// The wrapped key wipes itself on drop.
impl zeroize::ZeroizeOnDrop for SecretKey {}
const _: fn() = || {
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<p256::SecretKey>();
};

impl SecretKey {
    pub(crate) fn generate() -> Self {
        Self(p256::SecretKey::generate_from_rng(&mut SystemRng))
    }

    pub(crate) fn from_bytes(scalar: &[u8; SCALAR_LEN]) -> Result<Self, Error> {
        p256::SecretKey::from_slice(scalar)
            .map(Self)
            .map_err(|_| Error::InvalidKey)
    }

    pub(crate) fn to_bytes(&self) -> Zeroizing<[u8; SCALAR_LEN]> {
        Zeroizing::new(self.0.to_bytes().into())
    }

    pub(crate) fn from_pkcs8_der(der: &[u8]) -> Result<Self, Error> {
        p256::SecretKey::from_pkcs8_der(der)
            .map(Self)
            .map_err(|_| Error::InvalidKey)
    }

    pub(crate) fn to_pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let doc = self.0.to_pkcs8_der().map_err(|_| Error::InvalidKey)?;
        Ok(Zeroizing::new(doc.as_bytes().to_vec()))
    }

    pub(crate) fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public_key())
    }

    pub(crate) fn diffie_hellman(&self, peer: &PublicKey) -> Zeroizing<[u8; SCALAR_LEN]> {
        let shared = p256::ecdh::diffie_hellman(self.0.to_nonzero_scalar(), peer.0.as_affine());
        Zeroizing::new((*shared.raw_secret_bytes()).into())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PublicKey(p256::PublicKey);

impl PublicKey {
    pub(crate) fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, Error> {
        p256::PublicKey::from_sec1_bytes(bytes)
            .map(Self)
            .map_err(|_| Error::InvalidKey)
    }

    pub(crate) fn to_sec1_uncompressed(&self) -> [u8; SEC1_UNCOMPRESSED_LEN] {
        self.0
            .to_sec1_point(false)
            .as_bytes()
            .try_into()
            .expect("uncompressed P-256 point is 65 bytes")
    }
}
