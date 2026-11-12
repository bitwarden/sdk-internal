use rsa::{
    BoxedUint, Oaep, RsaPrivateKey, RsaPublicKey,
    pkcs1::DecodeRsaPrivateKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    traits::{PrivateKeyParts, PublicKeyParts},
};
use zeroize::Zeroizing;

use crate::{
    Error,
    random::SystemRng,
    rsa::{KeySize, OaepHash, PrivateComponents},
};

/// Number of primes in a standard (non multi-prime) RSA key.
const TWO_PRIMES: usize = 2;

#[derive(Clone)]
pub(crate) struct PrivateKey(RsaPrivateKey);

// The wrapped key wipes itself on drop.
impl zeroize::ZeroizeOnDrop for PrivateKey {}
const _: fn() = || {
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<RsaPrivateKey>();
};

impl PrivateKey {
    pub(crate) fn generate(size: KeySize) -> Self {
        let bits = match size {
            KeySize::Rsa2048 => 2048,
        };
        Self(RsaPrivateKey::new(&mut SystemRng, bits).expect("RSA key generation does not fail"))
    }

    pub(crate) fn from_pkcs8_der(der: &[u8]) -> Result<Self, Error> {
        RsaPrivateKey::from_pkcs8_der(der)
            .map(Self)
            .map_err(|_| Error::InvalidKey)
    }

    pub(crate) fn from_pkcs8_pem(pem: &str) -> Result<Self, Error> {
        RsaPrivateKey::from_pkcs8_pem(pem)
            .map(Self)
            .map_err(|_| Error::InvalidKey)
    }

    pub(crate) fn from_pkcs1_der(der: &[u8]) -> Result<Self, Error> {
        RsaPrivateKey::from_pkcs1_der(der)
            .map(Self)
            .map_err(|_| Error::InvalidKey)
    }

    pub(crate) fn from_components(
        n: &[u8],
        e: &[u8],
        d: &[u8],
        primes: &[&[u8]],
    ) -> Result<Self, Error> {
        // `components` and the SSH/JWK formats only describe two-prime keys.
        if primes.len() > TWO_PRIMES {
            return Err(Error::InvalidKey);
        }

        let uint = |b: &[u8]| BoxedUint::from_be_slice_vartime(b);
        RsaPrivateKey::from_components(
            uint(n),
            uint(e),
            uint(d),
            primes.iter().map(|p| uint(p)).collect(),
        )
        .map(Self)
        .map_err(|_| Error::InvalidKey)
    }

    pub(crate) fn to_pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let doc = self.0.to_pkcs8_der().map_err(|_| Error::InvalidKey)?;
        Ok(Zeroizing::new(doc.as_bytes().to_vec()))
    }

    pub(crate) fn components(&self) -> PrivateComponents {
        let primes = self.0.primes();
        let crt = self
            .0
            .crt_coefficient()
            .expect("validated keys carry a CRT coefficient");
        PrivateComponents {
            n: be(self.0.n()),
            e: be(self.0.e()),
            d: be_secret(self.0.d()),
            p: be_secret(&primes[0]),
            q: be_secret(&primes[1]),
            iqmp: be_secret(&crt),
        }
    }

    pub(crate) fn public_key(&self) -> PublicKey {
        PublicKey(self.0.to_public_key())
    }

    pub(crate) fn decrypt_oaep(
        &self,
        hash: OaepHash,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let result = match hash {
            OaepHash::Sha1 => self.0.decrypt(Oaep::<sha1::Sha1>::new(), ciphertext),
            OaepHash::Sha256 => self.0.decrypt(Oaep::<sha2::Sha256>::new(), ciphertext),
        };
        result
            .map(Zeroizing::new)
            .map_err(|_| Error::DecryptionFailed)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PublicKey(RsaPublicKey);

impl PublicKey {
    pub(crate) fn from_spki_der(der: &[u8]) -> Result<Self, Error> {
        RsaPublicKey::from_public_key_der(der)
            .map(Self)
            .map_err(|_| Error::InvalidKey)
    }

    pub(crate) fn to_spki_der(&self) -> Result<Vec<u8>, Error> {
        let doc = self.0.to_public_key_der().map_err(|_| Error::InvalidKey)?;
        Ok(doc.as_bytes().to_vec())
    }

    pub(crate) fn modulus(&self) -> Vec<u8> {
        be(self.0.n())
    }

    pub(crate) fn exponent(&self) -> Vec<u8> {
        be(self.0.e())
    }

    pub(crate) fn modulus_len(&self) -> usize {
        self.0.size()
    }

    pub(crate) fn encrypt_oaep(&self, hash: OaepHash, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let result = match hash {
            OaepHash::Sha1 => self
                .0
                .encrypt(&mut SystemRng, Oaep::<sha1::Sha1>::new(), plaintext),
            OaepHash::Sha256 => {
                self.0
                    .encrypt(&mut SystemRng, Oaep::<sha2::Sha256>::new(), plaintext)
            }
        };
        result.map_err(|_| Error::InvalidParameters)
    }
}

/// Minimal big-endian encoding (no leading zero bytes).
fn be(value: &BoxedUint) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first = bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(bytes.len().saturating_sub(1));
    bytes[first..].to_vec()
}

/// Minimal big-endian encoding of a secret value; every intermediate buffer is zeroized.
fn be_secret(value: &BoxedUint) -> Zeroizing<Vec<u8>> {
    let bytes = Zeroizing::new(value.to_be_bytes());
    let first = bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(bytes.len().saturating_sub(1));
    Zeroizing::new(bytes[first..].to_vec())
}
