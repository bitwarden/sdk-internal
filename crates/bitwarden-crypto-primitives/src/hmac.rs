//! HMAC (RFC 2104).

use subtle::ConstantTimeEq;

use crate::{Error, backend};

/// Hash function underlying an [`Hmac`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlg {
    /// SHA-1. Legacy use only.
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

/// One-shot HMAC of `data` under `key`.
pub fn hmac(alg: HashAlg, key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::new(alg, key);
    mac.update(data);
    mac.finalize()
}

/// Incremental HMAC. Key material is zeroized on drop.
#[derive(Clone)]
pub struct Hmac(backend::hmac::Hmac);

impl Hmac {
    /// Starts a MAC under `key`. Any key length is accepted.
    pub fn new(alg: HashAlg, key: &[u8]) -> Self {
        Self(backend::hmac::Hmac::new(alg, key))
    }

    /// Absorbs `data`.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Returns the tag.
    pub fn finalize(self) -> Vec<u8> {
        self.0.finalize()
    }

    /// Compares the tag with `tag` in constant time.
    pub fn verify(self, tag: &[u8]) -> Result<(), Error> {
        let computed = self.finalize();
        if computed.ct_eq(tag).into() {
            return Ok(());
        }
        Err(Error::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4231 test case 2.
    const KEY: &[u8] = b"Jefe";
    const DATA: &[u8] = b"what do ya want for nothing?";
    const SHA256_TAG: &str = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";

    #[test]
    fn known_answer_sha256() {
        assert_eq!(hex::encode(hmac(HashAlg::Sha256, KEY, DATA)), SHA256_TAG);
    }

    #[test]
    fn tag_lengths() {
        assert_eq!(hmac(HashAlg::Sha1, KEY, DATA).len(), 20);
        assert_eq!(hmac(HashAlg::Sha384, KEY, DATA).len(), 48);
        assert_eq!(hmac(HashAlg::Sha512, KEY, DATA).len(), 64);
    }

    #[test]
    fn verify_accepts_valid_and_rejects_invalid() {
        let tag = hmac(HashAlg::Sha256, KEY, DATA);

        let mut mac = Hmac::new(HashAlg::Sha256, KEY);
        mac.update(DATA);
        assert_eq!(mac.clone().verify(&tag), Ok(()));

        let mut bad = tag.clone();
        bad[0] ^= 1;
        assert_eq!(mac.clone().verify(&bad), Err(Error::InvalidSignature));
        assert_eq!(mac.verify(&tag[..16]), Err(Error::InvalidSignature));
    }
}
