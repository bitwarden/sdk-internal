use hmac::{KeyInit, Mac};

use crate::hmac::HashAlg;

/// HMAC state for each supported hash.
#[derive(Clone)]
pub(crate) enum Hmac {
    Sha1(hmac::Hmac<sha1::Sha1>),
    Sha256(hmac::Hmac<sha2::Sha256>),
    Sha384(hmac::Hmac<sha2::Sha384>),
    Sha512(hmac::Hmac<sha2::Sha512>),
}

impl Hmac {
    pub(crate) fn new(alg: HashAlg, key: &[u8]) -> Self {
        // HMAC accepts keys of any length; longer keys are hashed per RFC 2104.
        const ANY_LEN: &str = "HMAC accepts any key length";
        match alg {
            HashAlg::Sha1 => Self::Sha1(KeyInit::new_from_slice(key).expect(ANY_LEN)),
            HashAlg::Sha256 => Self::Sha256(KeyInit::new_from_slice(key).expect(ANY_LEN)),
            HashAlg::Sha384 => Self::Sha384(KeyInit::new_from_slice(key).expect(ANY_LEN)),
            HashAlg::Sha512 => Self::Sha512(KeyInit::new_from_slice(key).expect(ANY_LEN)),
        }
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha1(m) => m.update(data),
            Self::Sha256(m) => m.update(data),
            Self::Sha384(m) => m.update(data),
            Self::Sha512(m) => m.update(data),
        }
    }

    pub(crate) fn finalize(self) -> Vec<u8> {
        match self {
            Self::Sha1(m) => m.finalize().into_bytes().to_vec(),
            Self::Sha256(m) => m.finalize().into_bytes().to_vec(),
            Self::Sha384(m) => m.finalize().into_bytes().to_vec(),
            Self::Sha512(m) => m.finalize().into_bytes().to_vec(),
        }
    }
}
