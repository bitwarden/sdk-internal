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
    use crate::test_vectors::bytes;

    // RFC 4231 test case 1 (RFC 2202 test case 1 for SHA-1): key 0x0b * 20, data "Hi There".
    const KEY: &str = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
    const DATA: &str = "4869205468657265";

    #[test]
    fn known_answers_rfc4231() {
        let cases = [
            (HashAlg::Sha1, "b617318655057264e28bc0b6fb378c8ef146be00"),
            (
                HashAlg::Sha256,
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            ),
            (
                HashAlg::Sha384,
                "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c\
                faea9ea9076ede7f4af152e8b2fa9cb6",
            ),
            (
                HashAlg::Sha512,
                "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde\
                daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
            ),
        ];
        for (alg, expected) in cases {
            assert_eq!(
                hex::encode(hmac(alg, &bytes(KEY), &bytes(DATA))),
                expected,
                "{alg:?}"
            );
        }
    }

    #[test]
    fn verify_accepts_valid_and_rejects_invalid() {
        let tag = hmac(HashAlg::Sha256, &bytes(KEY), &bytes(DATA));

        let mut mac = Hmac::new(HashAlg::Sha256, &bytes(KEY));
        mac.update(&bytes(DATA));
        assert_eq!(mac.clone().verify(&tag), Ok(()));

        let mut bad = tag.clone();
        bad[0] ^= 1;
        assert_eq!(mac.clone().verify(&bad), Err(Error::InvalidSignature));
        assert_eq!(mac.verify(&tag[..16]), Err(Error::InvalidSignature));
    }

    /// RFC 4231 test case 6 data: the key is longer than every block size, so it is hashed first.
    const LONG_KEY_DATA: &str = "Test Using Larger Than Block-Size Key - Hash Key First";
    const LONG_KEY: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
    aaaaaa";
    const FOX: &str = "The quick brown fox jumps over the lazy dog";

    /// Expected tags per algorithm: (empty key and message, long key, key `"key"` over FOX).
    const VECTORS: [(HashAlg, &str, &str, &str); 4] = [
        (
            HashAlg::Sha1,
            "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d",
            "90d0dace1c1bdc957339307803160335bde6df2b",
            "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9",
        ),
        (
            HashAlg::Sha256,
            "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad",
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8",
        ),
        (
            HashAlg::Sha384,
            "6c1f2ee938fad2e24bd91298474382ca218c75db3d83e114b3d4367776d14d35\
            51289e75e8209cd4b792302840234adc",
            "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c6\
            0c2ef6ab4030fe8296248df163f44952",
            "d7f4727e2c0b39ae0f1e40cc96f60242d5b7801841cea6fc592c5d3e1ae50700\
            582a96cf35e1e554995fe4e03381c237",
        ),
        (
            HashAlg::Sha512,
            "b936cee86c9f87aa5d3c6f2e84cb5a4239a5fe50480a6ec66b70ab5b1f4ac673\
            0c6c515421b327ec1d69402e53dfb49ad7381eb067b338fd7b0cb22247225d47",
            "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352\
            6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
            "b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb\
            82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a",
        ),
    ];

    #[test]
    fn known_answers_all_algorithms() {
        for (alg, empty, long_key, fox) in VECTORS {
            assert_eq!(hex::encode(hmac(alg, b"", b"")), empty, "{alg:?} empty");
            assert_eq!(
                hex::encode(hmac(alg, &bytes(LONG_KEY), LONG_KEY_DATA.as_bytes())),
                long_key,
                "{alg:?} long key"
            );
            assert_eq!(
                hex::encode(hmac(alg, b"key", FOX.as_bytes())),
                fox,
                "{alg:?} fox"
            );
        }
    }
}
