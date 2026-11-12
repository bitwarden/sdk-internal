use ::openssl::{
    hash::{Hasher, MessageDigest},
    md::{Md, MdRef},
    md_ctx::MdCtx,
};
use zeroize::Zeroizing;

use crate::hmac::HashAlg;

/// Inner pad byte (RFC 2104 §2).
const IPAD: u8 = 0x36;
/// Outer pad byte (RFC 2104 §2).
const OPAD: u8 = 0x5c;
/// Input block length of SHA-1 and SHA-256.
const BLOCK_LEN_64: usize = 64;
/// Input block length of SHA-384 and SHA-512.
const BLOCK_LEN_128: usize = 128;

/// HMAC per RFC 2104 over two OpenSSL hashers.
///
/// Built from `Hasher` rather than OpenSSL's HMAC signer because the signer cannot be cloned, and
/// the incremental API must be `Clone`. Each hasher holds only the state after absorbing its
/// padded key block; OpenSSL wipes that state on drop.
#[derive(Clone)]
pub(crate) struct Hmac {
    inner: Hasher,
    outer: Hasher,
}

impl Hmac {
    pub(crate) fn new(alg: HashAlg, key: &[u8]) -> Self {
        let (digest, md, block_len) = match alg {
            HashAlg::Sha1 => (MessageDigest::sha1(), Md::sha1(), BLOCK_LEN_64),
            HashAlg::Sha256 => (MessageDigest::sha256(), Md::sha256(), BLOCK_LEN_64),
            HashAlg::Sha384 => (MessageDigest::sha384(), Md::sha384(), BLOCK_LEN_128),
            HashAlg::Sha512 => (MessageDigest::sha512(), Md::sha512(), BLOCK_LEN_128),
        };

        // K0: the key, hashed first if longer than a block, zero-padded to the block length.
        let mut block = Zeroizing::new(vec![0u8; block_len]);
        if key.len() > block_len {
            hash_into(md, key, &mut block[..md.size()]);
        } else {
            block[..key.len()].copy_from_slice(key);
        }

        Self {
            inner: keyed_hasher(digest, &block, IPAD),
            outer: keyed_hasher(digest, &block, OPAD),
        }
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        self.inner
            .update(data)
            .expect("hashing in-memory data does not fail");
    }

    pub(crate) fn finalize(mut self) -> Vec<u8> {
        const INFALLIBLE: &str = "hashing in-memory data does not fail";

        let inner = self.inner.finish().expect(INFALLIBLE);
        self.outer.update(&inner).expect(INFALLIBLE);
        self.outer.finish().expect(INFALLIBLE).to_vec()
    }
}

/// Hashes `data` straight into `out`, so a hashed key never sits in an unwiped buffer.
fn hash_into(md: &MdRef, data: &[u8], out: &mut [u8]) {
    const INFALLIBLE: &str = "hashing in-memory data does not fail";

    let mut ctx = MdCtx::new().expect(INFALLIBLE);
    ctx.digest_init(md).expect(INFALLIBLE);
    ctx.digest_update(data).expect(INFALLIBLE);
    ctx.digest_final(out).expect(INFALLIBLE);
}

/// A hasher that has absorbed `K0 XOR pad`.
fn keyed_hasher(digest: MessageDigest, block: &[u8], pad: u8) -> Hasher {
    const INFALLIBLE: &str = "hashing in-memory data does not fail";

    let padded = Zeroizing::new(block.iter().map(|b| b ^ pad).collect::<Vec<u8>>());
    let mut hasher = Hasher::new(digest).expect("OpenSSL provides the digest");
    hasher.update(&padded).expect(INFALLIBLE);
    hasher
}
