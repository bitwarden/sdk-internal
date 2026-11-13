use ::openssl::{
    kdf::{HkdfMode, hkdf},
    md::Md,
};
use zeroize::Zeroizing;

use crate::{Error, hkdf::PRK_LEN};

/// SHA-256 output length; also the minimum PRK length (RFC 5869 §2.3).
const HASH_LEN: usize = 32;
/// Maximum output is 255 blocks (RFC 5869 §2.3).
const MAX_OUTPUT_LEN: usize = 255 * HASH_LEN;

pub(crate) fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> Zeroizing<[u8; PRK_LEN]> {
    let mut prk = Zeroizing::new([0u8; HASH_LEN]);
    hkdf(
        Md::sha256(),
        ikm,
        salt,
        None,
        HkdfMode::ExtractOnly,
        None,
        prk.as_mut_slice(),
    )
    .expect("HKDF-Extract accepts any salt and IKM");
    prk
}

pub(crate) fn expand(prk: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), Error> {
    // OpenSSL does not enforce the PRK minimum; match RFC 5869 and the RustCrypto backend.
    if prk.len() < HASH_LEN || out.len() > MAX_OUTPUT_LEN {
        return Err(Error::InvalidParameters);
    }

    // OpenSSL rejects an empty output buffer; an empty expansion is trivially done.
    if out.is_empty() {
        return Ok(());
    }

    hkdf(
        Md::sha256(),
        prk,
        None,
        Some(info),
        HkdfMode::ExpandOnly,
        None,
        out,
    )
    .map_err(|_| Error::InvalidParameters)
}
