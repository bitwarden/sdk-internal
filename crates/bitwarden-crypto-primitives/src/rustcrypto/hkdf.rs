use zeroize::{Zeroize, Zeroizing};

use crate::{Error, hkdf::PRK_LEN};

type HkdfSha256 = hkdf::Hkdf<sha2::Sha256>;

pub(crate) fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> Zeroizing<[u8; PRK_LEN]> {
    let (mut prk, _) = HkdfSha256::extract(salt, ikm);
    let out = Zeroizing::new(prk.into());

    // The returned array is a stack copy; wipe it.
    prk.as_mut_slice().zeroize();
    out
}

pub(crate) fn expand(prk: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), Error> {
    HkdfSha256::from_prk(prk)
        .map_err(|_| Error::InvalidParameters)?
        .expand(info, out)
        .map_err(|_| Error::InvalidParameters)
}
