use zeroize::Zeroizing;

use crate::Error;

type HkdfSha256 = hkdf::Hkdf<sha2::Sha256>;

pub(crate) fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> Zeroizing<[u8; 32]> {
    let (prk, _) = HkdfSha256::extract(salt, ikm);
    Zeroizing::new(prk.into())
}

pub(crate) fn expand(prk: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), Error> {
    HkdfSha256::from_prk(prk)
        .map_err(|_| Error::InvalidParameters)?
        .expand(info, out)
        .map_err(|_| Error::InvalidParameters)
}
