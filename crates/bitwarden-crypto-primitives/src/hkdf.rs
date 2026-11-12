//! HKDF-SHA256 (RFC 5869).

use zeroize::Zeroizing;

use crate::{Error, backend};

/// HKDF-Extract. Returns the pseudorandom key.
pub fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> Zeroizing<[u8; 32]> {
    backend::hkdf::extract(salt, ikm)
}

/// HKDF-Expand of `prk` into `out`. Fails if `prk` is shorter than 32 bytes or `out` is longer
/// than 255 * 32 bytes.
pub fn expand(prk: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), Error> {
    backend::hkdf::expand(prk, info, out)
}

/// HKDF-Extract followed by HKDF-Expand.
pub fn derive(salt: Option<&[u8]>, ikm: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), Error> {
    let prk = extract(salt, ikm);
    expand(prk.as_slice(), info, out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 5869 test case 1.
    const IKM: [u8; 22] = [0x0b; 22];
    const SALT: &str = "000102030405060708090a0b0c";
    const INFO: &str = "f0f1f2f3f4f5f6f7f8f9";
    const PRK: &str = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5";
    const OKM: &str =
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";

    #[test]
    fn known_answer() {
        let salt = hex::decode(SALT).expect("hex");
        let info = hex::decode(INFO).expect("hex");

        assert_eq!(hex::encode(extract(Some(&salt), &IKM).as_slice()), PRK);

        let mut okm = [0u8; 42];
        derive(Some(&salt), &IKM, &info, &mut okm).expect("valid lengths");
        assert_eq!(hex::encode(okm), OKM);
    }

    #[test]
    fn rejects_short_prk_and_long_output() {
        let mut out = [0u8; 32];
        assert_eq!(
            expand(&[0u8; 16], b"", &mut out),
            Err(Error::InvalidParameters)
        );

        let mut too_long = vec![0u8; 255 * 32 + 1];
        assert_eq!(
            expand(&[0u8; 32], b"", &mut too_long),
            Err(Error::InvalidParameters)
        );
    }
}
